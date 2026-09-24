//! This module generates CSRs for the workload identity and issues leaf
//! certificates signed by a dynamic CA.
//!
//! aws-lc-rs and SymCrypt builds use rcgen. BoringSSL builds use boring's X.509
//! builders, because rcgen needs aws-lc-rs or ring to generate and parse keys.
//! There, the dynamic CA key must be RSA or ECDSA, and the CA certificate must
//! have a subject key identifier.

pub use imp::{DynamicCa, generate_csr};

pub struct Csr {
	pub csr_pem: String,
	pub key_pem: String,
}

#[cfg(any(feature = "crypto-aws-lc", feature = "crypto-symcrypt"))]
mod imp {
	use anyhow::anyhow;
	use rcgen::{CertificateParams, DistinguishedName, DnType, Issuer, KeyPair, SanType};
	use rustls::pki_types::CertificateDer;
	use rustls::pki_types::pem::PemObject;

	use super::Csr;

	/// Generates an ECDSA P-256 key and a CSR whose only SAN is `uri_san`.
	pub fn generate_csr(uri_san: &str) -> anyhow::Result<Csr> {
		let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
		let mut params = CertificateParams::default();
		params.subject_alt_names = vec![SanType::URI(uri_san.try_into()?)];
		params.key_identifier_method = rcgen::KeyIdMethod::Sha256;
		// Avoid setting CN. rcgen defaults it to "rcgen self signed cert" which we don't want
		params.distinguished_name = DistinguishedName::new();
		let csr_pem = params.serialize_request(&kp)?.pem()?;
		Ok(Csr {
			csr_pem,
			key_pem: kp.serialize_pem(),
		})
	}

	pub struct DynamicCa {
		cert_der: Vec<u8>,
		issuer: Issuer<'static, KeyPair>,
	}

	impl DynamicCa {
		pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> anyhow::Result<Self> {
			let cert_pem_str = std::str::from_utf8(cert_pem)?;
			let key_pem_str = std::str::from_utf8(key_pem)?;

			let cert_der = CertificateDer::pem_slice_iter(cert_pem)
				.next()
				.ok_or_else(|| anyhow!("no certificate found in dynamic CA PEM"))?
				.map_err(|e| anyhow!("failed to parse dynamic CA cert PEM: {e}"))?
				.to_vec();

			let key_pair = KeyPair::from_pem(key_pem_str)?;
			let issuer = Issuer::from_ca_cert_pem(cert_pem_str, key_pair)?;

			Ok(Self { cert_der, issuer })
		}

		pub fn cert_der(&self) -> &[u8] {
			&self.cert_der
		}

		/// Returns the DER certificate and PKCS#8 DER key of a new leaf for `domain`.
		pub fn generate_leaf_cert(&self, domain: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
			let mut params = CertificateParams::new(vec![domain.to_string()])?;
			params.distinguished_name.push(DnType::CommonName, domain);
			params.is_ca = rcgen::IsCa::NoCa;
			params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
			params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
			params.use_authority_key_identifier_extension = true;

			let leaf_key = KeyPair::generate()?;
			let leaf_cert = params.signed_by(&leaf_key, &self.issuer)?;

			Ok((leaf_cert.der().to_vec(), leaf_key.serialize_der()))
		}
	}
}

#[cfg(feature = "crypto-boring")]
mod imp {
	use anyhow::{Context, bail};
	use boring::asn1::Asn1Time;
	use boring::bn::BigNum;
	use boring::ec::{EcGroup, EcKey};
	use boring::error::ErrorStack;
	use boring::hash::MessageDigest;
	use boring::nid::Nid;
	use boring::pkey::{Id, PKey, PKeyRef, Private};
	use boring::stack::Stack;
	use boring::x509::extension::{
		AuthorityKeyIdentifier, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
	};
	use boring::x509::{X509, X509NameBuilder, X509ReqBuilder};
	use foreign_types::ForeignType;

	use super::Csr;

	// These match rcgen's default validity, so leaves from every backend agree.
	const NOT_BEFORE: i64 = 157_766_400; // 1975-01-01T00:00:00Z
	const NOT_AFTER: i64 = 67_090_118_400; // 4096-01-01T00:00:00Z

	/// Generates an ECDSA P-256 key and a CSR whose only SAN is `uri_san`.
	pub fn generate_csr(uri_san: &str) -> anyhow::Result<Csr> {
		let key = generate_p256_key()?;
		let mut builder = X509ReqBuilder::new()?;
		builder.set_pubkey(&key)?;
		// The subject is empty, so the CSR requests the critical SAN that RFC 5280
		// requires of the certificate.
		let san = SubjectAlternativeName::new()
			.critical()
			.uri(uri_san)
			.build(&builder.x509v3_context(None))?;
		let mut extensions = Stack::new()?;
		extensions.push(san)?;
		builder.add_extensions(&extensions)?;
		builder.sign(&key, MessageDigest::sha256())?;
		Ok(Csr {
			csr_pem: String::from_utf8(builder.build().to_pem()?)?,
			key_pem: String::from_utf8(key.private_key_to_pem_pkcs8()?)?,
		})
	}

	pub struct DynamicCa {
		cert: X509,
		cert_der: Vec<u8>,
		key: PKey<Private>,
		digest: MessageDigest,
	}

	impl DynamicCa {
		pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> anyhow::Result<Self> {
			let cert = X509::from_pem(cert_pem).context("failed to parse dynamic CA cert PEM")?;
			anyhow::ensure!(
				cert.subject_key_id().is_some(),
				"dynamic CA certificate has no subject key identifier"
			);
			let key =
				PKey::private_key_from_pem(key_pem).context("failed to parse dynamic CA key PEM")?;
			let digest = signature_digest(&key)?;
			Ok(Self {
				cert_der: cert.to_der()?,
				cert,
				key,
				digest,
			})
		}

		pub fn cert_der(&self) -> &[u8] {
			&self.cert_der
		}

		/// Returns the DER certificate and PKCS#8 DER key of a new leaf for `domain`.
		pub fn generate_leaf_cert(&self, domain: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
			let leaf_key = generate_p256_key()?;

			let mut name = X509NameBuilder::new()?;
			// BoringSSL limits the common name to 64 characters. The SAN carries the domain.
			if domain.len() <= 64 {
				name.append_entry_by_nid(Nid::COMMONNAME, domain)?;
			}
			let name = name.build();

			let serial = random_serial()?.to_asn1_integer()?;
			let not_before = Asn1Time::from_unix(NOT_BEFORE)?;
			let not_after = Asn1Time::from_unix(NOT_AFTER)?;

			let mut builder = X509::builder()?;
			builder.set_version(2)?;
			builder.set_serial_number(&serial)?;
			builder.set_subject_name(&name)?;
			builder.set_issuer_name(self.cert.subject_name())?;
			builder.set_not_before(&not_before)?;
			builder.set_not_after(&not_after)?;
			builder.set_pubkey(&leaf_key)?;
			let aki = AuthorityKeyIdentifier::new()
				.keyid(false)
				.build(&builder.x509v3_context(Some(&self.cert), None))?;
			let mut san = SubjectAlternativeName::new();
			// RFC 5280 requires a critical SAN when the subject is empty.
			if name.entries().next().is_none() {
				san.critical();
			}
			let san = san
				.dns(domain)
				.build(&builder.x509v3_context(Some(&self.cert), None))?;
			let key_usage = KeyUsage::new().critical().digital_signature().build()?;
			let extended_key_usage = ExtendedKeyUsage::new().server_auth().build()?;
			for extension in [&aki, &san, &key_usage, &extended_key_usage] {
				builder.append_extension(extension)?;
			}
			builder.sign(&self.key, self.digest)?;

			Ok((
				builder.build().to_der()?,
				leaf_key.private_key_to_der_pkcs8()?,
			))
		}
	}

	/// Generates a P-256 key with the pairwise consistency test FIPS 140-3 requires.
	fn generate_p256_key() -> anyhow::Result<PKey<Private>> {
		let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
		let key = EcKey::from_group(&group)?;
		// SAFETY: `key` owns a valid EC_KEY whose group is set.
		if unsafe { boring_sys::EC_KEY_generate_key_fips(key.as_ptr()) } != 1 {
			return Err(ErrorStack::get().into());
		}
		// SAFETY: the EC_KEY now holds a private key; the new wrapper takes ownership.
		let key = unsafe { EcKey::<Private>::from_ptr(key.into_ptr()) };
		Ok(PKey::from_ec_key(key)?)
	}

	/// Picks the digest rcgen would pair with the CA key.
	fn signature_digest(key: &PKeyRef<Private>) -> anyhow::Result<MessageDigest> {
		match key.id() {
			Id::RSA => Ok(MessageDigest::sha256()),
			Id::EC => match key.ec_key()?.group().curve_name() {
				Some(Nid::X9_62_PRIME256V1) => Ok(MessageDigest::sha256()),
				Some(Nid::SECP384R1) => Ok(MessageDigest::sha384()),
				Some(Nid::SECP521R1) => Ok(MessageDigest::sha512()),
				curve => bail!("unsupported dynamic CA curve {curve:?}"),
			},
			id => bail!("unsupported dynamic CA key type {id:?}"),
		}
	}

	/// Returns a random positive serial number of at most 20 octets (RFC 5280 4.1.2.2).
	fn random_serial() -> anyhow::Result<BigNum> {
		let mut serial = [0u8; 20];
		crate::crypto::rand::fill(&mut serial)?;
		serial_from_bytes(serial)
	}

	pub(super) fn serial_from_bytes(mut bytes: [u8; 20]) -> anyhow::Result<BigNum> {
		bytes[0] &= 0x7f;
		Ok(BigNum::from_slice(&bytes)?)
	}
}

#[cfg(test)]
mod tests {
	use rustls::pki_types::PrivatePkcs8KeyDer;
	use rustls::pki_types::pem::PemObject;
	use x509_parser::certification_request::X509CertificationRequest;
	use x509_parser::cri_attributes::ParsedCriAttribute;
	use x509_parser::extensions::{GeneralName, ParsedExtension};
	use x509_parser::prelude::{FromDer, X509Certificate};

	use super::{DynamicCa, generate_csr};

	#[test]
	fn csr_names_only_the_uri_san_and_is_signed_by_its_key() {
		let san = "spiffe://cluster.local/ns/default/sa/test";
		let csr = generate_csr(san).expect("generate CSR");

		// Parsing verifies the CSR signature.
		let params = rcgen::CertificateSigningRequestParams::from_pem(&csr.csr_pem).expect("parse CSR");
		assert!(params.params.distinguished_name.iter().next().is_none());
		assert_eq!(
			params.params.subject_alt_names,
			vec![rcgen::SanType::URI(san.try_into().unwrap())]
		);
		let key = rcgen::KeyPair::from_pem(&csr.key_pem).expect("parse key");
		assert_eq!(
			rcgen::PublicKeyData::der_bytes(&params.public_key),
			key.public_key_raw()
		);
		let key_der =
			rustls::pki_types::PrivateKeyDer::from_pem_slice(csr.key_pem.as_bytes()).expect("key PEM");
		crate::crypto::tls::key_provider(&crate::crypto::provider())
			.load_private_key(key_der)
			.expect("the TLS provider must load the CSR key");

		// The subject is empty, so the CSR requests the critical SAN that RFC 5280
		// requires of the certificate.
		let csr_der =
			rustls::pki_types::CertificateSigningRequestDer::from_pem_slice(csr.csr_pem.as_bytes())
				.expect("CSR PEM");
		let (_, parsed) = X509CertificationRequest::from_der(csr_der.as_ref()).expect("parse CSR");
		let san_is_critical = parsed
			.certification_request_info
			.iter_attributes()
			.any(|attribute| {
				matches!(attribute.parsed_attribute(), ParsedCriAttribute::ExtensionRequest(request)
					if request.extensions.iter().any(|e| e.critical
						&& matches!(e.parsed_extension(), ParsedExtension::SubjectAlternativeName(_))))
			});
		assert!(san_is_critical);
	}

	#[test]
	fn leaf_for_a_long_domain_carries_it_in_the_san() {
		let ca_key = rcgen::KeyPair::generate().expect("generate CA key");
		let mut ca_params = rcgen::CertificateParams::default();
		ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
		let ca_cert = ca_params.self_signed(&ca_key).expect("generate CA cert");
		let ca = DynamicCa::from_pem(ca_cert.pem().as_bytes(), ca_key.serialize_pem().as_bytes())
			.expect("parse CA");
		let domain = format!("{}.example.com", "a".repeat(60));

		let (leaf_der, _) = ca.generate_leaf_cert(&domain).expect("generate leaf");

		let (_, leaf) = X509Certificate::from_der(&leaf_der).expect("parse leaf");
		let san = leaf
			.extensions()
			.iter()
			.find(|e| {
				matches!(
					e.parsed_extension(),
					ParsedExtension::SubjectAlternativeName(_)
				)
			})
			.expect("leaf has a SAN");
		assert!(matches!(
			san.parsed_extension(),
			ParsedExtension::SubjectAlternativeName(san)
				if san.general_names == [GeneralName::DNSName(domain.as_str())]
		));
		// RFC 5280 requires a critical SAN when the subject is empty.
		let subject_is_empty = leaf.subject().iter().next().is_none();
		assert!(!subject_is_empty || san.critical);
	}

	#[cfg(feature = "crypto-boring")]
	#[test]
	fn serial_fits_in_20_octets() {
		let serial = super::imp::serial_from_bytes([0xff; 20]).unwrap();
		assert_eq!(serial.num_bits(), 159);
	}

	#[cfg(feature = "crypto-boring")]
	#[test]
	fn rejects_a_ca_without_a_subject_key_identifier() {
		use boring::asn1::Asn1Time;
		use boring::ec::{EcGroup, EcKey};
		use boring::hash::MessageDigest;
		use boring::nid::Nid;
		use boring::pkey::PKey;
		use boring::x509::extension::BasicConstraints;
		use boring::x509::{X509, X509NameBuilder};

		let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
		let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
		let mut name = X509NameBuilder::new().unwrap();
		name.append_entry_by_nid(Nid::COMMONNAME, "CA").unwrap();
		let name = name.build();
		let mut ca = X509::builder().unwrap();
		ca.set_version(2).unwrap();
		ca.set_subject_name(&name).unwrap();
		ca.set_issuer_name(&name).unwrap();
		ca.set_pubkey(&key).unwrap();
		ca.set_not_before(&Asn1Time::days_from_now(0).unwrap())
			.unwrap();
		ca.set_not_after(&Asn1Time::days_from_now(1).unwrap())
			.unwrap();
		let constraints = BasicConstraints::new().critical().ca().build().unwrap();
		ca.append_extension(&constraints).unwrap();
		ca.sign(&key, MessageDigest::sha256()).unwrap();

		let err = DynamicCa::from_pem(
			&ca.build().to_pem().unwrap(),
			&key.private_key_to_pem_pkcs8().unwrap(),
		)
		.err()
		.expect("a CA without a subject key identifier must be rejected");
		assert!(err.to_string().contains("subject key identifier"), "{err}");
	}

	#[test]
	fn leaf_is_a_server_certificate_for_the_domain() {
		for alg in [
			&rcgen::PKCS_ECDSA_P256_SHA256,
			&rcgen::PKCS_ECDSA_P384_SHA384,
			&rcgen::PKCS_RSA_SHA256,
		] {
			let ca_key = rcgen::KeyPair::generate_for(alg).expect("generate CA key");
			let mut ca_params = rcgen::CertificateParams::default();
			ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
			let ca_cert = ca_params.self_signed(&ca_key).expect("generate CA cert");
			let ca = DynamicCa::from_pem(ca_cert.pem().as_bytes(), ca_key.serialize_pem().as_bytes())
				.expect("parse CA");
			assert_eq!(ca.cert_der(), ca_cert.der().as_ref());

			let (leaf_der, key_der) = ca.generate_leaf_cert("example.com").expect("generate leaf");

			let (_, leaf) = X509Certificate::from_der(&leaf_der).expect("parse leaf");
			let (_, ca_parsed) = X509Certificate::from_der(ca_cert.der()).expect("parse CA");
			leaf
				.verify_signature(Some(ca_parsed.public_key()))
				.unwrap_or_else(|e| panic!("{alg:?}: leaf must verify against the CA: {e}"));
			assert_eq!(leaf.issuer(), ca_parsed.subject());
			assert_eq!(
				leaf
					.subject()
					.iter_common_name()
					.next()
					.and_then(|cn| cn.as_str().ok()),
				Some("example.com")
			);
			assert_eq!(leaf.validity().not_before.timestamp(), 157_766_400); // 1975-01-01
			assert_eq!(leaf.validity().not_after.timestamp(), 67_090_118_400); // 4096-01-01
			let (other_der, _) = ca.generate_leaf_cert("example.com").expect("generate leaf");
			let (_, other) = X509Certificate::from_der(&other_der).expect("parse leaf");
			assert_ne!(leaf.raw_serial(), other.raw_serial());
			for serial in [leaf.raw_serial(), other.raw_serial()] {
				// RFC 5280 4.1.2.2 requires a positive serial of at most 20 octets.
				assert!(serial.len() <= 20 && serial[0] & 0x80 == 0, "{serial:02x?}");
			}
			let extensions: Vec<_> = leaf.extensions().iter().collect();
			assert!(extensions.iter().any(|e| matches!(
				e.parsed_extension(),
				ParsedExtension::SubjectAlternativeName(san)
					if san.general_names == [GeneralName::DNSName("example.com")]
			)));
			assert!(extensions.iter().any(|e| e.critical
				&& matches!(e.parsed_extension(), ParsedExtension::KeyUsage(ku)
					if ku.digital_signature() && !ku.key_cert_sign())));
			assert!(extensions.iter().any(|e| matches!(
				e.parsed_extension(),
				ParsedExtension::ExtendedKeyUsage(eku) if eku.server_auth && !eku.client_auth
			)));
			assert!(
				!extensions
					.iter()
					.any(|e| matches!(e.parsed_extension(), ParsedExtension::BasicConstraints(bc) if bc.ca))
			);

			let leaf_key = rcgen::KeyPair::try_from(key_der.as_slice()).expect("parse leaf key");
			assert_eq!(
				rcgen::PublicKeyData::subject_public_key_info(&leaf_key),
				leaf.public_key().raw
			);
			let provider = crate::crypto::provider();
			crate::crypto::tls::key_provider(&provider)
				.load_private_key(PrivatePkcs8KeyDer::from(key_der).into())
				.expect("the TLS provider must load the leaf key");
		}
	}
}
