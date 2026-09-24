//! This module generates CSRs for the workload identity and issues leaf
//! certificates signed by a dynamic CA.

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
