//! [`PROVIDER`] implements jsonwebtoken's [`CryptoProvider`] with BoringSSL.
//!
//! jsonwebtoken hands over RSA private keys as PKCS#1, EC and Ed private keys
//! as PKCS#8, RSA public keys as PKCS#1 or modulus and exponent, EC public keys
//! as uncompressed points, and Ed public keys as raw bytes.

use std::ops::RangeInclusive;

use boring::bn::{BigNum, BigNumContext};
use boring::ec::{EcGroup, EcKey, EcPoint};
use boring::ecdsa::EcdsaSig;
use boring::error::ErrorStack;
use boring::hash::MessageDigest;
use boring::hmac::Hmac;
use boring::nid::Nid;
use boring::pkey::{HasParams, HasPublic, Id, PKey, PKeyRef, Private, Public};
use boring::rsa::{Padding, Rsa};
use boring::sign::{RsaPssSaltlen, Signer, Verifier};
use jsonwebtoken::crypto::{CryptoProvider, JwtSigner, JwtVerifier, KeyUtils};
use jsonwebtoken::errors::{Error, ErrorKind};
use jsonwebtoken::{
	Algorithm, AlgorithmFamily, DecodingKey, DecodingKeyKind, EncodingKey, signature,
};

pub static PROVIDER: CryptoProvider = CryptoProvider {
	signer_factory: new_signer,
	verifier_factory: new_verifier,
	// Only building JWKs from keys and computing JWK thumbprints use these.
	key_utils: KeyUtils::new_unimplemented(),
};

// aws-lc-rs accepts RSA keys of these sizes.
const RSA_BITS: RangeInclusive<u32> = 2048..=8192;

const ED25519_KEY_LEN: usize = 32;

// Prepending these bytes to a raw Ed25519 public key gives its SubjectPublicKeyInfo DER.
const ED25519_SPKI_PREFIX: [u8; 12] = [
	0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

enum Scheme {
	Hmac(MessageDigest),
	Asymmetric(AsymmetricScheme),
}

#[derive(Clone, Copy)]
enum AsymmetricScheme {
	RsaPkcs1(MessageDigest),
	RsaPss(MessageDigest),
	Ecdsa {
		digest: MessageDigest,
		curve: Nid,
		scalar_len: usize,
	},
	Ed25519,
}

fn scheme(algorithm: Algorithm) -> Result<Scheme, Error> {
	use AsymmetricScheme::*;
	Ok(match algorithm {
		Algorithm::HS256 => Scheme::Hmac(MessageDigest::sha256()),
		Algorithm::HS384 => Scheme::Hmac(MessageDigest::sha384()),
		Algorithm::HS512 => Scheme::Hmac(MessageDigest::sha512()),
		Algorithm::RS256 => Scheme::Asymmetric(RsaPkcs1(MessageDigest::sha256())),
		Algorithm::RS384 => Scheme::Asymmetric(RsaPkcs1(MessageDigest::sha384())),
		Algorithm::RS512 => Scheme::Asymmetric(RsaPkcs1(MessageDigest::sha512())),
		Algorithm::PS256 => Scheme::Asymmetric(RsaPss(MessageDigest::sha256())),
		Algorithm::PS384 => Scheme::Asymmetric(RsaPss(MessageDigest::sha384())),
		Algorithm::PS512 => Scheme::Asymmetric(RsaPss(MessageDigest::sha512())),
		Algorithm::ES256 => Scheme::Asymmetric(Ecdsa {
			digest: MessageDigest::sha256(),
			curve: Nid::X9_62_PRIME256V1,
			scalar_len: 32,
		}),
		Algorithm::ES384 => Scheme::Asymmetric(Ecdsa {
			digest: MessageDigest::sha384(),
			curve: Nid::SECP384R1,
			scalar_len: 48,
		}),
		// Ed25519 is outside BoringSSL's FIPS module.
		Algorithm::EdDSA if cfg!(feature = "fips") => return Err(ErrorKind::InvalidAlgorithm.into()),
		Algorithm::EdDSA => Scheme::Asymmetric(Ed25519),
		_ => return Err(ErrorKind::InvalidAlgorithm.into()),
	})
}

fn invalid_key(family: AlgorithmFamily) -> Error {
	match family {
		AlgorithmFamily::Rsa => ErrorKind::InvalidRsaKey("unusable RSA key".to_string()),
		AlgorithmFamily::Ec => ErrorKind::InvalidEcdsaKey,
		AlgorithmFamily::Ed => ErrorKind::InvalidEddsaKey,
		AlgorithmFamily::Hmac => ErrorKind::InvalidKeyFormat,
	}
	.into()
}

/// Reports whether `key` has the type, curve and size that `scheme` requires.
fn key_matches<T: HasParams + HasPublic>(scheme: AsymmetricScheme, key: &PKeyRef<T>) -> bool {
	use AsymmetricScheme::*;
	match scheme {
		RsaPkcs1(_) | RsaPss(_) => key.id() == Id::RSA && RSA_BITS.contains(&key.bits()),
		Ecdsa { curve, .. } => {
			key.id() == Id::EC
				&& key
					.ec_key()
					.is_ok_and(|ec| ec.group().curve_name() == Some(curve))
		},
		Ed25519 => key.id() == Id::ED25519,
	}
}

struct BoringSigner {
	algorithm: Algorithm,
	key: SigningKey,
}

enum SigningKey {
	Hmac(MessageDigest, EncodingKey),
	Asymmetric(AsymmetricScheme, PKey<Private>),
}

fn new_signer(algorithm: &Algorithm, key: &EncodingKey) -> Result<Box<dyn JwtSigner>, Error> {
	let family = algorithm.family();
	if key.family() != family {
		return Err(ErrorKind::InvalidKeyFormat.into());
	}
	let key = match scheme(*algorithm)? {
		Scheme::Hmac(digest) => SigningKey::Hmac(digest, key.clone()),
		Scheme::Asymmetric(scheme) => {
			let pkey = private_key(scheme, key.as_bytes())
				.ok()
				.filter(|pkey| key_matches(scheme, pkey))
				.ok_or_else(|| invalid_key(family))?;
			SigningKey::Asymmetric(scheme, pkey)
		},
	};
	Ok(Box::new(BoringSigner {
		algorithm: *algorithm,
		key,
	}))
}

fn private_key(scheme: AsymmetricScheme, der: &[u8]) -> Result<PKey<Private>, ErrorStack> {
	match scheme {
		AsymmetricScheme::RsaPkcs1(_) | AsymmetricScheme::RsaPss(_) => {
			PKey::from_rsa(Rsa::private_key_from_der(der)?)
		},
		AsymmetricScheme::Ecdsa { .. } | AsymmetricScheme::Ed25519 => PKey::private_key_from_pkcs8(der),
	}
}

impl signature::Signer<Vec<u8>> for BoringSigner {
	fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>, signature::Error> {
		match &self.key {
			SigningKey::Hmac(digest, key) => hmac(*digest, key.as_bytes(), msg),
			SigningKey::Asymmetric(scheme, pkey) => sign(*scheme, pkey, msg),
		}
		.map_err(signature::Error::from_source)
	}
}

impl JwtSigner for BoringSigner {
	fn algorithm(&self) -> Algorithm {
		self.algorithm
	}
}

fn sign(
	scheme: AsymmetricScheme,
	pkey: &PKeyRef<Private>,
	msg: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
	match scheme {
		AsymmetricScheme::Ed25519 => Signer::new_without_digest(pkey)?.sign_oneshot_to_vec(msg),
		AsymmetricScheme::RsaPkcs1(digest) => {
			let mut signer = Signer::new(digest, pkey)?;
			signer.set_rsa_padding(Padding::PKCS1)?;
			signer.sign_oneshot_to_vec(msg)
		},
		AsymmetricScheme::RsaPss(digest) => {
			// JWA fixes the salt length to the digest length and MGF1 to the same digest.
			let mut signer = Signer::new(digest, pkey)?;
			signer.set_rsa_padding(Padding::PKCS1_PSS)?;
			signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
			signer.set_rsa_mgf1_md(digest)?;
			signer.sign_oneshot_to_vec(msg)
		},
		AsymmetricScheme::Ecdsa {
			digest, scalar_len, ..
		} => {
			// BoringSSL emits DER; JWS uses fixed-length `r || s`.
			let der = Signer::new(digest, pkey)?.sign_oneshot_to_vec(msg)?;
			let signature = EcdsaSig::from_der(&der)?;
			let mut raw = signature.r().to_vec_padded(scalar_len)?;
			raw.extend(signature.s().to_vec_padded(scalar_len)?);
			Ok(raw)
		},
	}
}

fn hmac(digest: MessageDigest, secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, ErrorStack> {
	let mut mac = Hmac::init(secret, &digest)?;
	mac.update(msg)?;
	mac.finalize()
}

struct BoringVerifier {
	algorithm: Algorithm,
	key: VerifyingKey,
}

enum VerifyingKey {
	Hmac(MessageDigest, DecodingKey),
	Asymmetric(AsymmetricScheme, PKey<Public>),
}

fn new_verifier(algorithm: &Algorithm, key: &DecodingKey) -> Result<Box<dyn JwtVerifier>, Error> {
	let family = algorithm.family();
	if key.family() != family {
		return Err(ErrorKind::InvalidKeyFormat.into());
	}
	let key = match scheme(*algorithm)? {
		Scheme::Hmac(digest) => VerifyingKey::Hmac(digest, key.clone()),
		Scheme::Asymmetric(scheme) => {
			let pkey = public_key(scheme, key.kind())
				.filter(|pkey| key_matches(scheme, pkey))
				.ok_or_else(|| invalid_key(family))?;
			VerifyingKey::Asymmetric(scheme, pkey)
		},
	};
	Ok(Box::new(BoringVerifier {
		algorithm: *algorithm,
		key,
	}))
}

fn public_key(scheme: AsymmetricScheme, key: &DecodingKeyKind) -> Option<PKey<Public>> {
	use AsymmetricScheme::*;
	let key = match (scheme, key) {
		(RsaPkcs1(_) | RsaPss(_), DecodingKeyKind::RsaModulusExponent { n, e }) => {
			Rsa::from_public_components(BigNum::from_slice(n).ok()?, BigNum::from_slice(e).ok()?)
				.and_then(PKey::from_rsa)
		},
		(RsaPkcs1(_) | RsaPss(_), DecodingKeyKind::SecretOrDer(der)) => {
			Rsa::public_key_from_der_pkcs1(der).and_then(PKey::from_rsa)
		},
		(Ecdsa { curve, .. }, DecodingKeyKind::SecretOrDer(point)) => ec_public_key(curve, point),
		(Ed25519, DecodingKeyKind::SecretOrDer(raw)) if raw.len() == ED25519_KEY_LEN => {
			PKey::public_key_from_der(&[&ED25519_SPKI_PREFIX[..], raw].concat())
		},
		_ => return None,
	};
	key.ok()
}

fn ec_public_key(curve: Nid, point: &[u8]) -> Result<PKey<Public>, ErrorStack> {
	let group = EcGroup::from_curve_name(curve)?;
	let mut ctx = BigNumContext::new()?;
	let point = EcPoint::from_bytes(&group, point, &mut ctx)?;
	PKey::from_ec_key(EcKey::from_public_key(&group, &point)?)
}

impl signature::Verifier<Vec<u8>> for BoringVerifier {
	fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> Result<(), signature::Error> {
		let valid = match &self.key {
			VerifyingKey::Hmac(digest, key) => {
				let secret = key
					.try_get_as_bytes()
					.map_err(signature::Error::from_source)?;
				hmac(*digest, secret, msg).map(|expected| {
					expected.len() == signature.len() && boring::memcmp::eq(&expected, signature)
				})
			},
			VerifyingKey::Asymmetric(scheme, pkey) => verify(*scheme, pkey, msg, signature),
		}
		.map_err(signature::Error::from_source)?;
		valid.then_some(()).ok_or_else(signature::Error::new)
	}
}

impl JwtVerifier for BoringVerifier {
	fn algorithm(&self) -> Algorithm {
		self.algorithm
	}
}

fn verify(
	scheme: AsymmetricScheme,
	pkey: &PKeyRef<Public>,
	msg: &[u8],
	signature: &[u8],
) -> Result<bool, ErrorStack> {
	match scheme {
		AsymmetricScheme::Ed25519 => Verifier::new_without_digest(pkey)?.verify_oneshot(signature, msg),
		AsymmetricScheme::RsaPkcs1(digest) => {
			let mut verifier = Verifier::new(digest, pkey)?;
			verifier.set_rsa_padding(Padding::PKCS1)?;
			verifier.verify_oneshot(signature, msg)
		},
		AsymmetricScheme::RsaPss(digest) => {
			let mut verifier = Verifier::new(digest, pkey)?;
			verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
			verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
			verifier.set_rsa_mgf1_md(digest)?;
			verifier.verify_oneshot(signature, msg)
		},
		AsymmetricScheme::Ecdsa {
			digest, scalar_len, ..
		} => {
			if signature.len() != 2 * scalar_len {
				return Ok(false);
			}
			let (r, s) = signature.split_at(scalar_len);
			let der = EcdsaSig::from_private_components(BigNum::from_slice(r)?, BigNum::from_slice(s)?)?
				.to_der()?;
			Verifier::new(digest, pkey)?.verify_oneshot(&der, msg)
		},
	}
}
