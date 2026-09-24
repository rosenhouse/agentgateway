//! JWT crypto seam.
//!
//! JWT crypto lives inside the `jsonwebtoken` crate, which routes its
//! `encode`/`decode` through its own process-global provider. Rather than
//! wrapping those calls, this module just selects which provider is active for
//! the compiled-in `crypto-*` backend, via [`init`].

#[cfg(feature = "crypto-boring")]
mod boringssl;

/// Installs the process-global JWT crypto provider for the compiled-in backend.
///
/// Call once at startup, before any JWT signing or verification. Idempotent.
pub fn init() {
	// SymCrypt has no jsonwebtoken provider, so `crypto-symcrypt` falls back to
	// aws-lc-rs here.
	#[cfg(any(feature = "crypto-aws-lc", feature = "crypto-symcrypt"))]
	{
		let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
	}
	#[cfg(feature = "crypto-boring")]
	{
		let _ = boringssl::PROVIDER.install_default();
	}
}

#[cfg(test)]
mod tests {
	use base64::Engine;
	use base64::engine::general_purpose::URL_SAFE_NO_PAD;
	use jsonwebtoken::crypto::verify;
	use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};

	// This is jsonwebtoken's tests/eddsa/private_ed25519_key.pk8. BoringSSL
	// rejects the PKCS#8 v2 keys that rcgen generates.
	const ED25519_PKCS8_V1: &[u8] = &[
		0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
		0x6a, 0xc3, 0xfd, 0xee, 0xee, 0x29, 0x8a, 0x92, 0x63, 0x8b, 0x70, 0x0c, 0x4b, 0x11, 0x7c, 0xc3,
		0x2e, 0x2d, 0x2a, 0xce, 0x0d, 0xfd, 0x78, 0x76, 0x94, 0xe2, 0x4c, 0xae, 0x8a, 0xd5, 0x82, 0x34,
	];
	const ED25519_PUBLIC_X: &str = "2-Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8";

	// BoringSSL's FIPS module has no Ed25519.
	const EDDSA_AVAILABLE: bool = !cfg!(all(feature = "crypto-boring", feature = "fips"));

	const RFC8037_PUBLIC_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
	const RFC8037_MESSAGE: &str = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
	const RFC8037_SIGNATURE: &str =
		"hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

	const RFC7515_PAYLOAD: &str = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

	// RFC 7515 A.1 (HS256), A.3 (ES256) and RFC 8037 A.4 (EdDSA) were signed by
	// other implementations, so they pin the wire format of each signature.
	#[test]
	fn verifies_rfc_known_answers() {
		super::init();
		let hs256 = DecodingKey::from_secret(
			&URL_SAFE_NO_PAD
				.decode(
					"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
				)
				.unwrap(),
		);
		let es256 = DecodingKey::from_ec_components(
			"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
			"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
		)
		.unwrap();
		let eddsa = DecodingKey::from_ed_components(RFC8037_PUBLIC_X).unwrap();
		let mut cases = vec![
			(
				Algorithm::HS256,
				&hs256,
				format!("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.{RFC7515_PAYLOAD}"),
				"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			),
			(
				Algorithm::ES256,
				&es256,
				format!("eyJhbGciOiJFUzI1NiJ9.{RFC7515_PAYLOAD}"),
				"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q",
			),
		];
		if EDDSA_AVAILABLE {
			cases.push((
				Algorithm::EdDSA,
				&eddsa,
				RFC8037_MESSAGE.to_string(),
				RFC8037_SIGNATURE,
			));
		}
		for (alg, key, message, signature) in cases {
			assert!(
				verify(signature, message.as_bytes(), key, alg).unwrap(),
				"{alg:?}"
			);
			let altered = message.replace("eyJ", "eyK");
			assert!(
				!verify(signature, altered.as_bytes(), key, alg).unwrap_or(false),
				"{alg:?} must reject an altered message"
			);
		}
	}

	#[test]
	fn signs_and_verifies_every_algorithm() {
		super::init();
		let rsa = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
		let p256 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
		let p384 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
		let rsa_keys = || {
			(
				EncodingKey::from_rsa_pem(rsa.serialize_pem().as_bytes()).unwrap(),
				DecodingKey::from_rsa_pem(rsa.public_key_pem().as_bytes()).unwrap(),
			)
		};
		let ec_keys = |kp: &rcgen::KeyPair| {
			(
				EncodingKey::from_ec_pem(kp.serialize_pem().as_bytes()).unwrap(),
				DecodingKey::from_ec_pem(kp.public_key_pem().as_bytes()).unwrap(),
			)
		};
		let hmac_keys = || {
			(
				EncodingKey::from_secret(b"shared secret"),
				DecodingKey::from_secret(b"shared secret"),
			)
		};
		let mut cases = vec![
			(Algorithm::HS256, hmac_keys()),
			(Algorithm::HS384, hmac_keys()),
			(Algorithm::HS512, hmac_keys()),
			(Algorithm::RS256, rsa_keys()),
			(Algorithm::RS384, rsa_keys()),
			(Algorithm::RS512, rsa_keys()),
			(Algorithm::PS256, rsa_keys()),
			(Algorithm::PS384, rsa_keys()),
			(Algorithm::PS512, rsa_keys()),
			(Algorithm::ES256, ec_keys(&p256)),
			(Algorithm::ES384, ec_keys(&p384)),
		];
		if EDDSA_AVAILABLE {
			cases.push((
				Algorithm::EdDSA,
				(
					EncodingKey::from_ed_der(ED25519_PKCS8_V1),
					DecodingKey::from_ed_components(ED25519_PUBLIC_X).unwrap(),
				),
			));
		}
		let claims = serde_json::json!({"sub": "test", "exp": 4_102_444_800u64});
		for (alg, (encoding, decoding)) in cases {
			let token = encode(&Header::new(alg), &claims, &encoding)
				.unwrap_or_else(|e| panic!("{alg:?}: sign: {e}"));
			let validation = Validation::new(alg);
			let decoded = decode::<serde_json::Value>(&token, &decoding, &validation)
				.unwrap_or_else(|e| panic!("{alg:?}: verify: {e}"));
			assert_eq!(decoded.claims, claims);

			let (signing_input, encoded) = token.rsplit_once('.').unwrap();
			let signature = URL_SAFE_NO_PAD.decode(encoded).unwrap();
			let mut flipped = signature.clone();
			flipped[0] ^= 1;
			// For ECDSA this is `r || 00 || s`, which verifies unless the length is checked.
			let mut padded = signature.clone();
			padded.insert(signature.len() / 2, 0);
			let truncated = signature[..8].to_vec();
			for forged in [flipped, padded, truncated] {
				let forged = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(&forged));
				assert!(
					decode::<serde_json::Value>(&forged, &decoding, &validation).is_err(),
					"{alg:?}: a forged signature must be rejected"
				);
			}
		}
	}

	#[test]
	fn rejects_a_key_on_the_wrong_curve() {
		super::init();
		let p384 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
		let encoding = EncodingKey::from_ec_pem(p384.serialize_pem().as_bytes()).unwrap();
		let claims = serde_json::json!({"sub": "test"});
		assert!(encode(&Header::new(Algorithm::ES256), &claims, &encoding).is_err());
	}

	#[test]
	fn rejects_rsa_keys_under_2048_bits() {
		super::init();
		let private = include_bytes!("testdata/rsa1024.pem");
		let public = include_bytes!("testdata/rsa1024.pub.pem");
		let claims = serde_json::json!({"sub": "test"});
		let encoding = EncodingKey::from_rsa_pem(private).unwrap();
		assert!(encode(&Header::new(Algorithm::RS256), &claims, &encoding).is_err());
		// `openssl dgst -sha256 -sign testdata/rsa1024.pem` signed `message`.
		let message = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0";
		let signature = "1AyKP07T4HMuxK8HnDLSmiapHemjYr_h6JfQvPjVJFVc_fppdcbwtlQmWEewTXIQE2mdJIZuRjovy45dW-Qu1lKX41gwvL58N_AZ3q5Sva7R6tydOFXSjRN0LwzanGMS1KdnkNgfQAuoErKZUXnMEifzAr8Disdei9gFnKB87ck";
		let decoding = DecodingKey::from_rsa_pem(public).unwrap();
		assert!(!verify(signature, message.as_bytes(), &decoding, Algorithm::RS256).unwrap_or(false));
	}

	#[cfg(not(all(feature = "crypto-boring", feature = "fips")))]
	#[test]
	fn rejects_ed25519_keys_of_the_wrong_length() {
		super::init();
		let mut x = URL_SAFE_NO_PAD.decode(RFC8037_PUBLIC_X).unwrap();
		x.push(0);
		let key = DecodingKey::from_ed_components(&URL_SAFE_NO_PAD.encode(x)).unwrap();
		let message = RFC8037_MESSAGE.as_bytes();
		assert!(!verify(RFC8037_SIGNATURE, message, &key, Algorithm::EdDSA).unwrap_or(false));
	}

	#[cfg(all(feature = "crypto-boring", feature = "fips"))]
	#[test]
	fn rejects_eddsa_in_fips_mode() {
		super::init();
		let key = DecodingKey::from_ed_components(RFC8037_PUBLIC_X).unwrap();
		let message = RFC8037_MESSAGE.as_bytes();
		let err = verify(RFC8037_SIGNATURE, message, &key, Algorithm::EdDSA)
			.expect_err("EdDSA must be unavailable");
		assert_eq!(
			err.kind(),
			&jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
		);
	}
}
