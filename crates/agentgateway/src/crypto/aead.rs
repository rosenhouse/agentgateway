//! Authenticated encryption (AEAD) primitives.
//!
//! This is the single seam through which agentgateway performs symmetric
//! authenticated encryption. The backend is selected by the `crypto-*` feature;
//! `crypto-aws-lc` (the default) backs it with `aws-lc-rs`. Additional backends
//! plug in here behind `#[cfg]` without changing call sites.

/// Length in bytes of the AES-256-GCM nonce that [`Aes256Gcm::seal`] prepends to
/// each sealed message.
const NONCE_LEN: usize = 12;

pub use imp::Aes256Gcm;

#[cfg(feature = "crypto-aws-lc")]
mod imp {
	use aws_lc_rs::aead::{AES_256_GCM, Aad, Nonce, RandomizedNonceKey};

	use super::{AeadError, NONCE_LEN};

	/// AES-256-GCM authenticated encryption keyed with a caller-provided 32-byte key.
	///
	/// [`seal`](Aes256Gcm::seal) generates a fresh random nonce per message and
	/// returns `nonce || ciphertext || tag`; [`open`](Aes256Gcm::open) expects that
	/// same framing.
	#[derive(Debug)]
	pub struct Aes256Gcm {
		key: RandomizedNonceKey,
	}

	impl Aes256Gcm {
		/// Creates an AES-256-GCM key from 32 bytes of key material.
		pub fn new(key: &[u8]) -> Result<Self, AeadError> {
			let key = RandomizedNonceKey::new(&AES_256_GCM, key).map_err(|_| AeadError::InvalidKey)?;
			Ok(Self { key })
		}

		/// Seals `plaintext`, returning `nonce || ciphertext || tag`.
		pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, AeadError> {
			let mut in_out = plaintext.to_vec();
			// Generates a random nonce and appends the authentication tag in place.
			let nonce = self
				.key
				.seal_in_place_append_tag(Aad::empty(), &mut in_out)
				.map_err(|_| AeadError::EncryptionFailed)?;

			let mut result = nonce.as_ref().to_vec();
			result.extend_from_slice(&in_out);
			Ok(result)
		}

		/// Opens data framed as `nonce || ciphertext || tag`, returning the plaintext.
		pub fn open(&self, data: &[u8]) -> Result<Vec<u8>, AeadError> {
			if data.len() < NONCE_LEN {
				return Err(AeadError::InvalidFormat);
			}

			let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
			let nonce =
				Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| AeadError::InvalidFormat)?;
			let mut in_out = ciphertext.to_vec();
			let plaintext = self
				.key
				.open_in_place(nonce, Aad::empty(), &mut in_out)
				.map_err(|_| AeadError::DecryptionFailed)?;
			Ok(plaintext.to_vec())
		}
	}
}

#[cfg(feature = "crypto-symcrypt")]
mod imp {
	use super::{AeadError, NONCE_LEN};

	/// AES-256-GCM authentication tag length in bytes.
	const TAG_LEN: usize = 16;
	/// AES-256 key length in bytes.
	const KEY_LEN: usize = 32;

	/// AES-256-GCM authenticated encryption backed by SymCrypt. The wire format
	/// (`nonce || ciphertext || tag`) matches the aws-lc-rs backend.
	pub struct Aes256Gcm {
		key: symcrypt::gcm::GcmExpandedKey,
	}

	impl Aes256Gcm {
		/// Creates an AES-256-GCM key from 32 bytes of key material.
		pub fn new(key: &[u8]) -> Result<Self, AeadError> {
			if key.len() != KEY_LEN {
				return Err(AeadError::InvalidKey);
			}
			let key =
				symcrypt::gcm::GcmExpandedKey::new(key, symcrypt::cipher::BlockCipherType::AesBlock)
					.map_err(|_| AeadError::InvalidKey)?;
			Ok(Self { key })
		}

		/// Seals `plaintext`, returning `nonce || ciphertext || tag`.
		pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, AeadError> {
			let mut nonce = [0u8; NONCE_LEN];
			crate::crypto::rand::fill(&mut nonce).map_err(|_| AeadError::EncryptionFailed)?;
			let mut buffer = plaintext.to_vec();
			let mut tag = [0u8; TAG_LEN];
			self
				.key
				.encrypt_in_place(&nonce, &[], &mut buffer, &mut tag);
			let mut result = Vec::with_capacity(NONCE_LEN + buffer.len() + TAG_LEN);
			result.extend_from_slice(&nonce);
			result.extend_from_slice(&buffer);
			result.extend_from_slice(&tag);
			Ok(result)
		}

		/// Opens data framed as `nonce || ciphertext || tag`, returning the plaintext.
		pub fn open(&self, data: &[u8]) -> Result<Vec<u8>, AeadError> {
			if data.len() < NONCE_LEN + TAG_LEN {
				return Err(AeadError::InvalidFormat);
			}
			let (nonce_bytes, rest) = data.split_at(NONCE_LEN);
			let (ciphertext, tag) = rest.split_at(rest.len() - TAG_LEN);
			let nonce: &[u8; NONCE_LEN] = nonce_bytes
				.try_into()
				.map_err(|_| AeadError::InvalidFormat)?;
			let mut buffer = ciphertext.to_vec();
			self
				.key
				.decrypt_in_place(nonce, &[], &mut buffer, tag)
				.map_err(|_| AeadError::DecryptionFailed)?;
			Ok(buffer)
		}
	}

	// GcmExpandedKey does not implement Debug; provide a redacted impl matching the
	// derived Debug on the aws-lc-rs backend.
	impl std::fmt::Debug for Aes256Gcm {
		fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
			f.debug_struct("Aes256Gcm").finish_non_exhaustive()
		}
	}
}

#[cfg(feature = "crypto-boring")]
mod imp {
	use boring::aead::{AeadCtx, Algorithm};

	use super::{AeadError, NONCE_LEN};

	const TAG_LEN: usize = 16;

	/// AES-256-GCM backed by BoringSSL.
	///
	/// Sealing uses `EVP_aead_aes_256_gcm_randnonce`, which generates the nonce
	/// inside the FIPS module, as FIPS 140-3 requires for an approved seal. It
	/// emits `ciphertext || tag || nonce`; this type converts to and from the
	/// shared `nonce || ciphertext || tag` framing.
	pub struct Aes256Gcm {
		ctx: AeadCtx,
	}

	impl Aes256Gcm {
		/// Creates an AES-256-GCM key from 32 bytes of key material.
		pub fn new(key: &[u8]) -> Result<Self, AeadError> {
			// SAFETY: the function returns a pointer to a static `EVP_AEAD`.
			let algorithm = unsafe { Algorithm::from_ptr(boring_sys::EVP_aead_aes_256_gcm_randnonce()) };
			let ctx = AeadCtx::new_default_tag(&algorithm, key).map_err(|_| AeadError::InvalidKey)?;
			Ok(Self { ctx })
		}

		/// Seals `plaintext`, returning `nonce || ciphertext || tag`.
		pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, AeadError> {
			let mut buffer = plaintext.to_vec();
			let mut tag_and_nonce = [0u8; TAG_LEN + NONCE_LEN];
			let written = self
				.ctx
				.seal_in_place(&[], &mut buffer, &mut tag_and_nonce, &[])
				.map_err(|_| AeadError::EncryptionFailed)?;
			if written.len() != TAG_LEN + NONCE_LEN {
				return Err(AeadError::EncryptionFailed);
			}
			let (tag, nonce) = tag_and_nonce.split_at(TAG_LEN);
			let mut result = Vec::with_capacity(NONCE_LEN + buffer.len() + TAG_LEN);
			result.extend_from_slice(nonce);
			result.extend_from_slice(&buffer);
			result.extend_from_slice(tag);
			Ok(result)
		}

		/// Opens data framed as `nonce || ciphertext || tag`, returning the plaintext.
		pub fn open(&self, data: &[u8]) -> Result<Vec<u8>, AeadError> {
			if data.len() < NONCE_LEN + TAG_LEN {
				return Err(AeadError::InvalidFormat);
			}
			let (nonce, rest) = data.split_at(NONCE_LEN);
			let (ciphertext, tag) = rest.split_at(rest.len() - TAG_LEN);
			let mut tag_and_nonce = [0u8; TAG_LEN + NONCE_LEN];
			tag_and_nonce[..TAG_LEN].copy_from_slice(tag);
			tag_and_nonce[TAG_LEN..].copy_from_slice(nonce);
			let mut buffer = ciphertext.to_vec();
			self
				.ctx
				.open_in_place(&[], &mut buffer, &tag_and_nonce, &[])
				.map_err(|_| AeadError::DecryptionFailed)?;
			Ok(buffer)
		}
	}

	impl std::fmt::Debug for Aes256Gcm {
		fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
			f.debug_struct("Aes256Gcm").finish_non_exhaustive()
		}
	}
}

#[derive(Debug, thiserror::Error)]
pub enum AeadError {
	#[error("invalid key")]
	InvalidKey,
	#[error("encryption failed")]
	EncryptionFailed,
	#[error("decryption failed")]
	DecryptionFailed,
	#[error("invalid format")]
	InvalidFormat,
}

#[cfg(test)]
mod tests {
	use super::{AeadError, Aes256Gcm};

	#[test]
	fn round_trip() {
		let key = Aes256Gcm::new(&[7u8; 32]).expect("key");
		let sealed = key.seal(b"hello world").expect("seal");
		assert_ne!(sealed, b"hello world");
		assert_eq!(key.open(&sealed).expect("open"), b"hello world");
	}

	// This is test case 15 of the GCM specification, framed as `nonce || ciphertext || tag`.
	// Every backend must open data sealed by any other.
	#[test]
	fn opens_standard_gcm_framing() {
		let key =
			hex::decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308").expect("key");
		let sealed = hex::decode(concat!(
			"cafebabefacedbaddecaf888",
			"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa",
			"8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
			"b094dac5d93471bdec1a502270e3cc6c",
		))
		.expect("sealed");
		let plaintext = hex::decode(concat!(
			"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
			"1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
		))
		.expect("plaintext");
		let key = Aes256Gcm::new(&key).expect("key");
		assert_eq!(key.open(&sealed).expect("open"), plaintext);
	}

	#[test]
	fn short_input_fails_cleanly() {
		let key = Aes256Gcm::new(&[0u8; 32]).expect("key");
		assert!(matches!(
			key.open(&[0u8; 11]),
			Err(AeadError::InvalidFormat)
		));
	}

	#[test]
	fn tampered_ciphertext_fails() {
		let key = Aes256Gcm::new(&[1u8; 32]).expect("key");
		let mut sealed = key.seal(b"secret").expect("seal");
		let last = sealed.len() - 1;
		sealed[last] ^= 0xff;
		assert!(matches!(
			key.open(&sealed),
			Err(AeadError::DecryptionFailed)
		));
	}

	#[test]
	fn wrong_key_fails() {
		let sealed = Aes256Gcm::new(&[1u8; 32])
			.expect("key")
			.seal(b"x")
			.expect("seal");
		let other = Aes256Gcm::new(&[2u8; 32]).expect("key");
		assert!(matches!(
			other.open(&sealed),
			Err(AeadError::DecryptionFailed)
		));
	}
}
