//! Central cryptography module.
//!
//! Policy: all cryptographic operations in agentgateway SHOULD go through this
//! module so that the underlying crypto backend is pluggable and auditable. The
//! active backend is selected at compile time via `crypto-*` features (see
//! [`CRYPTO_BACKEND`]).
//!
//! Some operations cannot yet be routed through a pluggable backend (for
//! example legacy password hashing).
//! Such documented exceptions must be guarded with the appropriate
//! `#[cfg(feature = ...)]` so the backend in use stays explicit.

// Exactly one crypto backend must be selected at compile time. `fips` is an
// operating-mode modifier rather than a backend; it supports AWS-LC and BoringSSL.
#[cfg(not(any(
	feature = "crypto-aws-lc",
	feature = "crypto-symcrypt",
	feature = "crypto-boring"
)))]
compile_error!(
	"no crypto backend selected: enable exactly one of `crypto-aws-lc`, `crypto-symcrypt` or `crypto-boring`"
);

#[cfg(any(
	all(feature = "crypto-aws-lc", feature = "crypto-symcrypt"),
	all(feature = "crypto-aws-lc", feature = "crypto-boring"),
	all(feature = "crypto-symcrypt", feature = "crypto-boring"),
))]
compile_error!(
	"multiple crypto backends selected: enable exactly one of `crypto-aws-lc`, `crypto-symcrypt` or `crypto-boring` (pass --no-default-features for a non-default backend)"
);

#[cfg(all(
	feature = "fips",
	not(any(feature = "crypto-aws-lc", feature = "crypto-boring"))
))]
compile_error!("`fips` requires the `crypto-aws-lc` or `crypto-boring` backend");

pub mod aead;
pub mod digest;
pub mod jwt;
pub mod rand;
pub mod tls;
pub mod x509;

pub use tls::{provider, provider_with_options_validated};

/// Initializes process-global crypto state for the compiled-in backend.
///
/// Call once at startup, before building HTTP clients or using [`jwt`].
pub fn init() {
	// reqwest and google-cloud-auth have no rustls provider of their own in this
	// build.
	#[cfg(feature = "crypto-boring")]
	tls::install_process_default();
	jwt::init();
	// A FIPS build must actually be in FIPS mode. Fail closed rather than serve
	// traffic with a provider that only claims to be.
	#[cfg(feature = "fips")]
	tls::assert_fips_provider();
}

/// Human-readable name of the crypto backend compiled into this binary. Useful
/// for startup logging and diagnostics.
#[cfg(all(feature = "crypto-aws-lc", not(feature = "fips")))]
pub const CRYPTO_BACKEND: &str = "aws-lc-rs";

#[cfg(all(feature = "crypto-aws-lc", feature = "fips"))]
pub const CRYPTO_BACKEND: &str = "aws-lc-rs-fips";

#[cfg(feature = "crypto-symcrypt")]
pub const CRYPTO_BACKEND: &str = "symcrypt";

#[cfg(all(feature = "crypto-boring", not(feature = "fips")))]
pub const CRYPTO_BACKEND: &str = "boringssl";

#[cfg(all(feature = "crypto-boring", feature = "fips"))]
pub const CRYPTO_BACKEND: &str = "boringssl-fips";
