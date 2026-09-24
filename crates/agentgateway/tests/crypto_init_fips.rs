// This test has its own binary because the rustls process default is
// process-global.
#![cfg(feature = "fips")]

use std::sync::Arc;

use agentgateway::transport::tls::KeyExchangeGroup;
use rustls::crypto::CryptoProvider;

#[test]
#[should_panic(expected = "does not operate in FIPS mode")]
#[allow(clippy::disallowed_fields)]
fn init_rejects_a_non_fips_process_default() {
	let mut non_fips = Arc::unwrap_or_clone(agentgateway::crypto::provider());
	non_fips
		.kx_groups
		.push(KeyExchangeGroup::X25519.to_supported_kx_group());
	CryptoProvider::install_default(non_fips).unwrap();
	agentgateway::crypto::init();
}
