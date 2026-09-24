// Only the BoringSSL backend installs a rustls process default. This test has
// its own binary because that default is process-global.
#![cfg(feature = "crypto-boring")]

#[test]
#[allow(clippy::disallowed_methods, clippy::disallowed_fields)]
fn init_installs_process_default_tls_provider() {
	agentgateway::crypto::init();
	let installed =
		rustls::crypto::CryptoProvider::get_default().expect("init must install a default provider");
	let expected = agentgateway::crypto::provider();
	assert_eq!(installed.cipher_suites, expected.cipher_suites);
	let names = |p: &rustls::crypto::CryptoProvider| -> Vec<_> {
		p.kx_groups.iter().map(|g| g.name()).collect()
	};
	assert_eq!(names(installed), names(&expected));
}
