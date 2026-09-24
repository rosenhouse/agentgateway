//! This module adapts reqwest to the AWS SDK's `HttpClient`, so AWS requests use
//! the rustls process default that `crate::crypto::init` installs.
//! aws-smithy-http-client accepts a custom rustls provider only under
//! `--cfg aws_sdk_unstable`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_smithy_runtime_api::client::http::{
	HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpClient,
	SharedHttpConnector,
};
use aws_smithy_runtime_api::client::orchestrator::{HttpRequest, HttpResponse};
use aws_smithy_runtime_api::client::result::ConnectorError;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
use aws_smithy_types::body::SdkBody;

pub fn http_client() -> SharedHttpClient {
	SharedHttpClient::new(ReqwestHttpClient::default())
}

/// Holds the connect timeout and the read timeout, in that order.
type Timeouts = (Option<Duration>, Option<Duration>);

/// Keeps one connection pool per timeout configuration.
#[derive(Debug, Default)]
struct ReqwestHttpClient {
	connectors: Mutex<HashMap<Timeouts, SharedHttpConnector>>,
}

impl ReqwestHttpClient {
	fn connector(&self, settings: &HttpConnectorSettings) -> SharedHttpConnector {
		let key = (settings.connect_timeout(), settings.read_timeout());
		self
			.connectors
			.lock()
			.expect("lock poisoned")
			.entry(key)
			.or_insert_with(|| SharedHttpConnector::new(ReqwestConnector::new(settings)))
			.clone()
	}
}

impl HttpClient for ReqwestHttpClient {
	fn http_connector(
		&self,
		settings: &HttpConnectorSettings,
		_components: &RuntimeComponents,
	) -> SharedHttpConnector {
		self.connector(settings)
	}
}

#[derive(Debug)]
struct ReqwestConnector(Result<reqwest::Client, Arc<reqwest::Error>>);

impl ReqwestConnector {
	fn new(settings: &HttpConnectorSettings) -> Self {
		Self(client_builder(settings).build().map_err(Arc::new))
	}
}

fn client_builder(settings: &HttpConnectorSettings) -> reqwest::ClientBuilder {
	// Match aws-config's default client, which follows no redirects and reads
	// the proxy environment variables.
	let mut builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
	if let Some(timeout) = settings.connect_timeout() {
		builder = builder.connect_timeout(timeout);
	}
	if let Some(timeout) = settings.read_timeout() {
		builder = builder.read_timeout(timeout);
	}
	builder
}

impl HttpConnector for ReqwestConnector {
	fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
		let client = self.0.clone();
		HttpConnectorFuture::new(async move {
			let client = client.map_err(|e| ConnectorError::other(e.into(), None))?;
			let (parts, body) = request
				.try_into_http1x()
				.map_err(|e| ConnectorError::user(e.into()))?
				.into_parts();
			// Credential and metadata requests have in-memory bodies.
			let body = body
				.bytes()
				.ok_or_else(|| ConnectorError::user("streaming request bodies are not supported".into()))?
				.to_vec();
			let request = reqwest::Request::try_from(http::Request::from_parts(parts, body))
				.map_err(|e| ConnectorError::user(e.into()))?;

			let response = client.execute(request).await.map_err(connector_error)?;
			let mut builder = http::Response::builder().status(response.status());
			for (name, value) in response.headers() {
				builder = builder.header(name, value);
			}
			let body = response.bytes().await.map_err(connector_error)?;
			let response = builder
				.body(SdkBody::from(body))
				.map_err(|e| ConnectorError::other(e.into(), None))?;
			HttpResponse::try_from(response).map_err(|e| ConnectorError::other(e.into(), None))
		})
	}
}

fn connector_error(e: reqwest::Error) -> ConnectorError {
	if e.is_timeout() {
		ConnectorError::timeout(e.into())
	} else {
		ConnectorError::io(e.into())
	}
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use aws_smithy_runtime_api::client::http::{HttpConnector, HttpConnectorSettings};
	use aws_smithy_runtime_api::client::orchestrator::HttpRequest;
	use aws_smithy_types::body::SdkBody;
	use wiremock::matchers::{body_string, header, method, path};
	use wiremock::{Mock, MockServer, ResponseTemplate};

	use super::{ReqwestConnector, ReqwestHttpClient, client_builder};

	fn post(url: String) -> HttpRequest {
		HttpRequest::try_from(
			http::Request::post(url)
				.header("x-request", "1")
				.body(SdkBody::from("hello"))
				.unwrap(),
		)
		.unwrap()
	}

	#[tokio::test]
	async fn forwards_request_and_response() {
		crate::crypto::init();
		let server = MockServer::start().await;
		Mock::given(method("POST"))
			.and(path("/token"))
			.and(header("x-request", "1"))
			.and(body_string("hello"))
			.respond_with(
				ResponseTemplate::new(201)
					.insert_header("x-response", "2")
					.set_body_string("world"),
			)
			.mount(&server)
			.await;

		let connector = ReqwestConnector::new(&HttpConnectorSettings::builder().build());
		let response = connector
			.call(post(format!("{}/token", server.uri())))
			.await
			.expect("request succeeds");

		assert_eq!(response.status().as_u16(), 201);
		assert_eq!(response.headers().get("x-response"), Some("2"));
		assert_eq!(response.body().bytes(), Some(&b"world"[..]));
	}

	#[tokio::test]
	async fn returns_redirects_unfollowed() {
		crate::crypto::init();
		let server = MockServer::start().await;
		Mock::given(method("POST"))
			.respond_with(ResponseTemplate::new(302).insert_header("location", "/elsewhere"))
			.mount(&server)
			.await;

		let connector = ReqwestConnector::new(&HttpConnectorSettings::builder().build());
		let response = connector
			.call(post(server.uri()))
			.await
			.expect("request succeeds");
		assert_eq!(response.status().as_u16(), 302);
	}

	#[test]
	fn keeps_one_connector_per_timeout_pair() {
		crate::crypto::init();
		let client = ReqwestHttpClient::default();
		let short = HttpConnectorSettings::builder()
			.read_timeout(Duration::from_secs(1))
			.build();
		let long = HttpConnectorSettings::builder()
			.read_timeout(Duration::from_secs(2))
			.build();
		client.connector(&short);
		client.connector(&short);
		client.connector(&long);
		assert_eq!(client.connectors.lock().unwrap().len(), 2);
	}

	#[test]
	fn uses_proxy_environment_variables() {
		crate::crypto::init();
		let client = ReqwestConnector::new(&HttpConnectorSettings::builder().build())
			.0
			.unwrap();
		// reqwest offers no accessor; its Debug output lists the environment proxy matcher.
		assert!(format!("{client:?}").contains("proxies"), "{client:?}");
	}

	#[test]
	fn applies_connect_timeout() {
		let settings = HttpConnectorSettings::builder()
			.connect_timeout(Duration::from_millis(1500))
			.build();
		// Only the builder's Debug output lists the connect timeout.
		let builder = client_builder(&settings);
		assert!(
			format!("{builder:?}").contains("connect_timeout: 1.5s"),
			"{builder:?}"
		);
	}

	#[tokio::test]
	async fn applies_read_timeout() {
		crate::crypto::init();
		let server = MockServer::start().await;
		Mock::given(method("POST"))
			.respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
			.mount(&server)
			.await;

		let settings = HttpConnectorSettings::builder()
			.read_timeout(Duration::from_millis(100))
			.build();
		let err = ReqwestConnector::new(&settings)
			.call(post(server.uri()))
			.await
			.expect_err("the response is slower than the read timeout");
		assert!(err.is_timeout(), "{err:?}");
	}
}
