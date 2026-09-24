use std::time::Duration;

use anyhow::Context;
use sqlx::postgres::PgPoolOptions;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{PgPool, SqlitePool};

#[derive(Clone, Debug)]
pub enum DatabasePool {
	Sqlite(SqlitePool),
	Postgres(PgPool),
}

/// Default pool size when `maxConnections` is not set in config.
const DEFAULT_MAX_CONNECTIONS: u32 = 5;

impl DatabasePool {
	pub async fn connect(url: &str) -> anyhow::Result<Self> {
		Self::connect_with_max_connections(url, None).await
	}

	pub async fn connect_with_max_connections(
		url: &str,
		max_connections: Option<u32>,
	) -> anyhow::Result<Self> {
		let max_connections = max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS);
		anyhow::ensure!(
			max_connections > 0,
			"database maxConnections must be greater than zero"
		);
		if url.starts_with("postgres://") || url.starts_with("postgresql://") {
			#[cfg(feature = "crypto-boring")]
			require_plaintext_postgres(url)?;
			let pool = PgPoolOptions::new()
				.max_connections(max_connections)
				.connect(url)
				.await
				.context("failed to connect postgres database")?;
			return Ok(Self::Postgres(pool));
		}

		let options = url
			.parse::<SqliteConnectOptions>()
			.context("failed to parse sqlite database URL")?
			.create_if_missing(true)
			.journal_mode(SqliteJournalMode::Wal)
			.synchronous(SqliteSynchronous::Normal)
			.busy_timeout(Duration::from_secs(5));
		let pool = SqlitePoolOptions::new()
			.max_connections(max_connections)
			.connect_with(options)
			.await
			.context("failed to connect sqlite database")?;
		Ok(Self::Sqlite(pool))
	}
}

/// This build has no Postgres TLS. sqlx's default `sslmode=prefer` would then
/// fall back to plaintext silently, so plaintext must be requested explicitly.
#[cfg(feature = "crypto-boring")]
fn require_plaintext_postgres(url: &str) -> anyhow::Result<()> {
	use sqlx::postgres::{PgConnectOptions, PgSslMode};
	let options: PgConnectOptions = url
		.parse()
		.context("failed to parse postgres database URL")?;
	anyhow::ensure!(
		matches!(options.get_ssl_mode(), PgSslMode::Disable),
		"this build has no Postgres TLS support; set sslmode=disable to connect without TLS"
	);
	Ok(())
}

#[cfg(all(test, feature = "crypto-boring"))]
mod tests {
	use super::{DatabasePool, require_plaintext_postgres};

	#[tokio::test]
	async fn postgres_requires_explicit_plaintext() {
		// The explicit `prefer` overrides any PGSSLMODE in the environment.
		let err = DatabasePool::connect("postgres://user@127.0.0.1:1/db?sslmode=prefer")
			.await
			.expect_err("TLS is unavailable");
		assert!(format!("{err:#}").contains("sslmode=disable"), "{err:#}");
		require_plaintext_postgres("postgres://user@127.0.0.1:1/db?sslmode=require")
			.expect_err("TLS is unavailable");
		require_plaintext_postgres("postgres://user@127.0.0.1:1/db?sslmode=disable")
			.expect("plaintext was requested");
	}
}
