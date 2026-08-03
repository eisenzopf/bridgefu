//! Durable Amazon Connect StopContact ownership.
//!
//! A successful StartWebRTCContact is not allowed to proceed into media setup
//! until its exact cleanup authority is committed here. Resolution is deleted
//! only after StopContact succeeds (including the provider's already-ended
//! response class). Values are deliberately absent from Debug and diagnostics.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use rvoip_amazon_connect::{
    AmazonConnectAdapter, AmazonConnectCleanupObserver, ConnectError, ConnectProfileId,
    RetainedAmazonConnectCleanup, AMAZON_CONNECT_CONTACT_REFERENCE_KIND,
};
use rvoip_core::adapter::ExternalConnectionReference;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::Row;
use tokio::sync::{watch, Mutex};

use crate::call_service::CallRepositoryBackendConfig;

const SQLITE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS amazon_connect_cleanup_authority (
    profile_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    contact_id TEXT NOT NULL,
    retained_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (profile_id, instance_id, contact_id)
)
"#;

const POSTGRES_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS amazon_connect_cleanup_authority (
    profile_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    contact_id TEXT NOT NULL,
    retained_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (profile_id, instance_id, contact_id)
)
"#;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct CleanupKey {
    profile_id: String,
    instance_id: String,
    contact_id: String,
}

impl CleanupKey {
    fn from_cleanup(cleanup: &RetainedAmazonConnectCleanup) -> Self {
        Self {
            profile_id: cleanup.profile_id().as_str().to_owned(),
            instance_id: cleanup.instance_id().to_owned(),
            contact_id: cleanup.contact_id().to_owned(),
        }
    }

    fn into_cleanup(self) -> Result<RetainedAmazonConnectCleanup, ConnectError> {
        let profile_id = ConnectProfileId::new(self.profile_id)
            .map_err(|_| ConnectError::Control("durable cleanup profile is invalid".into()))?;
        RetainedAmazonConnectCleanup::new(profile_id, self.instance_id, self.contact_id)
    }
}

impl fmt::Debug for CleanupKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CleanupKey")
            .field("profile_id", &"[redacted]")
            .field("instance_id", &"[redacted]")
            .field("contact_id", &"[redacted]")
            .finish()
    }
}

enum CleanupBackend {
    Memory(Mutex<BTreeMap<CleanupKey, RetainedAmazonConnectCleanup>>),
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

/// Process-wide journal installed into each Amazon adapter before admission.
pub struct AmazonCleanupJournal {
    backend: CleanupBackend,
}

impl fmt::Debug for AmazonCleanupJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let backend = match &self.backend {
            CleanupBackend::Memory(_) => "memory",
            CleanupBackend::Sqlite(_) => "sqlite",
            CleanupBackend::Postgres(_) => "postgres",
        };
        formatter
            .debug_struct("AmazonCleanupJournal")
            .field("backend", &backend)
            .finish()
    }
}

impl AmazonCleanupJournal {
    /// Open the same durable backend selected for call state. SQL setup is
    /// idempotent so the frozen ReferenceTenant-only configuration also gains
    /// cleanup durability when the generic call API is disabled.
    pub async fn connect(config: CallRepositoryBackendConfig) -> anyhow::Result<Arc<Self>> {
        let backend = match &config {
            CallRepositoryBackendConfig::Memory => {
                CleanupBackend::Memory(Mutex::new(BTreeMap::new()))
            }
            CallRepositoryBackendConfig::Sqlite { database_url } => {
                let options = SqliteConnectOptions::from_str(database_url)?
                    .create_if_missing(true)
                    .foreign_keys(true)
                    .busy_timeout(std::time::Duration::from_secs(5));
                let pool = SqlitePoolOptions::new()
                    .max_connections(2)
                    .connect_with(options)
                    .await?;
                sqlx::query(SQLITE_SCHEMA).execute(&pool).await?;
                CleanupBackend::Sqlite(pool)
            }
            CallRepositoryBackendConfig::Postgres { database_url } => {
                let pool = PgPoolOptions::new()
                    .max_connections(2)
                    .connect(database_url)
                    .await?;
                sqlx::query(POSTGRES_SCHEMA).execute(&pool).await?;
                CleanupBackend::Postgres(pool)
            }
        };
        Ok(Arc::new(Self { backend }))
    }

    pub async fn pending(&self) -> anyhow::Result<Vec<RetainedAmazonConnectCleanup>> {
        let keys = match &self.backend {
            CleanupBackend::Memory(records) => {
                return Ok(records.lock().await.values().cloned().collect());
            }
            CleanupBackend::Sqlite(pool) => {
                sqlx::query(
                    "SELECT profile_id, instance_id, contact_id FROM amazon_connect_cleanup_authority ORDER BY retained_at, profile_id, instance_id, contact_id",
                )
                .fetch_all(pool)
                .await?
                .into_iter()
                .map(|row| CleanupKey {
                    profile_id: row.get("profile_id"),
                    instance_id: row.get("instance_id"),
                    contact_id: row.get("contact_id"),
                })
                .collect::<Vec<_>>()
            }
            CleanupBackend::Postgres(pool) => {
                sqlx::query(
                    "SELECT profile_id, instance_id, contact_id FROM amazon_connect_cleanup_authority ORDER BY retained_at, profile_id, instance_id, contact_id",
                )
                .fetch_all(pool)
                .await?
                .into_iter()
                .map(|row| CleanupKey {
                    profile_id: row.get("profile_id"),
                    instance_id: row.get("instance_id"),
                    contact_id: row.get("contact_id"),
                })
                .collect::<Vec<_>>()
            }
        };
        keys.into_iter()
            .map(CleanupKey::into_cleanup)
            .collect::<Result<Vec<_>, _>>()
            .map_err(anyhow::Error::from)
    }

    /// Reconcile contacts retained by a previous process incarnation before
    /// new admission. Failures remain durable and are reported only by count.
    pub async fn reconcile(
        self: &Arc<Self>,
        adapter: &Arc<AmazonConnectAdapter>,
    ) -> anyhow::Result<AmazonCleanupReconcileReport> {
        let records = self.pending().await?;
        let attempted = records.len();
        let mut resolved = 0usize;
        for cleanup in records {
            let reference = ExternalConnectionReference::new(
                AMAZON_CONNECT_CONTACT_REFERENCE_KIND,
                cleanup.contact_id().to_owned(),
            )
            .map_err(|_| anyhow::anyhow!("durable Amazon cleanup contact is invalid"))?;
            if adapter
                .stop_persisted_contact(cleanup.profile_id(), cleanup.instance_id(), &reference)
                .await
                .is_ok()
            {
                resolved += 1;
            }
        }
        Ok(AmazonCleanupReconcileReport {
            attempted,
            resolved,
            remaining: self.pending().await?.len(),
        })
    }

    /// Own periodic recovery until the process-wide shutdown boundary. The
    /// caller retains and joins the returned task; failures leave rows intact
    /// and expose only aggregate counts.
    pub fn spawn_reconciler(
        self: &Arc<Self>,
        adapter: Arc<AmazonConnectAdapter>,
        mut shutdown: watch::Receiver<bool>,
        interval: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        let journal = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            // Startup performs one synchronous reconciliation before public
            // admission, so the periodic owner waits a full interval first.
            tick.tick().await;
            loop {
                tokio::select! {
                    biased;
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                    _ = tick.tick() => {
                        match journal.reconcile(&adapter).await {
                            Ok(report) => {
                                metrics::gauge!("bridgefu_amazon_durable_cleanups_pending")
                                    .set(report.remaining as f64);
                                if report.attempted > 0 {
                                    tracing::info!(
                                        attempted = report.attempted,
                                        resolved = report.resolved,
                                        remaining = report.remaining,
                                        "reconciled durable Amazon cleanup authority"
                                    );
                                }
                            }
                            Err(_) => {
                                metrics::counter!("bridgefu_amazon_cleanup_reconcile_failures_total")
                                    .increment(1);
                                tracing::warn!("durable Amazon cleanup reconciliation failed");
                            }
                        }
                    }
                }
            }
        })
    }

    async fn retain(&self, cleanup: RetainedAmazonConnectCleanup) -> Result<(), ConnectError> {
        let key = CleanupKey::from_cleanup(&cleanup);
        match &self.backend {
            CleanupBackend::Memory(records) => {
                records.lock().await.insert(key, cleanup);
                Ok(())
            }
            CleanupBackend::Sqlite(pool) => sqlx::query(
                "INSERT INTO amazon_connect_cleanup_authority (profile_id, instance_id, contact_id) VALUES (?, ?, ?) ON CONFLICT(profile_id, instance_id, contact_id) DO NOTHING",
            )
            .bind(key.profile_id)
            .bind(key.instance_id)
            .bind(key.contact_id)
            .execute(pool)
            .await
            .map(|_| ())
            .map_err(|_| {
                ConnectError::Control("durable Amazon cleanup journal unavailable".into())
            }),
            CleanupBackend::Postgres(pool) => sqlx::query(
                "INSERT INTO amazon_connect_cleanup_authority (profile_id, instance_id, contact_id) VALUES ($1, $2, $3) ON CONFLICT(profile_id, instance_id, contact_id) DO NOTHING",
            )
            .bind(key.profile_id)
            .bind(key.instance_id)
            .bind(key.contact_id)
            .execute(pool)
            .await
            .map(|_| ())
            .map_err(|_| {
                ConnectError::Control("durable Amazon cleanup journal unavailable".into())
            }),
        }
    }

    async fn resolve(&self, cleanup: RetainedAmazonConnectCleanup) -> Result<(), ConnectError> {
        let key = CleanupKey::from_cleanup(&cleanup);
        match &self.backend {
            CleanupBackend::Memory(records) => {
                records.lock().await.remove(&key);
                Ok(())
            }
            CleanupBackend::Sqlite(pool) => sqlx::query(
                "DELETE FROM amazon_connect_cleanup_authority WHERE profile_id = ? AND instance_id = ? AND contact_id = ?",
            )
            .bind(key.profile_id)
            .bind(key.instance_id)
            .bind(key.contact_id)
            .execute(pool)
            .await
            .map(|_| ())
            .map_err(|_| {
                ConnectError::Control("durable Amazon cleanup journal unavailable".into())
            }),
            CleanupBackend::Postgres(pool) => sqlx::query(
                "DELETE FROM amazon_connect_cleanup_authority WHERE profile_id = $1 AND instance_id = $2 AND contact_id = $3",
            )
            .bind(key.profile_id)
            .bind(key.instance_id)
            .bind(key.contact_id)
            .execute(pool)
            .await
            .map(|_| ())
            .map_err(|_| {
                ConnectError::Control("durable Amazon cleanup journal unavailable".into())
            }),
        }
    }
}

#[async_trait]
impl AmazonConnectCleanupObserver for AmazonCleanupJournal {
    async fn retained(&self, cleanup: RetainedAmazonConnectCleanup) -> Result<(), ConnectError> {
        self.retain(cleanup).await
    }

    async fn resolved(&self, cleanup: RetainedAmazonConnectCleanup) -> Result<(), ConnectError> {
        self.resolve(cleanup).await
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AmazonCleanupReconcileReport {
    pub attempted: usize,
    pub resolved: usize,
    pub remaining: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvoip_amazon_connect::{
        ConnectConfig, ConnectContactStarter, ConnectionData, StartContactRequest,
        StopContactRequest,
    };

    struct NoopStarter;

    #[async_trait]
    impl ConnectContactStarter for NoopStarter {
        async fn start_webrtc_contact(
            &self,
            _request: StartContactRequest,
        ) -> Result<ConnectionData, ConnectError> {
            unreachable!("an empty cleanup journal performs no provider request")
        }

        async fn stop_contact(&self, _request: StopContactRequest) -> Result<(), ConnectError> {
            Ok(())
        }
    }

    fn cleanup(contact: &str) -> RetainedAmazonConnectCleanup {
        RetainedAmazonConnectCleanup::new(
            ConnectProfileId::new("test-profile").unwrap(),
            "test-instance",
            contact,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn memory_journal_is_exact_idempotent_and_redacted() {
        let journal = AmazonCleanupJournal::connect(CallRepositoryBackendConfig::Memory)
            .await
            .unwrap();
        let first = cleanup("contact-private");
        journal.retained(first.clone()).await.unwrap();
        journal.retained(first.clone()).await.unwrap();
        assert_eq!(journal.pending().await.unwrap(), vec![first.clone()]);
        assert!(!format!("{journal:?}").contains("contact-private"));
        assert!(!format!("{:?}", journal.pending().await.unwrap()).contains("contact-private"));
        journal.resolved(first).await.unwrap();
        assert!(journal.pending().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn sqlite_journal_survives_restart_and_rejects_tampered_rows() {
        let path = std::env::temp_dir().join(format!(
            "bridgefu-amazon-cleanup-{}.db",
            uuid::Uuid::new_v4()
        ));
        let url = format!("sqlite://{}", path.display());
        let first = AmazonCleanupJournal::connect(CallRepositoryBackendConfig::Sqlite {
            database_url: url.clone(),
        })
        .await
        .unwrap();
        first.retained(cleanup("restart-contact")).await.unwrap();
        drop(first);

        let restarted = AmazonCleanupJournal::connect(CallRepositoryBackendConfig::Sqlite {
            database_url: url,
        })
        .await
        .unwrap();
        assert_eq!(restarted.pending().await.unwrap().len(), 1);
        let CleanupBackend::Sqlite(pool) = &restarted.backend else {
            unreachable!();
        };
        sqlx::query("UPDATE amazon_connect_cleanup_authority SET instance_id = 'bad\nvalue'")
            .execute(pool)
            .await
            .unwrap();
        assert!(restarted.pending().await.is_err());
        drop(restarted);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[tokio::test]
    async fn periodic_reconciler_is_owned_and_joins_on_shutdown() {
        let journal = AmazonCleanupJournal::connect(CallRepositoryBackendConfig::Memory)
            .await
            .unwrap();
        let adapter = AmazonConnectAdapter::new(
            ConnectConfig::new("test-instance", "test-flow"),
            Arc::new(NoopStarter),
        );
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task =
            journal.spawn_reconciler(adapter, shutdown_rx, std::time::Duration::from_secs(3_600));
        shutdown_tx.send_replace(true);
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("cleanup reconciler shutdown deadline")
            .expect("cleanup reconciler task");
    }
}
