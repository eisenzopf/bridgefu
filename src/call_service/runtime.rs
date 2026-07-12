//! Shared construction seam for the transactional call service.
//!
//! Process frontends select a repository explicitly and receive the same
//! repository handles used by [`CallService`]. Requested durable backends fail
//! closed: connection, migration, and worker-registration errors are returned
//! to the caller and are never converted into an in-memory fallback.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use thiserror::Error;
use zeroize::Zeroize;

use crate::call_engine::{
    CallRepository, RegisterWorker, RepositoryError, WorkerId, WorkerSnapshot,
};
use crate::persistence::{MemoryRepository, PostgresRepository, SqliteRepository};

use super::{
    AttachmentPrincipalResolver, CallService, CallServiceClock, CallServiceCrypto,
    CallServiceRepository, CallTimeoutPolicy, ControlCryptoError, FixedWorkerPlacement,
};

/// Repository implementation selected for one transactional call runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallRepositoryBackendKind {
    /// Explicitly ephemeral development or test storage.
    Memory,
    /// Durable standalone SQLite storage.
    Sqlite,
    /// Durable clustered PostgreSQL storage.
    Postgres,
}

impl CallRepositoryBackendKind {
    /// Stable diagnostic label. No connection material is exposed.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgres",
        }
    }
}

/// Connection configuration for a call repository.
pub enum CallRepositoryBackendConfig {
    /// Explicitly ephemeral development or test storage.
    Memory,
    /// Durable SQLite database URL.
    Sqlite { database_url: String },
    /// Durable PostgreSQL database URL.
    Postgres { database_url: String },
}

impl CallRepositoryBackendConfig {
    fn kind(&self) -> CallRepositoryBackendKind {
        match self {
            Self::Memory => CallRepositoryBackendKind::Memory,
            Self::Sqlite { .. } => CallRepositoryBackendKind::Sqlite,
            Self::Postgres { .. } => CallRepositoryBackendKind::Postgres,
        }
    }
}

impl Drop for CallRepositoryBackendConfig {
    fn drop(&mut self) {
        match self {
            Self::Memory => {}
            Self::Sqlite { database_url } | Self::Postgres { database_url } => {
                database_url.zeroize();
            }
        }
    }
}

impl fmt::Debug for CallRepositoryBackendConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory => formatter.write_str("Memory"),
            Self::Sqlite { .. } => formatter
                .debug_struct("Sqlite")
                .field("database_url", &"[redacted]")
                .finish(),
            Self::Postgres { .. } => formatter
                .debug_struct("Postgres")
                .field("database_url", &"[redacted]")
                .finish(),
        }
    }
}

/// Complete, transport-neutral call-service startup configuration.
pub struct CallServiceRuntimeConfig {
    /// Selected repository. Durable selections never fall back to memory.
    pub backend: CallRepositoryBackendConfig,
    /// Stable worker identity used for durable fencing across restarts.
    pub worker_id: WorkerId,
    /// Maximum durable reservations for this worker.
    pub max_calls: usize,
    /// Shared HMAC material for idempotency and attachment tokens.
    pub control_key: Vec<u8>,
    /// Call setup, transfer, and ending deadlines.
    pub timeouts: CallTimeoutPolicy,
}

impl fmt::Debug for CallServiceRuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallServiceRuntimeConfig")
            .field("backend", &self.backend)
            .field("worker_id", &self.worker_id)
            .field("max_calls", &self.max_calls)
            .field("control_key", &"[redacted]")
            .field("timeouts", &self.timeouts)
            .finish()
    }
}

impl Drop for CallServiceRuntimeConfig {
    fn drop(&mut self) {
        self.control_key.zeroize();
        match &mut self.backend {
            CallRepositoryBackendConfig::Memory => {}
            CallRepositoryBackendConfig::Sqlite { database_url }
            | CallRepositoryBackendConfig::Postgres { database_url } => database_url.zeroize(),
        }
    }
}

/// Safe startup failure. Database URLs and control keys are never retained.
#[derive(Debug, Error)]
pub enum CallServiceRuntimeError {
    /// Repository connection, migration, or worker registration failed.
    #[error("transactional call repository unavailable")]
    Repository(#[source] RepositoryError),
    /// Control-plane HMAC material is invalid.
    #[error(transparent)]
    Crypto(#[from] ControlCryptoError),
}

/// One constructed call service and the exact shared repository behind it.
pub struct CallServiceRuntime {
    backend: CallRepositoryBackendKind,
    repository: Arc<dyn CallRepository>,
    service_repository: Arc<dyn CallServiceRepository>,
    service: Arc<CallService>,
    worker: WorkerSnapshot,
}

struct ValidatedRuntimeConfig {
    worker_id: WorkerId,
    max_calls: usize,
    timeouts: CallTimeoutPolicy,
    crypto: CallServiceCrypto,
}

impl fmt::Debug for CallServiceRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallServiceRuntime")
            .field("backend", &self.backend)
            .field("repository", &"[configured]")
            .field("worker", &self.worker)
            .finish_non_exhaustive()
    }
}

impl CallServiceRuntime {
    /// Selected repository implementation.
    #[must_use]
    pub const fn backend(&self) -> CallRepositoryBackendKind {
        self.backend
    }

    /// Transactional API service handle.
    #[must_use]
    pub fn service(&self) -> Arc<CallService> {
        Arc::clone(&self.service)
    }

    /// Shared core repository handle for worker/runtime construction.
    #[must_use]
    pub fn repository(&self) -> Arc<dyn CallRepository> {
        Arc::clone(&self.repository)
    }

    /// Shared service repository handle for execution/runtime construction.
    #[must_use]
    pub fn service_repository(&self) -> Arc<dyn CallServiceRepository> {
        Arc::clone(&self.service_repository)
    }

    /// Current registered worker incarnation.
    #[must_use]
    pub fn worker(&self) -> &WorkerSnapshot {
        &self.worker
    }
}

/// Opens the configured repository, registers its stable worker, and builds a
/// call service over those exact shared handles.
pub async fn build_call_service_runtime(
    mut config: CallServiceRuntimeConfig,
    attachment_principals: Arc<dyn AttachmentPrincipalResolver>,
    clock: Arc<dyn CallServiceClock>,
) -> Result<CallServiceRuntime, CallServiceRuntimeError> {
    // Validate secret material before opening or mutating a repository so an
    // invalid key cannot leave a worker registration behind.
    let crypto = CallServiceCrypto::new(std::mem::take(&mut config.control_key))?;
    let backend = config.backend.kind();
    let validated = ValidatedRuntimeConfig {
        worker_id: config.worker_id,
        max_calls: config.max_calls,
        timeouts: config.timeouts,
        crypto,
    };
    let mut repository_config =
        std::mem::replace(&mut config.backend, CallRepositoryBackendConfig::Memory);
    match &mut repository_config {
        CallRepositoryBackendConfig::Memory => {
            finish_runtime(
                MemoryRepository::new(),
                backend,
                validated,
                attachment_principals,
                clock,
            )
            .await
        }
        CallRepositoryBackendConfig::Sqlite { database_url } => {
            let result = SqliteRepository::connect(database_url.as_str()).await;
            let repository = result.map_err(CallServiceRuntimeError::Repository)?;
            finish_runtime(repository, backend, validated, attachment_principals, clock).await
        }
        CallRepositoryBackendConfig::Postgres { database_url } => {
            let result = PostgresRepository::connect(database_url.as_str()).await;
            let repository = result.map_err(CallServiceRuntimeError::Repository)?;
            finish_runtime(repository, backend, validated, attachment_principals, clock).await
        }
    }
}

async fn finish_runtime<R>(
    repository: R,
    backend: CallRepositoryBackendKind,
    config: ValidatedRuntimeConfig,
    attachment_principals: Arc<dyn AttachmentPrincipalResolver>,
    clock: Arc<dyn CallServiceClock>,
) -> Result<CallServiceRuntime, CallServiceRuntimeError>
where
    R: CallRepository + CallServiceRepository + 'static,
{
    let repository = Arc::new(repository);
    let worker = repository
        .register_worker(RegisterWorker {
            worker_id: config.worker_id,
            max_calls: config.max_calls,
            capabilities: BTreeSet::new(),
            at: clock.now(),
        })
        .await
        .map_err(CallServiceRuntimeError::Repository)?;
    let core_repository: Arc<dyn CallRepository> = repository.clone();
    let service_repository: Arc<dyn CallServiceRepository> = repository;
    let service = Arc::new(CallService::new(
        Arc::clone(&service_repository),
        Arc::new(FixedWorkerPlacement::new(worker.lease)),
        attachment_principals,
        config.crypto,
        clock,
        config.timeouts,
    ));
    Ok(CallServiceRuntime {
        backend,
        repository: core_repository,
        service_repository,
        service,
        worker,
    })
}
