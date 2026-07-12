//! Shared construction seam for the transactional call service.
//!
//! Process frontends select a repository explicitly and receive the same
//! repository handles used by [`CallService`]. Requested durable backends fail
//! closed: connection, migration, and worker-registration errors are returned
//! to the caller and are never converted into an in-memory fallback.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use zeroize::Zeroize;

use crate::call_engine::{
    validate_worker_lease_ttl, CallRepository, RegisterWorker, RenewWorkerLease, RepositoryError,
    WorkerId, WorkerSnapshot, DEFAULT_WORKER_LEASE_TTL,
};
use crate::coordination::{
    CoordinationClock, CoordinationError, CoordinationOutbox, CoordinationProjection,
    DatabasePollReason, DeploymentId, MemoryCoordinator, PostgresCoordinationOutbox,
    RedisCoordinationConfig, RedisCoordinator, SqliteCoordinationOutbox, WakeupConsumer,
    WakeupMessage, WakeupPoll,
};
use crate::persistence::{MemoryRepository, PostgresRepository, SqliteRepository};

use super::{
    AttachmentPrincipalResolver, CallService, CallServiceClock, CallServiceCrypto,
    CallServiceRepository, CallTimeoutPolicy, ControlCryptoError, FixedWorkerPlacement,
    RepositoryWorkerPlacement,
};

/// Explicit lease and optional Redis projection configuration.
pub struct CallServiceCoordinationConfig {
    /// Namespace shared by SQL outbox rows and Redis keys.
    pub deployment: DeploymentId,
    /// Authoritative worker lease duration.
    pub worker_lease_ttl: Duration,
    /// Database renewal cadence. Must be shorter than the lease.
    pub worker_renew_interval: Duration,
    /// Optional Redis projection/cache configuration. The URL is redacted and
    /// zeroized by `RedisCoordinationConfig`.
    pub redis: Option<RedisCoordinationConfig>,
    /// Explicit dev/test acknowledgement for running PostgreSQL without the
    /// clustered Redis projection and wakeup broker. Production gateway and
    /// worker modes must leave this disabled and configure clustered Redis.
    pub allow_db_only_coordination: bool,
}

impl CallServiceCoordinationConfig {
    /// Safe defaults for one validated deployment.
    #[must_use]
    pub fn new(deployment: DeploymentId) -> Self {
        Self {
            deployment,
            worker_lease_ttl: DEFAULT_WORKER_LEASE_TTL,
            worker_renew_interval: Duration::from_secs(10),
            redis: None,
            allow_db_only_coordination: false,
        }
    }

    fn validate_for_backend(
        &self,
        backend: CallRepositoryBackendKind,
    ) -> Result<(), CallServiceRuntimeError> {
        validate_worker_lease_ttl(self.worker_lease_ttl)
            .map_err(CallServiceRuntimeError::Repository)?;
        if self.worker_renew_interval.is_zero()
            || self.worker_renew_interval >= self.worker_lease_ttl
        {
            return Err(CallServiceRuntimeError::InvalidConfiguration(
                "worker renewal interval must be positive and shorter than lease TTL",
            ));
        }
        if self
            .redis
            .as_ref()
            .is_some_and(|redis| redis.deployment != self.deployment)
        {
            return Err(CallServiceRuntimeError::InvalidConfiguration(
                "Redis and runtime deployment IDs differ",
            ));
        }
        if let Some(redis) = &self.redis {
            redis
                .validate()
                .map_err(CallServiceRuntimeError::Coordination)?;
        }
        match backend {
            CallRepositoryBackendKind::Memory => {
                if self.redis.is_some() {
                    return Err(CallServiceRuntimeError::InvalidConfiguration(
                        "Redis coordination requires a durable SQL repository",
                    ));
                }
                if self.allow_db_only_coordination {
                    return Err(CallServiceRuntimeError::InvalidConfiguration(
                        "database-only coordination acknowledgement requires PostgreSQL",
                    ));
                }
            }
            CallRepositoryBackendKind::Sqlite => {
                if self.allow_db_only_coordination {
                    return Err(CallServiceRuntimeError::InvalidConfiguration(
                        "database-only coordination acknowledgement requires PostgreSQL",
                    ));
                }
            }
            CallRepositoryBackendKind::Postgres => match &self.redis {
                Some(redis) => {
                    if self.allow_db_only_coordination {
                        return Err(CallServiceRuntimeError::InvalidConfiguration(
                            "database-only coordination cannot be combined with Redis",
                        ));
                    }
                    if !redis.clustered {
                        return Err(CallServiceRuntimeError::InvalidConfiguration(
                            "PostgreSQL Redis coordination must enable clustered TLS mode",
                        ));
                    }
                }
                None if !self.allow_db_only_coordination => {
                    return Err(CallServiceRuntimeError::InvalidConfiguration(
                        "PostgreSQL requires clustered Redis or explicit database-only dev coordination",
                    ));
                }
                None => {}
            },
        }
        Ok(())
    }
}

impl fmt::Debug for CallServiceCoordinationConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallServiceCoordinationConfig")
            .field("deployment", &self.deployment)
            .field("worker_lease_ttl", &self.worker_lease_ttl)
            .field("worker_renew_interval", &self.worker_renew_interval)
            .field("redis", &self.redis)
            .field(
                "allow_db_only_coordination",
                &self.allow_db_only_coordination,
            )
            .finish()
    }
}

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
    /// Capabilities used by database-authoritative placement.
    pub worker_capabilities: BTreeSet<String>,
    /// Shared HMAC material for idempotency and attachment tokens.
    pub control_key: Vec<u8>,
    /// Call setup, transfer, and ending deadlines.
    pub timeouts: CallTimeoutPolicy,
    /// Worker lease and projection namespace configuration.
    pub coordination: CallServiceCoordinationConfig,
}

impl fmt::Debug for CallServiceRuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallServiceRuntimeConfig")
            .field("backend", &self.backend)
            .field("worker_id", &self.worker_id)
            .field("max_calls", &self.max_calls)
            .field("worker_capabilities", &self.worker_capabilities)
            .field("control_key", &"[redacted]")
            .field("timeouts", &self.timeouts)
            .field("coordination", &self.coordination)
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
    /// Redis projection/cache startup failed. No secret material is retained.
    #[error("coordination backend unavailable")]
    Coordination(#[source] CoordinationError),
    /// Explicit runtime bounds or namespaces were invalid.
    #[error("invalid runtime configuration: {0}")]
    InvalidConfiguration(&'static str),
}

/// One constructed call service and the exact shared repository behind it.
pub struct CallServiceRuntime {
    backend: CallRepositoryBackendKind,
    repository: Arc<dyn CallRepository>,
    service_repository: Arc<dyn CallServiceRepository>,
    service: Arc<CallService>,
    worker: WorkerSnapshot,
    clock: Arc<dyn CallServiceClock>,
    work_wakeups: watch::Sender<Option<RuntimeWorkWakeup>>,
    supervisor_health: watch::Sender<RuntimeSupervisorHealth>,
    supervisor: Option<RuntimeSupervisor>,
}

/// Coalesced signal that a worker must make bounded claims against the
/// authoritative repositories. Stream messages are latency hints only; an
/// empty message set is the mandatory paced database fallback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeWorkWakeup {
    /// Exact worker fence re-read from the authoritative repository before
    /// this notification was published.
    pub observed_worker: WorkerSnapshot,
    /// Wakeup hints and the reason the authoritative poll was initiated.
    pub poll: WakeupPoll,
}

/// Observable health of the worker lease and its owned background tasks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeSupervisorHealth {
    /// Lease renewal and authoritative wakeup polling are operating normally.
    Healthy,
    /// A transient authoritative-store failure prevented a renewal.
    Degraded,
    /// The exact worker fence expired, drained unexpectedly, or was replaced.
    LeaseLost,
    /// Explicit graceful shutdown has marked the worker draining.
    Draining,
    /// The runtime was dropped without an explicit graceful shutdown.
    Stopped,
}

struct ValidatedRuntimeConfig {
    worker_id: WorkerId,
    max_calls: usize,
    worker_capabilities: BTreeSet<String>,
    timeouts: CallTimeoutPolicy,
    crypto: CallServiceCrypto,
    coordination: CallServiceCoordinationConfig,
}

struct RuntimeSupervisor {
    cancel: watch::Sender<bool>,
    health: watch::Sender<RuntimeSupervisorHealth>,
    tasks: Vec<JoinHandle<()>>,
}

enum RuntimeCoordinationBackend {
    None,
    Memory(Arc<MemoryCoordinator>),
    Redis(Arc<RedisCoordinator>),
    #[cfg(test)]
    FailConsumerStartup,
}

struct RuntimeCoordinationClock(Arc<dyn CallServiceClock>);

impl CoordinationClock for RuntimeCoordinationClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        self.0.now()
    }
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

    /// Subscribes to coalesced worker wakeups. Every update means the caller
    /// must make bounded claims against all authoritative work queues; the
    /// included reasons are hints and must not narrow correctness polling.
    #[must_use]
    pub fn subscribe_work_wakeups(&self) -> watch::Receiver<Option<RuntimeWorkWakeup>> {
        self.work_wakeups.subscribe()
    }

    /// Subscribes to lease/supervisor health changes.
    #[must_use]
    pub fn subscribe_supervisor_health(&self) -> watch::Receiver<RuntimeSupervisorHealth> {
        self.supervisor_health.subscribe()
    }

    /// Marks this fence draining, cancels supervised background work, and
    /// joins every owned task. Active calls remain pinned for the normal
    /// worker drain path; no task is detached.
    pub async fn shutdown(mut self) -> Result<(), CallServiceRuntimeError> {
        self.supervisor_health
            .send_replace(RuntimeSupervisorHealth::Draining);
        if let Err(error) = self
            .repository
            .set_worker_draining(self.worker.lease, true, self.clock.now())
            .await
        {
            self.supervisor_health
                .send_replace(RuntimeSupervisorHealth::Degraded);
            return Err(CallServiceRuntimeError::Repository(error));
        }
        if let Some(supervisor) = self.supervisor.take() {
            supervisor.shutdown().await;
        }
        Ok(())
    }
}

impl Drop for CallServiceRuntime {
    fn drop(&mut self) {
        if let Some(supervisor) = self.supervisor.take() {
            supervisor.cancel_without_join();
        }
    }
}

impl RuntimeCoordinationBackend {
    async fn connect(
        coordination: &mut CallServiceCoordinationConfig,
        clock: Arc<dyn CallServiceClock>,
    ) -> Result<Self, CallServiceRuntimeError> {
        match coordination.redis.take() {
            Some(redis) => Ok(Self::Redis(Arc::new(
                RedisCoordinator::connect(redis)
                    .await
                    .map_err(CallServiceRuntimeError::Coordination)?,
            ))),
            None => Ok(Self::Memory(Arc::new(
                MemoryCoordinator::new(
                    coordination.deployment.clone(),
                    Arc::new(RuntimeCoordinationClock(clock)),
                    10_000,
                )
                .map_err(CallServiceRuntimeError::Coordination)?,
            ))),
        }
    }

    fn projection(&self) -> Option<Arc<dyn CoordinationProjection>> {
        match self {
            Self::None => None,
            Self::Memory(coordinator) => {
                Some(Arc::clone(coordinator) as Arc<dyn CoordinationProjection>)
            }
            Self::Redis(coordinator) => {
                Some(Arc::clone(coordinator) as Arc<dyn CoordinationProjection>)
            }
            #[cfg(test)]
            Self::FailConsumerStartup => None,
        }
    }

    async fn wakeup_consumer(
        &self,
        worker_id: WorkerId,
    ) -> Result<Option<Box<dyn WakeupConsumer>>, CallServiceRuntimeError> {
        const GROUP: &str = "bridgefu-workers-v1";
        let consumer_name = format!("{}-{}", worker_id, uuid::Uuid::new_v4().simple());
        match self {
            Self::None => Ok(None),
            Self::Memory(coordinator) => coordinator
                .wakeup_consumer(worker_id, GROUP, consumer_name, Duration::from_secs(2))
                .map(|consumer| Some(Box::new(consumer) as Box<dyn WakeupConsumer>))
                .map_err(CallServiceRuntimeError::Coordination),
            Self::Redis(coordinator) => coordinator
                .wakeup_consumer(worker_id, GROUP, consumer_name)
                .await
                .map(|consumer| Some(Box::new(consumer) as Box<dyn WakeupConsumer>))
                .map_err(CallServiceRuntimeError::Coordination),
            #[cfg(test)]
            Self::FailConsumerStartup => Err(CallServiceRuntimeError::Coordination(
                CoordinationError::Unavailable,
            )),
        }
    }
}

impl RuntimeSupervisor {
    #[allow(clippy::too_many_arguments)]
    fn start(
        repository: Arc<dyn CallRepository>,
        worker: crate::call_engine::WorkerLease,
        lease_ttl: Duration,
        renew_interval: Duration,
        clock: Arc<dyn CallServiceClock>,
        coordination_outbox: Option<Arc<dyn CoordinationOutbox>>,
        projection: Option<Arc<dyn CoordinationProjection>>,
        wakeup_consumer: Option<Box<dyn WakeupConsumer>>,
        work_wakeups: watch::Sender<Option<RuntimeWorkWakeup>>,
        health: watch::Sender<RuntimeSupervisorHealth>,
    ) -> Self {
        let (cancel, renew_cancel) = watch::channel(false);
        let mut tasks = vec![tokio::spawn(run_worker_renewal(
            Arc::clone(&repository),
            worker,
            lease_ttl,
            renew_interval,
            Arc::clone(&clock),
            cancel.clone(),
            renew_cancel,
            health.clone(),
        ))];
        if let (Some(outbox), Some(projection)) = (coordination_outbox, projection) {
            tasks.push(tokio::spawn(run_coordination_projector(
                outbox,
                projection,
                format!("worker-{}", worker.worker_id),
                cancel.subscribe(),
            )));
        }
        if let Some(consumer) = wakeup_consumer {
            tasks.push(tokio::spawn(run_work_wakeup_consumer(
                repository,
                worker,
                consumer,
                work_wakeups,
                clock,
                cancel.clone(),
                cancel.subscribe(),
                health.clone(),
            )));
        }
        Self {
            cancel,
            health,
            tasks,
        }
    }

    async fn shutdown(self) {
        let _ = self.cancel.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
    }

    fn cancel_without_join(self) {
        self.health.send_replace(RuntimeSupervisorHealth::Stopped);
        let _ = self.cancel.send(true);
        for task in self.tasks {
            task.abort();
        }
    }
}

async fn run_work_wakeup_consumer(
    repository: Arc<dyn CallRepository>,
    worker: crate::call_engine::WorkerLease,
    mut consumer: Box<dyn WakeupConsumer>,
    notifications: watch::Sender<Option<RuntimeWorkWakeup>>,
    clock: Arc<dyn CallServiceClock>,
    cancel_all: watch::Sender<bool>,
    mut cancel: watch::Receiver<bool>,
    health: watch::Sender<RuntimeSupervisorHealth>,
) {
    const BATCH_SIZE: usize = 128;
    const STALE_PENDING_IDLE: Duration = Duration::from_secs(1);
    const OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
    const DATABASE_RETRY: Duration = Duration::from_millis(250);

    let mut pending_acknowledgements = Vec::<String>::new();
    loop {
        let mut coordination_failed = false;
        if !pending_acknowledgements.is_empty() {
            let acknowledgement = tokio::select! {
                changed = cancel.changed() => {
                    if changed.is_err() || *cancel.borrow() {
                        break;
                    }
                    continue;
                }
                result = tokio::time::timeout(
                    OPERATION_TIMEOUT,
                    consumer.acknowledge(&pending_acknowledgements),
                ) => result,
            };
            if matches!(acknowledgement, Ok(Ok(_))) {
                pending_acknowledgements.clear();
            } else {
                coordination_failed = true;
            }
        }

        let mut poll = if coordination_failed {
            tokio::select! {
                changed = cancel.changed() => {
                    if changed.is_err() || *cancel.borrow() {
                        break;
                    }
                    continue;
                }
                _ = tokio::time::sleep(DATABASE_RETRY) => {}
            }
            WakeupPoll {
                messages: Vec::new(),
                database_poll_reason: DatabasePollReason::CoordinationUnavailable,
            }
        } else {
            tokio::select! {
                changed = cancel.changed() => {
                    if changed.is_err() || *cancel.borrow() {
                        break;
                    }
                    continue;
                }
                poll = consumer.poll(BATCH_SIZE) => poll,
            }
        };
        if !coordination_failed {
            let recovered = tokio::select! {
                changed = cancel.changed() => {
                    if changed.is_err() || *cancel.borrow() {
                        break;
                    }
                    continue;
                }
                result = tokio::time::timeout(
                    OPERATION_TIMEOUT,
                    consumer.auto_claim(STALE_PENDING_IDLE, BATCH_SIZE),
                ) => result,
            };
            match recovered {
                Ok(Ok(recovered)) => {
                    merge_wakeup_messages(&mut poll.messages, recovered, BATCH_SIZE);
                }
                _ => {
                    poll.database_poll_reason = DatabasePollReason::CoordinationUnavailable;
                }
            }
        }

        let observed_worker = loop {
            let snapshot = tokio::select! {
                changed = cancel.changed() => {
                    if changed.is_err() || *cancel.borrow() {
                        return;
                    }
                    continue;
                }
                result = tokio::time::timeout(
                    OPERATION_TIMEOUT,
                    repository.active_worker_snapshot(worker, clock.now()),
                ) => result,
            };
            match snapshot {
                Ok(Ok(snapshot)) => break snapshot,
                Ok(Err(RepositoryError::Unavailable)) | Err(_) => {
                    if *health.borrow() == RuntimeSupervisorHealth::Healthy {
                        health.send_replace(RuntimeSupervisorHealth::Degraded);
                    }
                    tokio::select! {
                        changed = cancel.changed() => {
                            if changed.is_err() || *cancel.borrow() {
                                return;
                            }
                        }
                        _ = tokio::time::sleep(DATABASE_RETRY) => {}
                    }
                }
                _ => {
                    if *health.borrow() != RuntimeSupervisorHealth::Draining {
                        health.send_replace(RuntimeSupervisorHealth::LeaseLost);
                    }
                    let _ = cancel_all.send(true);
                    return;
                }
            }
        };

        let entry_ids = poll
            .messages
            .iter()
            .map(|message| message.entry_id.clone())
            .collect::<Vec<_>>();
        notifications.send_replace(Some(RuntimeWorkWakeup {
            observed_worker,
            poll,
        }));
        if !entry_ids.is_empty() {
            let acknowledgement = tokio::select! {
                changed = cancel.changed() => {
                    if changed.is_err() || *cancel.borrow() {
                        break;
                    }
                    continue;
                }
                result = tokio::time::timeout(
                    OPERATION_TIMEOUT,
                    consumer.acknowledge(&entry_ids),
                ) => result,
            };
            if !matches!(acknowledgement, Ok(Ok(_))) {
                pending_acknowledgements = entry_ids;
            }
        }
    }
}

fn merge_wakeup_messages(
    messages: &mut Vec<WakeupMessage>,
    recovered: Vec<WakeupMessage>,
    limit: usize,
) {
    for message in recovered {
        if messages.len() >= limit {
            break;
        }
        if !messages
            .iter()
            .any(|existing| existing.entry_id == message.entry_id)
        {
            messages.push(message);
        }
    }
}

async fn run_worker_renewal(
    repository: Arc<dyn CallRepository>,
    worker: crate::call_engine::WorkerLease,
    lease_ttl: Duration,
    renew_interval: Duration,
    clock: Arc<dyn CallServiceClock>,
    cancel_all: watch::Sender<bool>,
    mut cancel: watch::Receiver<bool>,
    health: watch::Sender<RuntimeSupervisorHealth>,
) {
    let start = tokio::time::Instant::now() + renew_interval;
    let mut ticker = tokio::time::interval_at(start, renew_interval);
    loop {
        tokio::select! {
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    break;
                }
            }
            _ = ticker.tick() => {
                match repository.renew_worker_lease(RenewWorkerLease {
                    worker,
                    lease_ttl,
                    at: clock.now(),
                }).await {
                    Ok(_) => {
                        if *health.borrow() == RuntimeSupervisorHealth::Degraded {
                            health.send_replace(RuntimeSupervisorHealth::Healthy);
                        }
                    }
                    Err(RepositoryError::Unavailable) => {
                        // A transient store outage is retried at the bounded
                        // cadence. The database expiry still fails closed.
                        health.send_replace(RuntimeSupervisorHealth::Degraded);
                    }
                    Err(_) => {
                        if *health.borrow() != RuntimeSupervisorHealth::Draining {
                            health.send_replace(RuntimeSupervisorHealth::LeaseLost);
                        }
                        let _ = cancel_all.send(true);
                        break;
                    }
                }
            }
        }
    }
}

async fn run_coordination_projector(
    outbox: Arc<dyn CoordinationOutbox>,
    projection: Arc<dyn CoordinationProjection>,
    projector: String,
    mut cancel: watch::Receiver<bool>,
) {
    const CLAIM_TTL: Duration = Duration::from_secs(5);
    const BATCH_SIZE: usize = 128;
    let mut delay = Duration::from_millis(25);
    loop {
        tokio::select! {
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    break;
                }
            }
            _ = tokio::time::sleep(delay) => {
                match outbox.claim(&projector, CLAIM_TTL, BATCH_SIZE).await {
                    Ok(claims) => {
                        let had_claims = !claims.is_empty();
                        let mut failed = false;
                        for claim in claims {
                            if projection.apply(&claim.record.event).await.is_err()
                                || outbox.acknowledge(
                                    claim.record.event.sequence,
                                    &projector,
                                    claim.claim_generation,
                                ).await.is_err()
                            {
                                failed = true;
                                break;
                            }
                        }
                        delay = if failed {
                            Duration::from_millis(500)
                        } else if had_claims {
                            Duration::from_millis(25)
                        } else {
                            Duration::from_millis(250)
                        };
                    }
                    Err(_) => delay = Duration::from_secs(1),
                }
            }
        }
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
    config.coordination.validate_for_backend(backend)?;
    let mut validated = ValidatedRuntimeConfig {
        worker_id: config.worker_id,
        max_calls: config.max_calls,
        worker_capabilities: std::mem::take(&mut config.worker_capabilities),
        timeouts: config.timeouts,
        crypto,
        coordination: CallServiceCoordinationConfig {
            deployment: config.coordination.deployment.clone(),
            worker_lease_ttl: config.coordination.worker_lease_ttl,
            worker_renew_interval: config.coordination.worker_renew_interval,
            redis: config.coordination.redis.take(),
            allow_db_only_coordination: config.coordination.allow_db_only_coordination,
        },
    };
    let deployment = validated.coordination.deployment.clone();
    let mut repository_config =
        std::mem::replace(&mut config.backend, CallRepositoryBackendConfig::Memory);
    match &mut repository_config {
        CallRepositoryBackendConfig::Memory => {
            finish_runtime(
                Arc::new(MemoryRepository::new()),
                backend,
                validated,
                attachment_principals,
                clock,
                None,
                RuntimeCoordinationBackend::None,
            )
            .await
        }
        CallRepositoryBackendConfig::Sqlite { database_url } => {
            let result =
                SqliteRepository::connect_for_deployment(database_url.as_str(), deployment.clone())
                    .await;
            let repository = result.map_err(CallServiceRuntimeError::Repository)?;
            let outbox: Arc<dyn CoordinationOutbox> = Arc::new(
                SqliteCoordinationOutbox::from_pool(repository.pool().clone(), deployment),
            );
            let coordination = RuntimeCoordinationBackend::connect(
                &mut validated.coordination,
                Arc::clone(&clock),
            )
            .await?;
            finish_runtime(
                Arc::new(repository),
                backend,
                validated,
                attachment_principals,
                clock,
                Some(outbox),
                coordination,
            )
            .await
        }
        CallRepositoryBackendConfig::Postgres { database_url } => {
            let result = PostgresRepository::connect_for_deployment(
                database_url.as_str(),
                deployment.clone(),
            )
            .await;
            let repository = result.map_err(CallServiceRuntimeError::Repository)?;
            let outbox: Arc<dyn CoordinationOutbox> = Arc::new(
                PostgresCoordinationOutbox::from_pool(repository.pool().clone(), deployment),
            );
            let coordination = RuntimeCoordinationBackend::connect(
                &mut validated.coordination,
                Arc::clone(&clock),
            )
            .await?;
            finish_runtime(
                Arc::new(repository),
                backend,
                validated,
                attachment_principals,
                clock,
                Some(outbox),
                coordination,
            )
            .await
        }
    }
}

async fn finish_runtime<R>(
    repository: Arc<R>,
    backend: CallRepositoryBackendKind,
    config: ValidatedRuntimeConfig,
    attachment_principals: Arc<dyn AttachmentPrincipalResolver>,
    clock: Arc<dyn CallServiceClock>,
    coordination_outbox: Option<Arc<dyn CoordinationOutbox>>,
    coordination: RuntimeCoordinationBackend,
) -> Result<CallServiceRuntime, CallServiceRuntimeError>
where
    R: CallRepository + CallServiceRepository + 'static,
{
    // External coordination must be fully usable before this worker becomes
    // an authoritative placement candidate. Redis cannot participate in the
    // registration transaction, so dependency-first construction is the
    // equivalent fail-closed startup boundary.
    let wakeup_consumer = coordination.wakeup_consumer(config.worker_id).await?;
    let worker = repository
        .register_worker(RegisterWorker {
            worker_id: config.worker_id,
            max_calls: config.max_calls,
            capabilities: config.worker_capabilities,
            at: clock.now(),
            lease_ttl: config.coordination.worker_lease_ttl,
        })
        .await
        .map_err(CallServiceRuntimeError::Repository)?;
    let projection = coordination.projection();
    let core_repository: Arc<dyn CallRepository> = repository.clone();
    let service_repository: Arc<dyn CallServiceRepository> = repository;
    let placement: Arc<dyn super::WorkerPlacement> = if backend == CallRepositoryBackendKind::Memory
    {
        Arc::new(FixedWorkerPlacement::new(worker.lease))
    } else {
        let placement = RepositoryWorkerPlacement::new(Arc::clone(&core_repository));
        let placement = match projection.clone() {
            Some(projection) => placement.with_projection(projection),
            None => placement,
        };
        Arc::new(placement)
    };
    let service = Arc::new(CallService::new(
        Arc::clone(&service_repository),
        placement,
        attachment_principals,
        config.crypto,
        Arc::clone(&clock),
        config.timeouts,
    ));
    let (work_wakeups, _) = watch::channel(None);
    let (supervisor_health, _) = watch::channel(RuntimeSupervisorHealth::Healthy);
    let supervisor = RuntimeSupervisor::start(
        Arc::clone(&core_repository),
        worker.lease,
        config.coordination.worker_lease_ttl,
        config.coordination.worker_renew_interval,
        Arc::clone(&clock),
        coordination_outbox,
        projection,
        wakeup_consumer,
        work_wakeups.clone(),
        supervisor_health.clone(),
    );
    Ok(CallServiceRuntime {
        backend,
        repository: core_repository,
        service_repository,
        service,
        worker,
        clock,
        work_wakeups,
        supervisor_health,
        supervisor: Some(supervisor),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use tokio::sync::Notify;

    use super::*;
    use crate::call_engine::{CallRepository, RegisterWorker, WorkerId};
    use crate::coordination::{
        CoordinationError, DatabasePollReason, ProjectionSequence, WakeupMessage, WakeupReason,
    };

    #[derive(Debug)]
    struct ManualCallClock(Mutex<DateTime<Utc>>);

    impl ManualCallClock {
        fn new(now: DateTime<Utc>) -> Self {
            Self(Mutex::new(now))
        }

        fn set(&self, now: DateTime<Utc>) {
            *self.0.lock().unwrap() = now;
        }
    }

    impl CallServiceClock for ManualCallClock {
        fn now(&self) -> DateTime<Utc> {
            *self.0.lock().unwrap()
        }
    }

    fn at(second: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_900_000_000 + second, 0).unwrap()
    }

    async fn registered_worker(
        repository: &MemoryRepository,
        worker_id: WorkerId,
        now: DateTime<Utc>,
        lease_ttl: Duration,
    ) -> WorkerSnapshot {
        repository
            .register_worker(RegisterWorker {
                worker_id,
                max_calls: 1,
                capabilities: BTreeSet::new(),
                at: now,
                lease_ttl,
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn failed_coordination_consumer_startup_never_admits_worker() {
        let repository = Arc::new(MemoryRepository::new());
        let clock = Arc::new(ManualCallClock::new(at(0)));
        let coordination =
            CallServiceCoordinationConfig::new(DeploymentId::parse("startup-failure").unwrap());
        let error = finish_runtime(
            Arc::clone(&repository),
            CallRepositoryBackendKind::Sqlite,
            ValidatedRuntimeConfig {
                worker_id: WorkerId::new(),
                max_calls: 1,
                worker_capabilities: BTreeSet::new(),
                timeouts: CallTimeoutPolicy::default(),
                crypto: CallServiceCrypto::new(vec![0x55; 32]).unwrap(),
                coordination,
            },
            Arc::new(crate::call_service::SamePrincipalAttachmentResolver),
            clock,
            None,
            RuntimeCoordinationBackend::FailConsumerStartup,
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "coordination backend unavailable");
        assert!(repository
            .worker_candidates(&BTreeSet::new(), at(0), 8)
            .await
            .unwrap()
            .is_empty());
    }

    struct FailingAckConsumer {
        polls: usize,
    }

    #[async_trait]
    impl WakeupConsumer for FailingAckConsumer {
        async fn poll(&mut self, _count: usize) -> WakeupPoll {
            self.polls += 1;
            if self.polls == 1 {
                WakeupPoll {
                    messages: vec![WakeupMessage {
                        entry_id: "1-0".to_owned(),
                        sequence: ProjectionSequence::INITIAL,
                        reason: WakeupReason::Effects,
                    }],
                    database_poll_reason: DatabasePollReason::Wakeup,
                }
            } else {
                WakeupPoll {
                    messages: Vec::new(),
                    database_poll_reason: DatabasePollReason::IntervalElapsed,
                }
            }
        }

        async fn auto_claim(
            &mut self,
            _min_idle: Duration,
            _count: usize,
        ) -> Result<Vec<WakeupMessage>, CoordinationError> {
            Ok(Vec::new())
        }

        async fn acknowledge(&mut self, _entry_ids: &[String]) -> Result<usize, CoordinationError> {
            Err(CoordinationError::Unavailable)
        }
    }

    struct TriggeredConsumer {
        first: bool,
        trigger: Arc<Notify>,
    }

    #[async_trait]
    impl WakeupConsumer for TriggeredConsumer {
        async fn poll(&mut self, _count: usize) -> WakeupPoll {
            if self.first {
                self.first = false;
            } else {
                self.trigger.notified().await;
            }
            WakeupPoll {
                messages: Vec::new(),
                database_poll_reason: DatabasePollReason::IntervalElapsed,
            }
        }

        async fn auto_claim(
            &mut self,
            _min_idle: Duration,
            _count: usize,
        ) -> Result<Vec<WakeupMessage>, CoordinationError> {
            Ok(Vec::new())
        }

        async fn acknowledge(&mut self, _entry_ids: &[String]) -> Result<usize, CoordinationError> {
            Ok(0)
        }
    }

    #[tokio::test]
    async fn failed_ack_does_not_gate_paced_authoritative_fallback() {
        let repository = Arc::new(MemoryRepository::new());
        let clock = Arc::new(ManualCallClock::new(at(0)));
        let worker =
            registered_worker(&repository, WorkerId::new(), at(0), Duration::from_secs(30)).await;
        let (notifications, mut observer) = watch::channel(None);
        let (cancel, cancel_rx) = watch::channel(false);
        let (health, _) = watch::channel(RuntimeSupervisorHealth::Healthy);
        let task = tokio::spawn(run_work_wakeup_consumer(
            repository,
            worker.lease,
            Box::new(FailingAckConsumer { polls: 0 }),
            notifications,
            clock,
            cancel.clone(),
            cancel_rx,
            health,
        ));

        tokio::time::timeout(Duration::from_secs(1), observer.changed())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            observer
                .borrow()
                .as_ref()
                .unwrap()
                .poll
                .database_poll_reason,
            DatabasePollReason::Wakeup
        );
        tokio::time::timeout(Duration::from_secs(1), observer.changed())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            observer
                .borrow()
                .as_ref()
                .unwrap()
                .poll
                .database_poll_reason,
            DatabasePollReason::CoordinationUnavailable
        );
        let _ = cancel.send(true);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn expired_lease_suppresses_later_wakeup_and_cancels_supervisor() {
        let repository = Arc::new(MemoryRepository::new());
        let clock = Arc::new(ManualCallClock::new(at(0)));
        let worker =
            registered_worker(&repository, WorkerId::new(), at(0), Duration::from_secs(5)).await;
        let trigger = Arc::new(Notify::new());
        let (notifications, mut observer) = watch::channel(None);
        let (cancel, cancel_rx) = watch::channel(false);
        let (health, mut health_rx) = watch::channel(RuntimeSupervisorHealth::Healthy);
        let task = tokio::spawn(run_work_wakeup_consumer(
            repository,
            worker.lease,
            Box::new(TriggeredConsumer {
                first: true,
                trigger: Arc::clone(&trigger),
            }),
            notifications,
            clock.clone(),
            cancel,
            cancel_rx,
            health,
        ));
        tokio::time::timeout(Duration::from_secs(1), observer.changed())
            .await
            .unwrap()
            .unwrap();
        clock.set(at(5));
        trigger.notify_one();
        tokio::time::timeout(Duration::from_secs(1), health_rx.changed())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(*health_rx.borrow(), RuntimeSupervisorHealth::LeaseLost);
        assert!(!matches!(
            tokio::time::timeout(Duration::from_millis(100), observer.changed()).await,
            Ok(Ok(()))
        ));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn advanced_fence_suppresses_later_wakeup_and_cancels_supervisor() {
        let repository = Arc::new(MemoryRepository::new());
        let clock = Arc::new(ManualCallClock::new(at(0)));
        let worker_id = WorkerId::new();
        let worker =
            registered_worker(&repository, worker_id, at(0), Duration::from_secs(30)).await;
        let trigger = Arc::new(Notify::new());
        let (notifications, mut observer) = watch::channel(None);
        let (cancel, cancel_rx) = watch::channel(false);
        let (health, mut health_rx) = watch::channel(RuntimeSupervisorHealth::Healthy);
        let task = tokio::spawn(run_work_wakeup_consumer(
            repository.clone(),
            worker.lease,
            Box::new(TriggeredConsumer {
                first: true,
                trigger: Arc::clone(&trigger),
            }),
            notifications,
            clock,
            cancel,
            cancel_rx,
            health,
        ));
        tokio::time::timeout(Duration::from_secs(1), observer.changed())
            .await
            .unwrap()
            .unwrap();
        let replacement =
            registered_worker(&repository, worker_id, at(1), Duration::from_secs(30)).await;
        assert!(replacement.lease.fence > worker.lease.fence);
        trigger.notify_one();
        tokio::time::timeout(Duration::from_secs(1), health_rx.changed())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(*health_rx.borrow(), RuntimeSupervisorHealth::LeaseLost);
        assert!(!matches!(
            tokio::time::timeout(Duration::from_millis(100), observer.changed()).await,
            Ok(Ok(()))
        ));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn stale_renewal_marks_lease_lost_and_cancels_sibling_tasks() {
        let repository = Arc::new(MemoryRepository::new());
        let worker_id = WorkerId::new();
        let original =
            registered_worker(&repository, worker_id, at(0), Duration::from_secs(30)).await;
        let replacement =
            registered_worker(&repository, worker_id, at(1), Duration::from_secs(30)).await;
        assert!(replacement.lease.fence > original.lease.fence);
        let clock = Arc::new(ManualCallClock::new(at(1)));
        let (cancel, mut sibling_cancel) = watch::channel(false);
        let (health, _) = watch::channel(RuntimeSupervisorHealth::Healthy);
        let task = tokio::spawn(run_worker_renewal(
            repository,
            original.lease,
            Duration::from_secs(30),
            Duration::from_millis(10),
            clock,
            cancel.clone(),
            cancel.subscribe(),
            health.clone(),
        ));
        tokio::time::timeout(Duration::from_secs(1), sibling_cancel.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(*sibling_cancel.borrow());
        assert_eq!(*health.borrow(), RuntimeSupervisorHealth::LeaseLost);
        task.await.unwrap();
    }
}
