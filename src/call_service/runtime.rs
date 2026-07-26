//! Shared construction seam for the transactional call service.
//!
//! Process frontends select a repository explicitly and receive the same
//! repository handles used by [`CallService`]. Requested durable backends fail
//! closed: connection, migration, and worker-registration errors are returned
//! to the caller and are never converted into an in-memory fallback.

use std::collections::BTreeSet;
use std::fmt;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::FutureExt;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use zeroize::Zeroize;

use crate::call_engine::{
    validate_worker_lease_ttl, ActivateWorkerCapabilities, CallRepository, RegisterWorker,
    RenewWorkerLease, RepositoryError, WorkerId, WorkerSnapshot, DEFAULT_WORKER_LEASE_TTL,
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
    CallServiceRepository, CallTimeoutPolicy, ControlCryptoError, RepositoryWorkerPlacement,
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

/// Transport-free configuration for a public call-control process.
///
/// Unlike [`CallServiceRuntimeConfig`], this type deliberately has no worker
/// identity, capacity, or media capabilities. Constructing it can select and
/// enqueue work for an already-registered worker, but can never register this
/// process as a placement candidate or consume worker commands.
pub struct CallControlRuntimeConfig {
    /// Clustered deployments require the PostgreSQL repository.
    pub backend: CallRepositoryBackendConfig,
    /// Shared HMAC material for idempotency and attachment tokens.
    pub control_key: Vec<u8>,
    /// Call setup, transfer, and ending deadlines.
    pub timeouts: CallTimeoutPolicy,
    /// Exact worker IDs reachable through this gateway's private forwarding
    /// catalog. Placement may not select any other registered worker.
    pub eligible_workers: BTreeSet<WorkerId>,
    /// PostgreSQL/Redis deployment namespace and projection configuration.
    pub coordination: CallServiceCoordinationConfig,
}

impl fmt::Debug for CallControlRuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallControlRuntimeConfig")
            .field("backend", &self.backend)
            .field("control_key", &"[redacted]")
            .field("timeouts", &self.timeouts)
            .field("eligible_worker_count", &self.eligible_workers.len())
            .field("coordination", &self.coordination)
            .finish()
    }
}

impl Drop for CallControlRuntimeConfig {
    fn drop(&mut self) {
        self.control_key.zeroize();
        match &mut self.backend {
            CallRepositoryBackendConfig::Memory => {}
            CallRepositoryBackendConfig::Sqlite { database_url }
            | CallRepositoryBackendConfig::Postgres { database_url } => database_url.zeroize(),
        }
    }
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
    timeouts: CallTimeoutPolicy,
    worker: WorkerSnapshot,
    activated_worker: OnceLock<WorkerSnapshot>,
    clock: Arc<dyn CallServiceClock>,
    work_wakeups: watch::Sender<Option<RuntimeWorkWakeup>>,
    supervisor_health: watch::Sender<RuntimeSupervisorHealth>,
    supervisor: Option<RuntimeSupervisor>,
}

/// Durable call-control runtime for a role-separated public gateway.
///
/// This owns only the authenticated service, PostgreSQL handles, and the
/// ordered PostgreSQL-to-Redis projector. It owns no rvoip orchestrator, media
/// graph, worker lease, wakeup consumer, or execution supervisor.
pub struct CallControlRuntime {
    backend: CallRepositoryBackendKind,
    repository: Arc<dyn CallRepository>,
    service_repository: Arc<dyn CallServiceRepository>,
    service: Arc<CallService>,
    health: watch::Sender<CallControlRuntimeHealth>,
    supervisor: Option<ControlPlaneSupervisor>,
}

/// Observable lifecycle of the transport-free gateway control plane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallControlRuntimeHealth {
    /// PostgreSQL and clustered Redis were connected and the projector owns
    /// its bounded task.
    Healthy,
    /// The ordered Redis projection has failed repeatedly. PostgreSQL remains
    /// authoritative, but public admission must pause until notification
    /// delivery recovers.
    Degraded,
    /// New HTTP admission is closed and the projector is being joined.
    Draining,
    /// Every owned task has stopped.
    Stopped,
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

struct ControlRuntimeParts {
    backend: CallRepositoryBackendKind,
    crypto: CallServiceCrypto,
    timeouts: CallTimeoutPolicy,
    attachment_principals: Arc<dyn AttachmentPrincipalResolver>,
    clock: Arc<dyn CallServiceClock>,
    coordination_outbox: Arc<dyn CoordinationOutbox>,
    projection: Arc<dyn CoordinationProjection>,
    eligible_workers: BTreeSet<WorkerId>,
}

struct RuntimeSupervisor {
    cancel: watch::Sender<bool>,
    health: watch::Sender<RuntimeSupervisorHealth>,
    tasks: Vec<JoinHandle<()>>,
}

struct ControlPlaneSupervisor {
    cancel: watch::Sender<bool>,
    health: watch::Sender<CallControlRuntimeHealth>,
    tasks: Vec<JoinHandle<()>>,
}

#[async_trait]
trait WorkerLeaseAuthority: Send + Sync {
    async fn renew(&self, request: RenewWorkerLease) -> Result<WorkerSnapshot, RepositoryError>;
}

struct RepositoryWorkerLeaseAuthority(Arc<dyn CallRepository>);

#[async_trait]
impl WorkerLeaseAuthority for RepositoryWorkerLeaseAuthority {
    async fn renew(&self, request: RenewWorkerLease) -> Result<WorkerSnapshot, RepositoryError> {
        self.0.renew_worker_lease(request).await
    }
}

struct RuntimeTaskControl {
    cancel_all: watch::Sender<bool>,
    cancel: watch::Receiver<bool>,
    health: watch::Sender<RuntimeSupervisorHealth>,
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

impl fmt::Debug for CallControlRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallControlRuntime")
            .field("backend", &self.backend)
            .field("repository", &"[configured]")
            .field("worker_registered", &false)
            .finish_non_exhaustive()
    }
}

impl CallControlRuntime {
    /// Selected authoritative repository implementation.
    #[must_use]
    pub const fn backend(&self) -> CallRepositoryBackendKind {
        self.backend
    }

    /// Transactional API service handle.
    #[must_use]
    pub fn service(&self) -> Arc<CallService> {
        Arc::clone(&self.service)
    }

    /// Shared core repository used for webhook deduplication and diagnostics.
    #[must_use]
    pub fn repository(&self) -> Arc<dyn CallRepository> {
        Arc::clone(&self.repository)
    }

    /// Shared service repository. Exposed for qualification without granting
    /// this runtime worker execution authority.
    #[must_use]
    pub fn service_repository(&self) -> Arc<dyn CallServiceRepository> {
        Arc::clone(&self.service_repository)
    }

    /// Subscribes to the owned projector lifecycle.
    #[must_use]
    pub fn subscribe_health(&self) -> watch::Receiver<CallControlRuntimeHealth> {
        self.health.subscribe()
    }

    /// Stops and joins the ordered projector. No worker row is mutated because
    /// this runtime never registered one.
    pub async fn shutdown(mut self, deadline: Duration) {
        self.health.send_replace(CallControlRuntimeHealth::Draining);
        if let Some(supervisor) = self.supervisor.take() {
            supervisor.shutdown(deadline).await;
        }
        self.health.send_replace(CallControlRuntimeHealth::Stopped);
    }
}

impl Drop for CallControlRuntime {
    fn drop(&mut self) {
        if let Some(supervisor) = self.supervisor.take() {
            supervisor.cancel_without_join();
        }
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
        self.activated_worker.get().unwrap_or(&self.worker)
    }

    /// Atomically publishes the exact adapters installed for this worker
    /// without changing its fence. Public APIs must remain unexposed until
    /// this succeeds.
    pub async fn activate_worker_capabilities(
        &self,
        capabilities: BTreeSet<String>,
    ) -> Result<WorkerSnapshot, RepositoryError> {
        let activated = self
            .repository
            .activate_worker_capabilities(ActivateWorkerCapabilities {
                worker: self.worker.lease,
                capabilities,
                at: self.clock.now(),
            })
            .await?;
        if let Some(existing) = self.activated_worker.get() {
            if existing.lease != activated.lease || existing.capabilities != activated.capabilities
            {
                return Err(RepositoryError::Unavailable);
            }
            return Ok(existing.clone());
        }
        match self.activated_worker.set(activated.clone()) {
            Ok(()) => Ok(activated),
            Err(_) => {
                let existing = self
                    .activated_worker
                    .get()
                    .ok_or(RepositoryError::Unavailable)?;
                if existing.lease == activated.lease
                    && existing.capabilities == activated.capabilities
                {
                    Ok(existing.clone())
                } else {
                    Err(RepositoryError::Unavailable)
                }
            }
        }
    }

    /// Current injected UTC observation time used by execution claims and
    /// lifecycle reconciliation.
    #[must_use]
    pub fn observation_time(&self) -> chrono::DateTime<chrono::Utc> {
        self.clock.now()
    }

    /// Validated lifecycle timeout policy shared with the transactional
    /// service and execution supervisor.
    #[must_use]
    pub const fn timeouts(&self) -> CallTimeoutPolicy {
        self.timeouts
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

    #[cfg(test)]
    pub(crate) fn force_supervisor_health_for_test(&self, health: RuntimeSupervisorHealth) {
        self.supervisor_health.send_replace(health);
    }

    /// Marks this fence draining, cancels supervised background work, and
    /// joins every owned task. Active calls remain pinned for the normal
    /// worker drain path; no task is detached.
    pub async fn shutdown(mut self, deadline: Duration) -> Result<(), CallServiceRuntimeError> {
        let deadline_at = tokio::time::Instant::now() + deadline;
        let lost_lease = matches!(
            *self.supervisor_health.borrow(),
            RuntimeSupervisorHealth::LeaseLost | RuntimeSupervisorHealth::Stopped
        );
        let drain_result = if lost_lease {
            // The monotonic lease deadline is a hard write fence. Local tasks
            // still must be cancelled and joined, but this process no longer
            // has authority to mutate the durable worker row.
            Ok(())
        } else {
            self.supervisor_health
                .send_replace(RuntimeSupervisorHealth::Draining);
            if let Some(supervisor) = self.supervisor.as_ref() {
                supervisor.begin_shutdown();
            }
            bounded_repository_write(
                self.repository
                    .set_worker_draining(self.worker.lease, true, self.clock.now()),
                deadline_at,
            )
            .await
            .map(|_| ())
        };
        if let Some(supervisor) = self.supervisor.take() {
            supervisor
                .shutdown(runtime_shutdown_budget(deadline_at))
                .await;
        }
        drain_result.map_err(CallServiceRuntimeError::Repository)
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
        registered_at: tokio::time::Instant,
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
        let lease_authority: Arc<dyn WorkerLeaseAuthority> =
            Arc::new(RepositoryWorkerLeaseAuthority(Arc::clone(&repository)));
        let mut tasks = vec![tokio::spawn(run_worker_renewal(
            lease_authority,
            worker,
            registered_at,
            lease_ttl,
            renew_interval,
            Arc::clone(&clock),
            RuntimeTaskControl {
                cancel_all: cancel.clone(),
                cancel: renew_cancel,
                health: health.clone(),
            },
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
                RuntimeTaskControl {
                    cancel_all: cancel.clone(),
                    cancel: cancel.subscribe(),
                    health: health.clone(),
                },
            )));
        }
        Self {
            cancel,
            health,
            tasks,
        }
    }

    fn begin_shutdown(&self) {
        let _ = self.cancel.send(true);
    }

    async fn shutdown(self, deadline: Duration) {
        self.begin_shutdown();
        let deadline_at = tokio::time::Instant::now() + deadline;
        for mut task in self.tasks {
            if tokio::time::timeout(runtime_shutdown_budget(deadline_at), &mut task)
                .await
                .is_err()
            {
                task.abort();
                let _ = task.await;
            }
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

impl ControlPlaneSupervisor {
    fn start(
        outbox: Arc<dyn CoordinationOutbox>,
        projection: Arc<dyn CoordinationProjection>,
        health: watch::Sender<CallControlRuntimeHealth>,
    ) -> Self {
        let (cancel, _) = watch::channel(false);
        let projector = format!("control-{}", uuid::Uuid::new_v4().simple());
        let projector_cancel = cancel.subscribe();
        let observed_cancel = cancel.subscribe();
        let task_health = health.clone();
        let task = tokio::spawn(async move {
            let outcome = AssertUnwindSafe(run_control_coordination_projector(
                outbox,
                projection,
                projector,
                projector_cancel,
                task_health.clone(),
            ))
            .catch_unwind()
            .await;
            if outcome.is_err() || !*observed_cancel.borrow() {
                set_control_health_if_running(&task_health, CallControlRuntimeHealth::Stopped);
            }
        });
        Self {
            cancel,
            health,
            tasks: vec![task],
        }
    }

    async fn shutdown(self, deadline: Duration) {
        let _ = self.cancel.send(true);
        let deadline_at = tokio::time::Instant::now() + deadline;
        for mut task in self.tasks {
            if tokio::time::timeout(runtime_shutdown_budget(deadline_at), &mut task)
                .await
                .is_err()
            {
                task.abort();
                let _ = task.await;
            }
        }
    }

    fn cancel_without_join(self) {
        self.health.send_replace(CallControlRuntimeHealth::Stopped);
        let _ = self.cancel.send(true);
        for task in self.tasks {
            task.abort();
        }
    }
}

fn set_control_health_if_running(
    health: &watch::Sender<CallControlRuntimeHealth>,
    next: CallControlRuntimeHealth,
) {
    if matches!(
        *health.borrow(),
        CallControlRuntimeHealth::Healthy | CallControlRuntimeHealth::Degraded
    ) {
        health.send_replace(next);
    }
}

fn runtime_shutdown_budget(deadline: tokio::time::Instant) -> Duration {
    deadline.saturating_duration_since(tokio::time::Instant::now())
}

async fn bounded_repository_write<F, T>(
    future: F,
    deadline: tokio::time::Instant,
) -> Result<T, RepositoryError>
where
    F: std::future::Future<Output = Result<T, RepositoryError>>,
{
    tokio::time::timeout(runtime_shutdown_budget(deadline), future)
        .await
        .map_err(|_| RepositoryError::Unavailable)?
}

async fn run_work_wakeup_consumer(
    repository: Arc<dyn CallRepository>,
    worker: crate::call_engine::WorkerLease,
    mut consumer: Box<dyn WakeupConsumer>,
    notifications: watch::Sender<Option<RuntimeWorkWakeup>>,
    clock: Arc<dyn CallServiceClock>,
    mut control: RuntimeTaskControl,
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
                changed = control.cancel.changed() => {
                    if changed.is_err() || *control.cancel.borrow() {
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
                changed = control.cancel.changed() => {
                    if changed.is_err() || *control.cancel.borrow() {
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
                changed = control.cancel.changed() => {
                    if changed.is_err() || *control.cancel.borrow() {
                        break;
                    }
                    continue;
                }
                poll = consumer.poll(BATCH_SIZE) => poll,
            }
        };
        if !coordination_failed {
            let recovered = tokio::select! {
                changed = control.cancel.changed() => {
                    if changed.is_err() || *control.cancel.borrow() {
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
                changed = control.cancel.changed() => {
                    if changed.is_err() || *control.cancel.borrow() {
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
                    if *control.health.borrow() == RuntimeSupervisorHealth::Healthy {
                        control
                            .health
                            .send_replace(RuntimeSupervisorHealth::Degraded);
                    }
                    tokio::select! {
                        changed = control.cancel.changed() => {
                            if changed.is_err() || *control.cancel.borrow() {
                                return;
                            }
                        }
                        _ = tokio::time::sleep(DATABASE_RETRY) => {}
                    }
                }
                _ => {
                    if *control.health.borrow() != RuntimeSupervisorHealth::Draining {
                        control
                            .health
                            .send_replace(RuntimeSupervisorHealth::LeaseLost);
                    }
                    let _ = control.cancel_all.send(true);
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
                changed = control.cancel.changed() => {
                    if changed.is_err() || *control.cancel.borrow() {
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
    authority: Arc<dyn WorkerLeaseAuthority>,
    worker: crate::call_engine::WorkerLease,
    registered_at: tokio::time::Instant,
    lease_ttl: Duration,
    renew_interval: Duration,
    clock: Arc<dyn CallServiceClock>,
    mut control: RuntimeTaskControl,
) {
    let mut lease_valid_until = registered_at + lease_ttl;
    let start = registered_at + renew_interval;
    let mut ticker = tokio::time::interval_at(start, renew_interval);
    loop {
        tokio::select! {
            biased;
            changed = control.cancel.changed() => {
                if changed.is_err() || *control.cancel.borrow() {
                    break;
                }
            }
            _ = tokio::time::sleep_until(lease_valid_until) => {
                if *control.health.borrow() != RuntimeSupervisorHealth::Draining {
                    control
                        .health
                        .send_replace(RuntimeSupervisorHealth::LeaseLost);
                }
                let _ = control.cancel_all.send(true);
                break;
            }
            _ = ticker.tick() => {
                let attempt_started = tokio::time::Instant::now();
                let renewal = tokio::select! {
                    biased;
                    changed = control.cancel.changed() => {
                        if changed.is_err() || *control.cancel.borrow() {
                            break;
                        }
                        continue;
                    }
                    _ = tokio::time::sleep_until(lease_valid_until) => {
                        if *control.health.borrow() != RuntimeSupervisorHealth::Draining {
                            control
                                .health
                                .send_replace(RuntimeSupervisorHealth::LeaseLost);
                        }
                        let _ = control.cancel_all.send(true);
                        break;
                    }
                    result = authority.renew(RenewWorkerLease {
                        worker,
                        lease_ttl,
                        at: clock.now(),
                    }) => result,
                };
                match renewal {
                    Ok(_) => {
                        // The repository applies its authoritative expiry no
                        // earlier than this request began. Measuring from the
                        // local attempt start is therefore conservative even
                        // when a database response is delayed or wall clocks
                        // differ.
                        lease_valid_until = attempt_started + lease_ttl;
                        if *control.health.borrow() == RuntimeSupervisorHealth::Degraded {
                            control
                                .health
                                .send_replace(RuntimeSupervisorHealth::Healthy);
                        }
                    }
                    Err(RepositoryError::Unavailable) => {
                        // A transient store outage is retried at the bounded
                        // cadence. The database expiry still fails closed.
                        control
                            .health
                            .send_replace(RuntimeSupervisorHealth::Degraded);
                    }
                    Err(_) => {
                        if *control.health.borrow() != RuntimeSupervisorHealth::Draining {
                            control
                                .health
                                .send_replace(RuntimeSupervisorHealth::LeaseLost);
                        }
                        let _ = control.cancel_all.send(true);
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

/// Gateway projector with a health contract. A single transient failure is
/// retried without flapping readiness; three consecutive failed claim/apply
/// cycles pause public admission. Any successful authoritative cycle restores
/// health. The ordered outbox remains the source of truth throughout.
async fn run_control_coordination_projector(
    outbox: Arc<dyn CoordinationOutbox>,
    projection: Arc<dyn CoordinationProjection>,
    projector: String,
    mut cancel: watch::Receiver<bool>,
    health: watch::Sender<CallControlRuntimeHealth>,
) {
    const CLAIM_TTL: Duration = Duration::from_secs(5);
    const BATCH_SIZE: usize = 128;
    const FAILURE_THRESHOLD: u8 = 3;
    let mut delay = Duration::from_millis(25);
    let mut consecutive_failures = 0_u8;
    loop {
        tokio::select! {
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    break;
                }
            }
            _ = tokio::time::sleep(delay) => {
                let cycle = match outbox.claim(&projector, CLAIM_TTL, BATCH_SIZE).await {
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
                        if failed {
                            Err(Duration::from_millis(500))
                        } else if had_claims {
                            Ok(Duration::from_millis(25))
                        } else {
                            Ok(Duration::from_millis(250))
                        }
                    }
                    Err(_) => Err(Duration::from_secs(1)),
                };
                match cycle {
                    Ok(next_delay) => {
                        consecutive_failures = 0;
                        set_control_health_if_running(
                            &health,
                            CallControlRuntimeHealth::Healthy,
                        );
                        delay = next_delay;
                    }
                    Err(next_delay) => {
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        if consecutive_failures >= FAILURE_THRESHOLD {
                            set_control_health_if_running(
                                &health,
                                CallControlRuntimeHealth::Degraded,
                            );
                        }
                        delay = next_delay;
                    }
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

/// Opens the clustered repositories and builds a transport-free call-control
/// service. Startup is fail-closed and deliberately performs no worker
/// registration. Created effects and controls are committed to PostgreSQL and
/// announced through the existing ordered Redis projection for the selected
/// worker; workers retain their mandatory database polling fallback.
pub async fn build_call_control_runtime(
    mut config: CallControlRuntimeConfig,
    attachment_principals: Arc<dyn AttachmentPrincipalResolver>,
    clock: Arc<dyn CallServiceClock>,
) -> Result<CallControlRuntime, CallServiceRuntimeError> {
    let crypto = CallServiceCrypto::new(std::mem::take(&mut config.control_key))?;
    let backend = config.backend.kind();
    if backend != CallRepositoryBackendKind::Postgres {
        return Err(CallServiceRuntimeError::InvalidConfiguration(
            "split call control requires PostgreSQL",
        ));
    }
    if config.eligible_workers.is_empty() {
        return Err(CallServiceRuntimeError::InvalidConfiguration(
            "split call control requires at least one reachable worker",
        ));
    }
    config.coordination.validate_for_backend(backend)?;
    let deployment = config.coordination.deployment.clone();
    let mut repository_config =
        std::mem::replace(&mut config.backend, CallRepositoryBackendConfig::Memory);
    let CallRepositoryBackendConfig::Postgres { database_url } = &mut repository_config else {
        unreachable!("backend kind was checked above")
    };
    let repository = Arc::new(
        PostgresRepository::connect_for_deployment(database_url.as_str(), deployment.clone())
            .await
            .map_err(CallServiceRuntimeError::Repository)?,
    );
    let outbox: Arc<dyn CoordinationOutbox> = Arc::new(PostgresCoordinationOutbox::from_pool(
        repository.pool().clone(),
        deployment,
    ));
    let coordination =
        RuntimeCoordinationBackend::connect(&mut config.coordination, Arc::clone(&clock)).await?;
    let projection =
        coordination
            .projection()
            .ok_or(CallServiceRuntimeError::InvalidConfiguration(
                "split call control requires clustered Redis projection",
            ))?;
    finish_control_runtime(
        repository,
        ControlRuntimeParts {
            backend,
            crypto,
            timeouts: config.timeouts,
            attachment_principals,
            clock,
            coordination_outbox: outbox,
            projection,
            eligible_workers: std::mem::take(&mut config.eligible_workers),
        },
    )
}

fn finish_control_runtime<R>(
    repository: Arc<R>,
    parts: ControlRuntimeParts,
) -> Result<CallControlRuntime, CallServiceRuntimeError>
where
    R: CallRepository + CallServiceRepository + 'static,
{
    let core_repository: Arc<dyn CallRepository> = repository.clone();
    let service_repository: Arc<dyn CallServiceRepository> = repository;
    let placement: Arc<dyn super::WorkerPlacement> = Arc::new(
        RepositoryWorkerPlacement::new(Arc::clone(&core_repository))
            .with_projection(Arc::clone(&parts.projection))
            .with_allowed_workers(parts.eligible_workers)
            .with_replacement_worker_guard(),
    );
    let service = Arc::new(CallService::new(
        Arc::clone(&service_repository),
        placement,
        parts.attachment_principals,
        parts.crypto,
        parts.clock,
        parts.timeouts,
    ));
    let (health, _) = watch::channel(CallControlRuntimeHealth::Healthy);
    let supervisor =
        ControlPlaneSupervisor::start(parts.coordination_outbox, parts.projection, health.clone());
    Ok(CallControlRuntime {
        backend: parts.backend,
        repository: core_repository,
        service_repository,
        service,
        health,
        supervisor: Some(supervisor),
    })
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
    let worker_registration_started = tokio::time::Instant::now();
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
    let placement = RepositoryWorkerPlacement::new(Arc::clone(&core_repository))
        .with_allowed_workers(BTreeSet::from([worker.lease.worker_id]));
    let placement = match projection.clone() {
        Some(projection) => placement.with_projection(projection),
        None => placement,
    };
    let placement: Arc<dyn super::WorkerPlacement> = Arc::new(placement);
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
        worker_registration_started,
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
        timeouts: config.timeouts,
        worker,
        activated_worker: OnceLock::new(),
        clock,
        work_wakeups,
        supervisor_health,
        supervisor: Some(supervisor),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use tokio::sync::Notify;

    use super::*;
    use crate::call_engine::{CallRepository, RegisterWorker, WorkerId};
    use crate::call_service::SamePrincipalAttachmentResolver;
    use crate::coordination::{
        CoordinationError, DatabasePollReason, MemoryCoordinationOutbox, ProjectionSequence,
        WakeupMessage, WakeupReason,
    };

    #[derive(Debug)]
    struct ManualCallClock(Mutex<DateTime<Utc>>);

    #[derive(Debug)]
    struct UnavailableLeaseAuthority;

    #[derive(Debug)]
    struct UnavailableCoordinationOutbox;

    #[async_trait]
    impl CoordinationOutbox for UnavailableCoordinationOutbox {
        async fn claim(
            &self,
            _projector: &str,
            _claim_ttl: Duration,
            _limit: usize,
        ) -> Result<Vec<crate::coordination::CoordinationOutboxClaim>, CoordinationError> {
            Err(CoordinationError::Unavailable)
        }

        async fn acknowledge(
            &self,
            _sequence: ProjectionSequence,
            _projector: &str,
            _claim_generation: crate::coordination::CoordinationClaimGeneration,
        ) -> Result<(), CoordinationError> {
            Err(CoordinationError::Unavailable)
        }
    }

    #[async_trait]
    impl WorkerLeaseAuthority for UnavailableLeaseAuthority {
        async fn renew(
            &self,
            _request: RenewWorkerLease,
        ) -> Result<WorkerSnapshot, RepositoryError> {
            Err(RepositoryError::Unavailable)
        }
    }

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

    #[tokio::test]
    async fn stalled_worker_drain_write_cannot_exceed_shutdown_deadline() {
        let started = tokio::time::Instant::now();
        let result = bounded_repository_write(
            std::future::pending::<Result<(), RepositoryError>>(),
            started + Duration::from_millis(25),
        )
        .await;
        assert_eq!(result, Err(RepositoryError::Unavailable));
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[tokio::test]
    async fn runtime_supervisor_aborts_a_task_that_stalls_after_cancellation() {
        let (cancel, mut cancelled) = watch::channel(false);
        let (health, _) = watch::channel(RuntimeSupervisorHealth::Healthy);
        let observed_cancel = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&observed_cancel);
        let task = tokio::spawn(async move {
            while !*cancelled.borrow() {
                if cancelled.changed().await.is_err() {
                    return;
                }
            }
            observed.store(true, Ordering::SeqCst);
            std::future::pending::<()>().await;
        });
        let supervisor = RuntimeSupervisor {
            cancel,
            health,
            tasks: vec![task],
        };
        let started = tokio::time::Instant::now();
        supervisor.shutdown(Duration::from_millis(25)).await;
        assert!(observed_cancel.load(Ordering::SeqCst));
        assert!(started.elapsed() < Duration::from_millis(250));
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
    async fn control_runtime_selects_existing_workers_without_registering_or_draining_one() {
        let repository = Arc::new(MemoryRepository::new());
        let clock = Arc::new(ManualCallClock::new(at(0)));
        let worker = registered_worker(
            &repository,
            WorkerId::new(),
            at(0),
            Duration::from_secs(300),
        )
        .await;
        let deployment = DeploymentId::parse("control-runtime-test").unwrap();
        let coordination_clock: Arc<dyn CoordinationClock> =
            Arc::new(RuntimeCoordinationClock(clock.clone()));
        let outbox: Arc<dyn CoordinationOutbox> = Arc::new(MemoryCoordinationOutbox::new(
            deployment.clone(),
            Arc::clone(&coordination_clock),
        ));
        let projection: Arc<dyn CoordinationProjection> =
            Arc::new(MemoryCoordinator::new(deployment, coordination_clock, 128).unwrap());
        let runtime = finish_control_runtime(
            Arc::clone(&repository),
            ControlRuntimeParts {
                backend: CallRepositoryBackendKind::Memory,
                crypto: CallServiceCrypto::new(vec![0x62; 32]).unwrap(),
                timeouts: CallTimeoutPolicy {
                    setup: Duration::from_secs(30),
                    media_idle: Duration::from_secs(30),
                    transfer: Duration::from_secs(30),
                    ending: Duration::from_secs(30),
                },
                attachment_principals: Arc::new(SamePrincipalAttachmentResolver),
                clock,
                coordination_outbox: outbox,
                projection,
                eligible_workers: BTreeSet::from([worker.lease.worker_id]),
            },
        )
        .unwrap();

        let candidates = repository
            .worker_candidates(&BTreeSet::new(), at(1), 8)
            .await
            .unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].lease, worker.lease);
        assert!(!candidates[0].draining);
        assert!(format!("{runtime:?}").contains("worker_registered: false"));
        assert_eq!(
            *runtime.subscribe_health().borrow(),
            CallControlRuntimeHealth::Healthy
        );

        runtime.shutdown(Duration::from_secs(1)).await;
        let retained = repository
            .worker_snapshot(worker.lease.worker_id)
            .await
            .unwrap();
        assert_eq!(retained.lease, worker.lease);
        assert!(!retained.draining);
    }

    #[tokio::test]
    async fn control_runtime_projector_pauses_readiness_after_persistent_failure() {
        let clock: Arc<dyn CoordinationClock> = Arc::new(RuntimeCoordinationClock(Arc::new(
            ManualCallClock::new(at(0)),
        )));
        let projection: Arc<dyn CoordinationProjection> = Arc::new(
            MemoryCoordinator::new(
                DeploymentId::parse("control-projector-health-test").unwrap(),
                clock,
                128,
            )
            .unwrap(),
        );
        let (health, mut observed_health) = watch::channel(CallControlRuntimeHealth::Healthy);
        let supervisor = ControlPlaneSupervisor::start(
            Arc::new(UnavailableCoordinationOutbox),
            projection,
            health.clone(),
        );

        tokio::time::timeout(Duration::from_secs(4), async {
            while *observed_health.borrow() != CallControlRuntimeHealth::Degraded {
                observed_health.changed().await.unwrap();
            }
        })
        .await
        .expect("persistent projection failure paused readiness");
        supervisor.shutdown(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn public_control_runtime_builder_rejects_local_backends() {
        let error = build_call_control_runtime(
            CallControlRuntimeConfig {
                backend: CallRepositoryBackendConfig::Memory,
                control_key: vec![0x71; 32],
                timeouts: CallTimeoutPolicy {
                    setup: Duration::from_secs(30),
                    media_idle: Duration::from_secs(30),
                    transfer: Duration::from_secs(30),
                    ending: Duration::from_secs(30),
                },
                eligible_workers: BTreeSet::new(),
                coordination: CallServiceCoordinationConfig::new(
                    DeploymentId::parse("control-runtime-local-reject").unwrap(),
                ),
            },
            Arc::new(SamePrincipalAttachmentResolver),
            Arc::new(ManualCallClock::new(at(0))),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            CallServiceRuntimeError::InvalidConfiguration("split call control requires PostgreSQL")
        ));
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
            RuntimeTaskControl {
                cancel_all: cancel.clone(),
                cancel: cancel_rx,
                health,
            },
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
            RuntimeTaskControl {
                cancel_all: cancel,
                cancel: cancel_rx,
                health,
            },
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
            RuntimeTaskControl {
                cancel_all: cancel,
                cancel: cancel_rx,
                health,
            },
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
            Arc::new(RepositoryWorkerLeaseAuthority(repository)),
            original.lease,
            tokio::time::Instant::now(),
            Duration::from_secs(30),
            Duration::from_millis(10),
            clock,
            RuntimeTaskControl {
                cancel_all: cancel.clone(),
                cancel: cancel.subscribe(),
                health: health.clone(),
            },
        ));
        tokio::time::timeout(Duration::from_secs(1), sibling_cancel.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(*sibling_cancel.borrow());
        assert_eq!(*health.borrow(), RuntimeSupervisorHealth::LeaseLost);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn renewal_outage_cannot_extend_the_last_confirmed_lease() {
        let repository = Arc::new(MemoryRepository::new());
        let worker =
            registered_worker(&repository, WorkerId::new(), at(0), Duration::from_secs(30)).await;
        let clock = Arc::new(ManualCallClock::new(at(0)));
        let (cancel, mut sibling_cancel) = watch::channel(false);
        let (health, mut health_rx) = watch::channel(RuntimeSupervisorHealth::Healthy);
        let registered_at = tokio::time::Instant::now();
        let task = tokio::spawn(run_worker_renewal(
            Arc::new(UnavailableLeaseAuthority),
            worker.lease,
            registered_at,
            Duration::from_millis(80),
            Duration::from_millis(10),
            clock,
            RuntimeTaskControl {
                cancel_all: cancel.clone(),
                cancel: cancel.subscribe(),
                health,
            },
        ));

        tokio::time::timeout(Duration::from_millis(50), health_rx.changed())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(*health_rx.borrow(), RuntimeSupervisorHealth::Degraded);
        while *health_rx.borrow() != RuntimeSupervisorHealth::LeaseLost {
            tokio::time::timeout(Duration::from_millis(250), health_rx.changed())
                .await
                .unwrap()
                .unwrap();
        }
        tokio::time::timeout(Duration::from_millis(50), sibling_cancel.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(*sibling_cancel.borrow());
        assert!(tokio::time::Instant::now() >= registered_at + Duration::from_millis(80));
        task.await.unwrap();
    }
}
