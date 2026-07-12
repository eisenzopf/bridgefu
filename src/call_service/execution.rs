//! Bounded ownership of inbound signaling and authoritative rvoip lifecycle.
//!
//! The compatibility rvoip broadcast is intentionally absent from this
//! module. Admission, connection indexing, lifecycle reconciliation, and call
//! actors all use bounded single-consumer channels whose tasks are owned by
//! [`CallExecutionSupervisor`].

use std::collections::{HashMap, HashSet, VecDeque};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures_util::FutureExt;
use rvoip_core::adapter::{EndReason, RejectReason};
use rvoip_core::commands::InboundAction;
use rvoip_core::connection::Transport;
use rvoip_core::conversation::ConversationPolicy;
use rvoip_core::ids::{
    BridgeId, ConnectionId, ConversationId, ParticipantId, SessionId, TenantId as RvoipTenantId,
};
use rvoip_core::session::SessionMedium;
use rvoip_core::{
    InboundAdmission, OperationalEndReason, OperationalEvent, OperationalEventKind,
    OperationalEventStreamHealth, OperationalEventStreamHealthSubscription, Orchestrator,
};
use thiserror::Error;
use tokio::sync::{mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};

use crate::call_engine::{
    AttachmentTransport, CallCommand, CallId, CallState, ClaimedDeadline, ClaimedOutbox,
    CommandCommit, CommandId, DeadlineKind, EffectIntent, FailureDetails, LegId, LegState,
    RepositoryError, RestartClaim, TransferResult,
};

use super::{
    BoundConnectionStateCommit, CallExecutionPlan, CallServiceError, CallServiceRuntime,
    ClaimedControlEffect, ControlIntent, EffectResultOutcome, EffectResultReconciliation,
    InboundAttachmentError, InboundAttachmentRequest, InboundAttachmentResult,
    MediaActivityGeneration, MediaActivityObservation, ProviderEventReconciliationOutcome,
    ProviderEventReconciliationTransaction, ProviderKind, RuntimeSupervisorHealth,
    ServiceCommandOutcome, ServiceCommandTransaction, ServiceEffectPayload, ServiceEffectResult,
    StoredServiceCall,
};

const OPERATIONAL_MAILBOX_PER_CALL: usize = 64;
const ACTOR_COMMAND_MAILBOX: usize = 16;
const ACTOR_PENDING_WORK_CAPACITY: usize = 16;
const REPOSITORY_RETRY_MIN: Duration = Duration::from_millis(25);
const REPOSITORY_RETRY_MAX: Duration = Duration::from_secs(1);
const WORK_POLL_INTERVAL: Duration = Duration::from_millis(250);
// A live worker never intentionally reclaims its own ambiguous operation.
// Restart recovery resets claims immediately after a fence change, so a long
// TTL protects retained in-process results without delaying crash recovery.
const WORK_CLAIM_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const WORK_BATCH_SIZE: usize = 64;
const EXTERNAL_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const AUTHORITY_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const TERMINAL_RETIRE_QUIET: Duration = Duration::from_secs(1);

/// Installation or lifecycle failure for the call execution owner.
#[derive(Debug, Error)]
pub enum CallExecutionError {
    /// rvoip rejected installation or an owned operation.
    #[error("rvoip call execution setup failed: {0}")]
    Rvoip(#[from] rvoip_core::RvoipError),
    /// A configured capacity or timeout is invalid.
    #[error("invalid call execution configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// Durable startup recovery failed before listeners could be opened.
    #[error("durable call execution recovery failed: {0}")]
    Repository(#[from] RepositoryError),
    /// Durable startup recovery exceeded the configured setup boundary.
    #[error("durable call execution recovery timed out")]
    RecoveryTimeout,
    /// The worker fence was already unavailable while installing execution.
    #[error("durable call execution authority is unavailable")]
    RuntimeUnavailable,
}

/// One process-owned execution supervisor.
pub struct CallExecutionSupervisor {
    drain: watch::Sender<bool>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl CallExecutionSupervisor {
    /// Installs both correctness streams before adapters are registered and
    /// starts their single process owner.
    pub async fn install(
        orchestrator: Arc<Orchestrator>,
        call_runtime: Arc<CallServiceRuntime>,
        admission_capacity: usize,
        setup_timeout: Duration,
    ) -> Result<Self, CallExecutionError> {
        if admission_capacity == 0 {
            return Err(CallExecutionError::InvalidConfiguration(
                "admission capacity must be positive",
            ));
        }
        if setup_timeout.is_zero() {
            return Err(CallExecutionError::InvalidConfiguration(
                "setup timeout must be positive",
            ));
        }
        let admission =
            orchestrator.install_inbound_admission_gate(admission_capacity, setup_timeout)?;
        let operational =
            orchestrator.install_operational_event_stream(
                admission_capacity.checked_mul(8).ok_or(
                    CallExecutionError::InvalidConfiguration("operational event capacity overflow"),
                )?,
            )?;
        let operational_health = orchestrator.subscribe_operational_event_stream_health()?;
        if operational_health.current() != OperationalEventStreamHealth::Healthy {
            return Err(CallExecutionError::RuntimeUnavailable);
        }
        let mut runtime_health = call_runtime.subscribe_supervisor_health();
        recover_before_listeners_with_health(
            Arc::clone(&orchestrator),
            Arc::clone(&call_runtime),
            setup_timeout,
            &mut runtime_health,
        )
        .await?;
        let (drain, drain_rx) = watch::channel(false);
        let (stop, stop_rx) = watch::channel(false);
        let task = tokio::spawn(run_supervisor(
            admission,
            operational,
            orchestrator,
            call_runtime,
            admission_capacity,
            setup_timeout,
            drain_rx,
            stop_rx,
            runtime_health,
            operational_health,
        ));
        Ok(Self {
            drain,
            stop,
            task: Some(task),
        })
    }

    /// Stops accepting new signaling while retaining the operational stream
    /// and actors needed to observe listener/connection teardown.
    pub fn begin_drain(&self) {
        let _ = self.drain.send(true);
    }

    /// Stops new admission, drains owned actors, and aborts only as the
    /// caller-supplied bounded fallback.
    pub async fn shutdown(mut self, deadline: Duration) {
        let _ = self.drain.send(true);
        let _ = self.stop.send(true);
        let Some(mut task) = self.task.take() else {
            return;
        };
        if tokio::time::timeout(deadline, &mut task).await.is_err() {
            tracing::warn!("call execution supervisor did not drain; aborting owned root task");
            task.abort();
            let _ = task.await;
        }
    }
}

async fn recover_before_listeners_with_health(
    orchestrator: Arc<Orchestrator>,
    runtime: Arc<CallServiceRuntime>,
    setup_timeout: Duration,
    runtime_health: &mut watch::Receiver<RuntimeSupervisorHealth>,
) -> Result<(), CallExecutionError> {
    let recovery = tokio::time::timeout(
        setup_timeout,
        recover_before_listeners(orchestrator, runtime),
    );
    await_while_runtime_owned(recovery, runtime_health)
        .await
        .map_err(|()| CallExecutionError::RuntimeUnavailable)?
        .map_err(|_| CallExecutionError::RecoveryTimeout)?
        .map_err(CallExecutionError::Repository)
}

impl Drop for CallExecutionSupervisor {
    fn drop(&mut self) {
        let _ = self.drain.send(true);
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Advances every call left behind by an older fence before any public
/// signaling listener is constructed. The second loop completes the cleanup
/// effects emitted by those failures; no recovered process-local route is
/// ever activated or migrated.
async fn recover_before_listeners(
    orchestrator: Arc<Orchestrator>,
    runtime: Arc<CallServiceRuntime>,
) -> Result<(), RepositoryError> {
    let worker = runtime.worker().lease;
    // Recovery is already cancelled as one future by the runtime-health
    // guard installed by `recover_before_listeners_with_health`. Keep this
    // sender alive so nested bound-state commits see `Running` rather than a
    // closed watch channel, which is deliberately interpreted as authority
    // loss by normal live actors.
    let (_recovery_authority, shutdown) = watch::channel(ActorShutdown::Running);
    loop {
        let claims = runtime
            .repository()
            .claim_restart_calls(worker, runtime.observation_time(), WORK_BATCH_SIZE)
            .await?;
        if claims.is_empty() {
            break;
        }
        for claim in claims {
            recover_restarted_call(claim, Arc::clone(&runtime), shutdown.clone()).await?;
        }
    }
    for _ in 0..10_000 {
        let work = claim_startup_cleanup(Arc::clone(&runtime)).await?;
        if work.is_empty() {
            return Ok(());
        }
        for item in work {
            let _ = actor_work_call_id(&item).ok_or(RepositoryError::Unavailable)?;
            let outcome = execute_actor_work(
                item,
                Arc::clone(&orchestrator),
                Arc::clone(&runtime),
                HashMap::new(),
                None,
                shutdown.clone(),
            )
            .await;
            outcome.result?;
        }
    }
    Err(RepositoryError::Unavailable)
}

async fn claim_startup_cleanup(
    runtime: Arc<CallServiceRuntime>,
) -> Result<Vec<ActorWork>, RepositoryError> {
    let worker = runtime.worker().lease;
    let at = runtime.observation_time();
    let mut work = Vec::new();
    work.extend(
        runtime
            .repository()
            .claim_outbox(worker, at, WORK_CLAIM_TTL, WORK_BATCH_SIZE)
            .await?
            .into_iter()
            .map(ActorWork::Call),
    );
    work.extend(
        runtime
            .service_repository()
            .claim_control_effects(worker, at, WORK_CLAIM_TTL, WORK_BATCH_SIZE)
            .await?
            .into_iter()
            .map(ActorWork::Control),
    );
    work.extend(
        runtime
            .repository()
            .claim_provider_events(worker, at, WORK_CLAIM_TTL, WORK_BATCH_SIZE)
            .await?
            .into_iter()
            .map(ActorWork::Provider),
    );
    work.extend(
        runtime
            .repository()
            .claim_due_deadlines(worker, at, WORK_CLAIM_TTL, WORK_BATCH_SIZE)
            .await?
            .into_iter()
            .map(ActorWork::Deadline),
    );
    Ok(work)
}

fn actor_work_call_id(work: &ActorWork) -> Option<CallId> {
    match work {
        ActorWork::Call(claim) => Some(claim.record.call_id),
        ActorWork::Control(claim) => Some(claim.record.call_id),
        ActorWork::Provider(claim) => claim.event.target.as_ref().map(|target| target.call_id),
        ActorWork::Deadline(claim) => Some(claim.record.call_id),
        ActorWork::Restart(claim) => Some(claim.call.aggregate.id()),
    }
}

struct ProvenAdmission {
    admission: InboundAdmission,
    consumed: InboundAttachmentResult,
}

struct AdmissionProofResult {
    connection_id: ConnectionId,
    proven: Option<ProvenAdmission>,
    panicked: bool,
}

#[derive(Clone)]
struct ConnectionOwner {
    call_id: CallId,
    leg_id: LegId,
}

struct ActorSlot {
    commands: mpsc::Sender<ActorCommand>,
    operational: mpsc::Sender<OperationalEvent>,
    work: mpsc::Sender<ActorWork>,
    retiring: Arc<AtomicBool>,
}

enum ActorCommand {
    Admit(ProvenAdmission),
}

#[derive(Clone)]
enum ActorWork {
    Call(ClaimedOutbox),
    Control(ClaimedControlEffect),
    Provider(crate::call_engine::ClaimedProviderEvent),
    Deadline(ClaimedDeadline),
    Restart(Box<RestartClaim>),
}

#[derive(Default)]
struct WorkClaimBatch {
    items: Vec<ActorWork>,
}

struct ActorExit {
    call_id: CallId,
    tenant_id: crate::call_engine::TenantId,
    panicked: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActorShutdown {
    Running,
    Graceful,
    LeaseLost,
}

#[derive(Clone)]
struct ActorBinding {
    connection_id: ConnectionId,
    leg_id: LegId,
    binding_generation: crate::call_engine::BindingGeneration,
    state: LegState,
}

struct AdmissionOperationResult {
    connection_id: ConnectionId,
    conversation_id: Option<ConversationId>,
    session_id: Option<SessionId>,
    result: Result<(), rvoip_core::RvoipError>,
}

struct WorkOperationResult {
    effect_id: Option<crate::call_engine::EffectId>,
    bridge_update: Option<Option<BridgeId>>,
    result: Result<(), RepositoryError>,
}

struct CallActor {
    call_id: CallId,
    tenant_id: crate::call_engine::TenantId,
    plan: CallExecutionPlan,
    orchestrator: Arc<Orchestrator>,
    runtime: Arc<CallServiceRuntime>,
    commands: mpsc::Receiver<ActorCommand>,
    operational: mpsc::Receiver<OperationalEvent>,
    work: mpsc::Receiver<ActorWork>,
    drain: watch::Receiver<bool>,
    shutdown: watch::Receiver<ActorShutdown>,
    bindings: HashMap<LegId, ActorBinding>,
    pending_admissions: VecDeque<ProvenAdmission>,
    admission_operation: JoinSet<AdmissionOperationResult>,
    pending_work: VecDeque<ActorWork>,
    work_operation: JoinSet<WorkOperationResult>,
    bridge_id: Option<BridgeId>,
    conversation_id: Option<ConversationId>,
    session_id: Option<SessionId>,
    terminal: bool,
    retiring: Arc<AtomicBool>,
}

#[allow(clippy::too_many_arguments)]
async fn run_supervisor(
    mut admissions: mpsc::Receiver<InboundAdmission>,
    mut operational: mpsc::Receiver<OperationalEvent>,
    orchestrator: Arc<Orchestrator>,
    runtime: Arc<CallServiceRuntime>,
    admission_capacity: usize,
    setup_timeout: Duration,
    mut drain: watch::Receiver<bool>,
    mut stop: watch::Receiver<bool>,
    mut runtime_health: watch::Receiver<RuntimeSupervisorHealth>,
    mut operational_health: OperationalEventStreamHealthSubscription,
) {
    let mut proof_tasks = JoinSet::new();
    let mut inflight_admissions = HashSet::<ConnectionId>::new();
    let mut actors = JoinSet::<ActorExit>::new();
    let mut work_claims = JoinSet::<WorkClaimBatch>::new();
    let mut actor_slots = HashMap::<CallId, ActorSlot>::new();
    let mut connection_owners = HashMap::<ConnectionId, ConnectionOwner>::new();
    let mut leg_owners = HashMap::<(CallId, LegId), ConnectionId>::new();
    let mut work_wakeups = runtime.subscribe_work_wakeups();
    let initial_runtime_health = *runtime_health.borrow();
    let (actor_shutdown, actor_shutdown_rx) = watch::channel(ActorShutdown::Running);
    let mut work_poll = tokio::time::interval(WORK_POLL_INTERVAL);
    work_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut accepting_admission = true;
    let mut accepting_work = true;
    let mut lease_lost = false;
    let mut stopping = false;
    let mut pending_operational = None;
    let mut pending_work = VecDeque::new();
    let actor_task_capacity = runtime
        .worker()
        .max_calls
        .saturating_add(admission_capacity);
    match initial_runtime_health {
        RuntimeSupervisorHealth::Healthy | RuntimeSupervisorHealth::Degraded => {}
        RuntimeSupervisorHealth::Draining => {
            accepting_admission = false;
            accepting_work = false;
            admissions.close();
        }
        RuntimeSupervisorHealth::LeaseLost | RuntimeSupervisorHealth::Stopped => {
            lease_lost = true;
            accepting_admission = false;
            accepting_work = false;
            admissions.close();
            let _ = actor_shutdown.send(ActorShutdown::LeaseLost);
        }
    }
    if lease_lost {
        enter_authority_loss(
            &mut admissions,
            &mut proof_tasks,
            &mut inflight_admissions,
            &mut work_claims,
            &mut actors,
            &mut actor_slots,
            &mut connection_owners,
            &mut leg_owners,
            &mut pending_work,
            &actor_shutdown,
            &orchestrator,
        )
        .await;
        return;
    }

    loop {
        if stopping
            && proof_tasks.is_empty()
            && work_claims.is_empty()
            && pending_work.is_empty()
            && pending_operational.is_none()
            && operational.is_empty()
        {
            let _ = actor_shutdown.send(if lease_lost {
                ActorShutdown::LeaseLost
            } else {
                ActorShutdown::Graceful
            });
            break;
        }
        tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    stopping = true;
                    accepting_admission = false;
                    accepting_work = false;
                    admissions.close();
                    work_claims.abort_all();
                }
            }
            changed = runtime_health.changed() => {
                if changed.is_err() {
                    lease_lost = true;
                } else {
                    match *runtime_health.borrow() {
                        RuntimeSupervisorHealth::Healthy | RuntimeSupervisorHealth::Degraded => {}
                        RuntimeSupervisorHealth::Draining => {
                            accepting_admission = false;
                            accepting_work = false;
                            admissions.close();
                        }
                        RuntimeSupervisorHealth::LeaseLost | RuntimeSupervisorHealth::Stopped => {
                            lease_lost = true;
                        }
                    }
                }
                if lease_lost {
                    enter_authority_loss(
                        &mut admissions,
                        &mut proof_tasks,
                        &mut inflight_admissions,
                        &mut work_claims,
                        &mut actors,
                        &mut actor_slots,
                        &mut connection_owners,
                        &mut leg_owners,
                        &mut pending_work,
                        &actor_shutdown,
                        &orchestrator,
                    ).await;
                    break;
                }
            }
            health = operational_health.changed(), if !lease_lost => {
                if health != OperationalEventStreamHealth::Healthy {
                    tracing::error!("authoritative operational stream degraded");
                    lease_lost = true;
                    enter_authority_loss(
                        &mut admissions,
                        &mut proof_tasks,
                        &mut inflight_admissions,
                        &mut work_claims,
                        &mut actors,
                        &mut actor_slots,
                        &mut connection_owners,
                        &mut leg_owners,
                        &mut pending_work,
                        &actor_shutdown,
                        &orchestrator,
                    ).await;
                    break;
                }
            }
            changed = drain.changed() => {
                if changed.is_err() || *drain.borrow() {
                    accepting_admission = false;
                    admissions.close();
                    while let Ok(admission) = admissions.try_recv() {
                        let _ = tokio::time::timeout(
                            AUTHORITY_TEARDOWN_TIMEOUT,
                            admission.reject(RejectReason::ServerError),
                        ).await;
                    }
                }
            }
            result = actors.join_next(), if !actors.is_empty() => {
                match result {
                    Some(Ok(exit)) => {
                        if exit.panicked {
                            fail_panicked_actor(
                                exit.call_id,
                                &exit.tenant_id,
                                &connection_owners,
                                &orchestrator,
                                &runtime,
                                !lease_lost,
                            ).await;
                        }
                        actor_slots.remove(&exit.call_id);
                        connection_owners.retain(|_, owner| owner.call_id != exit.call_id);
                        leg_owners.retain(|(call_id, _), _| *call_id != exit.call_id);
                    }
                    Some(Err(error)) => {
                        tracing::error!(%error, "call actor panicked");
                    }
                    None => {}
                }
            }
            result = proof_tasks.join_next(), if !proof_tasks.is_empty() => {
                match result {
                    Some(Ok(result)) => {
                        if result.panicked {
                            tracing::error!(connection_id = %result.connection_id, "attachment proof task panicked");
                        }
                        if let Some(proven) = result.proven {
                            if !accepting_admission {
                                fail_unowned_proven_admission(
                                    proven,
                                    &orchestrator,
                                    &runtime,
                                    !lease_lost,
                                ).await;
                            } else {
                                register_proven_admission(
                                    proven,
                                    &orchestrator,
                                    &runtime,
                                    &mut actor_slots,
                                    &mut connection_owners,
                                    &mut leg_owners,
                                    &mut actors,
                                    actor_task_capacity,
                                    drain.clone(),
                                    actor_shutdown_rx.clone(),
                                ).await;
                            }
                        }
                        inflight_admissions.remove(&result.connection_id);
                    }
                    Some(Err(error)) => tracing::error!(%error, "attachment proof task panicked"),
                    None => {}
                }
            }
            result = work_claims.join_next(), if !work_claims.is_empty() => {
                match result {
                    Some(Ok(batch)) => {
                        pending_work.extend(batch.items);
                    }
                    Some(Err(error)) => tracing::error!(%error, "durable work claim task panicked"),
                    None => {}
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(1)), if pending_operational.is_some() => {
                let event = pending_operational.take().expect("guarded operational event");
                pending_operational = try_route_operational_event(
                    event,
                    &orchestrator,
                    &actor_slots,
                    &connection_owners,
                ).await;
            }
            _ = tokio::time::sleep(Duration::from_millis(1)), if !pending_work.is_empty() && !lease_lost => {
                let item = pending_work.pop_front().expect("guarded claimed work");
                if let Some(item) = route_claimed_work(
                    item,
                    &orchestrator,
                    &runtime,
                    &mut actor_slots,
                    &mut connection_owners,
                    &mut leg_owners,
                    &mut actors,
                    actor_task_capacity,
                    drain.clone(),
                    actor_shutdown_rx.clone(),
                ).await {
                    pending_work.push_back(item);
                }
            }
            event = operational.recv(), if pending_operational.is_none() => {
                let Some(event) = event else {
                    tracing::error!("authoritative operational receiver closed");
                    lease_lost = true;
                    enter_authority_loss(
                        &mut admissions,
                        &mut proof_tasks,
                        &mut inflight_admissions,
                        &mut work_claims,
                        &mut actors,
                        &mut actor_slots,
                        &mut connection_owners,
                        &mut leg_owners,
                        &mut pending_work,
                        &actor_shutdown,
                        &orchestrator,
                    ).await;
                    break;
                };
                pending_operational = try_route_operational_event(
                    event,
                    &orchestrator,
                    &actor_slots,
                    &connection_owners,
                ).await;
            }
            admission = admissions.recv(), if accepting_admission && proof_tasks.len() < admission_capacity => {
                let Some(admission) = admission else {
                    accepting_admission = false;
                    accepting_work = false;
                    continue;
                };
                let runtime = Arc::clone(&runtime);
                let connection_id = admission.connection_id().clone();
                inflight_admissions.insert(connection_id.clone());
                proof_tasks.spawn(async move {
                    match AssertUnwindSafe(prove_admission(admission, runtime, setup_timeout))
                        .catch_unwind()
                        .await
                    {
                        Ok(result) => result,
                        Err(_) => AdmissionProofResult {
                            connection_id,
                            proven: None,
                            panicked: true,
                        },
                    }
                });
            }
            changed = work_wakeups.changed(), if accepting_work && pending_work.is_empty() && work_claims.is_empty() => {
                if changed.is_ok() {
                    spawn_work_claim(&mut work_claims, Arc::clone(&runtime));
                }
            }
            _ = work_poll.tick(), if accepting_work && pending_work.is_empty() && work_claims.is_empty() => {
                spawn_work_claim(&mut work_claims, Arc::clone(&runtime));
            }
        }
    }

    while let Ok(admission) = admissions.try_recv() {
        let _ = tokio::time::timeout(
            AUTHORITY_TEARDOWN_TIMEOUT,
            admission.reject(RejectReason::ServerError),
        )
        .await;
    }
    while let Some(result) = proof_tasks.join_next().await {
        if let Ok(result) = result {
            if let Some(proven) = result.proven {
                fail_unowned_proven_admission(proven, &orchestrator, &runtime, !lease_lost).await;
            }
            inflight_admissions.remove(&result.connection_id);
        }
    }
    work_claims.abort_all();
    while work_claims.join_next().await.is_some() {}
    let _ = actor_shutdown.send(if lease_lost {
        ActorShutdown::LeaseLost
    } else {
        ActorShutdown::Graceful
    });
    actor_slots.clear();
    while let Some(result) = actors.join_next().await {
        if let Err(error) = result {
            tracing::warn!(%error, "call actor panicked while draining");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn enter_authority_loss(
    admissions: &mut mpsc::Receiver<InboundAdmission>,
    proof_tasks: &mut JoinSet<AdmissionProofResult>,
    inflight_admissions: &mut HashSet<ConnectionId>,
    work_claims: &mut JoinSet<WorkClaimBatch>,
    actors: &mut JoinSet<ActorExit>,
    actor_slots: &mut HashMap<CallId, ActorSlot>,
    connection_owners: &mut HashMap<ConnectionId, ConnectionOwner>,
    leg_owners: &mut HashMap<(CallId, LegId), ConnectionId>,
    pending_work: &mut VecDeque<ActorWork>,
    actor_shutdown: &watch::Sender<ActorShutdown>,
    orchestrator: &Arc<Orchestrator>,
) {
    admissions.close();
    proof_tasks.abort_all();
    work_claims.abort_all();
    pending_work.clear();
    let _ = actor_shutdown.send(ActorShutdown::LeaseLost);
    actors.abort_all();

    let owned_connections = take_authority_loss_connections(connection_owners, inflight_admissions);
    actor_slots.clear();
    connection_owners.clear();
    leg_owners.clear();

    let mut rejections = JoinSet::new();
    while let Ok(admission) = admissions.try_recv() {
        rejections.spawn(async move {
            let _ = tokio::time::timeout(
                AUTHORITY_TEARDOWN_TIMEOUT,
                admission.reject(RejectReason::ServerError),
            )
            .await;
        });
    }
    while rejections.join_next().await.is_some() {}
    while proof_tasks.join_next().await.is_some() {}
    while work_claims.join_next().await.is_some() {}
    while actors.join_next().await.is_some() {}
    bounded_end_connections(orchestrator, owned_connections, "execution authority lost").await;
}

fn take_authority_loss_connections(
    connection_owners: &HashMap<ConnectionId, ConnectionOwner>,
    inflight_admissions: &mut HashSet<ConnectionId>,
) -> Vec<ConnectionId> {
    let mut owned = connection_owners.keys().cloned().collect::<HashSet<_>>();
    owned.extend(inflight_admissions.drain());
    owned.into_iter().collect()
}

async fn bounded_end_connections(
    orchestrator: &Arc<Orchestrator>,
    connection_ids: Vec<ConnectionId>,
    detail: &'static str,
) {
    let mut teardowns = JoinSet::new();
    for connection_id in connection_ids {
        let orchestrator = Arc::clone(orchestrator);
        teardowns.spawn(async move {
            let _ = tokio::time::timeout(
                AUTHORITY_TEARDOWN_TIMEOUT,
                orchestrator.end_connection(
                    connection_id,
                    EndReason::Failed {
                        detail: detail.into(),
                    },
                ),
            )
            .await;
        });
    }
    while teardowns.join_next().await.is_some() {}
}

fn spawn_work_claim(claims: &mut JoinSet<WorkClaimBatch>, runtime: Arc<CallServiceRuntime>) {
    claims.spawn(async move { claim_durable_work(runtime).await });
}

async fn claim_durable_work(runtime: Arc<CallServiceRuntime>) -> WorkClaimBatch {
    let worker = runtime.worker().lease;
    let at = runtime.observation_time();
    let mut batch = WorkClaimBatch::default();
    match runtime
        .repository()
        .claim_outbox(worker, at, WORK_CLAIM_TTL, WORK_BATCH_SIZE)
        .await
    {
        Ok(claims) => batch.items.extend(claims.into_iter().map(ActorWork::Call)),
        Err(error) => tracing::warn!(%error, "claiming durable call effects failed"),
    }
    match runtime
        .service_repository()
        .claim_control_effects(worker, at, WORK_CLAIM_TTL, WORK_BATCH_SIZE)
        .await
    {
        Ok(claims) => batch
            .items
            .extend(claims.into_iter().map(ActorWork::Control)),
        Err(error) => tracing::warn!(%error, "claiming durable control effects failed"),
    }
    match runtime
        .repository()
        .claim_provider_events(worker, at, WORK_CLAIM_TTL, WORK_BATCH_SIZE)
        .await
    {
        Ok(claims) => batch
            .items
            .extend(claims.into_iter().map(ActorWork::Provider)),
        Err(error) => tracing::warn!(%error, "claiming provider events failed"),
    }
    match runtime
        .repository()
        .claim_due_deadlines(worker, at, WORK_CLAIM_TTL, WORK_BATCH_SIZE)
        .await
    {
        Ok(claims) => batch
            .items
            .extend(claims.into_iter().map(ActorWork::Deadline)),
        Err(error) => tracing::warn!(%error, "claiming due call deadlines failed"),
    }
    match runtime
        .repository()
        .claim_restart_calls(worker, at, WORK_BATCH_SIZE)
        .await
    {
        Ok(claims) => batch.items.extend(
            claims
                .into_iter()
                .map(|claim| ActorWork::Restart(Box::new(claim))),
        ),
        Err(error) => tracing::warn!(%error, "claiming restart call work failed"),
    }
    batch
}

async fn prove_admission(
    admission: InboundAdmission,
    runtime: Arc<CallServiceRuntime>,
    setup_timeout: Duration,
) -> AdmissionProofResult {
    let connection_id = admission.connection_id().clone();
    let proven = prove_admission_inner(admission, runtime, setup_timeout).await;
    AdmissionProofResult {
        connection_id,
        proven,
        panicked: false,
    }
}

async fn prove_admission_inner(
    mut admission: InboundAdmission,
    runtime: Arc<CallServiceRuntime>,
    setup_timeout: Duration,
) -> Option<ProvenAdmission> {
    let connection_id = admission.connection_id().clone();
    let transport = admission.transport();
    let principal = match admission.authenticated_principal() {
        Ok(principal) => principal,
        Err(_) => {
            let _ = admission.reject(RejectReason::Forbidden).await;
            return None;
        }
    };
    let mut context = match admission.take_inbound_context() {
        Ok(Some(context)) if context.is_bound_to(&connection_id, transport, &principal) => context,
        _ => {
            let _ = admission.reject(RejectReason::Forbidden).await;
            return None;
        }
    };
    let routing_token = context.take_routing_hint().map(|hint| hint.into_secret());
    let attachment_transport = match transport {
        Transport::Sip => AttachmentTransport::Sip,
        Transport::WebRtc => AttachmentTransport::WebRtc,
        _ => {
            let _ = admission.reject(RejectReason::NotAcceptable).await;
            return None;
        }
    };
    let request = InboundAttachmentRequest::new(
        principal,
        routing_token,
        attachment_transport,
        runtime.worker().lease,
        connection_id,
    );
    let mut runtime_health = runtime.subscribe_supervisor_health();
    let service = runtime.service();
    let consume = tokio::time::timeout(setup_timeout, service.consume_inbound_attachment(request));
    let consumed = match await_while_runtime_owned(consume, &mut runtime_health).await {
        Ok(consumed) => consumed,
        Err(()) => {
            let _ = admission.reject(RejectReason::ServerError).await;
            return None;
        }
    };
    let consumed = match consumed {
        Ok(Ok(consumed)) => consumed,
        Ok(Err(InboundAttachmentError::ProofRejected)) => {
            metrics::counter!("bridgefu_attachment_admission_total", "result" => "rejected")
                .increment(1);
            let _ = admission.reject(RejectReason::Forbidden).await;
            return None;
        }
        Ok(Err(InboundAttachmentError::Unavailable)) | Err(_) => {
            metrics::counter!("bridgefu_attachment_admission_total", "result" => "unavailable")
                .increment(1);
            let _ = admission.reject(RejectReason::ServerError).await;
            return None;
        }
    };
    Some(ProvenAdmission {
        admission,
        consumed,
    })
}

async fn await_while_runtime_owned<F, T>(
    future: F,
    health: &mut watch::Receiver<RuntimeSupervisorHealth>,
) -> Result<T, ()>
where
    F: std::future::Future<Output = T>,
{
    tokio::pin!(future);
    loop {
        if !matches!(
            *health.borrow(),
            RuntimeSupervisorHealth::Healthy | RuntimeSupervisorHealth::Degraded
        ) {
            return Err(());
        }
        tokio::select! {
            biased;
            changed = health.changed() => {
                if changed.is_err() {
                    return Err(());
                }
            }
            result = &mut future => return Ok(result),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn register_proven_admission(
    proven: ProvenAdmission,
    orchestrator: &Arc<Orchestrator>,
    runtime: &Arc<CallServiceRuntime>,
    actor_slots: &mut HashMap<CallId, ActorSlot>,
    connection_owners: &mut HashMap<ConnectionId, ConnectionOwner>,
    leg_owners: &mut HashMap<(CallId, LegId), ConnectionId>,
    actors: &mut JoinSet<ActorExit>,
    actor_task_capacity: usize,
    drain: watch::Receiver<bool>,
    shutdown: watch::Receiver<ActorShutdown>,
) {
    let call_id = proven.consumed.commit.call.aggregate.id();
    let tenant_id = proven.consumed.commit.call.aggregate.tenant_id().clone();
    let binding = &proven.consumed.binding;
    let connection_id = binding.connection_id.clone();
    let leg_id = binding.leg_id;
    let mut spawned = false;
    let mut inserted_index = false;
    if !actor_slots.contains_key(&call_id) {
        if !can_spawn_actor(actor_slots, runtime.worker().max_calls, actor_task_capacity) {
            fail_unowned_proven_admission(proven, orchestrator, runtime, true).await;
            return;
        }
        let stored = match load_service_call_while_runtime_owned(runtime, &tenant_id, call_id).await
        {
            Ok(stored) => stored,
            Err(_) => {
                fail_unowned_proven_admission(proven, orchestrator, runtime, true).await;
                return;
            }
        };
        if spawn_call_actor(
            stored,
            orchestrator,
            runtime,
            actor_slots,
            connection_owners,
            leg_owners,
            actors,
            drain,
            shutdown,
        )
        .is_err()
        {
            fail_unowned_proven_admission(proven, orchestrator, runtime, true).await;
            return;
        }
        spawned = true;
    }

    if !spawned {
        let indexed_connection = connection_owners.get(&connection_id);
        let indexed_leg = leg_owners.get(&(call_id, leg_id));
        let already_indexed_by_this_binding = matches!(
            (indexed_connection, indexed_leg),
            (Some(owner), Some(indexed_connection_id))
                if owner.call_id == call_id
                    && owner.leg_id == leg_id
                    && indexed_connection_id == &connection_id
        );
        if !already_indexed_by_this_binding
            && (indexed_connection.is_some() || indexed_leg.is_some())
        {
            fail_unowned_proven_admission(proven, orchestrator, runtime, true).await;
            return;
        }
        if !already_indexed_by_this_binding {
            connection_owners.insert(connection_id.clone(), ConnectionOwner { call_id, leg_id });
            leg_owners.insert((call_id, leg_id), connection_id.clone());
            inserted_index = true;
        }
    }

    let Some(slot) = actor_slots.get(&call_id) else {
        if inserted_index {
            connection_owners.remove(&connection_id);
            leg_owners.remove(&(call_id, leg_id));
        }
        fail_unowned_proven_admission(proven, orchestrator, runtime, true).await;
        return;
    };
    if let Err(error) = slot.commands.try_send(ActorCommand::Admit(proven)) {
        let ActorCommand::Admit(proven) = error.into_inner();
        if inserted_index {
            connection_owners.remove(&connection_id);
            leg_owners.remove(&(call_id, leg_id));
        }
        tracing::error!(%call_id, %connection_id, "call actor admission mailbox is unavailable");
        fail_unowned_proven_admission(proven, orchestrator, runtime, true).await;
    }
}

fn active_actor_count(actor_slots: &HashMap<CallId, ActorSlot>) -> usize {
    actor_slots
        .values()
        .filter(|slot| !slot.retiring.load(Ordering::Acquire))
        .count()
}

fn can_spawn_actor(
    actor_slots: &HashMap<CallId, ActorSlot>,
    max_active: usize,
    max_total: usize,
) -> bool {
    active_actor_count(actor_slots) < max_active && actor_slots.len() < max_total
}

fn can_buffer_actor_work(pending: usize) -> bool {
    pending < ACTOR_PENDING_WORK_CAPACITY
}

#[allow(clippy::too_many_arguments)]
fn spawn_call_actor(
    stored: StoredServiceCall,
    orchestrator: &Arc<Orchestrator>,
    runtime: &Arc<CallServiceRuntime>,
    actor_slots: &mut HashMap<CallId, ActorSlot>,
    connection_owners: &mut HashMap<ConnectionId, ConnectionOwner>,
    leg_owners: &mut HashMap<(CallId, LegId), ConnectionId>,
    actors: &mut JoinSet<ActorExit>,
    drain: watch::Receiver<bool>,
    shutdown: watch::Receiver<ActorShutdown>,
) -> Result<(), ()> {
    let call_id = stored.call.aggregate.id();
    let stored_bindings = stored
        .call
        .bindings
        .values()
        .map(|binding| (binding.connection_id.clone(), binding.leg_id))
        .collect::<Vec<_>>();
    if stored_bindings.iter().any(|(connection_id, leg_id)| {
        connection_owners.contains_key(connection_id)
            || leg_owners.contains_key(&(call_id, *leg_id))
    }) {
        tracing::error!(%call_id, "durable connection index conflicts with a live actor");
        return Err(());
    }
    for (connection_id, leg_id) in &stored_bindings {
        connection_owners.insert(
            connection_id.clone(),
            ConnectionOwner {
                call_id,
                leg_id: *leg_id,
            },
        );
        leg_owners.insert((call_id, *leg_id), connection_id.clone());
    }
    let (commands_tx, commands_rx) = mpsc::channel(ACTOR_COMMAND_MAILBOX);
    let (operational_tx, operational_rx) = mpsc::channel(OPERATIONAL_MAILBOX_PER_CALL);
    let (work_tx, work_rx) = mpsc::channel(ACTOR_COMMAND_MAILBOX);
    let retiring = Arc::new(AtomicBool::new(false));
    actor_slots.insert(
        call_id,
        ActorSlot {
            commands: commands_tx,
            operational: operational_tx,
            work: work_tx,
            retiring: Arc::clone(&retiring),
        },
    );
    let actor = CallActor::new(
        stored,
        Arc::clone(orchestrator),
        Arc::clone(runtime),
        commands_rx,
        operational_rx,
        work_rx,
        drain,
        shutdown,
        retiring,
    );
    let tenant_id = actor.tenant_id.clone();
    actors.spawn(async move {
        match AssertUnwindSafe(actor.run()).catch_unwind().await {
            Ok(exit) => exit,
            Err(_) => ActorExit {
                call_id,
                tenant_id,
                panicked: true,
            },
        }
    });
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn route_claimed_work(
    item: ActorWork,
    orchestrator: &Arc<Orchestrator>,
    runtime: &Arc<CallServiceRuntime>,
    actor_slots: &mut HashMap<CallId, ActorSlot>,
    connection_owners: &mut HashMap<ConnectionId, ConnectionOwner>,
    leg_owners: &mut HashMap<(CallId, LegId), ConnectionId>,
    actors: &mut JoinSet<ActorExit>,
    actor_task_capacity: usize,
    drain: watch::Receiver<bool>,
    shutdown: watch::Receiver<ActorShutdown>,
) -> Option<ActorWork> {
    let (tenant_id, call_id) = match &item {
        ActorWork::Call(claim) => (&claim.record.tenant_id, claim.record.call_id),
        ActorWork::Control(claim) => (&claim.record.tenant_id, claim.record.call_id),
        ActorWork::Provider(claim) => {
            let Some(target) = claim.event.target.as_ref() else {
                tracing::error!("claimed provider event has no durable target");
                return Some(item);
            };
            (&target.tenant_id, target.call_id)
        }
        ActorWork::Deadline(claim) => (&claim.record.tenant_id, claim.record.call_id),
        ActorWork::Restart(claim) => (claim.call.aggregate.tenant_id(), claim.call.aggregate.id()),
    };
    if !actor_slots.contains_key(&call_id) {
        if !can_spawn_actor(actor_slots, runtime.worker().max_calls, actor_task_capacity) {
            tracing::error!(%call_id, "durable work could not allocate its reserved call actor");
            return Some(item);
        }
        let stored = match load_service_call_while_runtime_owned(runtime, tenant_id, call_id).await
        {
            Ok(stored) => stored,
            Err(error) => {
                tracing::warn!(%call_id, %error, "loading claimed call work failed");
                return Some(item);
            }
        };
        if spawn_call_actor(
            stored,
            orchestrator,
            runtime,
            actor_slots,
            connection_owners,
            leg_owners,
            actors,
            drain,
            shutdown,
        )
        .is_err()
        {
            return Some(item);
        }
    }
    let Some(actor) = actor_slots.get(&call_id) else {
        return Some(item);
    };
    match try_deliver_actor_work(&actor.work, item) {
        None => None,
        Some(item) => {
            tracing::debug!(%call_id, "call actor work mailbox is temporarily unavailable");
            Some(item)
        }
    }
}

fn try_deliver_actor_work(mailbox: &mpsc::Sender<ActorWork>, item: ActorWork) -> Option<ActorWork> {
    match mailbox.try_send(item) {
        Ok(()) => None,
        Err(error) => Some(error.into_inner()),
    }
}

async fn fail_unowned_proven_admission(
    proven: ProvenAdmission,
    orchestrator: &Arc<Orchestrator>,
    runtime: &Arc<CallServiceRuntime>,
    allow_durable_write: bool,
) {
    let connection_id = proven.consumed.binding.connection_id.clone();
    let _ = tokio::time::timeout(
        AUTHORITY_TEARDOWN_TIMEOUT,
        proven.admission.reject(RejectReason::ServerError),
    )
    .await;
    if allow_durable_write {
        let failure = FailureDetails::sanitized(
            "execution_unavailable",
            "call execution owner unavailable after durable attachment",
            true,
        );
        let mut runtime_health = runtime.subscribe_supervisor_health();
        let compensation = tokio::time::timeout(
            Duration::from_secs(2),
            commit_binding_state(
                runtime,
                proven.consumed.commit.call.aggregate.tenant_id(),
                proven.consumed.commit.call.aggregate.id(),
                &proven.consumed.binding,
                LegState::Failed,
                Some(failure),
                runtime.observation_time(),
                None,
            ),
        );
        let _ = await_while_runtime_owned(compensation, &mut runtime_health).await;
    }
    let _ = tokio::time::timeout(
        AUTHORITY_TEARDOWN_TIMEOUT,
        orchestrator.end_connection(
            connection_id,
            EndReason::Failed {
                detail: "call execution owner unavailable".into(),
            },
        ),
    )
    .await;
}

async fn try_route_operational_event(
    event: OperationalEvent,
    orchestrator: &Arc<Orchestrator>,
    actors: &HashMap<CallId, ActorSlot>,
    owners: &HashMap<ConnectionId, ConnectionOwner>,
) -> Option<OperationalEvent> {
    let Some(owner) = owners.get(&event.connection_id) else {
        if matches!(event.kind, OperationalEventKind::Connected) {
            tracing::error!(connection_id = %event.connection_id, sequence = event.sequence, "unowned operational connection event");
            let _ = tokio::time::timeout(
                AUTHORITY_TEARDOWN_TIMEOUT,
                orchestrator.end_connection(
                    event.connection_id,
                    EndReason::Failed {
                        detail: "operational event has no durable owner".into(),
                    },
                ),
            )
            .await;
        }
        return None;
    };
    let Some(actor) = actors.get(&owner.call_id) else {
        tracing::error!(call_id = %owner.call_id, leg_id = %owner.leg_id, "operational event owner actor is missing");
        return None;
    };
    match actor.operational.try_send(event) {
        Ok(()) => None,
        Err(mpsc::error::TrySendError::Full(event)) => Some(event),
        Err(mpsc::error::TrySendError::Closed(event)) => {
            tracing::error!(call_id = %owner.call_id, leg_id = %owner.leg_id, "operational event owner actor closed");
            let _ = tokio::time::timeout(
                AUTHORITY_TEARDOWN_TIMEOUT,
                orchestrator.end_connection(
                    event.connection_id,
                    EndReason::Failed {
                        detail: "operational event owner closed".into(),
                    },
                ),
            )
            .await;
            None
        }
    }
}

async fn fail_panicked_actor(
    call_id: CallId,
    tenant_id: &crate::call_engine::TenantId,
    owners: &HashMap<ConnectionId, ConnectionOwner>,
    orchestrator: &Arc<Orchestrator>,
    runtime: &Arc<CallServiceRuntime>,
    allow_durable_write: bool,
) {
    let connections = owners
        .iter()
        .filter(|(_, owner)| owner.call_id == call_id)
        .map(|(connection_id, _)| connection_id.clone())
        .collect::<Vec<_>>();
    bounded_end_connections(orchestrator, connections, "call actor panicked").await;
    if !allow_durable_write {
        return;
    }
    let Ok(stored) = load_service_call_while_runtime_owned(runtime, tenant_id, call_id).await
    else {
        return;
    };
    for binding in stored.call.bindings.values() {
        let failure = FailureDetails::sanitized(
            "execution_panicked",
            "the process-owned call actor stopped unexpectedly",
            true,
        );
        let mut runtime_health = runtime.subscribe_supervisor_health();
        let compensation = tokio::time::timeout(
            Duration::from_secs(2),
            commit_binding_state(
                runtime,
                stored.call.aggregate.tenant_id(),
                call_id,
                binding,
                LegState::Failed,
                Some(failure),
                runtime.observation_time(),
                None,
            ),
        );
        let _ = await_while_runtime_owned(compensation, &mut runtime_health).await;
    }
}

async fn load_service_call_while_runtime_owned(
    runtime: &Arc<CallServiceRuntime>,
    tenant_id: &crate::call_engine::TenantId,
    call_id: CallId,
) -> Result<StoredServiceCall, RepositoryError> {
    let mut health = runtime.subscribe_supervisor_health();
    let repository = runtime.service_repository();
    await_while_runtime_owned(
        repository.load_service_call(tenant_id, call_id),
        &mut health,
    )
    .await
    .map_err(|()| RepositoryError::Unavailable)?
}

async fn activate_admission(
    proven: ProvenAdmission,
    orchestrator: Arc<Orchestrator>,
    tenant_id: crate::call_engine::TenantId,
    existing_session: Option<SessionId>,
    mut shutdown: watch::Receiver<ActorShutdown>,
) -> AdmissionOperationResult {
    let ProvenAdmission {
        admission,
        consumed,
    } = proven;
    let connection_id = consumed.binding.connection_id;
    let mut created_conversation = None;
    let mut created_session = None;
    let operation = supervise_rvoip_operation(async {
        let session_id = if let Some(session_id) = existing_session {
            session_id
        } else {
            let conversation_id = tokio::time::timeout(
                EXTERNAL_OPERATION_TIMEOUT,
                orchestrator.open_conversation(
                    RvoipTenantId::from_string(tenant_id.as_str()),
                    ConversationPolicy::default(),
                    HashMap::new(),
                ),
            )
            .await
            .map_err(|_| rvoip_core::RvoipError::InvalidState("conversation setup timed out"))??;
            created_conversation = Some(conversation_id.clone());
            let session_id = tokio::time::timeout(
                EXTERNAL_OPERATION_TIMEOUT,
                orchestrator.start_session(
                    conversation_id.clone(),
                    SessionMedium::Voice,
                    Vec::new(),
                ),
            )
            .await
            .map_err(|_| rvoip_core::RvoipError::InvalidState("session setup timed out"))??;
            created_session = Some(session_id.clone());
            session_id
        };
        tokio::time::timeout(EXTERNAL_OPERATION_TIMEOUT, admission.accept())
            .await
            .map_err(|_| {
                rvoip_core::RvoipError::InvalidState("admission activation timed out")
            })??;
        tokio::time::timeout(
            EXTERNAL_OPERATION_TIMEOUT,
            orchestrator.route_inbound_connection(
                connection_id.clone(),
                InboundAction::Accept {
                    session_id,
                    participant_id: ParticipantId::new(),
                },
            ),
        )
        .await
        .map_err(|_| rvoip_core::RvoipError::InvalidState("inbound routing timed out"))??;
        Ok(())
    });
    let result = match await_while_execution_owned(operation, &mut shutdown).await {
        Ok(result) => result,
        Err(()) => Err(rvoip_core::RvoipError::InvalidState(
            "admission activation lost execution authority",
        )),
    };
    if result.is_err() {
        if let Some(session_id) = created_session.take() {
            let _ = tokio::time::timeout(
                AUTHORITY_TEARDOWN_TIMEOUT,
                orchestrator.end_session(session_id, EndReason::Cancelled),
            )
            .await;
        }
        if let Some(conversation_id) = created_conversation.take() {
            let _ = tokio::time::timeout(
                AUTHORITY_TEARDOWN_TIMEOUT,
                orchestrator.close_conversation(conversation_id, true),
            )
            .await;
        }
    }
    AdmissionOperationResult {
        connection_id,
        conversation_id: created_conversation,
        session_id: created_session,
        result,
    }
}

async fn supervise_rvoip_operation<F, T>(future: F) -> Result<T, rvoip_core::RvoipError>
where
    F: std::future::Future<Output = Result<T, rvoip_core::RvoipError>>,
{
    match AssertUnwindSafe(future).catch_unwind().await {
        Ok(result) => result,
        Err(_) => Err(rvoip_core::RvoipError::InvalidState(
            "owned call operation panicked",
        )),
    }
}

impl CallActor {
    #[allow(clippy::too_many_arguments)]
    fn new(
        stored: StoredServiceCall,
        orchestrator: Arc<Orchestrator>,
        runtime: Arc<CallServiceRuntime>,
        commands: mpsc::Receiver<ActorCommand>,
        operational: mpsc::Receiver<OperationalEvent>,
        work: mpsc::Receiver<ActorWork>,
        drain: watch::Receiver<bool>,
        shutdown: watch::Receiver<ActorShutdown>,
        retiring: Arc<AtomicBool>,
    ) -> Self {
        let bindings = stored
            .call
            .bindings
            .values()
            .filter_map(|binding| {
                stored.call.aggregate.leg(binding.leg_id).map(|leg| {
                    (
                        binding.leg_id,
                        ActorBinding {
                            connection_id: binding.connection_id.clone(),
                            leg_id: binding.leg_id,
                            binding_generation: binding.binding_generation,
                            state: leg.state(),
                        },
                    )
                })
            })
            .collect();
        Self {
            call_id: stored.call.aggregate.id(),
            tenant_id: stored.call.aggregate.tenant_id().clone(),
            plan: stored.plan,
            orchestrator,
            runtime,
            commands,
            operational,
            work,
            drain,
            shutdown,
            bindings,
            pending_admissions: VecDeque::new(),
            admission_operation: JoinSet::new(),
            pending_work: VecDeque::new(),
            work_operation: JoinSet::new(),
            bridge_id: None,
            conversation_id: None,
            session_id: None,
            // A newly spawned actor must receive the work/admission that
            // caused its allocation before it can evaluate retirement. This
            // closes the send-after-spawn race for terminal cleanup effects.
            terminal: false,
            retiring,
        }
    }

    fn set_terminal(&mut self, terminal: bool) {
        self.terminal = terminal;
        self.retiring.store(terminal, Ordering::Release);
    }

    async fn run(mut self) -> ActorExit {
        let mut graceful = false;
        let mut terminal_since = None;
        loop {
            let operation_idle =
                self.admission_operation.is_empty() && self.work_operation.is_empty();
            if operation_idle && !graceful && !self.pending_admissions.is_empty() {
                self.start_next_admission();
            } else if operation_idle && !self.pending_work.is_empty() {
                self.start_next_work();
            }
            let idle = self.admission_operation.is_empty()
                && self.work_operation.is_empty()
                && self.pending_admissions.is_empty()
                && self.pending_work.is_empty()
                && self.commands.is_empty()
                && self.work.is_empty();
            if self.terminal && idle {
                let since = terminal_since.get_or_insert_with(tokio::time::Instant::now);
                if since.elapsed() >= TERMINAL_RETIRE_QUIET {
                    break;
                }
            } else {
                terminal_since = None;
            }
            if graceful && idle {
                break;
            }
            tokio::select! {
                biased;
                changed = self.shutdown.changed() => {
                    let state = if changed.is_err() {
                        ActorShutdown::LeaseLost
                    } else {
                        *self.shutdown.borrow()
                    };
                    if state == ActorShutdown::LeaseLost {
                        break;
                    }
                    if state == ActorShutdown::Graceful {
                        graceful = true;
                        self.commands.close();
                        self.work.close();
                        while let Ok(ActorCommand::Admit(proven)) = self.commands.try_recv() {
                            fail_unowned_proven_admission(
                                proven,
                                &self.orchestrator,
                                &self.runtime,
                                true,
                            ).await;
                        }
                    }
                }
                changed = self.drain.changed() => {
                    if changed.is_err() || *self.drain.borrow() {
                        while let Some(proven) = self.pending_admissions.pop_front() {
                            fail_unowned_proven_admission(
                                proven,
                                &self.orchestrator,
                                &self.runtime,
                                true,
                            ).await;
                        }
                    }
                }
                event = self.operational.recv() => {
                    let Some(event) = event else { break; };
                    self.handle_operational(event).await;
                }
                result = self.admission_operation.join_next(), if !self.admission_operation.is_empty() => {
                    match result {
                        Some(Ok(result)) => self.finish_admission_operation(result).await,
                        Some(Err(error)) => tracing::error!(call_id = %self.call_id, %error, "admission operation panicked"),
                        None => {}
                    }
                }
                result = self.work_operation.join_next(), if !self.work_operation.is_empty() => {
                    match result {
                        Some(Ok(result)) => self.finish_work_operation(result).await,
                        Some(Err(error)) => tracing::error!(call_id = %self.call_id, %error, "durable work operation panicked"),
                        None => {}
                    }
                }
                command = self.commands.recv() => {
                    if let Some(command) = command {
                        match command {
                            ActorCommand::Admit(proven) if !graceful => self.queue_admission(proven).await,
                            ActorCommand::Admit(proven) => {
                                fail_unowned_proven_admission(
                                    proven,
                                    &self.orchestrator,
                                    &self.runtime,
                                    true,
                                ).await;
                            }
                        }
                    }
                }
                work = self.work.recv(), if can_buffer_actor_work(self.pending_work.len()) => {
                    if let Some(work) = work {
                        self.pending_work.push_back(work);
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(25)), if terminal_since.is_some() => {}
            }
        }
        let allow_durable_cleanup = *self.shutdown.borrow() != ActorShutdown::LeaseLost;
        self.cleanup(allow_durable_cleanup).await;
        ActorExit {
            call_id: self.call_id,
            tenant_id: self.tenant_id.clone(),
            panicked: false,
        }
    }

    async fn queue_admission(&mut self, proven: ProvenAdmission) {
        let binding = &proven.consumed.binding;
        let existing_binding_matches = self.bindings.get(&binding.leg_id).is_some_and(|existing| {
            existing.connection_id == binding.connection_id
                && existing.binding_generation == binding.binding_generation
        });
        if proven.consumed.commit.call.aggregate.id() != self.call_id
            || proven.consumed.commit.call.aggregate.tenant_id() != &self.tenant_id
            || self
                .plan
                .legs
                .iter()
                .all(|leg| leg.leg_id != binding.leg_id)
            || (self.bindings.contains_key(&binding.leg_id) && !existing_binding_matches)
        {
            fail_unowned_proven_admission(proven, &self.orchestrator, &self.runtime, true).await;
            return;
        }
        if !existing_binding_matches {
            self.bindings.insert(
                binding.leg_id,
                ActorBinding {
                    connection_id: binding.connection_id.clone(),
                    leg_id: binding.leg_id,
                    binding_generation: binding.binding_generation,
                    state: LegState::Signaling,
                },
            );
        }
        self.pending_admissions.push_back(proven);
    }

    fn start_next_admission(&mut self) {
        let Some(proven) = self.pending_admissions.pop_front() else {
            return;
        };
        let orchestrator = Arc::clone(&self.orchestrator);
        let tenant_id = self.tenant_id.clone();
        let session_id = self.session_id.clone();
        let shutdown = self.shutdown.clone();
        self.admission_operation.spawn(async move {
            activate_admission(proven, orchestrator, tenant_id, session_id, shutdown).await
        });
    }

    async fn finish_admission_operation(&mut self, result: AdmissionOperationResult) {
        if result.result.is_ok() {
            if let Some(conversation_id) = result.conversation_id {
                self.conversation_id = Some(conversation_id);
            }
            if let Some(session_id) = result.session_id {
                self.session_id = Some(session_id);
            }
            metrics::counter!("bridgefu_attachment_admission_total", "result" => "accepted")
                .increment(1);
            return;
        }
        metrics::counter!("bridgefu_attachment_admission_total", "result" => "ended").increment(1);
        let Some(binding) = self
            .bindings
            .values()
            .find(|binding| binding.connection_id == result.connection_id)
        else {
            return;
        };
        let failure = FailureDetails::sanitized(
            "signaling_accept_failed",
            "rvoip could not attach the durably bound connection",
            true,
        );
        let _ = self
            .commit_current_binding(
                binding.leg_id,
                LegState::Failed,
                Some(failure),
                self.runtime.observation_time(),
            )
            .await
            .map(|stored| self.set_terminal(stored.call.aggregate.state().is_terminal()));
        let _ = self
            .orchestrator
            .end_connection(
                result.connection_id,
                EndReason::Failed {
                    detail: "durable admission activation failed".into(),
                },
            )
            .await;
    }

    fn start_next_work(&mut self) {
        let Some(work) = self.pending_work.pop_front() else {
            return;
        };
        let orchestrator = Arc::clone(&self.orchestrator);
        let runtime = Arc::clone(&self.runtime);
        let bindings = self.bindings.clone();
        let bridge_id = self.bridge_id.clone();
        let shutdown = self.shutdown.clone();
        let panic_work = work.clone();
        let panic_orchestrator = Arc::clone(&orchestrator);
        let panic_runtime = Arc::clone(&runtime);
        let panic_bindings = bindings.clone();
        let panic_shutdown = shutdown.clone();
        self.work_operation.spawn(async move {
            let mut authority = shutdown.clone();
            let operation = supervise_work_operation(
                execute_actor_work(work, orchestrator, runtime, bindings, bridge_id, shutdown),
                recover_panicked_actor_work(
                    panic_work,
                    panic_orchestrator,
                    panic_runtime,
                    panic_bindings,
                    panic_shutdown,
                ),
            );
            match await_while_execution_owned(operation, &mut authority).await {
                Ok(result) => result,
                Err(()) => WorkOperationResult {
                    effect_id: None,
                    bridge_update: None,
                    result: Err(RepositoryError::Unavailable),
                },
            }
        });
    }

    async fn finish_work_operation(&mut self, result: WorkOperationResult) {
        if let Some(bridge_update) = result.bridge_update {
            self.bridge_id = bridge_update;
        }
        if let Err(error) = result.result {
            if let Some(effect_id) = result.effect_id {
                tracing::warn!(call_id = %self.call_id, %effect_id, %error, "durable work did not reconcile");
            } else {
                tracing::warn!(call_id = %self.call_id, %error, "durable internal work failed");
            }
        }
        if let Ok(stored) = self
            .runtime
            .service_repository()
            .load_service_call(&self.tenant_id, self.call_id)
            .await
        {
            self.set_terminal(stored.call.aggregate.state().is_terminal());
            if !self.terminal {
                let _ = ensure_ending_deadline(&self.runtime, stored, self.shutdown.clone()).await;
            }
        }
    }

    async fn handle_operational(&mut self, event: OperationalEvent) {
        if *self.shutdown.borrow() == ActorShutdown::LeaseLost {
            return;
        }
        let Some(binding) = self
            .bindings
            .values()
            .find(|binding| binding.connection_id == event.connection_id)
            .cloned()
        else {
            tracing::error!(call_id = %self.call_id, connection_id = %event.connection_id, sequence = event.sequence, "actor received a foreign operational event");
            return;
        };
        let leg_id = binding.leg_id;
        let stored = match self
            .runtime
            .service_repository()
            .load_service_call(&self.tenant_id, self.call_id)
            .await
        {
            Ok(stored) => stored,
            Err(error) => {
                tracing::error!(call_id = %self.call_id, %error, "loading call for operational event failed");
                return;
            }
        };
        let Some(leg) = stored.call.aggregate.leg(leg_id) else {
            tracing::error!(call_id = %self.call_id, %leg_id, "bound operational leg disappeared");
            return;
        };
        if let OperationalEventKind::MediaActivity { generation } = &event.kind {
            if let Err(error) = self
                .record_media_activity(&binding, *generation, event.at, stored)
                .await
            {
                tracing::warn!(call_id = %self.call_id, %leg_id, %error, "authoritative media activity did not reconcile");
            }
            return;
        }
        let transition = classify_operational_event(leg.state(), &event.kind);
        match transition {
            OperationalTransition::Ignore => {
                self.set_terminal(stored.call.aggregate.state().is_terminal());
            }
            OperationalTransition::EndUnexpectedConnected => {
                let _ = self
                    .orchestrator
                    .end_connection(
                        event.connection_id,
                        EndReason::Failed {
                            detail: "connected event raced terminal call state".into(),
                        },
                    )
                    .await;
            }
            OperationalTransition::Commit { state, failure } => {
                let at = std::cmp::max(event.at, stored.call.aggregate.updated_at());
                if let Ok(committed) = self
                    .commit_current_binding(leg_id, state, failure, at)
                    .await
                {
                    let should_stop_peers = matches!(
                        event.kind,
                        OperationalEventKind::Ended { .. } | OperationalEventKind::Failed { .. }
                    ) && committed.call.aggregate.state()
                        == CallState::Ending;
                    self.set_terminal(committed.call.aggregate.state().is_terminal());
                    if !self.terminal {
                        let _ = ensure_ending_deadline(
                            &self.runtime,
                            committed.clone(),
                            self.shutdown.clone(),
                        )
                        .await;
                    }
                    if let Some(binding) = self.bindings.get_mut(&leg_id) {
                        binding.state = state;
                    }
                    if should_stop_peers {
                        self.stop_ending_peers(leg_id, &committed).await;
                    }
                }
            }
            OperationalTransition::Ephemeral => {
                metrics::counter!(
                    "bridgefu_operational_ephemeral_total",
                    "kind" => operational_kind_label(&event.kind)
                )
                .increment(1);
            }
        }
    }

    async fn stop_ending_peers(&self, source_leg_id: LegId, stored: &StoredServiceCall) {
        if *self.shutdown.borrow() == ActorShutdown::LeaseLost {
            return;
        }
        for binding in self.bindings.values() {
            if binding.leg_id == source_leg_id
                || stored
                    .call
                    .aggregate
                    .leg(binding.leg_id)
                    .is_none_or(|leg| leg.state() != LegState::Ending)
            {
                continue;
            }
            let _ = tokio::time::timeout(
                EXTERNAL_OPERATION_TIMEOUT,
                self.orchestrator
                    .end_connection(binding.connection_id.clone(), EndReason::BridgeTorn),
            )
            .await;
        }
    }

    async fn record_media_activity(
        &mut self,
        binding: &ActorBinding,
        generation: u64,
        observed_at: DateTime<Utc>,
        mut stored: StoredServiceCall,
    ) -> Result<(), RepositoryError> {
        let generation = i64::try_from(generation)
            .ok()
            .and_then(|generation| MediaActivityGeneration::from_i64(generation).ok())
            .ok_or(RepositoryError::InvalidInput(
                "media activity generation is outside the durable range",
            ))?;
        let command_id = CommandId::new();
        loop {
            if *self.shutdown.borrow() == ActorShutdown::LeaseLost {
                return Err(RepositoryError::Unavailable);
            }
            let Some(leg) = stored.call.aggregate.leg(binding.leg_id) else {
                return Ok(());
            };
            let Some(durable_binding) = stored.call.bindings.get(&binding.leg_id) else {
                return Ok(());
            };
            if !matches!(
                stored.call.aggregate.state(),
                CallState::Active | CallState::Transferring
            ) || !matches!(leg.state(), LegState::Connected | LegState::Held)
                || durable_binding.connection_id != binding.connection_id
                || durable_binding.binding_generation != binding.binding_generation
            {
                return Ok(());
            }
            let at = std::cmp::max(observed_at, stored.call.aggregate.updated_at());
            let observation = MediaActivityObservation {
                tenant_id: self.tenant_id.clone(),
                call_id: self.call_id,
                expected_version: stored.call.aggregate.version(),
                command_id,
                leg_id: binding.leg_id,
                binding_generation: binding.binding_generation,
                connection_id: binding.connection_id.clone(),
                activity_generation: generation,
                worker: self.runtime.worker().lease,
                at,
            };
            let mut delay = REPOSITORY_RETRY_MIN;
            loop {
                let service = self.runtime.service();
                let result = await_while_execution_owned(
                    service.record_media_activity(observation.clone()),
                    &mut self.shutdown,
                )
                .await
                .map_err(|()| RepositoryError::Unavailable)?;
                match result {
                    Ok(ServiceCommandOutcome::Committed(view))
                    | Ok(ServiceCommandOutcome::Replayed(view)) => {
                        self.set_terminal(view.command.call.aggregate.state().is_terminal());
                        return Ok(());
                    }
                    Err(CallServiceError::Repository(RepositoryError::Unavailable)) => {
                        tokio::select! {
                            changed = self.shutdown.changed() => {
                                if changed.is_err() || *self.shutdown.borrow() == ActorShutdown::LeaseLost {
                                    return Err(RepositoryError::Unavailable);
                                }
                            }
                            _ = tokio::time::sleep(delay) => {}
                        }
                        delay = (delay * 2).min(REPOSITORY_RETRY_MAX);
                    }
                    Err(CallServiceError::Repository(RepositoryError::VersionConflict)) => {
                        stored = self
                            .runtime
                            .service_repository()
                            .load_service_call(&self.tenant_id, self.call_id)
                            .await?;
                        break;
                    }
                    Err(CallServiceError::Repository(
                        RepositoryError::StaleClaim
                        | RepositoryError::StaleWorkerFence
                        | RepositoryError::InvalidInput(_),
                    )) => return Ok(()),
                    Err(CallServiceError::Repository(error)) => return Err(error),
                    Err(_) => return Err(RepositoryError::Unavailable),
                }
            }
        }
    }

    async fn commit_current_binding(
        &self,
        leg_id: LegId,
        state: LegState,
        failure: Option<FailureDetails>,
        at: DateTime<Utc>,
    ) -> Result<StoredServiceCall, RepositoryError> {
        let actor_binding = self
            .bindings
            .get(&leg_id)
            .ok_or(RepositoryError::StaleClaim)?;
        let seed = self
            .runtime
            .service_repository()
            .load_service_call(&self.tenant_id, self.call_id)
            .await?;
        let durable_binding = seed
            .call
            .bindings
            .get(&leg_id)
            .cloned()
            .ok_or(RepositoryError::StaleClaim)?;
        if durable_binding.connection_id != actor_binding.connection_id
            || durable_binding.binding_generation != actor_binding.binding_generation
        {
            return Err(RepositoryError::StaleClaim);
        }
        commit_binding_state(
            &self.runtime,
            &self.tenant_id,
            self.call_id,
            &durable_binding,
            state,
            failure,
            at,
            Some(self.shutdown.clone()),
        )
        .await
    }

    async fn cleanup(&mut self, allow_durable_write: bool) {
        while let Some(proven) = self.pending_admissions.pop_front() {
            fail_unowned_proven_admission(
                proven,
                &self.orchestrator,
                &self.runtime,
                allow_durable_write,
            )
            .await;
        }
        self.admission_operation.abort_all();
        while self.admission_operation.join_next().await.is_some() {}
        self.work_operation.abort_all();
        while self.work_operation.join_next().await.is_some() {}
        let leg_ids = self.bindings.keys().copied().collect::<Vec<_>>();
        for leg_id in leg_ids {
            if !allow_durable_write {
                continue;
            }
            let current = self
                .runtime
                .service_repository()
                .load_service_call(&self.tenant_id, self.call_id)
                .await
                .ok()
                .and_then(|stored| stored.call.aggregate.leg(leg_id).map(|leg| leg.state()));
            if current.is_some_and(|state| !state.is_terminal()) {
                let failure = FailureDetails::sanitized(
                    "execution_stopped",
                    "the process-owned call actor stopped before terminal convergence",
                    true,
                );
                let _ = tokio::time::timeout(
                    Duration::from_secs(2),
                    self.commit_current_binding(
                        leg_id,
                        LegState::Failed,
                        Some(failure),
                        self.runtime.observation_time(),
                    ),
                )
                .await;
            }
        }
        for binding in self.bindings.values() {
            let _ = tokio::time::timeout(
                EXTERNAL_OPERATION_TIMEOUT,
                self.orchestrator
                    .end_connection(binding.connection_id.clone(), EndReason::Cancelled),
            )
            .await;
        }
        if let Some(session_id) = self.session_id.take() {
            let _ = tokio::time::timeout(
                EXTERNAL_OPERATION_TIMEOUT,
                self.orchestrator
                    .end_session(session_id, EndReason::Cancelled),
            )
            .await;
        }
        if let Some(conversation_id) = self.conversation_id.take() {
            let _ = tokio::time::timeout(
                EXTERNAL_OPERATION_TIMEOUT,
                self.orchestrator.close_conversation(conversation_id, true),
            )
            .await;
        }
    }
}

#[derive(Clone)]
struct ClaimedEffectMeta {
    tenant_id: crate::call_engine::TenantId,
    call_id: CallId,
    effect_id: crate::call_engine::EffectId,
    claim_generation: crate::call_engine::ClaimGeneration,
}

#[derive(Clone)]
enum FollowUpPlan {
    None,
    FailLeg {
        leg_id: LegId,
        binding_generation: crate::call_engine::BindingGeneration,
        failure: FailureDetails,
    },
    FinishTransfer {
        deadline_generation: crate::call_engine::DeadlineGeneration,
        result: TransferResult,
    },
}

async fn supervise_work_operation<F, R>(operation: F, recovery: R) -> WorkOperationResult
where
    F: std::future::Future<Output = WorkOperationResult>,
    R: std::future::Future<Output = WorkOperationResult>,
{
    match AssertUnwindSafe(operation).catch_unwind().await {
        Ok(result) => result,
        Err(_) => recovery.await,
    }
}

async fn recover_panicked_actor_work(
    work: ActorWork,
    orchestrator: Arc<Orchestrator>,
    runtime: Arc<CallServiceRuntime>,
    bindings: HashMap<LegId, ActorBinding>,
    shutdown: watch::Receiver<ActorShutdown>,
) -> WorkOperationResult {
    let failure = FailureDetails::sanitized(
        "execution_panicked",
        "the owned external operation stopped unexpectedly",
        true,
    );
    for binding in bindings.values() {
        let _ = tokio::time::timeout(
            EXTERNAL_OPERATION_TIMEOUT,
            orchestrator.end_connection(
                binding.connection_id.clone(),
                EndReason::Failed {
                    detail: "owned call operation panicked".into(),
                },
            ),
        )
        .await;
    }
    match work {
        ActorWork::Call(claim) => {
            let effect_id = claim.record.effect_id;
            let meta = ClaimedEffectMeta {
                tenant_id: claim.record.tenant_id.clone(),
                call_id: claim.record.call_id,
                effect_id,
                claim_generation: claim.claim_generation,
            };
            let follow_up = match claim.record.intent {
                EffectIntent::StartLeg {
                    leg_id,
                    binding_generation,
                    ..
                }
                | EffectIntent::StopLeg {
                    leg_id,
                    binding_generation,
                    ..
                } => FollowUpPlan::FailLeg {
                    leg_id,
                    binding_generation,
                    failure: failure.clone(),
                },
                EffectIntent::BridgeMedia {
                    left_leg_id,
                    right_leg_id,
                } => bindings
                    .get(&left_leg_id)
                    .or_else(|| bindings.get(&right_leg_id))
                    .map_or(FollowUpPlan::None, |binding| FollowUpPlan::FailLeg {
                        leg_id: binding.leg_id,
                        binding_generation: binding.binding_generation,
                        failure: failure.clone(),
                    }),
                EffectIntent::ExecuteTransfer {
                    deadline_generation,
                } => FollowUpPlan::FinishTransfer {
                    deadline_generation,
                    result: TransferResult::Rejected(failure.clone()),
                },
                _ => FollowUpPlan::None,
            };
            WorkOperationResult {
                effect_id: Some(effect_id),
                bridge_update: None,
                result: reconcile_effect(
                    meta,
                    ServiceEffectResult::Failed(failure),
                    follow_up,
                    runtime,
                    shutdown,
                )
                .await,
            }
        }
        ActorWork::Control(claim) => {
            let effect_id = claim.record.effect_id;
            let meta = ClaimedEffectMeta {
                tenant_id: claim.record.tenant_id,
                call_id: claim.record.call_id,
                effect_id,
                claim_generation: claim.claim_generation,
            };
            WorkOperationResult {
                effect_id: Some(effect_id),
                bridge_update: None,
                result: reconcile_effect(
                    meta,
                    ServiceEffectResult::Failed(failure),
                    FollowUpPlan::None,
                    runtime,
                    shutdown,
                )
                .await,
            }
        }
        ActorWork::Provider(claim) => execute_provider_event(claim, runtime, shutdown).await,
        ActorWork::Deadline(claim) => WorkOperationResult {
            effect_id: None,
            bridge_update: None,
            result: commit_deadline(claim, runtime, shutdown).await,
        },
        ActorWork::Restart(claim) => WorkOperationResult {
            effect_id: None,
            bridge_update: None,
            result: recover_restarted_call(*claim, runtime, shutdown).await,
        },
    }
}

async fn execute_actor_work(
    work: ActorWork,
    orchestrator: Arc<Orchestrator>,
    runtime: Arc<CallServiceRuntime>,
    bindings: HashMap<LegId, ActorBinding>,
    bridge_id: Option<BridgeId>,
    shutdown: watch::Receiver<ActorShutdown>,
) -> WorkOperationResult {
    match work {
        ActorWork::Call(claim) => {
            execute_call_effect(claim, orchestrator, runtime, bindings, bridge_id, shutdown).await
        }
        ActorWork::Control(claim) => {
            execute_control_effect(claim, orchestrator, runtime, bindings, shutdown).await
        }
        ActorWork::Provider(claim) => execute_provider_event(claim, runtime, shutdown).await,
        ActorWork::Deadline(claim) => WorkOperationResult {
            effect_id: None,
            bridge_update: None,
            result: commit_deadline(claim, runtime, shutdown).await,
        },
        ActorWork::Restart(claim) => WorkOperationResult {
            effect_id: None,
            bridge_update: None,
            result: recover_restarted_call(*claim, runtime, shutdown).await,
        },
    }
}

async fn execute_call_effect(
    claim: ClaimedOutbox,
    orchestrator: Arc<Orchestrator>,
    runtime: Arc<CallServiceRuntime>,
    bindings: HashMap<LegId, ActorBinding>,
    bridge_id: Option<BridgeId>,
    shutdown: watch::Receiver<ActorShutdown>,
) -> WorkOperationResult {
    let effect_id = claim.record.effect_id;
    let meta = ClaimedEffectMeta {
        tenant_id: claim.record.tenant_id.clone(),
        call_id: claim.record.call_id,
        effect_id,
        claim_generation: claim.claim_generation,
    };
    let current = runtime
        .service_repository()
        .load_service_call(&meta.tenant_id, meta.call_id)
        .await;
    if let Ok(stored) = &current {
        if stored.call.aggregate.state().is_terminal() {
            let result = if matches!(
                claim.record.intent,
                EffectIntent::StartLeg { .. }
                    | EffectIntent::BridgeMedia { .. }
                    | EffectIntent::ExecuteTransfer { .. }
            ) {
                ServiceEffectResult::Failed(FailureDetails::sanitized(
                    "call_already_terminal",
                    "external work was retired after terminal call convergence",
                    false,
                ))
            } else {
                ServiceEffectResult::Succeeded
            };
            return WorkOperationResult {
                effect_id: Some(effect_id),
                bridge_update: None,
                result: reconcile_effect(meta, result, FollowUpPlan::None, runtime, shutdown).await,
            };
        }
    } else if let Err(error) = current {
        return WorkOperationResult {
            effect_id: Some(effect_id),
            bridge_update: None,
            result: Err(error),
        };
    }
    let mut bridge_update = None;
    let (result, follow_up) = match claim.record.intent {
        EffectIntent::AwaitLegAttachment { .. }
        | EffectIntent::ScheduleDeadline { .. }
        | EffectIntent::CancelDeadline { .. }
        | EffectIntent::CompensateTransfer { .. } => {
            (ServiceEffectResult::Succeeded, FollowUpPlan::None)
        }
        EffectIntent::BridgeMedia {
            left_leg_id,
            right_leg_id,
        } => {
            let left = bindings.get(&left_leg_id);
            let right = bindings.get(&right_leg_id);
            match (left, right) {
                (Some(left), Some(right)) => match tokio::time::timeout(
                    EXTERNAL_OPERATION_TIMEOUT,
                    orchestrator.bridge_connections(
                        left.connection_id.clone(),
                        right.connection_id.clone(),
                    ),
                )
                .await
                {
                    Ok(Ok(created)) => {
                        bridge_update = Some(Some(created));
                        (ServiceEffectResult::Succeeded, FollowUpPlan::None)
                    }
                    Ok(Err(_)) | Err(_) => {
                        let failure = FailureDetails::sanitized(
                            "media_bridge_failed",
                            "rvoip could not establish the two-leg media graph",
                            true,
                        );
                        (
                            ServiceEffectResult::Failed(failure.clone()),
                            FollowUpPlan::FailLeg {
                                leg_id: left_leg_id,
                                binding_generation: left.binding_generation,
                                failure,
                            },
                        )
                    }
                },
                _ => {
                    let failure = FailureDetails::sanitized(
                        "media_binding_missing",
                        "a connected media leg has no process-owned transport binding",
                        false,
                    );
                    let (leg_id, generation) = left
                        .map(|binding| (left_leg_id, binding.binding_generation))
                        .or_else(|| right.map(|binding| (right_leg_id, binding.binding_generation)))
                        .unwrap_or((left_leg_id, crate::call_engine::BindingGeneration::INITIAL));
                    (
                        ServiceEffectResult::Failed(failure.clone()),
                        FollowUpPlan::FailLeg {
                            leg_id,
                            binding_generation: generation,
                            failure,
                        },
                    )
                }
            }
        }
        EffectIntent::UnbridgeMedia { .. } => match bridge_id {
            Some(bridge_id) => match tokio::time::timeout(
                EXTERNAL_OPERATION_TIMEOUT,
                orchestrator.unbridge_connections(bridge_id),
            )
            .await
            {
                Ok(Ok(())) => {
                    bridge_update = Some(None);
                    (ServiceEffectResult::Succeeded, FollowUpPlan::None)
                }
                Ok(Err(_)) | Err(_) => (
                    ServiceEffectResult::Failed(FailureDetails::sanitized(
                        "media_unbridge_failed",
                        "rvoip could not confirm media graph removal",
                        true,
                    )),
                    FollowUpPlan::None,
                ),
            },
            None => (ServiceEffectResult::Succeeded, FollowUpPlan::None),
        },
        EffectIntent::StopLeg {
            leg_id,
            binding_generation,
            ..
        } => match bindings.get(&leg_id) {
            Some(binding) if binding.binding_generation == binding_generation => {
                match tokio::time::timeout(
                    EXTERNAL_OPERATION_TIMEOUT,
                    orchestrator
                        .end_connection(binding.connection_id.clone(), EndReason::BridgeTorn),
                )
                .await
                {
                    Ok(Ok(())) => (ServiceEffectResult::Succeeded, FollowUpPlan::None),
                    Ok(Err(_)) | Err(_) => (
                        ServiceEffectResult::Failed(FailureDetails::sanitized(
                            "stop_leg_failed",
                            "rvoip could not confirm transport teardown",
                            true,
                        )),
                        FollowUpPlan::None,
                    ),
                }
            }
            _ => (ServiceEffectResult::Succeeded, FollowUpPlan::None),
        },
        EffectIntent::StartLeg {
            leg_id,
            binding_generation,
            ..
        } => {
            // Gate 7 replaces this explicit fail-closed outcome with the
            // prepared outbound adapter path. Claiming and failing now keeps
            // unsupported outbound calls from blocking their entire ordered
            // outbox indefinitely.
            let authority = runtime
                .service_repository()
                .load_service_call(&meta.tenant_id, meta.call_id)
                .await
                .and_then(|stored| stored.plan.authorization_principal_fingerprint());
            let failure = if authority.is_ok() {
                FailureDetails::sanitized(
                    "outbound_not_ready",
                    "outbound signaling is not enabled for this endpoint",
                    false,
                )
            } else {
                FailureDetails::sanitized(
                    "outbound_authorization_missing",
                    "the persisted execution plan cannot authorize outbound signaling",
                    false,
                )
            };
            (
                ServiceEffectResult::Failed(failure.clone()),
                FollowUpPlan::FailLeg {
                    leg_id,
                    binding_generation,
                    failure,
                },
            )
        }
        EffectIntent::ExecuteTransfer {
            deadline_generation,
        } => {
            let payload = runtime
                .service_repository()
                .load_effect_payload(&meta.tenant_id, effect_id)
                .await;
            let valid_payload = matches!(
                payload,
                Ok(Some(ref stored_payload)) if matches!(
                    stored_payload.payload,
                    ServiceEffectPayload::Transfer { target_leg_id, target_binding_generation, .. }
                        if bindings.get(&target_leg_id).is_some_and(|binding|
                            binding.binding_generation == target_binding_generation)
                )
            );
            let failure = if valid_payload {
                FailureDetails::sanitized(
                    "transfer_not_ready",
                    "the selected transfer executor is not enabled",
                    false,
                )
            } else {
                FailureDetails::sanitized(
                    "transfer_target_unavailable",
                    "the persisted transfer target is missing or no longer current",
                    false,
                )
            };
            (
                ServiceEffectResult::Failed(failure.clone()),
                FollowUpPlan::FinishTransfer {
                    deadline_generation,
                    result: TransferResult::Rejected(failure),
                },
            )
        }
    };
    let reconciled = reconcile_effect(meta, result, follow_up, runtime, shutdown).await;
    WorkOperationResult {
        effect_id: Some(effect_id),
        bridge_update,
        result: reconciled,
    }
}

async fn execute_control_effect(
    claim: ClaimedControlEffect,
    orchestrator: Arc<Orchestrator>,
    runtime: Arc<CallServiceRuntime>,
    bindings: HashMap<LegId, ActorBinding>,
    shutdown: watch::Receiver<ActorShutdown>,
) -> WorkOperationResult {
    let effect_id = claim.record.effect_id;
    let meta = ClaimedEffectMeta {
        tenant_id: claim.record.tenant_id.clone(),
        call_id: claim.record.call_id,
        effect_id,
        claim_generation: claim.claim_generation,
    };
    let result = match (&claim.record.intent, bindings.get(&claim.record.leg_id)) {
        (ControlIntent::Dtmf { sequence }, Some(binding))
            if binding.binding_generation == claim.record.binding_generation =>
        {
            match tokio::time::timeout(
                EXTERNAL_OPERATION_TIMEOUT,
                orchestrator.send_dtmf(
                    binding.connection_id.clone(),
                    &sequence.digits,
                    u32::from(sequence.duration_ms),
                ),
            )
            .await
            {
                Ok(Ok(())) => ServiceEffectResult::Succeeded,
                Ok(Err(_)) | Err(_) => ServiceEffectResult::Failed(FailureDetails::sanitized(
                    "dtmf_failed",
                    "rvoip could not deliver the requested DTMF sequence",
                    true,
                )),
            }
        }
        _ => ServiceEffectResult::Failed(FailureDetails::sanitized(
            "dtmf_binding_stale",
            "the DTMF target transport binding is no longer current",
            false,
        )),
    };
    let reconciled = reconcile_effect(meta, result, FollowUpPlan::None, runtime, shutdown).await;
    WorkOperationResult {
        effect_id: Some(effect_id),
        bridge_update: None,
        result: reconciled,
    }
}

async fn execute_provider_event(
    claim: crate::call_engine::ClaimedProviderEvent,
    runtime: Arc<CallServiceRuntime>,
    mut shutdown: watch::Receiver<ActorShutdown>,
) -> WorkOperationResult {
    let result = reconcile_provider_event(claim, &runtime, &mut shutdown).await;
    WorkOperationResult {
        effect_id: None,
        bridge_update: None,
        result,
    }
}

async fn reconcile_provider_event(
    claim: crate::call_engine::ClaimedProviderEvent,
    runtime: &Arc<CallServiceRuntime>,
    shutdown: &mut watch::Receiver<ActorShutdown>,
) -> Result<(), RepositoryError> {
    let target = claim
        .event
        .target
        .clone()
        .ok_or(RepositoryError::ProviderReferenceConflict)?;
    loop {
        if *shutdown.borrow() == ActorShutdown::LeaseLost {
            return Err(RepositoryError::Unavailable);
        }
        let stored = runtime
            .service_repository()
            .load_service_call(&target.tenant_id, target.call_id)
            .await?;
        let observed_at = runtime.observation_time();
        let received_at = bounded_provider_received_at(observed_at, claim.event.received_at);
        let at = [observed_at, stored.call.aggregate.updated_at(), received_at]
            .into_iter()
            .max()
            .ok_or(RepositoryError::Unavailable)?;
        let follow_up = build_provider_follow_up(
            &claim.event.account,
            &claim.event.kind,
            &target,
            &stored,
            at,
        )?;
        let request = ProviderEventReconciliationTransaction {
            account: claim.event.account.clone(),
            event_digest: claim.event.event_digest,
            claim_generation: claim.claim_generation,
            worker: runtime.worker().lease,
            target: target.clone(),
            follow_up,
            at,
        };
        let mut delay = REPOSITORY_RETRY_MIN;
        loop {
            match runtime
                .service_repository()
                .reconcile_provider_event(request.clone())
                .await
            {
                Ok(ProviderEventReconciliationOutcome::Reconciled(_))
                | Ok(ProviderEventReconciliationOutcome::Replayed(_)) => return Ok(()),
                Err(RepositoryError::Unavailable) => {
                    tokio::select! {
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() == ActorShutdown::LeaseLost {
                                return Err(RepositoryError::Unavailable);
                            }
                        }
                        _ = tokio::time::sleep(delay) => {}
                    }
                    delay = (delay * 2).min(REPOSITORY_RETRY_MAX);
                }
                Err(RepositoryError::VersionConflict) => break,
                Err(error) => return Err(error),
            }
        }
    }
}

fn bounded_provider_received_at(
    observed_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
) -> DateTime<Utc> {
    let skew_bound = chrono::Duration::minutes(5);
    let Some(lower) = observed_at.checked_sub_signed(skew_bound) else {
        return observed_at;
    };
    let Some(upper) = observed_at.checked_add_signed(skew_bound) else {
        return observed_at;
    };
    if received_at < lower || received_at > upper {
        observed_at
    } else {
        received_at
    }
}

fn build_provider_follow_up(
    account: &crate::call_engine::ProviderAccountKey,
    kind: &str,
    target: &crate::call_engine::ProviderEventTarget,
    stored: &StoredServiceCall,
    at: DateTime<Utc>,
) -> Result<Option<ServiceCommandTransaction>, RepositoryError> {
    if stored.call.aggregate.state().is_terminal() {
        return Ok(None);
    }
    let leg = stored
        .call
        .aggregate
        .leg(target.leg_id)
        .ok_or(RepositoryError::ProviderReferenceConflict)?;
    let provider = stored
        .plan
        .legs
        .iter()
        .find(|spec| spec.leg_id == target.leg_id)
        .and_then(|spec| match &spec.endpoint {
            super::LegEndpointConfig::Provider(config)
                if config.account_profile == account.as_str() =>
            {
                Some(config.provider)
            }
            _ => None,
        })
        .ok_or(RepositoryError::ProviderReferenceConflict)?;
    let lifecycle = classify_provider_lifecycle(provider, kind);
    let (state, failure) = if matches!(lifecycle, ProviderLifecycle::Failed) {
        (
            LegState::Failed,
            Some(FailureDetails::sanitized(
                "provider_call_failed",
                "provider signaling did not complete successfully",
                false,
            )),
        )
    } else if lifecycle == ProviderLifecycle::Ended {
        if matches!(
            leg.state(),
            LegState::Connected | LegState::Held | LegState::Ending
        ) {
            (LegState::Ended, None)
        } else {
            (
                LegState::Failed,
                Some(FailureDetails::sanitized(
                    "provider_ended_during_setup",
                    "provider signaling ended before the leg connected",
                    false,
                )),
            )
        }
    } else if lifecycle == ProviderLifecycle::Connected {
        match leg.state() {
            LegState::Connected | LegState::Held | LegState::Ending => (leg.state(), None),
            _ => (LegState::Connected, None),
        }
    } else if lifecycle == ProviderLifecycle::Progress {
        match leg.state() {
            LegState::Pending | LegState::AwaitingAttach => (LegState::Signaling, None),
            _ => (leg.state(), None),
        }
    } else {
        // Verified but non-lifecycle callbacks (recording, machine detection,
        // DTMF acknowledgements, and future provider extensions) are durably
        // acknowledged through an explicit no-op command. They never infer a
        // call failure or connection from an unknown string.
        (leg.state(), leg.failure().cloned())
    };
    Ok(Some(ServiceCommandTransaction {
        command: CommandCommit {
            tenant_id: target.tenant_id.clone(),
            call_id: target.call_id,
            expected_version: stored.call.aggregate.version(),
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at,
                leg_id: target.leg_id,
                binding_generation: leg.binding_generation(),
                state,
                failure,
            },
            worker: stored.call.assignment.lease,
            attachments: Vec::new(),
            deadline_claim: None,
            at,
        },
        effect_payloads: Vec::new(),
        operation_idempotency: None,
        bound_connection: None,
        media_activity: None,
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderLifecycle {
    Progress,
    Connected,
    Ended,
    Failed,
    Ignore,
}

fn classify_provider_lifecycle(provider: ProviderKind, kind: &str) -> ProviderLifecycle {
    let kind = kind.trim().to_ascii_lowercase();
    match provider {
        ProviderKind::Twilio => match kind.as_str() {
            "queued" | "ringing" => ProviderLifecycle::Progress,
            "in-progress" => ProviderLifecycle::Connected,
            "completed" => ProviderLifecycle::Ended,
            "busy" | "failed" | "no-answer" | "canceled" => ProviderLifecycle::Failed,
            _ => ProviderLifecycle::Ignore,
        },
        ProviderKind::Telnyx => match kind.as_str() {
            "call.initiated" | "call.ringing" => ProviderLifecycle::Progress,
            "call.answered" | "call.bridged" => ProviderLifecycle::Connected,
            "call.hangup" => ProviderLifecycle::Ended,
            "call.failed" => ProviderLifecycle::Failed,
            _ => ProviderLifecycle::Ignore,
        },
        ProviderKind::Vonage => match kind.as_str() {
            "started" | "ringing" => ProviderLifecycle::Progress,
            "answered" => ProviderLifecycle::Connected,
            "completed" => ProviderLifecycle::Ended,
            "busy" | "unanswered" | "rejected" | "timeout" | "failed" | "cancelled"
            | "canceled" => ProviderLifecycle::Failed,
            _ => ProviderLifecycle::Ignore,
        },
    }
}

async fn reconcile_effect(
    meta: ClaimedEffectMeta,
    result: ServiceEffectResult,
    follow_up: FollowUpPlan,
    runtime: Arc<CallServiceRuntime>,
    mut shutdown: watch::Receiver<ActorShutdown>,
) -> Result<(), RepositoryError> {
    loop {
        if *shutdown.borrow() == ActorShutdown::LeaseLost {
            return Err(RepositoryError::Unavailable);
        }
        let at = runtime.observation_time();
        let built_follow_up = build_effect_follow_up(&meta, &follow_up, &runtime, at).await?;
        let at = built_follow_up
            .as_ref()
            .map_or(at, |follow_up| follow_up.command.at);
        let request = EffectResultReconciliation {
            tenant_id: meta.tenant_id.clone(),
            call_id: meta.call_id,
            effect_id: meta.effect_id,
            worker: runtime.worker().lease,
            claim_generation: meta.claim_generation,
            result: result.clone(),
            external_reference: None,
            follow_up: built_follow_up,
            at,
        };
        let mut delay = REPOSITORY_RETRY_MIN;
        loop {
            match runtime
                .service_repository()
                .reconcile_effect_result(request.clone())
                .await
            {
                Ok(EffectResultOutcome::Reconciled(_)) | Ok(EffectResultOutcome::Replayed(_)) => {
                    return Ok(())
                }
                Err(RepositoryError::Unavailable) => {
                    if *shutdown.borrow() == ActorShutdown::LeaseLost {
                        return Err(RepositoryError::Unavailable);
                    }
                    tokio::select! {
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() == ActorShutdown::LeaseLost {
                                return Err(RepositoryError::Unavailable);
                            }
                        }
                        _ = tokio::time::sleep(delay) => {}
                    }
                    delay = (delay * 2).min(REPOSITORY_RETRY_MAX);
                }
                Err(RepositoryError::VersionConflict)
                    if !matches!(follow_up, FollowUpPlan::None) =>
                {
                    break;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

async fn build_effect_follow_up(
    meta: &ClaimedEffectMeta,
    plan: &FollowUpPlan,
    runtime: &Arc<CallServiceRuntime>,
    requested_at: DateTime<Utc>,
) -> Result<Option<ServiceCommandTransaction>, RepositoryError> {
    let command = match plan {
        FollowUpPlan::None => return Ok(None),
        FollowUpPlan::FailLeg {
            leg_id,
            binding_generation,
            failure,
        } => CallCommand::SetLegState {
            at: requested_at,
            leg_id: *leg_id,
            binding_generation: *binding_generation,
            state: LegState::Failed,
            failure: Some(failure.clone()),
        },
        FollowUpPlan::FinishTransfer {
            deadline_generation,
            result,
        } => CallCommand::FinishTransfer {
            at: requested_at,
            deadline_generation: *deadline_generation,
            result: result.clone(),
        },
    };
    let stored = runtime
        .service_repository()
        .load_service_call(&meta.tenant_id, meta.call_id)
        .await?;
    let at = std::cmp::max(requested_at, stored.call.aggregate.updated_at());
    let command = match command {
        CallCommand::SetLegState {
            leg_id,
            binding_generation,
            state,
            failure,
            ..
        } => CallCommand::SetLegState {
            at,
            leg_id,
            binding_generation,
            state,
            failure,
        },
        CallCommand::FinishTransfer {
            deadline_generation,
            result,
            ..
        } => CallCommand::FinishTransfer {
            at,
            deadline_generation,
            result,
        },
        _ => unreachable!("follow-up plan only builds supported commands"),
    };
    Ok(Some(ServiceCommandTransaction {
        command: CommandCommit {
            tenant_id: meta.tenant_id.clone(),
            call_id: meta.call_id,
            expected_version: stored.call.aggregate.version(),
            command_id: CommandId::new(),
            command,
            worker: runtime.worker().lease,
            attachments: Vec::new(),
            deadline_claim: None,
            at,
        },
        effect_payloads: Vec::new(),
        operation_idempotency: None,
        bound_connection: None,
        media_activity: None,
    }))
}

async fn ensure_ending_deadline(
    runtime: &Arc<CallServiceRuntime>,
    mut stored: StoredServiceCall,
    mut shutdown: watch::Receiver<ActorShutdown>,
) -> Result<(), RepositoryError> {
    let tenant_id = stored.call.aggregate.tenant_id().clone();
    let call_id = stored.call.aggregate.id();
    let command_id = CommandId::new();
    let mut delay = REPOSITORY_RETRY_MIN;
    loop {
        if stored.call.aggregate.state() != crate::call_engine::CallState::Ending
            || stored
                .call
                .aggregate
                .deadlines()
                .get(DeadlineKind::Ending)
                .due_at()
                .is_some()
        {
            return Ok(());
        }
        if *shutdown.borrow() == ActorShutdown::LeaseLost {
            return Err(RepositoryError::Unavailable);
        }
        let at = std::cmp::max(
            runtime.observation_time(),
            stored.call.aggregate.updated_at(),
        );
        let due_at = at
            .checked_add_signed(
                chrono::Duration::from_std(runtime.timeouts().ending)
                    .map_err(|_| RepositoryError::InvalidInput("ending timeout is too large"))?,
            )
            .ok_or(RepositoryError::InvalidInput(
                "ending deadline is outside UTC range",
            ))?;
        let request = ServiceCommandTransaction {
            command: CommandCommit {
                tenant_id: tenant_id.clone(),
                call_id,
                expected_version: stored.call.aggregate.version(),
                command_id,
                command: CallCommand::ArmDeadline {
                    at,
                    kind: DeadlineKind::Ending,
                    due_at,
                },
                worker: runtime.worker().lease,
                attachments: Vec::new(),
                deadline_claim: None,
                at,
            },
            effect_payloads: Vec::new(),
            operation_idempotency: None,
            bound_connection: None,
            media_activity: None,
        };
        let repository = runtime.service_repository();
        let result = await_while_execution_owned(
            repository.commit_with_effect_payloads(request),
            &mut shutdown,
        )
        .await
        .map_err(|()| RepositoryError::Unavailable)?;
        match result {
            Ok(_) => return Ok(()),
            Err(RepositoryError::VersionConflict) => {
                stored = runtime
                    .service_repository()
                    .load_service_call(&tenant_id, call_id)
                    .await?;
                delay = REPOSITORY_RETRY_MIN;
            }
            Err(RepositoryError::Unavailable) => {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() == ActorShutdown::LeaseLost {
                            return Err(RepositoryError::Unavailable);
                        }
                    }
                    _ = tokio::time::sleep(delay) => {}
                }
                delay = (delay * 2).min(REPOSITORY_RETRY_MAX);
            }
            Err(error) => return Err(error),
        }
    }
}

async fn commit_deadline(
    claim: ClaimedDeadline,
    runtime: Arc<CallServiceRuntime>,
    mut shutdown: watch::Receiver<ActorShutdown>,
) -> Result<(), RepositoryError> {
    let tenant_id = claim.record.tenant_id.clone();
    let call_id = claim.record.call_id;
    loop {
        let stored = runtime
            .service_repository()
            .load_service_call(&tenant_id, call_id)
            .await?;
        let at = std::cmp::max(
            runtime.observation_time(),
            stored.call.aggregate.updated_at(),
        );
        let ending_deadline = at
            .checked_add_signed(
                chrono::Duration::from_std(runtime.timeouts().ending)
                    .map_err(|_| RepositoryError::InvalidInput("ending timeout is too large"))?,
            )
            .ok_or(RepositoryError::InvalidInput(
                "ending deadline is outside UTC range",
            ))?;
        let request = ServiceCommandTransaction {
            command: CommandCommit {
                tenant_id: tenant_id.clone(),
                call_id,
                expected_version: stored.call.aggregate.version(),
                command_id: CommandId::new(),
                command: CallCommand::DeadlineElapsed {
                    at,
                    kind: claim.record.kind,
                    generation: claim.record.generation,
                    ending_deadline: Some(ending_deadline),
                },
                worker: runtime.worker().lease,
                attachments: Vec::new(),
                deadline_claim: Some(claim.guard(runtime.worker().lease)),
                at,
            },
            effect_payloads: Vec::new(),
            operation_idempotency: None,
            bound_connection: None,
            media_activity: None,
        };
        let mut delay = REPOSITORY_RETRY_MIN;
        loop {
            match runtime
                .service_repository()
                .commit_with_effect_payloads(request.clone())
                .await
            {
                Ok(_) => return Ok(()),
                Err(RepositoryError::Unavailable) => {
                    if *shutdown.borrow() == ActorShutdown::LeaseLost {
                        return Err(RepositoryError::Unavailable);
                    }
                    tokio::select! {
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() == ActorShutdown::LeaseLost {
                                return Err(RepositoryError::Unavailable);
                            }
                        }
                        _ = tokio::time::sleep(delay) => {}
                    }
                    delay = (delay * 2).min(REPOSITORY_RETRY_MAX);
                }
                Err(RepositoryError::VersionConflict) => break,
                Err(error) => return Err(error),
            }
        }
    }
}

async fn recover_restarted_call(
    claim: RestartClaim,
    runtime: Arc<CallServiceRuntime>,
    shutdown: watch::Receiver<ActorShutdown>,
) -> Result<(), RepositoryError> {
    let tenant_id = claim.call.aggregate.tenant_id().clone();
    let call_id = claim.call.aggregate.id();
    let leg_ids = claim
        .call
        .aggregate
        .legs()
        .iter()
        .filter(|leg| !leg.state().is_terminal())
        .map(|leg| leg.id())
        .collect::<Vec<_>>();
    for leg_id in leg_ids {
        let stored = runtime
            .service_repository()
            .load_service_call(&tenant_id, call_id)
            .await?;
        let Some(leg) = stored.call.aggregate.leg(leg_id) else {
            return Err(RepositoryError::NotFound);
        };
        if leg.state().is_terminal() {
            continue;
        }
        let failure = FailureDetails::sanitized(
            "worker_restarted",
            "the previous process lost ownership of this active transport",
            true,
        );
        if let Some(binding) = stored.call.bindings.get(&leg_id) {
            commit_binding_state(
                &runtime,
                &tenant_id,
                call_id,
                binding,
                LegState::Failed,
                Some(failure),
                runtime.observation_time(),
                Some(shutdown.clone()),
            )
            .await?;
        } else {
            commit_unbound_restart_failure(
                &runtime,
                &stored,
                leg_id,
                leg.binding_generation(),
                failure,
                shutdown.clone(),
            )
            .await?;
        }
    }
    Ok(())
}

async fn commit_unbound_restart_failure(
    runtime: &Arc<CallServiceRuntime>,
    initial: &StoredServiceCall,
    leg_id: LegId,
    binding_generation: crate::call_engine::BindingGeneration,
    failure: FailureDetails,
    mut shutdown: watch::Receiver<ActorShutdown>,
) -> Result<(), RepositoryError> {
    let tenant_id = initial.call.aggregate.tenant_id().clone();
    let call_id = initial.call.aggregate.id();
    loop {
        let stored = runtime
            .service_repository()
            .load_service_call(&tenant_id, call_id)
            .await?;
        if stored
            .call
            .aggregate
            .leg(leg_id)
            .is_none_or(|leg| leg.state().is_terminal())
        {
            return Ok(());
        }
        let at = std::cmp::max(
            runtime.observation_time(),
            stored.call.aggregate.updated_at(),
        );
        let request = ServiceCommandTransaction {
            command: CommandCommit {
                tenant_id: tenant_id.clone(),
                call_id,
                expected_version: stored.call.aggregate.version(),
                command_id: CommandId::new(),
                command: CallCommand::SetLegState {
                    at,
                    leg_id,
                    binding_generation,
                    state: LegState::Failed,
                    failure: Some(failure.clone()),
                },
                worker: runtime.worker().lease,
                attachments: Vec::new(),
                deadline_claim: None,
                at,
            },
            effect_payloads: Vec::new(),
            operation_idempotency: None,
            bound_connection: None,
            media_activity: None,
        };
        let mut delay = REPOSITORY_RETRY_MIN;
        loop {
            match runtime
                .service_repository()
                .commit_with_effect_payloads(request.clone())
                .await
            {
                Ok(_) => return Ok(()),
                Err(RepositoryError::Unavailable) => {
                    if *shutdown.borrow() == ActorShutdown::LeaseLost {
                        return Err(RepositoryError::Unavailable);
                    }
                    tokio::select! {
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() == ActorShutdown::LeaseLost {
                                return Err(RepositoryError::Unavailable);
                            }
                        }
                        _ = tokio::time::sleep(delay) => {}
                    }
                    delay = (delay * 2).min(REPOSITORY_RETRY_MAX);
                }
                Err(RepositoryError::VersionConflict) => break,
                Err(error) => return Err(error),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn commit_binding_state(
    runtime: &Arc<CallServiceRuntime>,
    tenant_id: &crate::call_engine::TenantId,
    call_id: CallId,
    binding: &crate::call_engine::ConnectionBinding,
    state: LegState,
    failure: Option<FailureDetails>,
    at: DateTime<Utc>,
    mut cancel: Option<watch::Receiver<ActorShutdown>>,
) -> Result<StoredServiceCall, RepositoryError> {
    let tenant_id = tenant_id.clone();
    let mut stored = runtime
        .service_repository()
        .load_service_call(&tenant_id, call_id)
        .await?;
    let command_id = CommandId::new();
    let mut delay = REPOSITORY_RETRY_MIN;
    loop {
        let event_at = std::cmp::max(at, stored.call.aggregate.updated_at());
        let request = BoundConnectionStateCommit {
            tenant_id: tenant_id.clone(),
            call_id,
            expected_version: stored.call.aggregate.version(),
            command_id,
            leg_id: binding.leg_id,
            binding_generation: binding.binding_generation,
            connection_id: binding.connection_id.clone(),
            worker: runtime.worker().lease,
            state,
            failure: failure.clone(),
            at: event_at,
        };
        let repository = runtime.service_repository();
        let result = if let Some(cancel) = &mut cancel {
            await_while_execution_owned(
                repository.commit_bound_connection_state(request.clone()),
                cancel,
            )
            .await
            .map_err(|()| RepositoryError::Unavailable)?
        } else {
            repository
                .commit_bound_connection_state(request.clone())
                .await
        };
        match result {
            Ok(ServiceCommandOutcome::Committed(view))
            | Ok(ServiceCommandOutcome::Replayed(view)) => {
                return runtime
                    .service_repository()
                    .load_service_call(
                        view.command.call.aggregate.tenant_id(),
                        view.command.call.aggregate.id(),
                    )
                    .await;
            }
            Err(RepositoryError::VersionConflict) => {
                stored = runtime
                    .service_repository()
                    .load_service_call(&tenant_id, call_id)
                    .await?;
                let Some(leg) = stored.call.aggregate.leg(binding.leg_id) else {
                    return Err(RepositoryError::StaleClaim);
                };
                if leg.state() == state || leg.state().is_terminal() {
                    return Ok(stored);
                }
            }
            Err(RepositoryError::Unavailable) => {
                if let Some(cancel) = &mut cancel {
                    if *cancel.borrow() == ActorShutdown::LeaseLost {
                        return Err(RepositoryError::Unavailable);
                    }
                    tokio::select! {
                        changed = cancel.changed() => {
                            if changed.is_err() || *cancel.borrow() == ActorShutdown::LeaseLost {
                                return Err(RepositoryError::Unavailable);
                            }
                        }
                        _ = tokio::time::sleep(delay) => {}
                    }
                } else {
                    tokio::time::sleep(delay).await;
                }
                delay = (delay * 2).min(REPOSITORY_RETRY_MAX);
            }
            Err(error) => return Err(error),
        }
    }
}

async fn await_while_execution_owned<F, T>(
    future: F,
    shutdown: &mut watch::Receiver<ActorShutdown>,
) -> Result<T, ()>
where
    F: std::future::Future<Output = T>,
{
    tokio::pin!(future);
    loop {
        if *shutdown.borrow() == ActorShutdown::LeaseLost {
            return Err(());
        }
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() == ActorShutdown::LeaseLost {
                    return Err(());
                }
            }
            result = &mut future => return Ok(result),
        }
    }
}

enum OperationalTransition {
    Ignore,
    EndUnexpectedConnected,
    Commit {
        state: LegState,
        failure: Option<FailureDetails>,
    },
    Ephemeral,
}

fn classify_operational_event(
    current: LegState,
    event: &OperationalEventKind,
) -> OperationalTransition {
    match event {
        OperationalEventKind::Connected => match current {
            LegState::Signaling => OperationalTransition::Commit {
                state: LegState::Connected,
                failure: None,
            },
            LegState::Connected | LegState::Held => OperationalTransition::Ignore,
            LegState::Ending | LegState::Ended | LegState::Failed => {
                OperationalTransition::EndUnexpectedConnected
            }
            LegState::Pending | LegState::AwaitingAttach => OperationalTransition::Commit {
                state: LegState::Failed,
                failure: Some(FailureDetails::sanitized(
                    "connected_before_signaling",
                    "transport connected before durable signaling ownership",
                    false,
                )),
            },
        },
        OperationalEventKind::Ended { reason } => {
            let failed_reason = match reason {
                OperationalEndReason::Normal
                | OperationalEndReason::Cancelled
                | OperationalEndReason::BridgeTorn => false,
                OperationalEndReason::Failed | OperationalEndReason::Timeout => true,
                _ => true,
            };
            if current.is_terminal() {
                OperationalTransition::Ignore
            } else if failed_reason
                || matches!(
                    current,
                    LegState::Pending | LegState::AwaitingAttach | LegState::Signaling
                )
            {
                OperationalTransition::Commit {
                    state: LegState::Failed,
                    failure: Some(FailureDetails::sanitized(
                        if failed_reason {
                            "transport_ended_failed"
                        } else {
                            "connection_ended_during_setup"
                        },
                        "transport ended before the call completed normally",
                        false,
                    )),
                }
            } else {
                OperationalTransition::Commit {
                    state: LegState::Ended,
                    failure: None,
                }
            }
        }
        OperationalEventKind::Failed { .. } => {
            if current.is_terminal() {
                OperationalTransition::Ignore
            } else {
                OperationalTransition::Commit {
                    state: LegState::Failed,
                    failure: Some(FailureDetails::sanitized(
                        "transport_failed",
                        "transport reported a sanitized failure",
                        false,
                    )),
                }
            }
        }
        OperationalEventKind::MediaActivity { .. } => OperationalTransition::Ephemeral,
        OperationalEventKind::Dtmf { .. }
        | OperationalEventKind::DataMessage { .. }
        | OperationalEventKind::Transfer { .. } => OperationalTransition::Ephemeral,
        _ => OperationalTransition::Commit {
            state: LegState::Failed,
            failure: Some(FailureDetails::sanitized(
                "unsupported_operational_event",
                "transport emitted an unsupported lifecycle event",
                false,
            )),
        },
    }
}

fn operational_kind_label(kind: &OperationalEventKind) -> &'static str {
    match kind {
        OperationalEventKind::MediaActivity { .. } => "media_activity",
        OperationalEventKind::Dtmf { .. } => "dtmf",
        OperationalEventKind::DataMessage { .. } => "data_message",
        OperationalEventKind::Transfer { .. } => "transfer",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::atomic::AtomicUsize;

    use crate::call_engine::WorkerId;
    use crate::call_service::{
        build_call_service_runtime, CallRepositoryBackendConfig, CallServiceCoordinationConfig,
        CallServiceRuntimeConfig, CallTimeoutPolicy, CreateCallInput, IdempotencyKey,
        LegEndpointConfig, RequestedLeg, SamePrincipalAttachmentResolver, SipEndpointConfig,
        SystemCallServiceClock, WebRtcEndpointConfig,
    };
    use crate::coordination::DeploymentId;
    use crate::{api_principal::ApiPrincipal, call_engine::LegDirection};
    use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod};
    use rvoip_core::config::Config as CoreConfig;
    use rvoip_core::{IdentityAssurance, Jwk, OperationalEventStreamHealth};

    fn deadline_work(call_id: CallId) -> ActorWork {
        ActorWork::Deadline(ClaimedDeadline {
            record: crate::call_engine::DeadlineRecord {
                tenant_id: crate::call_engine::TenantId::parse("mailbox-tenant").unwrap(),
                call_id,
                kind: DeadlineKind::Setup,
                generation: crate::call_engine::DeadlineGeneration::default(),
                due_at: Utc::now(),
                state: crate::call_engine::DeadlineState::Pending,
            },
            claim_generation: crate::call_engine::ClaimGeneration::default(),
        })
    }

    fn actor_slot(retiring: bool) -> ActorSlot {
        let (commands, _) = mpsc::channel(1);
        let (operational, _) = mpsc::channel(1);
        let (work, _) = mpsc::channel(1);
        ActorSlot {
            commands,
            operational,
            work,
            retiring: Arc::new(AtomicBool::new(retiring)),
        }
    }

    #[test]
    fn authority_loss_tears_down_owned_and_not_yet_joined_proof_connections() {
        let call_id = CallId::new();
        let leg_id = LegId::new();
        let owned_connection = ConnectionId::new();
        let committed_proof_not_joined = ConnectionId::new();
        let mut owners = HashMap::from([(
            owned_connection.clone(),
            ConnectionOwner { call_id, leg_id },
        )]);
        let mut inflight =
            HashSet::from([owned_connection.clone(), committed_proof_not_joined.clone()]);
        let collected = take_authority_loss_connections(&owners, &mut inflight)
            .into_iter()
            .collect::<HashSet<_>>();
        assert_eq!(
            collected,
            HashSet::from([owned_connection, committed_proof_not_joined])
        );
        assert!(inflight.is_empty());
        owners.clear();
    }

    #[test]
    fn retiring_actors_release_active_capacity_but_total_tasks_remain_bounded() {
        let mut actors = HashMap::new();
        actors.insert(CallId::new(), actor_slot(true));
        assert_eq!(active_actor_count(&actors), 0);
        assert!(can_spawn_actor(&actors, 1, 3));
        actors.insert(CallId::new(), actor_slot(true));
        actors.insert(CallId::new(), actor_slot(true));
        assert!(!can_spawn_actor(&actors, 1, 3));
        actors.clear();
        actors.insert(CallId::new(), actor_slot(false));
        assert!(!can_spawn_actor(&actors, 1, 3));
    }

    #[test]
    fn per_call_claim_buffer_stops_at_its_explicit_bound() {
        assert!(can_buffer_actor_work(ACTOR_PENDING_WORK_CAPACITY - 1));
        assert!(!can_buffer_actor_work(ACTOR_PENDING_WORK_CAPACITY));
        assert!(!can_buffer_actor_work(ACTOR_PENDING_WORK_CAPACITY + 1));
    }

    #[tokio::test]
    async fn runtime_authority_loss_cancels_before_or_during_owned_future() {
        let (health, mut already_lost) = watch::channel(RuntimeSupervisorHealth::LeaseLost);
        let polls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&polls);
        let ready = std::future::poll_fn(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::Ready(())
        });
        assert_eq!(
            await_while_runtime_owned(ready, &mut already_lost).await,
            Err(())
        );
        assert_eq!(polls.load(Ordering::SeqCst), 0);

        let mut healthy = health.subscribe();
        health.send_replace(RuntimeSupervisorHealth::Healthy);
        let polls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&polls);
        let task = tokio::spawn(async move {
            let pending = std::future::poll_fn(move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
                std::task::Poll::<()>::Pending
            });
            await_while_runtime_owned(pending, &mut healthy).await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while polls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        health.send_replace(RuntimeSupervisorHealth::LeaseLost);
        assert_eq!(task.await.unwrap(), Err(()));
    }

    #[tokio::test]
    async fn operational_write_guard_never_polls_after_lease_loss() {
        let (_shutdown, mut lost) = watch::channel(ActorShutdown::LeaseLost);
        let polls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&polls);
        let write = std::future::poll_fn(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::Ready(())
        });
        assert_eq!(await_while_execution_owned(write, &mut lost).await, Err(()));
        assert_eq!(polls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn full_actor_mailbox_returns_the_exact_claim_for_root_retention() {
        let (sender, mut receiver) = mpsc::channel(1);
        let first_call = CallId::new();
        let retained_call = CallId::new();
        assert!(try_deliver_actor_work(&sender, deadline_work(first_call)).is_none());
        let retained = try_deliver_actor_work(&sender, deadline_work(retained_call))
            .expect("full mailbox must return ownership of the claim");
        assert_eq!(actor_work_call_id(&retained), Some(retained_call));
        assert_eq!(
            actor_work_call_id(&receiver.recv().await.unwrap()),
            Some(first_call)
        );
    }

    #[tokio::test]
    async fn admission_child_panic_is_converted_to_owned_failure() {
        let result = supervise_rvoip_operation(async {
            panic!("injected admission child panic");
            #[allow(unreachable_code)]
            Ok::<(), rvoip_core::RvoipError>(())
        })
        .await;
        assert!(matches!(
            result,
            Err(rvoip_core::RvoipError::InvalidState(
                "owned call operation panicked"
            ))
        ));
    }

    #[tokio::test]
    async fn work_child_panic_runs_the_retained_recovery_future() {
        let result = supervise_work_operation(
            async {
                panic!("injected durable work panic");
                #[allow(unreachable_code)]
                WorkOperationResult {
                    effect_id: None,
                    bridge_update: None,
                    result: Err(RepositoryError::Unavailable),
                }
            },
            async {
                WorkOperationResult {
                    effect_id: None,
                    bridge_update: None,
                    result: Ok(()),
                }
            },
        )
        .await;
        assert_eq!(result.result, Ok(()));
    }

    #[test]
    fn provider_lifecycle_normalization_is_conservative_and_provider_neutral() {
        assert_eq!(
            classify_provider_lifecycle(ProviderKind::Telnyx, "call.initiated"),
            ProviderLifecycle::Progress
        );
        assert_eq!(
            classify_provider_lifecycle(ProviderKind::Telnyx, "call.answered"),
            ProviderLifecycle::Connected
        );
        assert_eq!(
            classify_provider_lifecycle(ProviderKind::Twilio, "completed"),
            ProviderLifecycle::Ended
        );
        assert_eq!(
            classify_provider_lifecycle(ProviderKind::Telnyx, "call.hangup"),
            ProviderLifecycle::Ended
        );
        assert_eq!(
            classify_provider_lifecycle(ProviderKind::Vonage, "unanswered"),
            ProviderLifecycle::Failed
        );
        assert_eq!(
            classify_provider_lifecycle(ProviderKind::Twilio, "unanswered"),
            ProviderLifecycle::Ignore
        );
        assert_eq!(
            classify_provider_lifecycle(ProviderKind::Telnyx, "call.not-connected"),
            ProviderLifecycle::Ignore
        );
        assert_eq!(
            classify_provider_lifecycle(ProviderKind::Vonage, "new-provider-state"),
            ProviderLifecycle::Ignore
        );
        assert_eq!(
            classify_provider_lifecycle(ProviderKind::Vonage, "cancelled"),
            ProviderLifecycle::Failed
        );
    }

    #[test]
    fn provider_receive_skew_bound_cannot_overflow_at_datetime_edges() {
        assert_eq!(
            bounded_provider_received_at(DateTime::<Utc>::MIN_UTC, DateTime::<Utc>::MAX_UTC),
            DateTime::<Utc>::MIN_UTC
        );
        assert_eq!(
            bounded_provider_received_at(DateTime::<Utc>::MAX_UTC, DateTime::<Utc>::MIN_UTC),
            DateTime::<Utc>::MAX_UTC
        );
        let observed = Utc::now();
        let received = observed + chrono::Duration::seconds(30);
        assert_eq!(bounded_provider_received_at(observed, received), received);
    }

    #[test]
    fn media_activity_is_not_misclassified_as_a_lifecycle_failure() {
        assert!(matches!(
            classify_operational_event(
                LegState::Connected,
                &OperationalEventKind::MediaActivity { generation: 7 },
            ),
            OperationalTransition::Ephemeral
        ));
    }

    #[tokio::test]
    async fn lease_loss_stops_execution_and_retires_the_operational_receiver() {
        let mut coordination = CallServiceCoordinationConfig::new(
            DeploymentId::parse("execution-lease-loss-test").unwrap(),
        );
        coordination.worker_lease_ttl = Duration::from_secs(300);
        coordination.worker_renew_interval = Duration::from_secs(100);
        let runtime = Arc::new(
            build_call_service_runtime(
                CallServiceRuntimeConfig {
                    backend: CallRepositoryBackendConfig::Memory,
                    worker_id: WorkerId::new(),
                    max_calls: 2,
                    worker_capabilities: BTreeSet::from(["sip".into(), "webrtc".into()]),
                    control_key: vec![0x52; 32],
                    timeouts: CallTimeoutPolicy {
                        setup: Duration::from_secs(30),
                        media_idle: Duration::from_secs(30),
                        transfer: Duration::from_secs(30),
                        ending: Duration::from_secs(30),
                    },
                    coordination,
                },
                Arc::new(SamePrincipalAttachmentResolver),
                Arc::new(SystemCallServiceClock),
            )
            .await
            .unwrap(),
        );
        let orchestrator = Orchestrator::new(CoreConfig::default());
        let supervisor = CallExecutionSupervisor::install(
            Arc::clone(&orchestrator),
            Arc::clone(&runtime),
            4,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        runtime.force_supervisor_health_for_test(RuntimeSupervisorHealth::LeaseLost);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            orchestrator.operational_event_stream_health(),
            OperationalEventStreamHealth::Degraded,
            "authority loss tears down owned routes and then retires the correctness receiver"
        );
        supervisor.shutdown(Duration::from_secs(2)).await;
        drop(orchestrator);
        let repository = runtime.repository();
        let worker_id = runtime.worker().lease.worker_id;
        Arc::try_unwrap(runtime)
            .expect("execution supervisor released the runtime")
            .shutdown(Duration::from_secs(2))
            .await
            .unwrap();
        assert!(
            !repository
                .worker_snapshot(worker_id)
                .await
                .unwrap()
                .draining,
            "LeaseLost shutdown must perform no stale worker-row mutation"
        );
    }

    #[tokio::test]
    async fn install_rejects_an_already_lost_worker_before_recovery_or_listeners() {
        let mut coordination = CallServiceCoordinationConfig::new(
            DeploymentId::parse("execution-initial-lease-loss-test").unwrap(),
        );
        coordination.worker_lease_ttl = Duration::from_secs(300);
        coordination.worker_renew_interval = Duration::from_secs(100);
        let runtime = Arc::new(
            build_call_service_runtime(
                CallServiceRuntimeConfig {
                    backend: CallRepositoryBackendConfig::Memory,
                    worker_id: WorkerId::new(),
                    max_calls: 1,
                    worker_capabilities: BTreeSet::from(["sip".into(), "webrtc".into()]),
                    control_key: vec![0x53; 32],
                    timeouts: CallTimeoutPolicy::default(),
                    coordination,
                },
                Arc::new(SamePrincipalAttachmentResolver),
                Arc::new(SystemCallServiceClock),
            )
            .await
            .unwrap(),
        );
        runtime.force_supervisor_health_for_test(RuntimeSupervisorHealth::LeaseLost);
        let orchestrator = Orchestrator::new(CoreConfig::default());
        assert!(matches!(
            CallExecutionSupervisor::install(
                Arc::clone(&orchestrator),
                Arc::clone(&runtime),
                2,
                Duration::from_secs(1),
            )
            .await,
            Err(CallExecutionError::RuntimeUnavailable)
        ));
        assert_eq!(
            orchestrator.operational_event_stream_health(),
            OperationalEventStreamHealth::Degraded,
            "the failed install drops its correctness receiver and cannot be reused"
        );
        drop(orchestrator);
        Arc::try_unwrap(runtime)
            .expect("failed installation retained no runtime owner")
            .shutdown(Duration::from_secs(2))
            .await
            .unwrap();
    }

    fn media_principal() -> AuthenticatedPrincipal {
        AuthenticatedPrincipal {
            subject: "media-subject".into(),
            tenant: Some("media-tenant".into()),
            scopes: vec!["*".into()],
            issuer: Some("media-test".into()),
            expires_at: None,
            method: AuthenticationMethod::Jwt,
            assurance: IdentityAssurance::Pseudonymous {
                ephemeral_key: Jwk(serde_json::json!({"kty": "test"})),
            },
        }
    }

    async fn active_media_actor() -> (
        Arc<CallServiceRuntime>,
        CallActor,
        ActorBinding,
        watch::Sender<ActorShutdown>,
    ) {
        let mut coordination =
            CallServiceCoordinationConfig::new(DeploymentId::parse("media-actor-test").unwrap());
        coordination.worker_lease_ttl = Duration::from_secs(300);
        coordination.worker_renew_interval = Duration::from_secs(100);
        let runtime = Arc::new(
            build_call_service_runtime(
                CallServiceRuntimeConfig {
                    backend: CallRepositoryBackendConfig::Memory,
                    worker_id: WorkerId::new(),
                    max_calls: 2,
                    worker_capabilities: BTreeSet::from(["sip".into(), "webrtc".into()]),
                    control_key: vec![0x63; 32],
                    timeouts: CallTimeoutPolicy {
                        setup: Duration::from_secs(30),
                        media_idle: Duration::from_secs(30),
                        transfer: Duration::from_secs(30),
                        ending: Duration::from_secs(30),
                    },
                    coordination,
                },
                Arc::new(SamePrincipalAttachmentResolver),
                Arc::new(SystemCallServiceClock),
            )
            .await
            .unwrap(),
        );
        let principal = media_principal();
        let owner = ApiPrincipal::new(principal.clone(), Utc::now()).unwrap();
        let created = runtime
            .service()
            .create_call(
                &owner,
                &IdempotencyKey::parse("media-actor-call").unwrap(),
                CreateCallInput {
                    tenant_id: None,
                    legs: [
                        RequestedLeg {
                            direction: LegDirection::Inbound,
                            endpoint: LegEndpointConfig::Sip(SipEndpointConfig { uri: None }),
                        },
                        RequestedLeg {
                            direction: LegDirection::Inbound,
                            endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                                signaling_uri: None,
                            }),
                        },
                    ],
                },
            )
            .await
            .unwrap();
        let tenant_id = crate::call_engine::TenantId::parse("media-tenant").unwrap();
        for leg in &created.value.call.legs {
            let attachment = leg.attachment.as_ref().unwrap();
            let connection_id = ConnectionId::new();
            runtime
                .service()
                .consume_inbound_attachment(InboundAttachmentRequest::new(
                    principal.clone(),
                    Some(attachment.token.clone()),
                    attachment.transport,
                    runtime.worker().lease,
                    connection_id.clone(),
                ))
                .await
                .unwrap();
            let stored = runtime
                .service_repository()
                .load_service_call(&tenant_id, created.value.call.call_id)
                .await
                .unwrap();
            let binding = stored.call.bindings.get(&leg.leg_id).unwrap();
            let at = std::cmp::max(
                runtime.observation_time(),
                stored.call.aggregate.updated_at(),
            );
            runtime
                .service()
                .commit_bound_connection_state(BoundConnectionStateCommit {
                    tenant_id: tenant_id.clone(),
                    call_id: stored.call.aggregate.id(),
                    expected_version: stored.call.aggregate.version(),
                    command_id: CommandId::new(),
                    leg_id: leg.leg_id,
                    binding_generation: binding.binding_generation,
                    connection_id,
                    worker: runtime.worker().lease,
                    state: LegState::Connected,
                    failure: None,
                    at,
                })
                .await
                .unwrap();
        }
        let stored = runtime
            .service_repository()
            .load_service_call(&tenant_id, created.value.call.call_id)
            .await
            .unwrap();
        assert_eq!(stored.call.aggregate.state(), CallState::Active);
        let first_binding = stored.call.bindings.values().next().unwrap().clone();
        let actor_binding = ActorBinding {
            connection_id: first_binding.connection_id,
            leg_id: first_binding.leg_id,
            binding_generation: first_binding.binding_generation,
            state: LegState::Connected,
        };
        let (_commands_tx, commands_rx) = mpsc::channel(1);
        let (_operational_tx, operational_rx) = mpsc::channel(1);
        let (_work_tx, work_rx) = mpsc::channel(1);
        let (_drain_tx, drain_rx) = watch::channel(false);
        let (shutdown_tx, shutdown_rx) = watch::channel(ActorShutdown::Running);
        let actor = CallActor::new(
            stored,
            Orchestrator::new(CoreConfig::default()),
            Arc::clone(&runtime),
            commands_rx,
            operational_rx,
            work_rx,
            drain_rx,
            shutdown_rx,
            Arc::new(AtomicBool::new(false)),
        );
        (runtime, actor, actor_binding, shutdown_tx)
    }

    #[tokio::test]
    async fn media_activity_is_consecutive_stale_safe_and_lease_loss_cancelled() {
        let (runtime, mut actor, binding, shutdown) = active_media_actor().await;
        let initial = runtime
            .service_repository()
            .load_service_call(&actor.tenant_id, actor.call_id)
            .await
            .unwrap();
        let at = std::cmp::max(
            runtime.observation_time(),
            initial.call.aggregate.updated_at(),
        );
        actor
            .record_media_activity(&binding, 1, at, initial)
            .await
            .unwrap();
        let first = runtime
            .service_repository()
            .load_service_call(&actor.tenant_id, actor.call_id)
            .await
            .unwrap();
        let first_deadline = first
            .call
            .aggregate
            .deadlines()
            .get(DeadlineKind::Media)
            .due_at();
        assert!(first_deadline.is_some());

        actor
            .record_media_activity(&binding, 1, at, first.clone())
            .await
            .unwrap();
        let skipped = runtime
            .service_repository()
            .load_service_call(&actor.tenant_id, actor.call_id)
            .await
            .unwrap();
        actor
            .record_media_activity(&binding, 3, at, skipped)
            .await
            .unwrap();
        let unchanged = runtime
            .service_repository()
            .load_service_call(&actor.tenant_id, actor.call_id)
            .await
            .unwrap();
        assert_eq!(
            unchanged
                .call
                .aggregate
                .deadlines()
                .get(DeadlineKind::Media)
                .due_at(),
            first_deadline
        );

        let mut stale_binding = binding.clone();
        stale_binding.connection_id = ConnectionId::new();
        actor
            .record_media_activity(&stale_binding, 2, at, unchanged.clone())
            .await
            .unwrap();
        shutdown.send_replace(ActorShutdown::LeaseLost);
        assert_eq!(
            actor
                .record_media_activity(&binding, 2, at, unchanged)
                .await,
            Err(RepositoryError::Unavailable)
        );
    }

    #[test]
    fn operational_transition_never_revives_terminal_state() {
        for state in [LegState::Ending, LegState::Ended, LegState::Failed] {
            assert!(matches!(
                classify_operational_event(state, &OperationalEventKind::Connected),
                OperationalTransition::EndUnexpectedConnected
            ));
        }
    }

    #[test]
    fn setup_end_is_failure_but_connected_end_is_normal() {
        assert!(matches!(
            classify_operational_event(
                LegState::Signaling,
                &OperationalEventKind::Ended {
                    reason: OperationalEndReason::Normal,
                },
            ),
            OperationalTransition::Commit {
                state: LegState::Failed,
                ..
            }
        ));
        assert!(matches!(
            classify_operational_event(
                LegState::Connected,
                &OperationalEventKind::Ended {
                    reason: OperationalEndReason::Normal,
                },
            ),
            OperationalTransition::Commit {
                state: LegState::Ended,
                failure: None,
            }
        ));
    }

    #[test]
    fn operational_payload_debug_is_not_needed_for_routing_labels() {
        assert_eq!(
            operational_kind_label(&OperationalEventKind::Dtmf {
                digits: "1234".into(),
                duration_ms: 100,
            }),
            "dtmf"
        );
    }
}
