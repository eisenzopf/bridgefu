//! Bounded ownership of inbound signaling and authoritative rvoip lifecycle.
//!
//! The compatibility rvoip broadcast is intentionally absent from this
//! module. Admission, connection indexing, lifecycle reconciliation, and call
//! actors all use bounded single-consumer channels whose tasks are owned by
//! [`CallExecutionSupervisor`].

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use rvoip_core::adapter::{EndReason, RejectReason};
use rvoip_core::commands::InboundAction;
use rvoip_core::connection::Transport;
use rvoip_core::conversation::ConversationPolicy;
use rvoip_core::ids::{
    BridgeId, ConnectionId, ConversationId, ParticipantId, SessionId, TenantId as RvoipTenantId,
};
use rvoip_core::session::SessionMedium;
use rvoip_core::{
    InboundAdmission, OperationalEndReason, OperationalEvent, OperationalEventKind, Orchestrator,
};
use thiserror::Error;
use tokio::sync::{mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};

use crate::call_engine::{
    AttachmentTransport, CallCommand, CallId, ClaimedDeadline, ClaimedOutbox, CommandCommit,
    CommandId, EffectIntent, FailureDetails, LegId, LegState, RepositoryError, RestartClaim,
    TransferResult,
};

use super::{
    BoundConnectionStateCommit, CallExecutionPlan, CallServiceRuntime, ClaimedControlEffect,
    ControlIntent, EffectResultOutcome, EffectResultReconciliation, InboundAttachmentError,
    InboundAttachmentRequest, InboundAttachmentResult, ServiceCommandOutcome,
    ServiceCommandTransaction, ServiceEffectResult, StoredServiceCall,
};

const OPERATIONAL_MAILBOX_PER_CALL: usize = 64;
const ACTOR_COMMAND_MAILBOX: usize = 16;
const REPOSITORY_RETRY_MIN: Duration = Duration::from_millis(25);
const REPOSITORY_RETRY_MAX: Duration = Duration::from_secs(1);
const WORK_POLL_INTERVAL: Duration = Duration::from_millis(250);
const WORK_CLAIM_TTL: Duration = Duration::from_secs(30);
const WORK_BATCH_SIZE: usize = 64;

/// Installation or lifecycle failure for the call execution owner.
#[derive(Debug, Error)]
pub enum CallExecutionError {
    /// rvoip rejected installation or an owned operation.
    #[error("rvoip call execution setup failed: {0}")]
    Rvoip(#[from] rvoip_core::RvoipError),
    /// A configured capacity or timeout is invalid.
    #[error("invalid call execution configuration: {0}")]
    InvalidConfiguration(&'static str),
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
    pub fn install(
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
        let (drain, drain_rx) = watch::channel(false);
        let (stop, stop_rx) = watch::channel(false);
        let task = tokio::spawn(run_supervisor(
            admission,
            operational,
            orchestrator,
            call_runtime,
            setup_timeout,
            drain_rx,
            stop_rx,
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

impl Drop for CallExecutionSupervisor {
    fn drop(&mut self) {
        let _ = self.drain.send(true);
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

struct ProvenAdmission {
    admission: InboundAdmission,
    consumed: InboundAttachmentResult,
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
}

enum ActorCommand {
    Admit(ProvenAdmission),
}

enum ActorWork {
    Call(ClaimedOutbox),
    Control(ClaimedControlEffect),
    Deadline(ClaimedDeadline),
    Restart(RestartClaim),
}

#[derive(Default)]
struct WorkClaimBatch {
    items: Vec<ActorWork>,
}

struct ActorExit {
    call_id: CallId,
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
    stop: watch::Receiver<bool>,
    bindings: HashMap<LegId, ActorBinding>,
    pending_admissions: VecDeque<ProvenAdmission>,
    admission_operation: JoinSet<AdmissionOperationResult>,
    pending_work: VecDeque<ActorWork>,
    work_operation: JoinSet<WorkOperationResult>,
    bridge_id: Option<BridgeId>,
    conversation_id: Option<ConversationId>,
    session_id: Option<SessionId>,
}

async fn run_supervisor(
    mut admissions: mpsc::Receiver<InboundAdmission>,
    mut operational: mpsc::Receiver<OperationalEvent>,
    orchestrator: Arc<Orchestrator>,
    runtime: Arc<CallServiceRuntime>,
    setup_timeout: Duration,
    mut drain: watch::Receiver<bool>,
    mut stop: watch::Receiver<bool>,
) {
    let mut proof_tasks = JoinSet::new();
    let mut actors = JoinSet::<ActorExit>::new();
    let mut work_claims = JoinSet::<WorkClaimBatch>::new();
    let mut actor_slots = HashMap::<CallId, ActorSlot>::new();
    let mut connection_owners = HashMap::<ConnectionId, ConnectionOwner>::new();
    let mut work_wakeups = runtime.subscribe_work_wakeups();
    let mut work_poll = tokio::time::interval(WORK_POLL_INTERVAL);
    work_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    admissions.close();
                    break;
                }
            }
            changed = drain.changed() => {
                if changed.is_err() || *drain.borrow() {
                    admissions.close();
                    while let Ok(admission) = admissions.try_recv() {
                        let _ = admission.reject(RejectReason::ServerError).await;
                    }
                }
            }
            result = actors.join_next(), if !actors.is_empty() => {
                match result {
                    Some(Ok(exit)) => {
                        actor_slots.remove(&exit.call_id);
                        connection_owners.retain(|_, owner| owner.call_id != exit.call_id);
                    }
                    Some(Err(error)) => {
                        tracing::error!(%error, "call actor panicked");
                    }
                    None => {}
                }
            }
            result = proof_tasks.join_next(), if !proof_tasks.is_empty() => {
                match result {
                    Some(Ok(Some(proven))) => {
                        if *drain.borrow() {
                            fail_unowned_proven_admission(proven, &orchestrator, &runtime).await;
                        } else {
                            register_proven_admission(
                                proven,
                                &orchestrator,
                                &runtime,
                                &mut actor_slots,
                                &mut connection_owners,
                                &mut actors,
                                drain.clone(),
                                stop.clone(),
                            ).await;
                        }
                    }
                    Some(Ok(None)) => {}
                    Some(Err(error)) => tracing::error!(%error, "attachment proof task panicked"),
                    None => {}
                }
            }
            result = work_claims.join_next(), if !work_claims.is_empty() => {
                match result {
                    Some(Ok(batch)) => {
                        for item in batch.items {
                            route_claimed_work(
                                item,
                                &orchestrator,
                                &runtime,
                                &mut actor_slots,
                                &mut actors,
                                drain.clone(),
                                stop.clone(),
                            ).await;
                        }
                    }
                    Some(Err(error)) => tracing::error!(%error, "durable work claim task panicked"),
                    None => {}
                }
            }
            event = operational.recv() => {
                let Some(event) = event else {
                    tracing::error!("authoritative operational receiver closed");
                    break;
                };
                route_operational_event(
                    event,
                    &orchestrator,
                    &actor_slots,
                    &connection_owners,
                ).await;
            }
            admission = admissions.recv() => {
                let Some(admission) = admission else { break; };
                let runtime = Arc::clone(&runtime);
                proof_tasks.spawn(async move {
                    prove_admission(admission, runtime, setup_timeout).await
                });
            }
            changed = work_wakeups.changed(), if work_claims.is_empty() && !*drain.borrow() => {
                if changed.is_ok() {
                    spawn_work_claim(&mut work_claims, Arc::clone(&runtime));
                }
            }
            _ = work_poll.tick(), if work_claims.is_empty() && !*drain.borrow() => {
                spawn_work_claim(&mut work_claims, Arc::clone(&runtime));
            }
        }
    }

    while let Ok(admission) = admissions.try_recv() {
        let _ = admission.reject(RejectReason::ServerError).await;
    }
    while let Some(result) = proof_tasks.join_next().await {
        if let Ok(Some(proven)) = result {
            fail_unowned_proven_admission(proven, &orchestrator, &runtime).await;
        }
    }
    work_claims.abort_all();
    while work_claims.join_next().await.is_some() {}
    actor_slots.clear();
    while let Some(result) = actors.join_next().await {
        if let Err(error) = result {
            tracing::warn!(%error, "call actor panicked while draining");
        }
    }
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
        Ok(claims) => batch
            .items
            .extend(claims.into_iter().map(ActorWork::Restart)),
        Err(error) => tracing::warn!(%error, "claiming restart call work failed"),
    }
    batch
}

async fn prove_admission(
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
    let consumed = match tokio::time::timeout(
        setup_timeout,
        runtime.service().consume_inbound_attachment(request),
    )
    .await
    {
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

#[allow(clippy::too_many_arguments)]
async fn register_proven_admission(
    proven: ProvenAdmission,
    orchestrator: &Arc<Orchestrator>,
    runtime: &Arc<CallServiceRuntime>,
    actor_slots: &mut HashMap<CallId, ActorSlot>,
    connection_owners: &mut HashMap<ConnectionId, ConnectionOwner>,
    actors: &mut JoinSet<ActorExit>,
    drain: watch::Receiver<bool>,
    stop: watch::Receiver<bool>,
) {
    let call_id = proven.consumed.commit.call.aggregate.id();
    let tenant_id = proven.consumed.commit.call.aggregate.tenant_id().clone();
    let binding = &proven.consumed.binding;
    let connection_id = binding.connection_id.clone();
    let owner = ConnectionOwner {
        call_id,
        leg_id: binding.leg_id,
    };
    if connection_owners
        .insert(connection_id.clone(), owner)
        .is_some()
    {
        fail_unowned_proven_admission(proven, orchestrator, runtime).await;
        return;
    }

    if !actor_slots.contains_key(&call_id) {
        if actor_slots.len() >= runtime.worker().max_calls {
            connection_owners.remove(&connection_id);
            fail_unowned_proven_admission(proven, orchestrator, runtime).await;
            return;
        }
        let stored = match runtime
            .service_repository()
            .load_service_call(&tenant_id, call_id)
            .await
        {
            Ok(stored) => stored,
            Err(_) => {
                connection_owners.remove(&connection_id);
                fail_unowned_proven_admission(proven, orchestrator, runtime).await;
                return;
            }
        };
        spawn_call_actor(
            stored,
            orchestrator,
            runtime,
            actor_slots,
            actors,
            drain,
            stop,
        );
    }

    let Some(slot) = actor_slots.get(&call_id) else {
        connection_owners.remove(&connection_id);
        fail_unowned_proven_admission(proven, orchestrator, runtime).await;
        return;
    };
    if let Err(mpsc::error::SendError(ActorCommand::Admit(proven))) =
        slot.commands.send(ActorCommand::Admit(proven)).await
    {
        connection_owners.remove(&connection_id);
        tracing::error!(%call_id, %connection_id, "call actor rejected a proven admission");
        fail_unowned_proven_admission(proven, orchestrator, runtime).await;
    }
}

fn spawn_call_actor(
    stored: StoredServiceCall,
    orchestrator: &Arc<Orchestrator>,
    runtime: &Arc<CallServiceRuntime>,
    actor_slots: &mut HashMap<CallId, ActorSlot>,
    actors: &mut JoinSet<ActorExit>,
    drain: watch::Receiver<bool>,
    stop: watch::Receiver<bool>,
) {
    let call_id = stored.call.aggregate.id();
    let (commands_tx, commands_rx) = mpsc::channel(ACTOR_COMMAND_MAILBOX);
    let (operational_tx, operational_rx) = mpsc::channel(OPERATIONAL_MAILBOX_PER_CALL);
    let (work_tx, work_rx) = mpsc::channel(ACTOR_COMMAND_MAILBOX);
    actor_slots.insert(
        call_id,
        ActorSlot {
            commands: commands_tx,
            operational: operational_tx,
            work: work_tx,
        },
    );
    actors.spawn(
        CallActor::new(
            stored,
            Arc::clone(orchestrator),
            Arc::clone(runtime),
            commands_rx,
            operational_rx,
            work_rx,
            drain,
            stop,
        )
        .run(),
    );
}

async fn route_claimed_work(
    item: ActorWork,
    orchestrator: &Arc<Orchestrator>,
    runtime: &Arc<CallServiceRuntime>,
    actor_slots: &mut HashMap<CallId, ActorSlot>,
    actors: &mut JoinSet<ActorExit>,
    drain: watch::Receiver<bool>,
    stop: watch::Receiver<bool>,
) {
    let (tenant_id, call_id) = match &item {
        ActorWork::Call(claim) => (&claim.record.tenant_id, claim.record.call_id),
        ActorWork::Control(claim) => (&claim.record.tenant_id, claim.record.call_id),
        ActorWork::Deadline(claim) => (&claim.record.tenant_id, claim.record.call_id),
        ActorWork::Restart(claim) => (claim.call.aggregate.tenant_id(), claim.call.aggregate.id()),
    };
    if !actor_slots.contains_key(&call_id) {
        if actor_slots.len() >= runtime.worker().max_calls {
            tracing::error!(%call_id, "durable work could not allocate its reserved call actor");
            return;
        }
        let stored = match runtime
            .service_repository()
            .load_service_call(tenant_id, call_id)
            .await
        {
            Ok(stored) => stored,
            Err(error) => {
                tracing::warn!(%call_id, %error, "loading claimed call work failed");
                return;
            }
        };
        spawn_call_actor(
            stored,
            orchestrator,
            runtime,
            actor_slots,
            actors,
            drain,
            stop,
        );
    }
    let Some(actor) = actor_slots.get(&call_id) else {
        return;
    };
    if actor.work.send(item).await.is_err() {
        tracing::error!(%call_id, "call actor closed after durable work was claimed");
    }
}

async fn fail_unowned_proven_admission(
    proven: ProvenAdmission,
    orchestrator: &Arc<Orchestrator>,
    runtime: &Arc<CallServiceRuntime>,
) {
    let connection_id = proven.consumed.binding.connection_id.clone();
    let _ = proven.admission.reject(RejectReason::ServerError).await;
    let failure = FailureDetails::sanitized(
        "execution_unavailable",
        "call execution owner unavailable after durable attachment",
        true,
    );
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        commit_binding_state(
            runtime,
            proven.consumed.commit.call.aggregate.tenant_id(),
            proven.consumed.commit.call.aggregate.id(),
            &proven.consumed.binding,
            LegState::Failed,
            Some(failure),
            Utc::now(),
            None,
        ),
    )
    .await;
    let _ = orchestrator
        .end_connection(
            connection_id,
            EndReason::Failed {
                detail: "call execution owner unavailable".into(),
            },
        )
        .await;
}

async fn route_operational_event(
    event: OperationalEvent,
    orchestrator: &Arc<Orchestrator>,
    actors: &HashMap<CallId, ActorSlot>,
    owners: &HashMap<ConnectionId, ConnectionOwner>,
) {
    let Some(owner) = owners.get(&event.connection_id) else {
        if matches!(event.kind, OperationalEventKind::Connected) {
            tracing::error!(connection_id = %event.connection_id, sequence = event.sequence, "unowned operational connection event");
            let _ = orchestrator
                .end_connection(
                    event.connection_id,
                    EndReason::Failed {
                        detail: "operational event has no durable owner".into(),
                    },
                )
                .await;
        }
        return;
    };
    let Some(actor) = actors.get(&owner.call_id) else {
        tracing::error!(call_id = %owner.call_id, leg_id = %owner.leg_id, "operational event owner actor is missing");
        return;
    };
    if actor.operational.send(event).await.is_err() {
        tracing::error!(call_id = %owner.call_id, leg_id = %owner.leg_id, "operational event owner actor closed");
    }
}

impl CallActor {
    fn new(
        stored: StoredServiceCall,
        orchestrator: Arc<Orchestrator>,
        runtime: Arc<CallServiceRuntime>,
        commands: mpsc::Receiver<ActorCommand>,
        operational: mpsc::Receiver<OperationalEvent>,
        work: mpsc::Receiver<ActorWork>,
        drain: watch::Receiver<bool>,
        stop: watch::Receiver<bool>,
    ) -> Self {
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
            stop,
            bindings: HashMap::new(),
            pending_admissions: VecDeque::new(),
            admission_operation: JoinSet::new(),
            pending_work: VecDeque::new(),
            work_operation: JoinSet::new(),
            bridge_id: None,
            conversation_id: None,
            session_id: None,
        }
    }

    async fn run(mut self) -> ActorExit {
        loop {
            if self.admission_operation.is_empty() && !self.pending_admissions.is_empty() {
                self.start_next_admission().await;
            }
            if self.work_operation.is_empty() && !self.pending_work.is_empty() {
                self.start_next_work();
            }
            tokio::select! {
                biased;
                changed = self.stop.changed() => {
                    if changed.is_err() || *self.stop.borrow() {
                        break;
                    }
                }
                changed = self.drain.changed() => {
                    if changed.is_err() || *self.drain.borrow() {
                        while let Some(proven) = self.pending_admissions.pop_front() {
                            fail_unowned_proven_admission(
                                proven,
                                &self.orchestrator,
                                &self.runtime,
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
                        Some(Ok(result)) => self.finish_work_operation(result),
                        Some(Err(error)) => tracing::error!(call_id = %self.call_id, %error, "durable work operation panicked"),
                        None => {}
                    }
                }
                command = self.commands.recv() => {
                    let Some(command) = command else { break; };
                    match command {
                        ActorCommand::Admit(proven) => self.queue_admission(proven).await,
                    }
                }
                work = self.work.recv() => {
                    let Some(work) = work else { break; };
                    self.pending_work.push_back(work);
                }
            }
        }
        self.cleanup().await;
        ActorExit {
            call_id: self.call_id,
        }
    }

    async fn queue_admission(&mut self, proven: ProvenAdmission) {
        let binding = &proven.consumed.binding;
        if proven.consumed.commit.call.aggregate.id() != self.call_id
            || proven.consumed.commit.call.aggregate.tenant_id() != &self.tenant_id
            || self
                .plan
                .legs
                .iter()
                .all(|leg| leg.leg_id != binding.leg_id)
            || self.bindings.contains_key(&binding.leg_id)
        {
            fail_unowned_proven_admission(proven, &self.orchestrator, &self.runtime).await;
            return;
        }
        self.bindings.insert(
            binding.leg_id,
            ActorBinding {
                connection_id: binding.connection_id.clone(),
                leg_id: binding.leg_id,
                binding_generation: binding.binding_generation,
                state: LegState::Signaling,
            },
        );
        self.pending_admissions.push_back(proven);
    }

    async fn start_next_admission(&mut self) {
        let Some(proven) = self.pending_admissions.pop_front() else {
            return;
        };
        let session_id = match self.ensure_session().await {
            Ok(session_id) => session_id,
            Err(error) => {
                tracing::error!(call_id = %self.call_id, %error, "creating rvoip call session failed");
                fail_unowned_proven_admission(proven, &self.orchestrator, &self.runtime).await;
                return;
            }
        };
        let connection_id = proven.consumed.binding.connection_id.clone();
        let orchestrator = Arc::clone(&self.orchestrator);
        self.admission_operation.spawn(async move {
            let result = async {
                proven.admission.accept().await?;
                orchestrator
                    .route_inbound_connection(
                        connection_id.clone(),
                        InboundAction::Accept {
                            session_id,
                            participant_id: ParticipantId::new(),
                        },
                    )
                    .await
            }
            .await;
            AdmissionOperationResult {
                connection_id,
                result,
            }
        });
    }

    async fn ensure_session(&mut self) -> Result<SessionId, rvoip_core::RvoipError> {
        if let Some(session_id) = &self.session_id {
            return Ok(session_id.clone());
        }
        let conversation_id = self
            .orchestrator
            .open_conversation(
                RvoipTenantId::from_string(self.tenant_id.as_str()),
                ConversationPolicy::default(),
                HashMap::new(),
            )
            .await?;
        let session_id = match self
            .orchestrator
            .start_session(conversation_id.clone(), SessionMedium::Voice, Vec::new())
            .await
        {
            Ok(session_id) => session_id,
            Err(error) => {
                let _ = self
                    .orchestrator
                    .close_conversation(conversation_id, true)
                    .await;
                return Err(error);
            }
        };
        self.conversation_id = Some(conversation_id);
        self.session_id = Some(session_id.clone());
        Ok(session_id)
    }

    async fn finish_admission_operation(&mut self, result: AdmissionOperationResult) {
        if result.result.is_ok() {
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
            .commit_current_binding(binding.leg_id, LegState::Failed, Some(failure), Utc::now())
            .await;
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
        let stop = self.stop.clone();
        self.work_operation.spawn(async move {
            execute_actor_work(work, orchestrator, runtime, bindings, bridge_id, stop).await
        });
    }

    fn finish_work_operation(&mut self, result: WorkOperationResult) {
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
    }

    async fn handle_operational(&mut self, event: OperationalEvent) {
        let Some(binding) = self
            .bindings
            .values()
            .find(|binding| binding.connection_id == event.connection_id)
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
        let transition = classify_operational_event(leg.state(), &event.kind);
        match transition {
            OperationalTransition::Ignore => {}
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
                if self
                    .commit_current_binding(leg_id, state, failure, at)
                    .await
                    .is_ok()
                {
                    if let Some(binding) = self.bindings.get_mut(&leg_id) {
                        binding.state = state;
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
            Some(self.stop.clone()),
        )
        .await
    }

    async fn cleanup(&mut self) {
        while let Some(proven) = self.pending_admissions.pop_front() {
            fail_unowned_proven_admission(proven, &self.orchestrator, &self.runtime).await;
        }
        self.admission_operation.abort_all();
        while self.admission_operation.join_next().await.is_some() {}
        self.work_operation.abort_all();
        while self.work_operation.join_next().await.is_some() {}
        let leg_ids = self.bindings.keys().copied().collect::<Vec<_>>();
        for leg_id in leg_ids {
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
                        Utc::now(),
                    ),
                )
                .await;
            }
        }
        for binding in self.bindings.values() {
            let _ = self
                .orchestrator
                .end_connection(binding.connection_id.clone(), EndReason::Cancelled)
                .await;
        }
        if let Some(session_id) = self.session_id.take() {
            let _ = self
                .orchestrator
                .end_session(session_id, EndReason::Cancelled)
                .await;
        }
        if let Some(conversation_id) = self.conversation_id.take() {
            let _ = self
                .orchestrator
                .close_conversation(conversation_id, true)
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

async fn execute_actor_work(
    work: ActorWork,
    orchestrator: Arc<Orchestrator>,
    runtime: Arc<CallServiceRuntime>,
    bindings: HashMap<LegId, ActorBinding>,
    bridge_id: Option<BridgeId>,
    stop: watch::Receiver<bool>,
) -> WorkOperationResult {
    match work {
        ActorWork::Call(claim) => {
            execute_call_effect(claim, orchestrator, runtime, bindings, bridge_id, stop).await
        }
        ActorWork::Control(claim) => {
            execute_control_effect(claim, orchestrator, runtime, bindings, stop).await
        }
        ActorWork::Deadline(claim) => WorkOperationResult {
            effect_id: None,
            bridge_update: None,
            result: commit_deadline(claim, runtime, stop).await,
        },
        ActorWork::Restart(claim) => WorkOperationResult {
            effect_id: None,
            bridge_update: None,
            result: recover_restarted_call(claim, runtime, stop).await,
        },
    }
}

async fn execute_call_effect(
    claim: ClaimedOutbox,
    orchestrator: Arc<Orchestrator>,
    runtime: Arc<CallServiceRuntime>,
    bindings: HashMap<LegId, ActorBinding>,
    bridge_id: Option<BridgeId>,
    stop: watch::Receiver<bool>,
) -> WorkOperationResult {
    let effect_id = claim.record.effect_id;
    let meta = ClaimedEffectMeta {
        tenant_id: claim.record.tenant_id.clone(),
        call_id: claim.record.call_id,
        effect_id,
        claim_generation: claim.claim_generation,
    };
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
                (Some(left), Some(right)) => match orchestrator
                    .bridge_connections(left.connection_id.clone(), right.connection_id.clone())
                    .await
                {
                    Ok(created) => {
                        bridge_update = Some(Some(created));
                        (ServiceEffectResult::Succeeded, FollowUpPlan::None)
                    }
                    Err(_) => {
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
            Some(bridge_id) => match orchestrator.unbridge_connections(bridge_id).await {
                Ok(()) => {
                    bridge_update = Some(None);
                    (ServiceEffectResult::Succeeded, FollowUpPlan::None)
                }
                Err(_) => (
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
            Some(binding) if binding.binding_generation == binding_generation => match orchestrator
                .end_connection(binding.connection_id.clone(), EndReason::BridgeTorn)
                .await
            {
                Ok(()) => (ServiceEffectResult::Succeeded, FollowUpPlan::None),
                Err(_) => (
                    ServiceEffectResult::Failed(FailureDetails::sanitized(
                        "stop_leg_failed",
                        "rvoip could not confirm transport teardown",
                        true,
                    )),
                    FollowUpPlan::None,
                ),
            },
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
            let failure = FailureDetails::sanitized(
                "outbound_not_ready",
                "outbound signaling is not enabled for this endpoint",
                false,
            );
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
            let failure = FailureDetails::sanitized(
                "transfer_not_ready",
                "the selected transfer executor is not enabled",
                false,
            );
            (
                ServiceEffectResult::Failed(failure.clone()),
                FollowUpPlan::FinishTransfer {
                    deadline_generation,
                    result: TransferResult::Rejected(failure),
                },
            )
        }
    };
    let reconciled = reconcile_effect(meta, result, follow_up, runtime, stop).await;
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
    stop: watch::Receiver<bool>,
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
            match orchestrator
                .send_dtmf(
                    binding.connection_id.clone(),
                    &sequence.digits,
                    u32::from(sequence.duration_ms),
                )
                .await
            {
                Ok(()) => ServiceEffectResult::Succeeded,
                Err(_) => ServiceEffectResult::Failed(FailureDetails::sanitized(
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
    let reconciled = reconcile_effect(meta, result, FollowUpPlan::None, runtime, stop).await;
    WorkOperationResult {
        effect_id: Some(effect_id),
        bridge_update: None,
        result: reconciled,
    }
}

async fn reconcile_effect(
    meta: ClaimedEffectMeta,
    result: ServiceEffectResult,
    follow_up: FollowUpPlan,
    runtime: Arc<CallServiceRuntime>,
    mut stop: watch::Receiver<bool>,
) -> Result<(), RepositoryError> {
    loop {
        if *stop.borrow() {
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
                    if *stop.borrow() {
                        return Err(RepositoryError::Unavailable);
                    }
                    tokio::select! {
                        changed = stop.changed() => {
                            if changed.is_err() || *stop.borrow() {
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
    }))
}

async fn commit_deadline(
    claim: ClaimedDeadline,
    runtime: Arc<CallServiceRuntime>,
    mut stop: watch::Receiver<bool>,
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
                    if *stop.borrow() {
                        return Err(RepositoryError::Unavailable);
                    }
                    tokio::select! {
                        changed = stop.changed() => {
                            if changed.is_err() || *stop.borrow() {
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
    stop: watch::Receiver<bool>,
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
                Some(stop.clone()),
            )
            .await?;
        } else {
            commit_unbound_restart_failure(
                &runtime,
                &stored,
                leg_id,
                leg.binding_generation(),
                failure,
                stop.clone(),
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
    mut stop: watch::Receiver<bool>,
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
                    if *stop.borrow() {
                        return Err(RepositoryError::Unavailable);
                    }
                    tokio::select! {
                        changed = stop.changed() => {
                            if changed.is_err() || *stop.borrow() {
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

async fn commit_binding_state(
    runtime: &Arc<CallServiceRuntime>,
    tenant_id: &crate::call_engine::TenantId,
    call_id: CallId,
    binding: &crate::call_engine::ConnectionBinding,
    state: LegState,
    failure: Option<FailureDetails>,
    at: DateTime<Utc>,
    mut cancel: Option<watch::Receiver<bool>>,
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
        match runtime
            .service_repository()
            .commit_bound_connection_state(request.clone())
            .await
        {
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
                    if *cancel.borrow() {
                        return Err(RepositoryError::Unavailable);
                    }
                    tokio::select! {
                        changed = cancel.changed() => {
                            if changed.is_err() || *cancel.borrow() {
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
        OperationalEventKind::Dtmf { .. } => "dtmf",
        OperationalEventKind::DataMessage { .. } => "data_message",
        OperationalEventKind::Transfer { .. } => "transfer",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
