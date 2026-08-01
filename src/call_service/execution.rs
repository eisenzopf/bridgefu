//! Bounded ownership of inbound signaling and authoritative rvoip lifecycle.
//!
//! The compatibility rvoip broadcast is intentionally absent from this
//! module. Admission, connection indexing, lifecycle reconciliation, and call
//! actors all use bounded single-consumer channels whose tasks are owned by
//! [`CallExecutionSupervisor`].

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures_util::FutureExt;
use rvoip_amazon_connect::{
    AmazonConnectAdapter, ConnectProfileId, AMAZON_CONNECT_CONTACT_REFERENCE_KIND,
};
use rvoip_core::adapter::{
    EndReason, ExternalConnectionReference, OriginateRequest, RejectReason,
    TransferStatus as RvoipTransferStatus, TransferTarget as RvoipTransferTarget,
};
use rvoip_core::capability::CapabilityDescriptor;
use rvoip_core::commands::InboundAction;
use rvoip_core::connection::{Direction, Transport};
use rvoip_core::conversation::ConversationPolicy;
use rvoip_core::ids::{
    BridgeId, ConnectionId, ConversationId, ParticipantId, SessionId, TenantId as RvoipTenantId,
    TransferAttemptId,
};
use rvoip_core::session::SessionMedium;
use rvoip_core::{
    DirectionalMediaBridgePlan, InboundAdmission, InboundAdmissionTermination,
    OperationalEndReason, OperationalEvent, OperationalEventKind, OperationalEventStreamHealth,
    OperationalEventStreamHealthSubscription, Orchestrator, ProvisionalMediaRoute, RvoipError,
    StagedInboundDataChannel, StagedInboundDataPolicy,
};
use rvoip_sip::SipInitialHeaders;
use rvoip_webrtc::WebRtcOriginateContext;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::broadcast::WorkerBroadcastSubscriptionAuthority;
use crate::call_engine::{
    AttachmentPurpose, AttachmentTransport, CallCommand, CallId, CallState, ClaimedDeadline,
    ClaimedOutbox, CommandCommit, CommandId, ConnectionBinding, DeadlineKind, EffectIntent,
    FailureDetails, LegId, LegReplacementResult, LegState, ProviderReferenceRole, RepositoryError,
    RestartClaim, SignalingInitiator, SourceBeforeAnswerTermination, TenantId, TransferResult,
};
use crate::context::{
    BridgefuContextBridgePolicy, ContextEnvelope, ContextPolicy, ContextSourceBinding,
    CONTEXT_LABEL,
};
use crate::gateway_attachment::{
    WorkerAttachmentAdmissionReceipt, WorkerAttachmentAdmissionRequest,
    WorkerAttachmentAdmissionResponse, PRIVATE_ATTACHMENT_ADMISSION_RESPONSE_LABEL,
};
use crate::gateway_forwarding::{WorkerBroadcastAdmissionRequest, PRIVATE_FORWARD_SCOPE};
use crate::handoff_status::{HandoffStatusEnvelope, HandoffStatusKind};
#[cfg(test)]
use crate::private_egress::PrivateEgressLifecycleEvent;
use crate::private_egress::{
    PrivateEgressCommand, PrivateEgressEndReason, PrivateEgressError,
    PrivateEgressLifecycleDelivery, PrivateEgressLifecycleKind, PrivateEgressLifecycleState,
    PrivateEgressOperation, PrivateEgressProfile, PrivateEgressSource, PrivateEgressStagedControl,
    PrivateEgressTarget, PrivateEgressTransport, PRIVATE_EGRESS_COMMAND_LABEL,
    PRIVATE_EGRESS_LIFECYCLE_ACK_LABEL, PRIVATE_EGRESS_LIFECYCLE_LABEL,
    PRIVATE_EGRESS_RESPONSE_LABEL,
};
use crate::private_egress_stream::{
    PrivateEgressStreamAdmission, PrivateEgressWorkerConnection, PrivateEgressWorkerRuntime,
};
use crate::standardcharter_canary::{
    StandardCharterCanaryDecision, StandardCharterCanaryError, StandardCharterCanaryPolicy,
};

use super::{
    BoundConnectionStateCommit, BoundSourceTerminationCommit, CallExecutionPlan, CallServiceError,
    CallServiceRuntime, ClaimedControlEffect, ControlIntent, DisabledOutboundProfileResolver,
    DisabledProviderLegExecutor, EffectResultOutcome, EffectResultReconciliation,
    ExternalReferenceBinding, ExternalReferenceValue, InboundAttachmentError,
    InboundAttachmentRequest, InboundAttachmentResult, InitialContextRecordOutcome,
    InitialContextRecordRequest, MediaActivityGeneration, MediaActivityObservation,
    NamedProfileKind, NamedProfileRole, OutboundConnectionBind, OutboundConnectionBindOutcome,
    OutboundProfileError, OutboundProfileResolver, ProviderConnectDestinationRequest,
    ProviderDialClientState, ProviderDialRole, ProviderDtmfRequest,
    ProviderEventReconciliationOutcome, ProviderEventReconciliationTransaction,
    ProviderExecutionContext, ProviderExecutionError, ProviderExecutionReference,
    ProviderHangupRequest, ProviderKind, ProviderLegExecutor, ProviderStartMediaRequest,
    ProviderTransferCorrelation, ProviderTransferRequest, ReplacementConnectionPromotion,
    ReplacementInitialContextLookup, RuntimeSupervisorHealth, ServiceCommandOutcome,
    ServiceCommandTransaction, ServiceEffectPayload, ServiceEffectResult, SetupPolicy,
    SipInitialContextMode, StoredServiceCall,
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
const HANDOFF_STATUS_SEND_TIMEOUT: Duration = Duration::from_secs(2);
const TERMINAL_RETIRE_QUIET: Duration = Duration::from_secs(1);
const MAX_WORKER_DIRECT_BROADCASTS: usize = 1_000;
const PRIVATE_STAGED_CONTROL_CAPACITY: usize = 32;
const PENDING_PRIVATE_OPERATIONAL_CAPACITY: usize = 16;

#[derive(Clone, Copy)]
struct OutboundProfileFailure {
    code: &'static str,
    message: &'static str,
    retryable: bool,
}

fn outbound_profile_failure(error: OutboundProfileError) -> OutboundProfileFailure {
    match error {
        OutboundProfileError::NotInstalled => OutboundProfileFailure {
            code: "outbound_profile_not_installed",
            message: "the exact named outbound profile revision is not installed",
            retryable: false,
        },
        OutboundProfileError::InvalidSipProfile => OutboundProfileFailure {
            code: "outbound_sip_profile_invalid",
            message: "the named outbound SIP profile is invalid",
            retryable: false,
        },
        OutboundProfileError::InvalidWebRtcProfile => OutboundProfileFailure {
            code: "outbound_webrtc_profile_invalid",
            message: "the named outbound WebRTC profile is invalid",
            retryable: false,
        },
        OutboundProfileError::MaterialUnavailable => OutboundProfileFailure {
            code: "outbound_profile_material_unavailable",
            message: "the named outbound profile material is temporarily unavailable",
            retryable: true,
        },
    }
}

fn apply_sip_outbound_profile(
    resolver: &dyn OutboundProfileResolver,
    route: Option<&super::NamedRouteBinding>,
    context: rvoip_sip::SipOriginateContext,
) -> Result<rvoip_sip::SipOriginateContext, OutboundProfileError> {
    resolver.apply_sip(route, context)
}

fn apply_webrtc_outbound_profile(
    resolver: &dyn OutboundProfileResolver,
    route: Option<&super::NamedRouteBinding>,
    context: WebRtcOriginateContext,
) -> Result<WebRtcOriginateContext, OutboundProfileError> {
    resolver.apply_webrtc(route, context)
}

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
        Self::install_with_provider_executor(
            orchestrator,
            call_runtime,
            Arc::new(DisabledProviderLegExecutor),
            admission_capacity,
            setup_timeout,
        )
        .await
    }

    /// Installs call execution with one explicit native-provider boundary.
    ///
    /// The executor is retained by the supervisor and cloned only into the
    /// exact call actors that own durable effects. The legacy [`Self::install`]
    /// constructor remains fail-closed through [`DisabledProviderLegExecutor`].
    pub async fn install_with_provider_executor(
        orchestrator: Arc<Orchestrator>,
        call_runtime: Arc<CallServiceRuntime>,
        provider_executor: Arc<dyn ProviderLegExecutor>,
        admission_capacity: usize,
        setup_timeout: Duration,
    ) -> Result<Self, CallExecutionError> {
        Self::install_with_leg_executors(
            orchestrator,
            call_runtime,
            provider_executor,
            None,
            admission_capacity,
            setup_timeout,
        )
        .await
    }

    /// Installs call execution with native-provider and Amazon Connect
    /// outbound leg executors. Passing no Amazon adapter preserves the legacy
    /// fail-closed behavior.
    pub async fn install_with_leg_executors(
        orchestrator: Arc<Orchestrator>,
        call_runtime: Arc<CallServiceRuntime>,
        provider_executor: Arc<dyn ProviderLegExecutor>,
        amazon_connect: Option<Arc<AmazonConnectAdapter>>,
        admission_capacity: usize,
        setup_timeout: Duration,
    ) -> Result<Self, CallExecutionError> {
        Self::install_with_leg_executors_and_context_policy(
            orchestrator,
            call_runtime,
            provider_executor,
            amazon_connect,
            Arc::new(ContextPolicy::default()),
            admission_capacity,
            setup_timeout,
        )
        .await
    }

    /// Installs every outbound executor plus the validated context translation
    /// policy used at the authoritative DataMessage boundary.
    #[allow(clippy::too_many_arguments)]
    pub async fn install_with_leg_executors_and_context_policy(
        orchestrator: Arc<Orchestrator>,
        call_runtime: Arc<CallServiceRuntime>,
        provider_executor: Arc<dyn ProviderLegExecutor>,
        amazon_connect: Option<Arc<AmazonConnectAdapter>>,
        context_policy: Arc<ContextPolicy>,
        admission_capacity: usize,
        setup_timeout: Duration,
    ) -> Result<Self, CallExecutionError> {
        Self::install_with_leg_executors_context_and_canary_policy(
            orchestrator,
            call_runtime,
            provider_executor,
            amazon_connect,
            context_policy,
            None,
            admission_capacity,
            setup_timeout,
        )
        .await
    }

    /// Installs every executor plus the optional protected StandardCharter
    /// canary. Existing constructors always pass `None`, preserving the
    /// frozen listener and attachment-token behavior exactly.
    #[allow(clippy::too_many_arguments)]
    pub async fn install_with_leg_executors_context_and_canary_policy(
        orchestrator: Arc<Orchestrator>,
        call_runtime: Arc<CallServiceRuntime>,
        provider_executor: Arc<dyn ProviderLegExecutor>,
        amazon_connect: Option<Arc<AmazonConnectAdapter>>,
        context_policy: Arc<ContextPolicy>,
        standardcharter_canary: Option<Arc<StandardCharterCanaryPolicy>>,
        admission_capacity: usize,
        setup_timeout: Duration,
    ) -> Result<Self, CallExecutionError> {
        Self::install_with_leg_executors_context_canary_and_broadcast_authority(
            orchestrator,
            call_runtime,
            provider_executor,
            amazon_connect,
            context_policy,
            standardcharter_canary,
            None,
            admission_capacity,
            setup_timeout,
        )
        .await
    }

    /// Worker-mode constructor that classifies exact private broadcast
    /// subscribers before the ordinary QUIC attachment proof. All existing
    /// constructors retain their prior behavior by passing no authority.
    #[allow(clippy::too_many_arguments)]
    pub async fn install_with_leg_executors_context_canary_and_broadcast_authority(
        orchestrator: Arc<Orchestrator>,
        call_runtime: Arc<CallServiceRuntime>,
        provider_executor: Arc<dyn ProviderLegExecutor>,
        amazon_connect: Option<Arc<AmazonConnectAdapter>>,
        context_policy: Arc<ContextPolicy>,
        standardcharter_canary: Option<Arc<StandardCharterCanaryPolicy>>,
        broadcast_authority: Option<Arc<WorkerBroadcastSubscriptionAuthority>>,
        admission_capacity: usize,
        setup_timeout: Duration,
    ) -> Result<Self, CallExecutionError> {
        Self::install_with_leg_executors_context_canary_broadcast_and_outbound_profiles(
            orchestrator,
            call_runtime,
            provider_executor,
            amazon_connect,
            context_policy,
            standardcharter_canary,
            broadcast_authority,
            Arc::new(DisabledOutboundProfileResolver),
            admission_capacity,
            setup_timeout,
        )
        .await
    }

    /// Most-specific worker constructor, including execution-time resolution
    /// of named outbound signaling profiles. Every less-specific constructor
    /// installs [`DisabledOutboundProfileResolver`] so historical advanced
    /// calls remain compatible while named routes fail closed unless their
    /// exact profile revision is installed in this process.
    #[allow(clippy::too_many_arguments)]
    pub async fn install_with_leg_executors_context_canary_broadcast_and_outbound_profiles(
        orchestrator: Arc<Orchestrator>,
        call_runtime: Arc<CallServiceRuntime>,
        provider_executor: Arc<dyn ProviderLegExecutor>,
        amazon_connect: Option<Arc<AmazonConnectAdapter>>,
        context_policy: Arc<ContextPolicy>,
        standardcharter_canary: Option<Arc<StandardCharterCanaryPolicy>>,
        broadcast_authority: Option<Arc<WorkerBroadcastSubscriptionAuthority>>,
        outbound_profiles: Arc<dyn OutboundProfileResolver>,
        admission_capacity: usize,
        setup_timeout: Duration,
    ) -> Result<Self, CallExecutionError> {
        Self::install_with_leg_executors_context_canary_broadcast_profiles_and_private_egress(
            orchestrator,
            call_runtime,
            provider_executor,
            amazon_connect,
            context_policy,
            standardcharter_canary,
            broadcast_authority,
            outbound_profiles,
            None,
            admission_capacity,
            setup_timeout,
        )
        .await
    }

    /// Split-worker constructor that additionally owns the authenticated
    /// gateway egress command client and exact destination-stream admission
    /// registry. The ordinary constructors pass `None` and retain the local
    /// all-in-one adapter behavior.
    #[allow(clippy::too_many_arguments)]
    pub async fn install_with_leg_executors_context_canary_broadcast_profiles_and_private_egress(
        orchestrator: Arc<Orchestrator>,
        call_runtime: Arc<CallServiceRuntime>,
        provider_executor: Arc<dyn ProviderLegExecutor>,
        amazon_connect: Option<Arc<AmazonConnectAdapter>>,
        context_policy: Arc<ContextPolicy>,
        standardcharter_canary: Option<Arc<StandardCharterCanaryPolicy>>,
        broadcast_authority: Option<Arc<WorkerBroadcastSubscriptionAuthority>>,
        outbound_profiles: Arc<dyn OutboundProfileResolver>,
        private_egress: Option<Arc<PrivateEgressWorkerRuntime>>,
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
        context_policy
            .validate()
            .map_err(|_| CallExecutionError::InvalidConfiguration("context policy is invalid"))?;
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
            Arc::clone(&provider_executor),
            amazon_connect.clone(),
            Arc::clone(&context_policy),
            Arc::clone(&outbound_profiles),
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
            provider_executor,
            amazon_connect,
            context_policy,
            standardcharter_canary,
            broadcast_authority,
            outbound_profiles,
            private_egress,
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

// Recovery owns a deliberately explicit dependency boundary; grouping these
// process-lifetime authorities would obscure which component failed startup.
#[allow(clippy::too_many_arguments)]
async fn recover_before_listeners_with_health(
    orchestrator: Arc<Orchestrator>,
    runtime: Arc<CallServiceRuntime>,
    provider_executor: Arc<dyn ProviderLegExecutor>,
    amazon_connect: Option<Arc<AmazonConnectAdapter>>,
    context_policy: Arc<ContextPolicy>,
    outbound_profiles: Arc<dyn OutboundProfileResolver>,
    setup_timeout: Duration,
    runtime_health: &mut watch::Receiver<RuntimeSupervisorHealth>,
) -> Result<(), CallExecutionError> {
    let recovery = tokio::time::timeout(
        setup_timeout,
        recover_before_listeners(
            orchestrator,
            runtime,
            provider_executor,
            amazon_connect,
            context_policy,
            outbound_profiles,
        ),
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
    provider_executor: Arc<dyn ProviderLegExecutor>,
    amazon_connect: Option<Arc<AmazonConnectAdapter>>,
    context_policy: Arc<ContextPolicy>,
    outbound_profiles: Arc<dyn OutboundProfileResolver>,
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
            // Keep the complete effect executor behind the same heap boundary
            // used by live actors. Cancellation-aware StartLeg branches make
            // this future intentionally broad; materializing it in the
            // startup-recovery stack can overflow the default libtest thread.
            let outcome = Box::pin(execute_actor_work(
                item,
                ActorWorkExecutionContext {
                    orchestrator: Arc::clone(&orchestrator),
                    runtime: Arc::clone(&runtime),
                    provider_executor: Arc::clone(&provider_executor),
                    amazon_connect: amazon_connect.clone(),
                    context_policy: Arc::clone(&context_policy),
                    outbound_profiles: Arc::clone(&outbound_profiles),
                    private_egress: None,
                    bindings: HashMap::new(),
                    pending_inbound_authorities: HashMap::new(),
                    pending_replacement_bindings: HashMap::new(),
                    replaced_bindings: HashMap::new(),
                    bridge_id: None,
                    session_id: None,
                    outbound_registration: None,
                    setup_cancel: CancellationToken::new(),
                    shutdown: shutdown.clone(),
                },
            ))
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
    staged_private_egress: Option<PrivateEgressStagedControl>,
    signaling_metadata: Vec<(String, String)>,
    termination_watch_cancel: CancellationToken,
}

struct PendingAdmissionTermination {
    binding: ConnectionBinding,
    reason: SourceBeforeAnswerTermination,
}

struct ProvenWorkerBroadcastAdmission {
    admission: InboundAdmission,
    request: WorkerBroadcastAdmissionRequest,
    tenant: RvoipTenantId,
    authority_guard: WorkerBroadcastAuthorityGuard,
}

struct ProvenPrivateEgressAdmission {
    admission: InboundAdmission,
    descriptor: PrivateEgressStreamAdmission,
}

struct WorkerBroadcastAuthorityGuard {
    authority: Arc<WorkerBroadcastSubscriptionAuthority>,
    request: WorkerBroadcastAdmissionRequest,
    armed: bool,
}

impl WorkerBroadcastAuthorityGuard {
    fn new(
        authority: Arc<WorkerBroadcastSubscriptionAuthority>,
        request: WorkerBroadcastAdmissionRequest,
    ) -> Self {
        Self {
            authority,
            request,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for WorkerBroadcastAuthorityGuard {
    fn drop(&mut self) {
        if self.armed {
            self.authority.unbind_listener(
                &self.request.broadcast_id().to_string(),
                self.request.listener_id(),
            );
        }
    }
}

enum AdmissionProof {
    Call(Box<ProvenAdmission>),
    WorkerBroadcast(ProvenWorkerBroadcastAdmission),
    PrivateEgress(ProvenPrivateEgressAdmission),
}

struct AdmissionProofResult {
    connection_id: ConnectionId,
    proven: Option<AdmissionProof>,
    panicked: bool,
}

struct WorkerBroadcastSlot {
    operational: mpsc::Sender<OperationalEvent>,
}

struct WorkerBroadcastExit {
    connection_id: ConnectionId,
    panicked: bool,
}

#[derive(Default)]
struct WorkerBroadcastOwnedResources {
    conversation: Option<ConversationId>,
    session: Option<SessionId>,
    permit: Option<OwnedSemaphorePermit>,
}

struct WorkerBroadcastResources {
    connection_id: ConnectionId,
    request: WorkerBroadcastAdmissionRequest,
    orchestrator: Arc<Orchestrator>,
    authority: Arc<WorkerBroadcastSubscriptionAuthority>,
    owned: Mutex<WorkerBroadcastOwnedResources>,
    cleaned: AtomicBool,
}

impl WorkerBroadcastResources {
    fn new(
        connection_id: ConnectionId,
        request: WorkerBroadcastAdmissionRequest,
        orchestrator: Arc<Orchestrator>,
        authority: Arc<WorkerBroadcastSubscriptionAuthority>,
        permit: OwnedSemaphorePermit,
    ) -> Arc<Self> {
        Arc::new(Self {
            connection_id,
            request,
            orchestrator,
            authority,
            owned: Mutex::new(WorkerBroadcastOwnedResources {
                permit: Some(permit),
                ..WorkerBroadcastOwnedResources::default()
            }),
            cleaned: AtomicBool::new(false),
        })
    }

    async fn set_conversation(&self, conversation: ConversationId) {
        self.owned.lock().await.conversation = Some(conversation);
    }

    async fn set_session(&self, session: SessionId) {
        self.owned.lock().await.session = Some(session);
    }

    async fn cleanup(&self, failed: bool) {
        if self.cleaned.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
            self.authority.unbind_listener(
                &self.request.broadcast_id().to_string(),
                self.request.listener_id(),
            );
        }));
        let WorkerBroadcastOwnedResources {
            conversation,
            session,
            permit,
        } = std::mem::take(&mut *self.owned.lock().await);
        let reason = if failed {
            EndReason::Failed {
                detail: "private broadcast admission lifecycle failed".into(),
            }
        } else {
            EndReason::Normal
        };
        // Accept can become peer-visible before its future reports success.
        // End the exact adapter route unconditionally so an ambiguous timeout
        // still produces peer-visible SessionEnd and releases transport state.
        let _ = tokio::time::timeout(
            AUTHORITY_TEARDOWN_TIMEOUT,
            AssertUnwindSafe(
                self.orchestrator
                    .end_connection(self.connection_id.clone(), reason.clone()),
            )
            .catch_unwind(),
        )
        .await;
        if let Some(session) = session {
            let _ = tokio::time::timeout(
                AUTHORITY_TEARDOWN_TIMEOUT,
                AssertUnwindSafe(self.orchestrator.end_session(session, reason)).catch_unwind(),
            )
            .await;
        }
        if let Some(conversation) = conversation {
            let _ = tokio::time::timeout(
                AUTHORITY_TEARDOWN_TIMEOUT,
                AssertUnwindSafe(self.orchestrator.close_conversation(conversation, true))
                    .catch_unwind(),
            )
            .await;
        }
        drop(permit);
    }
}

#[derive(Clone)]
struct ConnectionOwner {
    call_id: CallId,
    leg_id: LegId,
}

/// Provisional ownership for a private destination connection.  This is
/// installed from the authenticated stream descriptor before the adapter is
/// accepted, but it deliberately is not durable/active connection ownership
/// until the call actor has installed the matching binding.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingConnectionAuthority {
    connection_id: ConnectionId,
    admission_id: Uuid,
    worker: crate::call_engine::WorkerLease,
    source: PrivateEgressSource,
    target: PrivateEgressTarget,
}

impl PendingConnectionAuthority {
    fn from_admission(
        connection_id: ConnectionId,
        descriptor: &PrivateEgressStreamAdmission,
    ) -> Self {
        Self {
            connection_id,
            admission_id: descriptor.admission_id,
            worker: descriptor.worker,
            source: descriptor.source.clone(),
            target: descriptor.target,
        }
    }

    fn from_binding(binding: &ActorBinding) -> Option<Self> {
        let private = binding.private_egress.as_ref()?;
        Some(Self {
            connection_id: binding.connection_id.clone(),
            admission_id: private.admission_id,
            worker: private.worker,
            source: private.source.clone(),
            target: private.target,
        })
    }

    fn matches_binding(&self, call_id: CallId, binding: &ActorBinding) -> bool {
        self.matches_target(call_id, binding.leg_id, binding.binding_generation)
            && Self::from_binding(binding).as_ref() == Some(self)
    }

    fn matches_target(
        &self,
        call_id: CallId,
        leg_id: LegId,
        binding_generation: crate::call_engine::BindingGeneration,
    ) -> bool {
        self.source.call_id == call_id
            && self.target.leg_id == leg_id
            && self.target.binding_generation == binding_generation
    }
}

struct PendingConnectionOwner {
    authority: PendingConnectionAuthority,
    runtime: Option<Arc<PrivateEgressWorkerRuntime>>,
    release_on_drop: bool,
    deadline: tokio::time::Instant,
    last_sequence: Option<u64>,
    staged: VecDeque<OperationalEvent>,
    promotion_started: bool,
    allow_parallel_generation: bool,
}

impl Drop for PendingConnectionOwner {
    fn drop(&mut self) {
        if self.release_on_drop {
            if let Some(runtime) = &self.runtime {
                runtime.admissions().release(self.authority.admission_id);
            }
        }
    }
}

enum PendingConnectionOwnerUpdate {
    Release(PendingConnectionAuthority),
    Installed {
        authority: PendingConnectionAuthority,
        staged: oneshot::Sender<Result<VecDeque<OperationalEvent>, ()>>,
    },
}

struct ActorSlot {
    commands: mpsc::Sender<ActorCommand>,
    operational: mpsc::Sender<OperationalEvent>,
    work: mpsc::Sender<ActorWork>,
    retiring: Arc<AtomicBool>,
}

enum ActorCommand {
    // Admission proof carries the complete inbound transport context and is
    // intentionally much larger than outbound registration. Keep mailbox
    // commands uniformly small so bursts do not multiply that payload by the
    // bounded channel capacity.
    Admit(Box<ProvenAdmission>),
    AdmitPrivateEgress(ProvenPrivateEgressAdmission),
    PrivateEgressLifecycle(PrivateEgressLifecycleDelivery),
    RegisterOutbound {
        binding: ActorBinding,
        replacement_effect_id: Option<crate::call_engine::EffectId>,
        complete_on_transport_connected: bool,
        created_session: Option<(ConversationId, SessionId)>,
        pending_authority: Option<PendingConnectionAuthority>,
        completion: oneshot::Sender<Result<(), ()>>,
    },
}

struct OutboundRegistration {
    call_id: CallId,
    binding: ActorBinding,
    allow_parallel_generation: bool,
    replacement_effect_id: Option<crate::call_engine::EffectId>,
    complete_on_transport_connected: bool,
    created_session: Option<(ConversationId, SessionId)>,
    completion: oneshot::Sender<Result<(), ()>>,
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
    private_egress: Option<PrivateEgressBinding>,
}

/// Exact pending source authority derived only from a consumed, single-use
/// attachment proof that is still owned by this call actor. It lets a split
/// destination prepare while attach-then-dial deliberately withholds the
/// source's final signaling answer.
#[derive(Clone)]
struct PendingInboundAuthority {
    tenant_id: crate::call_engine::TenantId,
    call_id: CallId,
    binding: ConnectionBinding,
    staged_private_egress: Option<PrivateEgressStagedControl>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PendingInboundAuthorityKey {
    leg_id: LegId,
    binding_generation: crate::call_engine::BindingGeneration,
    connection_id: ConnectionId,
}

impl PendingInboundAuthorityKey {
    fn from_binding(binding: &ConnectionBinding) -> Self {
        Self {
            leg_id: binding.leg_id,
            binding_generation: binding.binding_generation,
            connection_id: binding.connection_id.clone(),
        }
    }

    fn from_source(source: &PrivateEgressSource, connection_id: &ConnectionId) -> Self {
        Self {
            leg_id: source.leg_id,
            binding_generation: source.binding_generation,
            connection_id: connection_id.clone(),
        }
    }
}

#[derive(Clone)]
struct PrivateEgressBinding {
    admission_id: Uuid,
    worker: crate::call_engine::WorkerLease,
    source_connection: ConnectionId,
    source: PrivateEgressSource,
    target: PrivateEgressTarget,
    _connection: PrivateEgressWorkerConnection,
}

fn private_lifecycle_route_authority_matches(
    binding_leg_id: LegId,
    binding_generation: crate::call_engine::BindingGeneration,
    route_source_connection: &ConnectionId,
    route_source: &PrivateEgressSource,
    route_target: PrivateEgressTarget,
    delivery: &PrivateEgressLifecycleDelivery,
) -> bool {
    binding_leg_id == delivery.event.target.leg_id
        && binding_generation == delivery.event.target.binding_generation
        && route_source_connection == &delivery.source_connection
        && route_source == &delivery.event.source
        && route_target == delivery.event.target
}

#[derive(Clone)]
struct PendingReplacementBinding {
    binding: ActorBinding,
    effect_id: crate::call_engine::EffectId,
    complete_on_transport_connected: bool,
}

struct AdmissionOperationResult {
    binding: ConnectionBinding,
    connection_id: ConnectionId,
    conversation_id: Option<ConversationId>,
    session_id: Option<SessionId>,
    source_termination: Option<SourceBeforeAnswerTermination>,
    result: Result<(), rvoip_core::RvoipError>,
}

struct PrivateEgressAdmissionResult {
    authority: PendingConnectionAuthority,
    result: Result<(), &'static str>,
}

struct WorkOperationResult {
    effect_id: Option<crate::call_engine::EffectId>,
    bridge_update: Option<Option<BridgeId>>,
    handoff_signal: Option<HandoffWorkSignal>,
    result: Result<(), RepositoryError>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HandoffWorkSignal {
    replacement_leg_id: LegId,
    binding_generation: crate::call_engine::BindingGeneration,
    status: HandoffStatusKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveHandoffAttempt {
    replacement_leg_id: LegId,
    previous_binding_generation: crate::call_engine::BindingGeneration,
    pending_binding_generation: crate::call_engine::BindingGeneration,
    last_status: Option<HandoffStatusKind>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AttachThenDialLegs {
    ingress: LegId,
    destination: LegId,
}

fn direct_browser_leg_id(plan: &CallExecutionPlan, replacement_leg_id: LegId) -> Option<LegId> {
    plan.legs
        .iter()
        .filter(|spec| spec.leg_id != replacement_leg_id)
        .filter(|spec| matches!(spec.endpoint, super::LegEndpointConfig::WebRtc(_)))
        .filter(|spec| plan.leg_signaling_initiator(spec.leg_id) == Ok(SignalingInitiator::Remote))
        .map(|spec| spec.leg_id)
        .next()
}

async fn send_handoff_status_message(
    orchestrator: &Arc<Orchestrator>,
    browser_connection_id: ConnectionId,
    call_id: CallId,
    replacement_leg_id: LegId,
    binding_generation: crate::call_engine::BindingGeneration,
    status: HandoffStatusKind,
) {
    let Ok(message) = HandoffStatusEnvelope::new(
        call_id,
        replacement_leg_id,
        binding_generation,
        status,
        None,
    )
    .to_data_message() else {
        return;
    };
    let delivered = tokio::time::timeout(
        HANDOFF_STATUS_SEND_TIMEOUT,
        orchestrator.send_data_message(browser_connection_id, message),
    )
    .await
    .is_ok_and(|result| result.is_ok());
    metrics::counter!(
        "bridgefu_handoff_status_total",
        "status" => handoff_status_label(status),
        "result" => if delivered { "delivered" } else { "dropped" }
    )
    .increment(1);
}

/// Emit local ringback only after an outbound signaling implementation has
/// accepted the dial/prepare operation for this exact replacement generation.
/// Provider webhooks are deliberately not echoed as handoff status: they can
/// arrive after attachment or promotion and would otherwise regress the
/// browser's monotonic state machine.
async fn send_replacement_ringing(
    orchestrator: &Arc<Orchestrator>,
    stored: &StoredServiceCall,
    replacement_leg_id: LegId,
    binding_generation: crate::call_engine::BindingGeneration,
) {
    let Some(browser_leg_id) = direct_browser_leg_id(&stored.plan, replacement_leg_id) else {
        return;
    };
    if !stored
        .call
        .aggregate
        .leg(browser_leg_id)
        .is_some_and(|leg| matches!(leg.state(), LegState::Connected | LegState::Held))
    {
        return;
    }
    let Some(browser) = stored.call.bindings.get(&browser_leg_id) else {
        return;
    };
    send_handoff_status_message(
        orchestrator,
        browser.connection_id.clone(),
        stored.call.aggregate.id(),
        replacement_leg_id,
        binding_generation,
        HandoffStatusKind::Ringing,
    )
    .await;
}

const fn handoff_status_label(status: HandoffStatusKind) -> &'static str {
    match status {
        HandoffStatusKind::Preparing => "preparing",
        HandoffStatusKind::Ringing => "ringing",
        HandoffStatusKind::Attaching => "attaching",
        HandoffStatusKind::Connected => "connected",
        HandoffStatusKind::Resumed => "resumed",
        HandoffStatusKind::Failed => "failed",
        HandoffStatusKind::Ended => "ended",
    }
}

const fn handoff_status_can_follow(
    previous: Option<HandoffStatusKind>,
    next: HandoffStatusKind,
) -> bool {
    match previous {
        None => matches!(next, HandoffStatusKind::Preparing),
        Some(HandoffStatusKind::Preparing) => matches!(
            next,
            HandoffStatusKind::Ringing
                | HandoffStatusKind::Attaching
                | HandoffStatusKind::Connected
                | HandoffStatusKind::Resumed
                | HandoffStatusKind::Failed
                | HandoffStatusKind::Ended
        ),
        Some(HandoffStatusKind::Ringing) => matches!(
            next,
            HandoffStatusKind::Attaching
                | HandoffStatusKind::Connected
                | HandoffStatusKind::Resumed
                | HandoffStatusKind::Failed
                | HandoffStatusKind::Ended
        ),
        Some(HandoffStatusKind::Attaching) => matches!(
            next,
            HandoffStatusKind::Connected
                | HandoffStatusKind::Resumed
                | HandoffStatusKind::Failed
                | HandoffStatusKind::Ended
        ),
        Some(
            HandoffStatusKind::Connected
            | HandoffStatusKind::Resumed
            | HandoffStatusKind::Failed
            | HandoffStatusKind::Ended,
        ) => false,
    }
}

struct CallActor {
    call_id: CallId,
    tenant_id: crate::call_engine::TenantId,
    plan: CallExecutionPlan,
    orchestrator: Arc<Orchestrator>,
    runtime: Arc<CallServiceRuntime>,
    provider_executor: Arc<dyn ProviderLegExecutor>,
    amazon_connect: Option<Arc<AmazonConnectAdapter>>,
    context_policy: Arc<ContextPolicy>,
    outbound_profiles: Arc<dyn OutboundProfileResolver>,
    private_egress: Option<Arc<PrivateEgressWorkerRuntime>>,
    outbound_registration: mpsc::Sender<OutboundRegistration>,
    pending_owner_updates: mpsc::UnboundedSender<PendingConnectionOwnerUpdate>,
    commands: mpsc::Receiver<ActorCommand>,
    operational: mpsc::Receiver<OperationalEvent>,
    work: mpsc::Receiver<ActorWork>,
    drain: watch::Receiver<bool>,
    shutdown: watch::Receiver<ActorShutdown>,
    setup_cancel: CancellationToken,
    bindings: HashMap<LegId, ActorBinding>,
    pending_replacement_bindings: HashMap<LegId, PendingReplacementBinding>,
    replaced_bindings: HashMap<(LegId, crate::call_engine::BindingGeneration), ActorBinding>,
    active_handoff_attempt: Option<ActiveHandoffAttempt>,
    pending_initial_data_messages: HashMap<LegId, rvoip_core::DataMessage>,
    pending_admissions: VecDeque<ProvenAdmission>,
    pending_admission_terminations: JoinSet<Option<PendingAdmissionTermination>>,
    pending_inbound_authorities: HashMap<PendingInboundAuthorityKey, PendingInboundAuthority>,
    admission_operation: JoinSet<AdmissionOperationResult>,
    private_admission_operation: JoinSet<PrivateEgressAdmissionResult>,
    pending_private_lifecycle: HashMap<PrivateEgressTarget, PrivateEgressLifecycleDelivery>,
    pending_work: VecDeque<ActorWork>,
    work_operation: JoinSet<WorkOperationResult>,
    attach_then_dial: Option<AttachThenDialLegs>,
    provisional_early_media_attempted: bool,
    provisional_early_media_route: Option<ProvisionalMediaRoute>,
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
    provider_executor: Arc<dyn ProviderLegExecutor>,
    amazon_connect: Option<Arc<AmazonConnectAdapter>>,
    context_policy: Arc<ContextPolicy>,
    standardcharter_canary: Option<Arc<StandardCharterCanaryPolicy>>,
    broadcast_authority: Option<Arc<WorkerBroadcastSubscriptionAuthority>>,
    outbound_profiles: Arc<dyn OutboundProfileResolver>,
    private_egress: Option<Arc<PrivateEgressWorkerRuntime>>,
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
    let mut worker_broadcasts = JoinSet::<WorkerBroadcastExit>::new();
    let mut work_claims = JoinSet::<WorkClaimBatch>::new();
    let mut actor_slots = HashMap::<CallId, ActorSlot>::new();
    let mut connection_owners = HashMap::<ConnectionId, ConnectionOwner>::new();
    let mut pending_connection_owners = HashMap::<ConnectionId, PendingConnectionOwner>::new();
    let mut worker_broadcast_slots = HashMap::<ConnectionId, WorkerBroadcastSlot>::new();
    let mut leg_owners = HashMap::<(CallId, LegId), ConnectionId>::new();
    let (outbound_registration, mut outbound_registrations) =
        mpsc::channel::<OutboundRegistration>(admission_capacity);
    let (pending_owner_updates, mut pending_owner_update_rx) =
        mpsc::unbounded_channel::<PendingConnectionOwnerUpdate>();
    let mut work_wakeups = runtime.subscribe_work_wakeups();
    let mut private_lifecycle = private_egress
        .as_ref()
        .map(|runtime| runtime.control().subscribe_lifecycle());
    let initial_runtime_health = *runtime_health.borrow();
    let (actor_shutdown, actor_shutdown_rx) = watch::channel(ActorShutdown::Running);
    let worker_broadcast_capacity = Arc::new(Semaphore::new(
        orchestrator
            .direct_listener_limit()
            .min(MAX_WORKER_DIRECT_BROADCASTS),
    ));
    let mut work_poll = tokio::time::interval(WORK_POLL_INTERVAL);
    work_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pending_owner_sweep = tokio::time::interval(Duration::from_millis(100));
    pending_owner_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut accepting_admission = true;
    let mut accepting_work = true;
    let mut lease_lost = false;
    let mut stopping = false;
    let mut pending_operational = VecDeque::new();
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
            &mut pending_connection_owners,
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
            && pending_operational.is_empty()
            && operational.is_empty()
            && outbound_registrations.is_empty()
            && pending_owner_update_rx.is_empty()
            && pending_connection_owners.is_empty()
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
                        &mut pending_connection_owners,
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
                        &mut pending_connection_owners,
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
                        let abandoned = take_pending_connections_for_call(
                            &mut pending_connection_owners,
                            exit.call_id,
                        );
                        leg_owners.retain(|(call_id, _), _| *call_id != exit.call_id);
                        bounded_end_connections(
                            &orchestrator,
                            abandoned,
                            "pending private egress owner exited",
                        ).await;
                    }
                    Some(Err(error)) => {
                        tracing::error!(%error, "call actor panicked");
                    }
                    None => {}
                }
            }
            result = worker_broadcasts.join_next(), if !worker_broadcasts.is_empty() => {
                match result {
                    Some(Ok(exit)) => {
                        if exit.panicked {
                            tracing::error!(connection_id = %exit.connection_id, "private broadcast lifecycle task panicked");
                        }
                        worker_broadcast_slots.remove(&exit.connection_id);
                    }
                    Some(Err(error)) => tracing::error!(%error, "private broadcast lifecycle task failed"),
                    None => {}
                }
            }
            registration = outbound_registrations.recv() => {
                if let Some(registration) = registration {
                    if let Some(connection_id) = register_outbound_connection(
                        registration,
                        &actor_slots,
                        &mut connection_owners,
                        &mut pending_connection_owners,
                        &mut leg_owners,
                    ) {
                        bounded_end_connections(
                            &orchestrator,
                            vec![connection_id],
                            "private egress promotion failed",
                        ).await;
                    }
                }
            }
            // Promotion is ordered only against events for this exact pending
            // destination. Requiring the global operational queue to empty can
            // deadlock: the actor waits for this acknowledgement while an
            // unrelated source event waits for space in that actor's mailbox.
            // Absorb every already-received exact-destination event into its
            // bounded pending FIFO before publishing installed ownership.
            update = pending_owner_update_rx.recv() => {
                if let Some(update) = update {
                    if let PendingConnectionOwnerUpdate::Installed { authority, .. } = &update {
                        absorb_pending_owner_operational(
                            authority,
                            &mut operational,
                            &mut pending_operational,
                            &orchestrator,
                            &actor_slots,
                            &connection_owners,
                            &mut pending_connection_owners,
                            &worker_broadcast_slots,
                            private_egress.as_ref(),
                        ).await;
                    }
                    if let Some(connection_id) = apply_pending_owner_update(
                        update,
                        &actor_slots,
                        &mut connection_owners,
                        &mut pending_connection_owners,
                        &mut leg_owners,
                    ) {
                        bounded_end_connections(
                            &orchestrator,
                            vec![connection_id],
                            "pending private egress authority released",
                        ).await;
                    }
                }
            }
            _ = pending_owner_sweep.tick(), if !pending_connection_owners.is_empty() => {
                let expired = take_expired_pending_connections(
                    &mut pending_connection_owners,
                    tokio::time::Instant::now(),
                );
                bounded_end_connections(
                    &orchestrator,
                    expired,
                    "pending private egress authority expired",
                ).await;
            }
            delivery = async {
                match private_lifecycle.as_mut() {
                    Some(events) => events.recv().await.ok(),
                    None => std::future::pending().await,
                }
            } => {
                if let Some(delivery) = delivery {
                    route_private_egress_lifecycle(delivery, &actor_slots, &connection_owners);
                }
            }
            result = proof_tasks.join_next(), if !proof_tasks.is_empty() => {
                match result {
                    Some(Ok(result)) => {
                        if result.panicked {
                            tracing::error!(connection_id = %result.connection_id, "attachment proof task panicked");
                        }
                        if let Some(proven) = result.proven {
                            match proven {
                                AdmissionProof::Call(proven) if !accepting_admission => {
                                    fail_unowned_proven_admission(
                                        *proven,
                                        &orchestrator,
                                        &runtime,
                                        !lease_lost,
                                    ).await;
                                }
                                AdmissionProof::Call(proven) => {
                                    register_proven_admission(
                                        *proven,
                                        &orchestrator,
                                        &runtime,
                                        &provider_executor,
                                        &amazon_connect,
                                        &context_policy,
                                        &outbound_profiles,
                                        &private_egress,
                                        &outbound_registration,
                                        &mut actor_slots,
                                        &mut connection_owners,
                                        &pending_owner_updates,
                                        &mut leg_owners,
                                        &mut actors,
                                        actor_task_capacity,
                                        drain.clone(),
                                        actor_shutdown_rx.clone(),
                                    ).await;
                                }
                                AdmissionProof::WorkerBroadcast(proven) if !accepting_admission => {
                                    reject_worker_broadcast_admission(
                                        proven,
                                        broadcast_authority.as_ref(),
                                        RejectReason::ServerError,
                                    ).await;
                                }
                                AdmissionProof::WorkerBroadcast(proven) => {
                                    register_worker_broadcast_admission(
                                        proven,
                                        &orchestrator,
                                        broadcast_authority.as_ref(),
                                        &worker_broadcast_capacity,
                                        &mut worker_broadcast_slots,
                                        &mut worker_broadcasts,
                                        setup_timeout,
                                        actor_shutdown_rx.clone(),
                                    ).await;
                                }
                                AdmissionProof::PrivateEgress(proven) if !accepting_admission => {
                                    reject_private_egress_admission(
                                        proven,
                                        private_egress.as_ref(),
                                        RejectReason::ServerError,
                                    ).await;
                                }
                                AdmissionProof::PrivateEgress(proven) => {
                                    register_private_egress_admission(
                                        proven,
                                        private_egress.as_ref(),
                                        &actor_slots,
                                        &connection_owners,
                                        &mut pending_connection_owners,
                                        admission_capacity,
                                        setup_timeout,
                                    ).await;
                                }
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
            _ = tokio::time::sleep(Duration::from_millis(1)), if !pending_operational.is_empty() => {
                let event = pending_operational
                    .pop_front()
                    .expect("guarded operational event");
                if let Some(event) = try_route_operational_event(
                    event,
                    &orchestrator,
                    &actor_slots,
                    &connection_owners,
                    &mut pending_connection_owners,
                    &worker_broadcast_slots,
                ).await {
                    pending_operational.push_front(event);
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(1)), if !pending_work.is_empty() && !lease_lost => {
                let item = pending_work.pop_front().expect("guarded claimed work");
                if let Some(item) = route_claimed_work(
                    item,
                    &orchestrator,
                    &runtime,
                    &provider_executor,
                    &amazon_connect,
                    &context_policy,
                    &outbound_profiles,
                    &private_egress,
                    &outbound_registration,
                    &mut actor_slots,
                    &mut connection_owners,
                    &pending_owner_updates,
                    &mut leg_owners,
                    &mut actors,
                    actor_task_capacity,
                    drain.clone(),
                    actor_shutdown_rx.clone(),
                ).await {
                    pending_work.push_back(item);
                }
            }
            event = operational.recv(), if pending_operational.is_empty() => {
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
                        &mut pending_connection_owners,
                        &mut leg_owners,
                        &mut pending_work,
                        &actor_shutdown,
                        &orchestrator,
                    ).await;
                    break;
                };
                if private_egress
                    .as_ref()
                    .is_none_or(|runtime| !runtime.control().handle_operational_event(&event))
                {
                    if let Some(event) = try_route_operational_event(
                        event,
                        &orchestrator,
                        &actor_slots,
                        &connection_owners,
                        &mut pending_connection_owners,
                        &worker_broadcast_slots,
                    ).await {
                        pending_operational.push_back(event);
                    }
                }
            }
            admission = admissions.recv(), if accepting_admission && proof_tasks.len() < admission_capacity => {
                let Some(admission) = admission else {
                    accepting_admission = false;
                    accepting_work = false;
                    continue;
                };
                let runtime = Arc::clone(&runtime);
                let standardcharter_canary = standardcharter_canary.clone();
                let broadcast_authority = broadcast_authority.clone();
                let private_egress = private_egress.clone();
                let connection_id = admission.connection_id().clone();
                inflight_admissions.insert(connection_id.clone());
                proof_tasks.spawn(async move {
                    match AssertUnwindSafe(Box::pin(prove_admission(
                        admission,
                        runtime,
                        standardcharter_canary,
                        broadcast_authority,
                        private_egress,
                        setup_timeout,
                    )))
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
                match proven {
                    AdmissionProof::Call(proven) => {
                        fail_unowned_proven_admission(
                            *proven,
                            &orchestrator,
                            &runtime,
                            !lease_lost,
                        )
                        .await;
                    }
                    AdmissionProof::WorkerBroadcast(proven) => {
                        reject_worker_broadcast_admission(
                            proven,
                            broadcast_authority.as_ref(),
                            RejectReason::ServerError,
                        )
                        .await;
                    }
                    AdmissionProof::PrivateEgress(proven) => {
                        reject_private_egress_admission(
                            proven,
                            private_egress.as_ref(),
                            RejectReason::ServerError,
                        )
                        .await;
                    }
                }
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
    let abandoned_pending = pending_connection_owners
        .drain()
        .map(|(connection_id, _)| connection_id)
        .collect();
    bounded_end_connections(
        &orchestrator,
        abandoned_pending,
        "execution supervisor stopped with pending private egress",
    )
    .await;
    actor_slots.clear();
    worker_broadcast_slots.clear();
    while let Some(result) = actors.join_next().await {
        if let Err(error) = result {
            tracing::warn!(%error, "call actor panicked while draining");
        }
    }
    while let Some(result) = worker_broadcasts.join_next().await {
        if let Err(error) = result {
            tracing::warn!(%error, "private broadcast lifecycle failed while draining");
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
    pending_connection_owners: &mut HashMap<ConnectionId, PendingConnectionOwner>,
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

    let owned_connections = take_authority_loss_connections(
        connection_owners,
        pending_connection_owners,
        inflight_admissions,
    );
    actor_slots.clear();
    connection_owners.clear();
    pending_connection_owners.clear();
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
    pending_connection_owners: &HashMap<ConnectionId, PendingConnectionOwner>,
    inflight_admissions: &mut HashSet<ConnectionId>,
) -> Vec<ConnectionId> {
    let mut owned = connection_owners.keys().cloned().collect::<HashSet<_>>();
    owned.extend(pending_connection_owners.keys().cloned());
    owned.extend(inflight_admissions.drain());
    owned.into_iter().collect()
}

fn take_pending_connections_for_call(
    pending: &mut HashMap<ConnectionId, PendingConnectionOwner>,
    call_id: CallId,
) -> Vec<ConnectionId> {
    let connections = pending
        .iter()
        .filter(|(_, owner)| owner.authority.source.call_id == call_id)
        .map(|(connection_id, _)| connection_id.clone())
        .collect::<Vec<_>>();
    for connection_id in &connections {
        pending.remove(connection_id);
    }
    connections
}

fn take_expired_pending_connections(
    pending: &mut HashMap<ConnectionId, PendingConnectionOwner>,
    now: tokio::time::Instant,
) -> Vec<ConnectionId> {
    let connections = pending
        .iter()
        .filter(|(_, owner)| owner.deadline <= now)
        .map(|(connection_id, _)| connection_id.clone())
        .collect::<Vec<_>>();
    for connection_id in &connections {
        pending.remove(connection_id);
    }
    connections
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
    standardcharter_canary: Option<Arc<StandardCharterCanaryPolicy>>,
    broadcast_authority: Option<Arc<WorkerBroadcastSubscriptionAuthority>>,
    private_egress: Option<Arc<PrivateEgressWorkerRuntime>>,
    setup_timeout: Duration,
) -> AdmissionProofResult {
    let connection_id = admission.connection_id().clone();
    let proven = prove_admission_inner(
        admission,
        runtime,
        standardcharter_canary,
        broadcast_authority,
        private_egress,
        setup_timeout,
    )
    .await;
    AdmissionProofResult {
        connection_id,
        proven,
        panicked: false,
    }
}

async fn prove_admission_inner(
    mut admission: InboundAdmission,
    runtime: Arc<CallServiceRuntime>,
    standardcharter_canary: Option<Arc<StandardCharterCanaryPolicy>>,
    broadcast_authority: Option<Arc<WorkerBroadcastSubscriptionAuthority>>,
    private_egress: Option<Arc<PrivateEgressWorkerRuntime>>,
    setup_timeout: Duration,
) -> Option<AdmissionProof> {
    let setup_deadline = tokio::time::Instant::now() + setup_timeout;
    let connection_id = admission.connection_id().clone();
    let transport = admission.transport();
    let principal = match admission.authenticated_principal() {
        Ok(principal) => principal,
        Err(_) => {
            if transport == Transport::Quic {
                tracing::warn!("private QUIC admission missing authenticated principal");
            }
            let _ = admission.reject(RejectReason::Forbidden).await;
            return None;
        }
    };
    let mut context = match admission.take_inbound_context() {
        Ok(Some(context)) if context.is_bound_to(&connection_id, transport, &principal) => context,
        _ => {
            if transport == Transport::Quic {
                tracing::warn!("private QUIC admission missing bound routing context");
            }
            let _ = admission.reject(RejectReason::Forbidden).await;
            return None;
        }
    };
    let signaling_metadata: Vec<(String, String)> = context
        .metadata()
        .iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
    let mut inbound_routing_hint = context.take_routing_hint().map(|hint| hint.into_secret());
    let mut private_staged_channel: Option<StagedInboundDataChannel> = None;
    if transport == Transport::Quic {
        if principal.require_scope(PRIVATE_FORWARD_SCOPE).is_err() {
            tracing::warn!("private QUIC admission missing forwarding scope");
            let _ = admission.reject(RejectReason::Forbidden).await;
            return None;
        }
        if let Some(descriptor) = inbound_routing_hint
            .as_deref()
            .and_then(|hint| PrivateEgressStreamAdmission::from_routing_hint(hint).ok())
        {
            let authorized = principal.tenant.as_deref()
                == Some(descriptor.source.tenant_id.as_str())
                && private_egress
                    .as_ref()
                    .is_some_and(|runtime| runtime.admissions().authorizes(&descriptor));
            if !authorized {
                tracing::warn!(
                    admission_id = %descriptor.admission_id,
                    "private egress stream admission authority revalidation failed"
                );
                let _ = admission.reject(RejectReason::Forbidden).await;
                return None;
            }
            return Some(AdmissionProof::PrivateEgress(
                ProvenPrivateEgressAdmission {
                    admission,
                    descriptor,
                },
            ));
        }
        if let Some(request) = inbound_routing_hint
            .as_deref()
            .and_then(WorkerBroadcastAdmissionRequest::from_routing_hint)
        {
            let tenant = principal
                .tenant
                .as_deref()
                .filter(|tenant| !tenant.trim().is_empty());
            let authorized = tenant.is_some()
                && broadcast_authority.as_ref().is_some_and(|authority| {
                    authority.revalidate_listener(
                        &request.broadcast_id().to_string(),
                        request.listener_id(),
                    )
                });
            if !authorized {
                tracing::warn!("private broadcast admission authority revalidation failed");
                if let Some(authority) = &broadcast_authority {
                    authority.unbind_listener(
                        &request.broadcast_id().to_string(),
                        request.listener_id(),
                    );
                }
                let _ = admission.reject(RejectReason::Forbidden).await;
                return None;
            }
            return Some(AdmissionProof::WorkerBroadcast(
                ProvenWorkerBroadcastAdmission {
                    admission,
                    request,
                    tenant: RvoipTenantId::from_string(tenant.expect("authorized tenant")),
                    authority_guard: WorkerBroadcastAuthorityGuard::new(
                        Arc::clone(broadcast_authority.as_ref().expect("authorized authority")),
                        request,
                    ),
                },
            ));
        }
    }
    let (principal, mut routing_token, attachment_transport, private_request_id) = match transport {
        Transport::Sip => (
            principal,
            inbound_routing_hint.take(),
            AttachmentTransport::Sip,
            None,
        ),
        Transport::WebRtc => (
            principal,
            inbound_routing_hint.take(),
            AttachmentTransport::WebRtc,
            None,
        ),
        Transport::Quic => {
            if principal.require_scope(PRIVATE_FORWARD_SCOPE).is_err() {
                let _ = admission.reject(RejectReason::Forbidden).await;
                return None;
            }
            let Some(routing_hint) = inbound_routing_hint.take() else {
                tracing::warn!("private QUIC admission missing routing hint");
                let _ = admission.reject(RejectReason::Forbidden).await;
                return None;
            };
            let request = match WorkerAttachmentAdmissionRequest::from_routing_hint(routing_hint) {
                Ok(request) => request,
                Err(_) => {
                    tracing::warn!(
                        "private QUIC routing hint matched neither broadcast nor attachment"
                    );
                    let _ = admission.reject(RejectReason::Forbidden).await;
                    return None;
                }
            };
            let mut parts = match request
                .into_worker_parts(runtime.worker().lease, runtime.observation_time())
            {
                Ok(parts) => parts,
                Err(_) => {
                    let _ = admission.reject(RejectReason::Forbidden).await;
                    return None;
                }
            };
            if parts.principal.tenant.as_deref() != principal.tenant.as_deref() {
                let _ = admission.reject(RejectReason::Forbidden).await;
                return None;
            }
            private_staged_channel =
                match admission.open_staged_data_channel(StagedInboundDataPolicy::new(
                    [
                        PRIVATE_ATTACHMENT_ADMISSION_RESPONSE_LABEL,
                        PRIVATE_EGRESS_COMMAND_LABEL,
                        PRIVATE_EGRESS_LIFECYCLE_ACK_LABEL,
                    ],
                    [
                        PRIVATE_EGRESS_RESPONSE_LABEL,
                        PRIVATE_EGRESS_LIFECYCLE_LABEL,
                    ],
                    PRIVATE_STAGED_CONTROL_CAPACITY,
                )) {
                    Ok(channel) => Some(channel),
                    Err(error) => {
                        tracing::warn!(%error, "private attachment staged control setup failed");
                        let _ = admission.reject(RejectReason::ServerError).await;
                        return None;
                    }
                };
            let public_principal = parts.principal.clone();
            let routing_token = std::mem::take(&mut parts.routing_token);
            (
                public_principal,
                Some(routing_token),
                parts.transport,
                Some(parts.request_id),
            )
        }
        _ => {
            let _ = admission.reject(RejectReason::NotAcceptable).await;
            return None;
        }
    };
    if transport == Transport::Sip {
        if let (Some(policy), Some(presented_hint)) =
            (standardcharter_canary.as_ref(), routing_token.as_deref())
        {
            let mut runtime_health = runtime.subscribe_supervisor_health();
            let canary = tokio::time::timeout_at(
                setup_deadline,
                policy.admit(
                    &principal,
                    presented_hint,
                    &signaling_metadata,
                    runtime.as_ref(),
                ),
            );
            match await_while_runtime_owned(canary, &mut runtime_health).await {
                Ok(Ok(Ok(StandardCharterCanaryDecision::NotApplicable))) => {}
                Ok(Ok(Ok(StandardCharterCanaryDecision::Attachment(token)))) => {
                    routing_token = Some(token.into_secret());
                    metrics::counter!(
                        "bridgefu_standardcharter_canary_admission_total",
                        "result" => "created_or_replayed"
                    )
                    .increment(1);
                }
                Ok(Ok(Err(StandardCharterCanaryError::Rejected))) => {
                    metrics::counter!(
                        "bridgefu_standardcharter_canary_admission_total",
                        "result" => "rejected"
                    )
                    .increment(1);
                    let _ = admission.reject(RejectReason::Forbidden).await;
                    return None;
                }
                Ok(Ok(Err(
                    StandardCharterCanaryError::Unavailable
                    | StandardCharterCanaryError::InvalidConfiguration,
                )))
                | Ok(Err(_))
                | Err(()) => {
                    metrics::counter!(
                        "bridgefu_standardcharter_canary_admission_total",
                        "result" => "unavailable"
                    )
                    .increment(1);
                    let _ = admission.reject(RejectReason::ServerError).await;
                    return None;
                }
            }
        }
    }
    let request = InboundAttachmentRequest::new(
        principal,
        routing_token,
        attachment_transport,
        runtime.worker().lease,
        connection_id,
    );
    let mut runtime_health = runtime.subscribe_supervisor_health();
    let service = runtime.service();
    let consume =
        tokio::time::timeout_at(setup_deadline, service.consume_inbound_attachment(request));
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
    let private_response = private_request_id.map(|request_id| {
        WorkerAttachmentAdmissionResponse::admitted(
            request_id,
            WorkerAttachmentAdmissionReceipt {
                tenant_id: consumed.commit.call.aggregate.tenant_id().clone(),
                call_id: consumed.commit.call.aggregate.id(),
                leg_id: consumed.binding.leg_id,
                binding_generation: consumed.binding.binding_generation,
                worker: runtime.worker().lease,
            },
        )
    });
    let staged_private_egress = if let Some(response) = private_response {
        let Some(channel) = private_staged_channel.take() else {
            tracing::error!("private attachment admission lost its staged control channel");
            let _ = admission.reject(RejectReason::ServerError).await;
            let failure = FailureDetails::sanitized(
                "private_control_unavailable",
                "private attachment control setup failed after durable consume",
                true,
            );
            let _ = commit_binding_state(
                &runtime,
                consumed.commit.call.aggregate.tenant_id(),
                consumed.commit.call.aggregate.id(),
                &consumed.binding,
                LegState::Failed,
                Some(failure),
                runtime.observation_time(),
                None,
            )
            .await;
            return None;
        };
        let source = PrivateEgressSource {
            tenant_id: consumed.commit.call.aggregate.tenant_id().clone(),
            call_id: consumed.commit.call.aggregate.id(),
            leg_id: consumed.binding.leg_id,
            binding_generation: consumed.binding.binding_generation,
        };
        let (sender, receiver) = channel.split();
        let receipt_sender = sender.clone();
        let staged = match private_egress.as_ref() {
            Some(private_runtime) => match private_runtime.control().attach_staged_control(
                consumed.binding.connection_id.clone(),
                source,
                sender,
                receiver,
            ) {
                Ok(staged) => Some(staged),
                Err(error) => {
                    tracing::warn!(%error, "private attachment staged control ownership failed");
                    let _ = admission.reject(RejectReason::ServerError).await;
                    let failure = FailureDetails::sanitized(
                        "private_control_unavailable",
                        "private attachment control ownership failed after durable consume",
                        true,
                    );
                    let _ = commit_binding_state(
                        &runtime,
                        consumed.commit.call.aggregate.tenant_id(),
                        consumed.commit.call.aggregate.id(),
                        &consumed.binding,
                        LegState::Failed,
                        Some(failure),
                        runtime.observation_time(),
                        None,
                    )
                    .await;
                    return None;
                }
            },
            None => {
                drop(receiver);
                None
            }
        };
        let delivered = match response.to_data_message() {
            Ok(message) => matches!(
                tokio::time::timeout(EXTERNAL_OPERATION_TIMEOUT, receipt_sender.send(message))
                    .await,
                Ok(Ok(()))
            ),
            Err(_) => false,
        };
        if !delivered {
            tracing::warn!("private attachment staged admission receipt delivery failed");
            let _ = admission.reject(RejectReason::ServerError).await;
            let failure = FailureDetails::sanitized(
                "private_control_unavailable",
                "private attachment receipt delivery failed after durable consume",
                true,
            );
            let _ = commit_binding_state(
                &runtime,
                consumed.commit.call.aggregate.tenant_id(),
                consumed.commit.call.aggregate.id(),
                &consumed.binding,
                LegState::Failed,
                Some(failure),
                runtime.observation_time(),
                None,
            )
            .await;
            return None;
        }
        staged
    } else {
        None
    };
    Some(AdmissionProof::Call(Box::new(ProvenAdmission {
        admission,
        consumed,
        staged_private_egress,
        signaling_metadata,
        termination_watch_cancel: CancellationToken::new(),
    })))
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

async fn reject_worker_broadcast_admission(
    proven: ProvenWorkerBroadcastAdmission,
    authority: Option<&Arc<WorkerBroadcastSubscriptionAuthority>>,
    reason: RejectReason,
) {
    if let Some(authority) = authority {
        authority.unbind_listener(
            &proven.request.broadcast_id().to_string(),
            proven.request.listener_id(),
        );
    }
    let _ = tokio::time::timeout(AUTHORITY_TEARDOWN_TIMEOUT, proven.admission.reject(reason)).await;
}

async fn reject_private_egress_admission(
    proven: ProvenPrivateEgressAdmission,
    runtime: Option<&Arc<PrivateEgressWorkerRuntime>>,
    reason: RejectReason,
) {
    if let Some(runtime) = runtime {
        runtime.admissions().release(proven.descriptor.admission_id);
    }
    let _ = tokio::time::timeout(AUTHORITY_TEARDOWN_TIMEOUT, proven.admission.reject(reason)).await;
}

async fn register_private_egress_admission(
    proven: ProvenPrivateEgressAdmission,
    private_egress: Option<&Arc<PrivateEgressWorkerRuntime>>,
    actor_slots: &HashMap<CallId, ActorSlot>,
    connection_owners: &HashMap<ConnectionId, ConnectionOwner>,
    pending_connection_owners: &mut HashMap<ConnectionId, PendingConnectionOwner>,
    pending_capacity: usize,
    setup_timeout: Duration,
) {
    let call_id = proven.descriptor.source.call_id;
    let connection_id = proven.admission.connection_id().clone();
    let Some(private_runtime) = private_egress else {
        reject_private_egress_admission(proven, None, RejectReason::ServerError).await;
        return;
    };
    let Some(slot) = actor_slots.get(&call_id) else {
        reject_private_egress_admission(proven, private_egress, RejectReason::Forbidden).await;
        return;
    };
    if connection_owners.contains_key(&connection_id)
        || pending_connection_owners.contains_key(&connection_id)
        || pending_connection_owners.len() >= pending_capacity
    {
        reject_private_egress_admission(proven, private_egress, RejectReason::Busy).await;
        return;
    }
    let authority =
        PendingConnectionAuthority::from_admission(connection_id.clone(), &proven.descriptor);
    pending_connection_owners.insert(
        connection_id.clone(),
        PendingConnectionOwner {
            authority: authority.clone(),
            runtime: Some(Arc::clone(private_runtime)),
            release_on_drop: true,
            // Match the same bounded setup window used by admission
            // activation. The 100ms supervisor tick is only sweep cadence.
            deadline: tokio::time::Instant::now() + setup_timeout.min(EXTERNAL_OPERATION_TIMEOUT),
            last_sequence: None,
            staged: VecDeque::with_capacity(PENDING_PRIVATE_OPERATIONAL_CAPACITY),
            promotion_started: false,
            allow_parallel_generation: false,
        },
    );
    if let Err(error) = slot
        .commands
        .try_send(ActorCommand::AdmitPrivateEgress(proven))
    {
        let ActorCommand::AdmitPrivateEgress(proven) = error.into_inner() else {
            unreachable!("private egress registration sent a different actor command")
        };
        if pending_connection_owners
            .get(&connection_id)
            .is_some_and(|pending| pending.authority == authority)
        {
            pending_connection_owners.remove(&connection_id);
        }
        let _ = tokio::time::timeout(
            AUTHORITY_TEARDOWN_TIMEOUT,
            proven.admission.reject(RejectReason::Busy),
        )
        .await;
    }
}

fn route_private_egress_lifecycle(
    delivery: PrivateEgressLifecycleDelivery,
    actor_slots: &HashMap<CallId, ActorSlot>,
    connection_owners: &HashMap<ConnectionId, ConnectionOwner>,
) {
    let Some(owner) = connection_owners.get(&delivery.source_connection) else {
        return;
    };
    if owner.call_id != delivery.event.source.call_id
        || owner.leg_id != delivery.event.source.leg_id
    {
        return;
    }
    let Some(slot) = actor_slots.get(&owner.call_id) else {
        return;
    };
    if slot
        .commands
        .try_send(ActorCommand::PrivateEgressLifecycle(delivery))
        .is_err()
    {
        tracing::warn!(call_id = %owner.call_id, "private egress lifecycle mailbox is full");
    }
}

#[allow(clippy::too_many_arguments)]
async fn register_worker_broadcast_admission(
    mut proven: ProvenWorkerBroadcastAdmission,
    orchestrator: &Arc<Orchestrator>,
    authority: Option<&Arc<WorkerBroadcastSubscriptionAuthority>>,
    capacity: &Arc<Semaphore>,
    slots: &mut HashMap<ConnectionId, WorkerBroadcastSlot>,
    actors: &mut JoinSet<WorkerBroadcastExit>,
    setup_timeout: Duration,
    shutdown: watch::Receiver<ActorShutdown>,
) {
    let Some(authority) = authority.cloned() else {
        reject_worker_broadcast_admission(proven, None, RejectReason::Forbidden).await;
        return;
    };
    let connection_id = proven.admission.connection_id().clone();
    if slots.contains_key(&connection_id) {
        reject_worker_broadcast_admission(proven, Some(&authority), RejectReason::ServerError)
            .await;
        return;
    }
    let permit = match Arc::clone(capacity).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            reject_worker_broadcast_admission(proven, Some(&authority), RejectReason::Busy).await;
            return;
        }
    };
    let resources = WorkerBroadcastResources::new(
        connection_id.clone(),
        proven.request,
        Arc::clone(orchestrator),
        authority,
        permit,
    );
    proven.authority_guard.disarm();
    let (operational, operational_rx) = mpsc::channel(OPERATIONAL_MAILBOX_PER_CALL);
    slots.insert(connection_id.clone(), WorkerBroadcastSlot { operational });
    actors.spawn(async move {
        let lifecycle = AssertUnwindSafe(run_worker_broadcast_admission(
            proven,
            operational_rx,
            setup_timeout,
            shutdown,
            Arc::clone(&resources),
        ))
        .catch_unwind()
        .await;
        let (failed, panicked) = match lifecycle {
            Ok(Ok(())) => (false, false),
            Ok(Err(())) => (true, false),
            Err(_) => (true, true),
        };
        resources.cleanup(failed).await;
        WorkerBroadcastExit {
            connection_id,
            panicked,
        }
    });
}

async fn run_worker_broadcast_admission(
    proven: ProvenWorkerBroadcastAdmission,
    mut operational: mpsc::Receiver<OperationalEvent>,
    setup_timeout: Duration,
    mut shutdown: watch::Receiver<ActorShutdown>,
    resources: Arc<WorkerBroadcastResources>,
) -> Result<(), ()> {
    let setup_deadline = tokio::time::Instant::now() + setup_timeout;
    let conversation = match tokio::time::timeout_at(
        setup_deadline,
        resources.orchestrator.open_conversation(
            proven.tenant,
            ConversationPolicy::default(),
            HashMap::new(),
        ),
    )
    .await
    {
        Ok(Ok(conversation)) => conversation,
        _ => {
            let _ = proven.admission.reject(RejectReason::ServerError).await;
            return Err(());
        }
    };
    resources.set_conversation(conversation.clone()).await;
    let session = match tokio::time::timeout_at(
        setup_deadline,
        resources
            .orchestrator
            .start_session(conversation, SessionMedium::Voice, Vec::new()),
    )
    .await
    {
        Ok(Ok(session)) => session,
        _ => {
            let _ = proven.admission.reject(RejectReason::ServerError).await;
            return Err(());
        }
    };
    resources.set_session(session.clone()).await;
    if !resources.authority.revalidate_listener(
        &resources.request.broadcast_id().to_string(),
        resources.request.listener_id(),
    ) {
        let _ = proven.admission.reject(RejectReason::Forbidden).await;
        return Err(());
    }
    if !matches!(
        tokio::time::timeout_at(setup_deadline, proven.admission.accept()).await,
        Ok(Ok(()))
    ) {
        return Err(());
    }
    if !matches!(
        tokio::time::timeout_at(
            setup_deadline,
            resources.orchestrator.route_inbound_connection(
                resources.connection_id.clone(),
                InboundAction::Accept {
                    session_id: session,
                    participant_id: ParticipantId::new(),
                },
            ),
        )
        .await,
        Ok(Ok(()))
    ) {
        return Err(());
    }

    loop {
        if *shutdown.borrow() != ActorShutdown::Running {
            return if *shutdown.borrow() == ActorShutdown::LeaseLost {
                Err(())
            } else {
                Ok(())
            };
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() == ActorShutdown::LeaseLost {
                    return Err(());
                }
                if *shutdown.borrow() == ActorShutdown::Graceful {
                    return Ok(());
                }
            }
            event = operational.recv() => {
                let Some(event) = event else { return Err(()); };
                match event.kind {
                    OperationalEventKind::Connected
                    | OperationalEventKind::Progress { .. }
                    | OperationalEventKind::MediaActivity { .. } => {}
                    OperationalEventKind::Ended { .. } => return Ok(()),
                    OperationalEventKind::Failed { .. } => return Err(()),
                    _ => return Err(()),
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn register_proven_admission(
    proven: ProvenAdmission,
    orchestrator: &Arc<Orchestrator>,
    runtime: &Arc<CallServiceRuntime>,
    provider_executor: &Arc<dyn ProviderLegExecutor>,
    amazon_connect: &Option<Arc<AmazonConnectAdapter>>,
    context_policy: &Arc<ContextPolicy>,
    outbound_profiles: &Arc<dyn OutboundProfileResolver>,
    private_egress: &Option<Arc<PrivateEgressWorkerRuntime>>,
    outbound_registration: &mpsc::Sender<OutboundRegistration>,
    actor_slots: &mut HashMap<CallId, ActorSlot>,
    connection_owners: &mut HashMap<ConnectionId, ConnectionOwner>,
    pending_owner_updates: &mpsc::UnboundedSender<PendingConnectionOwnerUpdate>,
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
    let parallel_replacement = proven
        .consumed
        .commit
        .call
        .aggregate
        .replacement()
        .is_some_and(|replacement| {
            replacement.leg_id() == leg_id
                && replacement.pending_kind() == crate::call_engine::LegKind::Telnyx
                && replacement.pending_binding_generation() == binding.binding_generation
        });
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
            provider_executor,
            amazon_connect,
            context_policy,
            outbound_profiles,
            private_egress,
            outbound_registration,
            actor_slots,
            connection_owners,
            pending_owner_updates,
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
        let already_indexed_by_this_binding = indexed_connection.is_some_and(|owner| {
            owner.call_id == call_id
                && owner.leg_id == leg_id
                && (parallel_replacement
                    || indexed_leg.is_some_and(|indexed| indexed == &connection_id))
        });
        if !already_indexed_by_this_binding
            && (indexed_connection.is_some() || (!parallel_replacement && indexed_leg.is_some()))
        {
            fail_unowned_proven_admission(proven, orchestrator, runtime, true).await;
            return;
        }
        if !already_indexed_by_this_binding {
            connection_owners.insert(connection_id.clone(), ConnectionOwner { call_id, leg_id });
            if !parallel_replacement {
                leg_owners.insert((call_id, leg_id), connection_id.clone());
            }
            inserted_index = true;
        }
    }

    let Some(slot) = actor_slots.get(&call_id) else {
        if inserted_index {
            connection_owners.remove(&connection_id);
            if !parallel_replacement {
                leg_owners.remove(&(call_id, leg_id));
            }
        }
        fail_unowned_proven_admission(proven, orchestrator, runtime, true).await;
        return;
    };
    if let Err(error) = slot
        .commands
        .try_send(ActorCommand::Admit(Box::new(proven)))
    {
        let ActorCommand::Admit(proven) = error.into_inner() else {
            unreachable!("admission registration sent a different actor command")
        };
        if inserted_index {
            connection_owners.remove(&connection_id);
            if !parallel_replacement {
                leg_owners.remove(&(call_id, leg_id));
            }
        }
        tracing::error!(%call_id, %connection_id, "call actor admission mailbox is unavailable");
        fail_unowned_proven_admission(*proven, orchestrator, runtime, true).await;
    }
}

fn register_outbound_connection(
    registration: OutboundRegistration,
    actor_slots: &HashMap<CallId, ActorSlot>,
    connection_owners: &mut HashMap<ConnectionId, ConnectionOwner>,
    pending_connection_owners: &mut HashMap<ConnectionId, PendingConnectionOwner>,
    leg_owners: &mut HashMap<(CallId, LegId), ConnectionId>,
) -> Option<ConnectionId> {
    let OutboundRegistration {
        call_id,
        binding,
        allow_parallel_generation,
        replacement_effect_id,
        complete_on_transport_connected,
        created_session,
        completion,
    } = registration;
    let connection_id = binding.connection_id.clone();
    let leg_id = binding.leg_id;
    let pending_authority = PendingConnectionAuthority::from_binding(&binding);
    let indexed_connection = connection_owners.get(&connection_id);
    let indexed_leg = leg_owners.get(&(call_id, leg_id));
    let already_indexed = indexed_connection.is_some_and(|owner| {
        owner.call_id == call_id
            && owner.leg_id == leg_id
            && (allow_parallel_generation
                || indexed_leg.is_some_and(|indexed| indexed == &connection_id))
    });
    if !already_indexed
        && (indexed_connection.is_some() || (!allow_parallel_generation && indexed_leg.is_some()))
    {
        if let Some(authority) = pending_authority.as_ref() {
            remove_exact_pending_owner(pending_connection_owners, authority);
        }
        let _ = completion.send(Err(()));
        return pending_authority.map(|_| connection_id);
    }
    let Some(slot) = actor_slots.get(&call_id) else {
        if let Some(authority) = pending_authority.as_ref() {
            remove_exact_pending_owner(pending_connection_owners, authority);
        }
        let _ = completion.send(Err(()));
        return pending_authority.map(|_| connection_id);
    };
    if let Some(authority) = pending_authority.as_ref() {
        let exact_pending = pending_connection_owners
            .get(&connection_id)
            .is_some_and(|pending| pending.authority == *authority);
        if !exact_pending || !authority.matches_binding(call_id, &binding) {
            let _ = completion.send(Err(()));
            return Some(connection_id);
        }
        let pending = pending_connection_owners
            .get_mut(&connection_id)
            .expect("exact pending owner was checked");
        if pending.promotion_started {
            pending_connection_owners.remove(&connection_id);
            let _ = completion.send(Err(()));
            return Some(connection_id);
        }
        pending.promotion_started = true;
        pending.allow_parallel_generation = allow_parallel_generation;
    }
    // Private destinations remain provisional until the actor reports that
    // the exact binding has been installed. Ordinary outbound registrations
    // retain the pre-existing eager index behavior.
    let inserted = pending_authority.is_none() && !already_indexed;
    if inserted {
        connection_owners.insert(connection_id.clone(), ConnectionOwner { call_id, leg_id });
        if !allow_parallel_generation {
            leg_owners.insert((call_id, leg_id), connection_id.clone());
        }
    }
    let command = ActorCommand::RegisterOutbound {
        binding,
        replacement_effect_id,
        complete_on_transport_connected,
        created_session,
        pending_authority: pending_authority.clone(),
        completion,
    };
    if let Err(error) = slot.commands.try_send(command) {
        let failed_private = pending_authority.is_some();
        let ActorCommand::RegisterOutbound { completion, .. } = error.into_inner() else {
            unreachable!("outbound registration sent a different actor command")
        };
        if inserted {
            connection_owners.remove(&connection_id);
            if !allow_parallel_generation {
                leg_owners.remove(&(call_id, leg_id));
            }
        }
        if let Some(authority) = pending_authority {
            remove_exact_pending_owner(pending_connection_owners, &authority);
        }
        let _ = completion.send(Err(()));
        return failed_private.then_some(connection_id);
    }
    None
}

fn remove_exact_pending_owner(
    pending: &mut HashMap<ConnectionId, PendingConnectionOwner>,
    authority: &PendingConnectionAuthority,
) -> bool {
    if pending
        .get(&authority.connection_id)
        .is_some_and(|owner| owner.authority == *authority)
    {
        pending.remove(&authority.connection_id);
        true
    } else {
        false
    }
}

/// Completes the private promotion handshake. The actor has already installed
/// the binding when it sends `Installed`; this function atomically publishes
/// active ownership and hands it every event staged before publication.
fn apply_pending_owner_update(
    update: PendingConnectionOwnerUpdate,
    actor_slots: &HashMap<CallId, ActorSlot>,
    connection_owners: &mut HashMap<ConnectionId, ConnectionOwner>,
    pending_connection_owners: &mut HashMap<ConnectionId, PendingConnectionOwner>,
    leg_owners: &mut HashMap<(CallId, LegId), ConnectionId>,
) -> Option<ConnectionId> {
    match update {
        PendingConnectionOwnerUpdate::Release(authority) => {
            let exact = pending_connection_owners
                .get(&authority.connection_id)
                .is_some_and(|pending| pending.authority == authority);
            if exact {
                pending_connection_owners.remove(&authority.connection_id);
                Some(authority.connection_id)
            } else {
                None
            }
        }
        PendingConnectionOwnerUpdate::Installed { authority, staged } => {
            let Some(pending) = pending_connection_owners.get(&authority.connection_id) else {
                let _ = staged.send(Err(()));
                return Some(authority.connection_id);
            };
            if pending.authority != authority || !pending.promotion_started {
                let _ = staged.send(Err(()));
                return None;
            }
            let call_id = authority.source.call_id;
            let leg_id = authority.target.leg_id;
            let allow_parallel_generation = pending.allow_parallel_generation;
            let active_collision = connection_owners.contains_key(&authority.connection_id)
                || (!allow_parallel_generation && leg_owners.contains_key(&(call_id, leg_id)));
            if active_collision || !actor_slots.contains_key(&call_id) {
                pending_connection_owners.remove(&authority.connection_id);
                let _ = staged.send(Err(()));
                return Some(authority.connection_id);
            }
            let mut pending = pending_connection_owners
                .remove(&authority.connection_id)
                .expect("exact pending owner was checked");
            pending.release_on_drop = false;
            let staged_events = std::mem::take(&mut pending.staged);
            connection_owners.insert(
                authority.connection_id.clone(),
                ConnectionOwner { call_id, leg_id },
            );
            if !allow_parallel_generation {
                leg_owners.insert((call_id, leg_id), authority.connection_id.clone());
            }
            if staged.send(Ok(staged_events)).is_err() {
                connection_owners.remove(&authority.connection_id);
                if !allow_parallel_generation {
                    leg_owners.remove(&(call_id, leg_id));
                }
                // Promotion did not reach the actor, so the connection-owned
                // guard cannot be trusted to release the exact reservation.
                if let Some(runtime) = &pending.runtime {
                    runtime.admissions().release(authority.admission_id);
                }
                return Some(authority.connection_id);
            }
            None
        }
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

fn first_ready_queue_index<T>(
    queue: &VecDeque<T>,
    is_ready: impl FnMut(&T) -> bool,
) -> Option<usize> {
    queue.iter().position(is_ready)
}

fn is_terminal_cleanup_effect(intent: &EffectIntent) -> bool {
    matches!(
        intent,
        EffectIntent::StopLeg { .. }
            | EffectIntent::AbortLegReplacement { .. }
            | EffectIntent::UnbridgeMedia { .. }
    )
}

#[allow(clippy::too_many_arguments)]
fn spawn_call_actor(
    stored: StoredServiceCall,
    orchestrator: &Arc<Orchestrator>,
    runtime: &Arc<CallServiceRuntime>,
    provider_executor: &Arc<dyn ProviderLegExecutor>,
    amazon_connect: &Option<Arc<AmazonConnectAdapter>>,
    context_policy: &Arc<ContextPolicy>,
    outbound_profiles: &Arc<dyn OutboundProfileResolver>,
    private_egress: &Option<Arc<PrivateEgressWorkerRuntime>>,
    outbound_registration: &mpsc::Sender<OutboundRegistration>,
    actor_slots: &mut HashMap<CallId, ActorSlot>,
    connection_owners: &mut HashMap<ConnectionId, ConnectionOwner>,
    pending_owner_updates: &mpsc::UnboundedSender<PendingConnectionOwnerUpdate>,
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
        Arc::clone(provider_executor),
        amazon_connect.clone(),
        Arc::clone(context_policy),
        Arc::clone(outbound_profiles),
        private_egress.clone(),
        outbound_registration.clone(),
        pending_owner_updates.clone(),
        commands_rx,
        operational_rx,
        work_rx,
        drain,
        shutdown,
        retiring,
    );
    let tenant_id = actor.tenant_id.clone();
    actors.spawn(async move {
        match AssertUnwindSafe(Box::pin(actor.run())).catch_unwind().await {
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
    provider_executor: &Arc<dyn ProviderLegExecutor>,
    amazon_connect: &Option<Arc<AmazonConnectAdapter>>,
    context_policy: &Arc<ContextPolicy>,
    outbound_profiles: &Arc<dyn OutboundProfileResolver>,
    private_egress: &Option<Arc<PrivateEgressWorkerRuntime>>,
    outbound_registration: &mpsc::Sender<OutboundRegistration>,
    actor_slots: &mut HashMap<CallId, ActorSlot>,
    connection_owners: &mut HashMap<ConnectionId, ConnectionOwner>,
    pending_owner_updates: &mpsc::UnboundedSender<PendingConnectionOwnerUpdate>,
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
            provider_executor,
            amazon_connect,
            context_policy,
            outbound_profiles,
            private_egress,
            outbound_registration,
            actor_slots,
            connection_owners,
            pending_owner_updates,
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

#[allow(clippy::too_many_arguments)]
async fn absorb_pending_owner_operational(
    authority: &PendingConnectionAuthority,
    operational: &mut mpsc::Receiver<OperationalEvent>,
    pending_operational: &mut VecDeque<OperationalEvent>,
    orchestrator: &Arc<Orchestrator>,
    actors: &HashMap<CallId, ActorSlot>,
    owners: &HashMap<ConnectionId, ConnectionOwner>,
    pending_owners: &mut HashMap<ConnectionId, PendingConnectionOwner>,
    worker_broadcasts: &HashMap<ConnectionId, WorkerBroadcastSlot>,
    private_egress: Option<&Arc<PrivateEgressWorkerRuntime>>,
) {
    let mut deferred = VecDeque::with_capacity(pending_operational.len());
    while let Some(event) = pending_operational.pop_front() {
        if event.connection_id == authority.connection_id {
            if let Some(event) = try_route_operational_event(
                event,
                orchestrator,
                actors,
                owners,
                pending_owners,
                worker_broadcasts,
            )
            .await
            {
                deferred.push_back(event);
            }
        } else {
            deferred.push_back(event);
        }
    }

    while let Ok(event) = operational.try_recv() {
        if private_egress.is_some_and(|runtime| runtime.control().handle_operational_event(&event))
        {
            continue;
        }
        if event.connection_id == authority.connection_id {
            if let Some(event) = try_route_operational_event(
                event,
                orchestrator,
                actors,
                owners,
                pending_owners,
                worker_broadcasts,
            )
            .await
            {
                deferred.push_back(event);
            }
        } else {
            deferred.push_back(event);
        }
    }
    *pending_operational = deferred;
}

async fn try_route_operational_event(
    event: OperationalEvent,
    orchestrator: &Arc<Orchestrator>,
    actors: &HashMap<CallId, ActorSlot>,
    owners: &HashMap<ConnectionId, ConnectionOwner>,
    pending_owners: &mut HashMap<ConnectionId, PendingConnectionOwner>,
    worker_broadcasts: &HashMap<ConnectionId, WorkerBroadcastSlot>,
) -> Option<OperationalEvent> {
    if let Some(worker_broadcast) = worker_broadcasts.get(&event.connection_id) {
        return match worker_broadcast.operational.try_send(event) {
            Ok(()) => None,
            Err(mpsc::error::TrySendError::Full(event)) => Some(event),
            Err(mpsc::error::TrySendError::Closed(event)) => {
                let _ = tokio::time::timeout(
                    AUTHORITY_TEARDOWN_TIMEOUT,
                    orchestrator.end_connection(
                        event.connection_id,
                        EndReason::Failed {
                            detail: "private broadcast lifecycle owner closed".into(),
                        },
                    ),
                )
                .await;
                None
            }
        };
    }
    let event = match stage_pending_operational_event(pending_owners, event) {
        Ok(Some(event)) => event,
        Ok(None) => return None,
        Err((connection_id, detail)) => {
            tracing::error!(%connection_id, %detail, "pending private egress operational staging failed");
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
            return None;
        }
    };
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

fn stage_pending_operational_event(
    pending_owners: &mut HashMap<ConnectionId, PendingConnectionOwner>,
    event: OperationalEvent,
) -> Result<Option<OperationalEvent>, (ConnectionId, &'static str)> {
    let connection_id = event.connection_id.clone();
    let Some(pending) = pending_owners.get_mut(&connection_id) else {
        return Ok(Some(event));
    };
    let failure = pending_operational_failure(
        pending.last_sequence,
        pending.staged.len(),
        event.sequence,
        matches!(
            &event.kind,
            OperationalEventKind::Ended { .. } | OperationalEventKind::Failed { .. }
        ),
    );
    if let Some(detail) = failure {
        pending_owners.remove(&connection_id);
        metrics::counter!(
            "bridgefu_pending_private_operational_total",
            "result" => "failed"
        )
        .increment(1);
        return Err((connection_id, detail));
    }
    pending.last_sequence = Some(event.sequence);
    pending.staged.push_back(event);
    metrics::counter!(
        "bridgefu_pending_private_operational_total",
        "result" => "staged"
    )
    .increment(1);
    Ok(None)
}

fn pending_operational_failure(
    last_sequence: Option<u64>,
    staged_len: usize,
    sequence: u64,
    terminal: bool,
) -> Option<&'static str> {
    if last_sequence.is_some_and(|last| sequence <= last) {
        Some("pending private egress event sequence regressed")
    } else if staged_len >= PENDING_PRIVATE_OPERATIONAL_CAPACITY {
        Some("pending private egress event queue overflowed")
    } else if terminal {
        Some("pending private egress connection ended before promotion")
    } else {
        None
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

fn source_before_answer_termination(
    outcome: InboundAdmissionTermination,
) -> SourceBeforeAnswerTermination {
    match outcome {
        InboundAdmissionTermination::Cancelled => SourceBeforeAnswerTermination::Cancelled,
        InboundAdmissionTermination::RemoteEnded => SourceBeforeAnswerTermination::RemoteEnded,
        InboundAdmissionTermination::Failed => SourceBeforeAnswerTermination::Failed,
        _ => SourceBeforeAnswerTermination::Failed,
    }
}

async fn wait_inbound_admission_termination(
    mut termination: watch::Receiver<Option<InboundAdmissionTermination>>,
) -> InboundAdmissionTermination {
    loop {
        if let Some(outcome) = *termination.borrow_and_update() {
            return outcome;
        }
        if termination.changed().await.is_err() {
            return InboundAdmissionTermination::Failed;
        }
    }
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
        staged_private_egress: _,
        signaling_metadata: _,
        termination_watch_cancel: _,
    } = proven;
    let binding = consumed.binding;
    let connection_id = binding.connection_id.clone();
    let termination = admission.termination_receiver();
    let mut created_conversation = None;
    let mut created_session = None;
    let operation = supervise_rvoip_operation(Box::pin(async {
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
    }));
    let mut source_termination = None;
    let result = {
        let owned_operation = await_while_execution_owned(operation, &mut shutdown);
        tokio::pin!(owned_operation);
        tokio::select! {
            result = &mut owned_operation => match result {
                Ok(result) => result,
                Err(()) => Err(rvoip_core::RvoipError::InvalidState(
                    "admission activation lost execution authority",
                )),
            },
            outcome = wait_inbound_admission_termination(termination) => {
                source_termination = Some(source_before_answer_termination(outcome));
                Err(rvoip_core::RvoipError::AdmissionRejected(
                    "inbound connection ended during admission",
                ))
            }
        }
    };
    // A final-answer race can retire the exact provisional route while
    // `accept()` is in flight. Preserve that distinction so the actor uses the
    // same generation-fenced cross-leg transition as the pending-signal path instead
    // of misclassifying a caller CANCEL as a local signaling failure.
    if result.is_err()
        && source_termination.is_none()
        && orchestrator.connection_principal(&connection_id).is_err()
    {
        // Compatibility/fail-closed fallback for adapters that predate the
        // exact terminal signal. This is evaluated once after an activation
        // failure; it is not a liveness poll.
        source_termination = Some(SourceBeforeAnswerTermination::RemoteEnded);
    }
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
        binding,
        connection_id,
        conversation_id: created_conversation,
        session_id: created_session,
        source_termination,
        result,
    }
}

async fn activate_private_egress_admission(
    proven: ProvenPrivateEgressAdmission,
    orchestrator: Arc<Orchestrator>,
    runtime: Arc<PrivateEgressWorkerRuntime>,
    session_id: SessionId,
    timeout: Duration,
    mut shutdown: watch::Receiver<ActorShutdown>,
) -> PrivateEgressAdmissionResult {
    let ProvenPrivateEgressAdmission {
        admission,
        descriptor,
    } = proven;
    let connection_id = admission.connection_id().clone();
    let admission_id = descriptor.admission_id;
    let authority = PendingConnectionAuthority::from_admission(connection_id.clone(), &descriptor);
    let deadline = tokio::time::Instant::now() + timeout;
    let result = async {
        if *shutdown.borrow() != ActorShutdown::Running {
            let _ = admission.reject(RejectReason::ServerError).await;
            return Err("execution_not_owned");
        }
        match tokio::time::timeout_at(deadline, admission.accept()).await {
            Ok(Ok(())) => {}
            _ => return Err("accept_failed"),
        }
        if !matches!(
            tokio::time::timeout_at(
                deadline,
                orchestrator.route_inbound_connection(
                    connection_id.clone(),
                    InboundAction::Accept {
                        session_id,
                        participant_id: ParticipantId::new(),
                    },
                ),
            )
            .await,
            Ok(Ok(()))
        ) {
            return Err("route_failed");
        }
        let adapter = orchestrator
            .adapter(Transport::Quic)
            .map_err(|_| "adapter_missing")?;
        let stream = loop {
            if let Ok(streams) = adapter.streams(connection_id.clone()).await {
                if let Some(stream) = streams
                    .into_iter()
                    .find(|stream| stream.kind() == rvoip_core::stream::StreamKind::Audio)
                {
                    break stream;
                }
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() != ActorShutdown::Running {
                        return Err("execution_not_owned");
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("media_timeout");
            }
        };
        if stream.codec() != descriptor.codec {
            return Err("codec_mismatch");
        }
        runtime
            .admissions()
            .admit(&descriptor, connection_id.clone(), stream)
            .map_err(|_| "reservation_lost")?;
        Ok(())
    }
    .await;
    if result.is_err() {
        runtime.admissions().release(admission_id);
        let _ = tokio::time::timeout(
            AUTHORITY_TEARDOWN_TIMEOUT,
            orchestrator.end_connection(
                connection_id.clone(),
                EndReason::Failed {
                    detail: "private egress admission failed".into(),
                },
            ),
        )
        .await;
    }
    PrivateEgressAdmissionResult { authority, result }
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
        provider_executor: Arc<dyn ProviderLegExecutor>,
        amazon_connect: Option<Arc<AmazonConnectAdapter>>,
        context_policy: Arc<ContextPolicy>,
        outbound_profiles: Arc<dyn OutboundProfileResolver>,
        private_egress: Option<Arc<PrivateEgressWorkerRuntime>>,
        outbound_registration: mpsc::Sender<OutboundRegistration>,
        pending_owner_updates: mpsc::UnboundedSender<PendingConnectionOwnerUpdate>,
        commands: mpsc::Receiver<ActorCommand>,
        operational: mpsc::Receiver<OperationalEvent>,
        work: mpsc::Receiver<ActorWork>,
        drain: watch::Receiver<bool>,
        shutdown: watch::Receiver<ActorShutdown>,
        retiring: Arc<AtomicBool>,
    ) -> Self {
        let attach_then_dial = if stored.plan.setup_policy() == SetupPolicy::AttachThenDial {
            let ingress = stored
                .call
                .aggregate
                .legs()
                .iter()
                .find(|leg| leg.signaling_initiator() == SignalingInitiator::Remote)
                .map(|leg| leg.id());
            let destination = stored
                .call
                .aggregate
                .legs()
                .iter()
                .find(|leg| leg.signaling_initiator() == SignalingInitiator::Bridgefu)
                .map(|leg| leg.id());
            ingress
                .zip(destination)
                .map(|(ingress, destination)| AttachThenDialLegs {
                    ingress,
                    destination,
                })
        } else {
            None
        };
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
                            private_egress: None,
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
            provider_executor,
            amazon_connect,
            context_policy,
            outbound_profiles,
            private_egress,
            outbound_registration,
            pending_owner_updates,
            commands,
            operational,
            work,
            drain,
            shutdown,
            setup_cancel: CancellationToken::new(),
            bindings,
            pending_replacement_bindings: HashMap::new(),
            replaced_bindings: HashMap::new(),
            active_handoff_attempt: None,
            pending_initial_data_messages: HashMap::new(),
            pending_admissions: VecDeque::new(),
            pending_admission_terminations: JoinSet::new(),
            pending_inbound_authorities: HashMap::new(),
            admission_operation: JoinSet::new(),
            private_admission_operation: JoinSet::new(),
            pending_private_lifecycle: HashMap::new(),
            pending_work: VecDeque::new(),
            work_operation: JoinSet::new(),
            attach_then_dial,
            provisional_early_media_attempted: false,
            provisional_early_media_route: None,
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

    async fn begin_handoff_attempt(
        &mut self,
        replacement_leg_id: LegId,
        previous_binding_generation: crate::call_engine::BindingGeneration,
        pending_binding_generation: crate::call_engine::BindingGeneration,
    ) {
        if self
            .active_handoff_attempt
            .is_some_and(|active| active.pending_binding_generation >= pending_binding_generation)
        {
            return;
        }
        self.active_handoff_attempt = Some(ActiveHandoffAttempt {
            replacement_leg_id,
            previous_binding_generation,
            pending_binding_generation,
            last_status: None,
        });
        self.send_active_handoff_status(HandoffStatusKind::Preparing)
            .await;
    }

    async fn apply_handoff_work_signal(&mut self, signal: Option<HandoffWorkSignal>) {
        let Some(signal) = signal else {
            return;
        };
        if !self.active_handoff_attempt.is_some_and(|active| {
            active.replacement_leg_id == signal.replacement_leg_id
                && active.pending_binding_generation == signal.binding_generation
        }) {
            return;
        }
        self.send_active_handoff_status(signal.status).await;
    }

    async fn finish_handoff_after_durable_work(
        &mut self,
        stored: &StoredServiceCall,
        rebridge_succeeded: bool,
    ) {
        let Some(active) = self.active_handoff_attempt else {
            return;
        };
        if stored.call.aggregate.replacement().is_none()
            && stored.call.aggregate.state() == CallState::Active
            && rebridge_succeeded
        {
            let status = stored
                .call
                .bindings
                .get(&active.replacement_leg_id)
                .and_then(|binding| {
                    if binding.binding_generation == active.pending_binding_generation {
                        Some(HandoffStatusKind::Connected)
                    } else if binding.binding_generation == active.previous_binding_generation {
                        Some(HandoffStatusKind::Resumed)
                    } else {
                        None
                    }
                });
            if let Some(status) = status {
                self.send_active_handoff_status(status).await;
                self.active_handoff_attempt = None;
            }
            return;
        }

        let status = match stored.call.aggregate.state() {
            CallState::Failed => Some(HandoffStatusKind::Failed),
            CallState::Ended => Some(HandoffStatusKind::Ended),
            CallState::Ending
                if stored
                    .call
                    .aggregate
                    .legs()
                    .iter()
                    .any(|leg| leg.failure().is_some()) =>
            {
                Some(HandoffStatusKind::Failed)
            }
            _ => None,
        };
        if let Some(status) = status {
            self.send_active_handoff_status(status).await;
            self.active_handoff_attempt = None;
        }
    }

    async fn send_active_handoff_status(&mut self, status: HandoffStatusKind) {
        let Some(mut active) = self.active_handoff_attempt else {
            return;
        };
        if !handoff_status_can_follow(active.last_status, status) {
            return;
        }
        active.last_status = Some(status);
        self.active_handoff_attempt = Some(active);

        let Some(browser_leg_id) = direct_browser_leg_id(&self.plan, active.replacement_leg_id)
        else {
            return;
        };
        let Some(browser) = self
            .bindings
            .get(&browser_leg_id)
            .filter(|binding| matches!(binding.state, LegState::Connected | LegState::Held))
        else {
            return;
        };
        send_handoff_status_message(
            &self.orchestrator,
            browser.connection_id.clone(),
            self.call_id,
            active.replacement_leg_id,
            active.pending_binding_generation,
            status,
        )
        .await;
    }

    async fn run(mut self) -> ActorExit {
        let mut graceful = false;
        let mut terminal_since = None;
        loop {
            let operation_idle = self.admission_operation.is_empty()
                && self.private_admission_operation.is_empty()
                && self.work_operation.is_empty();
            if self.terminal
                && self.admission_operation.is_empty()
                && !self.pending_admissions.is_empty()
            {
                self.reject_pending_admissions().await;
            }
            if operation_idle && !graceful && self.next_ready_admission_index().is_some() {
                self.start_next_admission();
            } else if operation_idle && self.next_ready_work_index().is_some() {
                self.start_next_work().await;
            }
            let idle = self.admission_operation.is_empty()
                && self.private_admission_operation.is_empty()
                && self.work_operation.is_empty()
                && self.pending_admissions.is_empty()
                && self.pending_admission_terminations.is_empty()
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
                        let _ = self
                            .stop_provisional_early_media("graceful actor shutdown")
                            .await;
                        self.commands.close();
                        self.work.close();
                        while let Ok(command) = self.commands.try_recv() {
                            match command {
                                ActorCommand::Admit(proven) => {
                                    fail_unowned_proven_admission(
                                        *proven,
                                        &self.orchestrator,
                                        &self.runtime,
                                        true,
                                    ).await;
                                }
                                ActorCommand::RegisterOutbound {
                                    pending_authority,
                                    completion,
                                    ..
                                } => {
                                    if let Some(authority) = pending_authority {
                                        self.release_pending_owner(authority);
                                    }
                                    let _ = completion.send(Err(()));
                                }
                                ActorCommand::AdmitPrivateEgress(proven) => {
                                    self.release_pending_owner(
                                        PendingConnectionAuthority::from_admission(
                                            proven.admission.connection_id().clone(),
                                            &proven.descriptor,
                                        ),
                                    );
                                    if let Some(runtime) = &self.private_egress {
                                        runtime
                                            .admissions()
                                            .release(proven.descriptor.admission_id);
                                    }
                                    let _ = proven.admission.reject(RejectReason::ServerError).await;
                                }
                                ActorCommand::PrivateEgressLifecycle(_) => {}
                            }
                        }
                    }
                }
                changed = self.drain.changed() => {
                    if changed.is_err() || *self.drain.borrow() {
                        self.reject_pending_admissions().await;
                    }
                }
                terminated = self.pending_admission_terminations.join_next(), if !self.pending_admission_terminations.is_empty() => {
                    if let Some(Ok(Some(terminated))) = terminated {
                        self.handle_pending_admission_termination(terminated).await;
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
                result = self.private_admission_operation.join_next(), if !self.private_admission_operation.is_empty() => {
                    match result {
                        Some(Ok(result)) if result.result.is_err() => {
                            let authority = result.authority.clone();
                            tracing::warn!(
                                call_id = %self.call_id,
                                admission_id = %authority.admission_id,
                                connection_id = %authority.connection_id,
                                reason = result.result.expect_err("guarded error"),
                                "private egress destination admission failed"
                            );
                            self.release_pending_owner(authority);
                        }
                        Some(Ok(_)) => {}
                        Some(Err(error)) => tracing::error!(call_id = %self.call_id, %error, "private egress admission task panicked"),
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
                            ActorCommand::Admit(proven) if !graceful => self.queue_admission(*proven).await,
                            ActorCommand::Admit(proven) => {
                                fail_unowned_proven_admission(
                                    *proven,
                                    &self.orchestrator,
                                    &self.runtime,
                                    true,
                                ).await;
                            }
                            ActorCommand::RegisterOutbound {
                                binding,
                                replacement_effect_id,
                                complete_on_transport_connected,
                                created_session,
                                pending_authority,
                                completion,
                            } if !graceful => {
                                let handoff_signal = replacement_effect_id.map(|_| HandoffWorkSignal {
                                    replacement_leg_id: binding.leg_id,
                                    binding_generation: binding.binding_generation,
                                    status: HandoffStatusKind::Attaching,
                                });
                                let rollback_binding = binding.clone();
                                let private_target = binding
                                    .private_egress
                                    .as_ref()
                                    .map(|route| route.target);
                                let pending_for_release = pending_authority.clone();
                                let mut result = self.register_outbound(
                                    binding,
                                    replacement_effect_id,
                                    complete_on_transport_connected,
                                    created_session,
                                );
                                if result.is_ok() {
                                    if let Some(authority) = pending_authority {
                                        let (staged, staged_rx) = oneshot::channel();
                                        if self
                                            .pending_owner_updates
                                            .send(PendingConnectionOwnerUpdate::Installed {
                                                authority,
                                                staged,
                                            })
                                            .is_err()
                                        {
                                            result = Err(());
                                        } else {
                                            match staged_rx.await {
                                                Ok(Ok(mut events)) => {
                                                    while let Some(event) = events.pop_front() {
                                                        self.handle_operational(event).await;
                                                    }
                                                }
                                                Ok(Err(())) | Err(_) => result = Err(()),
                                            }
                                        }
                                        if result.is_err() {
                                            self.rollback_outbound_registration(
                                                &rollback_binding,
                                                replacement_effect_id,
                                            );
                                        }
                                    }
                                }
                                if result.is_err() {
                                    if let Some(authority) = pending_for_release {
                                        self.release_pending_owner(authority);
                                    }
                                }
                                if result.is_ok() {
                                    self.apply_handoff_work_signal(handoff_signal).await;
                                    if let Some(target) = private_target {
                                        self.replay_pending_private_lifecycle(target).await;
                                    }
                                    if self.next_ready_admission_index().is_some() {
                                        self.start_next_admission();
                                    }
                                }
                                let _ = completion.send(result);
                            }
                            ActorCommand::RegisterOutbound {
                                pending_authority,
                                completion,
                                ..
                            } => {
                                if let Some(authority) = pending_authority {
                                    self.release_pending_owner(authority);
                                }
                                let _ = completion.send(Err(()));
                            }
                            ActorCommand::AdmitPrivateEgress(proven) if !graceful => {
                                self.queue_private_egress_admission(proven).await;
                            }
                            ActorCommand::AdmitPrivateEgress(proven) => {
                                self.release_pending_owner(
                                    PendingConnectionAuthority::from_admission(
                                        proven.admission.connection_id().clone(),
                                        &proven.descriptor,
                                    ),
                                );
                                if let Some(runtime) = &self.private_egress {
                                    runtime
                                        .admissions()
                                        .release(proven.descriptor.admission_id);
                                }
                                let _ = proven.admission.reject(RejectReason::ServerError).await;
                            }
                            ActorCommand::PrivateEgressLifecycle(delivery) if !graceful => {
                                self.handle_private_egress_lifecycle(delivery).await;
                            }
                            ActorCommand::PrivateEgressLifecycle(_) => {}
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
        let authority_key = PendingInboundAuthorityKey::from_binding(binding);
        let pending_provider_replacement = proven
            .consumed
            .commit
            .call
            .aggregate
            .replacement()
            .is_some_and(|replacement| {
                replacement.leg_id() == binding.leg_id
                    && replacement.pending_kind() == crate::call_engine::LegKind::Telnyx
                    && replacement.pending_binding_generation() == binding.binding_generation
            });
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
            || (self.bindings.contains_key(&binding.leg_id)
                && !existing_binding_matches
                && !pending_provider_replacement)
        {
            fail_unowned_proven_admission(proven, &self.orchestrator, &self.runtime, true).await;
            return;
        }
        if self
            .pending_inbound_authorities
            .contains_key(&authority_key)
        {
            fail_unowned_proven_admission(proven, &self.orchestrator, &self.runtime, true).await;
            return;
        }
        if !pending_provider_replacement {
            self.stage_inbound_sip_context(&proven);
        }
        if !existing_binding_matches && !pending_provider_replacement {
            self.bindings.insert(
                binding.leg_id,
                ActorBinding {
                    connection_id: binding.connection_id.clone(),
                    leg_id: binding.leg_id,
                    binding_generation: binding.binding_generation,
                    state: LegState::Signaling,
                    private_egress: None,
                },
            );
        }
        self.pending_inbound_authorities.insert(
            authority_key,
            PendingInboundAuthority {
                tenant_id: self.tenant_id.clone(),
                call_id: self.call_id,
                binding: binding.clone(),
                staged_private_egress: proven.staged_private_egress.clone(),
            },
        );
        let binding = binding.clone();
        let termination = proven.admission.termination_receiver();
        let cancelled = proven.termination_watch_cancel.clone();
        self.pending_admission_terminations.spawn(async move {
            tokio::select! {
                _ = cancelled.cancelled() => None,
                outcome = wait_inbound_admission_termination(termination) => {
                    Some(PendingAdmissionTermination {
                        binding,
                        reason: source_before_answer_termination(outcome),
                    })
                }
            }
        });
        self.pending_admissions.push_back(proven);
        if pending_provider_replacement && self.next_ready_admission_index().is_some() {
            self.start_next_admission();
        }
    }

    fn pending_source_is_owned(&self, source: &PrivateEgressSource) -> bool {
        if source.tenant_id != self.tenant_id || source.call_id != self.call_id {
            return false;
        }
        let Some(actor_binding) = self.bindings.get(&source.leg_id) else {
            return false;
        };
        let key = PendingInboundAuthorityKey::from_source(source, &actor_binding.connection_id);
        self.pending_inbound_authorities
            .get(&key)
            .is_some_and(|authority| {
                authority.tenant_id == self.tenant_id
                    && authority.call_id == self.call_id
                    && authority.binding.connection_id == actor_binding.connection_id
                    && authority.binding.leg_id == source.leg_id
                    && authority.binding.binding_generation == source.binding_generation
                    && actor_binding.binding_generation == source.binding_generation
                    && actor_binding.state == LegState::Signaling
                    && self
                        .plan
                        .authorization_principal_fingerprint()
                        .is_ok_and(|fingerprint| {
                            fingerprint == authority.binding.principal_fingerprint
                        })
                    && self
                        .orchestrator
                        .connection_principal(&actor_binding.connection_id)
                        .is_ok_and(|principal| {
                            !principal.is_expired()
                                && principal.tenant.as_deref() == Some(self.tenant_id.as_str())
                        })
                    && self
                        .orchestrator
                        .connection_transport(&actor_binding.connection_id)
                        .is_ok_and(|transport| transport == Transport::Quic)
            })
    }

    async fn durable_source_is_owned(&self, source: &PrivateEgressSource) -> bool {
        if source.tenant_id != self.tenant_id || source.call_id != self.call_id {
            return false;
        }
        let Some(actor_binding) = self.bindings.get(&source.leg_id) else {
            return false;
        };
        if actor_binding.binding_generation != source.binding_generation
            || !matches!(
                actor_binding.state,
                LegState::Signaling | LegState::Connected | LegState::Held
            )
            || self
                .orchestrator
                .connection_transport(&actor_binding.connection_id)
                .ok()
                != Some(Transport::Quic)
            || self
                .orchestrator
                .connection_principal(&actor_binding.connection_id)
                .ok()
                .is_none_or(|principal| {
                    principal.is_expired()
                        || principal.tenant.as_deref() != Some(self.tenant_id.as_str())
                })
        {
            return false;
        }
        let Ok(expected_fingerprint) = self.plan.authorization_principal_fingerprint() else {
            return false;
        };
        self.runtime
            .service_repository()
            .load_service_call(&self.tenant_id, self.call_id)
            .await
            .ok()
            .and_then(|stored| stored.call.bindings.get(&source.leg_id).cloned())
            .is_some_and(|durable| {
                durable.connection_id == actor_binding.connection_id
                    && durable.binding_generation == source.binding_generation
                    && durable.principal_fingerprint == expected_fingerprint
            })
    }

    async fn source_is_owned(&self, source: &PrivateEgressSource) -> bool {
        self.pending_source_is_owned(source) || self.durable_source_is_owned(source).await
    }

    fn remove_pending_inbound_authority(
        &mut self,
        connection_id: &ConnectionId,
    ) -> Option<PendingInboundAuthority> {
        let key = self
            .pending_inbound_authorities
            .keys()
            .find(|key| &key.connection_id == connection_id)
            .cloned()?;
        let removed = self.pending_inbound_authorities.remove(&key);
        debug_assert!(
            self.pending_inbound_authorities
                .keys()
                .all(|candidate| &candidate.connection_id != connection_id),
            "one inbound connection cannot retain multiple actor authorities"
        );
        removed
    }

    async fn ensure_source_session(
        &mut self,
        source: &PrivateEgressSource,
    ) -> Result<SessionId, ()> {
        if *self.shutdown.borrow() != ActorShutdown::Running || !self.source_is_owned(source).await
        {
            return Err(());
        }
        match (&self.conversation_id, &self.session_id) {
            (Some(_), Some(session_id)) => return Ok(session_id.clone()),
            (None, None) => {}
            _ => return Err(()),
        }
        let conversation_id = tokio::time::timeout(
            EXTERNAL_OPERATION_TIMEOUT,
            self.orchestrator.open_conversation(
                RvoipTenantId::from_string(self.tenant_id.as_str()),
                ConversationPolicy::default(),
                HashMap::new(),
            ),
        )
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
        let session_id = match tokio::time::timeout(
            EXTERNAL_OPERATION_TIMEOUT,
            self.orchestrator.start_session(
                conversation_id.clone(),
                SessionMedium::Voice,
                Vec::new(),
            ),
        )
        .await
        {
            Ok(Ok(session_id)) => session_id,
            _ => {
                let _ = tokio::time::timeout(
                    AUTHORITY_TEARDOWN_TIMEOUT,
                    self.orchestrator.close_conversation(conversation_id, true),
                )
                .await;
                return Err(());
            }
        };
        if *self.shutdown.borrow() != ActorShutdown::Running || !self.source_is_owned(source).await
        {
            let _ = tokio::time::timeout(
                AUTHORITY_TEARDOWN_TIMEOUT,
                self.orchestrator
                    .end_session(session_id.clone(), EndReason::Cancelled),
            )
            .await;
            let _ = tokio::time::timeout(
                AUTHORITY_TEARDOWN_TIMEOUT,
                self.orchestrator.close_conversation(conversation_id, true),
            )
            .await;
            return Err(());
        }
        self.conversation_id = Some(conversation_id);
        self.session_id = Some(session_id.clone());
        Ok(session_id)
    }

    async fn queue_private_egress_admission(&mut self, proven: ProvenPrivateEgressAdmission) {
        let authority = PendingConnectionAuthority::from_admission(
            proven.admission.connection_id().clone(),
            &proven.descriptor,
        );
        let Some(runtime) = self.private_egress.as_ref().cloned() else {
            self.release_pending_owner(authority);
            let _ = proven.admission.reject(RejectReason::ServerError).await;
            return;
        };
        let descriptor = &proven.descriptor;
        let source_matches = descriptor.worker == self.runtime.worker().lease
            && descriptor.source.tenant_id == self.tenant_id
            && descriptor.source.call_id == self.call_id
            && descriptor.source.leg_id != descriptor.target.leg_id
            && self
                .bindings
                .get(&descriptor.source.leg_id)
                .is_some_and(|binding| {
                    binding.binding_generation == descriptor.source.binding_generation
                        && matches!(
                            binding.state,
                            LegState::Signaling | LegState::Connected | LegState::Held
                        )
                        && self
                            .orchestrator
                            .connection_transport(&binding.connection_id)
                            .is_ok_and(|transport| transport == Transport::Quic)
                });
        let target_in_plan = self
            .plan
            .legs
            .iter()
            .find(|leg| leg.leg_id == descriptor.target.leg_id)
            .is_some_and(|leg| {
                self.plan.leg_signaling_initiator(leg.leg_id) == Ok(SignalingInitiator::Bridgefu)
            });
        let target_state = self
            .runtime
            .service_repository()
            .load_service_call(&self.tenant_id, self.call_id)
            .await
            .ok();
        let target_is_current = target_state.as_ref().is_some_and(|stored| {
            stored
                .call
                .aggregate
                .leg(descriptor.target.leg_id)
                .is_some_and(|leg| {
                    leg.binding_generation() == descriptor.target.binding_generation
                        && self.plan.legs.iter().any(|planned| {
                            planned.leg_id == descriptor.target.leg_id
                                && matches!(
                                    planned.endpoint,
                                    super::LegEndpointConfig::Sip(_)
                                        | super::LegEndpointConfig::WebRtc(_)
                                )
                        })
                })
        });
        let target_is_pending_replacement = target_state.as_ref().is_some_and(|stored| {
            stored
                .call
                .aggregate
                .replacement()
                .is_some_and(|replacement| {
                    replacement.leg_id() == descriptor.target.leg_id
                        && replacement.pending_binding_generation()
                            == descriptor.target.binding_generation
                        && matches!(
                            replacement.pending_kind(),
                            crate::call_engine::LegKind::Sip
                                | crate::call_engine::LegKind::InteractiveWebRtc
                        )
                })
        });
        let target_matches = target_in_plan
            && (target_is_current || target_is_pending_replacement)
            && self
                .bindings
                .get(&descriptor.target.leg_id)
                .is_none_or(|binding| {
                    binding.binding_generation != descriptor.target.binding_generation
                });
        if !source_matches || !target_matches || !runtime.admissions().authorizes(descriptor) {
            self.release_pending_owner(authority);
            runtime.admissions().release(descriptor.admission_id);
            let _ = proven.admission.reject(RejectReason::Forbidden).await;
            return;
        }
        let session_id = match self.ensure_source_session(&descriptor.source).await {
            Ok(session_id) => session_id,
            Err(()) => {
                self.release_pending_owner(authority);
                runtime.admissions().release(descriptor.admission_id);
                let _ = proven.admission.reject(RejectReason::ServerError).await;
                return;
            }
        };
        let orchestrator = Arc::clone(&self.orchestrator);
        let timeout = self
            .runtime
            .timeouts()
            .setup
            .min(EXTERNAL_OPERATION_TIMEOUT);
        let shutdown = self.shutdown.clone();
        self.private_admission_operation.spawn(async move {
            activate_private_egress_admission(
                proven,
                orchestrator,
                runtime,
                session_id,
                timeout,
                shutdown,
            )
            .await
        });
    }

    async fn handle_private_egress_lifecycle(&mut self, delivery: PrivateEgressLifecycleDelivery) {
        let Some(runtime) = self.private_egress.as_ref() else {
            return;
        };
        let event = &delivery.event;
        let source_matches = event.worker == runtime.admissions().worker()
            && event.source.tenant_id == self.tenant_id
            && event.source.call_id == self.call_id
            && self
                .bindings
                .get(&event.source.leg_id)
                .is_some_and(|source| {
                    source.connection_id == delivery.source_connection
                        && source.binding_generation == event.source.binding_generation
                });
        if !source_matches {
            return;
        }
        let target_state = self
            .runtime
            .service_repository()
            .load_service_call(&self.tenant_id, self.call_id)
            .await
            .ok();
        let target_is_current = self
            .plan
            .legs
            .iter()
            .any(|leg| leg.leg_id == event.target.leg_id)
            && target_state.as_ref().is_some_and(|stored| {
                stored
                    .call
                    .aggregate
                    .leg(event.target.leg_id)
                    .is_some_and(|leg| leg.binding_generation() == event.target.binding_generation)
            });
        let target_is_pending_replacement = target_state.as_ref().is_some_and(|stored| {
            stored
                .call
                .aggregate
                .replacement()
                .is_some_and(|replacement| {
                    replacement.leg_id() == event.target.leg_id
                        && replacement.pending_binding_generation()
                            == event.target.binding_generation
                })
        });
        if target_is_pending_replacement {
            let should_replace = self
                .pending_private_lifecycle
                .get(&event.target)
                .is_none_or(|pending| pending.event.sequence <= event.sequence);
            if should_replace {
                self.pending_private_lifecycle
                    .insert(event.target, delivery);
            }
            return;
        }
        if !target_is_current {
            tracing::warn!(
                call_id = %self.call_id,
                target_leg_id = %event.target.leg_id,
                target_generation = event.target.binding_generation.value(),
                "rejected private-egress lifecycle for a foreign target generation"
            );
            return;
        }
        let Some(binding) = self
            .bindings
            .get(&event.target.leg_id)
            .filter(|binding| binding.binding_generation == event.target.binding_generation)
            .cloned()
        else {
            self.pending_private_lifecycle
                .insert(event.target, delivery);
            return;
        };
        let route_matches = binding.private_egress.as_ref().is_some_and(|route| {
            private_lifecycle_route_authority_matches(
                binding.leg_id,
                binding.binding_generation,
                &route.source_connection,
                &route.source,
                route.target,
                &delivery,
            )
        });
        if !route_matches {
            return;
        }
        let (state, failure) = match &event.kind {
            PrivateEgressLifecycleKind::Progress {
                status_code,
                early_media,
            } => {
                self.handle_owned_progress(&binding, *status_code, *early_media)
                    .await;
                return;
            }
            PrivateEgressLifecycleKind::State {
                state: PrivateEgressLifecycleState::Prepared,
                ..
            } => return,
            PrivateEgressLifecycleKind::State {
                state: PrivateEgressLifecycleState::Active,
                ..
            } => (LegState::Connected, None),
            PrivateEgressLifecycleKind::State {
                state: PrivateEgressLifecycleState::Ended,
                ..
            } => (LegState::Ended, None),
            PrivateEgressLifecycleKind::State {
                state: PrivateEgressLifecycleState::Failed,
                ..
            } => (
                LegState::Failed,
                Some(FailureDetails::sanitized(
                    "private_egress_remote_failed",
                    "the gateway-owned destination route failed",
                    true,
                )),
            ),
        };
        if binding.state == state || binding.state.is_terminal() {
            return;
        }
        let committed = self
            .commit_current_binding(
                binding.leg_id,
                state,
                failure,
                self.runtime.observation_time(),
            )
            .await;
        let Ok(committed) = committed else {
            return;
        };
        if let Some(current) = self.bindings.get_mut(&binding.leg_id) {
            current.state = state;
        }
        self.set_terminal(committed.call.aggregate.state().is_terminal());
        if matches!(state, LegState::Ended | LegState::Failed) {
            let _ = self
                .orchestrator
                .end_connection(binding.connection_id.clone(), EndReason::BridgeTorn)
                .await;
            if committed.call.aggregate.state() == CallState::Ending {
                self.stop_ending_peers(binding.leg_id, &committed).await;
            }
        }
    }

    async fn replay_pending_private_lifecycle(&mut self, target: PrivateEgressTarget) {
        let Some(delivery) = self.pending_private_lifecycle.remove(&target) else {
            return;
        };
        self.handle_private_egress_lifecycle(delivery).await;
    }

    fn provider_replacement_admission_is_ready_for_answer(&self, proven: &ProvenAdmission) -> bool {
        self.pending_replacement_bindings
            .get(&proven.consumed.binding.leg_id)
            .is_some_and(|pending| {
                pending.binding.connection_id == proven.consumed.binding.connection_id
                    && pending.binding.binding_generation
                        == proven.consumed.binding.binding_generation
                    && !pending.complete_on_transport_connected
            })
    }

    /// Install the one-way destination-to-ingress route for a real early-media
    /// response. The pending ingress admission owns the exact lifecycle
    /// generation, so no accepted or replaced connection can be targeted.
    async fn start_attach_then_dial_early_media(&mut self, destination: &ActorBinding) {
        if self.provisional_early_media_attempted
            || self.provisional_early_media_route.is_some()
            || destination.state != LegState::Signaling
        {
            return;
        }
        let Some(pair) = self.attach_then_dial else {
            return;
        };
        if destination.leg_id != pair.destination {
            return;
        }
        let Some(ingress) = self.bindings.get(&pair.ingress) else {
            return;
        };
        let ingress_connection_id = ingress.connection_id.clone();
        let ingress_binding_generation = ingress.binding_generation;
        let Some(index) = self.pending_admissions.iter().position(|proven| {
            proven.consumed.binding.leg_id == pair.ingress
                && proven.consumed.binding.connection_id == ingress_connection_id
                && proven.consumed.binding.binding_generation == ingress_binding_generation
        }) else {
            return;
        };

        self.provisional_early_media_attempted = true;
        let source_connection_id = destination.connection_id.clone();
        let route = {
            let proven = self
                .pending_admissions
                .get_mut(index)
                .expect("the located pending admission remains actor-owned");
            proven
                .admission
                .bridge_early_media_from(source_connection_id.clone())
                .await
        };
        match route {
            Ok(route) => {
                tracing::debug!(
                    call_id = %self.call_id,
                    source_connection_id = %route.source_connection_id(),
                    target_connection_id = %route.target_connection_id(),
                    "started attach-then-dial provisional media"
                );
                metrics::counter!(
                    "bridgefu_provisional_early_media_total",
                    "result" => "started"
                )
                .increment(1);
                self.provisional_early_media_route = Some(route);
            }
            Err(error) => {
                tracing::warn!(
                    call_id = %self.call_id,
                    connection_id = %source_connection_id,
                    %error,
                    "attach-then-dial provisional media could not start"
                );
                metrics::counter!(
                    "bridgefu_provisional_early_media_total",
                    "result" => "start_failed"
                )
                .increment(1);
            }
        }
    }

    /// Shared translation target for native and private-egress provisional
    /// progress. Keeping both paths here gives 183 early media identical
    /// generation, attach-then-dial, and one-shot route semantics.
    async fn handle_owned_progress(
        &mut self,
        destination: &ActorBinding,
        status_code: u16,
        early_media: bool,
    ) {
        tracing::debug!(
            call_id = %self.call_id,
            leg_id = %destination.leg_id,
            binding_generation = destination.binding_generation.value(),
            status_code,
            early_media,
            "processing owned provisional destination progress"
        );
        metrics::counter!(
            "bridgefu_destination_progress_total",
            "early_media" => if early_media { "true" } else { "false" }
        )
        .increment(1);
        if early_media {
            self.start_attach_then_dial_early_media(destination).await;
        }
    }

    /// Remove provisional media with graph acknowledgement before any final
    /// answer or ordinary bidirectional bridge can be promoted.
    async fn stop_provisional_early_media(
        &mut self,
        reason: &'static str,
    ) -> Result<(), rvoip_core::RvoipError> {
        let Some(route) = self.provisional_early_media_route.take() else {
            return Ok(());
        };
        let source_connection_id = route.source_connection_id().clone();
        let target_connection_id = route.target_connection_id().clone();
        let result = route.stop().await;
        match &result {
            Ok(()) => {
                tracing::debug!(
                    call_id = %self.call_id,
                    %source_connection_id,
                    %target_connection_id,
                    reason,
                    "stopped attach-then-dial provisional media"
                );
                metrics::counter!(
                    "bridgefu_provisional_early_media_total",
                    "result" => "stopped"
                )
                .increment(1);
            }
            Err(error) => {
                tracing::warn!(
                    call_id = %self.call_id,
                    %source_connection_id,
                    %target_connection_id,
                    reason,
                    %error,
                    "attach-then-dial provisional media stop was not acknowledged"
                );
                metrics::counter!(
                    "bridgefu_provisional_early_media_total",
                    "result" => "stop_failed"
                )
                .increment(1);
            }
        }
        result
    }

    /// Named-route calls use an explicit attach-then-dial barrier: consuming
    /// the source proof is enough to authorize destination setup, but an
    /// inbound SIP leg is not finally answered until destination media is
    /// connected. When no server-owned route context exists, an authenticated
    /// interactive WebRTC ingress whose destination requires browser-supplied
    /// initial context is activated early so its server-owned DataChannel can
    /// supply that context. The outbound SIP, Amazon Connect, or Telnyx
    /// operation remains durably context-gated and therefore performs no
    /// destination I/O merely because the browser transport activated.
    fn admission_is_ready_for_answer(&self, proven: &ProvenAdmission) -> bool {
        if self.provider_replacement_admission_is_ready_for_answer(proven) {
            return true;
        }
        let Some(pair) = self.attach_then_dial else {
            return true;
        };
        if proven.consumed.binding.leg_id != pair.ingress {
            return true;
        }
        if proven.consumed.binding.transport == AttachmentTransport::WebRtc
            && self.plan.legs.iter().any(|leg| {
                leg.leg_id == pair.ingress
                    && matches!(&leg.endpoint, super::LegEndpointConfig::WebRtc(_))
            })
            && self.plan.legs.iter().any(|leg| {
                leg.leg_id == pair.destination
                    && destination_requires_browser_context_before_dial(
                        &leg.endpoint,
                        self.plan
                            .named_route()
                            .and_then(super::NamedRouteBinding::context)
                            .is_some(),
                    )
            })
        {
            return true;
        }
        self.bindings
            .get(&pair.destination)
            .is_some_and(|binding| binding.state == LegState::Connected)
    }

    fn next_ready_admission_index(&self) -> Option<usize> {
        first_ready_queue_index(&self.pending_admissions, |proven| {
            self.admission_is_ready_for_answer(proven)
        })
    }

    /// Do not let a named-route destination create a peer-visible call until
    /// its single-use ingress attachment has been consumed and durably bound.
    /// Other effects (including the attachment wait marker and cleanup) stay
    /// runnable so the aggregate can converge on failure or timeout.
    fn work_is_ready(&self, work: &ActorWork) -> bool {
        let Some(pair) = self.attach_then_dial else {
            return true;
        };
        match work {
            ActorWork::Call(claim)
                if matches!(
                    &claim.record.intent,
                    EffectIntent::StartLeg { leg_id, .. } if *leg_id == pair.destination
                ) =>
            {
                self.bindings.contains_key(&pair.ingress)
            }
            _ => true,
        }
    }

    fn next_ready_work_index(&self) -> Option<usize> {
        self.pending_work
            .iter()
            .position(|work| self.work_is_ready(work))
    }

    async fn reject_pending_admissions(&mut self) {
        let _ = self
            .stop_provisional_early_media("pending admission rejected")
            .await;
        while let Some(proven) = self.pending_admissions.pop_front() {
            proven.termination_watch_cancel.cancel();
            let connection_id = proven.consumed.binding.connection_id.clone();
            let released = self.remove_pending_inbound_authority(&connection_id);
            debug_assert!(
                released.is_some(),
                "pending admission authority was not retained"
            );
            fail_unowned_proven_admission(proven, &self.orchestrator, &self.runtime, true).await;
        }
    }

    async fn handle_pending_admission_termination(
        &mut self,
        terminated: PendingAdmissionTermination,
    ) {
        let exact_pending = self.pending_admissions.iter().any(|proven| {
            let binding = &proven.consumed.binding;
            binding.connection_id == terminated.binding.connection_id
                && binding.leg_id == terminated.binding.leg_id
                && binding.binding_generation == terminated.binding.binding_generation
        });
        if !exact_pending {
            // A cancelled watcher may already have won its select while the
            // admission was moving into final activation. Exact generation
            // matching keeps that stale completion from ending the call.
            return;
        }
        let lost_source = self.pending_admissions.iter().find_map(|proven| {
            let binding = &proven.consumed.binding;
            if binding.connection_id != terminated.binding.connection_id
                || binding.leg_id != terminated.binding.leg_id
                || binding.binding_generation != terminated.binding.binding_generation
            {
                return None;
            }
            proven
                .consumed
                .commit
                .call
                .aggregate
                .leg(binding.leg_id)
                .filter(|leg| {
                    leg.signaling_initiator() == SignalingInitiator::Remote
                        && self
                            .attach_then_dial
                            .is_none_or(|pair| pair.ingress == binding.leg_id)
                })
                .map(|_| binding.clone())
        });

        // The pending admission does not emit a public operational event.
        // Persist its exact route generation as terminal before releasing the
        // admission so the aggregate atomically moves every peer to Ending and
        // emits the normal durable StopLeg effects.
        let committed_source = if let Some(source) = lost_source.as_ref() {
            match self
                .commit_source_terminated_before_answer(
                    source,
                    terminated.reason,
                    self.runtime.observation_time(),
                )
                .await
            {
                Ok(stored) => Some(stored),
                Err(error) => {
                    tracing::warn!(
                        call_id = %self.call_id,
                        source_leg_id = %source.leg_id,
                        source_generation = source.binding_generation.value(),
                        %error,
                        "failed to durably record pending source termination"
                    );
                    None
                }
            }
        } else {
            None
        };
        if committed_source.is_some() {
            // The durable transition is the authority boundary. From this
            // point no in-flight StartLeg operation may prepare, publish, or
            // activate a destination for this call.
            self.setup_cancel.cancel();
        }
        self.reject_pending_admissions().await;
        let stored = match committed_source {
            Some(stored) => Ok(stored),
            None => {
                self.runtime
                    .service_repository()
                    .load_service_call(&self.tenant_id, self.call_id)
                    .await
            }
        };
        if let Ok(stored) = stored {
            for durable in stored.call.bindings.values() {
                let Some(pending) = self
                    .pending_replacement_bindings
                    .get(&durable.leg_id)
                    .filter(|pending| {
                        pending.binding.connection_id == durable.connection_id
                            && pending.binding.binding_generation == durable.binding_generation
                    })
                    .cloned()
                else {
                    continue;
                };
                if let Some(old) = self.bindings.insert(durable.leg_id, pending.binding) {
                    if old.connection_id != durable.connection_id {
                        self.replaced_bindings
                            .insert((old.leg_id, old.binding_generation), old);
                    }
                }
                self.pending_replacement_bindings.remove(&durable.leg_id);
            }
            self.set_terminal(stored.call.aggregate.state().is_terminal());
            if !self.terminal {
                if let Some(source) = lost_source.as_ref() {
                    self.stop_ending_peers(source.leg_id, &stored).await;
                }
                self.converge_durable_binding_states(&stored);
                let _ = ensure_ending_deadline(&self.runtime, stored, self.shutdown.clone()).await;
            } else {
                self.converge_durable_binding_states(&stored);
            }
        }
    }

    fn stage_inbound_sip_context(&mut self, proven: &ProvenAdmission) {
        let binding = &proven.consumed.binding;
        if binding.transport != AttachmentTransport::Sip || proven.signaling_metadata.is_empty() {
            return;
        }
        let Some(target) = self
            .plan
            .legs
            .iter()
            .find(|leg| leg.leg_id != binding.leg_id)
        else {
            return;
        };
        if !matches!(
            &target.endpoint,
            super::LegEndpointConfig::WebRtc(_)
                | super::LegEndpointConfig::Whip(_)
                | super::LegEndpointConfig::Whep(_)
        ) {
            return;
        }
        let envelope = ContextEnvelope::from_sip_headers(
            ContextEnvelope::new(
                self.call_id.to_string(),
                self.tenant_id.as_str(),
                self.call_id.to_string(),
                binding.leg_id.to_string(),
            ),
            proven
                .signaling_metadata
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
            &self.context_policy,
        )
        .and_then(|envelope| envelope.to_data_message());
        match envelope {
            Ok(message) => {
                if self
                    .pending_initial_data_messages
                    .insert(target.leg_id, message)
                    .is_some()
                {
                    metrics::counter!(
                        "bridgefu_initial_context_total",
                        "result" => "replaced",
                        "reason" => "new_source_generation"
                    )
                    .increment(1);
                }
            }
            Err(_) => {
                metrics::counter!(
                    "bridgefu_initial_context_total",
                    "result" => "dropped",
                    "reason" => "invalid_sip_metadata"
                )
                .increment(1);
            }
        }
    }

    async fn deliver_pending_initial_data_messages(&mut self) {
        let targets = self
            .pending_initial_data_messages
            .keys()
            .copied()
            .collect::<Vec<_>>();
        for target_leg_id in targets {
            let Some(binding) = self.bindings.get(&target_leg_id) else {
                continue;
            };
            if binding.state != LegState::Connected {
                continue;
            }
            let connection_id = binding.connection_id.clone();
            let private_route = binding.private_egress.clone();
            let Some(message) = self
                .pending_initial_data_messages
                .get(&target_leg_id)
                .cloned()
            else {
                continue;
            };
            let delivered = match (&self.private_egress, private_route) {
                (Some(private_egress), Some(route)) => {
                    let command = private_egress_command(
                        Uuid::new_v4(),
                        &self.runtime,
                        route.source,
                        route.target,
                        PrivateEgressOperation::DataMessage { message },
                    );
                    match command {
                        Ok(command) => matches!(
                            tokio::time::timeout(
                                EXTERNAL_OPERATION_TIMEOUT,
                                private_egress
                                    .control()
                                    .execute(route.source_connection, command),
                            )
                            .await,
                            Ok(Ok(response))
                                if response.accepted
                                    && response.state
                                        == Some(PrivateEgressLifecycleState::Active)
                        ),
                        Err(()) => false,
                    }
                }
                _ => matches!(
                    tokio::time::timeout(
                        EXTERNAL_OPERATION_TIMEOUT,
                        self.orchestrator.send_data_message(connection_id, message),
                    )
                    .await,
                    Ok(Ok(()))
                ),
            };
            if delivered {
                self.pending_initial_data_messages.remove(&target_leg_id);
                metrics::counter!(
                    "bridgefu_initial_context_total",
                    "result" => "delivered",
                    "reason" => "sip_to_data_channel"
                )
                .increment(1);
            } else {
                tracing::debug!(
                    call_id = %self.call_id,
                    %target_leg_id,
                    "initial SIP context is waiting for a writable DataChannel"
                );
            }
        }
    }

    fn release_pending_owner(&self, authority: PendingConnectionAuthority) {
        let _ = self
            .pending_owner_updates
            .send(PendingConnectionOwnerUpdate::Release(authority));
    }

    fn register_outbound(
        &mut self,
        binding: ActorBinding,
        replacement_effect_id: Option<crate::call_engine::EffectId>,
        complete_on_transport_connected: bool,
        created_session: Option<(ConversationId, SessionId)>,
    ) -> Result<(), ()> {
        if self.setup_cancel.is_cancelled() {
            return Err(());
        }
        let existing_binding_matches = self.bindings.get(&binding.leg_id).is_some_and(|existing| {
            existing.connection_id == binding.connection_id
                && existing.binding_generation == binding.binding_generation
        });
        if self
            .plan
            .legs
            .iter()
            .all(|leg| leg.leg_id != binding.leg_id)
        {
            return Err(());
        }
        let is_pending_replacement =
            self.bindings.contains_key(&binding.leg_id) && !existing_binding_matches;
        if is_pending_replacement {
            let Some(current) = self.bindings.get(&binding.leg_id) else {
                return Err(());
            };
            if !self.active_handoff_attempt.is_some_and(|active| {
                active.replacement_leg_id == binding.leg_id
                    && active.previous_binding_generation == current.binding_generation
                    && active.pending_binding_generation == binding.binding_generation
            }) || self
                .pending_replacement_bindings
                .get(&binding.leg_id)
                .is_some_and(|pending| {
                    pending.binding.connection_id != binding.connection_id
                        || pending.binding.binding_generation != binding.binding_generation
                })
            {
                return Err(());
            }
        }
        if let Some((conversation_id, session_id)) = created_session {
            if self
                .conversation_id
                .as_ref()
                .is_some_and(|value| value != &conversation_id)
                || self
                    .session_id
                    .as_ref()
                    .is_some_and(|value| value != &session_id)
            {
                return Err(());
            }
            self.conversation_id = Some(conversation_id);
            self.session_id = Some(session_id);
        }
        if is_pending_replacement {
            let effect_id = replacement_effect_id.ok_or(())?;
            self.pending_replacement_bindings.insert(
                binding.leg_id,
                PendingReplacementBinding {
                    binding,
                    effect_id,
                    complete_on_transport_connected,
                },
            );
        } else if !existing_binding_matches {
            if replacement_effect_id.is_some() {
                return Err(());
            }
            self.bindings.insert(binding.leg_id, binding);
        }
        Ok(())
    }

    fn rollback_outbound_registration(
        &mut self,
        binding: &ActorBinding,
        replacement_effect_id: Option<crate::call_engine::EffectId>,
    ) {
        if replacement_effect_id.is_some() {
            if self
                .pending_replacement_bindings
                .get(&binding.leg_id)
                .is_some_and(|pending| {
                    pending.binding.connection_id == binding.connection_id
                        && pending.binding.binding_generation == binding.binding_generation
                })
            {
                self.pending_replacement_bindings.remove(&binding.leg_id);
                if let Some(target) = binding.private_egress.as_ref().map(|route| route.target) {
                    self.pending_private_lifecycle.remove(&target);
                }
            }
        } else if self.bindings.get(&binding.leg_id).is_some_and(|installed| {
            installed.connection_id == binding.connection_id
                && installed.binding_generation == binding.binding_generation
        }) {
            self.bindings.remove(&binding.leg_id);
        }
    }

    fn start_next_admission(&mut self) {
        let Some(index) = self.next_ready_admission_index() else {
            return;
        };
        let Some(proven) = self.pending_admissions.remove(index) else {
            return;
        };
        proven.termination_watch_cancel.cancel();
        tracing::debug!(
            call_id = %self.call_id,
            leg_id = %proven.consumed.binding.leg_id,
            connection_id = %proven.consumed.binding.connection_id,
            transport = ?proven.consumed.binding.transport,
            queue_index = index,
            remaining_admissions = self.pending_admissions.len(),
            "starting ready inbound admission"
        );
        let orchestrator = Arc::clone(&self.orchestrator);
        let tenant_id = self.tenant_id.clone();
        let session_id = self.session_id.clone();
        let shutdown = self.shutdown.clone();
        self.admission_operation.spawn(async move {
            activate_admission(proven, orchestrator, tenant_id, session_id, shutdown).await
        });
    }

    async fn finish_admission_operation(&mut self, result: AdmissionOperationResult) {
        let released = self.remove_pending_inbound_authority(&result.connection_id);
        debug_assert!(
            released.is_some(),
            "completed admission authority was not retained"
        );
        if let Err(error) = &result.result {
            tracing::warn!(
                call_id = %self.call_id,
                connection_id = %result.connection_id,
                %error,
                "inbound admission activation failed"
            );
        }
        tracing::debug!(
            call_id = %self.call_id,
            connection_id = %result.connection_id,
            succeeded = result.result.is_ok(),
            "inbound admission operation completed"
        );
        if result.result.is_ok() {
            if let Some(conversation_id) = result.conversation_id {
                self.conversation_id = Some(conversation_id);
            }
            if let Some(session_id) = result.session_id {
                self.session_id = Some(session_id);
            }
            metrics::counter!("bridgefu_attachment_admission_total", "result" => "accepted")
                .increment(1);
            self.deliver_pending_initial_data_messages().await;
            return;
        }
        let terminal_source_matches = result.source_termination.is_some()
            && result.binding.connection_id == result.connection_id
            && self
                .bindings
                .get(&result.binding.leg_id)
                .is_some_and(|binding| {
                    binding.connection_id == result.binding.connection_id
                        && binding.binding_generation == result.binding.binding_generation
                })
            && self
                .plan
                .leg_signaling_initiator(result.binding.leg_id)
                .is_ok_and(|initiator| initiator == SignalingInitiator::Remote)
            && self
                .attach_then_dial
                .is_none_or(|pair| pair.ingress == result.binding.leg_id);
        if terminal_source_matches {
            match self
                .commit_source_terminated_before_answer(
                    &result.binding,
                    result
                        .source_termination
                        .unwrap_or(SourceBeforeAnswerTermination::Failed),
                    self.runtime.observation_time(),
                )
                .await
            {
                Ok(stored) => {
                    // Stop every still-running setup operation before it can
                    // publish or activate a destination after the durable
                    // source-generation transition.
                    self.setup_cancel.cancel();
                    let _ = self
                        .stop_provisional_early_media("source ended during final answer")
                        .await;
                    self.set_terminal(stored.call.aggregate.state().is_terminal());
                    if !self.terminal {
                        self.stop_ending_peers(result.binding.leg_id, &stored).await;
                        self.converge_durable_binding_states(&stored);
                        let _ =
                            ensure_ending_deadline(&self.runtime, stored, self.shutdown.clone())
                                .await;
                    } else {
                        self.converge_durable_binding_states(&stored);
                    }
                    return;
                }
                Err(error) => {
                    tracing::warn!(
                        call_id = %self.call_id,
                        source_leg_id = %result.binding.leg_id,
                        source_generation = result.binding.binding_generation.value(),
                        %error,
                        "failed to record source termination during final-answer race"
                    );
                }
            }
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

    async fn start_next_work(&mut self) {
        let Some(index) = self.next_ready_work_index() else {
            return;
        };
        let Some(work) = self.pending_work.remove(index) else {
            return;
        };
        if let ActorWork::Call(claim) = &work {
            if let EffectIntent::StartLegReplacement {
                leg_id,
                previous_binding_generation,
                pending_binding_generation,
                ..
            } = &claim.record.intent
            {
                self.begin_handoff_attempt(
                    *leg_id,
                    *previous_binding_generation,
                    *pending_binding_generation,
                )
                .await;
            }
        }
        let orchestrator = Arc::clone(&self.orchestrator);
        let runtime = Arc::clone(&self.runtime);
        let provider_executor = Arc::clone(&self.provider_executor);
        let amazon_connect = self.amazon_connect.clone();
        let context_policy = Arc::clone(&self.context_policy);
        let outbound_profiles = Arc::clone(&self.outbound_profiles);
        let private_egress = self.private_egress.clone();
        let outbound_registration = self.outbound_registration.clone();
        let bindings = self.bindings.clone();
        let pending_inbound_authorities = self
            .pending_inbound_authorities
            .values()
            .filter_map(|authority| {
                let binding = &authority.binding;
                if authority.call_id != self.call_id
                    || authority.tenant_id != self.tenant_id
                    || self.bindings.get(&binding.leg_id).is_none_or(|actor| {
                        actor.connection_id != binding.connection_id
                            || actor.binding_generation != binding.binding_generation
                    })
                    || self
                        .orchestrator
                        .connection_principal(&binding.connection_id)
                        .is_err()
                {
                    return None;
                }
                Some((binding.leg_id, authority.clone()))
            })
            .collect::<HashMap<_, _>>();
        let pending_replacement_bindings = self.pending_replacement_bindings.clone();
        let replaced_bindings = self.replaced_bindings.clone();
        let bridge_id = self.bridge_id.clone();
        let session_id = self.session_id.clone();
        let setup_cancel = self.setup_cancel.clone();
        let shutdown = self.shutdown.clone();
        let panic_work = work.clone();
        let panic_orchestrator = Arc::clone(&orchestrator);
        let panic_runtime = Arc::clone(&runtime);
        let panic_provider_executor = Arc::clone(&provider_executor);
        let panic_bindings = bindings.clone();
        let panic_shutdown = shutdown.clone();
        self.work_operation.spawn(async move {
            let mut authority = shutdown.clone();
            // Keep the generic panic supervisor compact. Without these two
            // heap boundaries its state contains both the complete durable
            // call-effect future and its recovery future, which can overflow
            // the default Tokio/libtest stack in debug builds.
            let operation = supervise_work_operation(
                Box::pin(execute_actor_work(
                    work,
                    ActorWorkExecutionContext {
                        orchestrator,
                        runtime,
                        provider_executor,
                        amazon_connect,
                        context_policy,
                        outbound_profiles,
                        private_egress,
                        bindings,
                        pending_inbound_authorities,
                        pending_replacement_bindings,
                        replaced_bindings,
                        bridge_id,
                        session_id,
                        outbound_registration: Some(outbound_registration),
                        setup_cancel,
                        shutdown,
                    },
                )),
                Box::pin(recover_panicked_actor_work(
                    panic_work,
                    panic_orchestrator,
                    panic_runtime,
                    panic_provider_executor,
                    panic_bindings,
                    panic_shutdown,
                )),
            );
            match await_while_execution_owned(operation, &mut authority).await {
                Ok(result) => result,
                Err(()) => WorkOperationResult {
                    effect_id: None,
                    bridge_update: None,
                    handoff_signal: None,
                    result: Err(RepositoryError::Unavailable),
                },
            }
        });
    }

    async fn finish_work_operation(&mut self, result: WorkOperationResult) {
        let work_succeeded = result.result.is_ok();
        let rebridge_succeeded = matches!(result.bridge_update, Some(Some(_)));
        if let Some(bridge_update) = result.bridge_update {
            self.bridge_id = bridge_update;
        }
        if let Err(error) = &result.result {
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
            // Private UCTP is only the worker-to-gateway carrier. Once the
            // StartLeg operation has durably observed the gateway's accepted
            // native Activate response, retire any one-way 183 route before
            // the normal duplex bridge and final ingress answer can start.
            // The carrier's earlier Connected event is intentionally ignored
            // and cannot provide this readiness boundary.
            let activated_private_destination = self.attach_then_dial.and_then(|pair| {
                let binding = self.bindings.get(&pair.destination)?;
                (binding.private_egress.is_some()
                    && stored
                        .call
                        .aggregate
                        .leg(pair.destination)
                        .is_some_and(|leg| leg.state() == LegState::Connected))
                .then(|| binding.connection_id.clone())
            });
            if let Some(connection_id) = activated_private_destination {
                if self
                    .stop_provisional_early_media("private destination activated")
                    .await
                    .is_err()
                {
                    self.reject_pending_admissions().await;
                    let _ = self
                        .orchestrator
                        .end_connection(
                            connection_id,
                            EndReason::Failed {
                                detail: "provisional media promotion failed".into(),
                            },
                        )
                        .await;
                    return;
                }
            }
            // Provider replacements complete from the durable effect result,
            // rather than from a transport `Connected` event. Converge the
            // actor's process-owned binding before it starts the follow-up
            // StopLeg/BridgeMedia effects so those effects retire the exact
            // old generation and bridge the promoted generation.
            self.converge_durable_replacement_bindings(&stored);
            let pending_private_targets = self
                .bindings
                .values()
                .filter_map(|binding| binding.private_egress.as_ref().map(|route| route.target))
                .filter(|target| self.pending_private_lifecycle.contains_key(target))
                .collect::<Vec<_>>();
            for target in pending_private_targets {
                self.replay_pending_private_lifecycle(target).await;
            }
            // Provider lifecycle callbacks are reconciled directly into the
            // durable aggregate and do not emit an rvoip transport event. Keep
            // the actor's current-generation cache authoritative so an
            // attach-then-dial ingress can pass its final-answer barrier as
            // soon as the verified provider callback connects the destination.
            self.converge_durable_binding_states(&stored);
            if work_succeeded {
                self.apply_handoff_work_signal(result.handoff_signal).await;
            }
            self.finish_handoff_after_durable_work(&stored, rebridge_succeeded)
                .await;
            self.set_terminal(stored.call.aggregate.state().is_terminal());
            if stored.call.aggregate.state() == CallState::Ending
                && !self.pending_admissions.is_empty()
            {
                self.reject_pending_admissions().await;
                if let Ok(refreshed) = self
                    .runtime
                    .service_repository()
                    .load_service_call(&self.tenant_id, self.call_id)
                    .await
                {
                    self.set_terminal(refreshed.call.aggregate.state().is_terminal());
                    if !self.terminal {
                        let _ =
                            ensure_ending_deadline(&self.runtime, refreshed, self.shutdown.clone())
                                .await;
                    }
                }
            } else if !self.terminal {
                let _ = ensure_ending_deadline(&self.runtime, stored, self.shutdown.clone()).await;
            }
        }
    }

    fn converge_durable_replacement_bindings(&mut self, stored: &StoredServiceCall) {
        for durable in stored.call.bindings.values() {
            let Some(mut pending) = self
                .pending_replacement_bindings
                .get(&durable.leg_id)
                .filter(|pending| {
                    pending.binding.connection_id == durable.connection_id
                        && pending.binding.binding_generation == durable.binding_generation
                })
                .cloned()
            else {
                continue;
            };
            if let Some(leg) = stored.call.aggregate.leg(durable.leg_id) {
                pending.binding.state = leg.state();
            }
            if let Some(old) = self.bindings.insert(durable.leg_id, pending.binding) {
                if old.connection_id != durable.connection_id
                    || old.binding_generation != durable.binding_generation
                {
                    self.replaced_bindings
                        .insert((old.leg_id, old.binding_generation), old);
                }
            }
            self.pending_replacement_bindings.remove(&durable.leg_id);
        }
    }

    fn converge_durable_binding_states(&mut self, stored: &StoredServiceCall) {
        for (leg_id, binding) in &mut self.bindings {
            let Some(durable_binding) = stored.call.bindings.get(leg_id).filter(|durable| {
                durable.connection_id == binding.connection_id
                    && durable.binding_generation == binding.binding_generation
            }) else {
                continue;
            };
            let Some(leg) = stored.call.aggregate.leg(durable_binding.leg_id) else {
                continue;
            };
            binding.state = leg.state();
        }
    }

    async fn handle_operational(&mut self, event: OperationalEvent) {
        if *self.shutdown.borrow() == ActorShutdown::LeaseLost {
            return;
        }
        tracing::trace!(
            call_id = %self.call_id,
            connection_id = %event.connection_id,
            kind = ?event.kind,
            "processing owned connection operational event"
        );
        if let Some(pending) = self
            .pending_replacement_bindings
            .values()
            .find(|pending| pending.binding.connection_id == event.connection_id)
            .cloned()
        {
            self.handle_replacement_operational(pending, event).await;
            return;
        }
        if let Some(key) = self
            .replaced_bindings
            .iter()
            .find(|(_, binding)| binding.connection_id == event.connection_id)
            .map(|(key, _)| *key)
        {
            if matches!(
                event.kind,
                OperationalEventKind::Ended { .. } | OperationalEventKind::Failed { .. }
            ) {
                self.replaced_bindings.remove(&key);
            }
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
        let is_attach_then_dial_member = self.attach_then_dial.is_some_and(|pair| {
            binding.leg_id == pair.ingress || binding.leg_id == pair.destination
        });
        let is_attach_then_dial_destination = self
            .attach_then_dial
            .is_some_and(|pair| binding.leg_id == pair.destination);
        if matches!(&event.kind, OperationalEventKind::Connected)
            && is_attach_then_dial_destination
            && binding.private_egress.is_none()
            && self
                .stop_provisional_early_media("destination connected")
                .await
                .is_err()
        {
            // A final answer would let the normal duplex bridge race a
            // still-installed graph sink. Fail closed if removal was not
            // acknowledged.
            self.reject_pending_admissions().await;
            let _ = self
                .orchestrator
                .end_connection(
                    event.connection_id,
                    EndReason::Failed {
                        detail: "provisional media promotion failed".into(),
                    },
                )
                .await;
            return;
        }
        match &event.kind {
            OperationalEventKind::Progress {
                status_code,
                early_media,
            } if is_attach_then_dial_destination => {
                self.handle_owned_progress(&binding, *status_code, *early_media)
                    .await;
            }
            OperationalEventKind::Ended { .. } | OperationalEventKind::Failed { .. }
                if is_attach_then_dial_member =>
            {
                let _ = self
                    .stop_provisional_early_media("attach-then-dial leg ended")
                    .await;
            }
            _ => {}
        }
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
        let durable_source = stored
            .call
            .bindings
            .get(&binding.leg_id)
            .filter(|durable| {
                durable.connection_id == binding.connection_id
                    && durable.binding_generation == binding.binding_generation
            })
            .cloned();
        let source_ended_before_answer = durable_source.is_some()
            && stored.call.aggregate.state() == CallState::Connecting
            && leg.signaling_initiator() == SignalingInitiator::Remote
            && matches!(leg.state(), LegState::AwaitingAttach | LegState::Signaling)
            && self
                .attach_then_dial
                .is_none_or(|pair| pair.ingress == binding.leg_id);
        let source_termination = match &event.kind {
            OperationalEventKind::Ended { reason } if source_ended_before_answer => {
                Some(match reason {
                    OperationalEndReason::Cancelled => SourceBeforeAnswerTermination::Cancelled,
                    OperationalEndReason::Normal => SourceBeforeAnswerTermination::RemoteEnded,
                    _ => SourceBeforeAnswerTermination::Failed,
                })
            }
            OperationalEventKind::Failed { .. } if source_ended_before_answer => {
                Some(SourceBeforeAnswerTermination::Failed)
            }
            _ => None,
        };
        if let Some(reason) = source_termination {
            let durable_source =
                durable_source.expect("source terminal classification requires an exact binding");
            match self
                .commit_source_terminated_before_answer(&durable_source, reason, event.at)
                .await
            {
                Ok(committed) => {
                    // Once the exact inbound generation is durably terminal,
                    // no concurrent StartLeg operation may publish or activate
                    // the independently originated B2BUA peer.
                    self.setup_cancel.cancel();
                    self.set_terminal(committed.call.aggregate.state().is_terminal());
                    if !self.terminal {
                        self.stop_ending_peers(binding.leg_id, &committed).await;
                        self.converge_durable_binding_states(&committed);
                        let _ =
                            ensure_ending_deadline(&self.runtime, committed, self.shutdown.clone())
                                .await;
                    } else {
                        self.converge_durable_binding_states(&committed);
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        call_id = %self.call_id,
                        source_leg_id = %binding.leg_id,
                        source_generation = binding.binding_generation.value(),
                        %error,
                        "failed to durably record operational source termination before answer"
                    );
                }
            }
            return;
        }
        if let OperationalEventKind::MediaActivity { generation } = &event.kind {
            if let Err(error) = self
                .record_media_activity(&binding, *generation, event.at, stored)
                .await
            {
                tracing::warn!(call_id = %self.call_id, %leg_id, %error, "authoritative media activity did not reconcile");
            }
            return;
        }
        if let OperationalEventKind::DataMessage { message } = &event.kind {
            if self
                .record_initial_context_message(&binding, message, event.at, &stored)
                .await
            {
                return;
            }
        }
        if let OperationalEventKind::TransferStatus { attempt_id, status } = &event.kind {
            if let Err(error) = self
                .record_transfer_status(&binding, attempt_id.as_ref(), status, event.at, stored)
                .await
            {
                tracing::warn!(call_id = %self.call_id, %leg_id, %error, "authoritative transfer status did not reconcile");
            }
            return;
        }
        // The SIP transport becoming operational proves only that Telnyx has
        // attached its media call. The logical provider leg is not connected
        // until the verified `call.bridged` callback confirms the separately
        // originated destination call was linked.
        let transition = if (leg.kind() == crate::call_engine::LegKind::Telnyx
            || binding.private_egress.is_some())
            && matches!(event.kind, OperationalEventKind::Connected)
        {
            // A private-egress binding is the worker-side UCTP transport, not
            // proof that the gateway's SIP/WebRTC destination is ready. The
            // exact Activate response (and later gateway lifecycle events)
            // owns logical promotion. Treating this transport event as final
            // would release attach-then-dial before native media is ready.
            OperationalTransition::Ignore
        } else {
            classify_operational_event(leg.state(), &event.kind)
        };
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
                    if state == LegState::Connected {
                        self.deliver_pending_initial_data_messages().await;
                    }
                    if should_stop_peers {
                        self.stop_ending_peers(leg_id, &committed).await;
                    }
                    if committed.call.aggregate.state() == CallState::Ending
                        && !self.pending_admissions.is_empty()
                    {
                        self.reject_pending_admissions().await;
                        if let Ok(refreshed) = self
                            .runtime
                            .service_repository()
                            .load_service_call(&self.tenant_id, self.call_id)
                            .await
                        {
                            self.set_terminal(refreshed.call.aggregate.state().is_terminal());
                        }
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

    async fn handle_replacement_operational(
        &mut self,
        pending: PendingReplacementBinding,
        event: OperationalEvent,
    ) {
        let result = match event.kind {
            OperationalEventKind::Connected if pending.complete_on_transport_connected => {
                Some(LegReplacementResult::Connected)
            }
            OperationalEventKind::Connected => None,
            OperationalEventKind::Ended { .. } | OperationalEventKind::Failed { .. } => {
                Some(LegReplacementResult::Rejected(FailureDetails::sanitized(
                    "replacement_signaling_failed",
                    "the replacement route ended before media activation",
                    true,
                )))
            }
            _ => None,
        };
        let Some(result) = result else {
            return;
        };
        let mut stored = match self
            .runtime
            .service_repository()
            .load_service_call(&self.tenant_id, self.call_id)
            .await
        {
            Ok(stored) => stored,
            Err(error) => {
                tracing::warn!(call_id = %self.call_id, %error, "replacement lifecycle load failed");
                return;
            }
        };
        let command_id = CommandId::new();
        loop {
            let Some(replacement) = stored.call.aggregate.replacement() else {
                let _ = self
                    .orchestrator
                    .end_connection(pending.binding.connection_id.clone(), EndReason::Cancelled)
                    .await;
                self.pending_replacement_bindings
                    .remove(&pending.binding.leg_id);
                if let Some(target) = pending
                    .binding
                    .private_egress
                    .as_ref()
                    .map(|route| route.target)
                {
                    self.pending_private_lifecycle.remove(&target);
                }
                return;
            };
            if replacement.leg_id() != pending.binding.leg_id
                || replacement.pending_binding_generation() != pending.binding.binding_generation
            {
                return;
            }
            let deadline_generation = stored
                .call
                .aggregate
                .deadlines()
                .get(DeadlineKind::Transfer)
                .generation();
            let at = std::cmp::max(event.at, stored.call.aggregate.updated_at());
            let promotion = if matches!(result, LegReplacementResult::Connected) {
                let old = match self.bindings.get(&pending.binding.leg_id) {
                    Some(old) => old,
                    None => return,
                };
                let payload = match self
                    .runtime
                    .service_repository()
                    .load_effect_payload(&self.tenant_id, pending.effect_id)
                    .await
                {
                    Ok(Some(payload)) => payload,
                    _ => return,
                };
                let ServiceEffectPayload::LegReplacement {
                    endpoint,
                    authorization_principal_fingerprint,
                    ..
                } = payload.payload
                else {
                    return;
                };
                let transport = match endpoint {
                    super::LegEndpointConfig::Sip(_) => AttachmentTransport::Sip,
                    super::LegEndpointConfig::WebRtc(_)
                    | super::LegEndpointConfig::Whip(_)
                    | super::LegEndpointConfig::Whep(_)
                    | super::LegEndpointConfig::AmazonConnect(_) => AttachmentTransport::WebRtc,
                    super::LegEndpointConfig::Provider(_) => return,
                };
                Some(ReplacementConnectionPromotion {
                    previous_connection_id: old.connection_id.clone(),
                    connection_id: pending.binding.connection_id.clone(),
                    leg_id: pending.binding.leg_id,
                    previous_binding_generation: replacement.previous_binding_generation(),
                    pending_binding_generation: pending.binding.binding_generation,
                    transport,
                    principal_fingerprint: authorization_principal_fingerprint,
                })
            } else {
                None
            };
            let request = ServiceCommandTransaction {
                command: CommandCommit {
                    tenant_id: self.tenant_id.clone(),
                    call_id: self.call_id,
                    expected_version: stored.call.aggregate.version(),
                    command_id,
                    command: CallCommand::FinishLegReplacement {
                        at,
                        deadline_generation,
                        pending_binding_generation: pending.binding.binding_generation,
                        result: result.clone(),
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
                replacement_connection: promotion,
            };
            match self
                .runtime
                .service_repository()
                .commit_with_effect_payloads(request)
                .await
            {
                Ok(ServiceCommandOutcome::Committed(view))
                | Ok(ServiceCommandOutcome::Replayed(view)) => {
                    if matches!(result, LegReplacementResult::Connected) {
                        if let Some(old) = self
                            .bindings
                            .insert(pending.binding.leg_id, pending.binding.clone())
                        {
                            self.replaced_bindings
                                .insert((old.leg_id, old.binding_generation), old);
                        }
                        self.pending_replacement_bindings
                            .remove(&pending.binding.leg_id);
                    } else {
                        // The durable rejection resumed the previous
                        // generation. Retire only the exact process-owned
                        // attempt that produced this lifecycle event; a late
                        // failure must never erase a newer retry for the same
                        // logical leg.
                        let owns_rejected_attempt = self
                            .pending_replacement_bindings
                            .get(&pending.binding.leg_id)
                            .is_some_and(|current| {
                                current.effect_id == pending.effect_id
                                    && current.binding.connection_id
                                        == pending.binding.connection_id
                                    && current.binding.binding_generation
                                        == pending.binding.binding_generation
                            });
                        if owns_rejected_attempt {
                            self.pending_replacement_bindings
                                .remove(&pending.binding.leg_id);
                            if let Some(target) = pending
                                .binding
                                .private_egress
                                .as_ref()
                                .map(|route| route.target)
                            {
                                self.pending_private_lifecycle.remove(&target);
                            }
                        }
                    }
                    self.set_terminal(view.command.call.aggregate.state().is_terminal());
                    return;
                }
                Err(RepositoryError::VersionConflict | RepositoryError::Unavailable) => {
                    match self
                        .runtime
                        .service_repository()
                        .load_service_call(&self.tenant_id, self.call_id)
                        .await
                    {
                        Ok(current) => stored = current,
                        Err(_) => return,
                    }
                }
                Err(error) => {
                    tracing::warn!(call_id = %self.call_id, %error, "replacement lifecycle commit failed");
                    return;
                }
            }
        }
    }

    async fn record_transfer_status(
        &self,
        binding: &ActorBinding,
        attempt_id: Option<&TransferAttemptId>,
        status: &RvoipTransferStatus,
        observed_at: DateTime<Utc>,
        mut stored: StoredServiceCall,
    ) -> Result<StoredServiceCall, RepositoryError> {
        let Some(attempt_id) = attempt_id else {
            metrics::counter!(
                "bridgefu_transfer_status_total",
                "transport" => "rvoip",
                "result" => "missing_attempt"
            )
            .increment(1);
            return Ok(stored);
        };
        if !transfer_status_matches_current(&stored, binding, attempt_id) {
            metrics::counter!(
                "bridgefu_transfer_status_total",
                "transport" => "rvoip",
                "result" => "stale"
            )
            .increment(1);
            return Ok(stored);
        }
        let result = match status {
            RvoipTransferStatus::Accepted => {
                metrics::counter!(
                    "bridgefu_transfer_status_total",
                    "transport" => "rvoip",
                    "result" => "accepted"
                )
                .increment(1);
                return Ok(stored);
            }
            RvoipTransferStatus::Progress { .. } => {
                metrics::counter!(
                    "bridgefu_transfer_status_total",
                    "transport" => "rvoip",
                    "result" => "progress"
                )
                .increment(1);
                return Ok(stored);
            }
            RvoipTransferStatus::Completed { .. } => TransferResult::Completed,
            RvoipTransferStatus::Failed { status_code, .. } => {
                TransferResult::Rejected(FailureDetails::sanitized(
                    "transport_transfer_rejected",
                    "the transfer target rejected the transport request",
                    *status_code >= 500,
                ))
            }
            _ => return Ok(stored),
        };
        let command_id = CommandId::new();
        let mut delay = REPOSITORY_RETRY_MIN;
        loop {
            if *self.shutdown.borrow() == ActorShutdown::LeaseLost {
                return Err(RepositoryError::Unavailable);
            }
            let deadline = stored
                .call
                .aggregate
                .deadlines()
                .get(DeadlineKind::Transfer);
            if !transfer_status_matches_current(&stored, binding, attempt_id) {
                metrics::counter!(
                    "bridgefu_transfer_status_total",
                    "transport" => "rvoip",
                    "result" => "stale"
                )
                .increment(1);
                return Ok(stored);
            }
            let at = std::cmp::max(observed_at, stored.call.aggregate.updated_at());
            let request = ServiceCommandTransaction {
                command: CommandCommit {
                    tenant_id: self.tenant_id.clone(),
                    call_id: self.call_id,
                    expected_version: stored.call.aggregate.version(),
                    command_id,
                    command: CallCommand::FinishTransfer {
                        at,
                        deadline_generation: deadline.generation(),
                        result: result.clone(),
                    },
                    worker: self.runtime.worker().lease,
                    attachments: Vec::new(),
                    deadline_claim: None,
                    at,
                },
                effect_payloads: Vec::new(),
                operation_idempotency: None,
                bound_connection: None,
                media_activity: None,
                replacement_connection: None,
            };
            match self
                .runtime
                .service_repository()
                .commit_with_effect_payloads(request)
                .await
            {
                Ok(ServiceCommandOutcome::Committed(view))
                | Ok(ServiceCommandOutcome::Replayed(view)) => {
                    metrics::counter!(
                        "bridgefu_transfer_status_total",
                        "transport" => "rvoip",
                        "result" => if matches!(result, TransferResult::Completed) {
                            "completed"
                        } else {
                            "failed"
                        }
                    )
                    .increment(1);
                    return self
                        .runtime
                        .service_repository()
                        .load_service_call(
                            view.command.call.aggregate.tenant_id(),
                            view.command.call.aggregate.id(),
                        )
                        .await;
                }
                Err(RepositoryError::VersionConflict) => {
                    stored = self
                        .runtime
                        .service_repository()
                        .load_service_call(&self.tenant_id, self.call_id)
                        .await?;
                }
                Err(RepositoryError::Unavailable) => {
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(REPOSITORY_RETRY_MAX);
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Retains only the first valid context envelope needed by a distinct,
    /// not-yet-bound outbound SIP or Amazon Connect leg. Returning `true`
    /// means the reserved
    /// Bridgefu context label was consumed (or rejected) at this policy
    /// boundary; arbitrary application DataChannels continue through the
    /// ordinary ephemeral event path and the media-graph bridge policy.
    async fn record_initial_context_message(
        &self,
        source: &ActorBinding,
        message: &rvoip_core::DataMessage,
        observed_at: DateTime<Utc>,
        stored: &StoredServiceCall,
    ) -> bool {
        if message.label != CONTEXT_LABEL {
            return false;
        }
        let drop_message = |reason: &'static str| {
            metrics::counter!(
                "bridgefu_initial_context_total",
                "result" => "dropped",
                "reason" => reason
            )
            .increment(1);
        };
        let Some(durable_source) = stored.call.bindings.get(&source.leg_id) else {
            drop_message("source_unbound");
            return true;
        };
        if durable_source.connection_id != source.connection_id
            || durable_source.binding_generation != source.binding_generation
        {
            drop_message("source_stale");
            return true;
        }
        let Some(target) = stored
            .call
            .aggregate
            .legs()
            .iter()
            .find(|leg| leg.id() != source.leg_id)
        else {
            drop_message("target_missing");
            return true;
        };
        let required_sip = target.kind() == crate::call_engine::LegKind::Sip
            && self.plan.sip_initial_context_mode(target.id()).ok()
                == Some(SipInitialContextMode::Required);
        let initial_amazon = target.kind() == crate::call_engine::LegKind::AmazonConnect
            && self.plan.named_route().is_some()
            && direct_browser_leg_id(&self.plan, target.id()) == Some(source.leg_id);
        let initial_telnyx = target.kind() == crate::call_engine::LegKind::Telnyx
            && self.plan.named_route().is_some()
            && direct_browser_leg_id(&self.plan, target.id()) == Some(source.leg_id);
        if !required_sip && !initial_amazon && !initial_telnyx {
            metrics::counter!(
                "bridgefu_initial_context_total",
                "result" => "ignored",
                "reason" => "not_required"
            )
            .increment(1);
            return true;
        }
        if stored.call.bindings.contains_key(&target.id()) {
            // The first context envelope has already served its durable
            // attach-then-dial purpose. A connected SIP peer may receive later
            // context envelopes as ordinary in-dialog SIP MESSAGE traffic; do
            // not consume those at the initial-context boundary. Amazon
            // Connect remains initial-context-only and has no live data path.
            if required_sip {
                metrics::counter!(
                    "bridgefu_initial_context_total",
                    "result" => "forwarded",
                    "reason" => "sip_message"
                )
                .increment(1);
                return false;
            }
            metrics::counter!(
                "bridgefu_initial_context_total",
                "result" => "ignored",
                "reason" => "target_already_bound"
            )
            .increment(1);
            return true;
        }
        let envelope = match ContextEnvelope::from_data_message_for(
            message,
            self.tenant_id.as_str(),
            &self.call_id.to_string(),
            &source.leg_id.to_string(),
        ) {
            Ok(envelope) => envelope,
            Err(_) => {
                drop_message("invalid_envelope");
                return true;
            }
        };
        let initial_sip_headers = if required_sip {
            match envelope.to_sip_headers(&self.context_policy) {
                Ok(headers) => headers.into_iter().collect::<Vec<_>>(),
                Err(_) => {
                    drop_message("unsafe_headers");
                    return true;
                }
            }
        } else {
            Vec::new()
        };
        let envelope = match serde_json::to_vec(&envelope) {
            Ok(envelope) => envelope,
            Err(_) => {
                drop_message("encoding_failed");
                return true;
            }
        };
        let recorded_at = std::cmp::max(
            std::cmp::max(observed_at, durable_source.bound_at),
            stored.call.aggregate.updated_at(),
        );
        let request = InitialContextRecordRequest {
            tenant_id: self.tenant_id.clone(),
            call_id: self.call_id,
            source_connection_id: source.connection_id.clone(),
            source_leg_id: source.leg_id,
            source_binding_generation: source.binding_generation,
            target_leg_id: target.id(),
            target_binding_generation: target.binding_generation(),
            message_id: message.message_id.clone(),
            envelope,
            initial_sip_headers,
            recorded_at,
        };
        match self
            .runtime
            .service_repository()
            .record_initial_context(request)
            .await
        {
            Ok(InitialContextRecordOutcome::Recorded(_)) => {
                metrics::counter!(
                    "bridgefu_initial_context_total",
                    "result" => "recorded",
                    "reason" => "first"
                )
                .increment(1);
            }
            Ok(InitialContextRecordOutcome::Replayed(_)) => {
                metrics::counter!(
                    "bridgefu_initial_context_total",
                    "result" => "replayed",
                    "reason" => "exact"
                )
                .increment(1);
            }
            Err(RepositoryError::CommandConflict) => drop_message("conflict"),
            Err(RepositoryError::StaleClaim) => drop_message("stale_generation"),
            Err(error) => {
                tracing::warn!(
                    call_id = %self.call_id,
                    source_leg_id = %source.leg_id,
                    target_leg_id = %target.id(),
                    %error,
                    "durable initial context admission failed"
                );
                drop_message("repository_unavailable");
            }
        }
        true
    }

    async fn stop_ending_peers(&self, source_leg_id: LegId, stored: &StoredServiceCall) {
        if *self.shutdown.borrow() == ActorShutdown::LeaseLost {
            return;
        }
        for binding in self.bindings.values() {
            let exact_durable_ending_binding = stored
                .call
                .aggregate
                .leg(binding.leg_id)
                .zip(stored.call.bindings.get(&binding.leg_id))
                .is_some_and(|(leg, durable)| {
                    leg.state() == LegState::Ending
                        && leg.binding_generation() == binding.binding_generation
                        && durable.connection_id == binding.connection_id
                        && durable.binding_generation == binding.binding_generation
                });
            if binding.leg_id == source_leg_id || !exact_durable_ending_binding {
                continue;
            }
            if let (Some(private_egress), Some(route)) =
                (&self.private_egress, binding.private_egress.as_ref())
            {
                best_effort_private_egress_finish(
                    private_egress,
                    &route.source_connection,
                    None,
                    &self.runtime,
                    &route.source,
                    route.target,
                    private_egress_peer_stop_operation(binding.state),
                )
                .await;
            }
            let _ = tokio::time::timeout(
                EXTERNAL_OPERATION_TIMEOUT,
                self.orchestrator
                    .end_connection(binding.connection_id.clone(), EndReason::BridgeTorn),
            )
            .await;
        }
        for binding in self.pending_replacement_bindings.values() {
            if let (Some(private_egress), Some(route)) = (
                &self.private_egress,
                binding.binding.private_egress.as_ref(),
            ) {
                best_effort_private_egress_finish(
                    private_egress,
                    &route.source_connection,
                    None,
                    &self.runtime,
                    &route.source,
                    route.target,
                    PrivateEgressOperation::Abort,
                )
                .await;
            }
            let _ = tokio::time::timeout(
                EXTERNAL_OPERATION_TIMEOUT,
                self.orchestrator
                    .end_connection(binding.binding.connection_id.clone(), EndReason::Cancelled),
            )
            .await;
        }
        for binding in self.replaced_bindings.values() {
            if let (Some(private_egress), Some(route)) =
                (&self.private_egress, binding.private_egress.as_ref())
            {
                best_effort_private_egress_finish(
                    private_egress,
                    &route.source_connection,
                    None,
                    &self.runtime,
                    &route.source,
                    route.target,
                    PrivateEgressOperation::End {
                        reason: PrivateEgressEndReason::Normal,
                    },
                )
                .await;
            }
            let _ = tokio::time::timeout(
                EXTERNAL_OPERATION_TIMEOUT,
                self.orchestrator
                    .end_connection(binding.connection_id.clone(), EndReason::Cancelled),
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

    async fn commit_source_terminated_before_answer(
        &self,
        source: &ConnectionBinding,
        reason: SourceBeforeAnswerTermination,
        observed_at: DateTime<Utc>,
    ) -> Result<StoredServiceCall, RepositoryError> {
        let actor_binding = self
            .bindings
            .get(&source.leg_id)
            .filter(|binding| {
                binding.connection_id == source.connection_id
                    && binding.binding_generation == source.binding_generation
            })
            .ok_or(RepositoryError::StaleClaim)?;
        debug_assert_eq!(actor_binding.leg_id, source.leg_id);

        let tenant_id = self.tenant_id.clone();
        let mut stored = self
            .runtime
            .service_repository()
            .load_service_call(&tenant_id, self.call_id)
            .await?;
        let command_id = CommandId::new();
        let mut delay = REPOSITORY_RETRY_MIN;
        loop {
            let source_leg = stored
                .call
                .aggregate
                .leg(source.leg_id)
                .filter(|leg| {
                    leg.binding_generation() == source.binding_generation
                        && leg.signaling_initiator() == SignalingInitiator::Remote
                })
                .ok_or(RepositoryError::StaleClaim)?;
            if source_leg.state().is_terminal() {
                return Ok(stored);
            }
            let durable_binding = stored
                .call
                .bindings
                .get(&source.leg_id)
                .filter(|binding| {
                    binding.connection_id == source.connection_id
                        && binding.binding_generation == source.binding_generation
                })
                .ok_or(RepositoryError::StaleClaim)?;
            debug_assert_eq!(durable_binding.leg_id, source.leg_id);
            let at = std::cmp::max(observed_at, stored.call.aggregate.updated_at());
            let request = BoundSourceTerminationCommit {
                tenant_id: tenant_id.clone(),
                call_id: self.call_id,
                expected_version: stored.call.aggregate.version(),
                command_id,
                source_leg_id: source.leg_id,
                binding_generation: source.binding_generation,
                connection_id: source.connection_id.clone(),
                worker: self.runtime.worker().lease,
                reason,
                at,
            };
            let repository = self.runtime.service_repository();
            let mut shutdown = self.shutdown.clone();
            let result = await_while_execution_owned(
                repository.commit_bound_source_termination(request),
                &mut shutdown,
            )
            .await
            .map_err(|()| RepositoryError::Unavailable)?;
            match result {
                Ok(ServiceCommandOutcome::Committed(view))
                | Ok(ServiceCommandOutcome::Replayed(view)) => {
                    return self
                        .runtime
                        .service_repository()
                        .load_service_call(
                            view.command.call.aggregate.tenant_id(),
                            view.command.call.aggregate.id(),
                        )
                        .await;
                }
                Err(RepositoryError::VersionConflict) => {
                    stored = self
                        .runtime
                        .service_repository()
                        .load_service_call(&tenant_id, self.call_id)
                        .await?;
                }
                Err(RepositoryError::Unavailable) => {
                    if *self.shutdown.borrow() == ActorShutdown::LeaseLost {
                        return Err(RepositoryError::Unavailable);
                    }
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(REPOSITORY_RETRY_MAX);
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn cleanup(&mut self, allow_durable_write: bool) {
        let _ = self
            .stop_provisional_early_media("call actor cleanup")
            .await;
        while let Some(proven) = self.pending_admissions.pop_front() {
            proven.termination_watch_cancel.cancel();
            let connection_id = proven.consumed.binding.connection_id.clone();
            let released = self.remove_pending_inbound_authority(&connection_id);
            debug_assert!(
                released.is_some(),
                "cleanup lost pending admission authority"
            );
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
        self.pending_admission_terminations.abort_all();
        while self
            .pending_admission_terminations
            .join_next()
            .await
            .is_some()
        {}
        self.pending_inbound_authorities.clear();
        debug_assert!(self.pending_inbound_authorities.is_empty());
        self.private_admission_operation.abort_all();
        while self.private_admission_operation.join_next().await.is_some() {}
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
        if allow_durable_write {
            if let Some(private_egress) = &self.private_egress {
                for route in self
                    .bindings
                    .values()
                    .filter_map(|binding| binding.private_egress.as_ref())
                {
                    best_effort_private_egress_finish(
                        private_egress,
                        &route.source_connection,
                        None,
                        &self.runtime,
                        &route.source,
                        route.target,
                        PrivateEgressOperation::End {
                            reason: PrivateEgressEndReason::WorkerDrain,
                        },
                    )
                    .await;
                }
                for route in self
                    .pending_replacement_bindings
                    .values()
                    .filter_map(|binding| binding.binding.private_egress.as_ref())
                {
                    best_effort_private_egress_finish(
                        private_egress,
                        &route.source_connection,
                        None,
                        &self.runtime,
                        &route.source,
                        route.target,
                        PrivateEgressOperation::Abort,
                    )
                    .await;
                }
                for route in self
                    .replaced_bindings
                    .values()
                    .filter_map(|binding| binding.private_egress.as_ref())
                {
                    best_effort_private_egress_finish(
                        private_egress,
                        &route.source_connection,
                        None,
                        &self.runtime,
                        &route.source,
                        route.target,
                        PrivateEgressOperation::End {
                            reason: PrivateEgressEndReason::WorkerDrain,
                        },
                    )
                    .await;
                }
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
        for binding in self.pending_replacement_bindings.values() {
            let _ = tokio::time::timeout(
                EXTERNAL_OPERATION_TIMEOUT,
                self.orchestrator
                    .end_connection(binding.binding.connection_id.clone(), EndReason::Cancelled),
            )
            .await;
        }
        for binding in self.replaced_bindings.values() {
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

fn destination_requires_browser_context_before_dial(
    endpoint: &super::LegEndpointConfig,
    server_owned_route_context_present: bool,
) -> bool {
    if server_owned_route_context_present {
        return false;
    }
    matches!(
        endpoint,
        super::LegEndpointConfig::Sip(super::SipEndpointConfig {
            initial_context: SipInitialContextMode::Required,
            ..
        }) | super::LegEndpointConfig::AmazonConnect(_)
            | super::LegEndpointConfig::Provider(super::ProviderEndpointConfig {
                provider: ProviderKind::Telnyx,
                ..
            })
    )
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
    ProviderMediaStarted {
        leg_id: LegId,
        binding_generation: crate::call_engine::BindingGeneration,
    },
    FailLeg {
        leg_id: LegId,
        binding_generation: crate::call_engine::BindingGeneration,
        failure: FailureDetails,
    },
    FinishTransfer {
        deadline_generation: crate::call_engine::DeadlineGeneration,
        result: TransferResult,
    },
    FinishLegReplacement {
        deadline_generation: crate::call_engine::DeadlineGeneration,
        pending_binding_generation: crate::call_engine::BindingGeneration,
        result: LegReplacementResult,
        replacement_connection: Option<ReplacementConnectionPromotion>,
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
    _provider_executor: Arc<dyn ProviderLegExecutor>,
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
                | EffectIntent::ConnectProviderDestination {
                    leg_id,
                    binding_generation,
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
                EffectIntent::StartLegReplacement {
                    deadline_generation,
                    pending_binding_generation,
                    ..
                } => FollowUpPlan::FinishLegReplacement {
                    deadline_generation,
                    pending_binding_generation,
                    result: LegReplacementResult::Rejected(failure.clone()),
                    replacement_connection: None,
                },
                _ => FollowUpPlan::None,
            };
            WorkOperationResult {
                effect_id: Some(effect_id),
                bridge_update: None,
                handoff_signal: None,
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
                handoff_signal: None,
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
            handoff_signal: None,
            result: commit_deadline(claim, runtime, shutdown).await,
        },
        ActorWork::Restart(claim) => WorkOperationResult {
            effect_id: None,
            bridge_update: None,
            handoff_signal: None,
            result: recover_restarted_call(*claim, runtime, shutdown).await,
        },
    }
}

struct ActorWorkExecutionContext {
    orchestrator: Arc<Orchestrator>,
    runtime: Arc<CallServiceRuntime>,
    provider_executor: Arc<dyn ProviderLegExecutor>,
    amazon_connect: Option<Arc<AmazonConnectAdapter>>,
    context_policy: Arc<ContextPolicy>,
    outbound_profiles: Arc<dyn OutboundProfileResolver>,
    private_egress: Option<Arc<PrivateEgressWorkerRuntime>>,
    bindings: HashMap<LegId, ActorBinding>,
    pending_inbound_authorities: HashMap<LegId, PendingInboundAuthority>,
    pending_replacement_bindings: HashMap<LegId, PendingReplacementBinding>,
    replaced_bindings: HashMap<(LegId, crate::call_engine::BindingGeneration), ActorBinding>,
    bridge_id: Option<BridgeId>,
    session_id: Option<SessionId>,
    outbound_registration: Option<mpsc::Sender<OutboundRegistration>>,
    setup_cancel: CancellationToken,
    shutdown: watch::Receiver<ActorShutdown>,
}

async fn execute_actor_work(
    work: ActorWork,
    context: ActorWorkExecutionContext,
) -> WorkOperationResult {
    match work {
        ActorWork::Call(claim) => execute_call_effect(claim, context).await,
        ActorWork::Control(claim) => {
            execute_control_effect(
                claim,
                context.orchestrator,
                context.runtime,
                context.provider_executor,
                context.private_egress,
                context.bindings,
                context.shutdown,
            )
            .await
        }
        ActorWork::Provider(claim) => {
            execute_provider_event(claim, context.runtime, context.shutdown).await
        }
        ActorWork::Deadline(claim) => WorkOperationResult {
            effect_id: None,
            bridge_update: None,
            handoff_signal: None,
            result: commit_deadline(claim, context.runtime, context.shutdown).await,
        },
        ActorWork::Restart(claim) => WorkOperationResult {
            effect_id: None,
            bridge_update: None,
            handoff_signal: None,
            result: recover_restarted_call(*claim, context.runtime, context.shutdown).await,
        },
    }
}

struct AmazonStartExecution {
    result: ServiceEffectResult,
    follow_up: FollowUpPlan,
    external_reference: Option<ExternalReferenceBinding>,
}

struct WebRtcStartExecution {
    result: ServiceEffectResult,
    follow_up: FollowUpPlan,
}

struct SipStartExecution {
    result: ServiceEffectResult,
    follow_up: FollowUpPlan,
    external_reference: Option<ExternalReferenceBinding>,
}

struct PrivateEgressStartExecution {
    result: ServiceEffectResult,
    follow_up: FollowUpPlan,
}

impl PrivateEgressStartExecution {
    fn cancelled() -> Self {
        Self {
            result: ServiceEffectResult::Succeeded,
            follow_up: FollowUpPlan::None,
        }
    }

    fn failed(
        leg_id: LegId,
        binding_generation: crate::call_engine::BindingGeneration,
        code: &'static str,
        message: &'static str,
        retryable: bool,
    ) -> Self {
        tracing::warn!(
            %leg_id,
            binding_generation = binding_generation.value(),
            failure_code = code,
            "private egress start phase failed"
        );
        let failure = FailureDetails::sanitized(code, message, retryable);
        Self {
            result: ServiceEffectResult::Failed(failure.clone()),
            follow_up: FollowUpPlan::FailLeg {
                leg_id,
                binding_generation,
                failure,
            },
        }
    }

    fn restarted(leg_id: LegId, binding_generation: crate::call_engine::BindingGeneration) -> Self {
        Self {
            result: ServiceEffectResult::Succeeded,
            follow_up: FollowUpPlan::FailLeg {
                leg_id,
                binding_generation,
                failure: FailureDetails::sanitized(
                    "private_egress_worker_restarted",
                    "a gateway-owned destination cannot migrate across worker restart",
                    true,
                ),
            },
        }
    }
}

impl SipStartExecution {
    fn cancelled() -> Self {
        Self {
            result: ServiceEffectResult::Succeeded,
            follow_up: FollowUpPlan::None,
            external_reference: None,
        }
    }

    fn failed(
        leg_id: LegId,
        binding_generation: crate::call_engine::BindingGeneration,
        code: &'static str,
        message: &'static str,
        retryable: bool,
    ) -> Self {
        let failure = FailureDetails::sanitized(code, message, retryable);
        Self {
            result: ServiceEffectResult::Failed(failure.clone()),
            follow_up: FollowUpPlan::FailLeg {
                leg_id,
                binding_generation,
                failure,
            },
            external_reference: None,
        }
    }

    fn restarted(leg_id: LegId, binding_generation: crate::call_engine::BindingGeneration) -> Self {
        Self {
            result: ServiceEffectResult::Succeeded,
            follow_up: FollowUpPlan::FailLeg {
                leg_id,
                binding_generation,
                failure: FailureDetails::sanitized(
                    "worker_restarted",
                    "an outbound SIP route cannot migrate across worker restart",
                    true,
                ),
            },
            external_reference: None,
        }
    }
}

impl WebRtcStartExecution {
    fn cancelled() -> Self {
        Self {
            result: ServiceEffectResult::Succeeded,
            follow_up: FollowUpPlan::None,
        }
    }

    fn failed(
        leg_id: LegId,
        binding_generation: crate::call_engine::BindingGeneration,
        code: &'static str,
        message: &'static str,
        retryable: bool,
    ) -> Self {
        let failure = FailureDetails::sanitized(code, message, retryable);
        Self {
            result: ServiceEffectResult::Failed(failure.clone()),
            follow_up: FollowUpPlan::FailLeg {
                leg_id,
                binding_generation,
                failure,
            },
        }
    }

    fn restarted(leg_id: LegId, binding_generation: crate::call_engine::BindingGeneration) -> Self {
        Self {
            result: ServiceEffectResult::Succeeded,
            follow_up: FollowUpPlan::FailLeg {
                leg_id,
                binding_generation,
                failure: FailureDetails::sanitized(
                    "worker_restarted",
                    "an outbound WebRTC route cannot migrate across worker restart",
                    true,
                ),
            },
        }
    }
}

impl AmazonStartExecution {
    fn cancelled(external_reference: Option<ExternalReferenceBinding>) -> Self {
        Self {
            result: ServiceEffectResult::Succeeded,
            follow_up: FollowUpPlan::None,
            external_reference,
        }
    }

    fn failed(
        leg_id: LegId,
        binding_generation: crate::call_engine::BindingGeneration,
        code: &'static str,
        message: &'static str,
        retryable: bool,
    ) -> Self {
        let failure = FailureDetails::sanitized(code, message, retryable);
        Self {
            result: ServiceEffectResult::Failed(failure.clone()),
            follow_up: FollowUpPlan::FailLeg {
                leg_id,
                binding_generation,
                failure,
            },
            external_reference: None,
        }
    }
}

async fn open_outbound_voice_session(
    orchestrator: &Arc<Orchestrator>,
    tenant_id: &crate::call_engine::TenantId,
    shutdown: &mut watch::Receiver<ActorShutdown>,
) -> Result<(ConversationId, SessionId), RepositoryError> {
    let conversation = await_while_execution_owned(
        tokio::time::timeout(
            EXTERNAL_OPERATION_TIMEOUT,
            orchestrator.open_conversation(
                RvoipTenantId::from_string(tenant_id.as_str()),
                ConversationPolicy::default(),
                HashMap::new(),
            ),
        ),
        shutdown,
    )
    .await
    .map_err(|()| RepositoryError::Unavailable)?
    .map_err(|_| RepositoryError::Unavailable)?
    .map_err(|_| RepositoryError::Unavailable)?;
    let session = await_while_execution_owned(
        tokio::time::timeout(
            EXTERNAL_OPERATION_TIMEOUT,
            orchestrator.start_session(conversation.clone(), SessionMedium::Voice, Vec::new()),
        ),
        shutdown,
    )
    .await
    .map_err(|()| RepositoryError::Unavailable)?;
    match session {
        Ok(Ok(session)) => Ok((conversation, session)),
        Ok(Err(_)) | Err(_) => {
            let _ = tokio::time::timeout(
                AUTHORITY_TEARDOWN_TIMEOUT,
                orchestrator.close_conversation(conversation, true),
            )
            .await;
            Err(RepositoryError::Unavailable)
        }
    }
}

async fn open_outbound_voice_session_for_start(
    orchestrator: &Arc<Orchestrator>,
    tenant_id: &crate::call_engine::TenantId,
    shutdown: &mut watch::Receiver<ActorShutdown>,
    setup_cancel: &CancellationToken,
) -> Result<Option<(ConversationId, SessionId)>, RepositoryError> {
    let conversation = match await_start_operation(
        tokio::time::timeout(
            EXTERNAL_OPERATION_TIMEOUT,
            orchestrator.open_conversation(
                RvoipTenantId::from_string(tenant_id.as_str()),
                ConversationPolicy::default(),
                HashMap::new(),
            ),
        ),
        shutdown,
        setup_cancel,
    )
    .await
    {
        StartOperationWait::Completed(Ok(Ok(conversation))) => conversation,
        StartOperationWait::CallEnding => return Ok(None),
        StartOperationWait::Completed(Ok(Err(_)))
        | StartOperationWait::Completed(Err(_))
        | StartOperationWait::AuthorityLost => return Err(RepositoryError::Unavailable),
    };
    let session = match await_start_operation(
        tokio::time::timeout(
            EXTERNAL_OPERATION_TIMEOUT,
            orchestrator.start_session(conversation.clone(), SessionMedium::Voice, Vec::new()),
        ),
        shutdown,
        setup_cancel,
    )
    .await
    {
        StartOperationWait::Completed(Ok(Ok(session))) => Some(session),
        StartOperationWait::CallEnding => None,
        StartOperationWait::Completed(Ok(Err(_)))
        | StartOperationWait::Completed(Err(_))
        | StartOperationWait::AuthorityLost => {
            let _ = tokio::time::timeout(
                AUTHORITY_TEARDOWN_TIMEOUT,
                orchestrator.close_conversation(conversation, true),
            )
            .await;
            return Err(RepositoryError::Unavailable);
        }
    };
    let Some(session) = session else {
        let _ = tokio::time::timeout(
            AUTHORITY_TEARDOWN_TIMEOUT,
            orchestrator.close_conversation(conversation, true),
        )
        .await;
        return Ok(None);
    };
    Ok(Some((conversation, session)))
}

async fn close_created_voice_session(
    orchestrator: &Arc<Orchestrator>,
    created_session: &Option<(ConversationId, SessionId)>,
) {
    let Some((conversation_id, _)) = created_session else {
        return;
    };
    let _ = tokio::time::timeout(
        AUTHORITY_TEARDOWN_TIMEOUT,
        orchestrator.close_conversation(conversation_id.clone(), true),
    )
    .await;
}

fn bounded_effect_operation_timeout(
    stored: &StoredServiceCall,
    runtime: &CallServiceRuntime,
    deadline_kind: DeadlineKind,
) -> Duration {
    stored
        .call
        .aggregate
        .deadlines()
        .get(deadline_kind)
        .due_at()
        .map(|due_at| {
            due_at
                .signed_duration_since(runtime.observation_time())
                .to_std()
                .unwrap_or(Duration::ZERO)
                .min(EXTERNAL_OPERATION_TIMEOUT)
        })
        .unwrap_or(EXTERNAL_OPERATION_TIMEOUT)
}

fn amazon_external_reference_binding(
    leg_id: LegId,
    binding_generation: crate::call_engine::BindingGeneration,
    reference: &ExternalConnectionReference,
) -> Result<ExternalReferenceBinding, RepositoryError> {
    if reference.kind() != AMAZON_CONNECT_CONTACT_REFERENCE_KIND {
        return Err(RepositoryError::InvalidInput(
            "Amazon Connect activation returned an incompatible reference",
        ));
    }
    Ok(ExternalReferenceBinding {
        leg_id,
        binding_generation,
        role: ProviderReferenceRole::Media,
        value: ExternalReferenceValue::Signaling {
            namespace: reference.kind().to_owned(),
            value: reference.expose_secret().to_owned(),
        },
    })
}

fn sip_external_reference_binding(
    leg_id: LegId,
    binding_generation: crate::call_engine::BindingGeneration,
    reference: &ExternalConnectionReference,
) -> Result<ExternalReferenceBinding, RepositoryError> {
    if reference.kind() != "sip.call-id" {
        return Err(RepositoryError::InvalidInput(
            "SIP activation returned an incompatible reference",
        ));
    }
    Ok(ExternalReferenceBinding {
        leg_id,
        binding_generation,
        role: ProviderReferenceRole::Media,
        value: ExternalReferenceValue::Signaling {
            namespace: reference.kind().to_owned(),
            value: reference.expose_secret().to_owned(),
        },
    })
}

async fn register_prepared_outbound(
    registration: &mpsc::Sender<OutboundRegistration>,
    call_id: CallId,
    binding: ActorBinding,
    complete_on_transport_connected: bool,
    created_session: Option<(ConversationId, SessionId)>,
    shutdown: &mut watch::Receiver<ActorShutdown>,
) -> Result<(), RepositoryError> {
    let (completion, completed) = oneshot::channel();
    await_while_execution_owned(
        registration.send(OutboundRegistration {
            call_id,
            binding,
            allow_parallel_generation: false,
            replacement_effect_id: None,
            complete_on_transport_connected,
            created_session,
            completion,
        }),
        shutdown,
    )
    .await
    .map_err(|()| RepositoryError::Unavailable)?
    .map_err(|_| RepositoryError::Unavailable)?;
    await_while_execution_owned(completed, shutdown)
        .await
        .map_err(|()| RepositoryError::Unavailable)?
        .map_err(|_| RepositoryError::Unavailable)?
        .map_err(|()| RepositoryError::Unavailable)
}

async fn register_prepared_replacement(
    registration: &mpsc::Sender<OutboundRegistration>,
    call_id: CallId,
    binding: ActorBinding,
    effect_id: crate::call_engine::EffectId,
    complete_on_transport_connected: bool,
    created_session: Option<(ConversationId, SessionId)>,
    shutdown: &mut watch::Receiver<ActorShutdown>,
) -> Result<(), RepositoryError> {
    let (completion, completed) = oneshot::channel();
    await_while_execution_owned(
        registration.send(OutboundRegistration {
            call_id,
            binding,
            allow_parallel_generation: true,
            replacement_effect_id: Some(effect_id),
            complete_on_transport_connected,
            created_session,
            completion,
        }),
        shutdown,
    )
    .await
    .map_err(|()| RepositoryError::Unavailable)?
    .map_err(|_| RepositoryError::Unavailable)?;
    await_while_execution_owned(completed, shutdown)
        .await
        .map_err(|()| RepositoryError::Unavailable)?
        .map_err(|_| RepositoryError::Unavailable)?
        .map_err(|()| RepositoryError::Unavailable)
}

/// Maps trusted named-route context directly into the first outbound INVITE.
/// This path is evaluated only after attach-then-dial has authenticated the
/// source leg. Browser-supplied DataChannel context continues through the
/// durable first-message path below; it cannot override these server-owned
/// values or select a route.
fn named_route_context_envelope(
    stored: &StoredServiceCall,
    target_leg_id: LegId,
) -> Result<Option<ContextEnvelope>, ()> {
    let Some(context) = stored
        .plan
        .named_route()
        .and_then(|binding| binding.context())
    else {
        return Ok(None);
    };
    let source_leg_id = stored
        .call
        .aggregate
        .legs()
        .iter()
        .find(|leg| {
            leg.id() != target_leg_id && leg.signaling_initiator() == SignalingInitiator::Remote
        })
        .map(|leg| leg.id())
        .ok_or(())?;
    let mut envelope = ContextEnvelope::new(
        context.correlation_id.clone(),
        stored.call.aggregate.tenant_id().as_str(),
        stored.call.aggregate.id().to_string(),
        source_leg_id.to_string(),
    );
    envelope.metadata.clone_from(&context.metadata);
    envelope.validate().map_err(|_| ())?;
    Ok(Some(envelope))
}

/// Build provider state only from server-owned named-route context or the
/// first durable browser context admitted for this exact call. The provider
/// state remains corroborating evidence; it never selects the route.
#[allow(clippy::too_many_arguments)]
async fn telnyx_dial_client_state(
    stored: &StoredServiceCall,
    target_leg_id: LegId,
    binding_generation: crate::call_engine::BindingGeneration,
    execution: &ProviderExecutionContext,
    role: ProviderDialRole,
    context_policy: &ContextPolicy,
    runtime: &Arc<CallServiceRuntime>,
    wait_for_browser_context: bool,
    mut shutdown: watch::Receiver<ActorShutdown>,
) -> Result<ProviderDialClientState, RepositoryError> {
    let envelope = match named_route_context_envelope(stored, target_leg_id) {
        Ok(Some(envelope)) => Some(envelope),
        Err(()) => {
            return Err(RepositoryError::InvalidInput(
                "named-route provider context is invalid",
            ))
        }
        Ok(None) => {
            let Some(source_leg_id) = direct_browser_leg_id(&stored.plan, target_leg_id) else {
                return ProviderDialClientState::new(execution, role, None, context_policy)
                    .map_err(|_| {
                        RepositoryError::InvalidInput("provider dial context is invalid")
                    });
            };
            let deadline = tokio::time::Instant::now()
                + runtime.timeouts().setup.min(EXTERNAL_OPERATION_TIMEOUT);
            loop {
                match runtime
                    .service_repository()
                    .load_initial_context(
                        &execution.tenant_id,
                        execution.call_id,
                        target_leg_id,
                        binding_generation,
                    )
                    .await
                {
                    Ok(Some(context)) => {
                        let envelope = serde_json::from_slice::<ContextEnvelope>(&context.envelope)
                            .map_err(|_| {
                                RepositoryError::InvalidInput(
                                    "retained provider context is invalid",
                                )
                            })?;
                        envelope
                            .validate_binding(
                                execution.tenant_id.as_str(),
                                &execution.call_id.to_string(),
                                &source_leg_id.to_string(),
                            )
                            .map_err(|_| {
                                RepositoryError::InvalidInput(
                                    "retained provider context ownership is invalid",
                                )
                            })?;
                        break Some(envelope);
                    }
                    Ok(None) if !wait_for_browser_context => {
                        return Err(RepositoryError::StaleClaim)
                    }
                    Ok(None) | Err(RepositoryError::Unavailable) => {
                        if tokio::time::Instant::now() >= deadline {
                            return Err(RepositoryError::Unavailable);
                        }
                        tokio::select! {
                            changed = shutdown.changed() => {
                                if changed.is_err() || *shutdown.borrow() != ActorShutdown::Running {
                                    return Err(RepositoryError::Unavailable);
                                }
                            }
                            _ = tokio::time::sleep(REPOSITORY_RETRY_MIN) => {}
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    };
    ProviderDialClientState::new(execution, role, envelope.as_ref(), context_policy)
        .map_err(|_| RepositoryError::InvalidInput("provider dial context is invalid"))
}

fn named_route_initial_sip_headers(
    stored: &StoredServiceCall,
    target_leg_id: LegId,
    policy: &ContextPolicy,
) -> Result<Option<SipInitialHeaders>, ()> {
    let Some(envelope) = named_route_context_envelope(stored, target_leg_id)? else {
        return Ok(None);
    };
    let headers = envelope.to_sip_headers(policy).map_err(|_| ())?;
    SipInitialHeaders::new(headers).map(Some).map_err(|_| ())
}

fn context_to_amazon_attributes(
    envelope: &ContextEnvelope,
    policy: &ContextPolicy,
) -> Result<BTreeMap<String, String>, ()> {
    envelope.validate().map_err(|_| ())?;
    let mut attributes = BTreeMap::new();
    if policy
        .allows_metadata_key("correlation_id")
        .map_err(|_| ())?
    {
        attributes.insert("correlation_id".into(), envelope.correlation_id.clone());
    }
    for (key, value) in &envelope.metadata {
        if policy.allows_metadata_key(key).map_err(|_| ())? {
            attributes.insert(key.clone(), value.clone());
        }
    }
    Ok(attributes)
}

fn private_egress_command(
    command_id: Uuid,
    runtime: &CallServiceRuntime,
    source: PrivateEgressSource,
    target: PrivateEgressTarget,
    operation: PrivateEgressOperation,
) -> Result<PrivateEgressCommand, ()> {
    PrivateEgressCommand::new(
        command_id,
        runtime.observation_time().timestamp_millis(),
        runtime.timeouts().setup.min(Duration::from_secs(30)),
        runtime.worker().lease,
        source,
        target,
        operation,
    )
    .map_err(|_| ())
}

fn private_egress_phase_command_id(effect_id: Uuid, phase: u8) -> Uuid {
    let mut bytes = *effect_id.as_bytes();
    bytes[15] ^= phase;
    Uuid::from_bytes(bytes)
}

async fn execute_private_egress_finish(
    private_egress: &Arc<PrivateEgressWorkerRuntime>,
    source_connection: &ConnectionId,
    staged: Option<&PrivateEgressStagedControl>,
    runtime: &CallServiceRuntime,
    source: &PrivateEgressSource,
    target: PrivateEgressTarget,
    operation: PrivateEgressOperation,
) -> Result<(), ()> {
    let command =
        private_egress_command(Uuid::new_v4(), runtime, source.clone(), target, operation)?;
    match tokio::time::timeout(
        AUTHORITY_TEARDOWN_TIMEOUT,
        private_egress
            .control()
            .execute_with_staged(source_connection.clone(), staged, command),
    )
    .await
    {
        Ok(Ok(response))
            if response.accepted && response.state == Some(PrivateEgressLifecycleState::Ended) =>
        {
            Ok(())
        }
        _ => Err(()),
    }
}

async fn best_effort_private_egress_finish(
    private_egress: &Arc<PrivateEgressWorkerRuntime>,
    source_connection: &ConnectionId,
    staged: Option<&PrivateEgressStagedControl>,
    runtime: &CallServiceRuntime,
    source: &PrivateEgressSource,
    target: PrivateEgressTarget,
    operation: PrivateEgressOperation,
) {
    let _ = execute_private_egress_finish(
        private_egress,
        source_connection,
        staged,
        runtime,
        source,
        target,
        operation,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn execute_private_egress_start_leg(
    meta: &ClaimedEffectMeta,
    stored: &StoredServiceCall,
    leg_id: LegId,
    binding_generation: crate::call_engine::BindingGeneration,
    orchestrator: &Arc<Orchestrator>,
    runtime: &Arc<CallServiceRuntime>,
    context_policy: &ContextPolicy,
    private_egress: &Arc<PrivateEgressWorkerRuntime>,
    bindings: &HashMap<LegId, ActorBinding>,
    pending_inbound_authorities: &HashMap<LegId, PendingInboundAuthority>,
    outbound_registration: Option<&mpsc::Sender<OutboundRegistration>>,
    setup_cancel: &CancellationToken,
    mut shutdown: watch::Receiver<ActorShutdown>,
) -> Result<PrivateEgressStartExecution, RepositoryError> {
    if setup_cancel.is_cancelled() {
        return Ok(PrivateEgressStartExecution::cancelled());
    }
    let principal_fingerprint = match stored.plan.authorization_principal_fingerprint() {
        Ok(principal) => principal,
        Err(_) => {
            return Ok(PrivateEgressStartExecution::failed(
                leg_id,
                binding_generation,
                "outbound_authorization_missing",
                "the persisted execution plan cannot authorize gateway egress",
                false,
            ));
        }
    };
    let Some(leg) = stored.plan.legs.iter().find(|leg| leg.leg_id == leg_id) else {
        return Ok(PrivateEgressStartExecution::failed(
            leg_id,
            binding_generation,
            "private_egress_endpoint_invalid",
            "the persisted execution plan has no gateway egress endpoint",
            false,
        ));
    };
    let (transport, profile_kind, target, binding_transport) = match &leg.endpoint {
        super::LegEndpointConfig::Sip(endpoint) => (
            PrivateEgressTransport::Sip,
            NamedProfileKind::Sip,
            endpoint.uri.clone(),
            AttachmentTransport::Sip,
        ),
        super::LegEndpointConfig::WebRtc(endpoint) => (
            PrivateEgressTransport::WebRtc,
            NamedProfileKind::WebRtc,
            endpoint.signaling_uri.clone(),
            AttachmentTransport::WebRtc,
        ),
        _ => {
            return Ok(PrivateEgressStartExecution::failed(
                leg_id,
                binding_generation,
                "private_egress_endpoint_unsupported",
                "the split gateway cannot originate this endpoint type",
                false,
            ));
        }
    };
    let Some(target) = target else {
        return Ok(PrivateEgressStartExecution::failed(
            leg_id,
            binding_generation,
            "private_egress_target_missing",
            "the server-owned gateway egress target is absent",
            false,
        ));
    };

    if let Some(durable) = stored.call.bindings.get(&leg_id) {
        if durable.binding_generation != binding_generation
            || durable.transport != binding_transport
        {
            return Err(RepositoryError::StaleClaim);
        }
        let Some(existing) = bindings.get(&leg_id) else {
            return Ok(PrivateEgressStartExecution::restarted(
                leg_id,
                binding_generation,
            ));
        };
        if existing.connection_id == durable.connection_id
            && existing.binding_generation == binding_generation
            && existing.private_egress.is_some()
            && orchestrator
                .connection_transport(&existing.connection_id)
                .is_ok_and(|transport| transport == Transport::Quic)
        {
            return Ok(PrivateEgressStartExecution {
                result: ServiceEffectResult::Succeeded,
                follow_up: FollowUpPlan::None,
            });
        }
        return Ok(PrivateEgressStartExecution::restarted(
            leg_id,
            binding_generation,
        ));
    }
    if meta.claim_generation.as_i64() > 1 && !private_egress.restart_safe() {
        return Ok(PrivateEgressStartExecution::restarted(
            leg_id,
            binding_generation,
        ));
    }
    let Some(registration) = outbound_registration else {
        return Ok(PrivateEgressStartExecution::failed(
            leg_id,
            binding_generation,
            "private_egress_owner_unavailable",
            "the gateway egress owner is unavailable",
            true,
        ));
    };
    let Some(route) = stored.plan.named_route() else {
        return Ok(PrivateEgressStartExecution::failed(
            leg_id,
            binding_generation,
            "private_egress_route_missing",
            "split egress requires an exact persisted named route",
            false,
        ));
    };
    let mut destinations = route
        .profiles()
        .iter()
        .filter(|profile| profile.role() == NamedProfileRole::Destination);
    let Some(destination) = destinations.next() else {
        return Ok(PrivateEgressStartExecution::failed(
            leg_id,
            binding_generation,
            "private_egress_profile_missing",
            "the named route has no destination profile snapshot",
            false,
        ));
    };
    if destinations.next().is_some() || destination.kind() != profile_kind {
        return Ok(PrivateEgressStartExecution::failed(
            leg_id,
            binding_generation,
            "private_egress_profile_mismatch",
            "the named route destination profile does not match its endpoint",
            false,
        ));
    }
    let profile = PrivateEgressProfile {
        profile_id: destination.profile_id().to_owned(),
        revision: destination.revision().to_owned(),
    };
    let route_descriptor = match private_egress.routes().resolve(
        stored.call.aggregate.tenant_id(),
        route.route_id(),
        transport,
        &profile,
        &target,
    ) {
        Ok(route) => route,
        Err(_) => {
            return Ok(PrivateEgressStartExecution::failed(
                leg_id,
                binding_generation,
                "private_egress_route_not_installed",
                "the exact gateway egress route revision is not installed on this worker",
                false,
            ));
        }
    };
    let codec = route_descriptor
        .codecs
        .first()
        .cloned()
        .ok_or(RepositoryError::InvalidInput(
            "private egress route has no codec",
        ))?;
    let Some((source_leg_id, source_binding)) = stored
        .plan
        .legs
        .iter()
        .find(|candidate| candidate.leg_id != leg_id)
        .and_then(|candidate| {
            bindings
                .get(&candidate.leg_id)
                .map(|binding| (candidate.leg_id, binding))
        })
    else {
        return Ok(PrivateEgressStartExecution::failed(
            leg_id,
            binding_generation,
            "private_egress_source_unavailable",
            "the authenticated gateway source leg is unavailable",
            true,
        ));
    };
    let source_durable_matches = stored
        .call
        .bindings
        .get(&source_leg_id)
        .is_some_and(|durable| {
            durable.connection_id == source_binding.connection_id
                && durable.binding_generation == source_binding.binding_generation
                && durable.principal_fingerprint == principal_fingerprint
        });
    let source_pending_matches =
        pending_inbound_authorities
            .get(&source_leg_id)
            .is_some_and(|pending| {
                pending.tenant_id == meta.tenant_id
                    && pending.call_id == meta.call_id
                    && pending.binding.connection_id == source_binding.connection_id
                    && pending.binding.leg_id == source_leg_id
                    && pending.binding.binding_generation == source_binding.binding_generation
                    && pending.binding.principal_fingerprint == principal_fingerprint
            });
    let staged_control = pending_inbound_authorities
        .get(&source_leg_id)
        .filter(|pending| {
            pending.tenant_id == meta.tenant_id
                && pending.call_id == meta.call_id
                && pending.binding.connection_id == source_binding.connection_id
                && pending.binding.binding_generation == source_binding.binding_generation
        })
        .and_then(|pending| pending.staged_private_egress.as_ref());
    if !(source_durable_matches || source_pending_matches)
        || !matches!(
            source_binding.state,
            LegState::Signaling | LegState::Connected | LegState::Held
        )
        || orchestrator
            .connection_transport(&source_binding.connection_id)
            .ok()
            != Some(Transport::Quic)
    {
        return Ok(PrivateEgressStartExecution::failed(
            leg_id,
            binding_generation,
            "private_egress_source_stale",
            "the gateway source attachment no longer owns this call",
            true,
        ));
    }
    let source = PrivateEgressSource {
        tenant_id: meta.tenant_id.clone(),
        call_id: meta.call_id,
        leg_id: source_leg_id,
        binding_generation: source_binding.binding_generation,
    };
    let target_binding = PrivateEgressTarget {
        leg_id,
        binding_generation,
    };

    let initial_context = if transport == PrivateEgressTransport::Sip {
        let initial_context_mode = stored
            .plan
            .sip_initial_context_mode(leg_id)
            .map_err(|_| RepositoryError::InvalidInput("invalid SIP context policy"))?;
        match initial_context_mode {
            SipInitialContextMode::None => Vec::new(),
            SipInitialContextMode::Required => {
                match named_route_initial_sip_headers(stored, leg_id, context_policy) {
                    Ok(Some(headers)) => headers
                        .iter()
                        .map(|(name, value)| (name.as_str().to_owned(), value.to_owned()))
                        .collect(),
                    Err(()) => {
                        return Ok(PrivateEgressStartExecution::failed(
                            leg_id,
                            binding_generation,
                            "named_route_context_invalid",
                            "the server-owned named-route context could not be mapped safely",
                            false,
                        ));
                    }
                    Ok(None) => {
                        let deadline = tokio::time::Instant::now()
                            + runtime.timeouts().setup.min(EXTERNAL_OPERATION_TIMEOUT);
                        loop {
                            if tokio::time::Instant::now() >= deadline {
                                return Ok(PrivateEgressStartExecution::failed(
                                    leg_id,
                                    binding_generation,
                                    "initial_context_timeout",
                                    "required first-INVITE context did not arrive before setup expired",
                                    true,
                                ));
                            }
                            match runtime
                                .service_repository()
                                .load_initial_context(
                                    &meta.tenant_id,
                                    meta.call_id,
                                    leg_id,
                                    binding_generation,
                                )
                                .await
                            {
                                Ok(Some(context)) => break context.initial_sip_headers,
                                Ok(None) | Err(RepositoryError::Unavailable) => {
                                    tokio::select! {
                                        _ = setup_cancel.cancelled() => {
                                            return Ok(PrivateEgressStartExecution::cancelled());
                                        }
                                        changed = shutdown.changed() => {
                                            if changed.is_err() || *shutdown.borrow() != ActorShutdown::Running {
                                                return Err(RepositoryError::Unavailable);
                                            }
                                        }
                                        _ = tokio::time::sleep(REPOSITORY_RETRY_MIN) => {}
                                    }
                                }
                                Err(RepositoryError::StaleClaim | RepositoryError::NotFound) => {
                                    return Ok(PrivateEgressStartExecution::failed(
                                        leg_id,
                                        binding_generation,
                                        "initial_context_authority_lost",
                                        "the required first-INVITE context no longer belongs to this leg",
                                        false,
                                    ));
                                }
                                Err(error) => return Err(error),
                            }
                        }
                    }
                }
            }
        }
    } else {
        Vec::new()
    };
    if setup_cancel.is_cancelled() {
        return Ok(PrivateEgressStartExecution::cancelled());
    }

    let prepare = match private_egress_command(
        meta.effect_id.as_uuid(),
        runtime,
        source.clone(),
        target_binding,
        PrivateEgressOperation::Prepare {
            transport,
            profile,
            codec,
            target,
            initial_context,
        },
    ) {
        Ok(command) => command,
        Err(()) => {
            return Ok(PrivateEgressStartExecution::failed(
                leg_id,
                binding_generation,
                "private_egress_command_invalid",
                "the exact gateway egress command could not be represented",
                false,
            ));
        }
    };
    let admission = PrivateEgressStreamAdmission::from_prepare(&prepare)
        .map_err(|_| RepositoryError::InvalidInput("private egress stream admission is invalid"))?;
    let admission_id = admission.admission_id;
    let reservation = match private_egress.admissions().reserve(admission) {
        Ok(reservation) => reservation,
        Err(_) => {
            return Ok(PrivateEgressStartExecution::failed(
                leg_id,
                binding_generation,
                "private_egress_capacity",
                "gateway egress media admission capacity is exhausted",
                true,
            ));
        }
    };
    let prepare_response = match await_start_operation(
        private_egress.control().execute_with_staged(
            source_binding.connection_id.clone(),
            staged_control,
            prepare,
        ),
        &mut shutdown,
        setup_cancel,
    )
    .await
    {
        StartOperationWait::Completed(response) => response,
        StartOperationWait::CallEnding => {
            reservation.cancel();
            best_effort_private_egress_finish(
                private_egress,
                &source_binding.connection_id,
                staged_control,
                runtime,
                &source,
                target_binding,
                PrivateEgressOperation::Abort,
            )
            .await;
            return Ok(PrivateEgressStartExecution::cancelled());
        }
        StartOperationWait::AuthorityLost => {
            reservation.cancel();
            return Err(RepositoryError::Unavailable);
        }
    };
    let prepared = matches!(
        prepare_response,
        Ok(ref response)
            if response.accepted
                && response.state == Some(PrivateEgressLifecycleState::Prepared)
    );
    if !prepared {
        match &prepare_response {
            Ok(response) => tracing::warn!(
                call_id = %meta.call_id,
                %leg_id,
                binding_generation = binding_generation.value(),
                accepted = response.accepted,
                state = ?response.state,
                failure_code = response.failure_code.as_deref().unwrap_or("none"),
                "gateway private egress prepare response was rejected"
            ),
            Err(error) => tracing::warn!(
                call_id = %meta.call_id,
                %leg_id,
                binding_generation = binding_generation.value(),
                error_code = error.code(),
                "gateway private egress prepare command failed"
            ),
        }
        reservation.cancel();
        return Ok(PrivateEgressStartExecution::failed(
            leg_id,
            binding_generation,
            "private_egress_prepare_failed",
            "the gateway could not prepare the configured destination",
            true,
        ));
    }
    let destination_connection = match await_start_operation(
        reservation.wait(runtime.timeouts().setup.min(EXTERNAL_OPERATION_TIMEOUT)),
        &mut shutdown,
        setup_cancel,
    )
    .await
    {
        StartOperationWait::Completed(result) => result,
        StartOperationWait::CallEnding => {
            best_effort_private_egress_finish(
                private_egress,
                &source_binding.connection_id,
                staged_control,
                runtime,
                &source,
                target_binding,
                PrivateEgressOperation::Abort,
            )
            .await;
            return Ok(PrivateEgressStartExecution::cancelled());
        }
        StartOperationWait::AuthorityLost => return Err(RepositoryError::Unavailable),
    };
    let destination_connection = match destination_connection {
        Ok(connection) => connection,
        Err(_) => {
            best_effort_private_egress_finish(
                private_egress,
                &source_binding.connection_id,
                staged_control,
                runtime,
                &source,
                target_binding,
                PrivateEgressOperation::Abort,
            )
            .await;
            return Ok(PrivateEgressStartExecution::failed(
                leg_id,
                binding_generation,
                "private_egress_media_timeout",
                "the gateway destination media route did not attach in time",
                true,
            ));
        }
    };
    let connection_id = destination_connection.connection_id().clone();
    if setup_cancel.is_cancelled() {
        best_effort_private_egress_finish(
            private_egress,
            &source_binding.connection_id,
            staged_control,
            runtime,
            &source,
            target_binding,
            PrivateEgressOperation::Abort,
        )
        .await;
        let _ = orchestrator
            .end_connection(connection_id, EndReason::Cancelled)
            .await;
        return Ok(PrivateEgressStartExecution::cancelled());
    }
    let durable_binding = match runtime
        .service_repository()
        .bind_outbound_connection(OutboundConnectionBind {
            operation_id: CommandId::from_uuid(meta.effect_id.as_uuid()).map_err(|_| {
                RepositoryError::InvalidInput("effect ID cannot authorize an outbound binding")
            })?,
            effect_id: meta.effect_id,
            claim_generation: meta.claim_generation,
            tenant_id: meta.tenant_id.clone(),
            call_id: meta.call_id,
            leg_id,
            binding_generation,
            worker: runtime.worker().lease,
            connection_id: connection_id.clone(),
            transport: binding_transport,
            principal_fingerprint,
            at: runtime.observation_time(),
        })
        .await
    {
        Ok(OutboundConnectionBindOutcome::Bound(binding))
        | Ok(OutboundConnectionBindOutcome::Replayed(binding)) => binding,
        Err(error) => {
            best_effort_private_egress_finish(
                private_egress,
                &source_binding.connection_id,
                staged_control,
                runtime,
                &source,
                target_binding,
                PrivateEgressOperation::Abort,
            )
            .await;
            let _ = orchestrator
                .end_connection(connection_id, EndReason::Cancelled)
                .await;
            if setup_cancel.is_cancelled() {
                return Ok(PrivateEgressStartExecution::cancelled());
            }
            return Err(error);
        }
    };
    if let Err(error) = commit_binding_state(
        runtime,
        &meta.tenant_id,
        meta.call_id,
        &durable_binding,
        LegState::Signaling,
        None,
        runtime.observation_time(),
        Some(shutdown.clone()),
    )
    .await
    {
        best_effort_private_egress_finish(
            private_egress,
            &source_binding.connection_id,
            staged_control,
            runtime,
            &source,
            target_binding,
            PrivateEgressOperation::Abort,
        )
        .await;
        let _ = orchestrator
            .end_connection(connection_id, EndReason::Cancelled)
            .await;
        if setup_cancel.is_cancelled() {
            return Ok(PrivateEgressStartExecution::cancelled());
        }
        return Err(error);
    }
    let actor_binding = ActorBinding {
        connection_id: connection_id.clone(),
        leg_id,
        binding_generation,
        state: LegState::Signaling,
        private_egress: Some(PrivateEgressBinding {
            admission_id,
            worker: runtime.worker().lease,
            source_connection: source_binding.connection_id.clone(),
            source: source.clone(),
            target: target_binding,
            _connection: destination_connection,
        }),
    };
    if register_prepared_outbound(
        registration,
        meta.call_id,
        actor_binding,
        false,
        None,
        &mut shutdown,
    )
    .await
    .is_err()
    {
        best_effort_private_egress_finish(
            private_egress,
            &source_binding.connection_id,
            staged_control,
            runtime,
            &source,
            target_binding,
            PrivateEgressOperation::Abort,
        )
        .await;
        let _ = orchestrator
            .end_connection(connection_id, EndReason::Cancelled)
            .await;
        if setup_cancel.is_cancelled() {
            return Ok(PrivateEgressStartExecution::cancelled());
        }
        return Ok(PrivateEgressStartExecution::failed(
            leg_id,
            binding_generation,
            "private_egress_owner_unavailable",
            "the call actor could not retain the gateway destination",
            true,
        ));
    }
    let activate = private_egress_command(
        Uuid::new_v4(),
        runtime,
        source.clone(),
        target_binding,
        PrivateEgressOperation::Activate,
    )
    .map_err(|_| RepositoryError::InvalidInput("private egress activate is invalid"))?;
    let activation = match await_start_operation(
        private_egress.control().execute_with_staged(
            source_binding.connection_id.clone(),
            staged_control,
            activate,
        ),
        &mut shutdown,
        setup_cancel,
    )
    .await
    {
        StartOperationWait::Completed(result) => result,
        StartOperationWait::CallEnding => {
            best_effort_private_egress_finish(
                private_egress,
                &source_binding.connection_id,
                staged_control,
                runtime,
                &source,
                target_binding,
                PrivateEgressOperation::End {
                    reason: PrivateEgressEndReason::Normal,
                },
            )
            .await;
            let _ = orchestrator
                .end_connection(connection_id, EndReason::Cancelled)
                .await;
            return Ok(PrivateEgressStartExecution::cancelled());
        }
        StartOperationWait::AuthorityLost => return Err(RepositoryError::Unavailable),
    };
    let activated = matches!(
        activation,
        Ok(ref response)
            if response.accepted && response.state == Some(PrivateEgressLifecycleState::Active)
    );
    if !activated {
        best_effort_private_egress_finish(
            private_egress,
            &source_binding.connection_id,
            staged_control,
            runtime,
            &source,
            target_binding,
            PrivateEgressOperation::Abort,
        )
        .await;
        let _ = orchestrator
            .end_connection(connection_id, EndReason::Cancelled)
            .await;
        if setup_cancel.is_cancelled() {
            return Ok(PrivateEgressStartExecution::cancelled());
        }
        return Ok(PrivateEgressStartExecution::failed(
            leg_id,
            binding_generation,
            "private_egress_activate_failed",
            "the gateway destination could not be activated",
            true,
        ));
    }
    // The private UCTP connection becomes operational before the gateway's
    // native SIP/WebRTC leg is media-ready. Its Connected event therefore
    // cannot promote the logical destination. The accepted Activate response
    // is the exact readiness boundary; commit it durably so attach-then-dial
    // may release the source answer only after native activation succeeds.
    if let Err(error) = commit_binding_state(
        runtime,
        &meta.tenant_id,
        meta.call_id,
        &durable_binding,
        LegState::Connected,
        None,
        runtime.observation_time(),
        Some(shutdown.clone()),
    )
    .await
    {
        best_effort_private_egress_finish(
            private_egress,
            &source_binding.connection_id,
            staged_control,
            runtime,
            &source,
            target_binding,
            PrivateEgressOperation::End {
                reason: PrivateEgressEndReason::Failed,
            },
        )
        .await;
        let _ = orchestrator
            .end_connection(connection_id, EndReason::Cancelled)
            .await;
        if setup_cancel.is_cancelled() {
            return Ok(PrivateEgressStartExecution::cancelled());
        }
        return Err(error);
    }
    if setup_cancel.is_cancelled() {
        best_effort_private_egress_finish(
            private_egress,
            &source_binding.connection_id,
            staged_control,
            runtime,
            &source,
            target_binding,
            PrivateEgressOperation::End {
                reason: PrivateEgressEndReason::Normal,
            },
        )
        .await;
        let _ = orchestrator
            .end_connection(connection_id, EndReason::Cancelled)
            .await;
        return Ok(PrivateEgressStartExecution::cancelled());
    }
    Ok(PrivateEgressStartExecution {
        result: ServiceEffectResult::Succeeded,
        follow_up: FollowUpPlan::None,
    })
}

#[allow(clippy::too_many_arguments)]
async fn execute_sip_start_leg(
    meta: &ClaimedEffectMeta,
    stored: &StoredServiceCall,
    leg_id: LegId,
    binding_generation: crate::call_engine::BindingGeneration,
    orchestrator: &Arc<Orchestrator>,
    runtime: &Arc<CallServiceRuntime>,
    context_policy: &ContextPolicy,
    outbound_profiles: &dyn OutboundProfileResolver,
    existing_binding: Option<&ActorBinding>,
    existing_session: Option<SessionId>,
    outbound_registration: Option<&mpsc::Sender<OutboundRegistration>>,
    setup_cancel: &CancellationToken,
    mut shutdown: watch::Receiver<ActorShutdown>,
) -> Result<SipStartExecution, RepositoryError> {
    if setup_cancel.is_cancelled() {
        return Ok(SipStartExecution::cancelled());
    }
    let principal_fingerprint = match stored.plan.authorization_principal_fingerprint() {
        Ok(principal) => principal,
        Err(_) => {
            return Ok(SipStartExecution::failed(
                leg_id,
                binding_generation,
                "outbound_authorization_missing",
                "the persisted execution plan cannot authorize outbound SIP signaling",
                false,
            ));
        }
    };
    let initial_context_mode = match stored.plan.sip_initial_context_mode(leg_id) {
        Ok(mode) => mode,
        Err(_) => {
            return Ok(SipStartExecution::failed(
                leg_id,
                binding_generation,
                "sip_endpoint_invalid",
                "the persisted execution plan has no valid SIP context policy",
                false,
            ));
        }
    };
    let initial_headers = match initial_context_mode {
        SipInitialContextMode::None => SipInitialHeaders::default(),
        SipInitialContextMode::Required => {
            match named_route_initial_sip_headers(stored, leg_id, context_policy) {
                Ok(Some(headers)) => headers,
                Err(()) => {
                    return Ok(SipStartExecution::failed(
                        leg_id,
                        binding_generation,
                        "named_route_context_invalid",
                        "the server-owned named-route context could not be mapped safely",
                        false,
                    ));
                }
                Ok(None) => {
                    let deadline = tokio::time::Instant::now()
                        + runtime.timeouts().setup.min(EXTERNAL_OPERATION_TIMEOUT);
                    loop {
                        if tokio::time::Instant::now() >= deadline {
                            return Ok(SipStartExecution::failed(
                        leg_id,
                        binding_generation,
                        "initial_context_timeout",
                        "the required first-INVITE context did not arrive before setup expired",
                        true,
                    ));
                        }
                        match runtime
                            .service_repository()
                            .load_initial_context(
                                &meta.tenant_id,
                                meta.call_id,
                                leg_id,
                                binding_generation,
                            )
                            .await
                        {
                            Ok(Some(context)) => {
                                match SipInitialHeaders::new(context.initial_sip_headers) {
                                    Ok(headers) => break headers,
                                    Err(_) => {
                                        return Ok(SipStartExecution::failed(
                                    leg_id,
                                    binding_generation,
                                    "initial_context_invalid",
                                    "the retained first-INVITE context failed SIP header validation",
                                    false,
                                ));
                                    }
                                }
                            }
                            Ok(None) | Err(RepositoryError::Unavailable) => {
                                tokio::select! {
                                    _ = setup_cancel.cancelled() => {
                                        return Ok(SipStartExecution::cancelled());
                                    }
                                    changed = shutdown.changed() => {
                                        if changed.is_err() || *shutdown.borrow() != ActorShutdown::Running {
                                            return Err(RepositoryError::Unavailable);
                                        }
                                    }
                                    _ = tokio::time::sleep(REPOSITORY_RETRY_MIN) => {}
                                }
                            }
                            Err(RepositoryError::StaleClaim | RepositoryError::NotFound) => {
                                return Ok(SipStartExecution::failed(
                            leg_id,
                            binding_generation,
                            "initial_context_authority_lost",
                            "the required first-INVITE context no longer belongs to this leg incarnation",
                            false,
                        ));
                            }
                            Err(error) => return Err(error),
                        }
                    }
                }
            }
        }
    };
    let (target, context) = match stored.plan.sip_originate_context(leg_id, initial_headers) {
        Ok(context) => context,
        Err(_) => {
            return Ok(SipStartExecution::failed(
                leg_id,
                binding_generation,
                "sip_endpoint_invalid",
                "the persisted execution plan has no valid outbound SIP endpoint",
                false,
            ));
        }
    };

    if let Some(binding) = stored.call.bindings.get(&leg_id) {
        if binding.binding_generation != binding_generation
            || binding.transport != AttachmentTransport::Sip
        {
            return Err(RepositoryError::StaleClaim);
        }
        let Some(actor_binding) = existing_binding else {
            // INVITE is not replay-safe after a process restart. The original
            // route is worker-local, so converge through the exact generation
            // failure/StopLeg path without preparing another route.
            return Ok(SipStartExecution::restarted(leg_id, binding_generation));
        };
        if actor_binding.connection_id != binding.connection_id
            || actor_binding.binding_generation != binding_generation
        {
            return Err(RepositoryError::StaleClaim);
        }
        if orchestrator
            .connection_transport(&actor_binding.connection_id)
            .is_ok_and(|transport| transport == Transport::Sip)
        {
            return Ok(SipStartExecution {
                result: ServiceEffectResult::Succeeded,
                follow_up: FollowUpPlan::None,
                external_reference: None,
            });
        }
        return Ok(SipStartExecution::failed(
            leg_id,
            binding_generation,
            "sip_route_lost",
            "the process-owned outbound SIP route ended before reconciliation",
            true,
        ));
    }

    let Some(registration) = outbound_registration else {
        return Ok(SipStartExecution::failed(
            leg_id,
            binding_generation,
            "outbound_owner_unavailable",
            "the outbound connection owner is unavailable",
            true,
        ));
    };
    let context =
        match apply_sip_outbound_profile(outbound_profiles, stored.plan.named_route(), context) {
            Ok(context) => context,
            Err(error) => {
                let failure = outbound_profile_failure(error);
                return Ok(SipStartExecution::failed(
                    leg_id,
                    binding_generation,
                    failure.code,
                    failure.message,
                    failure.retryable,
                ));
            }
        };
    let (session_id, created_session) = if let Some(session_id) = existing_session {
        (session_id, None)
    } else {
        let Some(created) = open_outbound_voice_session_for_start(
            orchestrator,
            &meta.tenant_id,
            &mut shutdown,
            setup_cancel,
        )
        .await?
        else {
            return Ok(SipStartExecution::cancelled());
        };
        (created.1.clone(), Some(created))
    };
    let request = OriginateRequest::new(
        session_id,
        ParticipantId::new(),
        target,
        Direction::Outbound,
        CapabilityDescriptor::default(),
    )
    .with_transport(Transport::Sip)
    .with_context(context);
    let prepared = match await_start_operation(
        tokio::time::timeout(
            bounded_effect_operation_timeout(stored, runtime, DeadlineKind::Setup),
            orchestrator.prepare_outbound_connection(request),
        ),
        &mut shutdown,
        setup_cancel,
    )
    .await
    {
        StartOperationWait::Completed(Ok(Ok(prepared))) => prepared,
        StartOperationWait::Completed(Ok(Err(_))) | StartOperationWait::Completed(Err(_)) => {
            close_created_voice_session(orchestrator, &created_session).await;
            return Ok(SipStartExecution::failed(
                leg_id,
                binding_generation,
                "sip_prepare_failed",
                "rvoip could not prepare the outbound SIP route",
                true,
            ));
        }
        StartOperationWait::CallEnding => {
            close_created_voice_session(orchestrator, &created_session).await;
            return Ok(SipStartExecution::cancelled());
        }
        StartOperationWait::AuthorityLost => {
            close_created_voice_session(orchestrator, &created_session).await;
            return Err(RepositoryError::Unavailable);
        }
    };
    let connection_id = prepared.connection_id().clone();
    if setup_cancel.is_cancelled() {
        let _ = prepared.abort().await;
        close_created_voice_session(orchestrator, &created_session).await;
        return Ok(SipStartExecution::cancelled());
    }
    let bind = OutboundConnectionBind {
        operation_id: CommandId::from_uuid(meta.effect_id.as_uuid()).map_err(|_| {
            RepositoryError::InvalidInput("effect ID cannot authorize an outbound binding")
        })?,
        effect_id: meta.effect_id,
        claim_generation: meta.claim_generation,
        tenant_id: meta.tenant_id.clone(),
        call_id: meta.call_id,
        leg_id,
        binding_generation,
        worker: runtime.worker().lease,
        connection_id: connection_id.clone(),
        transport: AttachmentTransport::Sip,
        principal_fingerprint,
        at: runtime.observation_time(),
    };
    let durable_binding = match runtime
        .service_repository()
        .bind_outbound_connection(bind)
        .await
    {
        Ok(OutboundConnectionBindOutcome::Bound(binding))
        | Ok(OutboundConnectionBindOutcome::Replayed(binding)) => binding,
        Err(error) => {
            let _ = prepared.abort().await;
            close_created_voice_session(orchestrator, &created_session).await;
            if setup_cancel.is_cancelled() {
                return Ok(SipStartExecution::cancelled());
            }
            return Err(error);
        }
    };
    if let Err(error) = commit_binding_state(
        runtime,
        &meta.tenant_id,
        meta.call_id,
        &durable_binding,
        LegState::Signaling,
        None,
        runtime.observation_time(),
        Some(shutdown.clone()),
    )
    .await
    {
        let _ = prepared.abort().await;
        close_created_voice_session(orchestrator, &created_session).await;
        if setup_cancel.is_cancelled() {
            return Ok(SipStartExecution::cancelled());
        }
        return Err(error);
    }
    let actor_binding = ActorBinding {
        connection_id: connection_id.clone(),
        leg_id,
        binding_generation,
        state: LegState::Signaling,
        private_egress: None,
    };
    if register_prepared_outbound(
        registration,
        meta.call_id,
        actor_binding,
        true,
        created_session.clone(),
        &mut shutdown,
    )
    .await
    .is_err()
    {
        let _ = prepared.abort().await;
        close_created_voice_session(orchestrator, &created_session).await;
        if setup_cancel.is_cancelled() {
            return Ok(SipStartExecution::cancelled());
        }
        return Ok(SipStartExecution::failed(
            leg_id,
            binding_generation,
            "outbound_owner_unavailable",
            "the outbound connection owner could not register the route",
            true,
        ));
    }

    let handle = match await_start_operation(
        tokio::time::timeout(
            bounded_effect_operation_timeout(stored, runtime, DeadlineKind::Setup),
            prepared.commit(),
        ),
        &mut shutdown,
        setup_cancel,
    )
    .await
    {
        StartOperationWait::Completed(Ok(Ok(handle))) => handle,
        StartOperationWait::Completed(Ok(Err(_))) => {
            return Ok(SipStartExecution::failed(
                leg_id,
                binding_generation,
                "sip_start_failed",
                "outbound SIP signaling activation failed",
                true,
            ));
        }
        StartOperationWait::Completed(Err(_)) => {
            return Ok(SipStartExecution::failed(
                leg_id,
                binding_generation,
                "sip_start_timeout",
                "outbound SIP signaling exceeded the call setup deadline",
                true,
            ));
        }
        StartOperationWait::CallEnding => {
            return Ok(SipStartExecution::cancelled());
        }
        StartOperationWait::AuthorityLost => return Err(RepositoryError::Unavailable),
    };
    if setup_cancel.is_cancelled() {
        let _ = orchestrator
            .end_connection(connection_id, EndReason::BridgeTorn)
            .await;
        return Ok(SipStartExecution::cancelled());
    }
    let external_reference = match handle.outbound_activation().external_references() {
        [reference] => sip_external_reference_binding(leg_id, binding_generation, reference),
        _ => Err(RepositoryError::InvalidInput(
            "SIP activation returned no durable Call-ID",
        )),
    };
    match external_reference {
        Ok(external_reference) => Ok(SipStartExecution {
            result: ServiceEffectResult::Succeeded,
            follow_up: FollowUpPlan::None,
            external_reference: Some(external_reference),
        }),
        Err(_) => {
            let _ = orchestrator
                .end_connection(connection_id, EndReason::BridgeTorn)
                .await;
            Ok(SipStartExecution::failed(
                leg_id,
                binding_generation,
                "sip_call_id_missing",
                "SIP activation returned no durable Call-ID",
                false,
            ))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_web_rtc_start_leg(
    meta: &ClaimedEffectMeta,
    stored: &StoredServiceCall,
    leg_id: LegId,
    binding_generation: crate::call_engine::BindingGeneration,
    orchestrator: &Arc<Orchestrator>,
    runtime: &Arc<CallServiceRuntime>,
    outbound_profiles: &dyn OutboundProfileResolver,
    existing_binding: Option<&ActorBinding>,
    existing_session: Option<SessionId>,
    outbound_registration: Option<&mpsc::Sender<OutboundRegistration>>,
    setup_cancel: &CancellationToken,
    mut shutdown: watch::Receiver<ActorShutdown>,
) -> Result<WebRtcStartExecution, RepositoryError> {
    if setup_cancel.is_cancelled() {
        return Ok(WebRtcStartExecution::cancelled());
    }
    let principal_fingerprint = match stored.plan.authorization_principal_fingerprint() {
        Ok(principal) => principal,
        Err(_) => {
            return Ok(WebRtcStartExecution::failed(
                leg_id,
                binding_generation,
                "outbound_authorization_missing",
                "the persisted execution plan cannot authorize outbound WebRTC signaling",
                false,
            ));
        }
    };
    let context: WebRtcOriginateContext = match stored.plan.web_rtc_originate_context(leg_id) {
        Ok(context) => context,
        Err(_) => {
            return Ok(WebRtcStartExecution::failed(
                leg_id,
                binding_generation,
                "webrtc_endpoint_invalid",
                "the persisted execution plan has no valid outbound WebRTC endpoint",
                false,
            ));
        }
    };

    if let Some(binding) = stored.call.bindings.get(&leg_id) {
        if binding.binding_generation != binding_generation
            || binding.transport != AttachmentTransport::WebRtc
        {
            return Err(RepositoryError::StaleClaim);
        }
        let Some(actor_binding) = existing_binding else {
            // A prepared/activated WebRTC route is process-owned and its
            // one-shot signaling exchange is not replay-safe. Complete the
            // ambiguous StartLeg once, then converge through FailLeg and the
            // generation-matched StopLeg path.
            return Ok(WebRtcStartExecution::restarted(leg_id, binding_generation));
        };
        if actor_binding.connection_id != binding.connection_id
            || actor_binding.binding_generation != binding_generation
        {
            return Err(RepositoryError::StaleClaim);
        }
        if orchestrator
            .connection_transport(&actor_binding.connection_id)
            .is_ok_and(|transport| transport == Transport::WebRtc)
        {
            // The result write may have been interrupted after activation.
            // Never replay the route's POST/WebSocket handshake.
            return Ok(WebRtcStartExecution {
                result: ServiceEffectResult::Succeeded,
                follow_up: FollowUpPlan::None,
            });
        }
        return Ok(WebRtcStartExecution::failed(
            leg_id,
            binding_generation,
            "webrtc_route_lost",
            "the process-owned outbound WebRTC route ended before reconciliation",
            true,
        ));
    }

    let Some(registration) = outbound_registration else {
        return Ok(WebRtcStartExecution::failed(
            leg_id,
            binding_generation,
            "outbound_owner_unavailable",
            "the outbound connection owner is unavailable",
            true,
        ));
    };
    let context = match apply_webrtc_outbound_profile(
        outbound_profiles,
        stored.plan.named_route(),
        context,
    ) {
        Ok(context) => context,
        Err(error) => {
            let failure = outbound_profile_failure(error);
            return Ok(WebRtcStartExecution::failed(
                leg_id,
                binding_generation,
                failure.code,
                failure.message,
                failure.retryable,
            ));
        }
    };
    let (session_id, created_session) = if let Some(session_id) = existing_session {
        (session_id, None)
    } else {
        let Some(created) = open_outbound_voice_session_for_start(
            orchestrator,
            &meta.tenant_id,
            &mut shutdown,
            setup_cancel,
        )
        .await?
        else {
            return Ok(WebRtcStartExecution::cancelled());
        };
        (created.1.clone(), Some(created))
    };
    let target = context.endpoint().as_str().to_owned();
    let capabilities = match orchestrator.adapter(Transport::WebRtc) {
        Ok(adapter) => adapter.capabilities(),
        Err(_) => {
            close_created_voice_session(orchestrator, &created_session).await;
            return Ok(WebRtcStartExecution::failed(
                leg_id,
                binding_generation,
                "webrtc_adapter_unavailable",
                "the registered WebRTC adapter is unavailable",
                true,
            ));
        }
    };
    let request = OriginateRequest::new(
        session_id,
        ParticipantId::new(),
        target,
        Direction::Outbound,
        capabilities,
    )
    .with_transport(Transport::WebRtc)
    .with_context(context);
    let prepared = match await_start_operation(
        tokio::time::timeout(
            bounded_effect_operation_timeout(stored, runtime, DeadlineKind::Setup),
            orchestrator.prepare_outbound_connection(request),
        ),
        &mut shutdown,
        setup_cancel,
    )
    .await
    {
        StartOperationWait::Completed(Ok(Ok(prepared))) => prepared,
        StartOperationWait::Completed(Ok(Err(_))) | StartOperationWait::Completed(Err(_)) => {
            close_created_voice_session(orchestrator, &created_session).await;
            return Ok(WebRtcStartExecution::failed(
                leg_id,
                binding_generation,
                "webrtc_prepare_failed",
                "rvoip could not prepare the outbound WebRTC route",
                true,
            ));
        }
        StartOperationWait::CallEnding => {
            close_created_voice_session(orchestrator, &created_session).await;
            return Ok(WebRtcStartExecution::cancelled());
        }
        StartOperationWait::AuthorityLost => {
            close_created_voice_session(orchestrator, &created_session).await;
            return Err(RepositoryError::Unavailable);
        }
    };
    let connection_id = prepared.connection_id().clone();
    if setup_cancel.is_cancelled() {
        let _ = prepared.abort().await;
        close_created_voice_session(orchestrator, &created_session).await;
        return Ok(WebRtcStartExecution::cancelled());
    }
    let bind = OutboundConnectionBind {
        operation_id: CommandId::from_uuid(meta.effect_id.as_uuid()).map_err(|_| {
            RepositoryError::InvalidInput("effect ID cannot authorize an outbound binding")
        })?,
        effect_id: meta.effect_id,
        claim_generation: meta.claim_generation,
        tenant_id: meta.tenant_id.clone(),
        call_id: meta.call_id,
        leg_id,
        binding_generation,
        worker: runtime.worker().lease,
        connection_id: connection_id.clone(),
        transport: AttachmentTransport::WebRtc,
        principal_fingerprint,
        at: runtime.observation_time(),
    };
    let durable_binding = match runtime
        .service_repository()
        .bind_outbound_connection(bind)
        .await
    {
        Ok(OutboundConnectionBindOutcome::Bound(binding))
        | Ok(OutboundConnectionBindOutcome::Replayed(binding)) => binding,
        Err(error) => {
            let _ = prepared.abort().await;
            close_created_voice_session(orchestrator, &created_session).await;
            if setup_cancel.is_cancelled() {
                return Ok(WebRtcStartExecution::cancelled());
            }
            return Err(error);
        }
    };
    if let Err(error) = commit_binding_state(
        runtime,
        &meta.tenant_id,
        meta.call_id,
        &durable_binding,
        LegState::Signaling,
        None,
        runtime.observation_time(),
        Some(shutdown.clone()),
    )
    .await
    {
        let _ = prepared.abort().await;
        close_created_voice_session(orchestrator, &created_session).await;
        if setup_cancel.is_cancelled() {
            return Ok(WebRtcStartExecution::cancelled());
        }
        return Err(error);
    }
    let actor_binding = ActorBinding {
        connection_id: connection_id.clone(),
        leg_id,
        binding_generation,
        state: LegState::Signaling,
        private_egress: None,
    };
    if register_prepared_outbound(
        registration,
        meta.call_id,
        actor_binding,
        true,
        created_session.clone(),
        &mut shutdown,
    )
    .await
    .is_err()
    {
        let _ = prepared.abort().await;
        close_created_voice_session(orchestrator, &created_session).await;
        if setup_cancel.is_cancelled() {
            return Ok(WebRtcStartExecution::cancelled());
        }
        return Ok(WebRtcStartExecution::failed(
            leg_id,
            binding_generation,
            "outbound_owner_unavailable",
            "the outbound connection owner could not register the route",
            true,
        ));
    }

    match await_start_operation(
        tokio::time::timeout(
            bounded_effect_operation_timeout(stored, runtime, DeadlineKind::Setup),
            prepared.commit(),
        ),
        &mut shutdown,
        setup_cancel,
    )
    .await
    {
        StartOperationWait::Completed(Ok(Ok(_))) if setup_cancel.is_cancelled() => {
            let _ = orchestrator
                .end_connection(connection_id, EndReason::BridgeTorn)
                .await;
            Ok(WebRtcStartExecution::cancelled())
        }
        StartOperationWait::Completed(Ok(Ok(_))) => Ok(WebRtcStartExecution {
            result: ServiceEffectResult::Succeeded,
            follow_up: FollowUpPlan::None,
        }),
        StartOperationWait::Completed(Ok(Err(_))) => Ok(WebRtcStartExecution::failed(
            leg_id,
            binding_generation,
            "webrtc_start_failed",
            "outbound WebRTC signaling activation failed",
            true,
        )),
        StartOperationWait::Completed(Err(_)) => Ok(WebRtcStartExecution::failed(
            leg_id,
            binding_generation,
            "webrtc_start_timeout",
            "outbound WebRTC signaling exceeded the call setup deadline",
            true,
        )),
        StartOperationWait::CallEnding => Ok(WebRtcStartExecution::cancelled()),
        StartOperationWait::AuthorityLost => Err(RepositoryError::Unavailable),
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_amazon_start_leg(
    meta: &ClaimedEffectMeta,
    stored: &StoredServiceCall,
    leg_id: LegId,
    binding_generation: crate::call_engine::BindingGeneration,
    orchestrator: &Arc<Orchestrator>,
    runtime: &Arc<CallServiceRuntime>,
    context_policy: &ContextPolicy,
    amazon_connect: Option<&Arc<AmazonConnectAdapter>>,
    existing_session: Option<SessionId>,
    outbound_registration: Option<&mpsc::Sender<OutboundRegistration>>,
    setup_cancel: &CancellationToken,
    mut shutdown: watch::Receiver<ActorShutdown>,
) -> Result<AmazonStartExecution, RepositoryError> {
    if setup_cancel.is_cancelled() && !stored.call.bindings.contains_key(&leg_id) {
        return Ok(AmazonStartExecution::cancelled(None));
    }
    let spec = stored.plan.amazon_connect_start_spec(leg_id)?;
    let context_attributes = match named_route_context_envelope(stored, leg_id) {
        Ok(Some(envelope)) => match context_to_amazon_attributes(&envelope, context_policy) {
            Ok(attributes) => attributes,
            Err(()) => {
                return Ok(AmazonStartExecution::failed(
                    leg_id,
                    binding_generation,
                    "amazon_connect_context_invalid",
                    "the server-owned Amazon Connect context could not be mapped safely",
                    false,
                ));
            }
        },
        Err(()) => {
            return Ok(AmazonStartExecution::failed(
                leg_id,
                binding_generation,
                "amazon_connect_context_invalid",
                "the server-owned Amazon Connect context is invalid",
                false,
            ));
        }
        Ok(None)
            if stored.plan.named_route().is_some()
                && direct_browser_leg_id(&stored.plan, leg_id).is_some() =>
        {
            let source_leg_id = direct_browser_leg_id(&stored.plan, leg_id).ok_or(
                RepositoryError::InvalidInput("direct browser source leg missing"),
            )?;
            let deadline = tokio::time::Instant::now()
                + runtime.timeouts().setup.min(EXTERNAL_OPERATION_TIMEOUT);
            loop {
                if tokio::time::Instant::now() >= deadline {
                    return Ok(AmazonStartExecution::failed(
                        leg_id,
                        binding_generation,
                        "amazon_connect_initial_context_timeout",
                        "the required Amazon Connect screen-pop context did not arrive before setup expired",
                        true,
                    ));
                }
                match runtime
                    .service_repository()
                    .load_initial_context(&meta.tenant_id, meta.call_id, leg_id, binding_generation)
                    .await
                {
                    Ok(Some(context)) => {
                        let envelope = serde_json::from_slice::<ContextEnvelope>(&context.envelope)
                            .map_err(|_| {
                                RepositoryError::InvalidInput(
                                    "retained Amazon Connect context is invalid",
                                )
                            })?;
                        if envelope
                            .validate_binding(
                                meta.tenant_id.as_str(),
                                &meta.call_id.to_string(),
                                &source_leg_id.to_string(),
                            )
                            .is_err()
                        {
                            return Ok(AmazonStartExecution::failed(
                                leg_id,
                                binding_generation,
                                "amazon_connect_context_ownership_invalid",
                                "the retained Amazon Connect context does not own this call",
                                false,
                            ));
                        }
                        match context_to_amazon_attributes(&envelope, context_policy) {
                            Ok(attributes) => break attributes,
                            Err(()) => {
                                return Ok(AmazonStartExecution::failed(
                                    leg_id,
                                    binding_generation,
                                    "amazon_connect_context_invalid",
                                    "the retained Amazon Connect context could not be mapped safely",
                                    false,
                                ));
                            }
                        }
                    }
                    Ok(None) | Err(RepositoryError::Unavailable) => {
                        tokio::select! {
                            _ = setup_cancel.cancelled() => {
                                return Ok(AmazonStartExecution::cancelled(None));
                            }
                            changed = shutdown.changed() => {
                                if changed.is_err() || *shutdown.borrow() != ActorShutdown::Running {
                                    return Err(RepositoryError::Unavailable);
                                }
                            }
                            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(None) => BTreeMap::new(),
    };
    let context = spec.originate_context_with_attributes(meta.effect_id, context_attributes)?;
    let Some(adapter) = amazon_connect else {
        return Ok(AmazonStartExecution::failed(
            leg_id,
            binding_generation,
            "amazon_connect_not_configured",
            "Amazon Connect outbound execution is not configured",
            false,
        ));
    };

    if let Some(binding) = stored.call.bindings.get(&leg_id) {
        if binding.binding_generation != binding_generation
            || binding.transport != AttachmentTransport::WebRtc
        {
            return Err(RepositoryError::StaleClaim);
        }
        let mut recovered =
            await_while_execution_owned(adapter.recover_contact(&context), &mut shutdown)
                .await
                .map_err(|()| RepositoryError::Unavailable)?
                .map_err(|_| RepositoryError::Unavailable)?;
        let external_reference = amazon_external_reference_binding(
            leg_id,
            binding_generation,
            recovered.external_reference(),
        )?;
        // Persist the reference even when this eager stop exhausts its bounded
        // retries. The resulting StopLeg effect invokes exact persisted
        // cleanup again and the adapter also retains failed cleanup authority.
        let _ = await_while_execution_owned(recovered.stop(), &mut shutdown).await;
        let follow_up = stored
            .call
            .aggregate
            .leg(leg_id)
            .filter(|leg| !leg.state().is_terminal())
            .map_or(FollowUpPlan::None, |_| FollowUpPlan::FailLeg {
                leg_id,
                binding_generation,
                failure: FailureDetails::sanitized(
                    "worker_restarted",
                    "an ambiguously started Amazon contact was recovered after worker restart",
                    true,
                ),
            });
        return Ok(AmazonStartExecution {
            result: ServiceEffectResult::Succeeded,
            follow_up,
            external_reference: Some(external_reference),
        });
    }

    let Some(registration) = outbound_registration else {
        return Ok(AmazonStartExecution::failed(
            leg_id,
            binding_generation,
            "outbound_owner_unavailable",
            "the outbound connection owner is unavailable",
            true,
        ));
    };
    let (session_id, created_session) = if let Some(session_id) = existing_session {
        (session_id, None)
    } else {
        let Some(created) = open_outbound_voice_session_for_start(
            orchestrator,
            &meta.tenant_id,
            &mut shutdown,
            setup_cancel,
        )
        .await?
        else {
            return Ok(AmazonStartExecution::cancelled(None));
        };
        (created.1.clone(), Some(created))
    };
    let request = OriginateRequest::new(
        session_id,
        ParticipantId::new(),
        "amazon-connect",
        Direction::Outbound,
        CapabilityDescriptor::default(),
    )
    .with_transport(Transport::AmazonConnect)
    .with_context(context);
    let prepared = match await_start_operation(
        tokio::time::timeout(
            bounded_effect_operation_timeout(stored, runtime, DeadlineKind::Setup),
            orchestrator.prepare_outbound_connection(request),
        ),
        &mut shutdown,
        setup_cancel,
    )
    .await
    {
        StartOperationWait::Completed(Ok(Ok(prepared))) => prepared,
        StartOperationWait::Completed(Ok(Err(_))) | StartOperationWait::Completed(Err(_)) => {
            close_created_voice_session(orchestrator, &created_session).await;
            return Ok(AmazonStartExecution::failed(
                leg_id,
                binding_generation,
                "amazon_connect_prepare_failed",
                "rvoip could not prepare the Amazon Connect route",
                true,
            ));
        }
        StartOperationWait::CallEnding => {
            close_created_voice_session(orchestrator, &created_session).await;
            return Ok(AmazonStartExecution::cancelled(None));
        }
        StartOperationWait::AuthorityLost => {
            close_created_voice_session(orchestrator, &created_session).await;
            return Err(RepositoryError::Unavailable);
        }
    };
    let connection_id = prepared.connection_id().clone();
    if setup_cancel.is_cancelled() {
        let _ = prepared.abort().await;
        close_created_voice_session(orchestrator, &created_session).await;
        return Ok(AmazonStartExecution::cancelled(None));
    }
    let principal_fingerprint = stored.plan.authorization_principal_fingerprint()?;
    let bind = OutboundConnectionBind {
        operation_id: CommandId::from_uuid(meta.effect_id.as_uuid()).map_err(|_| {
            RepositoryError::InvalidInput("effect ID cannot authorize an outbound binding")
        })?,
        effect_id: meta.effect_id,
        claim_generation: meta.claim_generation,
        tenant_id: meta.tenant_id.clone(),
        call_id: meta.call_id,
        leg_id,
        binding_generation,
        worker: runtime.worker().lease,
        connection_id: connection_id.clone(),
        transport: AttachmentTransport::WebRtc,
        principal_fingerprint,
        at: runtime.observation_time(),
    };
    let durable_binding = match runtime
        .service_repository()
        .bind_outbound_connection(bind)
        .await
    {
        Ok(OutboundConnectionBindOutcome::Bound(binding))
        | Ok(OutboundConnectionBindOutcome::Replayed(binding)) => binding,
        Err(error) => {
            let _ = prepared.abort().await;
            close_created_voice_session(orchestrator, &created_session).await;
            if setup_cancel.is_cancelled() {
                return Ok(AmazonStartExecution::cancelled(None));
            }
            return Err(error);
        }
    };
    if let Err(error) = commit_binding_state(
        runtime,
        &meta.tenant_id,
        meta.call_id,
        &durable_binding,
        LegState::Signaling,
        None,
        runtime.observation_time(),
        Some(shutdown.clone()),
    )
    .await
    {
        let _ = prepared.abort().await;
        close_created_voice_session(orchestrator, &created_session).await;
        if setup_cancel.is_cancelled() {
            return Ok(AmazonStartExecution::cancelled(None));
        }
        return Err(error);
    }
    let actor_binding = ActorBinding {
        connection_id: connection_id.clone(),
        leg_id,
        binding_generation,
        state: LegState::Signaling,
        private_egress: None,
    };
    if register_prepared_outbound(
        registration,
        meta.call_id,
        actor_binding,
        true,
        created_session.clone(),
        &mut shutdown,
    )
    .await
    .is_err()
    {
        let _ = prepared.abort().await;
        close_created_voice_session(orchestrator, &created_session).await;
        if setup_cancel.is_cancelled() {
            return Ok(AmazonStartExecution::cancelled(None));
        }
        return Ok(AmazonStartExecution::failed(
            leg_id,
            binding_generation,
            "outbound_owner_unavailable",
            "the outbound connection owner could not register the route",
            true,
        ));
    }

    // Amazon retains its adapter-owned signaling/cleanup deadline, while the
    // outer call setup deadline prevents a blocked contact start from
    // starving the call actor's durable timeout/cleanup work.
    let handle = match await_start_operation(
        tokio::time::timeout(
            bounded_effect_operation_timeout(stored, runtime, DeadlineKind::Setup),
            prepared.commit(),
        ),
        &mut shutdown,
        setup_cancel,
    )
    .await
    {
        StartOperationWait::Completed(Ok(Ok(handle))) => handle,
        StartOperationWait::Completed(Ok(Err(_))) => {
            return Ok(AmazonStartExecution::failed(
                leg_id,
                binding_generation,
                "amazon_connect_start_failed",
                "Amazon Connect activation failed",
                true,
            ));
        }
        StartOperationWait::Completed(Err(_)) => {
            return Ok(AmazonStartExecution::failed(
                leg_id,
                binding_generation,
                "amazon_connect_start_timeout",
                "Amazon Connect activation exceeded the call setup deadline",
                true,
            ));
        }
        StartOperationWait::CallEnding => {
            return Ok(AmazonStartExecution::cancelled(None));
        }
        StartOperationWait::AuthorityLost => return Err(RepositoryError::Unavailable),
    };
    let references = handle.outbound_activation().external_references();
    let external_reference = match references {
        [reference] => amazon_external_reference_binding(leg_id, binding_generation, reference),
        _ => Err(RepositoryError::InvalidInput(
            "Amazon Connect activation returned an incompatible reference set",
        )),
    };
    match external_reference {
        Ok(external_reference) if setup_cancel.is_cancelled() => {
            let _ = orchestrator
                .end_connection(connection_id, EndReason::BridgeTorn)
                .await;
            Ok(AmazonStartExecution::cancelled(Some(external_reference)))
        }
        Ok(external_reference) => Ok(AmazonStartExecution {
            result: ServiceEffectResult::Succeeded,
            follow_up: FollowUpPlan::None,
            external_reference: Some(external_reference),
        }),
        Err(_) => {
            let _ = orchestrator
                .end_connection(connection_id, EndReason::BridgeTorn)
                .await;
            Ok(AmazonStartExecution::failed(
                leg_id,
                binding_generation,
                "amazon_connect_reference_invalid",
                "Amazon Connect activation returned no durable contact identity",
                false,
            ))
        }
    }
}

async fn stop_persisted_amazon_contact(
    meta: &ClaimedEffectMeta,
    stored: &StoredServiceCall,
    leg_id: LegId,
    binding_generation: crate::call_engine::BindingGeneration,
    runtime: &Arc<CallServiceRuntime>,
    amazon_connect: Option<&Arc<AmazonConnectAdapter>>,
    mut shutdown: watch::Receiver<ActorShutdown>,
) -> Result<(), ()> {
    let reference = runtime
        .service_repository()
        .load_external_reference_for_binding(
            &meta.tenant_id,
            meta.call_id,
            leg_id,
            binding_generation,
            ProviderReferenceRole::Media,
        )
        .await
        .map_err(|_| ())?;
    let Some(reference) = reference else {
        return Ok(());
    };
    let ExternalReferenceValue::Signaling { namespace, value } = reference.value else {
        return Ok(());
    };
    if namespace != AMAZON_CONNECT_CONTACT_REFERENCE_KIND {
        return Ok(());
    }
    let replacement_payload = runtime
        .service_repository()
        .load_effect_payload(&meta.tenant_id, reference.effect_id)
        .await
        .map_err(|_| ())?;
    let replacement_spec = replacement_payload.and_then(|payload| match payload.payload {
        ServiceEffectPayload::LegReplacement {
            leg_id: payload_leg_id,
            pending_binding_generation,
            endpoint: super::LegEndpointConfig::AmazonConnect(_),
            amazon_connect_start: Some(spec),
            ..
        } if payload_leg_id == leg_id && pending_binding_generation == binding_generation => {
            Some(spec)
        }
        _ => None,
    });
    let spec = match replacement_spec {
        Some(spec) => spec,
        None => stored
            .plan
            .legs
            .iter()
            .find(|leg| leg.leg_id == leg_id)
            .and_then(|leg| match leg.endpoint {
                super::LegEndpointConfig::AmazonConnect(_) => {
                    stored.plan.amazon_connect_start_spec(leg_id).ok().cloned()
                }
                _ => None,
            })
            .ok_or(())?,
    };
    let adapter = amazon_connect.ok_or(())?;
    let profile = ConnectProfileId::new(spec.profile().to_owned()).map_err(|_| ())?;
    let external_reference = ExternalConnectionReference::new(namespace, value).map_err(|_| ())?;
    await_while_execution_owned(
        adapter.stop_persisted_contact(&profile, spec.instance_id(), &external_reference),
        &mut shutdown,
    )
    .await?
    .map_err(|_| ())
}

async fn execute_call_effect(
    claim: ClaimedOutbox,
    context: ActorWorkExecutionContext,
) -> WorkOperationResult {
    let ActorWorkExecutionContext {
        orchestrator,
        runtime,
        provider_executor,
        amazon_connect,
        context_policy,
        outbound_profiles,
        private_egress,
        bindings,
        pending_inbound_authorities,
        pending_replacement_bindings,
        replaced_bindings,
        bridge_id,
        session_id,
        outbound_registration,
        setup_cancel,
        shutdown,
    } = context;
    let effect_id = claim.record.effect_id;
    let effect_intent = claim.record.intent.clone();
    let meta = ClaimedEffectMeta {
        tenant_id: claim.record.tenant_id.clone(),
        call_id: claim.record.call_id,
        effect_id,
        claim_generation: claim.claim_generation,
    };
    tracing::debug!(
        call_id = %meta.call_id,
        %effect_id,
        claim_generation = ?meta.claim_generation,
        intent = ?effect_intent,
        "starting durable call effect"
    );
    let current = runtime
        .service_repository()
        .load_service_call(&meta.tenant_id, meta.call_id)
        .await;
    if let Ok(stored) = &current {
        let requires_amazon_recovery = matches!(
            &claim.record.intent,
            EffectIntent::StartLeg {
                leg_id,
                kind: crate::call_engine::LegKind::AmazonConnect,
                ..
            } if stored.call.bindings.contains_key(leg_id)
        );
        let is_setup_effect = matches!(
            &claim.record.intent,
            EffectIntent::StartLeg { .. } | EffectIntent::ConnectProviderDestination { .. }
        );
        let cancelled_setup_effect = is_setup_effect
            && (setup_cancel.is_cancelled()
                || stored.call.aggregate.state() != CallState::Connecting)
            && !requires_amazon_recovery;
        if cancelled_setup_effect {
            return WorkOperationResult {
                effect_id: Some(effect_id),
                bridge_update: None,
                handoff_signal: None,
                result: reconcile_effect(
                    meta,
                    ServiceEffectResult::Succeeded,
                    FollowUpPlan::None,
                    runtime,
                    shutdown,
                )
                .await,
            };
        }
        if stored.call.aggregate.state().is_terminal()
            && !requires_amazon_recovery
            && !is_terminal_cleanup_effect(&claim.record.intent)
        {
            let result = if matches!(
                claim.record.intent,
                EffectIntent::StartLeg { .. }
                    | EffectIntent::ConnectProviderDestination { .. }
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
                handoff_signal: None,
                result: reconcile_effect(meta, result, FollowUpPlan::None, runtime, shutdown).await,
            };
        }
    } else if let Err(error) = current {
        return WorkOperationResult {
            effect_id: Some(effect_id),
            bridge_update: None,
            handoff_signal: None,
            result: Err(error),
        };
    }
    let stored = match current {
        Ok(stored) => stored,
        Err(error) => {
            return WorkOperationResult {
                effect_id: Some(effect_id),
                bridge_update: None,
                handoff_signal: None,
                result: Err(error),
            };
        }
    };
    let mut bridge_update = None;
    let mut external_reference = None;
    let mut additional_external_references = Vec::new();
    let (result, follow_up) = match claim.record.intent {
        EffectIntent::AwaitLegAttachment { .. }
        | EffectIntent::ScheduleDeadline { .. }
        | EffectIntent::CancelDeadline { .. }
        | EffectIntent::CompensateTransfer { .. } => {
            (ServiceEffectResult::Succeeded, FollowUpPlan::None)
        }
        EffectIntent::AbortLegReplacement {
            leg_id,
            pending_binding_generation,
        } => {
            let provider_result = match load_provider_media_for_binding(
                &runtime,
                &stored,
                &meta.tenant_id,
                meta.call_id,
                leg_id,
                pending_binding_generation,
            )
            .await
            {
                Ok((endpoint, media_call)) => tokio::time::timeout(
                    EXTERNAL_OPERATION_TIMEOUT,
                    provider_executor.hangup(ProviderHangupRequest {
                        context: ProviderExecutionContext {
                            tenant_id: meta.tenant_id.clone(),
                            call_id: meta.call_id,
                            leg_id,
                            binding_generation: pending_binding_generation,
                            effect_id,
                        },
                        endpoint,
                        media_call,
                    }),
                )
                .await
                .map_err(|_| ProviderExecutionError::Remote { retryable: true })
                .and_then(|result| result),
                Err(ProviderExecutionError::InvalidRequest) => Ok(()),
                Err(error) => Err(error),
            };
            let amazon_result = stop_persisted_amazon_contact(
                &meta,
                &stored,
                leg_id,
                pending_binding_generation,
                &runtime,
                amazon_connect.as_ref(),
                shutdown.clone(),
            )
            .await;
            let transport_result = match pending_replacement_bindings.get(&leg_id) {
                Some(pending)
                    if pending.binding.binding_generation == pending_binding_generation =>
                {
                    let private_result = match (
                        private_egress.as_ref(),
                        pending.binding.private_egress.as_ref(),
                    ) {
                        (Some(private_egress), Some(route))
                            if orchestrator
                                .connection_transport(&route.source_connection)
                                .is_ok_and(|transport| transport == Transport::Quic) =>
                        {
                            execute_private_egress_finish(
                                private_egress,
                                &route.source_connection,
                                None,
                                &runtime,
                                &route.source,
                                route.target,
                                PrivateEgressOperation::Abort,
                            )
                            .await
                        }
                        _ => Ok(()),
                    };
                    let connection_result = tokio::time::timeout(
                        EXTERNAL_OPERATION_TIMEOUT,
                        orchestrator.end_connection(
                            pending.binding.connection_id.clone(),
                            EndReason::Cancelled,
                        ),
                    )
                    .await
                    .map_err(|_| ())
                    .and_then(|result| result.map_err(|_| ()));
                    private_result.and(connection_result)
                }
                _ => Ok(()),
            };
            match (provider_result, amazon_result, transport_result) {
                (Ok(()), Ok(()), Ok(())) => (ServiceEffectResult::Succeeded, FollowUpPlan::None),
                (Err(error), _, _) => (
                    ServiceEffectResult::Failed(provider_execution_failure(
                        "replacement_provider_stop_failed",
                        error,
                    )),
                    FollowUpPlan::None,
                ),
                (_, Err(()), _) => (
                    ServiceEffectResult::Failed(FailureDetails::sanitized(
                        "replacement_amazon_stop_failed",
                        "the pending Amazon replacement contact could not be retired",
                        true,
                    )),
                    FollowUpPlan::None,
                ),
                (_, _, Err(())) => (
                    ServiceEffectResult::Failed(FailureDetails::sanitized(
                        "replacement_abort_failed",
                        "the pending replacement route could not be retired",
                        true,
                    )),
                    FollowUpPlan::None,
                ),
            }
        }
        EffectIntent::StartLegReplacement {
            leg_id,
            previous_binding_generation,
            deadline_generation,
            pending_binding_generation,
            ..
        } => match execute_start_leg_replacement(
            &meta,
            &stored,
            leg_id,
            previous_binding_generation,
            pending_binding_generation,
            deadline_generation,
            &orchestrator,
            &runtime,
            &provider_executor,
            context_policy.as_ref(),
            outbound_profiles.as_ref(),
            amazon_connect.as_ref(),
            private_egress.as_ref(),
            &bindings,
            pending_replacement_bindings.get(&leg_id),
            session_id,
            outbound_registration.as_ref(),
            shutdown.clone(),
        )
        .await
        {
            Ok(execution) => {
                external_reference = execution.external_reference;
                additional_external_references = execution.additional_external_references;
                (execution.result, execution.follow_up)
            }
            Err(error) => {
                return WorkOperationResult {
                    effect_id: Some(effect_id),
                    bridge_update: None,
                    handoff_signal: None,
                    result: Err(error),
                };
            }
        },
        EffectIntent::BridgeMedia {
            left_leg_id,
            right_leg_id,
        } => match stored
            .plan
            .media_bridge_plan(&stored.call.aggregate, left_leg_id, right_leg_id)
        {
            Ok(media_plan) => {
                let left = bindings.get(&left_leg_id);
                let right = bindings.get(&right_leg_id);
                match (left, right) {
                    (Some(left), Some(right)) => {
                        let context_policy = Arc::new(BridgefuContextBridgePolicy::new(
                            ContextSourceBinding::new(
                                left.connection_id.clone(),
                                meta.tenant_id.as_str(),
                                meta.call_id.to_string(),
                                left_leg_id.to_string(),
                            ),
                            ContextSourceBinding::new(
                                right.connection_id.clone(),
                                meta.tenant_id.as_str(),
                                meta.call_id.to_string(),
                                right_leg_id.to_string(),
                            ),
                        ));
                        match tokio::time::timeout(
                            EXTERNAL_OPERATION_TIMEOUT,
                            orchestrator.bridge_connections_directional_with_data_policy(
                                left.connection_id.clone(),
                                right.connection_id.clone(),
                                DirectionalMediaBridgePlan::new(
                                    media_plan.left_to_right(),
                                    media_plan.right_to_left(),
                                )
                                .expect("validated call media plan enables at least one direction"),
                                context_policy,
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
                        }
                    }
                    _ => {
                        let failure = FailureDetails::sanitized(
                            "media_binding_missing",
                            "a connected media leg has no process-owned transport binding",
                            false,
                        );
                        let (leg_id, generation) = left
                            .map(|binding| (left_leg_id, binding.binding_generation))
                            .or_else(|| {
                                right.map(|binding| (right_leg_id, binding.binding_generation))
                            })
                            .unwrap_or((
                                left_leg_id,
                                crate::call_engine::BindingGeneration::INITIAL,
                            ));
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
            Err(_) => {
                let failure = FailureDetails::sanitized(
                    "media_plan_invalid",
                    "durable call media directions do not form a complete bridge",
                    false,
                );
                let (leg_id, generation) = bindings
                    .get(&left_leg_id)
                    .map(|binding| (left_leg_id, binding.binding_generation))
                    .or_else(|| {
                        bindings
                            .get(&right_leg_id)
                            .map(|binding| (right_leg_id, binding.binding_generation))
                    })
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
        },
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
            reason,
        } => {
            let provider_result = match load_provider_media_for_binding(
                &runtime,
                &stored,
                &meta.tenant_id,
                meta.call_id,
                leg_id,
                binding_generation,
            )
            .await
            {
                Ok((endpoint, media_call)) => tokio::time::timeout(
                    EXTERNAL_OPERATION_TIMEOUT,
                    provider_executor.hangup(ProviderHangupRequest {
                        context: ProviderExecutionContext {
                            tenant_id: meta.tenant_id.clone(),
                            call_id: meta.call_id,
                            leg_id,
                            binding_generation,
                            effect_id,
                        },
                        endpoint,
                        media_call,
                    }),
                )
                .await
                .map_err(|_| ProviderExecutionError::Remote { retryable: true })
                .and_then(|result| result),
                Err(ProviderExecutionError::InvalidRequest) => Ok(()),
                Err(error) => Err(error),
            };
            let amazon_result = stop_persisted_amazon_contact(
                &meta,
                &stored,
                leg_id,
                binding_generation,
                &runtime,
                amazon_connect.as_ref(),
                shutdown.clone(),
            )
            .await;
            let transport_binding = bindings
                .get(&leg_id)
                .filter(|binding| binding.binding_generation == binding_generation)
                .or_else(|| replaced_bindings.get(&(leg_id, binding_generation)));
            let private_result = match (
                private_egress.as_ref(),
                transport_binding.and_then(|binding| {
                    binding
                        .private_egress
                        .as_ref()
                        .map(|route| (binding, route))
                }),
            ) {
                (Some(private_egress), Some((binding, route))) => {
                    let end_reason = match reason {
                        crate::call_engine::StopLegReason::Requested
                        | crate::call_engine::StopLegReason::PeerEnded => {
                            PrivateEgressEndReason::Normal
                        }
                        crate::call_engine::StopLegReason::Failure => {
                            PrivateEgressEndReason::Failed
                        }
                        crate::call_engine::StopLegReason::DeadlineExpired => {
                            PrivateEgressEndReason::Timeout
                        }
                    };
                    if orchestrator
                        .connection_transport(&route.source_connection)
                        .ok()
                        != Some(Transport::Quic)
                    {
                        // Source-route retirement invokes the gateway's
                        // generation-bound `end_source` compensation.
                        Ok(())
                    } else {
                        match private_egress_command(
                            Uuid::new_v4(),
                            &runtime,
                            route.source.clone(),
                            route.target,
                            PrivateEgressOperation::End { reason: end_reason },
                        ) {
                            Ok(command) => match tokio::time::timeout(
                                EXTERNAL_OPERATION_TIMEOUT,
                                private_egress
                                    .control()
                                    .execute(route.source_connection.clone(), command),
                            )
                            .await
                            {
                                Ok(Ok(response))
                                    if (response.accepted
                                        && response.state
                                            == Some(PrivateEgressLifecycleState::Ended))
                                        || binding.state.is_terminal() =>
                                {
                                    Ok(())
                                }
                                Ok(Err(PrivateEgressError::InvalidTransition))
                                    if binding.state == LegState::Ending =>
                                {
                                    // The immediate source-loss path may have
                                    // already aborted a still-prepared route.
                                    // A later durable End then proves there is
                                    // no live route left to terminate.
                                    Ok(())
                                }
                                _ => Err(()),
                            },
                            Err(()) => Err(()),
                        }
                    }
                }
                _ => Ok(()),
            };
            let transport_result = match transport_binding {
                Some(binding) if binding.binding_generation == binding_generation => {
                    tokio::time::timeout(
                        EXTERNAL_OPERATION_TIMEOUT,
                        orchestrator
                            .end_connection(binding.connection_id.clone(), EndReason::BridgeTorn),
                    )
                    .await
                    .map_err(|_| ())
                    .and_then(normalize_terminal_transport_cleanup)
                }
                _ => Ok(()),
            };
            match (
                provider_result,
                amazon_result,
                private_result,
                transport_result,
            ) {
                (Ok(()), Ok(()), Ok(()), Ok(())) => {
                    (ServiceEffectResult::Succeeded, FollowUpPlan::None)
                }
                (Err(error), _, _, _) => (
                    ServiceEffectResult::Failed(provider_execution_failure(
                        "provider_hangup_failed",
                        error,
                    )),
                    FollowUpPlan::None,
                ),
                (_, Err(()), _, _) => (
                    ServiceEffectResult::Failed(FailureDetails::sanitized(
                        "amazon_connect_stop_failed",
                        "Amazon Connect contact cleanup could not be confirmed",
                        true,
                    )),
                    FollowUpPlan::None,
                ),
                (_, _, Err(()), _) => (
                    ServiceEffectResult::Failed(FailureDetails::sanitized(
                        "private_egress_stop_failed",
                        "the gateway could not confirm destination route teardown",
                        true,
                    )),
                    FollowUpPlan::None,
                ),
                (_, _, _, Err(())) => (
                    ServiceEffectResult::Failed(FailureDetails::sanitized(
                        "stop_leg_failed",
                        "rvoip could not confirm transport teardown",
                        true,
                    )),
                    FollowUpPlan::None,
                ),
            }
        }
        EffectIntent::StartLeg {
            leg_id,
            binding_generation,
            kind,
            direction: _,
        } => {
            if let Some(private_egress) = private_egress.as_ref().filter(|_| {
                matches!(
                    kind,
                    crate::call_engine::LegKind::Sip
                        | crate::call_engine::LegKind::InteractiveWebRtc
                )
            }) {
                match Box::pin(execute_private_egress_start_leg(
                    &meta,
                    &stored,
                    leg_id,
                    binding_generation,
                    &orchestrator,
                    &runtime,
                    context_policy.as_ref(),
                    private_egress,
                    &bindings,
                    &pending_inbound_authorities,
                    outbound_registration.as_ref(),
                    &setup_cancel,
                    shutdown.clone(),
                ))
                .await
                {
                    Ok(execution) => (execution.result, execution.follow_up),
                    Err(error) => {
                        return WorkOperationResult {
                            effect_id: Some(effect_id),
                            bridge_update: None,
                            handoff_signal: None,
                            result: Err(error),
                        };
                    }
                }
            } else if kind == crate::call_engine::LegKind::Sip {
                match execute_sip_start_leg(
                    &meta,
                    &stored,
                    leg_id,
                    binding_generation,
                    &orchestrator,
                    &runtime,
                    context_policy.as_ref(),
                    outbound_profiles.as_ref(),
                    bindings.get(&leg_id),
                    session_id,
                    outbound_registration.as_ref(),
                    &setup_cancel,
                    shutdown.clone(),
                )
                .await
                {
                    Ok(execution) => {
                        external_reference = execution.external_reference;
                        (execution.result, execution.follow_up)
                    }
                    Err(error) => {
                        return WorkOperationResult {
                            effect_id: Some(effect_id),
                            bridge_update: None,
                            handoff_signal: None,
                            result: Err(error),
                        };
                    }
                }
            } else if kind == crate::call_engine::LegKind::AmazonConnect {
                match execute_amazon_start_leg(
                    &meta,
                    &stored,
                    leg_id,
                    binding_generation,
                    &orchestrator,
                    &runtime,
                    context_policy.as_ref(),
                    amazon_connect.as_ref(),
                    session_id,
                    outbound_registration.as_ref(),
                    &setup_cancel,
                    shutdown.clone(),
                )
                .await
                {
                    Ok(execution) => {
                        external_reference = execution.external_reference;
                        (execution.result, execution.follow_up)
                    }
                    Err(error) => {
                        return WorkOperationResult {
                            effect_id: Some(effect_id),
                            bridge_update: None,
                            handoff_signal: None,
                            result: Err(error),
                        };
                    }
                }
            } else if matches!(
                kind,
                crate::call_engine::LegKind::InteractiveWebRtc
                    | crate::call_engine::LegKind::Whip
                    | crate::call_engine::LegKind::Whep
            ) {
                match execute_web_rtc_start_leg(
                    &meta,
                    &stored,
                    leg_id,
                    binding_generation,
                    &orchestrator,
                    &runtime,
                    outbound_profiles.as_ref(),
                    bindings.get(&leg_id),
                    session_id,
                    outbound_registration.as_ref(),
                    &setup_cancel,
                    shutdown.clone(),
                )
                .await
                {
                    Ok(execution) => (execution.result, execution.follow_up),
                    Err(error) => {
                        return WorkOperationResult {
                            effect_id: Some(effect_id),
                            bridge_update: None,
                            handoff_signal: None,
                            result: Err(error),
                        };
                    }
                }
            } else {
                let provider_endpoint = stored
                    .plan
                    .legs
                    .iter()
                    .find(|spec| spec.leg_id == leg_id)
                    .and_then(|spec| match &spec.endpoint {
                        super::LegEndpointConfig::Provider(endpoint) => Some(endpoint.clone()),
                        _ => None,
                    });
                if kind == crate::call_engine::LegKind::Telnyx
                    && provider_endpoint
                        .as_ref()
                        .is_some_and(|endpoint| endpoint.provider == ProviderKind::Telnyx)
                {
                    let endpoint = provider_endpoint.expect("checked provider endpoint");
                    let provider_context = ProviderExecutionContext {
                        tenant_id: meta.tenant_id.clone(),
                        call_id: meta.call_id,
                        leg_id,
                        binding_generation,
                        effect_id,
                    };
                    let operation = match runtime
                        .service()
                        .provider_media_attachment_token(&stored, leg_id)
                    {
                        Ok(attachment_token) => telnyx_dial_client_state(
                            &stored,
                            leg_id,
                            binding_generation,
                            &provider_context,
                            ProviderDialRole::Media,
                            context_policy.as_ref(),
                            &runtime,
                            true,
                            shutdown.clone(),
                        )
                        .await
                        .map(|client_state| ProviderStartMediaRequest {
                            context: provider_context,
                            client_state,
                            endpoint,
                            attachment_token,
                        })
                        .map_err(|_| ()),
                        Err(_) => Err(()),
                    };
                    match operation {
                        Ok(request) => match tokio::time::timeout(
                            EXTERNAL_OPERATION_TIMEOUT,
                            provider_executor.start_media(request),
                        )
                        .await
                        {
                            Ok(Ok(reference)) => {
                                external_reference = Some(provider_reference_binding(
                                    leg_id,
                                    binding_generation,
                                    ProviderReferenceRole::Media,
                                    reference,
                                ));
                                let follow_up = if setup_cancel.is_cancelled() {
                                    // The provider originate was already submitted, so its
                                    // future must run to a bounded completion to recover the
                                    // exact cleanup handle. Persist that handle without trying
                                    // to advance an Ending call. The serialized StopLeg effect
                                    // then retires this exact provider generation.
                                    FollowUpPlan::None
                                } else {
                                    FollowUpPlan::ProviderMediaStarted {
                                        leg_id,
                                        binding_generation,
                                    }
                                };
                                (ServiceEffectResult::Succeeded, follow_up)
                            }
                            Ok(Err(error)) => {
                                let failure =
                                    provider_execution_failure("provider_media_start", error);
                                (
                                    ServiceEffectResult::Failed(failure.clone()),
                                    FollowUpPlan::FailLeg {
                                        leg_id,
                                        binding_generation,
                                        failure,
                                    },
                                )
                            }
                            Err(_) => {
                                let failure = FailureDetails::sanitized(
                                    "provider_media_start_timeout",
                                    "provider media origination exceeded its deadline",
                                    true,
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
                        },
                        Err(_) => {
                            let failure = FailureDetails::sanitized(
                                "provider_attachment_unavailable",
                                "the provider media attachment is unavailable",
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
                    }
                } else {
                    let authority = stored.plan.authorization_principal_fingerprint();
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
            }
        }
        EffectIntent::ConnectProviderDestination {
            leg_id,
            binding_generation,
        } => {
            let endpoint = stored
                .plan
                .legs
                .iter()
                .find(|spec| spec.leg_id == leg_id)
                .and_then(|spec| match &spec.endpoint {
                    super::LegEndpointConfig::Provider(endpoint)
                        if endpoint.provider == ProviderKind::Telnyx =>
                    {
                        Some(endpoint.clone())
                    }
                    _ => None,
                });
            let media = runtime
                .service_repository()
                .load_external_reference_by_role(
                    &meta.tenant_id,
                    meta.call_id,
                    leg_id,
                    ProviderReferenceRole::Media,
                )
                .await;
            let operation = match (endpoint, media) {
                (Some(endpoint), Ok(Some(media)))
                    if media.binding_generation == binding_generation =>
                {
                    match media.value {
                        ExternalReferenceValue::ProviderCall {
                            account,
                            provider_call_id,
                        } if account.as_str() == endpoint.account_profile => {
                            let provider_context = ProviderExecutionContext {
                                tenant_id: meta.tenant_id.clone(),
                                call_id: meta.call_id,
                                leg_id,
                                binding_generation,
                                effect_id,
                            };
                            telnyx_dial_client_state(
                                &stored,
                                leg_id,
                                binding_generation,
                                &provider_context,
                                ProviderDialRole::Destination,
                                context_policy.as_ref(),
                                &runtime,
                                false,
                                shutdown.clone(),
                            )
                            .await
                            .map(|client_state| ProviderConnectDestinationRequest {
                                context: provider_context,
                                client_state,
                                endpoint,
                                media_call: ProviderExecutionReference {
                                    account,
                                    provider_call_id,
                                },
                            })
                            .map_err(|_| ())
                        }
                        _ => Err(()),
                    }
                }
                _ => Err(()),
            };
            match operation {
                Ok(request) => match tokio::time::timeout(
                    EXTERNAL_OPERATION_TIMEOUT,
                    provider_executor.connect_destination(request),
                )
                .await
                {
                    Ok(Ok(reference)) => {
                        external_reference = Some(provider_reference_binding(
                            leg_id,
                            binding_generation,
                            ProviderReferenceRole::Destination,
                            reference,
                        ));
                        (ServiceEffectResult::Succeeded, FollowUpPlan::None)
                    }
                    Ok(Err(error)) => {
                        let failure = provider_execution_failure("provider_destination", error);
                        (
                            ServiceEffectResult::Failed(failure.clone()),
                            FollowUpPlan::FailLeg {
                                leg_id,
                                binding_generation,
                                failure,
                            },
                        )
                    }
                    Err(_) => {
                        let failure = FailureDetails::sanitized(
                            "provider_destination_timeout",
                            "provider destination origination exceeded its deadline",
                            true,
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
                },
                Err(()) => {
                    let failure = FailureDetails::sanitized(
                        "provider_media_reference_missing",
                        "the primary provider media reference is unavailable",
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
            }
        }
        EffectIntent::ExecuteTransfer {
            deadline_generation,
        } => {
            let payload = runtime
                .service_repository()
                .load_effect_payload(&meta.tenant_id, effect_id)
                .await;
            let operation = match payload {
                Ok(Some(stored_payload)) => {
                    let ServiceEffectPayload::Transfer {
                        target_leg_id,
                        target_binding_generation,
                        target,
                    } = stored_payload.payload
                    else {
                        return WorkOperationResult {
                            effect_id: Some(effect_id),
                            bridge_update: None,
                            handoff_signal: None,
                            result: Err(RepositoryError::InvalidInput(
                                "transfer effect has incompatible service payload",
                            )),
                        };
                    };
                    let binding = bindings.get(&target_leg_id).filter(|binding| {
                        binding.binding_generation == target_binding_generation
                            && stored
                                .call
                                .bindings
                                .get(&target_leg_id)
                                .is_some_and(|durable| {
                                    durable.binding_generation == target_binding_generation
                                        && durable.connection_id == binding.connection_id
                                })
                    });
                    match binding {
                        None => Err(FailureDetails::sanitized(
                            "transfer_binding_stale",
                            "the transfer target transport binding is no longer current",
                            false,
                        )),
                        Some(binding) => {
                            let context = ProviderExecutionContext {
                                tenant_id: meta.tenant_id.clone(),
                                call_id: meta.call_id,
                                leg_id: target_leg_id,
                                binding_generation: target_binding_generation,
                                effect_id,
                            };
                            match provider_endpoint_for_leg(&stored, target_leg_id) {
                                Some(endpoint) => load_provider_media_reference(
                                    &runtime,
                                    &meta.tenant_id,
                                    meta.call_id,
                                    target_leg_id,
                                    target_binding_generation,
                                    &endpoint,
                                )
                                .await
                                .map(|media_call| {
                                    let correlation = ProviderTransferCorrelation::new(
                                        &context,
                                        deadline_generation,
                                    );
                                    PreparedTransferOperation::Provider(Box::new(
                                        ProviderTransferRequest {
                                            context,
                                            endpoint,
                                            media_call,
                                            target,
                                            correlation,
                                        },
                                    ))
                                })
                                .map_err(|error| {
                                    provider_execution_failure("transfer_target_unavailable", error)
                                }),
                                None => rvoip_transfer_target(target).map(|target| {
                                    PreparedTransferOperation::Transport {
                                        connection_id: binding.connection_id.clone(),
                                        target,
                                        attempt_id: transfer_attempt_id(
                                            meta.call_id,
                                            target_leg_id,
                                            target_binding_generation,
                                            deadline_generation,
                                        ),
                                    }
                                }),
                            }
                        }
                    }
                }
                _ => Err(FailureDetails::sanitized(
                    "transfer_payload_unavailable",
                    "the durable transfer request is unavailable",
                    true,
                )),
            };
            match operation {
                Ok(PreparedTransferOperation::Provider(request)) => {
                    match tokio::time::timeout(
                        EXTERNAL_OPERATION_TIMEOUT,
                        provider_executor.transfer(*request),
                    )
                    .await
                    {
                        Ok(Ok(())) => (ServiceEffectResult::Succeeded, FollowUpPlan::None),
                        Ok(Err(error)) => {
                            let failure =
                                provider_execution_failure("provider_transfer_failed", error);
                            (
                                ServiceEffectResult::Failed(failure.clone()),
                                FollowUpPlan::FinishTransfer {
                                    deadline_generation,
                                    result: TransferResult::Rejected(failure),
                                },
                            )
                        }
                        Err(_) => {
                            let failure = FailureDetails::sanitized(
                                "provider_transfer_timeout",
                                "provider transfer submission exceeded its deadline",
                                true,
                            );
                            (
                                ServiceEffectResult::Failed(failure.clone()),
                                FollowUpPlan::FinishTransfer {
                                    deadline_generation,
                                    result: TransferResult::Rejected(failure),
                                },
                            )
                        }
                    }
                }
                Ok(PreparedTransferOperation::Transport {
                    connection_id,
                    target,
                    attempt_id,
                }) => match tokio::time::timeout(
                    EXTERNAL_OPERATION_TIMEOUT,
                    orchestrator.transfer_connection_with_attempt(
                        connection_id,
                        attempt_id,
                        target,
                    ),
                )
                .await
                {
                    Ok(Ok(())) => (ServiceEffectResult::Succeeded, FollowUpPlan::None),
                    Ok(Err(error)) => {
                        let failure = rvoip_transfer_failure(&error);
                        (
                            ServiceEffectResult::Failed(failure.clone()),
                            FollowUpPlan::FinishTransfer {
                                deadline_generation,
                                result: TransferResult::Rejected(failure),
                            },
                        )
                    }
                    Err(_) => {
                        let failure = FailureDetails::sanitized(
                            "transport_transfer_timeout",
                            "transport transfer submission exceeded its deadline",
                            true,
                        );
                        (
                            ServiceEffectResult::Failed(failure.clone()),
                            FollowUpPlan::FinishTransfer {
                                deadline_generation,
                                result: TransferResult::Rejected(failure),
                            },
                        )
                    }
                },
                Err(failure) => (
                    ServiceEffectResult::Failed(failure.clone()),
                    FollowUpPlan::FinishTransfer {
                        deadline_generation,
                        result: TransferResult::Rejected(failure),
                    },
                ),
            }
        }
    };
    let reconciled = reconcile_effect_with_references(
        meta,
        result,
        external_reference,
        additional_external_references,
        follow_up,
        runtime,
        shutdown,
    )
    .await;
    tracing::debug!(
        call_id = %claim.record.call_id,
        %effect_id,
        intent = ?effect_intent,
        reconciled = reconciled.is_ok(),
        "finished durable call effect"
    );
    WorkOperationResult {
        effect_id: Some(effect_id),
        bridge_update,
        handoff_signal: None,
        result: reconciled,
    }
}

struct ReplacementStartExecution {
    result: ServiceEffectResult,
    follow_up: FollowUpPlan,
    external_reference: Option<ExternalReferenceBinding>,
    additional_external_references: Vec<ExternalReferenceBinding>,
}

impl ReplacementStartExecution {
    fn connected(
        deadline_generation: crate::call_engine::DeadlineGeneration,
        pending_binding_generation: crate::call_engine::BindingGeneration,
        replacement_connection: ReplacementConnectionPromotion,
    ) -> Self {
        Self {
            result: ServiceEffectResult::Succeeded,
            follow_up: FollowUpPlan::FinishLegReplacement {
                deadline_generation,
                pending_binding_generation,
                result: LegReplacementResult::Connected,
                replacement_connection: Some(replacement_connection),
            },
            external_reference: None,
            additional_external_references: Vec::new(),
        }
    }

    fn rejected(
        deadline_generation: crate::call_engine::DeadlineGeneration,
        pending_binding_generation: crate::call_engine::BindingGeneration,
        code: &str,
        message: &str,
        retryable: bool,
    ) -> Self {
        let failure = FailureDetails::sanitized(code, message, retryable);
        Self {
            result: ServiceEffectResult::Failed(failure.clone()),
            follow_up: FollowUpPlan::FinishLegReplacement {
                deadline_generation,
                pending_binding_generation,
                result: LegReplacementResult::Rejected(failure),
                replacement_connection: None,
            },
            external_reference: None,
            additional_external_references: Vec::new(),
        }
    }

    fn rejected_with_provider_reference(
        deadline_generation: crate::call_engine::DeadlineGeneration,
        pending_binding_generation: crate::call_engine::BindingGeneration,
        failure: FailureDetails,
        reference: ExternalReferenceBinding,
    ) -> Self {
        Self {
            result: ServiceEffectResult::Failed(failure.clone()),
            follow_up: FollowUpPlan::FinishLegReplacement {
                deadline_generation,
                pending_binding_generation,
                result: LegReplacementResult::Rejected(failure),
                replacement_connection: None,
            },
            external_reference: Some(reference),
            additional_external_references: Vec::new(),
        }
    }
}

fn validated_replacement_route(
    payload: &ServiceEffectPayload,
) -> Result<super::NamedRouteBinding, ()> {
    payload.validate().map_err(|_| ())?;
    match payload {
        ServiceEffectPayload::LegReplacement {
            replacement_route: Some(route),
            ..
        } => Ok(route.clone()),
        _ => Err(()),
    }
}

fn replacement_uses_initial_context(endpoint: &super::LegEndpointConfig) -> bool {
    replacement_requires_initial_context(endpoint)
        || matches!(endpoint, super::LegEndpointConfig::AmazonConnect(_))
        || matches!(
            endpoint,
            super::LegEndpointConfig::Provider(super::ProviderEndpointConfig {
                provider: ProviderKind::Telnyx,
                ..
            })
        )
}

fn replacement_requires_initial_context(endpoint: &super::LegEndpointConfig) -> bool {
    matches!(
        endpoint,
        super::LegEndpointConfig::Sip(super::SipEndpointConfig {
            initial_context: SipInitialContextMode::Required,
            ..
        })
    )
}

#[allow(clippy::too_many_arguments)]
async fn wait_for_private_replacement_authority_loss(
    runtime: &CallServiceRuntime,
    tenant_id: &TenantId,
    call_id: CallId,
    source_leg_id: LegId,
    source_binding_generation: crate::call_engine::BindingGeneration,
    source_connection_id: &ConnectionId,
    target_leg_id: LegId,
    previous_binding_generation: crate::call_engine::BindingGeneration,
    previous_connection_id: &ConnectionId,
    pending_binding_generation: crate::call_engine::BindingGeneration,
) {
    loop {
        let stored = match runtime
            .service_repository()
            .load_service_call(tenant_id, call_id)
            .await
        {
            Ok(stored) => stored,
            Err(RepositoryError::Unavailable) => {
                tokio::time::sleep(REPOSITORY_RETRY_MIN).await;
                continue;
            }
            Err(_) => return,
        };
        let owned = stored
            .call
            .aggregate
            .replacement()
            .is_some_and(|replacement| {
                replacement.leg_id() == target_leg_id
                    && replacement.previous_binding_generation() == previous_binding_generation
                    && replacement.pending_binding_generation() == pending_binding_generation
            })
            && stored
                .call
                .bindings
                .get(&target_leg_id)
                .is_some_and(|binding| {
                    binding.binding_generation == previous_binding_generation
                        && &binding.connection_id == previous_connection_id
                })
            && stored
                .call
                .bindings
                .get(&source_leg_id)
                .is_some_and(|binding| {
                    binding.binding_generation == source_binding_generation
                        && &binding.connection_id == source_connection_id
                })
            && stored
                .call
                .aggregate
                .leg(source_leg_id)
                .is_some_and(|leg| matches!(leg.state(), LegState::Connected | LegState::Held));
        if !owned {
            return;
        }
        tokio::time::sleep(REPOSITORY_RETRY_MIN).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_private_egress_leg_replacement(
    meta: &ClaimedEffectMeta,
    stored: &StoredServiceCall,
    leg_id: LegId,
    previous_binding_generation: crate::call_engine::BindingGeneration,
    pending_binding_generation: crate::call_engine::BindingGeneration,
    deadline_generation: crate::call_engine::DeadlineGeneration,
    endpoint: &super::LegEndpointConfig,
    replacement_route: &super::NamedRouteBinding,
    replacement_sip_headers: &SipInitialHeaders,
    principal_fingerprint: crate::call_engine::PrincipalFingerprint,
    orchestrator: &Arc<Orchestrator>,
    runtime: &Arc<CallServiceRuntime>,
    private_egress: &Arc<PrivateEgressWorkerRuntime>,
    bindings: &HashMap<LegId, ActorBinding>,
    existing_pending: Option<&PendingReplacementBinding>,
    registration: &mpsc::Sender<OutboundRegistration>,
    mut shutdown: watch::Receiver<ActorShutdown>,
) -> Result<ReplacementStartExecution, RepositoryError> {
    let (transport, profile_kind, target, binding_transport, initial_context) = match endpoint {
        super::LegEndpointConfig::Sip(endpoint) => {
            let Some(target) = endpoint.uri.clone() else {
                return Ok(ReplacementStartExecution::rejected(
                    deadline_generation,
                    pending_binding_generation,
                    "private_egress_target_missing",
                    "the server-owned gateway replacement target is absent",
                    false,
                ));
            };
            (
                PrivateEgressTransport::Sip,
                NamedProfileKind::Sip,
                target,
                AttachmentTransport::Sip,
                replacement_sip_headers
                    .iter()
                    .map(|(name, value)| (name.as_str().to_owned(), value.to_owned()))
                    .collect::<Vec<_>>(),
            )
        }
        super::LegEndpointConfig::WebRtc(endpoint) => {
            let Some(target) = endpoint.signaling_uri.clone() else {
                return Ok(ReplacementStartExecution::rejected(
                    deadline_generation,
                    pending_binding_generation,
                    "private_egress_target_missing",
                    "the server-owned gateway replacement target is absent",
                    false,
                ));
            };
            (
                PrivateEgressTransport::WebRtc,
                NamedProfileKind::WebRtc,
                target,
                AttachmentTransport::WebRtc,
                Vec::new(),
            )
        }
        _ => {
            return Ok(ReplacementStartExecution::rejected(
                deadline_generation,
                pending_binding_generation,
                "private_egress_endpoint_unsupported",
                "the split gateway cannot originate this replacement endpoint type",
                false,
            ));
        }
    };

    let Some(previous_binding) = bindings.get(&leg_id).filter(|binding| {
        binding.binding_generation == previous_binding_generation
            && stored.call.bindings.get(&leg_id).is_some_and(|durable| {
                durable.connection_id == binding.connection_id
                    && durable.binding_generation == previous_binding_generation
            })
    }) else {
        return Ok(ReplacementStartExecution::rejected(
            deadline_generation,
            pending_binding_generation,
            "replacement_previous_binding_stale",
            "the held destination generation no longer owns this call",
            true,
        ));
    };

    let mut destinations = replacement_route
        .profiles()
        .iter()
        .filter(|profile| profile.role() == NamedProfileRole::Destination);
    let Some(destination) = destinations.next() else {
        return Ok(ReplacementStartExecution::rejected(
            deadline_generation,
            pending_binding_generation,
            "private_egress_profile_missing",
            "the replacement route has no destination profile snapshot",
            false,
        ));
    };
    if destinations.next().is_some() || destination.kind() != profile_kind {
        return Ok(ReplacementStartExecution::rejected(
            deadline_generation,
            pending_binding_generation,
            "private_egress_profile_mismatch",
            "the replacement profile does not match its endpoint",
            false,
        ));
    }
    let profile = PrivateEgressProfile {
        profile_id: destination.profile_id().to_owned(),
        revision: destination.revision().to_owned(),
    };
    let route_descriptor = match private_egress.routes().resolve(
        stored.call.aggregate.tenant_id(),
        replacement_route.route_id(),
        transport,
        &profile,
        &target,
    ) {
        Ok(route) => route,
        Err(_) => {
            return Ok(ReplacementStartExecution::rejected(
                deadline_generation,
                pending_binding_generation,
                "private_egress_route_not_installed",
                "the exact gateway replacement route revision is not installed on this worker",
                false,
            ));
        }
    };
    let codec = route_descriptor
        .codecs
        .first()
        .cloned()
        .ok_or(RepositoryError::InvalidInput(
            "private egress replacement route has no codec",
        ))?;

    let Some((source_leg_id, source_binding)) = stored
        .plan
        .legs
        .iter()
        .find(|candidate| candidate.leg_id != leg_id)
        .and_then(|candidate| {
            bindings
                .get(&candidate.leg_id)
                .map(|binding| (candidate.leg_id, binding))
        })
    else {
        return Ok(ReplacementStartExecution::rejected(
            deadline_generation,
            pending_binding_generation,
            "private_egress_source_unavailable",
            "the stable gateway source leg is unavailable for replacement",
            true,
        ));
    };
    let source_principal_fingerprint = match stored.plan.authorization_principal_fingerprint() {
        Ok(principal) => principal,
        Err(_) => {
            return Ok(ReplacementStartExecution::rejected(
                deadline_generation,
                pending_binding_generation,
                "private_egress_source_authority_missing",
                "the original gateway source authority is unavailable",
                false,
            ));
        }
    };
    let source_is_owned = stored
        .call
        .bindings
        .get(&source_leg_id)
        .is_some_and(|durable| {
            durable.connection_id == source_binding.connection_id
                && durable.binding_generation == source_binding.binding_generation
                && durable.principal_fingerprint == source_principal_fingerprint
        })
        && matches!(source_binding.state, LegState::Connected | LegState::Held)
        && orchestrator
            .connection_transport(&source_binding.connection_id)
            .is_ok_and(|transport| transport == Transport::Quic);
    if !source_is_owned {
        return Ok(ReplacementStartExecution::rejected(
            deadline_generation,
            pending_binding_generation,
            "private_egress_source_stale",
            "the stable gateway source leg no longer owns this call",
            true,
        ));
    }
    let source = PrivateEgressSource {
        tenant_id: meta.tenant_id.clone(),
        call_id: meta.call_id,
        leg_id: source_leg_id,
        binding_generation: source_binding.binding_generation,
    };
    let target_binding = PrivateEgressTarget {
        leg_id,
        binding_generation: pending_binding_generation,
    };

    let private_binding = if let Some(existing) = existing_pending {
        let Some(route) = existing.binding.private_egress.as_ref().filter(|route| {
            existing.effect_id == meta.effect_id
                && existing.binding.binding_generation == pending_binding_generation
                && route.worker == runtime.worker().lease
                && route.source_connection == source_binding.connection_id
                && route.source == source
                && route.target == target_binding
                && orchestrator
                    .connection_transport(&existing.binding.connection_id)
                    .is_ok_and(|transport| transport == Transport::Quic)
        }) else {
            return Ok(ReplacementStartExecution::rejected(
                deadline_generation,
                pending_binding_generation,
                "replacement_route_stale",
                "the pending gateway replacement no longer owns this call",
                true,
            ));
        };
        route.clone()
    } else {
        let prepare = match private_egress_command(
            meta.effect_id.as_uuid(),
            runtime,
            source.clone(),
            target_binding,
            PrivateEgressOperation::Prepare {
                transport,
                profile,
                codec,
                target,
                initial_context,
            },
        ) {
            Ok(command) => command,
            Err(()) => {
                return Ok(ReplacementStartExecution::rejected(
                    deadline_generation,
                    pending_binding_generation,
                    "private_egress_command_invalid",
                    "the exact gateway replacement command could not be represented",
                    false,
                ));
            }
        };
        let admission = PrivateEgressStreamAdmission::from_prepare(&prepare).map_err(|_| {
            RepositoryError::InvalidInput("private egress replacement admission is invalid")
        })?;
        let admission_id = admission.admission_id;
        let reservation = match private_egress.admissions().reserve(admission) {
            Ok(reservation) => reservation,
            Err(_) => {
                return Ok(ReplacementStartExecution::rejected(
                    deadline_generation,
                    pending_binding_generation,
                    "private_egress_capacity",
                    "gateway replacement admission capacity is exhausted",
                    true,
                ));
            }
        };
        let prepare_response = await_while_execution_owned(
            private_egress
                .control()
                .execute(source_binding.connection_id.clone(), prepare),
            &mut shutdown,
        )
        .await;
        let prepared = matches!(
            prepare_response,
            Ok(Ok(ref response))
                if response.accepted
                    && response.state == Some(PrivateEgressLifecycleState::Prepared)
        );
        if !prepared {
            reservation.cancel();
            if prepare_response.is_err() {
                return Err(RepositoryError::Unavailable);
            }
            return Ok(ReplacementStartExecution::rejected(
                deadline_generation,
                pending_binding_generation,
                "private_egress_prepare_failed",
                "the gateway could not prepare the configured replacement destination",
                true,
            ));
        }
        send_replacement_ringing(orchestrator, stored, leg_id, pending_binding_generation).await;
        let destination_connection = tokio::select! {
            result = reservation.wait(
                bounded_effect_operation_timeout(stored, runtime, DeadlineKind::Transfer)
            ) => result,
            () = wait_for_private_replacement_authority_loss(
                runtime,
                &meta.tenant_id,
                meta.call_id,
                source_leg_id,
                source_binding.binding_generation,
                &source_binding.connection_id,
                leg_id,
                previous_binding_generation,
                &previous_binding.connection_id,
                pending_binding_generation,
            ) => {
                private_egress.admissions().release(admission_id);
                best_effort_private_egress_finish(
                    private_egress,
                    &source_binding.connection_id,
                    None,
                    runtime,
                    &source,
                    target_binding,
                    PrivateEgressOperation::Abort,
                ).await;
                return Ok(ReplacementStartExecution {
                    result: ServiceEffectResult::Failed(FailureDetails::sanitized(
                        "replacement_cancelled",
                        "the source ended while the gateway replacement was preparing",
                        false,
                    )),
                    follow_up: FollowUpPlan::None,
                    external_reference: None,
                    additional_external_references: Vec::new(),
                });
            }
            changed = shutdown.changed() => {
                private_egress.admissions().release(admission_id);
                let _ = changed;
                best_effort_private_egress_finish(
                    private_egress,
                    &source_binding.connection_id,
                    None,
                    runtime,
                    &source,
                    target_binding,
                    PrivateEgressOperation::Abort,
                ).await;
                return Err(RepositoryError::Unavailable);
            }
        };
        let destination_connection = match destination_connection {
            Ok(connection) => connection,
            Err(_) => {
                best_effort_private_egress_finish(
                    private_egress,
                    &source_binding.connection_id,
                    None,
                    runtime,
                    &source,
                    target_binding,
                    PrivateEgressOperation::Abort,
                )
                .await;
                return Ok(ReplacementStartExecution::rejected(
                    deadline_generation,
                    pending_binding_generation,
                    "private_egress_media_timeout",
                    "the gateway replacement media route did not attach in time",
                    true,
                ));
            }
        };
        let connection_id = destination_connection.connection_id().clone();
        let route = PrivateEgressBinding {
            admission_id,
            worker: runtime.worker().lease,
            source_connection: source_binding.connection_id.clone(),
            source: source.clone(),
            target: target_binding,
            _connection: destination_connection,
        };
        let actor_binding = ActorBinding {
            connection_id: connection_id.clone(),
            leg_id,
            binding_generation: pending_binding_generation,
            state: LegState::Signaling,
            private_egress: Some(route.clone()),
        };
        if register_prepared_replacement(
            registration,
            meta.call_id,
            actor_binding,
            meta.effect_id,
            false,
            None,
            &mut shutdown,
        )
        .await
        .is_err()
        {
            best_effort_private_egress_finish(
                private_egress,
                &source_binding.connection_id,
                None,
                runtime,
                &source,
                target_binding,
                PrivateEgressOperation::Abort,
            )
            .await;
            let _ = orchestrator
                .end_connection(connection_id, EndReason::Cancelled)
                .await;
            return Ok(ReplacementStartExecution::rejected(
                deadline_generation,
                pending_binding_generation,
                "replacement_owner_unavailable",
                "the call actor could not own the pending gateway replacement",
                true,
            ));
        }
        route
    };

    let activate = private_egress_command(
        private_egress_phase_command_id(meta.effect_id.as_uuid(), 0xa5),
        runtime,
        private_binding.source.clone(),
        private_binding.target,
        PrivateEgressOperation::Activate,
    )
    .map_err(|_| RepositoryError::InvalidInput("private egress replacement activate is invalid"))?;
    let activation = await_while_execution_owned(
        private_egress
            .control()
            .execute(private_binding.source_connection.clone(), activate),
        &mut shutdown,
    )
    .await;
    let activated = matches!(
        activation,
        Ok(Ok(ref response))
            if response.accepted && response.state == Some(PrivateEgressLifecycleState::Active)
    );
    if !activated {
        best_effort_private_egress_finish(
            private_egress,
            &private_binding.source_connection,
            None,
            runtime,
            &private_binding.source,
            private_binding.target,
            PrivateEgressOperation::Abort,
        )
        .await;
        let _ = orchestrator
            .end_connection(
                private_binding._connection.connection_id().clone(),
                EndReason::Cancelled,
            )
            .await;
        if activation.is_err() {
            return Err(RepositoryError::Unavailable);
        }
        return Ok(ReplacementStartExecution::rejected(
            deadline_generation,
            pending_binding_generation,
            "private_egress_activate_failed",
            "the gateway replacement destination could not be activated",
            true,
        ));
    }

    let current = runtime
        .service_repository()
        .load_service_call(&meta.tenant_id, meta.call_id)
        .await?;
    let replacement_still_owned = current
        .call
        .aggregate
        .replacement()
        .is_some_and(|replacement| {
            replacement.leg_id() == leg_id
                && replacement.previous_binding_generation() == previous_binding_generation
                && replacement.pending_binding_generation() == pending_binding_generation
        })
        && current.call.bindings.get(&leg_id).is_some_and(|durable| {
            durable.connection_id == previous_binding.connection_id
                && durable.binding_generation == previous_binding_generation
        });
    if !replacement_still_owned {
        best_effort_private_egress_finish(
            private_egress,
            &private_binding.source_connection,
            None,
            runtime,
            &private_binding.source,
            private_binding.target,
            PrivateEgressOperation::End {
                reason: PrivateEgressEndReason::Cancelled,
            },
        )
        .await;
        return Ok(ReplacementStartExecution {
            result: ServiceEffectResult::Failed(FailureDetails::sanitized(
                "replacement_cancelled",
                "the source ended while the gateway replacement was activating",
                false,
            )),
            follow_up: FollowUpPlan::None,
            external_reference: None,
            additional_external_references: Vec::new(),
        });
    }

    Ok(ReplacementStartExecution::connected(
        deadline_generation,
        pending_binding_generation,
        ReplacementConnectionPromotion {
            previous_connection_id: previous_binding.connection_id.clone(),
            connection_id: private_binding._connection.connection_id().clone(),
            leg_id,
            previous_binding_generation,
            pending_binding_generation,
            transport: binding_transport,
            principal_fingerprint,
        },
    ))
}

#[allow(clippy::too_many_arguments)]
async fn execute_start_leg_replacement(
    meta: &ClaimedEffectMeta,
    stored: &StoredServiceCall,
    leg_id: LegId,
    previous_binding_generation: crate::call_engine::BindingGeneration,
    pending_binding_generation: crate::call_engine::BindingGeneration,
    deadline_generation: crate::call_engine::DeadlineGeneration,
    orchestrator: &Arc<Orchestrator>,
    runtime: &Arc<CallServiceRuntime>,
    provider_executor: &Arc<dyn ProviderLegExecutor>,
    context_policy: &ContextPolicy,
    outbound_profiles: &dyn OutboundProfileResolver,
    amazon_connect: Option<&Arc<AmazonConnectAdapter>>,
    private_egress: Option<&Arc<PrivateEgressWorkerRuntime>>,
    bindings: &HashMap<LegId, ActorBinding>,
    existing_pending: Option<&PendingReplacementBinding>,
    existing_session: Option<SessionId>,
    outbound_registration: Option<&mpsc::Sender<OutboundRegistration>>,
    mut shutdown: watch::Receiver<ActorShutdown>,
) -> Result<ReplacementStartExecution, RepositoryError> {
    if let Some(existing) = existing_pending {
        if existing.effect_id == meta.effect_id
            && existing.binding.binding_generation == pending_binding_generation
            && orchestrator
                .connection_transport(&existing.binding.connection_id)
                .is_ok()
        {
            if existing.complete_on_transport_connected {
                return Ok(ReplacementStartExecution {
                    result: ServiceEffectResult::Succeeded,
                    follow_up: FollowUpPlan::None,
                    external_reference: None,
                    additional_external_references: Vec::new(),
                });
            }
        } else {
            return Ok(ReplacementStartExecution::rejected(
                deadline_generation,
                pending_binding_generation,
                "replacement_route_stale",
                "the pending replacement route is no longer owned by this actor",
                true,
            ));
        }
    }
    if meta.claim_generation.as_i64() > 1 && existing_pending.is_none() {
        // SIP/WebRTC/Amazon activation is not replay-safe without the
        // process-owned prepared route. A reclaimed effect therefore fails
        // closed instead of risking a second destination call/contact.
        return Ok(ReplacementStartExecution::rejected(
            deadline_generation,
            pending_binding_generation,
            "replacement_worker_restarted",
            "the replacement route lost process ownership before activation completed",
            true,
        ));
    }
    let Some(registration) = outbound_registration else {
        return Ok(ReplacementStartExecution::rejected(
            deadline_generation,
            pending_binding_generation,
            "replacement_owner_unavailable",
            "the replacement route owner is unavailable",
            true,
        ));
    };
    let payload = runtime
        .service_repository()
        .load_effect_payload(&meta.tenant_id, meta.effect_id)
        .await?;
    let Some(payload) = payload else {
        return Ok(ReplacementStartExecution::rejected(
            deadline_generation,
            pending_binding_generation,
            "replacement_payload_unavailable",
            "the durable replacement endpoint is unavailable",
            false,
        ));
    };
    let replacement_route = match validated_replacement_route(&payload.payload) {
        Ok(route) => route,
        Err(()) => {
            return Ok(ReplacementStartExecution::rejected(
                deadline_generation,
                pending_binding_generation,
                "replacement_route_authority_invalid",
                "the durable replacement route authority is unavailable",
                false,
            ))
        }
    };
    let ServiceEffectPayload::LegReplacement {
        leg_id: payload_leg_id,
        previous_binding_generation: payload_previous,
        pending_binding_generation: payload_pending,
        endpoint,
        amazon_connect_start,
        authorization_principal_fingerprint,
        ..
    } = payload.payload
    else {
        return Err(RepositoryError::InvalidInput(
            "replacement effect has incompatible service payload",
        ));
    };
    if payload_leg_id != leg_id
        || payload_previous != previous_binding_generation
        || payload_pending != pending_binding_generation
        || stored
            .call
            .aggregate
            .replacement()
            .is_none_or(|replacement| {
                replacement.leg_id() != leg_id
                    || replacement.previous_binding_generation() != previous_binding_generation
                    || replacement.pending_binding_generation() != pending_binding_generation
                    || replacement.pending_kind() != endpoint.kind()
            })
    {
        return Err(RepositoryError::StaleClaim);
    }

    let replacement_context = if replacement_uses_initial_context(&endpoint) {
        match runtime
            .service_repository()
            .load_replacement_initial_context(ReplacementInitialContextLookup {
                tenant_id: meta.tenant_id.clone(),
                call_id: meta.call_id,
                target_leg_id: leg_id,
                previous_binding_generation,
                pending_binding_generation,
            })
            .await
        {
            Ok(Some(context)) => {
                let envelope = match serde_json::from_slice::<ContextEnvelope>(&context.envelope) {
                    Ok(envelope)
                        if envelope
                            .validate_binding(
                                meta.tenant_id.as_str(),
                                &meta.call_id.to_string(),
                                &context.source_leg_id.to_string(),
                            )
                            .is_ok() =>
                    {
                        envelope
                    }
                    _ => {
                        return Ok(ReplacementStartExecution::rejected(
                            deadline_generation,
                            pending_binding_generation,
                            "replacement_context_ownership_invalid",
                            "the retained initial context no longer owns this call",
                            false,
                        ));
                    }
                };
                metrics::counter!(
                    "bridgefu_initial_context_total",
                    "result" => "carried",
                    "reason" => match &endpoint {
                        super::LegEndpointConfig::Sip(_) => "replacement_sip",
                        super::LegEndpointConfig::AmazonConnect(_) => "replacement_amazon",
                        _ => "replacement_other",
                    }
                )
                .increment(1);
                Some(envelope)
            }
            Ok(None) => None,
            Err(RepositoryError::StaleClaim | RepositoryError::NotFound) => {
                return Err(RepositoryError::StaleClaim);
            }
            Err(error) => return Err(error),
        }
    } else {
        None
    };
    if replacement_context.is_none() && replacement_requires_initial_context(&endpoint) {
        return Ok(ReplacementStartExecution::rejected(
            deadline_generation,
            pending_binding_generation,
            "replacement_initial_context_missing",
            "the required initial context is unavailable for the replacement SIP route",
            false,
        ));
    }

    let replacement_sip_headers = if matches!(
        &endpoint,
        super::LegEndpointConfig::Sip(super::SipEndpointConfig {
            initial_context: SipInitialContextMode::Required,
            ..
        })
    ) {
        match replacement_context.as_ref() {
            Some(envelope) => match envelope
                .to_sip_headers(context_policy)
                .map_err(|_| ())
                .and_then(|headers| SipInitialHeaders::new(headers).map_err(|_| ()))
            {
                Ok(headers) => headers,
                Err(()) => {
                    return Ok(ReplacementStartExecution::rejected(
                        deadline_generation,
                        pending_binding_generation,
                        "replacement_context_invalid",
                        "the retained context could not be mapped to safe SIP headers",
                        false,
                    ));
                }
            },
            None => SipInitialHeaders::default(),
        }
    } else {
        SipInitialHeaders::default()
    };
    let replacement_amazon_attributes = if matches!(
        &endpoint,
        super::LegEndpointConfig::AmazonConnect(_)
    ) {
        match replacement_context.as_ref() {
            Some(envelope) => match context_to_amazon_attributes(envelope, context_policy) {
                Ok(attributes) => attributes,
                Err(()) => {
                    return Ok(ReplacementStartExecution::rejected(
                            deadline_generation,
                            pending_binding_generation,
                            "replacement_context_invalid",
                            "the retained context could not be mapped to safe Amazon Connect attributes",
                            false,
                        ));
                }
            },
            None => BTreeMap::new(),
        }
    } else {
        BTreeMap::new()
    };

    if let super::LegEndpointConfig::Provider(provider_endpoint) = &endpoint {
        if provider_endpoint.provider != ProviderKind::Telnyx {
            return Ok(ReplacementStartExecution::rejected(
                deadline_generation,
                pending_binding_generation,
                "provider_replacement_not_ready",
                "native replacement is supported only for Telnyx",
                false,
            ));
        }
        return execute_telnyx_leg_replacement(
            meta,
            stored,
            leg_id,
            previous_binding_generation,
            pending_binding_generation,
            deadline_generation,
            provider_endpoint.clone(),
            authorization_principal_fingerprint,
            replacement_context.as_ref(),
            context_policy,
            orchestrator,
            runtime,
            provider_executor,
            registration,
            &mut shutdown,
        )
        .await;
    }

    if let Some(private_egress) = private_egress.filter(|_| {
        matches!(
            &endpoint,
            super::LegEndpointConfig::Sip(_) | super::LegEndpointConfig::WebRtc(_)
        )
    }) {
        return execute_private_egress_leg_replacement(
            meta,
            stored,
            leg_id,
            previous_binding_generation,
            pending_binding_generation,
            deadline_generation,
            &endpoint,
            &replacement_route,
            &replacement_sip_headers,
            authorization_principal_fingerprint,
            orchestrator,
            runtime,
            private_egress,
            bindings,
            existing_pending,
            registration,
            shutdown,
        )
        .await;
    }

    let (session_id, created_session) = if let Some(session_id) = existing_session {
        (session_id, None)
    } else {
        let created =
            open_outbound_voice_session(orchestrator, &meta.tenant_id, &mut shutdown).await?;
        (created.1.clone(), Some(created))
    };
    let request = match &endpoint {
        super::LegEndpointConfig::Sip(_) => {
            let (target, context) =
                endpoint.replacement_sip_originate_context(replacement_sip_headers)?;
            let context = match apply_sip_outbound_profile(
                outbound_profiles,
                Some(&replacement_route),
                context,
            ) {
                Ok(context) => context,
                Err(error) => {
                    close_created_voice_session(orchestrator, &created_session).await;
                    let failure = outbound_profile_failure(error);
                    return Ok(ReplacementStartExecution::rejected(
                        deadline_generation,
                        pending_binding_generation,
                        failure.code,
                        failure.message,
                        failure.retryable,
                    ));
                }
            };
            OriginateRequest::new(
                session_id,
                ParticipantId::new(),
                target,
                Direction::Outbound,
                CapabilityDescriptor::default(),
            )
            .with_transport(Transport::Sip)
            .with_context(context)
        }
        super::LegEndpointConfig::WebRtc(_)
        | super::LegEndpointConfig::Whip(_)
        | super::LegEndpointConfig::Whep(_) => {
            let context = endpoint
                .replacement_web_rtc_originate_context(authorization_principal_fingerprint)?;
            let context = match apply_webrtc_outbound_profile(
                outbound_profiles,
                Some(&replacement_route),
                context,
            ) {
                Ok(context) => context,
                Err(error) => {
                    close_created_voice_session(orchestrator, &created_session).await;
                    let failure = outbound_profile_failure(error);
                    return Ok(ReplacementStartExecution::rejected(
                        deadline_generation,
                        pending_binding_generation,
                        failure.code,
                        failure.message,
                        failure.retryable,
                    ));
                }
            };
            let target = context.endpoint().as_str().to_owned();
            let capabilities = match orchestrator.adapter(Transport::WebRtc) {
                Ok(adapter) => adapter.capabilities(),
                Err(_) => {
                    close_created_voice_session(orchestrator, &created_session).await;
                    return Ok(ReplacementStartExecution::rejected(
                        deadline_generation,
                        pending_binding_generation,
                        "webrtc_adapter_unavailable",
                        "the registered WebRTC adapter is unavailable",
                        true,
                    ));
                }
            };
            OriginateRequest::new(
                session_id,
                ParticipantId::new(),
                target,
                Direction::Outbound,
                capabilities,
            )
            .with_transport(Transport::WebRtc)
            .with_context(context)
        }
        super::LegEndpointConfig::AmazonConnect(_) => {
            let Some(spec) = amazon_connect_start else {
                close_created_voice_session(orchestrator, &created_session).await;
                return Ok(ReplacementStartExecution::rejected(
                    deadline_generation,
                    pending_binding_generation,
                    "amazon_connect_start_unavailable",
                    "the replacement Amazon start authority is unavailable",
                    false,
                ));
            };
            if amazon_connect.is_none() {
                close_created_voice_session(orchestrator, &created_session).await;
                return Ok(ReplacementStartExecution::rejected(
                    deadline_generation,
                    pending_binding_generation,
                    "amazon_connect_not_configured",
                    "Amazon Connect replacement execution is not configured",
                    false,
                ));
            }
            let context = spec
                .originate_context_with_attributes(meta.effect_id, replacement_amazon_attributes)?;
            OriginateRequest::new(
                session_id,
                ParticipantId::new(),
                "amazon-connect",
                Direction::Outbound,
                CapabilityDescriptor::default(),
            )
            .with_transport(Transport::AmazonConnect)
            .with_context(context)
        }
        super::LegEndpointConfig::Provider(_) => unreachable!("provider replacement handled above"),
    };

    let prepared = match await_while_execution_owned(
        tokio::time::timeout(
            bounded_effect_operation_timeout(stored, runtime, DeadlineKind::Transfer),
            orchestrator.prepare_outbound_connection(request),
        ),
        &mut shutdown,
    )
    .await
    {
        Ok(Ok(Ok(prepared))) => prepared,
        Ok(Ok(Err(_))) | Ok(Err(_)) => {
            close_created_voice_session(orchestrator, &created_session).await;
            return Ok(ReplacementStartExecution::rejected(
                deadline_generation,
                pending_binding_generation,
                "replacement_prepare_failed",
                "rvoip could not prepare the replacement route",
                true,
            ));
        }
        Err(()) => {
            close_created_voice_session(orchestrator, &created_session).await;
            return Err(RepositoryError::Unavailable);
        }
    };
    send_replacement_ringing(orchestrator, stored, leg_id, pending_binding_generation).await;
    let connection_id = prepared.connection_id().clone();
    let actor_binding = ActorBinding {
        connection_id: connection_id.clone(),
        leg_id,
        binding_generation: pending_binding_generation,
        state: LegState::Signaling,
        private_egress: None,
    };
    if register_prepared_replacement(
        registration,
        meta.call_id,
        actor_binding,
        meta.effect_id,
        true,
        created_session.clone(),
        &mut shutdown,
    )
    .await
    .is_err()
    {
        let _ = prepared.abort().await;
        close_created_voice_session(orchestrator, &created_session).await;
        return Ok(ReplacementStartExecution::rejected(
            deadline_generation,
            pending_binding_generation,
            "replacement_owner_unavailable",
            "the call actor could not own the pending replacement route",
            true,
        ));
    }
    match await_while_execution_owned(
        tokio::time::timeout(
            bounded_effect_operation_timeout(stored, runtime, DeadlineKind::Transfer),
            prepared.commit(),
        ),
        &mut shutdown,
    )
    .await
    {
        Ok(Ok(Ok(handle))) => {
            let references = handle.outbound_activation().external_references();
            let external_reference = match &endpoint {
                super::LegEndpointConfig::Sip(_) => match references {
                    [reference] => sip_external_reference_binding(
                        leg_id,
                        pending_binding_generation,
                        reference,
                    ),
                    _ => Err(RepositoryError::InvalidInput(
                        "replacement SIP activation returned no durable Call-ID",
                    )),
                }
                .map(Some),
                super::LegEndpointConfig::AmazonConnect(_) => match references {
                    [reference] => amazon_external_reference_binding(
                        leg_id,
                        pending_binding_generation,
                        reference,
                    ),
                    _ => Err(RepositoryError::InvalidInput(
                        "replacement Amazon activation returned no durable contact identity",
                    )),
                }
                .map(Some),
                super::LegEndpointConfig::WebRtc(_)
                | super::LegEndpointConfig::Whip(_)
                | super::LegEndpointConfig::Whep(_) => Ok(None),
                super::LegEndpointConfig::Provider(_) => Err(RepositoryError::InvalidInput(
                    "provider replacement is unavailable",
                )),
            };
            match external_reference {
                Ok(external_reference) => Ok(ReplacementStartExecution {
                    result: ServiceEffectResult::Succeeded,
                    follow_up: FollowUpPlan::None,
                    external_reference,
                    additional_external_references: Vec::new(),
                }),
                Err(_) => {
                    let _ = orchestrator
                        .end_connection(connection_id, EndReason::BridgeTorn)
                        .await;
                    Ok(ReplacementStartExecution::rejected(
                        deadline_generation,
                        pending_binding_generation,
                        "replacement_reference_invalid",
                        "replacement activation returned no durable route identity",
                        false,
                    ))
                }
            }
        }
        Ok(Ok(Err(_))) => Ok(ReplacementStartExecution::rejected(
            deadline_generation,
            pending_binding_generation,
            "replacement_start_failed",
            "replacement signaling activation failed",
            true,
        )),
        Ok(Err(_)) => Ok(ReplacementStartExecution::rejected(
            deadline_generation,
            pending_binding_generation,
            "replacement_start_timeout",
            "replacement signaling exceeded the transfer deadline",
            true,
        )),
        Err(()) => Err(RepositoryError::Unavailable),
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_telnyx_leg_replacement(
    meta: &ClaimedEffectMeta,
    stored: &StoredServiceCall,
    leg_id: LegId,
    previous_binding_generation: crate::call_engine::BindingGeneration,
    pending_binding_generation: crate::call_engine::BindingGeneration,
    deadline_generation: crate::call_engine::DeadlineGeneration,
    endpoint: super::ProviderEndpointConfig,
    principal_fingerprint: crate::call_engine::PrincipalFingerprint,
    replacement_context: Option<&ContextEnvelope>,
    context_policy: &ContextPolicy,
    orchestrator: &Arc<Orchestrator>,
    runtime: &Arc<CallServiceRuntime>,
    provider_executor: &Arc<dyn ProviderLegExecutor>,
    registration: &mpsc::Sender<OutboundRegistration>,
    shutdown: &mut watch::Receiver<ActorShutdown>,
) -> Result<ReplacementStartExecution, RepositoryError> {
    let attachment_token = match runtime
        .service()
        .provider_media_attachment_token_for_generation(stored, leg_id, pending_binding_generation)
    {
        Ok(token) => token,
        Err(_) => {
            return Ok(ReplacementStartExecution::rejected(
                deadline_generation,
                pending_binding_generation,
                "provider_attachment_unavailable",
                "the pending Telnyx media attachment is unavailable",
                false,
            ));
        }
    };
    let context = ProviderExecutionContext {
        tenant_id: meta.tenant_id.clone(),
        call_id: meta.call_id,
        leg_id,
        binding_generation: pending_binding_generation,
        effect_id: meta.effect_id,
    };
    let media_client_state = match ProviderDialClientState::new(
        &context,
        ProviderDialRole::Media,
        replacement_context,
        context_policy,
    ) {
        Ok(state) => state,
        Err(_) => {
            return Ok(ReplacementStartExecution::rejected(
                deadline_generation,
                pending_binding_generation,
                "provider_context_invalid",
                "the retained Telnyx context could not be projected safely",
                false,
            ));
        }
    };
    let media_call = match await_while_execution_owned(
        tokio::time::timeout(
            bounded_effect_operation_timeout(stored, runtime, DeadlineKind::Transfer),
            provider_executor.start_media(ProviderStartMediaRequest {
                context: context.clone(),
                client_state: media_client_state,
                endpoint: endpoint.clone(),
                attachment_token,
            }),
        ),
        shutdown,
    )
    .await
    {
        Ok(Ok(Ok(reference))) => reference,
        Ok(Ok(Err(error))) => {
            let failure = provider_execution_failure("provider_media_start", error);
            return Ok(ReplacementStartExecution::rejected(
                deadline_generation,
                pending_binding_generation,
                failure.code(),
                failure.message(),
                failure.retryable(),
            ));
        }
        Ok(Err(_)) => {
            return Ok(ReplacementStartExecution::rejected(
                deadline_generation,
                pending_binding_generation,
                "provider_media_start_timeout",
                "Telnyx media origination exceeded the replacement deadline",
                true,
            ));
        }
        Err(()) => return Err(RepositoryError::Unavailable),
    };
    let media_reference = provider_reference_binding(
        leg_id,
        pending_binding_generation,
        ProviderReferenceRole::Media,
        media_call.clone(),
    );
    send_replacement_ringing(orchestrator, stored, leg_id, pending_binding_generation).await;
    let attachment = await_while_execution_owned(
        tokio::time::timeout(
            bounded_effect_operation_timeout(stored, runtime, DeadlineKind::Transfer),
            async {
                loop {
                    let current = runtime
                        .service_repository()
                        .load_service_call(&meta.tenant_id, meta.call_id)
                        .await?;
                    if current
                        .call
                        .aggregate
                        .replacement()
                        .is_none_or(|replacement| {
                            replacement.leg_id() != leg_id
                                || replacement.previous_binding_generation()
                                    != previous_binding_generation
                                || replacement.pending_binding_generation()
                                    != pending_binding_generation
                        })
                    {
                        return Err(RepositoryError::StaleClaim);
                    }
                    if let Some(binding) = runtime
                        .service_repository()
                        .load_attachment_binding(
                            &meta.tenant_id,
                            meta.call_id,
                            leg_id,
                            pending_binding_generation,
                            AttachmentPurpose::ProviderMedia,
                        )
                        .await?
                    {
                        return Ok(binding);
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            },
        ),
        shutdown,
    )
    .await;
    let attachment = match attachment {
        Ok(Ok(Ok(binding))) => binding,
        Ok(Ok(Err(RepositoryError::StaleClaim))) => {
            let _ = provider_executor
                .hangup(ProviderHangupRequest {
                    context,
                    endpoint,
                    media_call,
                })
                .await;
            return Ok(ReplacementStartExecution {
                result: ServiceEffectResult::Failed(FailureDetails::sanitized(
                    "provider_replacement_cancelled",
                    "the source ended while Telnyx replacement media was attaching",
                    false,
                )),
                follow_up: FollowUpPlan::None,
                external_reference: Some(media_reference),
                additional_external_references: Vec::new(),
            });
        }
        Ok(Ok(Err(error))) => return Err(error),
        Ok(Err(_)) => {
            let failure = FailureDetails::sanitized(
                "provider_attachment_timeout",
                "Telnyx did not consume its authenticated SIP attachment in time",
                true,
            );
            return Ok(ReplacementStartExecution::rejected_with_provider_reference(
                deadline_generation,
                pending_binding_generation,
                failure,
                media_reference,
            ));
        }
        Err(()) => return Err(RepositoryError::Unavailable),
    };
    if attachment.transport != AttachmentTransport::Sip
        || attachment.principal_fingerprint != principal_fingerprint
    {
        return Ok(ReplacementStartExecution::rejected_with_provider_reference(
            deadline_generation,
            pending_binding_generation,
            FailureDetails::sanitized(
                "provider_attachment_mismatch",
                "the authenticated Telnyx attachment does not match replacement authority",
                false,
            ),
            media_reference,
        ));
    }
    let pending = ActorBinding {
        connection_id: attachment.connection_id.clone(),
        leg_id,
        binding_generation: pending_binding_generation,
        state: LegState::Signaling,
        private_egress: None,
    };
    if register_prepared_replacement(
        registration,
        meta.call_id,
        pending,
        meta.effect_id,
        false,
        None,
        shutdown,
    )
    .await
    .is_err()
    {
        return Ok(ReplacementStartExecution::rejected_with_provider_reference(
            deadline_generation,
            pending_binding_generation,
            FailureDetails::sanitized(
                "replacement_owner_unavailable",
                "the call actor could not own the Telnyx media attachment",
                true,
            ),
            media_reference,
        ));
    }
    let destination_client_state = match ProviderDialClientState::new(
        &context,
        ProviderDialRole::Destination,
        replacement_context,
        context_policy,
    ) {
        Ok(state) => state,
        Err(_) => {
            return Ok(ReplacementStartExecution::rejected_with_provider_reference(
                deadline_generation,
                pending_binding_generation,
                FailureDetails::sanitized(
                    "provider_context_invalid",
                    "the retained Telnyx context could not be projected safely",
                    false,
                ),
                media_reference,
            ));
        }
    };
    match await_while_execution_owned(
        tokio::time::timeout(
            bounded_effect_operation_timeout(stored, runtime, DeadlineKind::Transfer),
            provider_executor.connect_destination(ProviderConnectDestinationRequest {
                context,
                client_state: destination_client_state,
                endpoint,
                media_call,
            }),
        ),
        shutdown,
    )
    .await
    {
        Ok(Ok(Ok(destination))) => {
            Ok(ReplacementStartExecution {
                result: ServiceEffectResult::Succeeded,
                // A successful Dial response proves only that Telnyx accepted
                // the destination command. The held route must remain current
                // until the exact destination reference emits an authenticated
                // `call.bridged` callback. Provider-event reconciliation owns
                // the atomic binding promotion.
                follow_up: FollowUpPlan::None,
                external_reference: Some(media_reference),
                additional_external_references: vec![provider_reference_binding(
                    leg_id,
                    pending_binding_generation,
                    ProviderReferenceRole::Destination,
                    destination,
                )],
            })
        }
        Ok(Ok(Err(error))) => Ok(ReplacementStartExecution::rejected_with_provider_reference(
            deadline_generation,
            pending_binding_generation,
            provider_execution_failure("provider_destination", error),
            media_reference,
        )),
        Ok(Err(_)) => Ok(ReplacementStartExecution::rejected_with_provider_reference(
            deadline_generation,
            pending_binding_generation,
            FailureDetails::sanitized(
                "provider_destination_timeout",
                "Telnyx destination origination exceeded the replacement deadline",
                true,
            ),
            media_reference,
        )),
        Err(()) => Err(RepositoryError::Unavailable),
    }
}

enum PreparedTransferOperation {
    Provider(Box<ProviderTransferRequest>),
    Transport {
        connection_id: ConnectionId,
        target: RvoipTransferTarget,
        attempt_id: TransferAttemptId,
    },
}

fn rvoip_transfer_target(
    target: super::TransferTarget,
) -> Result<RvoipTransferTarget, FailureDetails> {
    match target {
        super::TransferTarget::Sip { uri } | super::TransferTarget::WebRtc { uri } => {
            Ok(RvoipTransferTarget::Uri(uri))
        }
        super::TransferTarget::AmazonConnect { .. } | super::TransferTarget::Provider { .. } => {
            Err(FailureDetails::sanitized(
                "transfer_target_unsupported",
                "the transport cannot represent the requested transfer target",
                false,
            ))
        }
    }
}

fn transfer_attempt_id(
    call_id: CallId,
    leg_id: LegId,
    binding_generation: crate::call_engine::BindingGeneration,
    deadline_generation: crate::call_engine::DeadlineGeneration,
) -> TransferAttemptId {
    TransferAttemptId::from_string(format!(
        "xfer_{}_{}_{}_{}",
        call_id.as_uuid().simple(),
        leg_id.as_uuid().simple(),
        binding_generation.value(),
        deadline_generation.value()
    ))
}

fn transfer_status_matches_current(
    stored: &StoredServiceCall,
    binding: &ActorBinding,
    attempt_id: &TransferAttemptId,
) -> bool {
    let deadline = stored
        .call
        .aggregate
        .deadlines()
        .get(DeadlineKind::Transfer);
    stored.call.aggregate.state() == CallState::Transferring
        && deadline.due_at().is_some()
        && transfer_attempt_id(
            stored.call.aggregate.id(),
            binding.leg_id,
            binding.binding_generation,
            deadline.generation(),
        ) == *attempt_id
        && stored
            .call
            .bindings
            .get(&binding.leg_id)
            .is_some_and(|durable| {
                durable.connection_id == binding.connection_id
                    && durable.binding_generation == binding.binding_generation
            })
}

fn rvoip_transfer_failure(error: &rvoip_core::RvoipError) -> FailureDetails {
    if error.diagnostic_class() == "not-implemented" {
        FailureDetails::sanitized(
            "transport_transfer_unsupported",
            "the selected transport does not support transfer",
            false,
        )
    } else {
        FailureDetails::sanitized(
            "transport_transfer_failed",
            "the transport rejected transfer submission",
            true,
        )
    }
}

fn provider_reference_binding(
    leg_id: LegId,
    binding_generation: crate::call_engine::BindingGeneration,
    role: ProviderReferenceRole,
    reference: ProviderExecutionReference,
) -> ExternalReferenceBinding {
    ExternalReferenceBinding {
        leg_id,
        binding_generation,
        role,
        value: ExternalReferenceValue::ProviderCall {
            account: reference.account,
            provider_call_id: reference.provider_call_id,
        },
    }
}

fn provider_endpoint_for_leg(
    stored: &StoredServiceCall,
    leg_id: LegId,
) -> Option<super::ProviderEndpointConfig> {
    stored
        .plan
        .legs
        .iter()
        .find(|spec| spec.leg_id == leg_id)
        .and_then(|spec| match &spec.endpoint {
            super::LegEndpointConfig::Provider(endpoint)
                if endpoint.provider == ProviderKind::Telnyx =>
            {
                Some(endpoint.clone())
            }
            _ => None,
        })
}

async fn load_provider_media_reference(
    runtime: &Arc<CallServiceRuntime>,
    tenant_id: &crate::call_engine::TenantId,
    call_id: CallId,
    leg_id: LegId,
    binding_generation: crate::call_engine::BindingGeneration,
    endpoint: &super::ProviderEndpointConfig,
) -> Result<ProviderExecutionReference, ProviderExecutionError> {
    let stored = runtime
        .service_repository()
        .load_external_reference_by_role(tenant_id, call_id, leg_id, ProviderReferenceRole::Media)
        .await
        .map_err(|_| ProviderExecutionError::Remote { retryable: true })?
        .filter(|reference| {
            reference.binding_generation == binding_generation
                && reference.role == ProviderReferenceRole::Media
        })
        .ok_or(ProviderExecutionError::InvalidRequest)?;
    match stored.value {
        ExternalReferenceValue::ProviderCall {
            account,
            provider_call_id,
        } if account.as_str() == endpoint.account_profile => Ok(ProviderExecutionReference {
            account,
            provider_call_id,
        }),
        _ => Err(ProviderExecutionError::AccountProfileMismatch),
    }
}

async fn load_provider_media_for_binding(
    runtime: &Arc<CallServiceRuntime>,
    stored: &StoredServiceCall,
    tenant_id: &crate::call_engine::TenantId,
    call_id: CallId,
    leg_id: LegId,
    binding_generation: crate::call_engine::BindingGeneration,
) -> Result<(super::ProviderEndpointConfig, ProviderExecutionReference), ProviderExecutionError> {
    let reference = runtime
        .service_repository()
        .load_external_reference_for_binding(
            tenant_id,
            call_id,
            leg_id,
            binding_generation,
            ProviderReferenceRole::Media,
        )
        .await
        .map_err(|_| ProviderExecutionError::Remote { retryable: true })?
        .ok_or(ProviderExecutionError::InvalidRequest)?;
    let endpoint = provider_endpoint_for_leg(stored, leg_id).filter(|endpoint| {
        matches!(
            &reference.value,
            ExternalReferenceValue::ProviderCall { account, .. }
                if account.as_str() == endpoint.account_profile
        )
    });
    let endpoint = match endpoint {
        Some(endpoint) => endpoint,
        None => runtime
            .service_repository()
            .load_effect_payload(tenant_id, reference.effect_id)
            .await
            .map_err(|_| ProviderExecutionError::Remote { retryable: true })?
            .and_then(|payload| match payload.payload {
                ServiceEffectPayload::LegReplacement {
                    leg_id: payload_leg,
                    pending_binding_generation,
                    endpoint: super::LegEndpointConfig::Provider(endpoint),
                    ..
                } if payload_leg == leg_id
                    && pending_binding_generation == binding_generation
                    && endpoint.provider == ProviderKind::Telnyx =>
                {
                    Some(endpoint)
                }
                _ => None,
            })
            .ok_or(ProviderExecutionError::InvalidRequest)?,
    };
    match reference.value {
        ExternalReferenceValue::ProviderCall {
            account,
            provider_call_id,
        } if account.as_str() == endpoint.account_profile => Ok((
            endpoint,
            ProviderExecutionReference {
                account,
                provider_call_id,
            },
        )),
        _ => Err(ProviderExecutionError::AccountProfileMismatch),
    }
}

fn provider_execution_failure(
    operation: &'static str,
    error: ProviderExecutionError,
) -> FailureDetails {
    let code = match error {
        ProviderExecutionError::Disabled => "provider_execution_disabled",
        ProviderExecutionError::Unsupported => "provider_operation_unsupported",
        ProviderExecutionError::AccountProfileMismatch => "provider_account_mismatch",
        ProviderExecutionError::InvalidRequest => "provider_request_invalid",
        ProviderExecutionError::Remote { .. } => operation,
    };
    FailureDetails::sanitized(
        code,
        "the provider operation did not complete successfully",
        error.retryable(),
    )
}

async fn execute_control_effect(
    claim: ClaimedControlEffect,
    orchestrator: Arc<Orchestrator>,
    runtime: Arc<CallServiceRuntime>,
    provider_executor: Arc<dyn ProviderLegExecutor>,
    private_egress: Option<Arc<PrivateEgressWorkerRuntime>>,
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
            if let (Some(private_egress), Some(route)) =
                (private_egress.as_ref(), binding.private_egress.as_ref())
            {
                let command = private_egress_command(
                    Uuid::new_v4(),
                    &runtime,
                    route.source.clone(),
                    route.target,
                    PrivateEgressOperation::Dtmf {
                        digits: sequence.digits.clone(),
                        duration_ms: u32::from(sequence.duration_ms),
                    },
                );
                match command {
                    Ok(command) => match tokio::time::timeout(
                        EXTERNAL_OPERATION_TIMEOUT,
                        private_egress
                            .control()
                            .execute(route.source_connection.clone(), command),
                    )
                    .await
                    {
                        Ok(Ok(response))
                            if response.accepted
                                && response.state == Some(PrivateEgressLifecycleState::Active) =>
                        {
                            ServiceEffectResult::Succeeded
                        }
                        _ => ServiceEffectResult::Failed(FailureDetails::sanitized(
                            "private_egress_dtmf_failed",
                            "the gateway could not deliver the requested DTMF sequence",
                            true,
                        )),
                    },
                    Err(()) => ServiceEffectResult::Failed(FailureDetails::sanitized(
                        "private_egress_dtmf_invalid",
                        "the gateway DTMF command could not be represented",
                        false,
                    )),
                }
            } else {
                match runtime
                    .service_repository()
                    .load_service_call(&meta.tenant_id, meta.call_id)
                    .await
                {
                    Ok(stored) => match load_provider_media_for_binding(
                        &runtime,
                        &stored,
                        &meta.tenant_id,
                        meta.call_id,
                        claim.record.leg_id,
                        claim.record.binding_generation,
                    )
                    .await
                    {
                        Ok((endpoint, media_call)) => match tokio::time::timeout(
                            EXTERNAL_OPERATION_TIMEOUT,
                            provider_executor.send_dtmf(ProviderDtmfRequest {
                                context: ProviderExecutionContext {
                                    tenant_id: meta.tenant_id.clone(),
                                    call_id: meta.call_id,
                                    leg_id: claim.record.leg_id,
                                    binding_generation: claim.record.binding_generation,
                                    effect_id,
                                },
                                endpoint,
                                media_call,
                                sequence: sequence.clone(),
                            }),
                        )
                        .await
                        {
                            Ok(Ok(())) => ServiceEffectResult::Succeeded,
                            Ok(Err(error)) => ServiceEffectResult::Failed(
                                provider_execution_failure("provider_dtmf_failed", error),
                            ),
                            Err(_) => ServiceEffectResult::Failed(FailureDetails::sanitized(
                                "provider_dtmf_timeout",
                                "provider DTMF delivery exceeded its deadline",
                                true,
                            )),
                        },
                        Err(ProviderExecutionError::InvalidRequest) => match tokio::time::timeout(
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
                            Ok(Err(_)) | Err(_) => {
                                ServiceEffectResult::Failed(FailureDetails::sanitized(
                                    "dtmf_failed",
                                    "rvoip could not deliver the requested DTMF sequence",
                                    true,
                                ))
                            }
                        },
                        Err(error) => ServiceEffectResult::Failed(provider_execution_failure(
                            "provider_dtmf_reference_failed",
                            error,
                        )),
                    },
                    Err(_) => ServiceEffectResult::Failed(FailureDetails::sanitized(
                        "dtmf_call_unavailable",
                        "the DTMF target call is unavailable",
                        true,
                    )),
                }
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
        handoff_signal: None,
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
        handoff_signal: None,
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
        let authority = current_provider_for_event(&claim.event, &target, &stored, runtime).await?;
        let follow_up = match authority {
            Some(authority) => {
                build_provider_follow_up(
                    authority,
                    &claim.event.kind,
                    &claim.event.payload,
                    &target,
                    &stored,
                    runtime,
                    at,
                )
                .await?
            }
            None => None,
        };
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProviderEventAuthority {
    provider: ProviderKind,
    binding_generation: crate::call_engine::BindingGeneration,
    effect_id: crate::call_engine::EffectId,
    pending_replacement: bool,
}

async fn current_provider_for_event(
    event: &crate::call_engine::ProviderEventEnvelope,
    target: &crate::call_engine::ProviderEventTarget,
    stored: &StoredServiceCall,
    runtime: &Arc<CallServiceRuntime>,
) -> Result<Option<ProviderEventAuthority>, RepositoryError> {
    let Some(leg) = stored.call.aggregate.leg(target.leg_id) else {
        return Err(RepositoryError::ProviderReferenceConflict);
    };
    let current_reference = runtime
        .service_repository()
        .load_external_reference_by_role(
            &target.tenant_id,
            target.call_id,
            target.leg_id,
            target.role,
        )
        .await?;
    let current_reference = current_reference.filter(|reference| {
        reference.binding_generation == leg.binding_generation()
            && provider_reference_matches_event(reference, event)
    });
    let replacement = stored
        .call
        .aggregate
        .replacement()
        .filter(|replacement| replacement.leg_id() == target.leg_id);
    let pending_reference = match replacement {
        Some(replacement) => runtime
            .service_repository()
            .load_external_reference_for_binding(
                &target.tenant_id,
                target.call_id,
                target.leg_id,
                replacement.pending_binding_generation(),
                target.role,
            )
            .await?
            .filter(|reference| provider_reference_matches_event(reference, event)),
        None => None,
    };
    let (reference, pending_replacement) = match (current_reference, pending_reference) {
        (Some(reference), None) => (reference, false),
        (None, Some(reference)) => (reference, true),
        (None, None) => return Ok(None),
        (Some(_), Some(_)) => return Err(RepositoryError::ProviderReferenceConflict),
    };

    if let Some(payload) = runtime
        .service_repository()
        .load_effect_payload(&target.tenant_id, reference.effect_id)
        .await?
    {
        if let ServiceEffectPayload::LegReplacement {
            endpoint: super::LegEndpointConfig::Provider(endpoint),
            ..
        } = payload.payload
        {
            if endpoint.account_profile == event.account.as_str() {
                return Ok(Some(ProviderEventAuthority {
                    provider: endpoint.provider,
                    binding_generation: reference.binding_generation,
                    effect_id: reference.effect_id,
                    pending_replacement,
                }));
            }
            return Err(RepositoryError::ProviderReferenceConflict);
        }
    }

    stored
        .plan
        .legs
        .iter()
        .find(|spec| spec.leg_id == target.leg_id)
        .and_then(|spec| match &spec.endpoint {
            super::LegEndpointConfig::Provider(endpoint)
                if endpoint.account_profile == event.account.as_str() =>
            {
                Some(endpoint.provider)
            }
            _ => None,
        })
        .map(|provider| {
            Some(ProviderEventAuthority {
                provider,
                binding_generation: reference.binding_generation,
                effect_id: reference.effect_id,
                pending_replacement,
            })
        })
        .ok_or(RepositoryError::ProviderReferenceConflict)
}

fn provider_reference_matches_event(
    reference: &super::StoredExternalReference,
    event: &crate::call_engine::ProviderEventEnvelope,
) -> bool {
    matches!(
        &reference.value,
        ExternalReferenceValue::ProviderCall {
            account,
            provider_call_id,
        } if account == &event.account && provider_call_id == &event.provider_call_id
    )
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

async fn build_provider_follow_up(
    authority: ProviderEventAuthority,
    kind: &str,
    payload: &serde_json::Value,
    target: &crate::call_engine::ProviderEventTarget,
    stored: &StoredServiceCall,
    runtime: &Arc<CallServiceRuntime>,
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
    if authority.pending_replacement {
        if !telnyx_dial_client_state_matches(authority, payload, target) {
            record_telnyx_client_state_rejection(target.role, "replacement_mismatch");
            return Ok(None);
        }
        return build_pending_telnyx_replacement_follow_up(
            authority, kind, target, stored, runtime, at,
        )
        .await;
    }
    let provider = authority.provider;
    let transfer_callback = provider == ProviderKind::Telnyx
        && target.role == ProviderReferenceRole::Media
        && stored.call.aggregate.state() == CallState::Transferring
        && matches!(
            kind.trim().to_ascii_lowercase().as_str(),
            "call.bridged" | "call.failed"
        );
    if let Some(result) = correlated_provider_transfer_result(
        provider,
        kind,
        payload,
        target,
        stored,
        authority.binding_generation,
    ) {
        let deadline_generation = stored
            .call
            .aggregate
            .deadlines()
            .get(DeadlineKind::Transfer)
            .generation();
        return Ok(Some(provider_follow_up_transaction(
            target,
            stored,
            at,
            CallCommand::FinishTransfer {
                at,
                deadline_generation,
                result,
            },
        )));
    }
    if transfer_callback {
        record_telnyx_client_state_rejection(target.role, "transfer_mismatch");
        return Ok(None);
    }
    if provider == ProviderKind::Telnyx
        && !telnyx_lifecycle_client_state_matches(authority, payload, target)
    {
        record_telnyx_client_state_rejection(target.role, "dial_mismatch");
        return Ok(None);
    }
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
        if provider == ProviderKind::Telnyx
            && stored
                .call
                .bindings
                .get(&target.leg_id)
                .is_none_or(|binding| binding.binding_generation != leg.binding_generation())
        {
            return Err(RepositoryError::StaleClaim);
        }
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
    Ok(Some(provider_follow_up_transaction(
        target,
        stored,
        at,
        CallCommand::SetLegState {
            at,
            leg_id: target.leg_id,
            binding_generation: leg.binding_generation(),
            state,
            failure,
        },
    )))
}

fn telnyx_dial_client_state_matches(
    authority: ProviderEventAuthority,
    payload: &serde_json::Value,
    target: &crate::call_engine::ProviderEventTarget,
) -> bool {
    if authority.provider != ProviderKind::Telnyx {
        return false;
    }
    let Some(client_state) = payload
        .pointer("/data/payload/client_state")
        .and_then(serde_json::Value::as_str)
    else {
        return false;
    };
    let Ok(state) =
        telnyx::calls::client_state::decode_json::<ProviderDialClientState>(client_state)
    else {
        return false;
    };
    let role = match target.role {
        ProviderReferenceRole::Media => ProviderDialRole::Media,
        ProviderReferenceRole::Destination => ProviderDialRole::Destination,
    };
    state.matches(
        &ProviderExecutionContext {
            tenant_id: target.tenant_id.clone(),
            call_id: target.call_id,
            leg_id: target.leg_id,
            binding_generation: authority.binding_generation,
            effect_id: authority.effect_id,
        },
        role,
    )
}

fn telnyx_lifecycle_client_state_matches(
    authority: ProviderEventAuthority,
    payload: &serde_json::Value,
    target: &crate::call_engine::ProviderEventTarget,
) -> bool {
    if telnyx_dial_client_state_matches(authority, payload, target) {
        return true;
    }
    if target.role != ProviderReferenceRole::Media {
        return false;
    }
    let Some(client_state) = payload
        .pointer("/data/payload/client_state")
        .and_then(serde_json::Value::as_str)
    else {
        return false;
    };
    telnyx::calls::client_state::decode_json::<ProviderTransferCorrelation>(client_state).is_ok_and(
        |state| {
            state.matches_owner(
                &target.tenant_id,
                target.call_id,
                target.leg_id,
                authority.binding_generation,
            )
        },
    )
}

fn record_telnyx_client_state_rejection(role: ProviderReferenceRole, reason: &'static str) {
    metrics::counter!(
        "bridgefu_provider_client_state_total",
        "provider" => "telnyx",
        "role" => match role {
            ProviderReferenceRole::Media => "media",
            ProviderReferenceRole::Destination => "destination",
        },
        "result" => "rejected",
        "reason" => reason
    )
    .increment(1);
}

async fn build_pending_telnyx_replacement_follow_up(
    authority: ProviderEventAuthority,
    kind: &str,
    target: &crate::call_engine::ProviderEventTarget,
    stored: &StoredServiceCall,
    runtime: &Arc<CallServiceRuntime>,
    at: DateTime<Utc>,
) -> Result<Option<ServiceCommandTransaction>, RepositoryError> {
    if authority.provider != ProviderKind::Telnyx {
        return Err(RepositoryError::ProviderReferenceConflict);
    }
    let replacement = stored
        .call
        .aggregate
        .replacement()
        .filter(|replacement| {
            replacement.leg_id() == target.leg_id
                && replacement.pending_binding_generation() == authority.binding_generation
                && replacement.pending_kind() == crate::call_engine::LegKind::Telnyx
        })
        .ok_or(RepositoryError::StaleClaim)?;
    let deadline = stored
        .call
        .aggregate
        .deadlines()
        .get(DeadlineKind::Transfer);
    if stored.call.aggregate.state() != CallState::Transferring || deadline.due_at().is_none() {
        return Err(RepositoryError::StaleClaim);
    }

    let result = match kind.trim().to_ascii_lowercase().as_str() {
        "call.bridged" if target.role == ProviderReferenceRole::Destination => {
            LegReplacementResult::Connected
        }
        // Either half of the provider-controlled pair ending before the
        // destination-ready proof invalidates the attempt and resumes the
        // exact held generation.
        "call.failed" | "call.hangup" | "call.not-connected" => {
            LegReplacementResult::Rejected(FailureDetails::sanitized(
                "provider_replacement_not_ready",
                "the provider destination ended before media was ready",
                false,
            ))
        }
        // Progress and unknown signed callbacks are acknowledged without
        // changing the durable replacement. In particular, a media-role
        // `call.bridged` can never promote the destination-role binding.
        _ => return Ok(None),
    };

    let mut transaction = provider_follow_up_transaction(
        target,
        stored,
        at,
        CallCommand::FinishLegReplacement {
            at,
            deadline_generation: deadline.generation(),
            pending_binding_generation: authority.binding_generation,
            result: result.clone(),
        },
    );
    if matches!(result, LegReplacementResult::Connected) {
        let previous = stored
            .call
            .bindings
            .get(&target.leg_id)
            .filter(|binding| {
                binding.binding_generation == replacement.previous_binding_generation()
            })
            .ok_or(RepositoryError::StaleClaim)?;
        let pending = runtime
            .service_repository()
            .load_attachment_binding(
                &target.tenant_id,
                target.call_id,
                target.leg_id,
                authority.binding_generation,
                AttachmentPurpose::ProviderMedia,
            )
            .await?
            .filter(|binding| {
                binding.leg_id == target.leg_id
                    && binding.binding_generation == authority.binding_generation
                    && binding.transport == AttachmentTransport::Sip
            })
            .ok_or(RepositoryError::StaleClaim)?;
        transaction.replacement_connection = Some(ReplacementConnectionPromotion {
            previous_connection_id: previous.connection_id.clone(),
            connection_id: pending.connection_id,
            leg_id: target.leg_id,
            previous_binding_generation: replacement.previous_binding_generation(),
            pending_binding_generation: authority.binding_generation,
            transport: AttachmentTransport::Sip,
            principal_fingerprint: pending.principal_fingerprint,
        });
    }
    Ok(Some(transaction))
}

fn provider_follow_up_transaction(
    target: &crate::call_engine::ProviderEventTarget,
    stored: &StoredServiceCall,
    at: DateTime<Utc>,
    command: CallCommand,
) -> ServiceCommandTransaction {
    ServiceCommandTransaction {
        command: CommandCommit {
            tenant_id: target.tenant_id.clone(),
            call_id: target.call_id,
            expected_version: stored.call.aggregate.version(),
            command_id: CommandId::new(),
            command,
            worker: stored.call.assignment.lease,
            attachments: Vec::new(),
            deadline_claim: None,
            at,
        },
        effect_payloads: Vec::new(),
        operation_idempotency: None,
        bound_connection: None,
        media_activity: None,
        replacement_connection: None,
    }
}

fn correlated_provider_transfer_result(
    provider: ProviderKind,
    kind: &str,
    payload: &serde_json::Value,
    target: &crate::call_engine::ProviderEventTarget,
    stored: &StoredServiceCall,
    binding_generation: crate::call_engine::BindingGeneration,
) -> Option<TransferResult> {
    if provider != ProviderKind::Telnyx
        || target.role != ProviderReferenceRole::Media
        || stored.call.aggregate.state() != CallState::Transferring
    {
        return None;
    }
    let result = match kind.trim().to_ascii_lowercase().as_str() {
        "call.bridged" => TransferResult::Completed,
        "call.failed" => TransferResult::Rejected(FailureDetails::sanitized(
            "provider_transfer_rejected",
            "the provider reported that the transfer did not complete",
            false,
        )),
        _ => return None,
    };
    let deadline = stored
        .call
        .aggregate
        .deadlines()
        .get(DeadlineKind::Transfer);
    deadline.due_at()?;
    let client_state = payload
        .pointer("/data/payload/client_state")
        .and_then(serde_json::Value::as_str)?;
    let correlation =
        telnyx::calls::client_state::decode_json::<ProviderTransferCorrelation>(client_state)
            .ok()?;
    correlation
        .matches(
            &target.tenant_id,
            target.call_id,
            target.leg_id,
            binding_generation,
            deadline.generation(),
        )
        .then_some(result)
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
            "call.initiated" | "call.ringing" | "call.answered" => ProviderLifecycle::Progress,
            "call.bridged" => ProviderLifecycle::Connected,
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
    shutdown: watch::Receiver<ActorShutdown>,
) -> Result<(), RepositoryError> {
    reconcile_effect_with_reference(meta, result, None, follow_up, runtime, shutdown).await
}

async fn reconcile_effect_with_reference(
    meta: ClaimedEffectMeta,
    result: ServiceEffectResult,
    external_reference: Option<ExternalReferenceBinding>,
    follow_up: FollowUpPlan,
    runtime: Arc<CallServiceRuntime>,
    shutdown: watch::Receiver<ActorShutdown>,
) -> Result<(), RepositoryError> {
    reconcile_effect_with_references(
        meta,
        result,
        external_reference,
        Vec::new(),
        follow_up,
        runtime,
        shutdown,
    )
    .await
}

async fn reconcile_effect_with_references(
    meta: ClaimedEffectMeta,
    result: ServiceEffectResult,
    external_reference: Option<ExternalReferenceBinding>,
    additional_external_references: Vec<ExternalReferenceBinding>,
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
            external_reference: external_reference.clone(),
            additional_external_references: additional_external_references.clone(),
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
        FollowUpPlan::ProviderMediaStarted {
            leg_id,
            binding_generation,
        } => CallCommand::ProviderMediaStarted {
            at: requested_at,
            leg_id: *leg_id,
            binding_generation: *binding_generation,
        },
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
        FollowUpPlan::FinishLegReplacement {
            deadline_generation,
            pending_binding_generation,
            result,
            ..
        } => CallCommand::FinishLegReplacement {
            at: requested_at,
            deadline_generation: *deadline_generation,
            pending_binding_generation: *pending_binding_generation,
            result: result.clone(),
        },
    };
    let stored = runtime
        .service_repository()
        .load_service_call(&meta.tenant_id, meta.call_id)
        .await?;
    if matches!(plan, FollowUpPlan::ProviderMediaStarted { .. })
        && stored.call.aggregate.state() != CallState::Connecting
    {
        // Source loss can commit concurrently after StartLeg observes its
        // cancellation token but before reconciliation is built. Retain the
        // successful provider reference while suppressing the now-invalid
        // state advance; the already-enqueued StopLeg owns compensation.
        return Ok(None);
    }
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
        CallCommand::ProviderMediaStarted {
            leg_id,
            binding_generation,
            ..
        } => CallCommand::ProviderMediaStarted {
            at,
            leg_id,
            binding_generation,
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
        CallCommand::FinishLegReplacement {
            deadline_generation,
            pending_binding_generation,
            result,
            ..
        } => CallCommand::FinishLegReplacement {
            at,
            deadline_generation,
            pending_binding_generation,
            result,
        },
        _ => unreachable!("follow-up plan only builds supported commands"),
    };
    let replacement_connection = match plan {
        FollowUpPlan::FinishLegReplacement {
            replacement_connection,
            ..
        } => replacement_connection.clone(),
        _ => None,
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
        replacement_connection,
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
            replacement_connection: None,
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
            replacement_connection: None,
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
            replacement_connection: None,
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

fn private_egress_peer_stop_operation(state: LegState) -> PrivateEgressOperation {
    if matches!(state, LegState::Connected | LegState::Held) {
        PrivateEgressOperation::End {
            reason: PrivateEgressEndReason::Normal,
        }
    } else {
        // Prepare is deliberately dormant. If source cancellation wins before
        // activation, abort the prepared destination rather than representing
        // it as an established call.
        PrivateEgressOperation::Abort
    }
}

fn normalize_terminal_transport_cleanup(result: Result<(), RvoipError>) -> Result<(), ()> {
    match result {
        Ok(()) | Err(RvoipError::ConnectionNotFound(_)) => Ok(()),
        Err(_) => Err(()),
    }
}

enum StartOperationWait<T> {
    Completed(T),
    CallEnding,
    AuthorityLost,
}

async fn await_start_operation<F, T>(
    future: F,
    shutdown: &mut watch::Receiver<ActorShutdown>,
    setup_cancel: &CancellationToken,
) -> StartOperationWait<T>
where
    F: std::future::Future<Output = T>,
{
    tokio::pin!(future);
    loop {
        if setup_cancel.is_cancelled() {
            return StartOperationWait::CallEnding;
        }
        if *shutdown.borrow() == ActorShutdown::LeaseLost {
            return StartOperationWait::AuthorityLost;
        }
        tokio::select! {
            biased;
            _ = setup_cancel.cancelled() => return StartOperationWait::CallEnding,
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() == ActorShutdown::LeaseLost {
                    return StartOperationWait::AuthorityLost;
                }
            }
            result = &mut future => return StartOperationWait::Completed(result),
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
        OperationalEventKind::MediaActivity { .. }
        | OperationalEventKind::Progress { .. }
        | OperationalEventKind::Dtmf { .. }
        | OperationalEventKind::DataMessage { .. }
        | OperationalEventKind::Transfer { .. }
        | OperationalEventKind::TransferStatus { .. } => OperationalTransition::Ephemeral,
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
        OperationalEventKind::Progress { .. } => "progress",
        OperationalEventKind::Dtmf { .. } => "dtmf",
        OperationalEventKind::DataMessage { .. } => "data_message",
        OperationalEventKind::Transfer { .. } => "transfer",
        OperationalEventKind::TransferStatus { .. } => "transfer_status",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;

    use crate::call_engine::{BindingGeneration, WorkerFence, WorkerId, WorkerLease};
    use crate::call_service::{
        build_call_service_runtime, AmazonConnectEndpointConfig, AmazonConnectStartSpec,
        CallRepositoryBackendConfig, CallServiceCoordinationConfig, CallServiceRuntimeConfig,
        CallTimeoutPolicy, ConfiguredSipOutboundProfile, CreateCallInput, IdempotencyKey,
        LegEndpointConfig, NamedProfileBinding, NamedProfileKind, NamedProfileRole,
        NamedRouteBinding, ProviderEndpointConfig, RequestedLeg, SamePrincipalAttachmentResolver,
        SipEndpointConfig, StaticOutboundProfileResolver, SystemCallServiceClock,
        TransferCallInput, TransferTarget, WebRtcEndpointConfig,
    };
    use crate::coordination::DeploymentId;
    use crate::{
        api_principal::{ApiPrincipal, CallScope},
        call_engine::LegDirection,
    };
    use async_trait::async_trait;
    use rvoip_amazon_connect::{
        ConnectConfig, ConnectContactStarter, ConnectionData, StartContactRequest,
        StopContactRequest,
    };
    use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod};
    use rvoip_core::config::Config as CoreConfig;
    use rvoip_core::{IdentityAssurance, Jwk, OperationalEventStreamHealth};
    use tokio::sync::Notify;

    fn named_sip_profile_route(revision: &str) -> NamedRouteBinding {
        NamedRouteBinding::new_with_profiles(
            "support",
            None,
            vec![NamedProfileBinding::new(
                NamedProfileRole::Destination,
                NamedProfileKind::Sip,
                "primary",
                revision,
            )
            .unwrap()],
        )
        .unwrap()
    }

    #[test]
    fn execution_applies_only_the_exact_named_sip_profile_revision() {
        let revision = "a".repeat(64);
        let mut resolver = StaticOutboundProfileResolver::default();
        resolver.insert_sip(
            "primary".into(),
            revision.clone(),
            ConfiguredSipOutboundProfile {
                from_uri: "sips:bridge@example.test".into(),
                outbound_proxy: None,
                auth: None,
            },
        );
        let route = named_sip_profile_route(&revision);
        let applied = apply_sip_outbound_profile(
            &resolver,
            Some(&route),
            rvoip_sip::SipOriginateContext::new(),
        )
        .unwrap();
        assert_eq!(applied.from_uri(), Some("sips:bridge@example.test"));

        let stale = named_sip_profile_route(&"b".repeat(64));
        let error = apply_sip_outbound_profile(
            &resolver,
            Some(&stale),
            rvoip_sip::SipOriginateContext::new(),
        )
        .unwrap_err();
        assert_eq!(error, OutboundProfileError::NotInstalled);
        let failure = outbound_profile_failure(error);
        assert_eq!(failure.code, "outbound_profile_not_installed");
        assert!(!failure.retryable);
    }

    #[test]
    fn replacement_initial_context_is_opt_in_for_sip_and_initial_only_for_amazon() {
        let sip_without_context = LegEndpointConfig::Sip(SipEndpointConfig {
            uri: Some("sips:agent@example.test".into()),
            initial_context: SipInitialContextMode::None,
        });
        assert!(!replacement_uses_initial_context(&sip_without_context));
        assert!(!replacement_requires_initial_context(&sip_without_context));

        let sip_with_context = LegEndpointConfig::Sip(SipEndpointConfig {
            uri: Some("sips:agent@example.test".into()),
            initial_context: SipInitialContextMode::Required,
        });
        assert!(replacement_uses_initial_context(&sip_with_context));
        assert!(replacement_requires_initial_context(&sip_with_context));

        let amazon = LegEndpointConfig::AmazonConnect(AmazonConnectEndpointConfig {
            instance_id: "instance".into(),
            contact_flow_id: "flow".into(),
        });
        assert!(replacement_uses_initial_context(&amazon));
        assert!(!replacement_requires_initial_context(&amazon));
    }

    #[test]
    fn only_destinations_without_server_owned_context_require_browser_preanswer() {
        let amazon = LegEndpointConfig::AmazonConnect(AmazonConnectEndpointConfig {
            instance_id: "instance".into(),
            contact_flow_id: "flow".into(),
        });
        let telnyx = LegEndpointConfig::Provider(ProviderEndpointConfig {
            provider: ProviderKind::Telnyx,
            account_profile: "telnyx-profile".into(),
            destination: Some("+12065550123".into()),
        });
        let generic_sip = LegEndpointConfig::Sip(SipEndpointConfig {
            uri: Some("sips:agent@example.test".into()),
            initial_context: SipInitialContextMode::None,
        });
        let context_sip = LegEndpointConfig::Sip(SipEndpointConfig {
            uri: Some("sips:agent@example.test".into()),
            initial_context: SipInitialContextMode::Required,
        });

        for endpoint in [&amazon, &telnyx, &context_sip] {
            assert!(destination_requires_browser_context_before_dial(
                endpoint, false,
            ));
            assert!(!destination_requires_browser_context_before_dial(
                endpoint, true,
            ));
        }
        assert!(!destination_requires_browser_context_before_dial(
            &generic_sip,
            false,
        ));
    }

    #[test]
    fn historical_replacement_payload_without_profile_authority_fails_before_io() {
        let payload = ServiceEffectPayload::LegReplacement {
            leg_id: LegId::new(),
            previous_binding_generation: BindingGeneration::INITIAL,
            pending_binding_generation: BindingGeneration::INITIAL.next().unwrap(),
            endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                uri: Some("sips:agent@call-center.example.test".into()),
                initial_context: crate::call_service::SipInitialContextMode::None,
            }),
            amazon_connect_start: None,
            route_id: "support".into(),
            replacement_route: None,
            authorization_principal_fingerprint: crate::call_engine::PrincipalFingerprint::new(
                [0x61; 32],
            ),
        };

        assert!(validated_replacement_route(&payload).is_err());
    }

    fn bound_worker_broadcast_authority() -> (
        Arc<WorkerBroadcastSubscriptionAuthority>,
        WorkerBroadcastAdmissionRequest,
    ) {
        let worker = WorkerLease {
            worker_id: WorkerId::new(),
            fence: WorkerFence::INITIAL,
        };
        let authority = WorkerBroadcastSubscriptionAuthority::new(worker);
        let tenant = crate::call_engine::TenantId::parse("broadcast-test-tenant").unwrap();
        let broadcast_id = uuid::Uuid::new_v4();
        let listener_id = uuid::Uuid::new_v4();
        let generation = uuid::Uuid::new_v4();
        authority.activate_for_test(tenant.clone(), broadcast_id.to_string(), generation);
        assert!(authority.authorize_and_bind(
            tenant.as_str(),
            &broadcast_id.to_string(),
            listener_id,
            worker.fence.as_i64(),
            generation,
        ));
        let request = WorkerBroadcastAdmissionRequest::from_routing_hint(&format!(
            "bf-broadcast-admit-v1.{broadcast_id}.{listener_id}"
        ))
        .expect("test broadcast admission hint");
        (authority, request)
    }

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

    #[derive(Default)]
    struct RecordingConnectStarter {
        starts: Mutex<Vec<StartContactRequest>>,
        stops: Mutex<Vec<StopContactRequest>>,
    }

    #[async_trait]
    impl ConnectContactStarter for RecordingConnectStarter {
        async fn start_webrtc_contact(
            &self,
            request: StartContactRequest,
        ) -> rvoip_amazon_connect::Result<ConnectionData> {
            self.starts.lock().unwrap().push(request);
            Ok(ConnectionData {
                contact_id: "recovered-amazon-contact".into(),
                participant_id: String::new(),
                participant_token: String::new(),
                meeting_id: String::new(),
                media_region: String::new(),
                attendee_id: String::new(),
                join_token: String::new(),
                media_placement: Default::default(),
            })
        }

        async fn stop_contact(
            &self,
            request: StopContactRequest,
        ) -> rvoip_amazon_connect::Result<()> {
            self.stops.lock().unwrap().push(request);
            Ok(())
        }
    }

    async fn claim_matching_call_effect(
        runtime: &Arc<CallServiceRuntime>,
        mut matches: impl FnMut(&EffectIntent) -> bool,
    ) -> ClaimedOutbox {
        for _ in 0..16 {
            let at = runtime.observation_time();
            let claims = runtime
                .repository()
                .claim_outbox(runtime.worker().lease, at, Duration::from_secs(30), 64)
                .await
                .unwrap();
            let mut selected = None;
            for claim in claims {
                if selected.is_none() && matches(&claim.record.intent) {
                    selected = Some(claim);
                    continue;
                }
                runtime
                    .service_repository()
                    .reconcile_effect_result(EffectResultReconciliation {
                        tenant_id: claim.record.tenant_id.clone(),
                        call_id: claim.record.call_id,
                        effect_id: claim.record.effect_id,
                        worker: runtime.worker().lease,
                        claim_generation: claim.claim_generation,
                        result: ServiceEffectResult::Succeeded,
                        external_reference: None,
                        additional_external_references: Vec::new(),
                        follow_up: None,
                        at,
                    })
                    .await
                    .unwrap();
            }
            if let Some(selected) = selected {
                return selected;
            }
        }
        panic!("matching call effect was not claimable")
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
        let pending = HashMap::new();
        let collected = take_authority_loss_connections(&owners, &pending, &mut inflight)
            .into_iter()
            .collect::<HashSet<_>>();
        assert_eq!(
            collected,
            HashSet::from([owned_connection, committed_proof_not_joined])
        );
        assert!(inflight.is_empty());
        owners.clear();
    }

    fn pending_private_authority(
        call_id: CallId,
        leg_id: LegId,
        binding_generation: BindingGeneration,
    ) -> PendingConnectionAuthority {
        PendingConnectionAuthority {
            connection_id: ConnectionId::new(),
            admission_id: Uuid::new_v4(),
            worker: WorkerLease {
                worker_id: WorkerId::new(),
                fence: WorkerFence::INITIAL,
            },
            source: PrivateEgressSource {
                tenant_id: crate::call_engine::TenantId::parse("pending-owner-tenant").unwrap(),
                call_id,
                leg_id: LegId::new(),
                binding_generation: BindingGeneration::INITIAL,
            },
            target: PrivateEgressTarget {
                leg_id,
                binding_generation,
            },
        }
    }

    fn pending_private_owner(authority: PendingConnectionAuthority) -> PendingConnectionOwner {
        PendingConnectionOwner {
            authority,
            runtime: None,
            release_on_drop: true,
            deadline: tokio::time::Instant::now() + Duration::from_secs(30),
            last_sequence: None,
            staged: VecDeque::new(),
            promotion_started: true,
            allow_parallel_generation: false,
        }
    }

    #[test]
    fn pending_private_owner_promotes_only_after_actor_installed_ack() {
        let call_id = CallId::new();
        let leg_id = LegId::new();
        let authority = pending_private_authority(call_id, leg_id, BindingGeneration::INITIAL);
        let mut pending = HashMap::from([(
            authority.connection_id.clone(),
            pending_private_owner(authority.clone()),
        )]);
        let (commands, _commands_rx) = mpsc::channel(1);
        let (operational, _operational_rx) = mpsc::channel(1);
        let (work, _work_rx) = mpsc::channel(1);
        let actors = HashMap::from([(
            call_id,
            ActorSlot {
                commands,
                operational,
                work,
                retiring: Arc::new(AtomicBool::new(false)),
            },
        )]);
        let mut owners = HashMap::new();
        let mut legs = HashMap::new();
        let (staged, staged_rx) = oneshot::channel();

        assert!(apply_pending_owner_update(
            PendingConnectionOwnerUpdate::Installed {
                authority: authority.clone(),
                staged,
            },
            &actors,
            &mut owners,
            &mut pending,
            &mut legs,
        )
        .is_none());
        assert!(pending.is_empty());
        assert_eq!(
            owners
                .get(&authority.connection_id)
                .map(|owner| owner.leg_id),
            Some(leg_id)
        );
        assert_eq!(legs.get(&(call_id, leg_id)), Some(&authority.connection_id));
        assert!(staged_rx.blocking_recv().unwrap().unwrap().is_empty());
    }

    #[test]
    fn pending_private_owner_rejects_foreign_generation_without_consuming_authority() {
        let call_id = CallId::new();
        let leg_id = LegId::new();
        let authority = pending_private_authority(call_id, leg_id, BindingGeneration::INITIAL);
        let mut foreign = authority.clone();
        foreign.target.binding_generation = BindingGeneration::INITIAL.next().unwrap();
        let mut pending = HashMap::from([(
            authority.connection_id.clone(),
            pending_private_owner(authority.clone()),
        )]);
        let (staged, staged_rx) = oneshot::channel();

        assert!(apply_pending_owner_update(
            PendingConnectionOwnerUpdate::Installed {
                authority: foreign,
                staged,
            },
            &HashMap::new(),
            &mut HashMap::new(),
            &mut pending,
            &mut HashMap::new(),
        )
        .is_none());
        assert!(staged_rx.blocking_recv().unwrap().is_err());
        assert_eq!(
            pending
                .get(&authority.connection_id)
                .map(|owner| &owner.authority),
            Some(&authority)
        );
        assert!(!authority.matches_target(
            call_id,
            leg_id,
            BindingGeneration::INITIAL.next().unwrap()
        ));
    }

    #[test]
    fn pending_private_operational_fifo_is_bounded_and_order_checked() {
        assert!(pending_operational_failure(None, 0, 1, false).is_none());
        assert!(pending_operational_failure(Some(1), 1, 2, false).is_none());
        assert_eq!(
            pending_operational_failure(
                Some(PENDING_PRIVATE_OPERATIONAL_CAPACITY as u64),
                PENDING_PRIVATE_OPERATIONAL_CAPACITY,
                PENDING_PRIVATE_OPERATIONAL_CAPACITY as u64 + 1,
                false,
            ),
            Some("pending private egress event queue overflowed")
        );
        assert_eq!(
            pending_operational_failure(Some(9), 1, 9, false),
            Some("pending private egress event sequence regressed")
        );
        assert_eq!(
            pending_operational_failure(Some(9), 1, 10, true),
            Some("pending private egress connection ended before promotion")
        );
    }

    #[test]
    fn pending_private_owner_deadline_removes_only_expired_connections() {
        let now = tokio::time::Instant::now();
        let expired =
            pending_private_authority(CallId::new(), LegId::new(), BindingGeneration::INITIAL);
        let live =
            pending_private_authority(CallId::new(), LegId::new(), BindingGeneration::INITIAL);
        let mut expired_owner = pending_private_owner(expired.clone());
        expired_owner.deadline = now;
        let mut live_owner = pending_private_owner(live.clone());
        live_owner.deadline = now + Duration::from_secs(30);
        let mut pending = HashMap::from([
            (expired.connection_id.clone(), expired_owner),
            (live.connection_id.clone(), live_owner),
        ]);

        assert_eq!(
            take_expired_pending_connections(&mut pending, now),
            vec![expired.connection_id]
        );
        assert!(pending.contains_key(&live.connection_id));
    }

    #[test]
    fn worker_broadcast_proof_panic_drops_exact_authority_guard() {
        let (authority, request) = bound_worker_broadcast_authority();
        assert_eq!(authority.listener_count(), 1);
        let result = std::panic::catch_unwind(AssertUnwindSafe({
            let authority = Arc::clone(&authority);
            move || {
                let _guard = WorkerBroadcastAuthorityGuard::new(authority, request);
                panic!("injected broadcast proof panic");
            }
        }));
        assert!(result.is_err());
        assert_eq!(authority.listener_count(), 0);
    }

    #[tokio::test]
    async fn worker_broadcast_proof_cancellation_drops_exact_authority_guard() {
        let (authority, request) = bound_worker_broadcast_authority();
        let entered = Arc::new(Notify::new());
        let entered_task = Arc::clone(&entered);
        let authority_task = Arc::clone(&authority);
        let task = tokio::spawn(async move {
            let _guard = WorkerBroadcastAuthorityGuard::new(authority_task, request);
            entered_task.notify_one();
            std::future::pending::<()>().await;
        });
        entered.notified().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(authority.listener_count(), 0);
    }

    #[tokio::test]
    async fn worker_broadcast_cleanup_is_idempotent_and_releases_capacity_after_failure() {
        let (authority, request) = bound_worker_broadcast_authority();
        let capacity = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&capacity).acquire_owned().await.unwrap();
        let resources = WorkerBroadcastResources::new(
            ConnectionId::new(),
            request,
            Orchestrator::new(CoreConfig::default()),
            Arc::clone(&authority),
            permit,
        );
        assert_eq!(capacity.available_permits(), 0);
        resources.cleanup(true).await;
        resources.cleanup(true).await;
        assert_eq!(authority.listener_count(), 0);
        assert_eq!(capacity.available_permits(), 1);
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

    #[test]
    fn provisional_attach_then_dial_source_does_not_block_ready_destination_admission() {
        let ingress = LegId::new();
        let destination = LegId::new();
        let mut pending = VecDeque::from([ingress, destination]);

        let selected = first_ready_queue_index(&pending, |leg_id| *leg_id == destination)
            .expect("the ready destination behind a provisional source must be selected");
        assert_eq!(selected, 1);
        assert_eq!(pending.remove(selected), Some(destination));
        assert_eq!(pending.front(), Some(&ingress));

        assert_eq!(
            first_ready_queue_index(&pending, |leg_id| *leg_id == ingress),
            Some(0),
            "the source remains queued and can be answered after the destination connects"
        );
    }

    #[test]
    fn terminal_calls_still_execute_external_cleanup_effects() {
        let leg_id = LegId::new();
        assert!(is_terminal_cleanup_effect(&EffectIntent::StopLeg {
            leg_id,
            binding_generation: crate::call_engine::BindingGeneration::INITIAL,
            reason: crate::call_engine::StopLegReason::PeerEnded,
        }));
        assert!(is_terminal_cleanup_effect(
            &EffectIntent::AbortLegReplacement {
                leg_id,
                pending_binding_generation: crate::call_engine::BindingGeneration::INITIAL,
            }
        ));
        assert!(is_terminal_cleanup_effect(&EffectIntent::UnbridgeMedia {
            left_leg_id: leg_id,
            right_leg_id: LegId::new(),
        }));
        assert!(!is_terminal_cleanup_effect(
            &EffectIntent::AwaitLegAttachment {
                leg_id,
                binding_generation: crate::call_engine::BindingGeneration::INITIAL,
            }
        ));
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
                    handoff_signal: None,
                    result: Err(RepositoryError::Unavailable),
                }
            },
            async {
                WorkOperationResult {
                    effect_id: None,
                    bridge_update: None,
                    handoff_signal: None,
                    result: Ok(()),
                }
            },
        )
        .await;
        assert_eq!(result.result, Ok(()));
    }

    #[tokio::test]
    async fn persisted_amazon_start_recovers_exact_effect_and_tears_down_exact_contact() {
        let mut coordination = CallServiceCoordinationConfig::new(
            DeploymentId::parse("amazon-worker-recovery-test").unwrap(),
        );
        coordination.worker_lease_ttl = Duration::from_secs(300);
        coordination.worker_renew_interval = Duration::from_secs(100);
        let runtime = Arc::new(
            build_call_service_runtime(
                CallServiceRuntimeConfig {
                    backend: CallRepositoryBackendConfig::Memory,
                    worker_id: WorkerId::new(),
                    max_calls: 2,
                    worker_capabilities: BTreeSet::from(["sip".into(), "amazon_connect".into()]),
                    control_key: vec![0x67; 32],
                    timeouts: CallTimeoutPolicy::default(),
                    coordination,
                },
                Arc::new(SamePrincipalAttachmentResolver),
                Arc::new(SystemCallServiceClock),
            )
            .await
            .unwrap(),
        );
        let authenticated = AuthenticatedPrincipal {
            subject: "amazon-worker-subject".into(),
            tenant: Some("amazon-worker-tenant".into()),
            scopes: vec!["*".into(), CallScope::ArbitraryDestination.as_str().into()],
            issuer: Some("amazon-worker-test".into()),
            expires_at: None,
            method: AuthenticationMethod::Jwt,
            assurance: IdentityAssurance::Pseudonymous {
                ephemeral_key: Jwk(serde_json::json!({"kty": "test"})),
            },
        };
        let principal = ApiPrincipal::new(authenticated, Utc::now()).unwrap();
        let spec = AmazonConnectStartSpec::new(
            "default",
            "worker-instance",
            "worker-flow",
            BTreeMap::from([("correlation_id".into(), "worker-correlation".into())]),
            "Worker Caller",
            Some("Worker recovery test".into()),
        )
        .unwrap();
        let created = runtime
            .service()
            .create_call(
                &principal,
                &IdempotencyKey::parse("amazon-worker-recovery-call").unwrap(),
                CreateCallInput {
                    tenant_id: None,
                    legs: [
                        RequestedLeg {
                            direction: LegDirection::Inbound,
                            signaling_initiator: None,
                            media_flow: Default::default(),
                            endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                                uri: None,
                                initial_context: Default::default(),
                            }),
                            amazon_connect_start: None,
                        },
                        RequestedLeg {
                            direction: LegDirection::Outbound,
                            signaling_initiator: None,
                            media_flow: Default::default(),
                            endpoint: LegEndpointConfig::AmazonConnect(
                                AmazonConnectEndpointConfig {
                                    instance_id: "worker-instance".into(),
                                    contact_flow_id: "worker-flow".into(),
                                },
                            ),
                            amazon_connect_start: Some(spec.clone()),
                        },
                    ],
                },
            )
            .await
            .unwrap();
        let call_id = created.value.call.call_id;
        let amazon_leg_id = created.value.call.legs[1].leg_id;
        let tenant_id = principal.tenant().clone();
        let start_claim = claim_matching_call_effect(&runtime, |intent| {
            matches!(
                intent,
                EffectIntent::StartLeg {
                    leg_id,
                    kind: crate::call_engine::LegKind::AmazonConnect,
                    direction: LegDirection::Outbound,
                    ..
                } if *leg_id == amazon_leg_id
            )
        })
        .await;
        let expected_start = spec
            .originate_context(start_claim.record.effect_id)
            .unwrap()
            .start_request();
        let stored = runtime
            .service_repository()
            .load_service_call(&tenant_id, call_id)
            .await
            .unwrap();
        let connection_id = ConnectionId::new();
        runtime
            .service_repository()
            .bind_outbound_connection(OutboundConnectionBind {
                operation_id: CommandId::from_uuid(start_claim.record.effect_id.as_uuid()).unwrap(),
                effect_id: start_claim.record.effect_id,
                claim_generation: start_claim.claim_generation,
                tenant_id: tenant_id.clone(),
                call_id,
                leg_id: amazon_leg_id,
                binding_generation: crate::call_engine::BindingGeneration::INITIAL,
                worker: runtime.worker().lease,
                connection_id,
                transport: AttachmentTransport::WebRtc,
                principal_fingerprint: stored.plan.authorization_principal_fingerprint().unwrap(),
                at: runtime.observation_time(),
            })
            .await
            .unwrap();

        let starter = Arc::new(RecordingConnectStarter::default());
        let adapter = AmazonConnectAdapter::new(
            ConnectConfig::new("legacy-unused-instance", "legacy-unused-flow"),
            starter.clone(),
        );
        let orchestrator = Orchestrator::new(CoreConfig::default());
        let (_shutdown, shutdown) = watch::channel(ActorShutdown::Running);
        let recovery = execute_call_effect(
            start_claim.clone(),
            ActorWorkExecutionContext {
                orchestrator: Arc::clone(&orchestrator),
                runtime: Arc::clone(&runtime),
                provider_executor: Arc::new(DisabledProviderLegExecutor),
                amazon_connect: Some(Arc::clone(&adapter)),
                context_policy: Arc::new(ContextPolicy::default()),
                outbound_profiles: Arc::new(DisabledOutboundProfileResolver),
                private_egress: None,
                bindings: HashMap::new(),
                pending_inbound_authorities: HashMap::new(),
                pending_replacement_bindings: HashMap::new(),
                replaced_bindings: HashMap::new(),
                bridge_id: None,
                session_id: None,
                outbound_registration: None,
                setup_cancel: CancellationToken::new(),
                shutdown: shutdown.clone(),
            },
        )
        .await;
        assert_eq!(recovery.result, Ok(()));
        {
            let starts = starter.starts.lock().unwrap();
            assert_eq!(starts.len(), 1);
            assert_eq!(starts[0].instance_id, expected_start.instance_id);
            assert_eq!(starts[0].contact_flow_id, expected_start.contact_flow_id);
            assert_eq!(starts[0].attributes, expected_start.attributes);
            assert_eq!(starts[0].client_token, expected_start.client_token);
        }
        let persisted = runtime
            .service_repository()
            .load_external_reference_by_role(
                &tenant_id,
                call_id,
                amazon_leg_id,
                ProviderReferenceRole::Media,
            )
            .await
            .unwrap()
            .expect("recovery persisted the exact contact reference");
        assert_eq!(persisted.binding_generation, BindingGeneration::INITIAL);
        assert_eq!(
            persisted.value,
            ExternalReferenceValue::Signaling {
                namespace: AMAZON_CONNECT_CONTACT_REFERENCE_KIND.into(),
                value: "recovered-amazon-contact".into(),
            }
        );
        assert_eq!(starter.stops.lock().unwrap().len(), 1);

        let stored = runtime
            .service_repository()
            .load_service_call(&tenant_id, call_id)
            .await
            .unwrap();
        stop_persisted_amazon_contact(
            &ClaimedEffectMeta {
                tenant_id: tenant_id.clone(),
                call_id,
                effect_id: start_claim.record.effect_id,
                claim_generation: start_claim.claim_generation,
            },
            &stored,
            amazon_leg_id,
            BindingGeneration::INITIAL,
            &runtime,
            Some(&adapter),
            shutdown,
        )
        .await
        .unwrap();
        {
            let stops = starter.stops.lock().unwrap();
            assert_eq!(stops.len(), 2);
            assert!(stops.iter().all(|request| {
                request.instance_id == "worker-instance"
                    && request.contact_id == "recovered-amazon-contact"
            }));
        }

        drop(orchestrator);
        Arc::try_unwrap(runtime)
            .expect("Amazon recovery test released the runtime")
            .shutdown(Duration::from_secs(2))
            .await
            .unwrap();
    }

    #[test]
    fn provider_lifecycle_normalization_is_conservative_and_provider_neutral() {
        assert_eq!(
            classify_provider_lifecycle(ProviderKind::Telnyx, "call.initiated"),
            ProviderLifecycle::Progress
        );
        assert_eq!(
            classify_provider_lifecycle(ProviderKind::Telnyx, "call.answered"),
            ProviderLifecycle::Progress
        );
        assert_eq!(
            classify_provider_lifecycle(ProviderKind::Telnyx, "call.bridged"),
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

    #[tokio::test]
    async fn telnyx_transfer_callbacks_require_exact_live_correlation() {
        let (runtime, actor, _binding, _shutdown) = active_media_actor().await;
        let owner = ApiPrincipal::new(media_principal(), Utc::now()).unwrap();
        let initial = runtime
            .service_repository()
            .load_service_call(&actor.tenant_id, actor.call_id)
            .await
            .unwrap();
        let sip_leg = initial
            .call
            .aggregate
            .legs()
            .iter()
            .find(|leg| leg.kind() == crate::call_engine::LegKind::Sip)
            .unwrap();
        let sip_leg_id = sip_leg.id();
        let binding_generation = sip_leg.binding_generation();
        runtime
            .service()
            .transfer_call(
                &owner,
                actor.call_id,
                &IdempotencyKey::parse("media-actor-telnyx-transfer").unwrap(),
                TransferCallInput {
                    tenant_id: None,
                    target_leg_id: sip_leg_id,
                    target: TransferTarget::Sip {
                        uri: "sip:replacement@example.invalid".into(),
                    },
                },
            )
            .await
            .unwrap();
        let mut transferring = runtime
            .service_repository()
            .load_service_call(&actor.tenant_id, actor.call_id)
            .await
            .unwrap();
        assert_eq!(transferring.call.aggregate.state(), CallState::Transferring);
        let deadline_generation = transferring
            .call
            .aggregate
            .deadlines()
            .get(DeadlineKind::Transfer)
            .generation();
        let account =
            crate::call_engine::ProviderAccountKey::parse("telnyx-transfer-test").unwrap();
        let provider_leg = transferring
            .plan
            .legs
            .iter_mut()
            .find(|spec| spec.leg_id == sip_leg_id)
            .unwrap();
        provider_leg.endpoint = LegEndpointConfig::Provider(ProviderEndpointConfig {
            provider: ProviderKind::Telnyx,
            account_profile: account.as_str().into(),
            destination: Some("+15555550123".into()),
        });
        let target = crate::call_engine::ProviderEventTarget {
            tenant_id: actor.tenant_id.clone(),
            call_id: actor.call_id,
            leg_id: sip_leg_id,
            role: ProviderReferenceRole::Media,
        };
        let context = ProviderExecutionContext {
            tenant_id: actor.tenant_id.clone(),
            call_id: actor.call_id,
            leg_id: sip_leg_id,
            binding_generation,
            effect_id: crate::call_engine::EffectId::new(),
        };
        let correlation = ProviderTransferCorrelation::new(&context, deadline_generation);
        let client_state = telnyx::calls::client_state::encode_json(&correlation).unwrap();
        let payload = serde_json::json!({
            "data": {"payload": {"client_state": client_state}}
        });

        let completed = build_provider_follow_up(
            ProviderEventAuthority {
                provider: ProviderKind::Telnyx,
                binding_generation,
                effect_id: context.effect_id,
                pending_replacement: false,
            },
            "call.bridged",
            &payload,
            &target,
            &transferring,
            &runtime,
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(
            completed.command.command,
            CallCommand::FinishTransfer {
                deadline_generation: observed,
                result: TransferResult::Completed,
                ..
            } if observed == deadline_generation
        ));

        let failed = build_provider_follow_up(
            ProviderEventAuthority {
                provider: ProviderKind::Telnyx,
                binding_generation,
                effect_id: context.effect_id,
                pending_replacement: false,
            },
            "call.failed",
            &payload,
            &target,
            &transferring,
            &runtime,
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(
            failed.command.command,
            CallCommand::FinishTransfer {
                deadline_generation: observed,
                result: TransferResult::Rejected(_),
                ..
            } if observed == deadline_generation
        ));

        let stale_correlation = ProviderTransferCorrelation::new(
            &context,
            crate::call_engine::DeadlineGeneration::default(),
        );
        let stale_payload = serde_json::json!({
            "data": {"payload": {"client_state":
                telnyx::calls::client_state::encode_json(&stale_correlation).unwrap()
            }}
        });
        assert!(correlated_provider_transfer_result(
            ProviderKind::Telnyx,
            "call.bridged",
            &stale_payload,
            &target,
            &transferring,
            binding_generation,
        )
        .is_none());
        let wrong_role = crate::call_engine::ProviderEventTarget {
            role: ProviderReferenceRole::Destination,
            ..target
        };
        assert!(correlated_provider_transfer_result(
            ProviderKind::Telnyx,
            "call.bridged",
            &payload,
            &wrong_role,
            &transferring,
            binding_generation,
        )
        .is_none());
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
            scopes: vec!["*".into(), CallScope::ArbitraryDestination.as_str().into()],
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
                            signaling_initiator: None,
                            media_flow: Default::default(),
                            endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                                uri: None,
                                initial_context: Default::default(),
                            }),
                            amazon_connect_start: None,
                        },
                        RequestedLeg {
                            direction: LegDirection::Inbound,
                            signaling_initiator: None,
                            media_flow: Default::default(),
                            endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                                signaling_uri: None,
                            }),
                            amazon_connect_start: None,
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
            private_egress: None,
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
            Arc::new(DisabledProviderLegExecutor),
            None,
            Arc::new(ContextPolicy::default()),
            Arc::new(DisabledOutboundProfileResolver),
            None,
            mpsc::channel(1).0,
            mpsc::unbounded_channel().0,
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
    async fn durable_lifecycle_state_converges_the_actor_binding_cache() {
        let (runtime, mut actor, binding, _shutdown) = active_media_actor().await;
        actor
            .bindings
            .get_mut(&binding.leg_id)
            .expect("actor binding")
            .state = LegState::Signaling;
        let stored = runtime
            .service_repository()
            .load_service_call(&actor.tenant_id, actor.call_id)
            .await
            .unwrap();
        assert_eq!(
            stored
                .call
                .aggregate
                .leg(binding.leg_id)
                .expect("durable leg")
                .state(),
            LegState::Connected
        );

        actor.converge_durable_binding_states(&stored);

        assert_eq!(
            actor
                .bindings
                .get(&binding.leg_id)
                .expect("converged actor binding")
                .state,
            LegState::Connected,
            "a verified provider callback must release an attach-then-dial final-answer barrier"
        );
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
    fn source_teardown_aborts_prepared_private_egress_and_ends_connected_egress() {
        for state in [
            LegState::Pending,
            LegState::AwaitingAttach,
            LegState::Signaling,
            LegState::Ending,
        ] {
            assert!(matches!(
                private_egress_peer_stop_operation(state),
                PrivateEgressOperation::Abort
            ));
        }
        for state in [LegState::Connected, LegState::Held] {
            assert!(matches!(
                private_egress_peer_stop_operation(state),
                PrivateEgressOperation::End {
                    reason: PrivateEgressEndReason::Normal
                }
            ));
        }
    }

    #[test]
    fn repeated_transport_teardown_accepts_only_an_already_absent_route() {
        assert_eq!(normalize_terminal_transport_cleanup(Ok(())), Ok(()));
        assert_eq!(
            normalize_terminal_transport_cleanup(Err(RvoipError::ConnectionNotFound(
                ConnectionId::new(),
            ))),
            Ok(())
        );
        assert_eq!(
            normalize_terminal_transport_cleanup(Err(RvoipError::InvalidState(
                "route is still active",
            ))),
            Err(())
        );
    }

    #[test]
    fn provisional_progress_does_not_advance_the_durable_leg_state() {
        let progress = OperationalEventKind::Progress {
            status_code: 183,
            early_media: true,
        };
        assert!(matches!(
            classify_operational_event(LegState::Signaling, &progress),
            OperationalTransition::Ephemeral
        ));
        assert_eq!(operational_kind_label(&progress), "progress");
    }

    #[test]
    fn private_progress_requires_exact_source_and_target_generations() {
        let worker = WorkerLease {
            worker_id: WorkerId::new(),
            fence: WorkerFence::INITIAL,
        };
        let source_connection = ConnectionId::new();
        let source = PrivateEgressSource {
            tenant_id: crate::call_engine::TenantId::parse("progress-authority-tenant").unwrap(),
            call_id: CallId::new(),
            leg_id: LegId::new(),
            binding_generation: BindingGeneration::INITIAL,
        };
        let target = PrivateEgressTarget {
            leg_id: LegId::new(),
            binding_generation: BindingGeneration::INITIAL,
        };
        let event =
            PrivateEgressLifecycleEvent::progress(worker, source.clone(), target, 183, true)
                .unwrap();
        let delivery = PrivateEgressLifecycleDelivery {
            source_connection: source_connection.clone(),
            event,
        };
        assert!(private_lifecycle_route_authority_matches(
            target.leg_id,
            target.binding_generation,
            &source_connection,
            &source,
            target,
            &delivery,
        ));

        let foreign_target = PrivateEgressTarget {
            binding_generation: target.binding_generation.next().unwrap(),
            ..target
        };
        assert!(!private_lifecycle_route_authority_matches(
            foreign_target.leg_id,
            foreign_target.binding_generation,
            &source_connection,
            &source,
            target,
            &delivery,
        ));
        let mut foreign_source = source.clone();
        foreign_source.binding_generation = source.binding_generation.next().unwrap();
        assert!(!private_lifecycle_route_authority_matches(
            target.leg_id,
            target.binding_generation,
            &source_connection,
            &foreign_source,
            target,
            &delivery,
        ));
        assert!(!private_lifecycle_route_authority_matches(
            target.leg_id,
            target.binding_generation,
            &ConnectionId::new(),
            &source,
            target,
            &delivery,
        ));
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
