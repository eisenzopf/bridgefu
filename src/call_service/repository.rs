//! Additive repository contract for durable call execution.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rvoip_core::ids::ConnectionId;
use serde::{Deserialize, Serialize};

use crate::call_engine::{
    AttachmentTransport, BindingGeneration, CallId, CallRepository, ClaimGeneration, CommandCommit,
    CommandCommitView, CommandId, ConnectionBinding, CreateCall, EffectId, FailureDetails, LegId,
    OutboxRecord, OutboxState, PrincipalFingerprint, ProviderEventEnvelope, RepositoryError,
    StoredCall, TenantId, WorkerLease,
};

use super::{CallExecutionPlan, ControlIntent, ExternalReferenceValue, ServiceEffectPayload};

/// Call aggregate and the immutable worker execution plan created with it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoredServiceCall {
    /// Existing call-engine view.
    pub call: StoredCall,
    /// Immutable endpoint and leg execution configuration.
    pub plan: CallExecutionPlan,
}

/// Atomic call creation plus its execution plan.
#[derive(Clone, Debug)]
pub struct ServiceCreateTransaction {
    /// Existing atomic core create request.
    pub create: CreateCall,
    /// Plan validated against `create.initial`.
    pub plan: CallExecutionPlan,
}

/// Service creation result. Replays always carry the originally stored plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceCreateOutcome {
    /// Call and plan were created in this transaction.
    Created(StoredServiceCall),
    /// The retained idempotency claim returned the original call and plan.
    Replayed(StoredServiceCall),
}

/// One service payload mapped to a core effect ordinal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServiceEffectPayloadInput {
    /// Zero-based effect order in the core command decision.
    pub ordinal: u32,
    /// Additional execution data absent from the core state machine.
    pub payload: ServiceEffectPayload,
}

/// Durable service payload mapped to its generated core effect ID.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoredServiceEffectPayload {
    /// Generated core effect ID.
    pub effect_id: EffectId,
    /// Core command that produced the effect.
    pub command_id: CommandId,
    /// Effect order within that command.
    pub ordinal: u32,
    /// Service-only execution data.
    pub payload: ServiceEffectPayload,
}

/// Atomic core command plus service-owned effect payloads.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServiceCommandTransaction {
    /// Existing compare-and-swap command transaction.
    pub command: CommandCommit,
    /// Payloads keyed by core decision ordinal.
    pub effect_payloads: Vec<ServiceEffectPayloadInput>,
}

/// Exact result of a service command transaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServiceCommandView {
    /// Existing core command result.
    pub command: CommandCommitView,
    /// Service payloads mapped to generated effect IDs.
    pub effect_payloads: Vec<StoredServiceEffectPayload>,
}

/// New service command or exact command-ID replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceCommandOutcome {
    /// Command and payloads were persisted together.
    Committed(ServiceCommandView),
    /// The exact request returned its original result.
    Replayed(ServiceCommandView),
}

/// Fenced non-state-changing control command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ControlCommandTransaction {
    /// Stable idempotency and replay identifier.
    pub command_id: CommandId,
    /// Authenticated tenant ownership.
    pub tenant_id: TenantId,
    /// Owning call.
    pub call_id: CallId,
    /// Current target leg.
    pub leg_id: LegId,
    /// Exact leg binding incarnation.
    pub binding_generation: BindingGeneration,
    /// Current assigned worker.
    pub worker: WorkerLease,
    /// Durable control operation.
    pub intent: ControlIntent,
    /// Repository observation time.
    pub at: DateTime<Utc>,
}

/// Immutable receipt for an accepted control command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoredControlCommand {
    /// Stable command identifier.
    pub command_id: CommandId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Owning call.
    pub call_id: CallId,
    /// Target leg.
    pub leg_id: LegId,
    /// Target binding incarnation.
    pub binding_generation: BindingGeneration,
    /// Assignment fence at creation.
    pub worker: WorkerLease,
    /// Requested operation.
    pub intent: ControlIntent,
    /// Persistence time.
    pub recorded_at: DateTime<Utc>,
}

/// Outbox record for a control command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ControlOutboxRecord {
    /// Stable effect identity.
    pub effect_id: EffectId,
    /// Command that produced the effect.
    pub command_id: CommandId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Owning call.
    pub call_id: CallId,
    /// Current target leg.
    pub leg_id: LegId,
    /// Target binding incarnation.
    pub binding_generation: BindingGeneration,
    /// Fenced execution owner.
    pub worker: WorkerLease,
    /// Control operation to execute.
    pub intent: ControlIntent,
    /// Earliest claim time.
    pub available_at: DateTime<Utc>,
    /// Durable claim/completion state.
    pub state: OutboxState,
}

/// Exact control-command result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ControlCommandView {
    /// Immutable command receipt.
    pub command: StoredControlCommand,
    /// One durable control effect.
    pub effect: ControlOutboxRecord,
}

/// New control command or exact command-ID replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlCommandOutcome {
    /// Command was durably enqueued.
    Enqueued(ControlCommandView),
    /// The exact request returned the original effect.
    Replayed(ControlCommandView),
}

/// Claimed control effect and its completion guard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedControlEffect {
    /// Claimed record.
    pub record: ControlOutboxRecord,
    /// Exact claim incarnation.
    pub claim_generation: ClaimGeneration,
}

/// Idempotent outbound rvoip connection binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundConnectionBind {
    /// Operation replay identifier.
    pub operation_id: CommandId,
    /// Authenticated tenant ownership.
    pub tenant_id: TenantId,
    /// Owning call.
    pub call_id: CallId,
    /// Outbound leg to bind.
    pub leg_id: LegId,
    /// Exact current leg incarnation.
    pub binding_generation: BindingGeneration,
    /// Current assignment fence.
    pub worker: WorkerLease,
    /// rvoip connection identifier, permanently single-use.
    pub connection_id: ConnectionId,
    /// Actual signaling/media transport class.
    pub transport: AttachmentTransport,
    /// Principal that authorized creation of the outbound binding.
    pub principal_fingerprint: PrincipalFingerprint,
    /// Binding time.
    pub at: DateTime<Utc>,
}

/// New outbound binding or exact operation replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboundConnectionBindOutcome {
    /// Binding was created and its connection ID tombstoned.
    Bound(ConnectionBinding),
    /// The exact operation returned its original binding.
    Replayed(ConnectionBinding),
}

/// External reference attached to a successful leg effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalReferenceBinding {
    /// Exact effect leg.
    pub leg_id: LegId,
    /// Exact effect binding generation.
    pub binding_generation: BindingGeneration,
    /// Provider or signaling reference.
    pub value: ExternalReferenceValue,
}

/// Durable tenant/call ownership for an external reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoredExternalReference {
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Owning call.
    pub call_id: CallId,
    /// Owning leg.
    pub leg_id: LegId,
    /// Binding generation that created the reference.
    pub binding_generation: BindingGeneration,
    /// Effect that returned the reference.
    pub effect_id: EffectId,
    /// Redacted external value.
    pub value: ExternalReferenceValue,
    /// Binding time.
    pub bound_at: DateTime<Utc>,
}

/// Result reported by an effect executor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "result", content = "failure", rename_all = "snake_case")]
pub enum ServiceEffectResult {
    /// External operation succeeded.
    Succeeded,
    /// External operation failed with bounded safe details.
    Failed(FailureDetails),
}

/// One atomic external-effect result transaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EffectResultReconciliation {
    /// Tenant guard copied from the claimed effect.
    pub tenant_id: TenantId,
    /// Call guard copied from the claimed effect.
    pub call_id: CallId,
    /// Claimed core or control effect.
    pub effect_id: EffectId,
    /// Current fenced worker.
    pub worker: WorkerLease,
    /// Exact claim incarnation.
    pub claim_generation: ClaimGeneration,
    /// Successful or failed external result.
    pub result: ServiceEffectResult,
    /// Optional reference returned by a successful start-leg operation.
    pub external_reference: Option<ExternalReferenceBinding>,
    /// Optional state-machine follow-up committed in the same transaction.
    pub follow_up: Option<ServiceCommandTransaction>,
    /// Reconciliation time.
    pub at: DateTime<Utc>,
}

/// Completed effect record returned by reconciliation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "source", content = "record", rename_all = "snake_case")]
pub enum CompletedServiceEffect {
    /// Existing core call-effect record.
    Call(OutboxRecord),
    /// Service control-effect record.
    Control(ControlOutboxRecord),
}

/// Exact atomic reconciliation result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EffectResultView {
    /// Completed core or control effect.
    pub effect: CompletedServiceEffect,
    /// Stored external reference when one was supplied.
    pub external_reference: Option<StoredExternalReference>,
    /// Provider callbacks released by binding a provider call reference.
    pub released_provider_events: Vec<ProviderEventEnvelope>,
    /// Optional state-machine result committed atomically.
    pub follow_up: Option<ServiceCommandView>,
}

/// First reconciliation or an exact effect-ID replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectResultOutcome {
    /// Result was applied in this transaction.
    Reconciled(EffectResultView),
    /// The exact report returned its original result.
    Replayed(EffectResultView),
}

/// Durable service companion. Implementations perform no provider or rvoip I/O.
#[async_trait]
pub trait CallServiceRepository: CallRepository {
    /// Creates the core call and immutable execution plan atomically.
    async fn create_with_plan(
        &self,
        request: ServiceCreateTransaction,
    ) -> Result<ServiceCreateOutcome, RepositoryError>;

    /// Loads a tenant-owned call and its execution plan.
    async fn load_service_call(
        &self,
        tenant_id: &TenantId,
        call_id: CallId,
    ) -> Result<StoredServiceCall, RepositoryError>;

    /// Commits a core command and service effect payloads atomically.
    async fn commit_with_effect_payloads(
        &self,
        request: ServiceCommandTransaction,
    ) -> Result<ServiceCommandOutcome, RepositoryError>;

    /// Loads the optional service payload for a tenant-owned effect.
    async fn load_effect_payload(
        &self,
        tenant_id: &TenantId,
        effect_id: EffectId,
    ) -> Result<Option<StoredServiceEffectPayload>, RepositoryError>;

    /// Enqueues a fenced DTMF/control operation without changing call state.
    async fn enqueue_control(
        &self,
        request: ControlCommandTransaction,
    ) -> Result<ControlCommandOutcome, RepositoryError>;

    /// Claims control effects for one worker incarnation.
    async fn claim_control_effects(
        &self,
        worker: WorkerLease,
        at: DateTime<Utc>,
        claim_ttl: Duration,
        limit: usize,
    ) -> Result<Vec<ClaimedControlEffect>, RepositoryError>;

    /// Binds an outbound rvoip connection and permanently retires its ID.
    async fn bind_outbound_connection(
        &self,
        request: OutboundConnectionBind,
    ) -> Result<OutboundConnectionBindOutcome, RepositoryError>;

    /// Loads the current external reference for a tenant-owned leg.
    async fn load_external_reference(
        &self,
        tenant_id: &TenantId,
        call_id: CallId,
        leg_id: LegId,
    ) -> Result<Option<StoredExternalReference>, RepositoryError>;

    /// Atomically reconciles a claimed effect and all related durable state.
    async fn reconcile_effect_result(
        &self,
        request: EffectResultReconciliation,
    ) -> Result<EffectResultOutcome, RepositoryError>;
}
