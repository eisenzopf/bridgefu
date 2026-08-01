//! Additive repository contract for durable call execution.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rvoip_core::ids::{ConnectionId, MessageId};
use serde::{Deserialize, Deserializer, Serialize};

use crate::call_engine::{
    AggregateVersion, AttachmentCandidate, AttachmentConsume, AttachmentIssue, AttachmentLookup,
    AttachmentTransport, BindingGeneration, CallCommand, CallId, ClaimGeneration, CommandCommit,
    CommandCommitView, CommandId, ConnectionBinding, ConsumedAttachment, CreateCall, EffectId,
    FailureDetails, IdempotencyKeyDigest, LegId, LegState, OutboxRecord, OutboxState,
    PrincipalFingerprint, ProviderAccountKey, ProviderEventDigest, ProviderEventEnvelope,
    ProviderEventTarget, ProviderReferenceRole, RepositoryError, RequestDigest,
    SourceBeforeAnswerTermination, StoredCall, TenantId, WorkerLease,
};

use super::{CallExecutionPlan, ControlIntent, ExternalReferenceValue, ServiceEffectPayload};

/// Call aggregate and the immutable worker execution plan created with it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoredServiceCall {
    /// Existing call-engine view.
    pub call: StoredCall,
    /// Immutable endpoint and leg execution configuration.
    pub plan: CallExecutionPlan,
    /// Immutable initial inbound attachment descriptors. Raw tokens are never stored.
    pub attachments: Vec<AttachmentIssue>,
}

/// Atomic call creation plus its execution plan.
#[derive(Clone, Debug)]
pub struct ServiceCreateTransaction {
    /// Existing atomic core create request.
    pub create: CreateCall,
    /// Plan validated against `create.initial`.
    pub plan: CallExecutionPlan,
    /// Additional prevalidated worker-bound attachment choices, in placement
    /// order. The repository tries these only when an earlier candidate lost
    /// its fence or capacity race.
    pub alternatives: Vec<ServiceCreateCandidate>,
}

/// One worker-specific call-creation choice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceCreateCandidate {
    /// Candidate worker fence.
    pub worker: WorkerLease,
    /// Attachment descriptors bound to that exact worker fence.
    pub attachments: Vec<AttachmentIssue>,
}

/// Service creation result. Replays always carry the originally stored plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceCreateOutcome {
    /// Call and plan were created in this transaction.
    Created(StoredServiceCall),
    /// The retained idempotency claim returned the original call and plan.
    Replayed(StoredServiceCall),
}

/// Public HTTP operation protected by the tenant-wide idempotency-key namespace.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceOperationKind {
    /// Creates one two-leg call.
    CreateCall,
    /// Starts durable call teardown.
    HangupCall,
    /// Starts a durable call transfer.
    TransferCall,
    /// Enqueues DTMF for one bound leg.
    DtmfCall,
}

/// Tenant-scoped canonical idempotency claim supplied by the HTTP service.
///
/// Digests have redacted `Debug` implementations. The raw header and request
/// body never cross this repository boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperationIdempotency {
    /// HMAC digest of the tenant-bound `Idempotency-Key` header.
    pub key_digest: IdempotencyKeyDigest,
    /// HMAC digest of the canonical authenticated operation request.
    pub request_digest: RequestDigest,
    /// Typed public operation whose original result must be replayed.
    pub operation: ServiceOperationKind,
}

impl OperationIdempotency {
    pub(crate) fn validate_service_command(
        &self,
        command: &CallCommand,
    ) -> Result<(), RepositoryError> {
        let valid = matches!(
            (&self.operation, command),
            (
                ServiceOperationKind::HangupCall,
                CallCommand::BeginEnding { .. }
            ) | (
                ServiceOperationKind::TransferCall,
                CallCommand::BeginTransfer { .. }
            ) | (
                ServiceOperationKind::TransferCall,
                CallCommand::BeginLegReplacement { .. }
            )
        );
        if valid {
            Ok(())
        } else {
            Err(RepositoryError::InvalidInput(
                "operation idempotency kind does not match service command",
            ))
        }
    }

    pub(crate) fn validate_control(&self, intent: &ControlIntent) -> Result<(), RepositoryError> {
        if self.operation == ServiceOperationKind::DtmfCall
            && matches!(intent, ControlIntent::Dtmf { .. })
        {
            Ok(())
        } else {
            Err(RepositoryError::InvalidInput(
                "operation idempotency kind does not match control command",
            ))
        }
    }
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

/// Exact durable connection guard retained with lifecycle-command replay.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BoundConnectionGuard {
    /// Exact rvoip route that produced the lifecycle observation.
    pub connection_id: ConnectionId,
    /// Exact logical leg.
    pub leg_id: LegId,
    /// Exact signaling/media incarnation.
    pub binding_generation: BindingGeneration,
}

/// Atomic promotion of an actor-owned pending route when a logical-leg
/// replacement reports connected. The old route remains process-owned long
/// enough for the emitted `StopLeg` effect, while durable ownership changes
/// exactly with the aggregate binding generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReplacementConnectionPromotion {
    /// Exact old connection still current before the commit.
    pub previous_connection_id: ConnectionId,
    /// Prepared replacement connection becoming current.
    pub connection_id: ConnectionId,
    /// Stable logical leg.
    pub leg_id: LegId,
    /// Old aggregate binding generation.
    pub previous_binding_generation: BindingGeneration,
    /// Reserved pending generation.
    pub pending_binding_generation: BindingGeneration,
    /// Actual replacement transport class.
    pub transport: AttachmentTransport,
    /// Principal that authorized the server-controlled replacement route.
    pub principal_fingerprint: PrincipalFingerprint,
}

/// Monotonic media-activity observation for one exact connection binding.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MediaActivityGeneration(u64);

impl MediaActivityGeneration {
    /// First authoritative activity observation for a connection binding.
    pub const INITIAL: Self = Self(1);

    /// Returns the database-safe signed representation.
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    /// Reconstructs a positive signed database generation.
    pub fn from_i64(value: i64) -> Result<Self, RepositoryError> {
        if value <= 0 {
            Err(RepositoryError::InvalidInput(
                "media activity generation must be positive",
            ))
        } else {
            Ok(Self(value as u64))
        }
    }

    /// Advances to the next exact activity observation.
    pub fn next(self) -> Result<Self, RepositoryError> {
        if self.0 >= i64::MAX as u64 {
            Err(RepositoryError::CounterExhausted)
        } else {
            Ok(Self(self.0 + 1))
        }
    }
}

impl<'de> Deserialize<'de> for MediaActivityGeneration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        if value == 0 || value > i64::MAX as u64 {
            return Err(serde::de::Error::custom(
                "media activity generation must fit a positive signed database integer",
            ));
        }
        Ok(Self(value))
    }
}

/// Exact activity proof retained with a media-deadline refresh command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MediaActivityGuard {
    /// Exact rvoip route that emitted authoritative media activity.
    pub connection_id: ConnectionId,
    /// Exact logical leg carrying that route.
    pub leg_id: LegId,
    /// Exact signaling/media incarnation.
    pub binding_generation: BindingGeneration,
    /// Strictly consecutive route-local activity observation.
    pub activity_generation: MediaActivityGeneration,
}

/// Atomic core command plus service-owned effect payloads.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServiceCommandTransaction {
    /// Existing compare-and-swap command transaction.
    pub command: CommandCommit,
    /// Payloads keyed by core decision ordinal.
    pub effect_payloads: Vec<ServiceEffectPayloadInput>,
    /// Optional public-operation replay claim. Internal effect follow-ups omit it.
    #[serde(default)]
    pub operation_idempotency: Option<OperationIdempotency>,
    /// Optional exact connection guard for transport lifecycle observations.
    #[serde(default)]
    pub bound_connection: Option<BoundConnectionGuard>,
    /// Optional exact activity proof for a media-idle deadline refresh.
    #[serde(default)]
    pub media_activity: Option<MediaActivityGuard>,
    /// Optional atomic current-binding promotion for
    /// `FinishLegReplacement(Connected)`.
    #[serde(default)]
    pub replacement_connection: Option<ReplacementConnectionPromotion>,
}

/// Fenced lifecycle transition for one exact durably bound connection.
///
/// The repository validates the current connection ID and binding generation
/// inside the same transaction as the state-machine command. This prevents a
/// delayed event from an old transport route from advancing a replacement
/// leg after a restart or transfer.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BoundConnectionStateCommit {
    /// Authenticated tenant ownership.
    pub tenant_id: TenantId,
    /// Durable call receiving the observation.
    pub call_id: CallId,
    /// Compare-and-swap version retained across lost-response retries.
    pub expected_version: AggregateVersion,
    /// Stable event delivery identity retained across retries.
    pub command_id: CommandId,
    /// Exact logical leg.
    pub leg_id: LegId,
    /// Exact signaling/media incarnation.
    pub binding_generation: BindingGeneration,
    /// Exact rvoip route that produced the event.
    pub connection_id: ConnectionId,
    /// Current fenced worker.
    pub worker: WorkerLease,
    /// Target lifecycle state.
    pub state: LegState,
    /// Sanitized failure details when `state` is failed.
    pub failure: Option<FailureDetails>,
    /// Observation and commit time.
    pub at: DateTime<Utc>,
}

impl std::fmt::Debug for BoundConnectionStateCommit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BoundConnectionStateCommit")
            .field("tenant_id", &self.tenant_id)
            .field("call_id", &self.call_id)
            .field("expected_version", &self.expected_version)
            .field("command_id", &self.command_id)
            .field("leg_id", &self.leg_id)
            .field("binding_generation", &self.binding_generation)
            .field("connection_id", &self.connection_id)
            .field("worker", &self.worker)
            .field("state", &self.state)
            .field("failure", &self.failure.as_ref().map(|_| "[redacted]"))
            .field("at", &self.at)
            .finish()
    }
}

/// Fenced terminal transition for a remotely initiated source that vanished
/// before final answer.
///
/// The repository validates the current connection ID and binding generation
/// in the same transaction that ends the source and starts peer teardown.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BoundSourceTerminationCommit {
    /// Authenticated tenant ownership.
    pub tenant_id: TenantId,
    /// Durable call receiving the observation.
    pub call_id: CallId,
    /// Compare-and-swap version retained across lost-response retries.
    pub expected_version: AggregateVersion,
    /// Stable event delivery identity retained across retries.
    pub command_id: CommandId,
    /// Exact remotely initiated source leg.
    pub source_leg_id: LegId,
    /// Exact signaling incarnation that disappeared.
    pub binding_generation: BindingGeneration,
    /// Exact rvoip route that disappeared.
    pub connection_id: ConnectionId,
    /// Current fenced worker.
    pub worker: WorkerLease,
    /// Sanitized source termination reason.
    pub reason: SourceBeforeAnswerTermination,
    /// Observation and commit time.
    pub at: DateTime<Utc>,
}

/// Fenced media activity that arms or refreshes the call's media-idle timer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MediaActivityCommit {
    /// Authenticated tenant ownership.
    pub tenant_id: TenantId,
    /// Durable call receiving the observation.
    pub call_id: CallId,
    /// Compare-and-swap version retained across lost-response retries.
    pub expected_version: AggregateVersion,
    /// Stable activity delivery identity retained across retries.
    pub command_id: CommandId,
    /// Exact logical leg where media was observed.
    pub leg_id: LegId,
    /// Exact signaling/media incarnation.
    pub binding_generation: BindingGeneration,
    /// Exact rvoip route that emitted activity.
    pub connection_id: ConnectionId,
    /// Strictly consecutive route-local activity generation.
    pub activity_generation: MediaActivityGeneration,
    /// Current fenced worker.
    pub worker: WorkerLease,
    /// Authoritative activity observation time.
    pub at: DateTime<Utc>,
    /// Absolute media-idle deadline derived from configured policy.
    pub due_at: DateTime<Utc>,
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
    /// Optional public-operation replay claim. Internal controls may omit it.
    #[serde(default)]
    pub operation_idempotency: Option<OperationIdempotency>,
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

/// Monotonic, database-safe order of controls targeting one binding generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ControlSequence(u64);

impl ControlSequence {
    /// First control queued for a binding generation.
    pub const INITIAL: Self = Self(1);

    /// Returns the database-safe signed representation.
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    /// Reconstructs a sequence read from a signed database column.
    pub fn from_i64(value: i64) -> Result<Self, RepositoryError> {
        if value <= 0 {
            Err(RepositoryError::InvalidInput(
                "control sequence must be a positive database integer",
            ))
        } else {
            Ok(Self(value as u64))
        }
    }

    pub(crate) fn next(self) -> Result<Self, RepositoryError> {
        if self.0 >= i64::MAX as u64 {
            Err(RepositoryError::CounterExhausted)
        } else {
            Ok(Self(self.0 + 1))
        }
    }
}

impl<'de> Deserialize<'de> for ControlSequence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        if value == 0 || value > i64::MAX as u64 {
            return Err(serde::de::Error::custom(
                "control sequence must fit a positive signed database integer",
            ));
        }
        Ok(Self(value))
    }
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
    /// FIFO order within this exact call/leg/binding generation.
    pub sequence: ControlSequence,
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

/// Typed immutable result retained by the shared 24-hour idempotency row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "receipt", rename_all = "snake_case")]
pub enum OperationIdempotencyReceipt {
    /// Existing call-creation receipt. The original create snapshot is loaded
    /// through its version-zero command result.
    CreateCall,
    /// Original state-changing service command result.
    ServiceCommand {
        /// Exact public operation represented by the command.
        operation: ServiceOperationKind,
        /// Immutable result returned to every exact retry.
        view: Box<ServiceCommandView>,
    },
    /// Original non-state-changing control result.
    ControlCommand {
        /// Exact public operation represented by the control.
        operation: ServiceOperationKind,
        /// Immutable result returned to every exact retry.
        view: Box<ControlCommandView>,
    },
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutboundConnectionBind {
    /// Operation replay identifier.
    pub operation_id: CommandId,
    /// Exact claimed `StartLeg` effect authorizing the provisional route.
    pub effect_id: EffectId,
    /// Exact incarnation of that effect claim.
    pub claim_generation: ClaimGeneration,
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

/// Atomic request to retain the first validated context message for one exact
/// outbound signaling leg incarnation.
///
/// Envelope bytes and header values may contain customer context. They are
/// persisted for signaling, but deliberately omitted from [`Debug`].
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct InitialContextRecordRequest {
    /// Authenticated tenant ownership.
    pub tenant_id: TenantId,
    /// Owning two-leg call.
    pub call_id: CallId,
    /// Exact current rvoip route that delivered the context message.
    pub source_connection_id: ConnectionId,
    /// Logical source leg bound to `source_connection_id`.
    pub source_leg_id: LegId,
    /// Current source signaling/media incarnation.
    pub source_binding_generation: BindingGeneration,
    /// Distinct destination leg that will receive the initial signaling context.
    pub target_leg_id: LegId,
    /// Current target signaling/media incarnation.
    pub target_binding_generation: BindingGeneration,
    /// Stable transport-neutral DataMessage identity.
    pub message_id: MessageId,
    /// Validated serialized `bridgefu.context.v1` envelope.
    pub envelope: Vec<u8>,
    /// Validated, ordered, duplicate-preserving initial SIP headers. This is
    /// empty for Amazon Connect attribute projection.
    pub initial_sip_headers: Vec<(String, String)>,
    /// Repository observation and persistence time.
    pub recorded_at: DateTime<Utc>,
}

impl std::fmt::Debug for InitialContextRecordRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InitialContextRecordRequest")
            .field("tenant_id", &self.tenant_id)
            .field("call_id", &self.call_id)
            .field("source_connection_id", &self.source_connection_id)
            .field("source_leg_id", &self.source_leg_id)
            .field("source_binding_generation", &self.source_binding_generation)
            .field("target_leg_id", &self.target_leg_id)
            .field("target_binding_generation", &self.target_binding_generation)
            .field("message_id_present", &!self.message_id.as_str().is_empty())
            .field("envelope_bytes", &self.envelope.len())
            .field("initial_sip_header_count", &self.initial_sip_headers.len())
            .field("recorded_at", &self.recorded_at)
            .finish()
    }
}

/// Immutable context retained for one exact target leg generation.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoredInitialContext {
    /// Authenticated tenant ownership.
    pub tenant_id: TenantId,
    /// Owning call.
    pub call_id: CallId,
    /// Exact source rvoip route at admission time.
    pub source_connection_id: ConnectionId,
    /// Source logical leg.
    pub source_leg_id: LegId,
    /// Source leg incarnation at admission time.
    pub source_binding_generation: BindingGeneration,
    /// Destination signaling leg.
    pub target_leg_id: LegId,
    /// Destination leg incarnation.
    pub target_binding_generation: BindingGeneration,
    /// Original DataMessage identity.
    pub message_id: MessageId,
    /// Serialized, validated `bridgefu.context.v1` envelope.
    pub envelope: Vec<u8>,
    /// Ordered initial SIP headers. Values are sensitive and must not be logged;
    /// Amazon Connect context records retain an empty projection here.
    pub initial_sip_headers: Vec<(String, String)>,
    /// Persistence time.
    pub recorded_at: DateTime<Utc>,
}

impl std::fmt::Debug for StoredInitialContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredInitialContext")
            .field("tenant_id", &self.tenant_id)
            .field("call_id", &self.call_id)
            .field("source_connection_id", &self.source_connection_id)
            .field("source_leg_id", &self.source_leg_id)
            .field("source_binding_generation", &self.source_binding_generation)
            .field("target_leg_id", &self.target_leg_id)
            .field("target_binding_generation", &self.target_binding_generation)
            .field("message_id_present", &!self.message_id.as_str().is_empty())
            .field("envelope_bytes", &self.envelope.len())
            .field("initial_sip_header_count", &self.initial_sip_headers.len())
            .field("recorded_at", &self.recorded_at)
            .finish()
    }
}

impl From<InitialContextRecordRequest> for StoredInitialContext {
    fn from(request: InitialContextRecordRequest) -> Self {
        Self {
            tenant_id: request.tenant_id,
            call_id: request.call_id,
            source_connection_id: request.source_connection_id,
            source_leg_id: request.source_leg_id,
            source_binding_generation: request.source_binding_generation,
            target_leg_id: request.target_leg_id,
            target_binding_generation: request.target_binding_generation,
            message_id: request.message_id,
            envelope: request.envelope,
            initial_sip_headers: request.initial_sip_headers,
            recorded_at: request.recorded_at,
        }
    }
}

/// First durable context admission or an exact lost-response replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InitialContextRecordOutcome {
    /// Context was retained in this transaction.
    Recorded(StoredInitialContext),
    /// The byte-for-byte identical request returned the retained record.
    Replayed(StoredInitialContext),
}

/// Exact make-before-break fence for reusing a source-admitted initial
/// context with a pending destination generation.
///
/// The retained context row remains immutable at its original target
/// generation. Repositories use this lookup to prove that the requested
/// replacement is still active and that the original source connection still
/// owns its leg before releasing the envelope to a replacement adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplacementInitialContextLookup {
    /// Authenticated tenant ownership.
    pub tenant_id: TenantId,
    /// Owning two-leg call.
    pub call_id: CallId,
    /// Stable logical destination leg being replaced.
    pub target_leg_id: LegId,
    /// Held destination generation that remains current until promotion.
    pub previous_binding_generation: BindingGeneration,
    /// Exact pending destination generation authorized to consume the context.
    pub pending_binding_generation: BindingGeneration,
}

/// External reference attached to a successful leg effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalReferenceBinding {
    /// Exact effect leg.
    pub leg_id: LegId,
    /// Exact effect binding generation.
    pub binding_generation: BindingGeneration,
    /// Role occupied by this reference within a provider-controlled leg.
    #[serde(default)]
    pub role: ProviderReferenceRole,
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
    /// Role occupied by this reference within a provider-controlled leg.
    #[serde(default)]
    pub role: ProviderReferenceRole,
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
    /// Additional references returned by one compound provider operation.
    ///
    /// Telnyx leg replacement starts the Bridgefu-facing media call and the
    /// linked destination call under one durable effect. Both identifiers are
    /// therefore committed with the promotion rather than leaving the
    /// destination callback unowned after a crash.
    #[serde(default)]
    pub additional_external_references: Vec<ExternalReferenceBinding>,
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
    /// Additional stored references supplied by a compound provider effect.
    #[serde(default)]
    pub additional_external_references: Vec<StoredExternalReference>,
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

/// Atomic service-managed provider callback reconciliation.
///
/// The target is repeated deliberately as an immutable ownership guard. The
/// repository requires it to match both the retained event target and the
/// provider reference released by the original start-leg reconciliation.
/// `follow_up` may be omitted only after the target call is durably terminal;
/// otherwise a callback must advance the aggregate through a validated service
/// command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderEventReconciliationTransaction {
    /// Provider credential/account namespace.
    pub account: ProviderAccountKey,
    /// Exact normalized provider event identity.
    pub event_digest: ProviderEventDigest,
    /// Exact claim incarnation held by the worker.
    pub claim_generation: ClaimGeneration,
    /// Current fenced worker.
    pub worker: WorkerLease,
    /// Exact tenant, call, and provider-leg target.
    pub target: ProviderEventTarget,
    /// Optional service command committed with callback completion.
    pub follow_up: Option<ServiceCommandTransaction>,
    /// Reconciliation time. A follow-up command must use this exact time.
    pub at: DateTime<Utc>,
}

/// Exact durable result of applying or acknowledging a provider callback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderEventReconciliationView {
    /// Applied provider event.
    pub event: ProviderEventEnvelope,
    /// Target independently retained with the completion receipt.
    pub target: ProviderEventTarget,
    /// Worker fence independently retained with the completion receipt.
    pub worker: WorkerLease,
    /// Claim generation independently retained with the completion receipt.
    pub claim_generation: ClaimGeneration,
    /// Optional state-machine result committed atomically.
    pub follow_up: Option<ServiceCommandView>,
}

/// First service reconciliation or an exact lost-response replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderEventReconciliationOutcome {
    /// Callback and optional follow-up were committed in this transaction.
    Reconciled(ProviderEventReconciliationView),
    /// The exact request returned its original durable result.
    Replayed(ProviderEventReconciliationView),
}

/// Durable service companion. Implementations perform no provider or rvoip I/O.
#[async_trait]
pub trait CallServiceRepository: Send + Sync {
    /// Inspects one inbound attachment proof without consuming it.
    ///
    /// Implementations must preserve the core repository's indistinguishable
    /// proof-rejection semantics. This seam keeps the complete proof flow on
    /// the service repository used by [`super::CallService`].
    async fn inspect_inbound_attachment(
        &self,
        request: AttachmentLookup,
    ) -> Result<AttachmentCandidate, RepositoryError>;

    /// Atomically consumes one inspected proof, binds its rvoip connection,
    /// and commits the supplied signaling transition.
    async fn consume_inbound_attachment(
        &self,
        request: AttachmentConsume,
    ) -> Result<ConsumedAttachment, RepositoryError>;

    /// Loads the authenticated connection retained by one exact consumed
    /// attachment generation. Pending provider replacements use this without
    /// disturbing the logical leg's still-current binding.
    async fn load_attachment_binding(
        &self,
        _tenant_id: &TenantId,
        _call_id: CallId,
        _leg_id: LegId,
        _binding_generation: BindingGeneration,
        _purpose: crate::call_engine::AttachmentPurpose,
    ) -> Result<Option<ConnectionBinding>, RepositoryError> {
        Err(RepositoryError::InvalidInput(
            "attachment binding lookup is unsupported",
        ))
    }

    /// Atomically validates one exact connection binding and commits its
    /// lifecycle observation.
    async fn commit_bound_connection_state(
        &self,
        request: BoundConnectionStateCommit,
    ) -> Result<ServiceCommandOutcome, RepositoryError>;

    /// Atomically validates one exact pending source and begins peer teardown.
    async fn commit_bound_source_termination(
        &self,
        request: BoundSourceTerminationCommit,
    ) -> Result<ServiceCommandOutcome, RepositoryError>;

    /// Atomically validates exact, consecutive media activity and arms or
    /// refreshes `DeadlineKind::Media` without allowing stale activity to
    /// resurrect a cancelled timer.
    async fn commit_media_activity(
        &self,
        request: MediaActivityCommit,
    ) -> Result<ServiceCommandOutcome, RepositoryError>;

    /// Returns an unexpired exact create receipt before worker placement.
    ///
    /// Implementations do not mutate retention state during this preflight.
    /// A retained tenant/key with a different request or receipt kind returns
    /// [`RepositoryError::IdempotencyConflict`].
    async fn load_create_replay(
        &self,
        tenant_id: &TenantId,
        key_digest: IdempotencyKeyDigest,
        request_digest: RequestDigest,
        at: DateTime<Utc>,
    ) -> Result<Option<StoredServiceCall>, RepositoryError>;

    /// Returns an unexpired exact state-changing operation receipt before
    /// endpoint capability validation or current-state evaluation.
    ///
    /// This preserves the original result when a provider or transport is
    /// disabled after an operation committed. A retained tenant/key with a
    /// different request, call, or operation kind returns
    /// [`RepositoryError::IdempotencyConflict`].
    async fn load_service_command_replay(
        &self,
        tenant_id: &TenantId,
        call_id: CallId,
        key_digest: IdempotencyKeyDigest,
        request_digest: RequestDigest,
        operation: ServiceOperationKind,
        at: DateTime<Utc>,
    ) -> Result<Option<ServiceCommandView>, RepositoryError>;

    /// Returns an unexpired exact control-operation receipt before current
    /// assignment validation. This lets a gateway preserve the original
    /// response without dispatching new work after its route catalog changes.
    async fn load_control_command_replay(
        &self,
        tenant_id: &TenantId,
        call_id: CallId,
        key_digest: IdempotencyKeyDigest,
        request_digest: RequestDigest,
        operation: ServiceOperationKind,
        at: DateTime<Utc>,
    ) -> Result<Option<ControlCommandView>, RepositoryError>;

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

    /// Commits `BeginLegReplacement` only after atomically revalidating the
    /// exact unreleased call assignment and its live, non-draining worker
    /// capability. An exact retained idempotency receipt is replayed before
    /// current worker health is considered.
    async fn commit_leg_replacement_with_worker_guard(
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

    /// Atomically validates both current leg generations and the exact current
    /// source connection before retaining one initial context for the target.
    async fn record_initial_context(
        &self,
        _request: InitialContextRecordRequest,
    ) -> Result<InitialContextRecordOutcome, RepositoryError> {
        Err(RepositoryError::InvalidInput(
            "initial context persistence is unsupported",
        ))
    }

    /// Loads context for one exact current target leg generation.
    async fn load_initial_context(
        &self,
        _tenant_id: &TenantId,
        _call_id: CallId,
        _target_leg_id: LegId,
        _target_binding_generation: BindingGeneration,
    ) -> Result<Option<StoredInitialContext>, RepositoryError> {
        Err(RepositoryError::InvalidInput(
            "initial context persistence is unsupported",
        ))
    }

    /// Loads the immutable source-admitted context only while the exact
    /// make-before-break replacement remains active and its source connection
    /// is still current.
    ///
    /// Implementations must not copy or retarget the stored row. The pending
    /// adapter re-projects the validated envelope into its own initial-only
    /// signaling contract.
    async fn load_replacement_initial_context(
        &self,
        _lookup: ReplacementInitialContextLookup,
    ) -> Result<Option<StoredInitialContext>, RepositoryError> {
        Err(RepositoryError::InvalidInput(
            "replacement initial context persistence is unsupported",
        ))
    }

    /// Loads the current external reference for a tenant-owned leg.
    async fn load_external_reference(
        &self,
        tenant_id: &TenantId,
        call_id: CallId,
        leg_id: LegId,
    ) -> Result<Option<StoredExternalReference>, RepositoryError>;

    /// Loads one exact role for a tenant-owned provider leg. Implementations
    /// predating role-aware references remain compatible for the primary
    /// media role and fail closed for additional roles.
    async fn load_external_reference_by_role(
        &self,
        tenant_id: &TenantId,
        call_id: CallId,
        leg_id: LegId,
        role: ProviderReferenceRole,
    ) -> Result<Option<StoredExternalReference>, RepositoryError> {
        if role == ProviderReferenceRole::Media {
            self.load_external_reference(tenant_id, call_id, leg_id)
                .await
        } else {
            Err(RepositoryError::InvalidInput(
                "role-aware external references are unsupported",
            ))
        }
    }

    /// Loads one exact external reference incarnation.
    ///
    /// Unlike [`Self::load_external_reference_by_role`], this remains usable
    /// after a logical leg has advanced to a newer binding generation. That
    /// distinction is required to deterministically retire the held route
    /// after a make-before-break replacement.
    async fn load_external_reference_for_binding(
        &self,
        tenant_id: &TenantId,
        call_id: CallId,
        leg_id: LegId,
        binding_generation: BindingGeneration,
        role: ProviderReferenceRole,
    ) -> Result<Option<StoredExternalReference>, RepositoryError> {
        Ok(self
            .load_external_reference_by_role(tenant_id, call_id, leg_id, role)
            .await?
            .filter(|reference| reference.binding_generation == binding_generation))
    }

    /// Atomically reconciles a claimed effect and all related durable state.
    async fn reconcile_effect_result(
        &self,
        request: EffectResultReconciliation,
    ) -> Result<EffectResultOutcome, RepositoryError>;

    /// Atomically applies one claimed provider callback to a service-managed
    /// call, or acknowledges it after terminal completion.
    async fn reconcile_provider_event(
        &self,
        _request: ProviderEventReconciliationTransaction,
    ) -> Result<ProviderEventReconciliationOutcome, RepositoryError> {
        Err(RepositoryError::InvalidInput(
            "service-managed provider reconciliation is unsupported",
        ))
    }
}
