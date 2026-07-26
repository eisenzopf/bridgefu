//! Backend-neutral atomic repository contract for the durable call engine.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rvoip_core::ids::ConnectionId;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use thiserror::Error;

use super::{
    AggregateVersion, AttachmentId, AttachmentTokenDigest, BindingGeneration, CallAggregate,
    CallCommand, CallId, CommandDisposition, CommandId, DeadlineGeneration, DeadlineKind, EffectId,
    EffectIntent, FailureDetails, IdempotencyKeyDigest, LegId, LegState, PrincipalFingerprint,
    ProviderEventDigest, ProviderPayloadDigest, RequestDigest, TenantId, WorkerId,
};

/// Fixed retention period for call-creation idempotency claims.
pub const IDEMPOTENCY_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
/// Maximum normalized provider-event JSON size accepted by the repository.
pub const MAX_PROVIDER_EVENT_BYTES: usize = 64 * 1024;
const MAX_PROVIDER_IDENTIFIER_BYTES: usize = 512;
const MAX_PROVIDER_KIND_BYTES: usize = 128;
const MAX_CAPABILITY_BYTES: usize = 128;
/// Default worker lease duration used by production runtime configuration.
pub const DEFAULT_WORKER_LEASE_TTL: Duration = Duration::from_secs(30);
/// Shortest supported worker lease.
pub const MIN_WORKER_LEASE_TTL: Duration = Duration::from_secs(5);
/// Longest supported worker lease.
pub const MAX_WORKER_LEASE_TTL: Duration = Duration::from_secs(5 * 60);

/// Monotonic worker incarnation used to reject a stale process.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct WorkerFence(u64);

impl WorkerFence {
    /// First worker incarnation.
    pub const INITIAL: Self = Self(1);

    /// Returns the database-safe signed value.
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    pub(crate) fn next(self) -> Result<Self, RepositoryError> {
        if self.0 >= i64::MAX as u64 {
            Err(RepositoryError::CounterExhausted)
        } else {
            Ok(Self(self.0 + 1))
        }
    }
}

impl<'de> Deserialize<'de> for WorkerFence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        if value == 0 || value > i64::MAX as u64 {
            return Err(serde::de::Error::custom(
                "worker fence must fit a positive signed database integer",
            ));
        }
        Ok(Self(value))
    }
}

/// Monotonic claim generation for reclaimable work.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ClaimGeneration(u64);

impl ClaimGeneration {
    /// Returns the database-safe signed value.
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    pub(crate) fn next(self) -> Result<Self, RepositoryError> {
        if self.0 >= i64::MAX as u64 {
            Err(RepositoryError::CounterExhausted)
        } else {
            Ok(Self(self.0 + 1))
        }
    }
}

impl<'de> Deserialize<'de> for ClaimGeneration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        if value > i64::MAX as u64 {
            return Err(serde::de::Error::custom(
                "claim generation exceeds signed database range",
            ));
        }
        Ok(Self(value))
    }
}

/// Monotonic repository-assigned ordering for verified provider events.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProviderReceiptSequence(u64);

impl ProviderReceiptSequence {
    /// First durable provider receipt.
    pub const INITIAL: Self = Self(1);

    /// Returns the database-safe signed value.
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    pub(crate) fn next(self) -> Result<Self, RepositoryError> {
        if self.0 >= i64::MAX as u64 {
            Err(RepositoryError::CounterExhausted)
        } else {
            Ok(Self(self.0 + 1))
        }
    }
}

impl<'de> Deserialize<'de> for ProviderReceiptSequence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        if value == 0 || value > i64::MAX as u64 {
            return Err(serde::de::Error::custom(
                "provider receipt sequence must fit a positive signed database integer",
            ));
        }
        Ok(Self(value))
    }
}

/// Current fenced worker identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct WorkerLease {
    /// Stable worker identity.
    pub worker_id: WorkerId,
    /// Current worker incarnation.
    pub fence: WorkerFence,
}

/// Durable worker capacity view.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkerSnapshot {
    /// Current fenced worker identity.
    pub lease: WorkerLease,
    /// Maximum assigned nonterminal calls.
    pub max_calls: usize,
    /// Current assigned nonterminal calls.
    pub reserved_calls: usize,
    /// Whether the worker refuses new calls.
    pub draining: bool,
    /// Validated capability identifiers.
    pub capabilities: BTreeSet<String>,
    /// Last repository update.
    pub updated_at: DateTime<Utc>,
    /// Authoritative expiry for this exact fence.
    pub lease_expires_at: DateTime<Utc>,
}

/// Maximum number of authoritative placement candidates returned by one
/// repository query. Public callers cannot force an unbounded collection.
pub const MAX_WORKER_CANDIDATE_LIMIT: usize = 1_024;

/// Registration request. Re-registering the same ID advances its fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterWorker {
    /// Stable worker identity.
    pub worker_id: WorkerId,
    /// Maximum assigned nonterminal calls.
    pub max_calls: usize,
    /// Capability identifiers used by later selection layers.
    pub capabilities: BTreeSet<String>,
    /// Registration time.
    pub at: DateTime<Utc>,
    /// Requested bounded lease duration.
    pub lease_ttl: Duration,
}

/// Same-fence activation of the concrete adapters installed by a worker.
///
/// Workers may register with an empty capability set while their signaling
/// and provider adapters are being installed. This operation publishes that
/// inventory exactly once without advancing the worker fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivateWorkerCapabilities {
    /// Exact current worker incarnation.
    pub worker: WorkerLease,
    /// Non-empty concrete adapter capability set.
    pub capabilities: BTreeSet<String>,
    /// Authoritative observation time (replaced with database time by SQL backends).
    pub at: DateTime<Utc>,
}

/// Same-fence worker heartbeat request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenewWorkerLease {
    /// Exact current worker incarnation.
    pub worker: WorkerLease,
    /// Requested bounded lease duration.
    pub lease_ttl: Duration,
    /// Authoritative observation time (replaced with database time by SQL backends).
    pub at: DateTime<Utc>,
}

/// Fenced call-to-worker assignment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkerAssignment {
    /// Assigned worker.
    pub lease: WorkerLease,
    /// Assignment time.
    pub assigned_at: DateTime<Utc>,
    /// Capacity-release time; set exactly once.
    pub released_at: Option<DateTime<Utc>>,
}

/// Transport class accepted by an attachment token.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentTransport {
    /// SIP signaling and RTP media.
    Sip,
    /// Interactive WebRTC, WHIP, or WHEP signaling.
    WebRtc,
}

/// A connection durably bound to one leg generation.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConnectionBinding {
    /// Exact rvoip connection ID.
    pub connection_id: ConnectionId,
    /// Bound logical leg.
    pub leg_id: LegId,
    /// Bound leg generation.
    pub binding_generation: BindingGeneration,
    /// Actual transport.
    pub transport: AttachmentTransport,
    /// Authenticated issuer/tenant/subject fingerprint.
    pub principal_fingerprint: PrincipalFingerprint,
    /// Binding time.
    pub bound_at: DateTime<Utc>,
}

impl fmt::Debug for ConnectionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionBinding")
            .field("connection_id", &self.connection_id)
            .field("leg_id", &self.leg_id)
            .field("binding_generation", &self.binding_generation)
            .field("transport", &self.transport)
            .field("principal_fingerprint", &"[redacted]")
            .field("bound_at", &self.bound_at)
            .finish()
    }
}

/// Tenant-scoped persisted call plus execution bindings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoredCall {
    /// Pure call aggregate.
    pub aggregate: CallAggregate,
    /// Current or released worker assignment.
    pub assignment: WorkerAssignment,
    /// Current connection bindings keyed by logical leg.
    pub bindings: BTreeMap<LegId, ConnectionBinding>,
}

/// One attachment token digest to persist atomically with a call decision.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentPurpose {
    /// Public attachment explicitly returned for an inbound logical leg.
    #[default]
    PublicInbound,
    /// Internal provider SIP media attachment; never returned by an API view.
    ProviderMedia,
}

/// One attachment token digest to persist atomically with a call decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AttachmentIssue {
    /// Stable attachment row identity.
    pub attachment_id: AttachmentId,
    /// Digest of the raw 256-bit token; the raw token is never accepted here.
    pub token_digest: AttachmentTokenDigest,
    /// Visibility and state-machine policy for this attachment.
    #[serde(default)]
    pub purpose: AttachmentPurpose,
    /// Target leg.
    pub leg_id: LegId,
    /// Exact binding generation.
    pub binding_generation: BindingGeneration,
    /// Expected signaling/media transport.
    pub transport: AttachmentTransport,
    /// Exact authenticated principal allowed to consume this token.
    pub expected_principal: PrincipalFingerprint,
    /// Absolute two-minute-style expiry supplied by policy.
    pub expires_at: DateTime<Utc>,
}

/// Durable idempotent call-creation input.
#[derive(Clone, Debug)]
pub struct CreateCall {
    /// Newly constructed version-zero aggregate.
    pub initial: CallAggregate,
    /// Initial state-machine command.
    pub command_id: CommandId,
    /// Initial command, normally `StartConnecting`.
    pub command: CallCommand,
    /// Exact worker reservation requested for this call.
    pub worker: WorkerLease,
    /// Digest of the untrusted HTTP idempotency key.
    pub idempotency_key: IdempotencyKeyDigest,
    /// Digest of the canonical tenant-bound request.
    pub request_digest: RequestDigest,
    /// Inbound attachment rows created with the initial decision.
    pub attachments: Vec<AttachmentIssue>,
    /// Repository observation time.
    pub at: DateTime<Utc>,
}

/// Result of an idempotent call creation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateCallOutcome {
    /// This transaction created and reserved the call.
    Created(StoredCall),
    /// The same tenant/key/request already created this call.
    Replayed(StoredCall),
}

/// Persisted command receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoredCommand {
    /// Stable command ID.
    pub command_id: CommandId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Owning call.
    pub call_id: CallId,
    /// Aggregate version observed by the command.
    pub observed_version: AggregateVersion,
    /// Aggregate version after the command decision.
    pub result_version: AggregateVersion,
    /// Original pure command.
    pub command: CallCommand,
    /// Exact worker lease supplied by the command request.
    pub worker: WorkerLease,
    /// Exact attachment rows supplied by the command request.
    pub attachments: Vec<AttachmentIssue>,
    /// Exact optional timer claim supplied by the command request.
    pub deadline_claim: Option<DeadlineClaimGuard>,
    /// State-machine disposition.
    pub disposition: CommandDisposition,
    /// Repository persistence time.
    pub recorded_at: DateTime<Utc>,
}

/// Optional guard that makes timer completion atomic with its command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeadlineClaimGuard {
    /// Call owning the deadline.
    pub call_id: CallId,
    /// Deadline kind.
    pub kind: DeadlineKind,
    /// Domain timer generation.
    pub generation: DeadlineGeneration,
    /// Worker claim owner.
    pub worker: WorkerLease,
    /// Claim incarnation.
    pub claim_generation: ClaimGeneration,
}

/// Optimistic, fenced pure-command transaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandCommit {
    /// Authenticated tenant scope.
    pub tenant_id: TenantId,
    /// Target call.
    pub call_id: CallId,
    /// Expected aggregate version.
    pub expected_version: AggregateVersion,
    /// Stable delivery-deduplication ID.
    pub command_id: CommandId,
    /// Pure state-machine command.
    pub command: CallCommand,
    /// Exact worker assignment fence.
    pub worker: WorkerLease,
    /// New attachment rows, usually from a rotated binding.
    pub attachments: Vec<AttachmentIssue>,
    /// Optional claimed timer completed by this command.
    pub deadline_claim: Option<DeadlineClaimGuard>,
    /// Repository persistence time.
    pub at: DateTime<Utc>,
}

/// Result shared by ordinary and attachment-driven command commits.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandCommitView {
    /// Persisted command receipt.
    pub command: StoredCommand,
    /// Resulting tenant-scoped call.
    pub call: StoredCall,
    /// Ordered outbox entries produced by the decision.
    pub outbox: Vec<OutboxRecord>,
}

/// Command commit or exact command-ID replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandCommitOutcome {
    /// This transaction persisted the decision.
    Committed(CommandCommitView),
    /// The exact command was already persisted.
    Replayed(CommandCommitView),
}

/// Opaque valid attachment candidate returned before atomic consumption.
#[derive(Clone)]
pub struct AttachmentCandidate {
    pub(crate) attachment_id: AttachmentId,
    pub(crate) token_digest: AttachmentTokenDigest,
    pub(crate) purpose: AttachmentPurpose,
    pub(crate) tenant_id: TenantId,
    pub(crate) call_id: CallId,
    pub(crate) leg_id: LegId,
    pub(crate) binding_generation: BindingGeneration,
    pub(crate) transport: AttachmentTransport,
    pub(crate) worker: WorkerLease,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) expected_principal: PrincipalFingerprint,
    pub(crate) expected_version: AggregateVersion,
}

impl AttachmentCandidate {
    /// Logical leg selected by the token.
    #[must_use]
    pub const fn leg_id(&self) -> LegId {
        self.leg_id
    }

    /// Call selected by the token.
    #[must_use]
    pub const fn call_id(&self) -> CallId {
        self.call_id
    }

    /// Exact leg generation selected by the token.
    #[must_use]
    pub const fn binding_generation(&self) -> BindingGeneration {
        self.binding_generation
    }

    /// Expected transport.
    #[must_use]
    pub const fn transport(&self) -> AttachmentTransport {
        self.transport
    }

    /// Attachment visibility and state-machine policy.
    #[must_use]
    pub const fn purpose(&self) -> AttachmentPurpose {
        self.purpose
    }

    /// Token expiry.
    #[must_use]
    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub(crate) const fn expected_version(&self) -> AggregateVersion {
        self.expected_version
    }
}

impl fmt::Debug for AttachmentCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttachmentCandidate")
            .field("attachment_id", &self.attachment_id)
            .field("token_digest", &"[redacted]")
            .field("purpose", &self.purpose)
            .field("tenant_id", &self.tenant_id)
            .field("call_id", &self.call_id)
            .field("leg_id", &self.leg_id)
            .field("binding_generation", &self.binding_generation)
            .field("transport", &self.transport)
            .field("worker", &self.worker)
            .field("expires_at", &self.expires_at)
            .field("expected_principal", &"[redacted]")
            .field("expected_version", &self.expected_version)
            .finish()
    }
}

/// Lookup for a tenant-, transport-, and fence-bound attachment.
#[derive(Clone, Debug)]
pub struct AttachmentLookup {
    /// Digest of the presented raw token.
    pub token_digest: AttachmentTokenDigest,
    /// Authenticated tenant.
    pub tenant_id: TenantId,
    /// Actual inbound transport.
    pub transport: AttachmentTransport,
    /// Authenticated issuer/tenant/subject fingerprint.
    pub principal_fingerprint: PrincipalFingerprint,
    /// Worker expected to own this call.
    pub worker: WorkerLease,
    /// Lookup time.
    pub at: DateTime<Utc>,
}

/// Atomic attachment consumption and signaling-state transaction.
#[derive(Clone)]
pub struct AttachmentConsume {
    /// Opaque candidate from `inspect_attachment`.
    pub candidate: AttachmentCandidate,
    /// Stable command delivery ID.
    pub command_id: CommandId,
    /// Must transition the candidate leg/generation to `Signaling`.
    pub command: CallCommand,
    /// Exact rvoip connection ID.
    pub connection_id: ConnectionId,
    /// Redacted authenticated ownership fingerprint.
    pub principal_fingerprint: PrincipalFingerprint,
    /// Absolute expiry of the authenticated principal, when bounded.
    ///
    /// Repositories must compare this deadline with their authoritative time
    /// inside the same transaction that consumes the attachment. A caller-side
    /// expiry observation is not sufficient because the transaction may wait
    /// behind database or lock contention.
    pub principal_expires_at: Option<DateTime<Utc>>,
    /// Binding and persistence time.
    pub at: DateTime<Utc>,
}

impl fmt::Debug for AttachmentConsume {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttachmentConsume")
            .field("candidate", &self.candidate)
            .field("command_id", &self.command_id)
            .field("command", &self.command)
            .field("connection_id", &self.connection_id)
            .field("principal_fingerprint", &"[redacted]")
            .field(
                "principal_expires_at",
                &self.principal_expires_at.as_ref().map(|_| "[redacted]"),
            )
            .field("at", &self.at)
            .finish()
    }
}

/// Successful attachment transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumedAttachment {
    /// Durable connection binding.
    pub binding: ConnectionBinding,
    /// State-machine commit made atomically with token consumption.
    pub commit: CommandCommitView,
}

/// Provider credential/account namespace.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProviderAccountKey(String);

impl ProviderAccountKey {
    /// Validates a bounded provider account namespace.
    pub fn parse(value: impl Into<String>) -> Result<Self, RepositoryError> {
        let value = value.into();
        if valid_identifier(&value, MAX_PROVIDER_IDENTIFIER_BYTES) {
            Ok(Self(value))
        } else {
            Err(RepositoryError::InvalidInput(
                "invalid provider account key",
            ))
        }
    }

    /// Returns the validated account key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProviderAccountKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderAccountKey([redacted])")
    }
}

impl<'de> Deserialize<'de> for ProviderAccountKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Provider-owned call ID. It is redacted because it can encode a phone account or PII.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProviderCallId(String);

impl ProviderCallId {
    /// Validates a bounded provider call ID.
    pub fn parse(value: impl Into<String>) -> Result<Self, RepositoryError> {
        let value = value.into();
        if valid_identifier(&value, MAX_PROVIDER_IDENTIFIER_BYTES) {
            Ok(Self(value))
        } else {
            Err(RepositoryError::InvalidInput("invalid provider call ID"))
        }
    }

    /// Explicitly reveals the value at the provider API boundary.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProviderCallId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderCallId([redacted])")
    }
}

impl<'de> Deserialize<'de> for ProviderCallId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Provider event lifecycle in durable storage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProviderEventState {
    /// No provider-call reference existed at receipt time.
    PendingReference,
    /// A call/leg target is known and the event awaits application.
    Ready,
    /// Exclusively claimed by a fenced worker until expiry.
    Claimed {
        /// Claim owner.
        worker: WorkerLease,
        /// Claim incarnation.
        generation: ClaimGeneration,
        /// Time at which this claim incarnation began.
        claimed_at: DateTime<Utc>,
        /// Claim expiry.
        expires_at: DateTime<Utc>,
    },
    /// The event was applied by a later transactional service step.
    Applied,
}

/// Tenant-scoped target for a normalized provider event.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderReferenceRole {
    /// Provider call whose SIP/RTP media terminates at Bridgefu.
    #[default]
    Media,
    /// Provider call to the requested destination, linked to the media call.
    Destination,
}

impl ProviderReferenceRole {
    /// Stable storage and diagnostics label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Media => "media",
            Self::Destination => "destination",
        }
    }
}

/// Tenant-scoped target for a normalized provider event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderEventTarget {
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Owning call.
    pub call_id: CallId,
    /// Provider-controlled leg.
    pub leg_id: LegId,
    /// Exact provider call role which emitted the callback.
    #[serde(default)]
    pub role: ProviderReferenceRole,
}

/// Normalized durable provider event. Debug deliberately omits identifiers and JSON.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderEventEnvelope {
    /// Provider credential/account namespace.
    pub account: ProviderAccountKey,
    /// Digest of the provider event ID.
    pub event_digest: ProviderEventDigest,
    /// Digest of the canonical normalized payload.
    pub payload_digest: ProviderPayloadDigest,
    /// Provider call ID used for eventual reconciliation.
    pub provider_call_id: ProviderCallId,
    /// Bounded normalized event kind.
    pub kind: String,
    /// Bounded normalized JSON, never formatted by `Debug`.
    pub payload: Value,
    /// Provider occurrence time when supplied.
    pub occurred_at: Option<DateTime<Utc>>,
    /// Bridgefu receipt time.
    pub received_at: DateTime<Utc>,
    /// Monotonic repository insertion order.
    pub receipt_sequence: ProviderReceiptSequence,
    /// Current matching target.
    pub target: Option<ProviderEventTarget>,
    /// Durable lifecycle state.
    pub state: ProviderEventState,
    /// Time at which a transactional service step applied the event.
    pub applied_at: Option<DateTime<Utc>>,
}

impl fmt::Debug for ProviderEventEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderEventEnvelope")
            .field("account", &"[redacted]")
            .field("event_digest", &"[redacted]")
            .field("payload_digest", &"[redacted]")
            .field("provider_call_id", &"[redacted]")
            .field("kind", &self.kind)
            .field("payload", &"[redacted]")
            .field("occurred_at", &self.occurred_at)
            .field("received_at", &self.received_at)
            .field("receipt_sequence", &self.receipt_sequence)
            .field("target", &self.target)
            .field("state", &self.state)
            .field("applied_at", &self.applied_at)
            .finish()
    }
}

/// Provider webhook ingestion input.
#[derive(Clone)]
pub struct ProviderEventInput {
    /// Provider credential/account namespace.
    pub account: ProviderAccountKey,
    /// Digest of provider event ID.
    pub event_digest: ProviderEventDigest,
    /// Digest of canonical normalized payload.
    pub payload_digest: ProviderPayloadDigest,
    /// Provider call ID.
    pub provider_call_id: ProviderCallId,
    /// Normalized event kind.
    pub kind: String,
    /// Bounded normalized payload.
    pub payload: Value,
    /// Provider occurrence time.
    pub occurred_at: Option<DateTime<Utc>>,
    /// Bridgefu receipt time.
    pub received_at: DateTime<Utc>,
}

impl fmt::Debug for ProviderEventInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderEventInput")
            .field("account", &"[redacted]")
            .field("event_digest", &"[redacted]")
            .field("payload_digest", &"[redacted]")
            .field("provider_call_id", &"[redacted]")
            .field("kind", &self.kind)
            .field("payload", &"[redacted]")
            .field("occurred_at", &self.occurred_at)
            .field("received_at", &self.received_at)
            .finish()
    }
}

/// Provider webhook insertion or exact duplicate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderEventOutcome {
    /// A new provider event was retained.
    Accepted(ProviderEventEnvelope),
    /// The same provider event and payload were already retained.
    Duplicate(ProviderEventEnvelope),
}

/// Binds an external provider call ID to one call leg.
#[derive(Clone, Debug)]
pub struct BindProviderReference {
    /// Authenticated tenant scope.
    pub tenant_id: TenantId,
    /// Owning call.
    pub call_id: CallId,
    /// Provider-controlled leg.
    pub leg_id: LegId,
    /// Provider call role within the logical leg.
    pub role: ProviderReferenceRole,
    /// Provider namespace.
    pub account: ProviderAccountKey,
    /// External call ID.
    pub provider_call_id: ProviderCallId,
    /// Current call worker.
    pub worker: WorkerLease,
    /// Binding time.
    pub at: DateTime<Utc>,
}

/// Claimed provider event and its exact completion guard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedProviderEvent {
    /// Claimed event snapshot.
    pub event: ProviderEventEnvelope,
    /// Claim incarnation.
    pub claim_generation: ClaimGeneration,
}

/// Atomically applies a claimed provider event with its call command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderEventCommit {
    /// Provider namespace.
    pub account: ProviderAccountKey,
    /// Exact provider event ID digest.
    pub event_digest: ProviderEventDigest,
    /// Exact claim incarnation.
    pub claim_generation: ClaimGeneration,
    /// Current call worker.
    pub worker: WorkerLease,
    /// Associated pure call command transaction.
    pub command: CommandCommit,
    /// Completion time; must equal the command time.
    pub at: DateTime<Utc>,
}

/// Atomic provider event and call-command result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderEventCommitOutcome {
    /// Applied provider event.
    pub event: ProviderEventEnvelope,
    /// Associated call command result.
    pub command: CommandCommitOutcome,
}

/// Fenced terminal-call acknowledgement for a provider event that requires no
/// further aggregate transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TerminalProviderEventAcknowledge {
    /// Provider namespace.
    pub account: ProviderAccountKey,
    /// Exact provider event ID digest.
    pub event_digest: ProviderEventDigest,
    /// Exact claim incarnation.
    pub claim_generation: ClaimGeneration,
    /// Current call worker.
    pub worker: WorkerLease,
    /// Exact tenant/call/leg target retained on the event.
    pub target: ProviderEventTarget,
    /// Acknowledgement time.
    pub at: DateTime<Utc>,
}

/// Idempotent terminal provider-event acknowledgement outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TerminalProviderEventAcknowledgeOutcome {
    /// This transaction acknowledged the event.
    Acknowledged(ProviderEventEnvelope),
    /// The exact acknowledgement had already committed.
    Replayed(ProviderEventEnvelope),
}

/// Outbox execution lifecycle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum OutboxState {
    /// Available for a worker claim.
    Ready,
    /// Exclusively claimed until the supplied UTC time.
    Claimed {
        /// Worker claim owner.
        worker: WorkerLease,
        /// Claim incarnation.
        generation: ClaimGeneration,
        /// Time at which this claim incarnation was acquired.
        claimed_at: DateTime<Utc>,
        /// Claim expiry.
        expires_at: DateTime<Utc>,
    },
    /// External work completed successfully.
    Succeeded {
        /// Completion time.
        at: DateTime<Utc>,
    },
    /// External work completed with a sanitized failure.
    Failed {
        /// Completion time.
        at: DateTime<Utc>,
        /// Sanitized failure.
        failure: FailureDetails,
    },
}

/// Ordered effect outbox row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutboxRecord {
    /// Stable effect identity.
    pub effect_id: EffectId,
    /// Command that produced the effect.
    pub command_id: CommandId,
    /// Effect order within that command.
    pub ordinal: u32,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Owning call.
    pub call_id: CallId,
    /// Aggregate version that produced this ordered effect batch.
    pub aggregate_version: AggregateVersion,
    /// Assignment fence at creation.
    pub worker: WorkerLease,
    /// Pure effect intent.
    pub intent: EffectIntent,
    /// Earliest claim time.
    pub available_at: DateTime<Utc>,
    /// Current execution state.
    pub state: OutboxState,
}

/// Claimed outbox row and its exact completion guard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedOutbox {
    /// Claimed record.
    pub record: OutboxRecord,
    /// Exact claim generation.
    pub claim_generation: ClaimGeneration,
}

/// Outbox completion result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboxCompletion {
    /// External work succeeded.
    Succeeded,
    /// External work failed with bounded safe details.
    Failed(FailureDetails),
}

/// Deadline persistence lifecycle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DeadlineState {
    /// Waiting for due time.
    Pending,
    /// Claimed by the assigned worker.
    Claimed {
        /// Worker claim owner.
        worker: WorkerLease,
        /// Claim incarnation.
        generation: ClaimGeneration,
        /// Claim expiry.
        expires_at: DateTime<Utc>,
    },
    /// Cancelled by a later state transition.
    Cancelled {
        /// Cancellation time.
        at: DateTime<Utc>,
    },
    /// Completed atomically with `DeadlineElapsed`.
    Completed {
        /// Completion time.
        at: DateTime<Utc>,
    },
}

/// Materialized scheduled deadline.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeadlineRecord {
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Owning call.
    pub call_id: CallId,
    /// Deadline kind.
    pub kind: DeadlineKind,
    /// Domain timer generation.
    pub generation: DeadlineGeneration,
    /// Absolute due time.
    pub due_at: DateTime<Utc>,
    /// Current persistence lifecycle.
    pub state: DeadlineState,
}

/// Claimed deadline and exact command guard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedDeadline {
    /// Claimed row.
    pub record: DeadlineRecord,
    /// Claim incarnation.
    pub claim_generation: ClaimGeneration,
}

impl ClaimedDeadline {
    /// Builds the guard to include in the matching command commit.
    #[must_use]
    pub fn guard(&self, worker: WorkerLease) -> DeadlineClaimGuard {
        DeadlineClaimGuard {
            call_id: self.record.call_id,
            kind: self.record.kind,
            generation: self.record.generation,
            worker,
            claim_generation: self.claim_generation,
        }
    }
}

/// Call reclaimed by a newer incarnation of its assigned worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestartClaim {
    /// Recovered call after its assignment fence was advanced.
    pub call: StoredCall,
    /// Superseded worker fence.
    pub previous_fence: WorkerFence,
}

/// Errors have bounded, non-secret representations suitable for service mapping.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RepositoryError {
    /// Tenant-scoped resource was absent.
    #[error("resource not found")]
    NotFound,
    /// Worker admission had no capacity.
    #[error("worker capacity exhausted")]
    CapacityExceeded,
    /// Worker ID/fence was not current or the worker was draining.
    #[error("stale or unavailable worker lease")]
    StaleWorkerFence,
    /// The exact live worker does not own every adapter required by the plan.
    #[error("worker capability is unavailable")]
    WorkerCapabilityUnavailable,
    /// Aggregate compare-and-swap failed.
    #[error("aggregate version conflict")]
    VersionConflict,
    /// Same command ID was reused with different contents or ownership.
    #[error("command identifier conflict")]
    CommandConflict,
    /// Same idempotency key was reused for another canonical request.
    #[error("idempotency key conflict")]
    IdempotencyConflict,
    /// Attachment was invalid, expired, consumed, or outside its binding.
    #[error("attachment rejected")]
    AttachmentRejected,
    /// Attachment digest, row ID, binding, or connection uniqueness failed.
    #[error("attachment uniqueness conflict")]
    AttachmentConflict,
    /// Provider event ID was reused for a different payload.
    #[error("provider event payload conflict")]
    ProviderEventConflict,
    /// Provider call reference was already bound to another target.
    #[error("provider call reference conflict")]
    ProviderReferenceConflict,
    /// Work completion used a stale, expired, or foreign claim.
    #[error("stale work claim")]
    StaleClaim,
    /// A persistent monotonic counter exhausted its signed database range.
    #[error("persistent counter exhausted")]
    CounterExhausted,
    /// Input violated a bounded repository invariant.
    #[error("invalid repository input: {0}")]
    InvalidInput(&'static str),
    /// Pure state-machine validation failed.
    #[error("call state transition rejected")]
    DomainRejected,
    /// In-memory lock poisoning or an equivalent backend failure.
    #[error("repository unavailable")]
    Unavailable,
}

/// High-level atomic call repository. Implementations never perform external I/O.
#[async_trait]
pub trait CallRepository: Send + Sync {
    /// Registers a worker and advances its durable fence.
    async fn register_worker(
        &self,
        request: RegisterWorker,
    ) -> Result<WorkerSnapshot, RepositoryError>;

    /// Publishes the concrete adapter inventory for one exact live worker.
    /// Empty registration to non-empty activation is allowed once; replaying
    /// the exact set is idempotent and any later change is rejected.
    async fn activate_worker_capabilities(
        &self,
        request: ActivateWorkerCapabilities,
    ) -> Result<WorkerSnapshot, RepositoryError>;

    /// Renews one unexpired exact fence without changing its identity.
    async fn renew_worker_lease(
        &self,
        request: RenewWorkerLease,
    ) -> Result<WorkerSnapshot, RepositoryError>;

    /// Changes admission state only for the current worker incarnation.
    async fn set_worker_draining(
        &self,
        worker: WorkerLease,
        draining: bool,
        at: DateTime<Utc>,
    ) -> Result<WorkerSnapshot, RepositoryError>;

    /// Returns a worker snapshot.
    async fn worker_snapshot(&self, worker_id: WorkerId)
        -> Result<WorkerSnapshot, RepositoryError>;

    /// Re-reads one exact fence and rejects a draining or expired lease. SQL
    /// implementations replace `at` with authoritative database time.
    async fn active_worker_snapshot(
        &self,
        worker: WorkerLease,
        at: DateTime<Utc>,
    ) -> Result<WorkerSnapshot, RepositoryError>;

    /// Returns a bounded authoritative candidate set. Selection is a hint;
    /// call creation still reserves capacity atomically.
    async fn worker_candidates(
        &self,
        required_capabilities: &BTreeSet<String>,
        at: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<WorkerSnapshot>, RepositoryError>;

    /// Atomically reserves capacity and persists the first call decision.
    async fn create_call(&self, request: CreateCall) -> Result<CreateCallOutcome, RepositoryError>;

    /// Loads a call only in the authenticated tenant scope.
    async fn load_call(
        &self,
        tenant_id: &TenantId,
        call_id: CallId,
    ) -> Result<StoredCall, RepositoryError>;

    /// Atomically CASes a call, command, outbox, deadlines, and attachments.
    async fn commit_command(
        &self,
        request: CommandCommit,
    ) -> Result<CommandCommitOutcome, RepositoryError>;

    /// Releases terminal call capacity exactly once.
    async fn release_assignment(
        &self,
        tenant_id: &TenantId,
        call_id: CallId,
        worker: WorkerLease,
        at: DateTime<Utc>,
    ) -> Result<bool, RepositoryError>;

    /// Looks up a valid attachment without consuming it.
    async fn inspect_attachment(
        &self,
        request: AttachmentLookup,
    ) -> Result<AttachmentCandidate, RepositoryError>;

    /// Consumes an attachment and commits its exact connection binding atomically.
    ///
    /// Implementations must enforce both the durable attachment expiry and the
    /// supplied principal expiry against transaction-authoritative time.
    async fn consume_attachment(
        &self,
        request: AttachmentConsume,
    ) -> Result<ConsumedAttachment, RepositoryError>;

    /// Durably deduplicates a verified, normalized provider event.
    async fn ingest_provider_event(
        &self,
        request: ProviderEventInput,
    ) -> Result<ProviderEventOutcome, RepositoryError>;

    /// Binds a provider call ID and returns earlier callbacks in receipt order.
    async fn bind_provider_reference(
        &self,
        request: BindProviderReference,
    ) -> Result<Vec<ProviderEventEnvelope>, RepositoryError>;

    /// Claims provider events in monotonic repository receipt order.
    async fn claim_provider_events(
        &self,
        worker: WorkerLease,
        at: DateTime<Utc>,
        claim_ttl: Duration,
        limit: usize,
    ) -> Result<Vec<ClaimedProviderEvent>, RepositoryError>;

    /// Atomically applies a claimed provider event and its call command.
    async fn complete_provider_event(
        &self,
        request: ProviderEventCommit,
    ) -> Result<ProviderEventCommitOutcome, RepositoryError>;

    /// Acknowledges a claimed provider event for an already-terminal call.
    async fn acknowledge_terminal_provider_event(
        &self,
        request: TerminalProviderEventAcknowledge,
    ) -> Result<TerminalProviderEventAcknowledgeOutcome, RepositoryError>;

    /// Claims ordered effects for the current assigned worker.
    async fn claim_outbox(
        &self,
        worker: WorkerLease,
        at: DateTime<Utc>,
        claim_ttl: Duration,
        limit: usize,
    ) -> Result<Vec<ClaimedOutbox>, RepositoryError>;

    /// Completes a currently held outbox claim.
    async fn complete_outbox(
        &self,
        effect_id: EffectId,
        worker: WorkerLease,
        claim_generation: ClaimGeneration,
        completion: OutboxCompletion,
        at: DateTime<Utc>,
    ) -> Result<OutboxRecord, RepositoryError>;

    /// Claims due deadlines for the current assigned worker.
    async fn claim_due_deadlines(
        &self,
        worker: WorkerLease,
        at: DateTime<Utc>,
        claim_ttl: Duration,
        limit: usize,
    ) -> Result<Vec<ClaimedDeadline>, RepositoryError>;

    /// Advances old assignments to a newer incarnation of the same worker.
    async fn claim_restart_calls(
        &self,
        worker: WorkerLease,
        at: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<RestartClaim>, RepositoryError>;
}

pub(crate) fn validate_register_worker(request: &RegisterWorker) -> Result<(), RepositoryError> {
    if request.max_calls == 0 {
        return Err(RepositoryError::InvalidInput(
            "worker max_calls must be greater than zero",
        ));
    }
    validate_worker_capabilities(&request.capabilities)?;
    validate_worker_lease_ttl(request.lease_ttl)
}

pub(crate) fn validate_worker_capabilities(
    capabilities: &BTreeSet<String>,
) -> Result<(), RepositoryError> {
    if capabilities.iter().any(|capability| {
        capability.is_empty()
            || capability.len() > MAX_CAPABILITY_BYTES
            || capability.chars().any(char::is_control)
    }) {
        return Err(RepositoryError::InvalidInput("invalid worker capability"));
    }
    Ok(())
}

pub(crate) fn validate_worker_candidate_limit(limit: usize) -> Result<(), RepositoryError> {
    if limit > MAX_WORKER_CANDIDATE_LIMIT {
        Err(RepositoryError::InvalidInput(
            "worker candidate limit exceeds the repository bound",
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn validate_worker_lease_ttl(ttl: Duration) -> Result<(), RepositoryError> {
    if ttl < MIN_WORKER_LEASE_TTL || ttl > MAX_WORKER_LEASE_TTL {
        Err(RepositoryError::InvalidInput("invalid worker lease TTL"))
    } else {
        Ok(())
    }
}

pub(crate) fn worker_lease_expiry(
    at: DateTime<Utc>,
    ttl: Duration,
) -> Result<DateTime<Utc>, RepositoryError> {
    validate_worker_lease_ttl(ttl)?;
    chrono_ttl(at, ttl)
}

pub(crate) fn validate_provider_event(request: &ProviderEventInput) -> Result<(), RepositoryError> {
    if !valid_identifier(&request.kind, MAX_PROVIDER_KIND_BYTES) {
        return Err(RepositoryError::InvalidInput("invalid provider event kind"));
    }
    let payload = serde_json::to_vec(&request.payload)
        .map_err(|_| RepositoryError::InvalidInput("provider payload is not serializable"))?;
    if payload.len() > MAX_PROVIDER_EVENT_BYTES {
        return Err(RepositoryError::InvalidInput(
            "provider payload is too large",
        ));
    }
    Ok(())
}

pub(crate) fn validate_attachment_issue(
    call: &CallAggregate,
    issue: &AttachmentIssue,
    at: DateTime<Utc>,
) -> Result<(), RepositoryError> {
    if issue.expires_at <= at {
        return Err(RepositoryError::InvalidInput(
            "attachment expiry must be in the future",
        ));
    }
    let leg = call.leg(issue.leg_id).ok_or(RepositoryError::InvalidInput(
        "attachment leg is outside call",
    ))?;
    let valid_state = match issue.purpose {
        AttachmentPurpose::PublicInbound => {
            leg.direction() == crate::call_engine::LegDirection::Inbound
                && leg.state() == LegState::AwaitingAttach
        }
        AttachmentPurpose::ProviderMedia => {
            let ordinary = leg.direction() == crate::call_engine::LegDirection::Outbound
                && leg.kind() == crate::call_engine::LegKind::Telnyx
                && leg.binding_generation() == issue.binding_generation
                && matches!(leg.state(), LegState::Pending | LegState::Signaling);
            let replacement = call.replacement().is_some_and(|replacement| {
                replacement.leg_id() == issue.leg_id
                    && replacement.pending_kind() == crate::call_engine::LegKind::Telnyx
                    && replacement.pending_binding_generation() == issue.binding_generation
            });
            (ordinary || replacement) && issue.transport == AttachmentTransport::Sip
        }
    };
    if !valid_state {
        return Err(RepositoryError::InvalidInput(
            "attachment does not match its leg purpose or generation",
        ));
    }
    Ok(())
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

pub(crate) fn chrono_ttl(
    at: DateTime<Utc>,
    ttl: Duration,
) -> Result<DateTime<Utc>, RepositoryError> {
    if ttl.is_zero() {
        return Err(RepositoryError::InvalidInput(
            "claim TTL must be greater than zero",
        ));
    }
    let ttl = chrono::Duration::from_std(ttl)
        .map_err(|_| RepositoryError::InvalidInput("claim TTL is too large"))?;
    at.checked_add_signed(ttl)
        .ok_or(RepositoryError::InvalidInput("claim expiry overflow"))
}

pub(crate) fn idempotency_expiry(at: DateTime<Utc>) -> Result<DateTime<Utc>, RepositoryError> {
    chrono_ttl(at, IDEMPOTENCY_RETENTION)
}
