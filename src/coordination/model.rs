//! Safe, backend-neutral coordination models.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::call_engine::{
    AttachmentTokenDigest, AttachmentTransport, CallId, PrincipalFingerprint, WorkerId, WorkerLease,
};

const MAX_DEPLOYMENT_BYTES: usize = 63;
const MAX_NAME_BYTES: usize = 128;
const MAX_CAPABILITIES: usize = 64;
const MAX_CLAIM_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(30);
const MAX_PROJECTION_LIFETIME: TimeDelta = TimeDelta::hours(24);

/// Deployment namespace used in every memory and Redis key.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DeploymentId(String);

impl DeploymentId {
    /// Parses a key-safe deployment name.
    pub fn parse(value: impl Into<String>) -> Result<Self, CoordinationError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_DEPLOYMENT_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(CoordinationError::InvalidInput("invalid deployment ID"));
        }
        Ok(Self(value))
    }

    /// Returns the validated key component.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DeploymentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("DeploymentId")
            .field(&self.0)
            .finish()
    }
}

impl<'de> Deserialize<'de> for DeploymentId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Monotonic database-safe coordination event sequence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProjectionSequence(u64);

impl ProjectionSequence {
    /// First coordination event.
    pub const INITIAL: Self = Self(1);

    /// Reconstructs a sequence from a signed database column.
    pub fn from_i64(value: i64) -> Result<Self, CoordinationError> {
        if value <= 0 {
            Err(CoordinationError::InvalidInput(
                "projection sequence must be positive",
            ))
        } else {
            Ok(Self(value as u64))
        }
    }

    /// Returns the signed database representation.
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    pub(crate) fn next(self) -> Result<Self, CoordinationError> {
        if self.0 >= i64::MAX as u64 {
            Err(CoordinationError::CounterExhausted)
        } else {
            Ok(Self(self.0 + 1))
        }
    }
}

impl<'de> Deserialize<'de> for ProjectionSequence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        if value == 0 || value > i64::MAX as u64 {
            return Err(serde::de::Error::custom(
                "projection sequence exceeds signed database range",
            ));
        }
        Ok(Self(value))
    }
}

/// Monotonic claim incarnation for coordination outbox work.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CoordinationClaimGeneration(u64);

impl CoordinationClaimGeneration {
    /// Reconstructs a claim generation from a signed database column.
    pub fn from_i64(value: i64) -> Result<Self, CoordinationError> {
        if value < 0 {
            Err(CoordinationError::InvalidInput(
                "claim generation must not be negative",
            ))
        } else {
            Ok(Self(value as u64))
        }
    }

    /// Returns the signed database representation.
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    pub(crate) fn next(self) -> Result<Self, CoordinationError> {
        if self.0 >= i64::MAX as u64 {
            Err(CoordinationError::CounterExhausted)
        } else {
            Ok(Self(self.0 + 1))
        }
    }
}

impl<'de> Deserialize<'de> for CoordinationClaimGeneration {
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

/// SHA-256-sized replay marker. Raw idempotency keys and tokens never enter coordination.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReplayDigest([u8; 32]);

impl ReplayDigest {
    /// Constructs a marker from an already-derived digest.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Exposes bytes only to a persistence/key-encoding boundary.
    #[must_use]
    pub const fn expose_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ReplayDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReplayDigest([redacted])")
    }
}

/// Authoritative worker snapshot projected from PostgreSQL or standalone memory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkerCoordinationSnapshot {
    /// Exact worker incarnation.
    pub lease: WorkerLease,
    /// Authoritative capacity ceiling.
    pub max_calls: usize,
    /// Authoritative reservations already committed in the call repository.
    pub reserved_calls: usize,
    /// One-way drain bit for this fence.
    pub draining: bool,
    /// Validated capability identifiers.
    pub capabilities: BTreeSet<String>,
    /// Absolute lease expiry decided by the authoritative repository clock.
    pub lease_expires_at: DateTime<Utc>,
}

impl WorkerCoordinationSnapshot {
    pub(crate) fn validate(&self) -> Result<(), CoordinationError> {
        if self.max_calls == 0 || self.reserved_calls > self.max_calls {
            return Err(CoordinationError::InvalidInput(
                "invalid projected worker capacity",
            ));
        }
        validate_capabilities(&self.capabilities)
    }

    /// Remaining authoritative capacity represented by this hint.
    #[must_use]
    pub fn available_calls(&self) -> usize {
        self.max_calls.saturating_sub(self.reserved_calls)
    }
}

/// Short-lived call-to-worker routing hint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CallRouteHint {
    /// Call identity. Tenant authorization remains in PostgreSQL/API policy.
    pub call_id: CallId,
    /// Exact assigned worker incarnation.
    pub worker: WorkerLease,
    /// Absolute cache expiry.
    pub expires_at: DateTime<Utc>,
}

/// Non-authoritative routing projection for one opaque inbound attachment.
///
/// The raw bearer, tenant identifier, call identifier, and leg identifier are
/// deliberately absent. `tenant_binding` is the existing keyed principal
/// fingerprint (issuer + tenant + subject), so a gateway can reject an
/// owner/tenant mismatch before opening a private route without turning Redis
/// into an attachment authorization database. The assigned worker remains
/// authoritative and must consume the bearer under this exact fence before it
/// acknowledges the route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AttachmentRouteHint {
    /// SHA-256 digest of the opaque attachment bearer; also the projection key.
    pub token_digest: AttachmentTokenDigest,
    /// Exact worker incarnation that issued the attachment.
    pub worker: WorkerLease,
    /// Signaling transport the bearer was issued for.
    pub transport: AttachmentTransport,
    /// Keyed issuer/tenant/subject binding. Debug output is redacted by type.
    pub tenant_binding: PrincipalFingerprint,
    /// Absolute bearer expiry copied from authoritative attachment state.
    pub expires_at: DateTime<Utc>,
}

/// Exact lookup supplied by an authenticated gateway.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachmentRouteLookup {
    pub token_digest: AttachmentTokenDigest,
    pub transport: AttachmentTransport,
    pub tenant_binding: PrincipalFingerprint,
}

/// Short-lived replay hint containing only a derived digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReplayMarker {
    /// Derived replay digest.
    pub digest: ReplayDigest,
    /// Absolute cache expiry.
    pub expires_at: DateTime<Utc>,
}

/// Safe coordination projection payload. It cannot represent credentials,
/// raw tokens, provider payloads, or tenant authorization decisions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum CoordinationPayload {
    /// Worker lease/capacity/capability projection.
    Worker(WorkerCoordinationSnapshot),
    /// Call route hint.
    Route(CallRouteHint),
    /// Explicitly removes a call route while retaining its sequence tombstone.
    /// Emit this transactionally when an assignment is released or a call
    /// reaches terminal cleanup.
    RouteRemoved {
        /// Call whose cached assignment must no longer be returned.
        call_id: CallId,
    },
    /// Routes one opaque attachment digest to its exact worker incarnation.
    AttachmentRoute(AttachmentRouteHint),
    /// Removes a consumed, revoked, or otherwise retired attachment route.
    AttachmentRouteRemoved {
        /// Digest whose cached routing projection must become inactive.
        token_digest: AttachmentTokenDigest,
    },
    /// Replay digest hint.
    Replay(ReplayMarker),
    /// Wake a worker so it polls authoritative database work.
    WakeWorker {
        /// Worker to wake.
        worker_id: WorkerId,
        /// Typed reason containing no durable work payload.
        reason: WakeupReason,
    },
}

/// One ordered coordination-outbox event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CoordinationEvent {
    /// Deployment namespace.
    pub deployment: DeploymentId,
    /// Monotonic authoritative sequence.
    pub sequence: ProjectionSequence,
    /// Safe projection/wakeup payload.
    pub payload: CoordinationPayload,
    /// Authoritative persistence time.
    pub recorded_at: DateTime<Utc>,
}

impl CoordinationEvent {
    pub(crate) fn validate(&self) -> Result<(), CoordinationError> {
        if self.recorded_at.timestamp_millis() < 0 {
            return Err(CoordinationError::InvalidInput(
                "coordination time must follow the Unix epoch",
            ));
        }
        match &self.payload {
            CoordinationPayload::Worker(worker) => {
                worker.validate()?;
                validate_projection_expiry(
                    worker.lease_expires_at,
                    self.recorded_at,
                    "invalid projected worker lease expiry",
                )
            }
            CoordinationPayload::Route(route) => validate_projection_expiry(
                route.expires_at,
                self.recorded_at,
                "invalid projected route expiry",
            ),
            CoordinationPayload::AttachmentRoute(route) => validate_projection_expiry(
                route.expires_at,
                self.recorded_at,
                "invalid projected attachment route expiry",
            ),
            CoordinationPayload::Replay(marker) => validate_projection_expiry(
                marker.expires_at,
                self.recorded_at,
                "invalid projected replay expiry",
            ),
            _ => Ok(()),
        }
    }
}

fn validate_projection_expiry(
    expires_at: DateTime<Utc>,
    recorded_at: DateTime<Utc>,
    error: &'static str,
) -> Result<(), CoordinationError> {
    let maximum = recorded_at
        .checked_add_signed(MAX_PROJECTION_LIFETIME)
        .ok_or(CoordinationError::InvalidData)?;
    if expires_at <= recorded_at || expires_at > maximum {
        Err(CoordinationError::InvalidInput(error))
    } else {
        Ok(())
    }
}

/// Why a worker should poll its authoritative database queues.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeupReason {
    /// Core effect outbox may have work.
    Effects,
    /// Control/DTMF outbox may have work.
    Controls,
    /// A deadline may be due.
    Deadlines,
    /// Provider callbacks may be ready.
    ProviderEvents,
    /// Worker assignment or drain state changed.
    Assignment,
    /// Durable broadcast start/stop commands may have work.
    Broadcasts,
}

impl WakeupReason {
    /// Stable Redis field value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Effects => "effects",
            Self::Controls => "controls",
            Self::Deadlines => "deadlines",
            Self::ProviderEvents => "provider_events",
            Self::Assignment => "assignment",
            Self::Broadcasts => "broadcasts",
        }
    }

    /// Parses the stable Redis field value.
    pub fn parse(value: &str) -> Result<Self, CoordinationError> {
        match value {
            "effects" => Ok(Self::Effects),
            "controls" => Ok(Self::Controls),
            "deadlines" => Ok(Self::Deadlines),
            "provider_events" => Ok(Self::ProviderEvents),
            "assignment" => Ok(Self::Assignment),
            "broadcasts" => Ok(Self::Broadcasts),
            _ => Err(CoordinationError::InvalidData),
        }
    }
}

/// Wakeup stream entry. It is only a hint; consumers must claim database work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WakeupMessage {
    /// Backend stream entry ID.
    pub entry_id: String,
    /// Coordination sequence that emitted the hint.
    pub sequence: ProjectionSequence,
    /// Hint reason.
    pub reason: WakeupReason,
}

/// Why a consumer should execute its bounded authoritative database poll.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabasePollReason {
    /// One or more Redis/memory hints arrived.
    Wakeup,
    /// Blocking wait reached the bounded fallback interval.
    IntervalElapsed,
    /// The cache/stream backend was unavailable or malformed.
    CoordinationUnavailable,
}

/// Result of one wakeup wait. Every variant requires an authoritative DB claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WakeupPoll {
    /// Best-effort hints, possibly empty.
    pub messages: Vec<WakeupMessage>,
    /// Reason to poll PostgreSQL/standalone repository now.
    pub database_poll_reason: DatabasePollReason,
}

/// Capability/capacity selection request. Results are hints only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerSelectionRequest {
    /// Required capabilities.
    pub required_capabilities: BTreeSet<String>,
    /// Maximum hints to return.
    pub limit: usize,
}

impl WorkerSelectionRequest {
    pub(crate) fn validate(&self) -> Result<(), CoordinationError> {
        if self.limit == 0 || self.limit > 1_024 {
            return Err(CoordinationError::InvalidInput("invalid selection limit"));
        }
        validate_capabilities(&self.required_capabilities)
    }
}

fn validate_capabilities(capabilities: &BTreeSet<String>) -> Result<(), CoordinationError> {
    if capabilities.len() > MAX_CAPABILITIES
        || capabilities.iter().any(|capability| {
            capability.is_empty()
                || capability.len() > MAX_NAME_BYTES
                || capability.chars().any(char::is_control)
        })
    {
        Err(CoordinationError::InvalidInput(
            "invalid projected worker capability",
        ))
    } else {
        Ok(())
    }
}

/// Idempotent projection result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionApplyOutcome {
    /// A newer event changed the cache.
    Applied,
    /// The identical sequence and body were already present.
    Duplicate,
    /// A newer sequence already won; this event was ignored.
    Stale,
}

/// Coordination errors are bounded and never include Redis URLs, tokens, or payloads.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CoordinationError {
    /// Input violated a bounded invariant.
    #[error("invalid coordination input: {0}")]
    InvalidInput(&'static str),
    /// The same sequence carried different content.
    #[error("coordination sequence conflict")]
    SequenceConflict,
    /// A stale worker fence attempted to overwrite a newer incarnation.
    #[error("stale worker fence")]
    StaleFence,
    /// An expired lease cannot be renewed with the same fence.
    #[error("expired worker lease cannot be resurrected")]
    LeaseExpired,
    /// Drain is one-way until a new fence is registered.
    #[error("worker drain cannot be reversed for the same fence")]
    DrainIsOneWay,
    /// A claim was expired, foreign, or already completed.
    #[error("stale coordination claim")]
    StaleClaim,
    /// A persistent counter exhausted its database range.
    #[error("coordination counter exhausted")]
    CounterExhausted,
    /// Redis/PostgreSQL was unavailable. No connection details are retained.
    #[error("coordination backend unavailable")]
    Unavailable,
    /// Backend data did not match the safe typed contract.
    #[error("invalid coordination backend data")]
    InvalidData,
}

/// Injected clock used by standalone coordination and deterministic tests.
pub trait CoordinationClock: Send + Sync {
    /// Current UTC time.
    fn now(&self) -> DateTime<Utc>;
}

/// Production wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCoordinationClock;

impl CoordinationClock for SystemCoordinationClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Deterministic test/standalone clock.
#[derive(Debug)]
pub struct ManualCoordinationClock {
    epoch_millis: AtomicI64,
}

impl ManualCoordinationClock {
    /// Creates a clock at the supplied UTC instant.
    #[must_use]
    pub fn new(now: DateTime<Utc>) -> Self {
        Self {
            epoch_millis: AtomicI64::new(now.timestamp_millis()),
        }
    }

    /// Moves the clock to an exact UTC instant.
    pub fn set(&self, now: DateTime<Utc>) {
        self.epoch_millis
            .store(now.timestamp_millis(), Ordering::SeqCst);
    }

    /// Advances the clock by a non-negative duration.
    pub fn advance(&self, duration: Duration) -> Result<(), CoordinationError> {
        let millis = i64::try_from(duration.as_millis())
            .map_err(|_| CoordinationError::InvalidInput("clock advance is too large"))?;
        self.epoch_millis
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(millis)
            })
            .map_err(|_| CoordinationError::InvalidInput("clock advance overflow"))?;
        Ok(())
    }
}

impl CoordinationClock for ManualCoordinationClock {
    fn now(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(self.epoch_millis.load(Ordering::SeqCst))
            .expect("validated manual coordination clock")
    }
}

/// Projection/cache interface. Implementations never reserve authoritative capacity.
#[async_trait]
pub trait CoordinationProjection: Send + Sync {
    /// Applies one ordered database-outbox event with per-key sequence CAS.
    async fn apply(
        &self,
        event: &CoordinationEvent,
    ) -> Result<ProjectionApplyOutcome, CoordinationError>;

    /// Returns active capability/capacity hints. The caller must still reserve in DB.
    async fn worker_hints(
        &self,
        request: &WorkerSelectionRequest,
    ) -> Result<Vec<WorkerCoordinationSnapshot>, CoordinationError>;

    /// Returns a live route hint or `None`, which triggers database fallback.
    async fn route_hint(&self, call_id: CallId)
        -> Result<Option<CallRouteHint>, CoordinationError>;

    /// Resolves one live, owner-bound attachment route hint.
    ///
    /// `None` is fail-closed for clustered gateways. Implementations must also
    /// verify that the exact projected worker fence is still live.
    async fn attachment_route_hint(
        &self,
        lookup: AttachmentRouteLookup,
    ) -> Result<Option<AttachmentRouteHint>, CoordinationError>;

    /// Returns a live replay hint. Authorization and canonical-result replay remain in DB.
    async fn replay_seen(&self, digest: ReplayDigest) -> Result<bool, CoordinationError>;
}

/// Best-effort worker wakeup publisher.
#[async_trait]
pub trait WakeupPublisher: Send + Sync {
    /// Publishes a bounded payload-free wakeup.
    async fn publish_wakeup(
        &self,
        worker_id: WorkerId,
        sequence: ProjectionSequence,
        reason: WakeupReason,
    ) -> Result<(), CoordinationError>;
}

/// Dedicated wakeup consumer. Every poll result requires an authoritative
/// active-lease recheck and a coalesced signal to the bounded DB work claimers.
#[async_trait]
pub trait WakeupConsumer: Send {
    /// Reads new consumer-group entries with a bounded blocking interval.
    async fn poll(&mut self, count: usize) -> WakeupPoll;

    /// Recovers stale pending deliveries with an exact minimum idle threshold.
    async fn auto_claim(
        &mut self,
        min_idle: Duration,
        count: usize,
    ) -> Result<Vec<WakeupMessage>, CoordinationError>;

    /// Acknowledges best-effort hints only after the active lease was rechecked
    /// and the authoritative work-claim signal was published.
    async fn acknowledge(&mut self, entry_ids: &[String]) -> Result<usize, CoordinationError>;
}

/// Validates an outbox claim TTL.
pub(crate) fn checked_claim_expiry(
    now: DateTime<Utc>,
    ttl: Duration,
) -> Result<DateTime<Utc>, CoordinationError> {
    if ttl.is_zero() || ttl > MAX_CLAIM_TTL {
        return Err(CoordinationError::InvalidInput("invalid claim TTL"));
    }
    let delta = TimeDelta::from_std(ttl)
        .map_err(|_| CoordinationError::InvalidInput("claim TTL is too large"))?;
    now.checked_add_signed(delta)
        .ok_or(CoordinationError::InvalidInput("claim expiry overflow"))
}

/// Validates a bounded stream fallback interval.
pub(crate) fn validate_poll_interval(interval: Duration) -> Result<(), CoordinationError> {
    if interval.is_zero() || interval > MAX_POLL_INTERVAL {
        Err(CoordinationError::InvalidInput(
            "invalid database fallback poll interval",
        ))
    } else {
        Ok(())
    }
}
