//! Authenticated split gateway egress command protocol.
//!
//! Commands travel only inside the existing mutually-authenticated UCTP 0.2
//! connection. The gateway supplies [`PrivateEgressRouteAuthority`] from the
//! already admitted source route; values in the command never create their
//! own authority. This keeps tenant, call, source-leg, attachment-generation,
//! and worker-fence checks at one boundary before an egress implementation is
//! invoked.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use dashmap::DashMap;
use rvoip_core::adapter::EndReason;
use rvoip_core::capability::CodecInfo;
use rvoip_core::connection::Transport;
use rvoip_core::events::Event;
use rvoip_core::ids::ConnectionId;
use rvoip_core::operational_events::{OperationalEvent, OperationalEventKind};
use rvoip_core::{
    DataMessage, DataReliability, Orchestrator, StagedInboundDataReceiver, StagedInboundDataSender,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{broadcast, oneshot, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::call_engine::{BindingGeneration, CallId, LegId, TenantId, WorkerLease};
pub use crate::private_egress_redis::{
    RedisPrivateEgressStateConfig, RedisPrivateEgressStateStore,
};
pub use crate::private_egress_state::{
    MemoryPrivateEgressStateStore, PrivateEgressCommandClaim, PrivateEgressGatewayEpoch,
    PrivateEgressRecoveredRoute, PrivateEgressRouteKey, PrivateEgressStateStore,
};

/// Reliable UCTP `message.send` label used for worker-to-gateway commands.
pub const PRIVATE_EGRESS_COMMAND_LABEL: &str = "bridgefu.private-egress.command.v1";
/// Reliable UCTP `message.send` label used for gateway command replies.
pub const PRIVATE_EGRESS_RESPONSE_LABEL: &str = "bridgefu.private-egress.response.v1";
/// Reliable UCTP `message.send` label used for asynchronous gateway lifecycle.
pub const PRIVATE_EGRESS_LIFECYCLE_LABEL: &str = "bridgefu.private-egress.lifecycle.v1";
/// Reliable worker acknowledgement for one exact lifecycle journal record.
pub const PRIVATE_EGRESS_LIFECYCLE_ACK_LABEL: &str = "bridgefu.private-egress.lifecycle-ack.v1";
pub const PRIVATE_EGRESS_CONTENT_TYPE: &str = "application/vnd.bridgefu.private-egress+json";

const PROTOCOL_VERSION: u8 = 1;
const MAX_COMMAND_BYTES: usize = 16 * 1024;
const MAX_TARGET_BYTES: usize = 2_048;
const MAX_PROFILE_ID_BYTES: usize = 128;
const MAX_PROFILE_REVISION_BYTES: usize = 128;
const MAX_CONTEXT_ENTRIES: usize = 32;
const MAX_CONTEXT_NAME_BYTES: usize = 128;
const MAX_CONTEXT_VALUE_BYTES: usize = 2_048;
const MAX_CLOCK_SKEW: Duration = Duration::from_secs(10);
const MAX_COMMAND_LIFETIME: Duration = Duration::from_secs(30);

/// True only for Bridgefu-internal labels that public DataChannels and SIP
/// MESSAGE mappings must never originate or receive.
#[must_use]
pub fn is_private_egress_label(label: &str) -> bool {
    matches!(
        label,
        PRIVATE_EGRESS_COMMAND_LABEL
            | PRIVATE_EGRESS_RESPONSE_LABEL
            | PRIVATE_EGRESS_LIFECYCLE_LABEL
            | PRIVATE_EGRESS_LIFECYCLE_ACK_LABEL
    )
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateEgressTransport {
    Sip,
    WebRtc,
}

/// Exact source authority repeated on the wire and compared with the route
/// that physically carried the command.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct PrivateEgressSource {
    pub tenant_id: TenantId,
    pub call_id: CallId,
    pub leg_id: LegId,
    pub binding_generation: BindingGeneration,
}

/// Destination incarnation. A later replacement uses the same logical leg
/// with a greater generation and cannot mutate the prior incarnation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct PrivateEgressTarget {
    pub leg_id: LegId,
    pub binding_generation: BindingGeneration,
}

/// Non-secret profile identity. Secret material stays in the gateway process
/// and is resolved only by the installed egress handler.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateEgressProfile {
    pub profile_id: String,
    pub revision: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateEgressEndReason {
    Normal,
    Cancelled,
    Rejected,
    Timeout,
    Failed,
    WorkerDrain,
}

/// Versioned command operation. Prepare is intentionally dormant; only a
/// subsequent Activate may make signaling peer-visible.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum PrivateEgressOperation {
    Prepare {
        transport: PrivateEgressTransport,
        profile: PrivateEgressProfile,
        /// Exact codec carried by the destination-side private stream.
        codec: CodecInfo,
        /// Sanitized destination selected by the durable route, never by a
        /// public browser or model.
        target: String,
        /// Ordered, allowlisted initial context. The gateway egress profile
        /// decides whether each value becomes a SIP header or other metadata.
        #[serde(default)]
        initial_context: Vec<(String, String)>,
    },
    Activate,
    Abort,
    End {
        reason: PrivateEgressEndReason,
    },
    Dtmf {
        digits: String,
        duration_ms: u32,
    },
    DataMessage {
        message: DataMessage,
    },
}

impl fmt::Debug for PrivateEgressOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prepare {
                transport,
                profile,
                initial_context,
                ..
            } => formatter
                .debug_struct("Prepare")
                .field("transport", transport)
                .field("profile_id_present", &!profile.profile_id.is_empty())
                .field("profile_revision_present", &!profile.revision.is_empty())
                .field("target", &"[redacted]")
                .field("initial_context_fields", &initial_context.len())
                .finish(),
            Self::Activate => formatter.write_str("Activate"),
            Self::Abort => formatter.write_str("Abort"),
            Self::End { reason } => formatter.debug_tuple("End").field(reason).finish(),
            Self::Dtmf { duration_ms, .. } => formatter
                .debug_struct("Dtmf")
                .field("digits", &"[redacted]")
                .field("duration_ms", duration_ms)
                .finish(),
            Self::DataMessage { message } => formatter
                .debug_struct("DataMessage")
                .field("message", message)
                .finish(),
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateEgressCommand {
    pub version: u8,
    pub command_id: Uuid,
    /// UTC Unix milliseconds. Commands have a small bounded lifetime and are
    /// additionally replay-protected by command ID plus canonical digest.
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub worker: WorkerLease,
    pub source: PrivateEgressSource,
    pub target: PrivateEgressTarget,
    pub operation: PrivateEgressOperation,
}

impl fmt::Debug for PrivateEgressCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateEgressCommand")
            .field("version", &self.version)
            .field("command_id", &self.command_id)
            .field("worker", &self.worker)
            .field("source", &self.source)
            .field("target", &self.target)
            .field("operation", &self.operation)
            .finish()
    }
}

impl PrivateEgressCommand {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        command_id: Uuid,
        now_ms: i64,
        lifetime: Duration,
        worker: WorkerLease,
        source: PrivateEgressSource,
        target: PrivateEgressTarget,
        operation: PrivateEgressOperation,
    ) -> Result<Self, PrivateEgressError> {
        let lifetime_ms = i64::try_from(lifetime.as_millis())
            .ok()
            .filter(|value| *value > 0)
            .ok_or(PrivateEgressError::InvalidCommand)?;
        let expires_at_ms = now_ms
            .checked_add(lifetime_ms)
            .ok_or(PrivateEgressError::InvalidCommand)?;
        let command = Self {
            version: PROTOCOL_VERSION,
            command_id,
            issued_at_ms: now_ms,
            expires_at_ms,
            worker,
            source,
            target,
            operation,
        };
        command.validate(now_ms)?;
        Ok(command)
    }

    pub fn validate(&self, now_ms: i64) -> Result<(), PrivateEgressError> {
        if self.version != PROTOCOL_VERSION || self.command_id.is_nil() {
            return Err(PrivateEgressError::InvalidCommand);
        }
        let lifetime_ms = self
            .expires_at_ms
            .checked_sub(self.issued_at_ms)
            .filter(|value| *value > 0)
            .ok_or(PrivateEgressError::InvalidCommand)?;
        if u128::try_from(lifetime_ms).unwrap_or(u128::MAX) > MAX_COMMAND_LIFETIME.as_millis() {
            return Err(PrivateEgressError::InvalidCommand);
        }
        let skew_ms = i64::try_from(MAX_CLOCK_SKEW.as_millis()).unwrap_or(i64::MAX);
        if self.issued_at_ms > now_ms.saturating_add(skew_ms) || self.expires_at_ms < now_ms {
            return Err(PrivateEgressError::Expired);
        }
        validate_operation(&self.operation)
    }

    pub fn to_data_message(&self) -> Result<DataMessage, PrivateEgressError> {
        let bytes = serde_json::to_vec(self).map_err(|_| PrivateEgressError::InvalidCommand)?;
        if bytes.len() > MAX_COMMAND_BYTES {
            return Err(PrivateEgressError::InvalidCommand);
        }
        Ok(DataMessage::reliable(
            PRIVATE_EGRESS_COMMAND_LABEL,
            PRIVATE_EGRESS_CONTENT_TYPE,
            bytes,
        ))
    }

    pub fn from_data_message(
        message: &DataMessage,
        now_ms: i64,
    ) -> Result<Self, PrivateEgressError> {
        validate_wire_message(message, PRIVATE_EGRESS_COMMAND_LABEL)?;
        let command: Self = serde_json::from_slice(&message.bytes)
            .map_err(|_| PrivateEgressError::InvalidCommand)?;
        command.validate(now_ms)?;
        Ok(command)
    }

    fn digest(&self) -> Result<[u8; 32], PrivateEgressError> {
        let encoded = serde_json::to_vec(self).map_err(|_| PrivateEgressError::InvalidCommand)?;
        Ok(Sha256::digest(encoded).into())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateEgressLifecycleState {
    Prepared,
    Active,
    Ended,
    Failed,
}

/// Adapter-authoritative lifecycle information delivered independently of a
/// command response. Provisional SIP progress is deliberately not represented
/// as a route state: a 180/183 response may enable ringback or early media, but
/// it never makes the destination active.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PrivateEgressLifecycleKind {
    State {
        state: PrivateEgressLifecycleState,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason_code: Option<String>,
    },
    Progress {
        status_code: u16,
        early_media: bool,
    },
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateEgressResponse {
    pub version: u8,
    pub command_id: Uuid,
    pub accepted: bool,
    pub replayed: bool,
    pub state: Option<PrivateEgressLifecycleState>,
    pub failure_code: Option<String>,
    /// Adapter-owned stable identifier. Debug formatting always redacts it.
    pub external_reference: Option<String>,
}

impl fmt::Debug for PrivateEgressResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateEgressResponse")
            .field("version", &self.version)
            .field("command_id", &self.command_id)
            .field("accepted", &self.accepted)
            .field("replayed", &self.replayed)
            .field("state", &self.state)
            .field("failure_code", &self.failure_code)
            .field(
                "external_reference_present",
                &self.external_reference.is_some(),
            )
            .finish()
    }
}

impl PrivateEgressResponse {
    pub fn rejected(command_id: Uuid, error: PrivateEgressError) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            command_id,
            accepted: false,
            replayed: false,
            state: None,
            failure_code: Some(error.code().to_owned()),
            external_reference: None,
        }
    }

    pub fn to_data_message(&self) -> Result<DataMessage, PrivateEgressError> {
        let bytes = serde_json::to_vec(self).map_err(|_| PrivateEgressError::InvalidResponse)?;
        if bytes.len() > MAX_COMMAND_BYTES {
            return Err(PrivateEgressError::InvalidResponse);
        }
        Ok(DataMessage::reliable(
            PRIVATE_EGRESS_RESPONSE_LABEL,
            PRIVATE_EGRESS_CONTENT_TYPE,
            bytes,
        ))
    }

    pub fn from_data_message(message: &DataMessage) -> Result<Self, PrivateEgressError> {
        validate_wire_message(message, PRIVATE_EGRESS_RESPONSE_LABEL)?;
        let response: Self = serde_json::from_slice(&message.bytes)
            .map_err(|_| PrivateEgressError::InvalidResponse)?;
        if response.version != PROTOCOL_VERSION || response.command_id.is_nil() {
            return Err(PrivateEgressError::InvalidResponse);
        }
        Ok(response)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateEgressLifecycleEvent {
    pub version: u8,
    pub event_id: Uuid,
    pub worker: WorkerLease,
    pub source: PrivateEgressSource,
    pub target: PrivateEgressTarget,
    /// Gateway process incarnation assigned by the durable journal.
    pub gateway_epoch: Uuid,
    /// Monotonic per-route journal sequence assigned before delivery.
    pub sequence: u64,
    pub kind: PrivateEgressLifecycleKind,
}

impl PrivateEgressLifecycleEvent {
    pub fn new(
        worker: WorkerLease,
        source: PrivateEgressSource,
        target: PrivateEgressTarget,
        state: PrivateEgressLifecycleState,
        reason_code: Option<String>,
    ) -> Result<Self, PrivateEgressError> {
        let event = Self {
            version: PROTOCOL_VERSION,
            event_id: Uuid::new_v4(),
            worker,
            source,
            target,
            gateway_epoch: Uuid::nil(),
            sequence: 0,
            kind: PrivateEgressLifecycleKind::State { state, reason_code },
        };
        event.validate_kind()?;
        Ok(event)
    }

    /// Construct one unjournaled provisional SIP response. Only provisional
    /// status codes are accepted; final responses must use a state event.
    pub fn progress(
        worker: WorkerLease,
        source: PrivateEgressSource,
        target: PrivateEgressTarget,
        status_code: u16,
        early_media: bool,
    ) -> Result<Self, PrivateEgressError> {
        let event = Self {
            version: PROTOCOL_VERSION,
            event_id: Uuid::new_v4(),
            worker,
            source,
            target,
            gateway_epoch: Uuid::nil(),
            sequence: 0,
            kind: PrivateEgressLifecycleKind::Progress {
                status_code,
                early_media,
            },
        };
        event.validate_kind()?;
        Ok(event)
    }

    #[must_use]
    pub fn state(&self) -> Option<PrivateEgressLifecycleState> {
        match &self.kind {
            PrivateEgressLifecycleKind::State { state, .. } => Some(*state),
            PrivateEgressLifecycleKind::Progress { .. } => None,
        }
    }

    #[must_use]
    pub fn progress_details(&self) -> Option<(u16, bool)> {
        match &self.kind {
            PrivateEgressLifecycleKind::Progress {
                status_code,
                early_media,
            } => Some((*status_code, *early_media)),
            PrivateEgressLifecycleKind::State { .. } => None,
        }
    }

    fn validate_kind(&self) -> Result<(), PrivateEgressError> {
        match &self.kind {
            PrivateEgressLifecycleKind::State { reason_code, .. } => {
                if reason_code.as_ref().is_some_and(|reason| {
                    reason.is_empty()
                        || reason.len() > 128
                        || !reason
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
                }) {
                    return Err(PrivateEgressError::InvalidResponse);
                }
            }
            PrivateEgressLifecycleKind::Progress { status_code, .. }
                if !(100..=199).contains(status_code) =>
            {
                return Err(PrivateEgressError::InvalidResponse);
            }
            PrivateEgressLifecycleKind::Progress { .. } => {}
        }
        Ok(())
    }

    pub fn to_data_message(&self) -> Result<DataMessage, PrivateEgressError> {
        if self.version != PROTOCOL_VERSION
            || self.event_id.is_nil()
            || self.gateway_epoch.is_nil()
            || self.sequence == 0
        {
            return Err(PrivateEgressError::InvalidResponse);
        }
        self.validate_kind()?;
        let bytes = serde_json::to_vec(self).map_err(|_| PrivateEgressError::InvalidResponse)?;
        if bytes.len() > MAX_COMMAND_BYTES {
            return Err(PrivateEgressError::InvalidResponse);
        }
        Ok(DataMessage::reliable(
            PRIVATE_EGRESS_LIFECYCLE_LABEL,
            PRIVATE_EGRESS_CONTENT_TYPE,
            bytes,
        ))
    }

    pub fn from_data_message(message: &DataMessage) -> Result<Self, PrivateEgressError> {
        validate_wire_message(message, PRIVATE_EGRESS_LIFECYCLE_LABEL)?;
        let event: Self = serde_json::from_slice(&message.bytes)
            .map_err(|_| PrivateEgressError::InvalidResponse)?;
        if event.version != PROTOCOL_VERSION
            || event.event_id.is_nil()
            || event.gateway_epoch.is_nil()
            || event.sequence == 0
        {
            return Err(PrivateEgressError::InvalidResponse);
        }
        event.validate_kind()?;
        Ok(event)
    }
}

fn lifecycle_is_terminal(event: &PrivateEgressLifecycleEvent) -> bool {
    event.state().is_some_and(|state| {
        matches!(
            state,
            PrivateEgressLifecycleState::Ended | PrivateEgressLifecycleState::Failed
        )
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateEgressLifecycleAck {
    pub version: u8,
    pub event_id: Uuid,
    pub worker: WorkerLease,
    pub source: PrivateEgressSource,
    pub target: PrivateEgressTarget,
    pub gateway_epoch: Uuid,
    pub sequence: u64,
}

impl PrivateEgressLifecycleAck {
    pub fn from_event(event: &PrivateEgressLifecycleEvent) -> Result<Self, PrivateEgressError> {
        if event.gateway_epoch.is_nil() || event.sequence == 0 {
            return Err(PrivateEgressError::InvalidResponse);
        }
        Ok(Self {
            version: PROTOCOL_VERSION,
            event_id: event.event_id,
            worker: event.worker,
            source: event.source.clone(),
            target: event.target,
            gateway_epoch: event.gateway_epoch,
            sequence: event.sequence,
        })
    }

    pub fn to_data_message(&self) -> Result<DataMessage, PrivateEgressError> {
        if self.version != PROTOCOL_VERSION
            || self.event_id.is_nil()
            || self.gateway_epoch.is_nil()
            || self.sequence == 0
        {
            return Err(PrivateEgressError::InvalidResponse);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| PrivateEgressError::InvalidResponse)?;
        if bytes.len() > MAX_COMMAND_BYTES {
            return Err(PrivateEgressError::InvalidResponse);
        }
        Ok(DataMessage::reliable(
            PRIVATE_EGRESS_LIFECYCLE_ACK_LABEL,
            PRIVATE_EGRESS_CONTENT_TYPE,
            bytes,
        ))
    }

    pub fn from_data_message(message: &DataMessage) -> Result<Self, PrivateEgressError> {
        validate_wire_message(message, PRIVATE_EGRESS_LIFECYCLE_ACK_LABEL)?;
        let ack: Self = serde_json::from_slice(&message.bytes)
            .map_err(|_| PrivateEgressError::InvalidResponse)?;
        if ack.version != PROTOCOL_VERSION
            || ack.event_id.is_nil()
            || ack.gateway_epoch.is_nil()
            || ack.sequence == 0
        {
            return Err(PrivateEgressError::InvalidResponse);
        }
        Ok(ack)
    }
}

/// Route-derived authority. Only a successfully consumed attachment route has
/// both a worker fence and binding generation and can construct this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateEgressRouteAuthority {
    pub worker: WorkerLease,
    pub source: PrivateEgressSource,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PrivateEgressError {
    #[error("private egress command is invalid")]
    InvalidCommand,
    #[error("private egress response is invalid")]
    InvalidResponse,
    #[error("private egress command expired")]
    Expired,
    #[error("private egress route ownership mismatch")]
    OwnershipMismatch,
    #[error("private egress command ID was replayed with different bytes")]
    ReplayConflict,
    #[error("private egress command transition is invalid")]
    InvalidTransition,
    #[error("private egress capacity is exhausted")]
    CapacityExceeded,
    #[error("private egress operation timed out")]
    Timeout,
    #[error("private egress handler rejected the operation")]
    HandlerRejected,
    #[error("private egress runtime is draining")]
    Draining,
    #[error("private egress state store is unavailable")]
    StateUnavailable,
    #[error("private egress gateway epoch is no longer authoritative")]
    DeadEpoch,
    #[error("private egress dead-epoch cleanup failed")]
    DeadEpochRecoveryFailed,
}

impl PrivateEgressError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidCommand => "invalid_command",
            Self::InvalidResponse => "invalid_response",
            Self::Expired => "expired",
            Self::OwnershipMismatch => "ownership_mismatch",
            Self::ReplayConflict => "replay_conflict",
            Self::InvalidTransition => "invalid_transition",
            Self::CapacityExceeded => "capacity_exceeded",
            Self::Timeout => "timeout",
            Self::HandlerRejected => "handler_rejected",
            Self::Draining => "draining",
            Self::StateUnavailable => "state_unavailable",
            Self::DeadEpoch => "dead_epoch",
            Self::DeadEpochRecoveryFailed => "dead_epoch_recovery_failed",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PrivateEgressHandlerResult {
    pub external_reference: Option<String>,
}

/// Gateway-owned signaling/media implementation. It receives only commands
/// that passed physical-route ownership, replay, transition, and capacity
/// checks.
#[async_trait]
pub trait PrivateEgressHandler: Send + Sync {
    async fn execute(
        &self,
        authority: &PrivateEgressRouteAuthority,
        command: &PrivateEgressCommand,
    ) -> Result<PrivateEgressHandlerResult, PrivateEgressError>;

    /// Acknowledge one route fenced from a prior gateway process incarnation.
    /// The default is fail-closed. Implementations may return success only
    /// when they can prove no live process-local signaling/media resource is
    /// reachable; this is intentionally separate from ordinary idempotent End.
    async fn recover_dead_epoch_route(
        &self,
        _authority: &PrivateEgressRouteAuthority,
        _target: PrivateEgressTarget,
        _dead_epoch: Uuid,
    ) -> Result<(), PrivateEgressError> {
        Err(PrivateEgressError::DeadEpochRecoveryFailed)
    }

    /// Observe an adapter-authoritative lifecycle transition after the
    /// command state machine has accepted it. Nonterminal observations are
    /// delivered immediately. Terminal observations are delivered only after
    /// the worker's exact lifecycle ACK has been durably validated, so an
    /// implementation cannot retire the transport that still carries the
    /// event before delivery completes.
    async fn observe_lifecycle(
        &self,
        _authority: &PrivateEgressRouteAuthority,
        _event: &PrivateEgressLifecycleEvent,
    ) {
    }

    /// Drain every process-local route owned by this handler. The command
    /// service invokes this boundary after it has stopped accepting Prepare
    /// commands and has ended its authoritative source routes. Implementors
    /// must remove their route registrations and cancel supervised work even
    /// when `timeout` is exhausted; returning [`PrivateEgressError::Timeout`]
    /// reports that graceful adapter teardown did not finish in time.
    async fn drain(&self, _timeout: Duration) -> Result<(), PrivateEgressError> {
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct PrivateEgressServiceConfig {
    pub max_active_routes: usize,
    pub max_replay_entries: usize,
    pub replay_ttl: Duration,
    pub operation_timeout: Duration,
}

impl Default for PrivateEgressServiceConfig {
    fn default() -> Self {
        Self {
            max_active_routes: 2_000,
            max_replay_entries: 8_192,
            replay_ttl: Duration::from_secs(120),
            operation_timeout: Duration::from_secs(10),
        }
    }
}

impl PrivateEgressServiceConfig {
    fn validate(&self) -> Result<(), PrivateEgressError> {
        if self.max_active_routes == 0
            || self.max_replay_entries == 0
            || self.replay_ttl < MAX_COMMAND_LIFETIME
            || self.operation_timeout.is_zero()
            || self.operation_timeout > Duration::from_secs(30)
        {
            return Err(PrivateEgressError::InvalidCommand);
        }
        Ok(())
    }
}

type RouteKey = PrivateEgressRouteKey;

struct RouteRecord {
    state: PrivateEgressLifecycleState,
    permit: Option<OwnedSemaphorePermit>,
}

struct ReplayRecord {
    digest: [u8; 32],
    created_at: Instant,
    response: Option<PrivateEgressResponse>,
    notify: Arc<Notify>,
}

struct ReplayState {
    entries: HashMap<Uuid, ReplayRecord>,
    completed: VecDeque<Uuid>,
}

struct RouteTombstone {
    key: RouteKey,
    cell: Arc<tokio::sync::Mutex<Option<RouteRecord>>>,
    completed_at: Instant,
}

/// Bounded, replay-safe gateway command state machine.
pub struct PrivateEgressCommandService {
    handler: Arc<dyn PrivateEgressHandler>,
    config: PrivateEgressServiceConfig,
    epoch: PrivateEgressGatewayEpoch,
    state_store: Arc<dyn PrivateEgressStateStore>,
    capacity: Arc<Semaphore>,
    routes: DashMap<RouteKey, Arc<tokio::sync::Mutex<Option<RouteRecord>>>>,
    terminal_routes: Mutex<VecDeque<RouteTombstone>>,
    replay: Mutex<ReplayState>,
    draining: std::sync::atomic::AtomicBool,
}

impl fmt::Debug for PrivateEgressCommandService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateEgressCommandService")
            .field("gateway_id", &self.epoch.gateway_id)
            .field("gateway_epoch", &self.epoch.instance_id)
            .field("durable_state", &self.state_store.is_durable())
            .field("active_routes", &self.routes.len())
            .field(
                "draining",
                &self.draining.load(std::sync::atomic::Ordering::Acquire),
            )
            .finish_non_exhaustive()
    }
}

impl PrivateEgressCommandService {
    pub fn new(
        handler: Arc<dyn PrivateEgressHandler>,
        config: PrivateEgressServiceConfig,
    ) -> Result<Arc<Self>, PrivateEgressError> {
        config.validate()?;
        let epoch = PrivateEgressGatewayEpoch::standalone();
        let memory =
            MemoryPrivateEgressStateStore::new(config.max_replay_entries, config.replay_ttl)?;
        let recovered = memory.activate(&epoch, unix_time_ms());
        debug_assert!(recovered.is_empty());
        Ok(Self::build(handler, config, epoch, memory))
    }

    /// Construct a restart-aware service over an explicitly supplied state
    /// store. The previous instance is fenced before this service can execute
    /// commands; every recovered route is synchronously failed closed.
    pub async fn new_with_state_store(
        handler: Arc<dyn PrivateEgressHandler>,
        config: PrivateEgressServiceConfig,
        epoch: PrivateEgressGatewayEpoch,
        state_store: Arc<dyn PrivateEgressStateStore>,
    ) -> Result<Arc<Self>, PrivateEgressError> {
        config.validate()?;
        let now_ms = unix_time_ms();
        let recovered = state_store.begin_epoch(&epoch, now_ms).await?;
        for recovered in recovered {
            let authority = recovered.key.authority();
            if !matches!(
                tokio::time::timeout(
                    config.operation_timeout,
                    handler.recover_dead_epoch_route(
                        &authority,
                        recovered.key.target,
                        recovered.dead_epoch,
                    ),
                )
                .await,
                Ok(Ok(_))
            ) {
                return Err(PrivateEgressError::DeadEpochRecoveryFailed);
            }
            state_store
                .complete_route_recovery(&epoch, &recovered.key)
                .await
                .map_err(|_| PrivateEgressError::DeadEpochRecoveryFailed)?;
        }
        Ok(Self::build(handler, config, epoch, state_store))
    }

    fn build(
        handler: Arc<dyn PrivateEgressHandler>,
        config: PrivateEgressServiceConfig,
        epoch: PrivateEgressGatewayEpoch,
        state_store: Arc<dyn PrivateEgressStateStore>,
    ) -> Arc<Self> {
        Arc::new(Self {
            handler,
            capacity: Arc::new(Semaphore::new(config.max_active_routes)),
            config,
            epoch,
            state_store,
            routes: DashMap::new(),
            terminal_routes: Mutex::new(VecDeque::new()),
            replay: Mutex::new(ReplayState {
                entries: HashMap::new(),
                completed: VecDeque::new(),
            }),
            draining: std::sync::atomic::AtomicBool::new(false),
        })
    }

    #[must_use]
    pub fn gateway_epoch(&self) -> &PrivateEgressGatewayEpoch {
        &self.epoch
    }

    #[must_use]
    pub fn has_durable_state(&self) -> bool {
        self.state_store.is_durable()
    }

    pub fn begin_drain(&self) {
        self.draining
            .store(true, std::sync::atomic::Ordering::Release);
    }

    #[must_use]
    pub fn active_routes(&self) -> usize {
        self.routes
            .iter()
            .filter(|entry| {
                entry.value().try_lock().is_ok_and(|record| {
                    record.as_ref().is_some_and(|record| {
                        matches!(
                            record.state,
                            PrivateEgressLifecycleState::Prepared
                                | PrivateEgressLifecycleState::Active
                        )
                    })
                })
            })
            .count()
    }

    /// Stop new private-egress admission and synchronously retire all service
    /// and handler routes. This is the process shutdown boundary: callers must
    /// await it while the gateway's private and native transports are still
    /// available for End/Abort and lifecycle delivery.
    pub async fn drain(&self, timeout: Duration) -> Result<(), PrivateEgressError> {
        self.begin_drain();
        let deadline = tokio::time::Instant::now() + timeout;
        let mut authorities = Vec::new();
        for key in self.routes.iter().map(|entry| entry.key().clone()) {
            let authority = key.authority();
            if !authorities.contains(&authority) {
                authorities.push(authority);
            }
        }

        let mut timed_out = false;
        for authority in authorities {
            timed_out |= self.end_source_until(&authority, deadline).await;
        }

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        // The handler drain contract is itself deadline-aware and must always
        // unregister local routes. Do not cancel it at the outer boundary or
        // a forced timeout could strand proxy registrations and pump tasks.
        let handler_result = self.handler.drain(remaining).await;
        let handler_error = match handler_result {
            Ok(()) => None,
            Err(PrivateEgressError::Timeout) => {
                timed_out = true;
                None
            }
            Err(error) => Some(error),
        };

        // Terminal tombstones and any route concurrently made unreachable by
        // forced drain must not retain capacity or appear live after this
        // boundary. In-flight holders own their Arc and will observe drain;
        // removing the authoritative registration prevents resurrection.
        let keys = self
            .routes
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in keys {
            if let Some((_, cell)) = self.routes.remove(&key) {
                if let Ok(mut record) = cell.try_lock() {
                    *record = None;
                }
            }
        }
        self.terminal_routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();

        if let Some(error) = handler_error {
            return Err(error);
        }
        if timed_out || tokio::time::Instant::now() > deadline {
            Err(PrivateEgressError::Timeout)
        } else {
            Ok(())
        }
    }

    pub async fn execute(
        &self,
        authority: PrivateEgressRouteAuthority,
        command: PrivateEgressCommand,
        now_ms: i64,
    ) -> Result<PrivateEgressResponse, PrivateEgressError> {
        self.sweep_terminal_routes();
        command.validate(now_ms)?;
        if command.worker != authority.worker || command.source != authority.source {
            return Err(PrivateEgressError::OwnershipMismatch);
        }
        if matches!(command.operation, PrivateEgressOperation::Prepare { .. })
            && self.routes.len()
                >= self
                    .config
                    .max_active_routes
                    .saturating_add(self.config.max_replay_entries)
        {
            return Err(PrivateEgressError::CapacityExceeded);
        }
        let digest = command.digest()?;
        loop {
            let waiter = {
                let mut replay = self
                    .replay
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                sweep_replay(&mut replay, self.config.replay_ttl);
                if let Some(record) = replay.entries.get(&command.command_id) {
                    if record.digest != digest {
                        metrics::counter!(
                            "bridgefu_private_egress_commands_total",
                            "operation" => operation_name(&command.operation),
                            "outcome" => "replay-conflict"
                        )
                        .increment(1);
                        return Err(PrivateEgressError::ReplayConflict);
                    }
                    if let Some(response) = &record.response {
                        let mut response = response.clone();
                        response.replayed = true;
                        metrics::counter!(
                            "bridgefu_private_egress_commands_total",
                            "operation" => operation_name(&command.operation),
                            "outcome" => "replayed"
                        )
                        .increment(1);
                        return Ok(response);
                    }
                    Some(Arc::clone(&record.notify).notified_owned())
                } else {
                    if replay.entries.len() >= self.config.max_replay_entries {
                        return Err(PrivateEgressError::CapacityExceeded);
                    }
                    replay.entries.insert(
                        command.command_id,
                        ReplayRecord {
                            digest,
                            created_at: Instant::now(),
                            response: None,
                            notify: Arc::new(Notify::new()),
                        },
                    );
                    None
                }
            };
            if let Some(waiter) = waiter {
                tokio::time::timeout(self.config.operation_timeout, waiter)
                    .await
                    .map_err(|_| PrivateEgressError::Timeout)?;
                continue;
            }
            break;
        }

        let durable_claim = self
            .state_store
            .claim_command(&self.epoch, command.command_id, digest, now_ms)
            .await;
        let durable_claim = match durable_claim {
            Ok(claim) => claim,
            Err(error) => {
                let notify = self
                    .replay
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .entries
                    .remove(&command.command_id)
                    .map(|record| record.notify);
                if let Some(notify) = notify {
                    notify.notify_waiters();
                }
                return Err(error);
            }
        };
        match durable_claim {
            PrivateEgressCommandClaim::Acquired => {}
            PrivateEgressCommandClaim::Completed(mut response) => {
                let notify = {
                    let mut replay = self
                        .replay
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let record = replay
                        .entries
                        .get_mut(&command.command_id)
                        .ok_or(PrivateEgressError::StateUnavailable)?;
                    record.response = Some(response.clone());
                    let notify = Arc::clone(&record.notify);
                    replay.completed.push_back(command.command_id);
                    notify
                };
                notify.notify_waiters();
                response.replayed = true;
                return Ok(response);
            }
            PrivateEgressCommandClaim::InFlight => {
                let rejected = PrivateEgressResponse::rejected(
                    command.command_id,
                    PrivateEgressError::StateUnavailable,
                );
                let notify = {
                    let mut replay = self
                        .replay
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let record = replay
                        .entries
                        .get_mut(&command.command_id)
                        .ok_or(PrivateEgressError::StateUnavailable)?;
                    record.response = Some(rejected);
                    let notify = Arc::clone(&record.notify);
                    replay.completed.push_back(command.command_id);
                    notify
                };
                notify.notify_waiters();
                self.begin_drain();
                return Err(PrivateEgressError::StateUnavailable);
            }
        }

        let result = self.execute_once(&authority, &command).await;
        let stored = match result {
            Ok(response) => response,
            Err(error) => PrivateEgressResponse::rejected(command.command_id, error),
        };
        if let Err(error) = self
            .state_store
            .complete_command(
                &self.epoch,
                command.command_id,
                digest,
                &stored,
                unix_time_ms(),
            )
            .await
        {
            self.begin_drain();
            let notify = {
                let mut replay = self
                    .replay
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let record = replay
                    .entries
                    .get_mut(&command.command_id)
                    .ok_or(PrivateEgressError::StateUnavailable)?;
                record.response = Some(PrivateEgressResponse::rejected(command.command_id, error));
                Arc::clone(&record.notify)
            };
            notify.notify_waiters();
            return Err(error);
        }
        let notify = {
            let mut replay = self
                .replay
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let record = replay
                .entries
                .get_mut(&command.command_id)
                .ok_or(PrivateEgressError::InvalidResponse)?;
            record.response = Some(stored.clone());
            let notify = Arc::clone(&record.notify);
            replay.completed.push_back(command.command_id);
            notify
        };
        notify.notify_waiters();
        metrics::counter!(
            "bridgefu_private_egress_commands_total",
            "operation" => operation_name(&command.operation),
            "outcome" => if stored.accepted { "accepted" } else { "rejected" }
        )
        .increment(1);
        metrics::gauge!("bridgefu_private_egress_active_routes").set(self.active_routes() as f64);
        Ok(stored)
    }

    async fn execute_once(
        &self,
        authority: &PrivateEgressRouteAuthority,
        command: &PrivateEgressCommand,
    ) -> Result<PrivateEgressResponse, PrivateEgressError> {
        if self.draining.load(std::sync::atomic::Ordering::Acquire)
            && matches!(command.operation, PrivateEgressOperation::Prepare { .. })
        {
            return Err(PrivateEgressError::Draining);
        }
        self.state_store.assert_epoch(&self.epoch).await?;
        let key = RouteKey::new(command.worker, &command.source, command.target);
        let preparing = matches!(command.operation, PrivateEgressOperation::Prepare { .. });
        let cell = if preparing {
            self.routes
                .entry(key.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(None)))
                .clone()
        } else {
            self.routes
                .get(&key)
                .map(|entry| Arc::clone(entry.value()))
                .ok_or(PrivateEgressError::InvalidTransition)?
        };
        let record = cell.lock().await;
        let expected_state = match &command.operation {
            PrivateEgressOperation::Prepare { .. } if record.is_none() => None,
            PrivateEgressOperation::Activate
                if record.as_ref().is_some_and(|record| {
                    record.state == PrivateEgressLifecycleState::Prepared
                }) =>
            {
                Some(PrivateEgressLifecycleState::Active)
            }
            PrivateEgressOperation::Abort
                if record.as_ref().is_some_and(|record| {
                    record.state == PrivateEgressLifecycleState::Prepared
                }) =>
            {
                Some(PrivateEgressLifecycleState::Ended)
            }
            PrivateEgressOperation::End { .. }
                if record.as_ref().is_some_and(|record| {
                    matches!(
                        record.state,
                        PrivateEgressLifecycleState::Prepared | PrivateEgressLifecycleState::Active
                    )
                }) =>
            {
                Some(PrivateEgressLifecycleState::Ended)
            }
            PrivateEgressOperation::Dtmf { .. } | PrivateEgressOperation::DataMessage { .. }
                if record
                    .as_ref()
                    .is_some_and(|record| record.state == PrivateEgressLifecycleState::Active) =>
            {
                Some(PrivateEgressLifecycleState::Active)
            }
            _ => return Err(PrivateEgressError::InvalidTransition),
        };

        let durable_expected = record.as_ref().map(|record| record.state);
        let durable_next = expected_state.unwrap_or(PrivateEgressLifecycleState::Prepared);
        if let Err(error) = self
            .state_store
            .claim_route_transition(
                &self.epoch,
                &key,
                command.command_id,
                durable_expected,
                durable_next,
            )
            .await
        {
            drop(record);
            if preparing {
                remove_empty_route_cell(&self.routes, &key, &cell);
            }
            return Err(error);
        }

        let permit = if preparing {
            match Arc::clone(&self.capacity).try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    let _ = self
                        .state_store
                        .abort_route_transition(&self.epoch, &key, command.command_id)
                        .await;
                    drop(record);
                    remove_empty_route_cell(&self.routes, &key, &cell);
                    return Err(PrivateEgressError::CapacityExceeded);
                }
            }
        } else {
            None
        };
        // Adapter activation may emit provisional SIP progress before its
        // final command result. Do not hold the process-local route mutex
        // across adapter I/O; the durable pending transition remains the
        // serialization fence while Progress is journaled independently.
        drop(record);
        let handler = tokio::time::timeout(
            self.config.operation_timeout,
            self.handler.execute(authority, command),
        )
        .await;
        let handler = match handler {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                if self
                    .state_store
                    .abort_route_transition(&self.epoch, &key, command.command_id)
                    .await
                    .is_err()
                {
                    self.begin_drain();
                    return Err(PrivateEgressError::StateUnavailable);
                }
                if preparing {
                    remove_empty_route_cell(&self.routes, &key, &cell);
                }
                return Err(error);
            }
            Err(_) => {
                if self
                    .state_store
                    .abort_route_transition(&self.epoch, &key, command.command_id)
                    .await
                    .is_err()
                {
                    self.begin_drain();
                    return Err(PrivateEgressError::StateUnavailable);
                }
                if preparing {
                    remove_empty_route_cell(&self.routes, &key, &cell);
                }
                return Err(PrivateEgressError::Timeout);
            }
        };

        if let Err(error) = self
            .state_store
            .complete_route_transition(
                &self.epoch,
                &key,
                command.command_id,
                durable_next,
                unix_time_ms(),
            )
            .await
        {
            self.begin_drain();
            let cleanup = PrivateEgressCommand {
                version: PROTOCOL_VERSION,
                command_id: Uuid::new_v4(),
                issued_at_ms: unix_time_ms(),
                expires_at_ms: unix_time_ms().saturating_add(5_000),
                worker: command.worker,
                source: command.source.clone(),
                target: command.target,
                operation: PrivateEgressOperation::End {
                    reason: PrivateEgressEndReason::Failed,
                },
            };
            let _ = tokio::time::timeout(
                self.config.operation_timeout,
                self.handler.execute(authority, &cleanup),
            )
            .await;
            if preparing {
                remove_empty_route_cell(&self.routes, &key, &cell);
            }
            return Err(error);
        }

        let mut record = cell.lock().await;
        let local_state_matches = if preparing {
            record.is_none()
        } else {
            record.as_ref().map(|record| record.state) == durable_expected
        };
        if !local_state_matches {
            self.begin_drain();
            return Err(PrivateEgressError::StateUnavailable);
        }
        let state = match &command.operation {
            PrivateEgressOperation::Prepare { .. } => {
                *record = Some(RouteRecord {
                    state: PrivateEgressLifecycleState::Prepared,
                    permit: Some(permit.expect("prepare reserved a permit")),
                });
                PrivateEgressLifecycleState::Prepared
            }
            PrivateEgressOperation::Activate => {
                record.as_mut().expect("validated route").state =
                    PrivateEgressLifecycleState::Active;
                PrivateEgressLifecycleState::Active
            }
            PrivateEgressOperation::Abort | PrivateEgressOperation::End { .. } => {
                let record = record.as_mut().expect("validated route");
                record.state = PrivateEgressLifecycleState::Ended;
                record.permit.take();
                PrivateEgressLifecycleState::Ended
            }
            PrivateEgressOperation::Dtmf { .. } | PrivateEgressOperation::DataMessage { .. } => {
                expected_state.expect("validated active command retains active state")
            }
        };
        drop(record);
        if state == PrivateEgressLifecycleState::Ended {
            self.retain_terminal_route(key, Arc::clone(&cell));
        }
        Ok(PrivateEgressResponse {
            version: PROTOCOL_VERSION,
            command_id: command.command_id,
            accepted: true,
            replayed: false,
            state: Some(state),
            failure_code: None,
            external_reference: handler.external_reference,
        })
    }

    /// Fail closed when the authenticated source route disappears. Every
    /// registered destination owned by that exact worker fence and source
    /// attachment generation is ended once, including a terminal route still
    /// waiting for its lifecycle ACK. Capacity is released even if gateway
    /// adapter cleanup reports an error.
    pub async fn end_source(&self, authority: &PrivateEgressRouteAuthority) {
        let deadline = tokio::time::Instant::now() + self.config.operation_timeout;
        let _ = self.end_source_until(authority, deadline).await;
    }

    async fn end_source_until(
        &self,
        authority: &PrivateEgressRouteAuthority,
        deadline: tokio::time::Instant,
    ) -> bool {
        let mut timed_out = false;
        let mut keys = match tokio::time::timeout_at(
            deadline,
            self.state_store
                .fail_source(&self.epoch, authority, unix_time_ms()),
        )
        .await
        {
            Ok(Ok(keys)) => keys,
            Ok(Err(_)) => {
                self.begin_drain();
                Vec::new()
            }
            Err(_) => {
                self.begin_drain();
                timed_out = true;
                Vec::new()
            }
        };
        for local in self
            .routes
            .iter()
            .filter(|entry| {
                let key = entry.key();
                key.worker == authority.worker
                    && key.tenant_id == authority.source.tenant_id
                    && key.call_id == authority.source.call_id
                    && key.source_leg_id == authority.source.leg_id
                    && key.source_binding_generation == authority.source.binding_generation
            })
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>()
        {
            if !keys.contains(&local) {
                keys.push(local);
            }
        }
        for key in keys {
            let cell = self.routes.get(&key).map(|entry| Arc::clone(entry.value()));
            let mut record = match &cell {
                Some(cell) => Some(cell.lock().await),
                None => None,
            };
            // A terminal state can still own a live proxy/private route until
            // its lifecycle event is ACKed. If the source disappears first,
            // there can be no later ACK on that route, so source cleanup must
            // explicitly retire it just like Prepared or Active state.
            let needs_end = record
                .as_ref()
                .is_none_or(|record| record.as_ref().is_some());
            if needs_end {
                let now_ms = unix_time_ms();
                let command = PrivateEgressCommand {
                    version: PROTOCOL_VERSION,
                    command_id: Uuid::new_v4(),
                    issued_at_ms: now_ms,
                    expires_at_ms: now_ms.saturating_add(5_000),
                    worker: authority.worker,
                    source: authority.source.clone(),
                    target: key.target,
                    operation: PrivateEgressOperation::End {
                        reason: PrivateEgressEndReason::Cancelled,
                    },
                };
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    timed_out = true;
                } else {
                    let operation_timeout = self.config.operation_timeout.min(remaining);
                    if tokio::time::timeout(
                        operation_timeout,
                        self.handler.execute(authority, &command),
                    )
                    .await
                    .is_err()
                    {
                        timed_out = true;
                    }
                }
            }
            if let Some(record) = record.as_mut() {
                **record = None;
            }
            drop(record);
            if let Some(cell) = cell {
                self.routes
                    .remove_if(&key, |_, candidate| Arc::ptr_eq(candidate, &cell));
            }
        }
        timed_out
    }

    /// Apply an adapter-authoritative asynchronous lifecycle transition before
    /// it is sent to the worker. A late event for an old target generation or
    /// source attachment cannot retire the current route.
    pub async fn record_lifecycle(
        &self,
        authority: &PrivateEgressRouteAuthority,
        event: &PrivateEgressLifecycleEvent,
    ) -> Result<PrivateEgressLifecycleEvent, PrivateEgressError> {
        if event.worker != authority.worker || event.source != authority.source {
            return Err(PrivateEgressError::OwnershipMismatch);
        }
        let key = RouteKey::new(event.worker, &event.source, event.target);
        let cell = self
            .routes
            .get(&key)
            .map(|entry| Arc::clone(entry.value()))
            .ok_or(PrivateEgressError::InvalidTransition)?;
        let mut record = cell.lock().await;
        let current = record
            .as_mut()
            .ok_or(PrivateEgressError::InvalidTransition)?;
        let allowed = match &event.kind {
            PrivateEgressLifecycleKind::Progress { .. } => {
                current.state == PrivateEgressLifecycleState::Prepared
            }
            PrivateEgressLifecycleKind::State { state, .. } => matches!(
                (current.state, *state),
                (
                    PrivateEgressLifecycleState::Prepared,
                    PrivateEgressLifecycleState::Prepared
                        | PrivateEgressLifecycleState::Active
                        | PrivateEgressLifecycleState::Ended
                        | PrivateEgressLifecycleState::Failed
                ) | (
                    PrivateEgressLifecycleState::Active,
                    PrivateEgressLifecycleState::Active
                        | PrivateEgressLifecycleState::Ended
                        | PrivateEgressLifecycleState::Failed
                )
            ),
        };
        if !allowed {
            return Err(PrivateEgressError::InvalidTransition);
        }
        let stamped = self
            .state_store
            .append_lifecycle(&self.epoch, &key, event, unix_time_ms())
            .await?;
        let terminal = stamped.state().is_some_and(|state| {
            matches!(
                state,
                PrivateEgressLifecycleState::Ended | PrivateEgressLifecycleState::Failed
            )
        });
        if let Some(state) = stamped.state() {
            current.state = state;
            if terminal {
                current.permit.take();
            }
        }
        drop(record);
        // A terminal adapter event still has to traverse the authoritative
        // source route and receive an exact durable ACK. Retiring the proxy
        // here closes its private media route before that exchange finishes
        // and can make a real remote hangup permanently unacknowledgeable.
        // Nonterminal observations do not release transport state and retain
        // their existing immediate delivery semantics.
        if !terminal {
            self.handler.observe_lifecycle(authority, &stamped).await;
        }
        if terminal {
            self.retain_terminal_route(key, cell);
        }
        Ok(stamped)
    }

    pub async fn acknowledge_lifecycle(
        &self,
        authority: &PrivateEgressRouteAuthority,
        ack: &PrivateEgressLifecycleAck,
    ) -> Result<(), PrivateEgressError> {
        if ack.worker != authority.worker
            || ack.source != authority.source
            || ack.gateway_epoch != self.epoch.instance_id
        {
            return Err(PrivateEgressError::OwnershipMismatch);
        }
        let key = RouteKey::new(ack.worker, &ack.source, ack.target);
        // Capture the exact still-unacknowledged event before marking it
        // durable. A replayed ACK remains idempotent (the event is no longer
        // in this set), while the state store remains the final authority for
        // event ID, route, epoch, and sequence validation.
        let terminal = self
            .state_store
            .unacked_lifecycle(&self.epoch, &key)
            .await?
            .into_iter()
            .find(|event| event.event_id == ack.event_id && event.sequence == ack.sequence)
            .filter(lifecycle_is_terminal);
        self.state_store
            .ack_lifecycle(&self.epoch, &key, ack.event_id, ack.sequence)
            .await?;
        if let Some(event) = terminal {
            // Cleanup is deliberately after the durable ACK. The handler is
            // exact-generation and idempotent, so concurrent duplicate ACKs
            // can never retire a replacement route.
            self.handler.observe_lifecycle(authority, &event).await;
        }
        Ok(())
    }

    pub async fn unacked_lifecycle(
        &self,
        authority: &PrivateEgressRouteAuthority,
        target: PrivateEgressTarget,
    ) -> Result<Vec<PrivateEgressLifecycleEvent>, PrivateEgressError> {
        let key = RouteKey::new(authority.worker, &authority.source, target);
        self.state_store.unacked_lifecycle(&self.epoch, &key).await
    }

    fn retain_terminal_route(
        &self,
        key: RouteKey,
        cell: Arc<tokio::sync::Mutex<Option<RouteRecord>>>,
    ) {
        let mut terminal = self
            .terminal_routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        terminal.push_back(RouteTombstone {
            key,
            cell,
            completed_at: Instant::now(),
        });
        sweep_terminal_routes(&self.routes, &mut terminal, self.config.replay_ttl);
    }

    fn sweep_terminal_routes(&self) {
        let mut terminal = self
            .terminal_routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        sweep_terminal_routes(&self.routes, &mut terminal, self.config.replay_ttl);
    }
}

fn remove_empty_route_cell(
    routes: &DashMap<RouteKey, Arc<tokio::sync::Mutex<Option<RouteRecord>>>>,
    key: &RouteKey,
    cell: &Arc<tokio::sync::Mutex<Option<RouteRecord>>>,
) {
    routes.remove_if(key, |_, candidate| {
        Arc::ptr_eq(candidate, cell)
            && Arc::strong_count(candidate) == 2
            && candidate.try_lock().is_ok_and(|record| record.is_none())
    });
}

fn unix_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or_default()
}

fn sweep_replay(state: &mut ReplayState, ttl: Duration) {
    let now = Instant::now();
    while let Some(command_id) = state.completed.front().copied() {
        let expired = state.entries.get(&command_id).is_none_or(|record| {
            record.response.is_some() && now.saturating_duration_since(record.created_at) >= ttl
        });
        if !expired {
            break;
        }
        state.completed.pop_front();
        state.entries.remove(&command_id);
    }
}

fn sweep_terminal_routes(
    routes: &DashMap<RouteKey, Arc<tokio::sync::Mutex<Option<RouteRecord>>>>,
    terminal: &mut VecDeque<RouteTombstone>,
    ttl: Duration,
) {
    let now = Instant::now();
    loop {
        let should_remove = terminal
            .front()
            .is_some_and(|record| now.saturating_duration_since(record.completed_at) >= ttl);
        if !should_remove {
            break;
        }
        let record = terminal.pop_front().expect("front was present");
        routes.remove_if(&record.key, |_, candidate| {
            Arc::ptr_eq(candidate, &record.cell)
        });
    }
}

fn validate_wire_message(
    message: &DataMessage,
    expected_label: &str,
) -> Result<(), PrivateEgressError> {
    message
        .validate()
        .map_err(|_| PrivateEgressError::InvalidCommand)?;
    if message.label != expected_label
        || message.content_type != PRIVATE_EGRESS_CONTENT_TYPE
        || message.reliability != DataReliability::ReliableOrdered
        || message.bytes.len() > MAX_COMMAND_BYTES
    {
        return Err(PrivateEgressError::InvalidCommand);
    }
    Ok(())
}

fn validate_operation(operation: &PrivateEgressOperation) -> Result<(), PrivateEgressError> {
    match operation {
        PrivateEgressOperation::Prepare {
            transport,
            profile,
            codec,
            target,
            initial_context,
        } => {
            let target_ok = !target.is_empty()
                && target.len() <= MAX_TARGET_BYTES
                && !target.chars().any(char::is_control)
                && match transport {
                    PrivateEgressTransport::Sip => {
                        target.starts_with("sip:") || target.starts_with("sips:")
                    }
                    PrivateEgressTransport::WebRtc => target.starts_with("wss://"),
                };
            let profile_ok = valid_component(&profile.profile_id, MAX_PROFILE_ID_BYTES)
                && valid_component(&profile.revision, MAX_PROFILE_REVISION_BYTES);
            let codec_ok = !codec.name.is_empty()
                && codec.name.len() <= 64
                && codec.clock_rate_hz > 0
                && (1..=2).contains(&codec.channels)
                && codec
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
            let context_ok = initial_context.len() <= MAX_CONTEXT_ENTRIES
                && initial_context.iter().all(|(name, value)| {
                    valid_component(name, MAX_CONTEXT_NAME_BYTES)
                        && value.len() <= MAX_CONTEXT_VALUE_BYTES
                        && !value.chars().any(char::is_control)
                });
            if !target_ok || !profile_ok || !codec_ok || !context_ok {
                return Err(PrivateEgressError::InvalidCommand);
            }
        }
        PrivateEgressOperation::Dtmf {
            digits,
            duration_ms,
        } => {
            if digits.is_empty()
                || digits.len() > 32
                || !(40..=6_000).contains(duration_ms)
                || !digits.bytes().all(|digit| {
                    digit.is_ascii_digit()
                        || matches!(digit, b'*' | b'#' | b'A'..=b'D' | b'a'..=b'd')
                })
            {
                return Err(PrivateEgressError::InvalidCommand);
            }
        }
        PrivateEgressOperation::DataMessage { message } => {
            message
                .validate()
                .map_err(|_| PrivateEgressError::InvalidCommand)?;
            if message.reliability != DataReliability::ReliableOrdered
                || is_private_egress_label(&message.label)
            {
                return Err(PrivateEgressError::InvalidCommand);
            }
        }
        PrivateEgressOperation::Activate
        | PrivateEgressOperation::Abort
        | PrivateEgressOperation::End { .. } => {}
    }
    Ok(())
}

fn valid_component(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

const fn operation_name(operation: &PrivateEgressOperation) -> &'static str {
    match operation {
        PrivateEgressOperation::Prepare { .. } => "prepare",
        PrivateEgressOperation::Activate => "activate",
        PrivateEgressOperation::Abort => "abort",
        PrivateEgressOperation::End { .. } => "end",
        PrivateEgressOperation::Dtmf { .. } => "dtmf",
        PrivateEgressOperation::DataMessage { .. } => "data-message",
    }
}

struct PendingResponse {
    source_connection: ConnectionId,
    source: PrivateEgressSource,
    response: oneshot::Sender<Result<PrivateEgressResponse, PrivateEgressError>>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct LifecycleReceiptKey {
    source: PrivateEgressSource,
    target: PrivateEgressTarget,
}

struct LifecycleReceipt {
    gateway_epoch: Uuid,
    last_sequence: u64,
    recent: VecDeque<(u64, Uuid)>,
    completed_at: Option<Instant>,
}

struct PrivateEgressStagedControlInner {
    source_connection: ConnectionId,
    source: PrivateEgressSource,
    sender: StagedInboundDataSender,
    cancel: CancellationToken,
    task: Mutex<Option<JoinHandle<()>>>,
}

struct StagedControlOutcome {
    ack: Option<DataMessage>,
    lifecycle: Option<PrivateEgressLifecycleDelivery>,
}

impl Drop for PrivateEgressStagedControlInner {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self
            .task
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            task.abort();
        }
    }
}

/// Exact, admission-generation-bound private control path used only while a
/// source attachment is waiting for its final signaling answer. The ordinary
/// published DataMessage path remains authoritative after admission.
#[derive(Clone)]
pub struct PrivateEgressStagedControl {
    inner: Arc<PrivateEgressStagedControlInner>,
}

impl fmt::Debug for PrivateEgressStagedControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateEgressStagedControl")
            .field("source_connection", &self.inner.source_connection)
            .field("source", &self.inner.source)
            .finish_non_exhaustive()
    }
}

impl PrivateEgressStagedControl {
    fn matches(&self, connection_id: &ConnectionId, source: &PrivateEgressSource) -> bool {
        self.inner.source_connection == *connection_id && self.inner.source == *source
    }

    async fn send(&self, message: DataMessage) -> rvoip_core::Result<()> {
        self.inner.sender.send(message).await
    }
}

#[derive(Clone, Debug)]
pub struct PrivateEgressLifecycleDelivery {
    pub source_connection: ConnectionId,
    pub event: PrivateEgressLifecycleEvent,
}

/// Worker-side bounded client for the authenticated command path. It sends on
/// an existing private UCTP attachment Connection and accepts a reply only on
/// that same Connection. Constructing a command does not make a new network
/// route or select a gateway.
pub struct PrivateEgressControlClient {
    orchestrator: Arc<Orchestrator>,
    worker: WorkerLease,
    timeout: Duration,
    capacity: Arc<Semaphore>,
    pending: DashMap<Uuid, PendingResponse>,
    lifecycle_receipts: DashMap<LifecycleReceiptKey, LifecycleReceipt>,
    lifecycle_receipt_capacity: usize,
    lifecycle: broadcast::Sender<PrivateEgressLifecycleDelivery>,
    draining: AtomicBool,
    cancel: CancellationToken,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl fmt::Debug for PrivateEgressControlClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateEgressControlClient")
            .field("worker", &self.worker)
            .field("pending", &self.pending.len())
            .field("draining", &self.draining.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl PrivateEgressControlClient {
    pub fn start(
        orchestrator: Arc<Orchestrator>,
        worker: WorkerLease,
        max_pending_commands: usize,
        timeout: Duration,
    ) -> Result<Arc<Self>, PrivateEgressError> {
        Self::start_inner(orchestrator, worker, max_pending_commands, timeout, true)
    }

    /// Construct a client whose replies and lifecycle messages are fed from
    /// the call supervisor's authoritative operational stream.
    pub fn start_authoritative(
        orchestrator: Arc<Orchestrator>,
        worker: WorkerLease,
        max_pending_commands: usize,
        timeout: Duration,
    ) -> Result<Arc<Self>, PrivateEgressError> {
        Self::start_inner(orchestrator, worker, max_pending_commands, timeout, false)
    }

    fn start_inner(
        orchestrator: Arc<Orchestrator>,
        worker: WorkerLease,
        max_pending_commands: usize,
        timeout: Duration,
        compatibility_event_pump: bool,
    ) -> Result<Arc<Self>, PrivateEgressError> {
        if max_pending_commands == 0
            || timeout.is_zero()
            || timeout > Duration::from_secs(30)
            || tokio::runtime::Handle::try_current().is_err()
        {
            return Err(PrivateEgressError::InvalidCommand);
        }
        let (lifecycle, _) = broadcast::channel(max_pending_commands.min(4_096));
        let client = Arc::new(Self {
            orchestrator,
            worker,
            timeout,
            capacity: Arc::new(Semaphore::new(max_pending_commands)),
            pending: DashMap::new(),
            lifecycle_receipts: DashMap::new(),
            lifecycle_receipt_capacity: max_pending_commands.min(4_096),
            lifecycle,
            draining: AtomicBool::new(false),
            cancel: CancellationToken::new(),
            task: Mutex::new(None),
        });
        if compatibility_event_pump {
            client.spawn_event_pump();
        }
        Ok(client)
    }

    #[must_use]
    pub const fn worker(&self) -> WorkerLease {
        self.worker
    }

    fn spawn_event_pump(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let cancel = self.cancel.clone();
        let mut events = self.orchestrator.subscribe_events();
        let task = tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    _ = cancel.cancelled() => break,
                    event = events.recv() => match event {
                        Ok(event) => event,
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => break,
                    },
                };
                let Some(client) = Weak::upgrade(&weak) else {
                    break;
                };
                client.handle_event(event);
            }
            if let Some(client) = Weak::upgrade(&weak) {
                client.fail_pending(PrivateEgressError::HandlerRejected);
            }
        });
        *self
            .task
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(task);
    }

    fn handle_event(&self, event: Event) {
        let Event::DataMessageReceived {
            connection_id,
            message,
            ..
        } = event
        else {
            return;
        };
        self.handle_data_message(&connection_id, &message);
    }

    /// Consume only reserved private-egress DataMessages from the
    /// authoritative stream. Returning true tells the call supervisor not to
    /// expose the reserved envelope to ordinary call context handling.
    pub fn handle_operational_event(&self, event: &OperationalEvent) -> bool {
        let OperationalEventKind::DataMessage { message } = &event.kind else {
            return false;
        };
        self.handle_data_message(&event.connection_id, message)
    }

    fn handle_data_message(&self, connection_id: &ConnectionId, message: &DataMessage) -> bool {
        if message.label == PRIVATE_EGRESS_RESPONSE_LABEL {
            let Ok(response) = PrivateEgressResponse::from_data_message(message) else {
                return true;
            };
            let matching = self
                .pending
                .get(&response.command_id)
                .is_some_and(|pending| pending.source_connection == *connection_id);
            if matching {
                if let Some((_, pending)) = self.pending.remove(&response.command_id) {
                    let _ = pending.response.send(Ok(response));
                }
            }
            return true;
        }
        if message.label == PRIVATE_EGRESS_LIFECYCLE_LABEL {
            let Ok(event) = PrivateEgressLifecycleEvent::from_data_message(message) else {
                return true;
            };
            if event.worker == self.worker
                && self
                    .orchestrator
                    .connection_principal(connection_id)
                    .ok()
                    .and_then(|principal| principal.tenant)
                    .as_deref()
                    == Some(event.source.tenant_id.as_str())
            {
                let accepted = self.accept_lifecycle(&event);
                if let Ok(is_new) = accepted {
                    let lifecycle = is_new.then(|| PrivateEgressLifecycleDelivery {
                        source_connection: connection_id.clone(),
                        event: event.clone(),
                    });
                    if let Ok(ack) = PrivateEgressLifecycleAck::from_event(&event)
                        .and_then(|ack| ack.to_data_message())
                    {
                        let ack_diagnostic =
                            PrivateEgressLifecycleAck::from_data_message(&ack).ok();
                        let orchestrator = Arc::clone(&self.orchestrator);
                        let lifecycle_sender = self.lifecycle.clone();
                        let connection_id = connection_id.clone();
                        let timeout = self.timeout;
                        tokio::spawn(async move {
                            if matches!(
                                tokio::time::timeout(
                                    timeout,
                                    orchestrator.send_data_message(connection_id.clone(), ack),
                                )
                                .await,
                                Ok(Ok(()))
                            ) {
                                if let Some(ack) = ack_diagnostic {
                                    tracing::debug!(
                                        ack_path = "active",
                                        event_id = %ack.event_id,
                                        source_generation = ?ack.source.binding_generation,
                                        target_generation = ?ack.target.binding_generation,
                                        "worker dispatched private-egress lifecycle ACK before publication"
                                    );
                                }
                                if let Some(lifecycle) = lifecycle {
                                    let _ = lifecycle_sender.send(lifecycle);
                                }
                            } else {
                                if let Some(ack) = ack_diagnostic {
                                    tracing::warn!(
                                        ack_path = "active",
                                        event_id = %ack.event_id,
                                        source_generation = ?ack.source.binding_generation,
                                        target_generation = ?ack.target.binding_generation,
                                        "worker failed to dispatch private-egress lifecycle ACK"
                                    );
                                }
                                let _ = orchestrator
                                    .end_connection(
                                        connection_id,
                                        EndReason::Failed {
                                            detail: "private egress lifecycle ack failed".into(),
                                        },
                                    )
                                    .await;
                            }
                        });
                    } else {
                        let orchestrator = Arc::clone(&self.orchestrator);
                        let connection_id = connection_id.clone();
                        tokio::spawn(async move {
                            let _ = orchestrator
                                .end_connection(
                                    connection_id,
                                    EndReason::Failed {
                                        detail: "invalid private egress lifecycle ack".into(),
                                    },
                                )
                                .await;
                        });
                    }
                } else {
                    let orchestrator = Arc::clone(&self.orchestrator);
                    let connection_id = connection_id.clone();
                    tokio::spawn(async move {
                        let _ = orchestrator
                            .end_connection(
                                connection_id,
                                EndReason::Failed {
                                    detail: "invalid private egress lifecycle sequence".into(),
                                },
                            )
                            .await;
                    });
                }
            }
            return true;
        }
        false
    }

    fn accept_lifecycle(
        &self,
        event: &PrivateEgressLifecycleEvent,
    ) -> Result<bool, PrivateEgressError> {
        self.lifecycle_receipts.retain(|_, receipt| {
            receipt
                .completed_at
                .is_none_or(|completed| completed.elapsed() < Duration::from_secs(120))
        });
        let key = LifecycleReceiptKey {
            source: event.source.clone(),
            target: event.target,
        };
        let at_capacity = self.lifecycle_receipts.len() >= self.lifecycle_receipt_capacity;
        match self.lifecycle_receipts.entry(key) {
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                if event.sequence != 1 || at_capacity {
                    return Err(PrivateEgressError::InvalidResponse);
                }
                entry.insert(LifecycleReceipt {
                    gateway_epoch: event.gateway_epoch,
                    last_sequence: 1,
                    recent: VecDeque::from([(1, event.event_id)]),
                    completed_at: lifecycle_is_terminal(event).then(Instant::now),
                });
                Ok(true)
            }
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                let receipt = entry.get_mut();
                if receipt.gateway_epoch != event.gateway_epoch {
                    return Err(PrivateEgressError::DeadEpoch);
                }
                if event.sequence == receipt.last_sequence.saturating_add(1) {
                    receipt.last_sequence = event.sequence;
                    receipt.recent.push_back((event.sequence, event.event_id));
                    while receipt.recent.len() > 64 {
                        receipt.recent.pop_front();
                    }
                    if lifecycle_is_terminal(event) {
                        receipt.completed_at = Some(Instant::now());
                    }
                    return Ok(true);
                }
                if event.sequence <= receipt.last_sequence
                    && receipt
                        .recent
                        .iter()
                        .any(|seen| *seen == (event.sequence, event.event_id))
                {
                    return Ok(false);
                }
                Err(PrivateEgressError::InvalidResponse)
            }
        }
    }

    /// Bind the reserved pre-answer channel to one exact consumed source
    /// attachment. Messages received here are never published as ordinary
    /// rvoip events; malformed, replayed, or cross-source traffic tears down
    /// the still-pending connection.
    pub fn attach_staged_control(
        self: &Arc<Self>,
        source_connection: ConnectionId,
        source: PrivateEgressSource,
        sender: StagedInboundDataSender,
        mut receiver: StagedInboundDataReceiver,
    ) -> Result<PrivateEgressStagedControl, PrivateEgressError> {
        if sender.connection_id() != &source_connection
            || self
                .orchestrator
                .connection_transport(&source_connection)
                .ok()
                != Some(Transport::Quic)
            || self
                .orchestrator
                .connection_principal(&source_connection)
                .ok()
                .and_then(|principal| principal.tenant)
                .as_deref()
                != Some(source.tenant_id.as_str())
        {
            return Err(PrivateEgressError::OwnershipMismatch);
        }
        let inner = Arc::new(PrivateEgressStagedControlInner {
            source_connection: source_connection.clone(),
            source: source.clone(),
            sender,
            cancel: CancellationToken::new(),
            task: Mutex::new(None),
        });
        let weak_client = Arc::downgrade(self);
        let cancel = inner.cancel.clone();
        let ack_sender = inner.sender.clone();
        let task_connection = source_connection;
        let task_source = source;
        let task = tokio::spawn(async move {
            loop {
                let message = tokio::select! {
                    _ = cancel.cancelled() => break,
                    message = receiver.recv() => match message {
                        Some(message) => message,
                        None => break,
                    },
                };
                let Some(client) = weak_client.upgrade() else {
                    break;
                };
                let handled =
                    client.handle_staged_data_message(&task_connection, &task_source, &message);
                let outcome = match handled {
                    Ok(outcome) => outcome,
                    Err(_) => {
                        client.fail_pending_for_source(
                            &task_connection,
                            &task_source,
                            PrivateEgressError::HandlerRejected,
                        );
                        let _ = client
                            .orchestrator
                            .end_connection(
                                task_connection.clone(),
                                EndReason::Failed {
                                    detail: "invalid staged private egress control".into(),
                                },
                            )
                            .await;
                        break;
                    }
                };
                if let Some(ack) = outcome.ack {
                    let ack_diagnostic = PrivateEgressLifecycleAck::from_data_message(&ack).ok();
                    if !matches!(
                        tokio::time::timeout(client.timeout, ack_sender.send(ack)).await,
                        Ok(Ok(()))
                    ) {
                        if let Some(ack) = ack_diagnostic {
                            tracing::warn!(
                                ack_path = "staged",
                                event_id = %ack.event_id,
                                source_generation = ?ack.source.binding_generation,
                                target_generation = ?ack.target.binding_generation,
                                "worker failed to dispatch staged private-egress lifecycle ACK"
                            );
                        }
                        let _ = client
                            .orchestrator
                            .end_connection(
                                task_connection.clone(),
                                EndReason::Failed {
                                    detail: "staged private egress lifecycle ack failed".into(),
                                },
                            )
                            .await;
                        break;
                    }
                    if let Some(ack) = ack_diagnostic {
                        tracing::debug!(
                            ack_path = "staged",
                            event_id = %ack.event_id,
                            source_generation = ?ack.source.binding_generation,
                            target_generation = ?ack.target.binding_generation,
                            "worker dispatched staged private-egress lifecycle ACK before publication"
                        );
                    }
                }
                if let Some(lifecycle) = outcome.lifecycle {
                    let _ = client.lifecycle.send(lifecycle);
                }
            }
        });
        *inner
            .task
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(task);
        Ok(PrivateEgressStagedControl { inner })
    }

    fn handle_staged_data_message(
        &self,
        connection_id: &ConnectionId,
        source: &PrivateEgressSource,
        message: &DataMessage,
    ) -> Result<StagedControlOutcome, PrivateEgressError> {
        match message.label.as_str() {
            PRIVATE_EGRESS_RESPONSE_LABEL => {
                let response = PrivateEgressResponse::from_data_message(message)?;
                let matching = self
                    .pending
                    .get(&response.command_id)
                    .is_some_and(|pending| {
                        pending.source_connection == *connection_id && pending.source == *source
                    });
                if !matching {
                    return Err(PrivateEgressError::ReplayConflict);
                }
                let Some((_, pending)) = self.pending.remove(&response.command_id) else {
                    return Err(PrivateEgressError::ReplayConflict);
                };
                let _ = pending.response.send(Ok(response));
                Ok(StagedControlOutcome {
                    ack: None,
                    lifecycle: None,
                })
            }
            PRIVATE_EGRESS_LIFECYCLE_LABEL => {
                let event = PrivateEgressLifecycleEvent::from_data_message(message)?;
                if event.worker != self.worker
                    || event.source != *source
                    || self
                        .orchestrator
                        .connection_principal(connection_id)
                        .ok()
                        .and_then(|principal| principal.tenant)
                        .as_deref()
                        != Some(source.tenant_id.as_str())
                {
                    return Err(PrivateEgressError::OwnershipMismatch);
                }
                let is_new = self.accept_lifecycle(&event)?;
                let lifecycle = is_new.then(|| PrivateEgressLifecycleDelivery {
                    source_connection: connection_id.clone(),
                    event: event.clone(),
                });
                let ack = PrivateEgressLifecycleAck::from_event(&event)
                    .and_then(|ack| ack.to_data_message())
                    .map(Some)?;
                Ok(StagedControlOutcome { ack, lifecycle })
            }
            _ => Err(PrivateEgressError::InvalidResponse),
        }
    }

    pub fn subscribe_lifecycle(&self) -> broadcast::Receiver<PrivateEgressLifecycleDelivery> {
        self.lifecycle.subscribe()
    }

    pub fn begin_drain(&self) {
        self.draining.store(true, Ordering::Release);
    }

    pub async fn execute(
        &self,
        source_connection: ConnectionId,
        command: PrivateEgressCommand,
    ) -> Result<PrivateEgressResponse, PrivateEgressError> {
        self.execute_with_staged(source_connection, None, command)
            .await
    }

    /// Execute on the exact staged channel while admission is pending, then
    /// fall back to the ordinary published route once rvoip revokes staging
    /// during final-answer promotion.
    pub async fn execute_with_staged(
        &self,
        source_connection: ConnectionId,
        staged: Option<&PrivateEgressStagedControl>,
        command: PrivateEgressCommand,
    ) -> Result<PrivateEgressResponse, PrivateEgressError> {
        if self.draining.load(Ordering::Acquire)
            && matches!(command.operation, PrivateEgressOperation::Prepare { .. })
        {
            return Err(PrivateEgressError::Draining);
        }
        command.validate(unix_time_ms())?;
        if command.worker != self.worker
            || self
                .orchestrator
                .connection_transport(&source_connection)
                .ok()
                != Some(Transport::Quic)
            || self
                .orchestrator
                .connection_principal(&source_connection)
                .ok()
                .and_then(|principal| principal.tenant)
                .as_deref()
                != Some(command.source.tenant_id.as_str())
        {
            return Err(PrivateEgressError::OwnershipMismatch);
        }
        let _permit = Arc::clone(&self.capacity)
            .try_acquire_owned()
            .map_err(|_| PrivateEgressError::CapacityExceeded)?;
        let (response, received) = oneshot::channel();
        match self.pending.entry(command.command_id) {
            dashmap::mapref::entry::Entry::Occupied(_) => {
                return Err(PrivateEgressError::ReplayConflict)
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(PendingResponse {
                    source_connection: source_connection.clone(),
                    source: command.source.clone(),
                    response,
                });
            }
        }
        let message = match command.to_data_message() {
            Ok(message) => message,
            Err(error) => {
                self.pending.remove(&command.command_id);
                return Err(error);
            }
        };
        if staged.is_some_and(|staged| !staged.matches(&source_connection, &command.source)) {
            self.pending.remove(&command.command_id);
            return Err(PrivateEgressError::OwnershipMismatch);
        }
        let staged_sent = if let Some(staged) = staged {
            matches!(
                tokio::time::timeout(self.timeout, staged.send(message.clone())).await,
                Ok(Ok(()))
            )
        } else {
            false
        };
        let sent = if staged_sent {
            Ok(Ok(()))
        } else {
            tokio::time::timeout(
                self.timeout,
                self.orchestrator
                    .send_data_message(source_connection, message),
            )
            .await
        };
        if !matches!(sent, Ok(Ok(()))) {
            self.pending.remove(&command.command_id);
            return Err(if sent.is_err() {
                PrivateEgressError::Timeout
            } else {
                PrivateEgressError::HandlerRejected
            });
        }
        match tokio::time::timeout(self.timeout, received).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(PrivateEgressError::HandlerRejected),
            Err(_) => {
                self.pending.remove(&command.command_id);
                Err(PrivateEgressError::Timeout)
            }
        }
    }

    fn fail_pending(&self, error: PrivateEgressError) {
        let ids = self
            .pending
            .iter()
            .map(|entry| *entry.key())
            .collect::<Vec<_>>();
        for id in ids {
            if let Some((_, pending)) = self.pending.remove(&id) {
                let _ = pending.response.send(Err(error));
            }
        }
    }

    fn fail_pending_for_source(
        &self,
        connection_id: &ConnectionId,
        source: &PrivateEgressSource,
        error: PrivateEgressError,
    ) {
        let ids = self
            .pending
            .iter()
            .filter(|entry| entry.source_connection == *connection_id && entry.source == *source)
            .map(|entry| *entry.key())
            .collect::<Vec<_>>();
        for id in ids {
            if let Some((_, pending)) = self.pending.remove(&id) {
                let _ = pending.response.send(Err(error));
            }
        }
    }

    pub async fn shutdown(&self) {
        self.begin_drain();
        self.cancel.cancel();
        self.fail_pending(PrivateEgressError::Draining);
        let task = self
            .task
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(mut task) = task {
            if tokio::time::timeout(self.timeout, &mut task).await.is_err() {
                task.abort();
                let _ = task.await;
            }
        }
    }
}

impl Drop for PrivateEgressControlClient {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct RecordingHandler {
        calls: AtomicUsize,
        lifecycle_observations: AtomicUsize,
    }

    struct RecoveryHandler {
        fail_cleanup: AtomicBool,
        cleanup_calls: AtomicUsize,
    }

    struct DrainHandler {
        block_end: AtomicBool,
        end_calls: AtomicUsize,
        drain_calls: AtomicUsize,
    }

    #[async_trait]
    impl PrivateEgressHandler for DrainHandler {
        async fn execute(
            &self,
            _authority: &PrivateEgressRouteAuthority,
            command: &PrivateEgressCommand,
        ) -> Result<PrivateEgressHandlerResult, PrivateEgressError> {
            if matches!(command.operation, PrivateEgressOperation::End { .. }) {
                self.end_calls.fetch_add(1, Ordering::AcqRel);
                if self.block_end.load(Ordering::Acquire) {
                    std::future::pending::<()>().await;
                }
            }
            Ok(PrivateEgressHandlerResult::default())
        }

        async fn drain(&self, _timeout: Duration) -> Result<(), PrivateEgressError> {
            self.drain_calls.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    #[async_trait]
    impl PrivateEgressHandler for RecoveryHandler {
        async fn execute(
            &self,
            _authority: &PrivateEgressRouteAuthority,
            command: &PrivateEgressCommand,
        ) -> Result<PrivateEgressHandlerResult, PrivateEgressError> {
            if matches!(command.operation, PrivateEgressOperation::End { .. }) {
                self.cleanup_calls.fetch_add(1, Ordering::AcqRel);
                if self.fail_cleanup.load(Ordering::Acquire) {
                    return Err(PrivateEgressError::HandlerRejected);
                }
            }
            Ok(PrivateEgressHandlerResult {
                external_reference: None,
            })
        }

        async fn recover_dead_epoch_route(
            &self,
            _authority: &PrivateEgressRouteAuthority,
            _target: PrivateEgressTarget,
            _dead_epoch: Uuid,
        ) -> Result<(), PrivateEgressError> {
            self.cleanup_calls.fetch_add(1, Ordering::AcqRel);
            if self.fail_cleanup.load(Ordering::Acquire) {
                Err(PrivateEgressError::DeadEpochRecoveryFailed)
            } else {
                Ok(())
            }
        }
    }

    #[async_trait]
    impl PrivateEgressHandler for RecordingHandler {
        async fn execute(
            &self,
            _authority: &PrivateEgressRouteAuthority,
            command: &PrivateEgressCommand,
        ) -> Result<PrivateEgressHandlerResult, PrivateEgressError> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            Ok(PrivateEgressHandlerResult {
                external_reference: matches!(command.operation, PrivateEgressOperation::Activate)
                    .then(|| "gateway-route-redacted".to_owned()),
            })
        }

        async fn observe_lifecycle(
            &self,
            _authority: &PrivateEgressRouteAuthority,
            _event: &PrivateEgressLifecycleEvent,
        ) {
            self.lifecycle_observations.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn lease() -> WorkerLease {
        serde_json::from_value(serde_json::json!({
            "worker_id": "00000000-0000-4000-8000-000000000051",
            "fence": 7
        }))
        .unwrap()
    }

    fn authority() -> PrivateEgressRouteAuthority {
        PrivateEgressRouteAuthority {
            worker: lease(),
            source: PrivateEgressSource {
                tenant_id: TenantId::parse("tenant-a").unwrap(),
                call_id: "00000000-0000-4000-8000-000000000061".parse().unwrap(),
                leg_id: "00000000-0000-4000-8000-000000000062".parse().unwrap(),
                binding_generation: BindingGeneration::INITIAL,
            },
        }
    }

    fn command(
        authority: &PrivateEgressRouteAuthority,
        target: PrivateEgressTarget,
        operation: PrivateEgressOperation,
    ) -> PrivateEgressCommand {
        PrivateEgressCommand::new(
            Uuid::new_v4(),
            1_700_000_000_000,
            Duration::from_secs(5),
            authority.worker,
            authority.source.clone(),
            target,
            operation,
        )
        .unwrap()
    }

    fn target() -> PrivateEgressTarget {
        PrivateEgressTarget {
            leg_id: "00000000-0000-4000-8000-000000000063".parse().unwrap(),
            binding_generation: BindingGeneration::INITIAL,
        }
    }

    fn prepare(authority: &PrivateEgressRouteAuthority) -> PrivateEgressCommand {
        prepare_target(authority, target())
    }

    fn service_config() -> PrivateEgressServiceConfig {
        PrivateEgressServiceConfig {
            max_active_routes: 4,
            max_replay_entries: 32,
            replay_ttl: Duration::from_secs(60),
            operation_timeout: Duration::from_secs(1),
        }
    }

    fn prepare_target(
        authority: &PrivateEgressRouteAuthority,
        target: PrivateEgressTarget,
    ) -> PrivateEgressCommand {
        command(
            authority,
            target,
            PrivateEgressOperation::Prepare {
                transport: PrivateEgressTransport::Sip,
                profile: PrivateEgressProfile {
                    profile_id: "primary".into(),
                    revision: "a".repeat(64),
                },
                codec: CodecInfo::from_name_with_defaults("opus"),
                target: "sips:queue@example.test".into(),
                initial_context: vec![("X-Correlation-Id".into(), "corr-1".into())],
            },
        )
    }

    #[tokio::test]
    async fn command_service_graceful_drain_ends_routes_and_awaits_handler() {
        let handler = Arc::new(DrainHandler {
            block_end: AtomicBool::new(false),
            end_calls: AtomicUsize::new(0),
            drain_calls: AtomicUsize::new(0),
        });
        let service = PrivateEgressCommandService::new(
            Arc::clone(&handler) as Arc<dyn PrivateEgressHandler>,
            service_config(),
        )
        .unwrap();
        let authority = authority();
        service
            .execute(authority.clone(), prepare(&authority), 1_700_000_000_001)
            .await
            .unwrap();

        service.drain(Duration::from_secs(1)).await.unwrap();

        assert_eq!(handler.end_calls.load(Ordering::Acquire), 1);
        assert_eq!(handler.drain_calls.load(Ordering::Acquire), 1);
        assert_eq!(service.active_routes(), 0);
        assert!(service.routes.is_empty());
    }

    #[tokio::test]
    async fn command_service_forced_drain_times_out_but_leaves_zero_routes() {
        let handler = Arc::new(DrainHandler {
            block_end: AtomicBool::new(true),
            end_calls: AtomicUsize::new(0),
            drain_calls: AtomicUsize::new(0),
        });
        let service = PrivateEgressCommandService::new(
            Arc::clone(&handler) as Arc<dyn PrivateEgressHandler>,
            service_config(),
        )
        .unwrap();
        let authority = authority();
        service
            .execute(authority.clone(), prepare(&authority), 1_700_000_000_001)
            .await
            .unwrap();

        assert_eq!(
            service.drain(Duration::from_millis(1)).await,
            Err(PrivateEgressError::Timeout)
        );

        assert_eq!(handler.end_calls.load(Ordering::Acquire), 1);
        assert_eq!(handler.drain_calls.load(Ordering::Acquire), 1);
        assert_eq!(service.active_routes(), 0);
        assert!(service.routes.is_empty());
    }

    #[test]
    fn wire_contract_is_bounded_reliable_and_redacted() {
        let route_authority = authority();
        let prepare = prepare(&route_authority);
        let message = prepare.to_data_message().unwrap();
        assert_eq!(message.label, PRIVATE_EGRESS_COMMAND_LABEL);
        assert_eq!(message.reliability, DataReliability::ReliableOrdered);
        assert_eq!(
            PrivateEgressCommand::from_data_message(&message, 1_700_000_000_001).unwrap(),
            prepare
        );
        let debug = format!("{prepare:?}");
        assert!(!debug.contains("queue@example.test"));
        assert!(!debug.contains("corr-1"));
        assert!(PrivateEgressCommand::new(
            Uuid::new_v4(),
            1_700_000_000_000,
            Duration::from_secs(31),
            route_authority.worker,
            route_authority.source.clone(),
            target(),
            PrivateEgressOperation::Activate,
        )
        .is_err());
        assert!(PrivateEgressLifecycleEvent::progress(
            lease(),
            route_authority.source.clone(),
            target(),
            99,
            false,
        )
        .is_err());
        assert!(PrivateEgressLifecycleEvent::progress(
            lease(),
            route_authority.source,
            target(),
            200,
            true,
        )
        .is_err());
    }

    #[tokio::test]
    async fn exact_authority_transitions_and_replay_are_enforced() {
        let handler = Arc::new(RecordingHandler {
            calls: AtomicUsize::new(0),
            lifecycle_observations: AtomicUsize::new(0),
        });
        let service = PrivateEgressCommandService::new(
            Arc::clone(&handler) as Arc<dyn PrivateEgressHandler>,
            PrivateEgressServiceConfig {
                max_active_routes: 1,
                max_replay_entries: 16,
                replay_ttl: Duration::from_secs(60),
                operation_timeout: Duration::from_secs(1),
            },
        )
        .unwrap();
        let authority = authority();
        let prepare_command = prepare(&authority);
        let first = service
            .execute(
                authority.clone(),
                prepare_command.clone(),
                1_700_000_000_001,
            )
            .await
            .unwrap();
        assert!(first.accepted);
        assert_eq!(first.state, Some(PrivateEgressLifecycleState::Prepared));
        assert_eq!(service.active_routes(), 1);
        let replay = service
            .execute(
                authority.clone(),
                prepare_command.clone(),
                1_700_000_000_002,
            )
            .await
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(handler.calls.load(Ordering::Acquire), 1);

        let mut conflict = prepare_command.clone();
        conflict.operation = PrivateEgressOperation::Abort;
        assert_eq!(
            service
                .execute(authority.clone(), conflict, 1_700_000_000_002)
                .await,
            Err(PrivateEgressError::ReplayConflict)
        );

        let active = service
            .execute(
                authority.clone(),
                command(&authority, target(), PrivateEgressOperation::Activate),
                1_700_000_000_002,
            )
            .await
            .unwrap();
        assert_eq!(active.state, Some(PrivateEgressLifecycleState::Active));
        assert!(active.external_reference.is_some());

        let ended = service
            .execute(
                authority.clone(),
                command(
                    &authority,
                    target(),
                    PrivateEgressOperation::End {
                        reason: PrivateEgressEndReason::Normal,
                    },
                ),
                1_700_000_000_003,
            )
            .await
            .unwrap();
        assert_eq!(ended.state, Some(PrivateEgressLifecycleState::Ended));
        assert_eq!(service.active_routes(), 0);
        let stale_reopen = service
            .execute(authority.clone(), prepare(&authority), 1_700_000_000_004)
            .await
            .unwrap();
        assert!(!stale_reopen.accepted);
        assert_eq!(
            stale_reopen.failure_code.as_deref(),
            Some("invalid_transition")
        );

        let replacement_target = PrivateEgressTarget {
            leg_id: LegId::new(),
            binding_generation: BindingGeneration::INITIAL,
        };
        service
            .execute(
                authority.clone(),
                prepare_target(&authority, replacement_target),
                1_700_000_000_004,
            )
            .await
            .unwrap();
        service
            .execute(
                authority.clone(),
                command(
                    &authority,
                    replacement_target,
                    PrivateEgressOperation::Activate,
                ),
                1_700_000_000_004,
            )
            .await
            .unwrap();
        let failed_event = PrivateEgressLifecycleEvent::new(
            authority.worker,
            authority.source.clone(),
            replacement_target,
            PrivateEgressLifecycleState::Failed,
            Some("remote_hangup".into()),
        )
        .unwrap();
        let stamped = service
            .record_lifecycle(&authority, &failed_event)
            .await
            .unwrap();
        assert_eq!(
            handler.lifecycle_observations.load(Ordering::Acquire),
            0,
            "terminal transport cleanup must wait for the durable lifecycle ACK"
        );
        let ack = PrivateEgressLifecycleAck::from_event(&stamped).unwrap();
        let mut wrong_ack = ack.clone();
        wrong_ack.sequence = wrong_ack.sequence.saturating_add(1);
        assert_eq!(
            service.acknowledge_lifecycle(&authority, &wrong_ack).await,
            Err(PrivateEgressError::OwnershipMismatch)
        );
        assert_eq!(handler.lifecycle_observations.load(Ordering::Acquire), 0);
        service
            .acknowledge_lifecycle(&authority, &ack)
            .await
            .unwrap();
        assert_eq!(handler.lifecycle_observations.load(Ordering::Acquire), 1);
        service
            .acknowledge_lifecycle(&authority, &ack)
            .await
            .unwrap();
        assert_eq!(
            handler.lifecycle_observations.load(Ordering::Acquire),
            1,
            "a replayed lifecycle ACK must not repeat transport cleanup"
        );
        assert_eq!(service.active_routes(), 0);
        assert_eq!(
            service.record_lifecycle(&authority, &failed_event).await,
            Err(PrivateEgressError::InvalidTransition)
        );

        let mut wrong = prepare(&authority);
        wrong.worker = serde_json::from_value(serde_json::json!({
            "worker_id": "00000000-0000-4000-8000-000000000052",
            "fence": 7
        }))
        .unwrap();
        assert_eq!(
            service.execute(authority, wrong, 1_700_000_000_004).await,
            Err(PrivateEgressError::OwnershipMismatch)
        );
    }

    #[tokio::test]
    async fn source_loss_retires_a_terminal_route_still_waiting_for_ack() {
        let handler = Arc::new(RecordingHandler {
            calls: AtomicUsize::new(0),
            lifecycle_observations: AtomicUsize::new(0),
        });
        let service = PrivateEgressCommandService::new(
            Arc::clone(&handler) as Arc<dyn PrivateEgressHandler>,
            PrivateEgressServiceConfig {
                max_active_routes: 1,
                max_replay_entries: 16,
                replay_ttl: Duration::from_secs(60),
                operation_timeout: Duration::from_secs(1),
            },
        )
        .unwrap();
        let authority = authority();
        let target = target();
        service
            .execute(authority.clone(), prepare(&authority), 1_700_000_000_001)
            .await
            .unwrap();
        service
            .execute(
                authority.clone(),
                command(&authority, target, PrivateEgressOperation::Activate),
                1_700_000_000_002,
            )
            .await
            .unwrap();
        let terminal = PrivateEgressLifecycleEvent::new(
            authority.worker,
            authority.source.clone(),
            target,
            PrivateEgressLifecycleState::Ended,
            Some("remote_ended".into()),
        )
        .unwrap();
        service
            .record_lifecycle(&authority, &terminal)
            .await
            .unwrap();
        assert_eq!(handler.lifecycle_observations.load(Ordering::Acquire), 0);

        service.end_source(&authority).await;

        assert_eq!(
            handler.calls.load(Ordering::Acquire),
            3,
            "source cleanup must issue End for a terminal route whose ACK can no longer arrive"
        );
        assert_eq!(service.active_routes(), 0);
    }

    #[tokio::test]
    async fn failed_dead_epoch_cleanup_remains_release_blocking_until_it_succeeds() {
        let store = MemoryPrivateEgressStateStore::new(64, Duration::from_secs(60)).unwrap();
        let first = PrivateEgressGatewayEpoch::new(
            "gateway-recovery-test",
            Uuid::parse_str("00000000-0000-4000-8000-000000000171").unwrap(),
        )
        .unwrap();
        let second = PrivateEgressGatewayEpoch::new(
            "gateway-recovery-test",
            Uuid::parse_str("00000000-0000-4000-8000-000000000172").unwrap(),
        )
        .unwrap();
        store.begin_epoch(&first, 3_000).await.unwrap();
        let authority = authority();
        let route = PrivateEgressRouteKey::new(authority.worker, &authority.source, target());
        let prepare_id = Uuid::new_v4();
        store
            .claim_route_transition(
                &first,
                &route,
                prepare_id,
                None,
                PrivateEgressLifecycleState::Prepared,
            )
            .await
            .unwrap();
        store
            .complete_route_transition(
                &first,
                &route,
                prepare_id,
                PrivateEgressLifecycleState::Prepared,
                3_001,
            )
            .await
            .unwrap();
        let handler = Arc::new(RecoveryHandler {
            fail_cleanup: AtomicBool::new(true),
            cleanup_calls: AtomicUsize::new(0),
        });
        let state: Arc<dyn PrivateEgressStateStore> = store.clone();

        assert_eq!(
            PrivateEgressCommandService::new_with_state_store(
                Arc::clone(&handler) as Arc<dyn PrivateEgressHandler>,
                service_config(),
                second.clone(),
                Arc::clone(&state),
            )
            .await
            .unwrap_err(),
            PrivateEgressError::DeadEpochRecoveryFailed
        );
        assert_eq!(handler.cleanup_calls.load(Ordering::Acquire), 1);
        assert_eq!(
            PrivateEgressCommandService::new_with_state_store(
                Arc::clone(&handler) as Arc<dyn PrivateEgressHandler>,
                service_config(),
                second.clone(),
                Arc::clone(&state),
            )
            .await
            .unwrap_err(),
            PrivateEgressError::DeadEpochRecoveryFailed
        );
        assert_eq!(handler.cleanup_calls.load(Ordering::Acquire), 2);

        handler.fail_cleanup.store(false, Ordering::Release);
        let service = PrivateEgressCommandService::new_with_state_store(
            Arc::clone(&handler) as Arc<dyn PrivateEgressHandler>,
            service_config(),
            second.clone(),
            Arc::clone(&state),
        )
        .await
        .unwrap();
        assert!(!service.has_durable_state());
        assert_eq!(handler.cleanup_calls.load(Ordering::Acquire), 3);
        assert!(store.begin_epoch(&second, 3_002).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_prepare_releases_capacity_and_drain_rejects_only_new_routes() {
        struct RejectFirst(AtomicUsize);
        #[async_trait]
        impl PrivateEgressHandler for RejectFirst {
            async fn execute(
                &self,
                _authority: &PrivateEgressRouteAuthority,
                _command: &PrivateEgressCommand,
            ) -> Result<PrivateEgressHandlerResult, PrivateEgressError> {
                if self.0.fetch_add(1, Ordering::AcqRel) == 0 {
                    Err(PrivateEgressError::HandlerRejected)
                } else {
                    Ok(PrivateEgressHandlerResult::default())
                }
            }
        }
        let service = PrivateEgressCommandService::new(
            Arc::new(RejectFirst(AtomicUsize::new(0))),
            PrivateEgressServiceConfig {
                max_active_routes: 1,
                max_replay_entries: 16,
                replay_ttl: Duration::from_secs(60),
                operation_timeout: Duration::from_secs(1),
            },
        )
        .unwrap();
        let authority = authority();
        let failed = service
            .execute(authority.clone(), prepare(&authority), 1_700_000_000_001)
            .await
            .unwrap();
        assert!(!failed.accepted);
        assert_eq!(failed.failure_code.as_deref(), Some("handler_rejected"));
        assert_eq!(service.active_routes(), 0);

        let accepted = service
            .execute(authority.clone(), prepare(&authority), 1_700_000_000_002)
            .await
            .unwrap();
        assert!(accepted.accepted);
        service.begin_drain();
        let second_target = PrivateEgressTarget {
            leg_id: LegId::new(),
            binding_generation: BindingGeneration::INITIAL,
        };
        let rejected = service
            .execute(
                authority.clone(),
                command(
                    &authority,
                    second_target,
                    PrivateEgressOperation::Prepare {
                        transport: PrivateEgressTransport::WebRtc,
                        profile: PrivateEgressProfile {
                            profile_id: "wss-primary".into(),
                            revision: "b".repeat(64),
                        },
                        codec: CodecInfo::from_name_with_defaults("opus"),
                        target: "wss://agent.example.test/signal".into(),
                        initial_context: Vec::new(),
                    },
                ),
                1_700_000_000_003,
            )
            .await
            .unwrap();
        assert_eq!(rejected.failure_code.as_deref(), Some("draining"));
    }

    #[tokio::test]
    async fn worker_drain_rejects_prepare_but_keeps_cleanup_commands_available() {
        let orchestrator = Orchestrator::new(Default::default());
        let client = PrivateEgressControlClient::start_authoritative(
            orchestrator,
            lease(),
            4,
            Duration::from_secs(1),
        )
        .unwrap();
        client.begin_drain();
        let authority = authority();
        let now = unix_time_ms();
        let cleanup = PrivateEgressCommand::new(
            Uuid::new_v4(),
            now,
            Duration::from_secs(1),
            authority.worker,
            authority.source.clone(),
            target(),
            PrivateEgressOperation::End {
                reason: PrivateEgressEndReason::WorkerDrain,
            },
        )
        .unwrap();
        assert_eq!(
            client.execute(ConnectionId::new(), cleanup).await,
            Err(PrivateEgressError::OwnershipMismatch),
            "cleanup reached route ownership validation instead of being rejected by drain"
        );
        let prepare = PrivateEgressCommand::new(
            Uuid::new_v4(),
            now,
            Duration::from_secs(1),
            authority.worker,
            authority.source,
            target(),
            PrivateEgressOperation::Prepare {
                transport: PrivateEgressTransport::Sip,
                profile: PrivateEgressProfile {
                    profile_id: "primary".into(),
                    revision: "a".repeat(64),
                },
                codec: CodecInfo::from_name_with_defaults("opus"),
                target: "sips:queue@example.test".into(),
                initial_context: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(
            client.execute(ConnectionId::new(), prepare).await,
            Err(PrivateEgressError::Draining)
        );
        client.shutdown().await;
    }

    #[tokio::test]
    async fn terminal_route_tombstones_remain_bounded_with_command_replay_state() {
        let service = PrivateEgressCommandService::new(
            Arc::new(RecordingHandler {
                calls: AtomicUsize::new(0),
                lifecycle_observations: AtomicUsize::new(0),
            }),
            PrivateEgressServiceConfig {
                max_active_routes: 1,
                max_replay_entries: 12,
                replay_ttl: Duration::from_secs(60),
                operation_timeout: Duration::from_secs(1),
            },
        )
        .unwrap();
        let authority = authority();
        for _ in 0..4 {
            let route = PrivateEgressTarget {
                leg_id: LegId::new(),
                binding_generation: BindingGeneration::INITIAL,
            };
            assert!(
                service
                    .execute(
                        authority.clone(),
                        prepare_target(&authority, route),
                        1_700_000_000_001,
                    )
                    .await
                    .unwrap()
                    .accepted
            );
            assert!(
                service
                    .execute(
                        authority.clone(),
                        command(&authority, route, PrivateEgressOperation::Activate),
                        1_700_000_000_002,
                    )
                    .await
                    .unwrap()
                    .accepted
            );
            assert!(
                service
                    .execute(
                        authority.clone(),
                        command(
                            &authority,
                            route,
                            PrivateEgressOperation::End {
                                reason: PrivateEgressEndReason::Normal,
                            },
                        ),
                        1_700_000_000_003,
                    )
                    .await
                    .unwrap()
                    .accepted
            );
        }
        assert_eq!(service.routes.len(), 4);
        assert!(service.routes.len() <= service.config.max_replay_entries);
        assert_eq!(
            service
                .execute(
                    authority.clone(),
                    prepare_target(
                        &authority,
                        PrivateEgressTarget {
                            leg_id: LegId::new(),
                            binding_generation: BindingGeneration::INITIAL,
                        },
                    ),
                    1_700_000_000_004,
                )
                .await,
            Err(PrivateEgressError::CapacityExceeded)
        );
    }
}
