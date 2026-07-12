//! Pure, serializable call and leg state transitions.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use uuid::Uuid;

const MAX_TENANT_ID_BYTES: usize = 128;
const MAX_FAILURE_CODE_BYTES: usize = 64;
const MAX_FAILURE_MESSAGE_CHARS: usize = 256;
const MAX_PERSISTED_GENERATION: u64 = i64::MAX as u64;

macro_rules! uuid_id {
    ($name:ident, $label:literal) => {
        #[doc = concat!("Strong ", $label, " identifier.")]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[doc = concat!("Generates a new ", $label, " identifier.")]
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            #[doc = concat!("Constructs a ", $label, " identifier from a non-nil UUID.")]
            pub fn from_uuid(value: Uuid) -> Result<Self, DomainError> {
                if value.is_nil() {
                    return Err(DomainError::InvalidIdentifier { kind: $label });
                }
                Ok(Self(value))
            }

            /// Returns the underlying UUID value.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = DomainError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let value = Uuid::parse_str(value)
                    .map_err(|_| DomainError::InvalidIdentifier { kind: $label })?;
                Self::from_uuid(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = Uuid::deserialize(deserializer)?;
                Self::from_uuid(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

uuid_id!(CallId, "call");
uuid_id!(LegId, "leg");

/// Stable, validated tenant identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TenantId(String);

impl TenantId {
    /// Parses a tenant identifier.
    ///
    /// Tenant identifiers are deliberately conservative so they are safe in
    /// logs, database keys, metrics exemplars, and routing keys.
    pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_TENANT_ID_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte));
        if !valid {
            return Err(DomainError::InvalidTenantId);
        }
        Ok(Self(value))
    }

    /// Returns the validated tenant identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for TenantId {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl<'de> Deserialize<'de> for TenantId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Monotonic aggregate version used by compare-and-swap repositories.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AggregateVersion(u64);

impl AggregateVersion {
    /// Returns the numeric version.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Returns the database-safe signed representation.
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    fn next(self) -> Result<Self, DomainError> {
        if self.0 >= MAX_PERSISTED_GENERATION {
            Err(DomainError::GenerationExhausted {
                kind: "aggregate_version",
            })
        } else {
            Ok(Self(self.0 + 1))
        }
    }
}

impl<'de> Deserialize<'de> for AggregateVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        if value > MAX_PERSISTED_GENERATION {
            return Err(serde::de::Error::custom(
                "aggregate version exceeds signed database range",
            ));
        }
        Ok(Self(value))
    }
}

/// Generation of a leg's current signaling/media attachment.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct BindingGeneration(u64);

impl BindingGeneration {
    /// Initial binding generation assigned to a new leg.
    pub const INITIAL: Self = Self(1);

    /// Returns the numeric generation.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Returns the database-safe signed representation.
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    fn next(self) -> Result<Self, DomainError> {
        if self.0 >= MAX_PERSISTED_GENERATION {
            Err(DomainError::GenerationExhausted {
                kind: "binding_generation",
            })
        } else {
            Ok(Self(self.0 + 1))
        }
    }
}

impl<'de> Deserialize<'de> for BindingGeneration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        if value == 0 || value > MAX_PERSISTED_GENERATION {
            return Err(serde::de::Error::custom(
                "binding generation must fit a positive signed database integer",
            ));
        }
        Ok(Self(value))
    }
}

/// Generation of an armed call deadline.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DeadlineGeneration(u64);

impl DeadlineGeneration {
    /// Returns the numeric generation.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Returns the database-safe signed representation.
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    fn next(self) -> Result<Self, DomainError> {
        if self.0 >= MAX_PERSISTED_GENERATION {
            Err(DomainError::GenerationExhausted {
                kind: "deadline_generation",
            })
        } else {
            Ok(Self(self.0 + 1))
        }
    }
}

impl<'de> Deserialize<'de> for DeadlineGeneration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        if value > MAX_PERSISTED_GENERATION {
            return Err(serde::de::Error::custom(
                "deadline generation exceeds signed database range",
            ));
        }
        Ok(Self(value))
    }
}

/// Direction of a logical call leg relative to Bridgefu.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegDirection {
    /// A remote endpoint attaches or originates toward Bridgefu.
    Inbound,
    /// Bridgefu originates toward a remote endpoint.
    Outbound,
}

/// Signaling/provider kind for a logical call leg.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegKind {
    /// Standard SIP signaling with RTP media.
    Sip,
    /// Interactive WebRTC offer/answer signaling and DataChannels.
    #[serde(rename = "webrtc", alias = "interactive_webrtc")]
    InteractiveWebRtc,
    /// WebRTC HTTP ingestion (WHIP).
    Whip,
    /// WebRTC HTTP egress (WHEP).
    Whep,
    /// Amazon Connect StartWebRTCContact/Chime leg.
    AmazonConnect,
    /// Twilio-controlled SIP/RTP leg.
    Twilio,
    /// Telnyx-controlled SIP/RTP leg.
    Telnyx,
    /// Vonage-controlled SIP/RTP leg.
    Vonage,
}

/// Call aggregate lifecycle state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallState {
    /// The durable call exists but execution has not started.
    Pending,
    /// One or both logical legs are attaching or signaling.
    Connecting,
    /// Both legs are connected and their media is bridged.
    Active,
    /// An explicit transfer is in progress.
    Transferring,
    /// Peer teardown is in progress.
    Ending,
    /// Both legs ended without a terminal failure.
    Ended,
    /// Both legs are terminal and the call failed.
    Failed,
}

impl CallState {
    /// Whether this state is terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Ended | Self::Failed)
    }
}

/// Logical call-leg lifecycle state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegState {
    /// The leg exists but execution has not started.
    Pending,
    /// The leg is waiting for a single-use inbound attachment.
    AwaitingAttach,
    /// Signaling is in progress.
    Signaling,
    /// Signaling and media are connected.
    Connected,
    /// The connected leg is held.
    Held,
    /// Teardown is in progress.
    Ending,
    /// Teardown completed normally.
    Ended,
    /// The leg terminated with a sanitized failure.
    Failed,
}

impl LegState {
    /// Whether this state is terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Ended | Self::Failed)
    }
}

/// Safe failure information suitable for persistence and API responses.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FailureDetails {
    code: String,
    message: String,
    retryable: bool,
}

#[derive(Deserialize)]
struct FailureDetailsWire {
    code: String,
    message: String,
    retryable: bool,
}

impl FailureDetails {
    /// Constructs already-sanitized failure details.
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        retryable: bool,
    ) -> Result<Self, DomainError> {
        let code = code.into();
        let message = message.into();
        if !valid_failure_code(&code) || !valid_failure_message(&message) {
            return Err(DomainError::UnsafeFailureDetails);
        }
        Ok(Self {
            code,
            message,
            retryable,
        })
    }

    /// Normalizes untrusted provider/transport text into bounded safe details.
    #[must_use]
    pub fn sanitized(code: &str, message: &str, retryable: bool) -> Self {
        let mut safe_code = code
            .chars()
            .map(|character| character.to_ascii_lowercase())
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                    character
                } else {
                    '_'
                }
            })
            .take(MAX_FAILURE_CODE_BYTES)
            .collect::<String>();
        safe_code = safe_code.trim_matches('_').to_owned();
        if safe_code.is_empty() {
            safe_code = "unknown_failure".to_owned();
        }

        let mut safe_message = String::new();
        let mut previous_whitespace = false;
        for character in message.chars() {
            let character = if character.is_control() {
                ' '
            } else {
                character
            };
            if character.is_whitespace() {
                if !previous_whitespace && !safe_message.is_empty() {
                    safe_message.push(' ');
                }
                previous_whitespace = true;
            } else {
                safe_message.push(character);
                previous_whitespace = false;
            }
            if safe_message.chars().count() >= MAX_FAILURE_MESSAGE_CHARS {
                break;
            }
        }
        let safe_message = safe_message.trim().to_owned();
        let safe_message = if safe_message.is_empty() {
            "operation failed".to_owned()
        } else {
            safe_message
        };

        Self {
            code: safe_code,
            message: safe_message,
            retryable,
        }
    }

    /// Stable machine-readable failure code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Bounded, single-line diagnostic message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Whether policy may safely consider retrying the failed operation.
    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.retryable
    }
}

impl<'de> Deserialize<'de> for FailureDetails {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = FailureDetailsWire::deserialize(deserializer)?;
        Self::new(wire.code, wire.message, wire.retryable).map_err(serde::de::Error::custom)
    }
}

fn valid_failure_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_FAILURE_CODE_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

fn valid_failure_message(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_FAILURE_MESSAGE_CHARS
        && !value.chars().any(char::is_control)
}

/// A leg specification used when constructing a new call.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegSpec {
    /// Direction relative to Bridgefu.
    pub direction: LegDirection,
    /// Signaling/provider kind.
    pub kind: LegKind,
}

/// A logical endpoint bridged by a call aggregate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Leg {
    id: LegId,
    direction: LegDirection,
    kind: LegKind,
    state: LegState,
    binding_generation: BindingGeneration,
    created_at: DateTime<Utc>,
    state_changed_at: DateTime<Utc>,
    connected_at: Option<DateTime<Utc>>,
    ended_at: Option<DateTime<Utc>>,
    failure: Option<FailureDetails>,
}

impl Leg {
    fn new(id: LegId, spec: LegSpec, now: DateTime<Utc>) -> Self {
        Self {
            id,
            direction: spec.direction,
            kind: spec.kind,
            state: LegState::Pending,
            binding_generation: BindingGeneration::INITIAL,
            created_at: now,
            state_changed_at: now,
            connected_at: None,
            ended_at: None,
            failure: None,
        }
    }

    /// Stable leg identifier.
    #[must_use]
    pub const fn id(&self) -> LegId {
        self.id
    }

    /// Direction relative to Bridgefu.
    #[must_use]
    pub const fn direction(&self) -> LegDirection {
        self.direction
    }

    /// Signaling/provider kind.
    #[must_use]
    pub const fn kind(&self) -> LegKind {
        self.kind
    }

    /// Current leg state.
    #[must_use]
    pub const fn state(&self) -> LegState {
        self.state
    }

    /// Current binding generation.
    #[must_use]
    pub const fn binding_generation(&self) -> BindingGeneration {
        self.binding_generation
    }

    /// Creation time in UTC.
    #[must_use]
    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Time of the most recent state transition in UTC.
    #[must_use]
    pub const fn state_changed_at(&self) -> DateTime<Utc> {
        self.state_changed_at
    }

    /// First connected time, when available.
    #[must_use]
    pub const fn connected_at(&self) -> Option<DateTime<Utc>> {
        self.connected_at
    }

    /// Terminal time, when available.
    #[must_use]
    pub const fn ended_at(&self) -> Option<DateTime<Utc>> {
        self.ended_at
    }

    /// Sanitized terminal failure, when present.
    #[must_use]
    pub const fn failure(&self) -> Option<&FailureDetails> {
        self.failure.as_ref()
    }
}

/// Kind of lifecycle deadline.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadlineKind {
    /// Maximum time for both legs to connect.
    Setup,
    /// Maximum time without expected media activity.
    Media,
    /// Maximum time for a transfer command to settle.
    Transfer,
    /// Maximum time for all legs to finish teardown.
    Ending,
}

/// Current generation and due time for one deadline kind.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeadlineSlot {
    generation: DeadlineGeneration,
    due_at: Option<DateTime<Utc>>,
}

impl DeadlineSlot {
    /// Current generation, including the generation of a cancelled timer.
    #[must_use]
    pub const fn generation(self) -> DeadlineGeneration {
        self.generation
    }

    /// Armed due time, or `None` when no timer is armed.
    #[must_use]
    pub const fn due_at(self) -> Option<DateTime<Utc>> {
        self.due_at
    }
}

/// All lifecycle deadline slots for a call.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CallDeadlines {
    setup: DeadlineSlot,
    media: DeadlineSlot,
    transfer: DeadlineSlot,
    ending: DeadlineSlot,
}

impl CallDeadlines {
    /// Returns a deadline slot by kind.
    #[must_use]
    pub const fn get(self, kind: DeadlineKind) -> DeadlineSlot {
        match kind {
            DeadlineKind::Setup => self.setup,
            DeadlineKind::Media => self.media,
            DeadlineKind::Transfer => self.transfer,
            DeadlineKind::Ending => self.ending,
        }
    }

    fn get_mut(&mut self, kind: DeadlineKind) -> &mut DeadlineSlot {
        match kind {
            DeadlineKind::Setup => &mut self.setup,
            DeadlineKind::Media => &mut self.media,
            DeadlineKind::Transfer => &mut self.transfer,
            DeadlineKind::Ending => &mut self.ending,
        }
    }
}

/// Terminal result selected while peer teardown is still running.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "result", content = "failure", rename_all = "snake_case")]
pub enum TerminalOutcome {
    /// Normal terminal result.
    Ended,
    /// Failed terminal result with safe details.
    Failed(FailureDetails),
}

/// Durable aggregate for exactly two explicitly bridged logical legs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CallAggregate {
    id: CallId,
    tenant_id: TenantId,
    version: AggregateVersion,
    state: CallState,
    legs: [Leg; 2],
    deadlines: CallDeadlines,
    terminal_outcome: Option<TerminalOutcome>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    state_changed_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct CallAggregateWire {
    id: CallId,
    tenant_id: TenantId,
    version: AggregateVersion,
    state: CallState,
    legs: [Leg; 2],
    deadlines: CallDeadlines,
    terminal_outcome: Option<TerminalOutcome>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    state_changed_at: DateTime<Utc>,
}

impl<'de> Deserialize<'de> for CallAggregate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CallAggregateWire::deserialize(deserializer)?;
        let aggregate = Self {
            id: wire.id,
            tenant_id: wire.tenant_id,
            version: wire.version,
            state: wire.state,
            legs: wire.legs,
            deadlines: wire.deadlines,
            terminal_outcome: wire.terminal_outcome,
            created_at: wire.created_at,
            updated_at: wire.updated_at,
            state_changed_at: wire.state_changed_at,
        };
        aggregate.validate().map_err(serde::de::Error::custom)?;
        Ok(aggregate)
    }
}

impl CallAggregate {
    /// Creates a new call with generated call and leg identifiers.
    pub fn new(tenant_id: TenantId, legs: [LegSpec; 2], now: DateTime<Utc>) -> Self {
        let left_id = LegId::new();
        let mut right_id = LegId::new();
        while right_id == left_id {
            right_id = LegId::new();
        }
        // UUID v4 values cannot be nil because their version bits are set.
        Self::with_ids(
            CallId::new(),
            tenant_id,
            [(left_id, legs[0]), (right_id, legs[1])],
            now,
        )
        .expect("generated UUIDs are non-nil")
    }

    /// Creates a call with caller-supplied identifiers for durable recovery and tests.
    pub fn with_ids(
        id: CallId,
        tenant_id: TenantId,
        legs: [(LegId, LegSpec); 2],
        now: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        if legs[0].0 == legs[1].0 {
            return Err(DomainError::DuplicateLegId(legs[0].0));
        }
        let aggregate = Self {
            id,
            tenant_id,
            version: AggregateVersion::default(),
            state: CallState::Pending,
            legs: [
                Leg::new(legs[0].0, legs[0].1, now),
                Leg::new(legs[1].0, legs[1].1, now),
            ],
            deadlines: CallDeadlines::default(),
            terminal_outcome: None,
            created_at: now,
            updated_at: now,
            state_changed_at: now,
        };
        aggregate.validate()?;
        Ok(aggregate)
    }

    /// Applies a command without I/O and returns the next aggregate plus effect intents.
    ///
    /// The receiver is never modified. Repositories can compare-and-swap the returned
    /// aggregate by [`AggregateVersion`] before dispatching its effects.
    pub fn decide(&self, command: CallCommand) -> Result<CallDecision, DomainError> {
        let mut aggregate = self.clone();
        let command_result = aggregate.apply_command(command)?;
        if command_result.disposition == CommandDisposition::Applied {
            aggregate.version = aggregate.version.next()?;
            aggregate.updated_at = command_result.at;
        }
        aggregate.validate()?;
        Ok(CallDecision {
            aggregate,
            effects: command_result.effects,
            disposition: command_result.disposition,
        })
    }

    /// Stable call identifier.
    #[must_use]
    pub const fn id(&self) -> CallId {
        self.id
    }

    /// Authenticated tenant that owns the call.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Current compare-and-swap version.
    #[must_use]
    pub const fn version(&self) -> AggregateVersion {
        self.version
    }

    /// Current call state.
    #[must_use]
    pub const fn state(&self) -> CallState {
        self.state
    }

    /// The two logical legs. The fixed array is part of the persistence contract.
    #[must_use]
    pub const fn legs(&self) -> &[Leg; 2] {
        &self.legs
    }

    /// Finds a logical leg by ID.
    #[must_use]
    pub fn leg(&self, id: LegId) -> Option<&Leg> {
        self.legs.iter().find(|leg| leg.id == id)
    }

    /// Current lifecycle deadlines and their generations.
    #[must_use]
    pub const fn deadlines(&self) -> CallDeadlines {
        self.deadlines
    }

    /// Selected terminal outcome while ending, or the final outcome after termination.
    #[must_use]
    pub const fn terminal_outcome(&self) -> Option<&TerminalOutcome> {
        self.terminal_outcome.as_ref()
    }

    /// Creation time in UTC.
    #[must_use]
    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Time of the latest applied command in UTC.
    #[must_use]
    pub const fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    /// Time of the latest call-state change in UTC.
    #[must_use]
    pub const fn state_changed_at(&self) -> DateTime<Utc> {
        self.state_changed_at
    }

    /// Revalidates all durable aggregate invariants.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.legs[0].id == self.legs[1].id {
            return Err(DomainError::DuplicateLegId(self.legs[0].id));
        }
        if self.updated_at < self.created_at || self.state_changed_at > self.updated_at {
            return Err(DomainError::InvalidSnapshot("invalid call timestamps"));
        }
        for leg in &self.legs {
            if leg.binding_generation.value() == 0 {
                return Err(DomainError::InvalidSnapshot(
                    "leg binding generation must be nonzero",
                ));
            }
            if leg.created_at < self.created_at
                || leg.state_changed_at < leg.created_at
                || leg.state_changed_at > self.updated_at
                || leg
                    .connected_at
                    .is_some_and(|at| at < leg.created_at || at > self.updated_at)
                || leg
                    .ended_at
                    .is_some_and(|at| at < leg.created_at || at > self.updated_at)
            {
                return Err(DomainError::InvalidSnapshot("invalid leg timestamps"));
            }
            if leg.state == LegState::Failed && leg.failure.is_none() {
                return Err(DomainError::InvalidSnapshot(
                    "failed leg must contain failure details",
                ));
            }
            if leg.state != LegState::Failed && leg.failure.is_some() {
                return Err(DomainError::InvalidSnapshot(
                    "only failed leg may contain failure details",
                ));
            }
            if leg.state.is_terminal() != leg.ended_at.is_some() {
                return Err(DomainError::InvalidSnapshot(
                    "terminal leg timestamp does not match state",
                ));
            }
        }

        match self.state {
            CallState::Pending => {
                if self.legs.iter().any(|leg| leg.state != LegState::Pending) {
                    return Err(DomainError::InvalidSnapshot(
                        "pending call must contain pending legs",
                    ));
                }
            }
            CallState::Connecting => {
                if self.legs.iter().any(|leg| {
                    !matches!(
                        leg.state,
                        LegState::Pending
                            | LegState::AwaitingAttach
                            | LegState::Signaling
                            | LegState::Connected
                    )
                }) {
                    return Err(DomainError::InvalidSnapshot(
                        "connecting call contains an incompatible leg state",
                    ));
                }
            }
            CallState::Active | CallState::Transferring => {
                if self
                    .legs
                    .iter()
                    .any(|leg| !matches!(leg.state, LegState::Connected | LegState::Held))
                {
                    return Err(DomainError::InvalidSnapshot(
                        "active call legs must be connected or held",
                    ));
                }
            }
            CallState::Ending => {
                if self.terminal_outcome.is_none()
                    || self.legs.iter().any(|leg| {
                        !matches!(
                            leg.state,
                            LegState::Ending | LegState::Ended | LegState::Failed
                        )
                    })
                {
                    return Err(DomainError::InvalidSnapshot(
                        "ending call requires an outcome and ending or terminal legs",
                    ));
                }
                if self.legs.iter().any(|leg| leg.state == LegState::Failed)
                    && !matches!(self.terminal_outcome, Some(TerminalOutcome::Failed(_)))
                {
                    return Err(DomainError::InvalidSnapshot(
                        "failed ending leg requires failed terminal outcome",
                    ));
                }
            }
            CallState::Ended => {
                if self.terminal_outcome != Some(TerminalOutcome::Ended)
                    || self.legs.iter().any(|leg| leg.state != LegState::Ended)
                {
                    return Err(DomainError::InvalidSnapshot(
                        "ended call requires two normally ended legs and normal outcome",
                    ));
                }
            }
            CallState::Failed => {
                if !matches!(self.terminal_outcome, Some(TerminalOutcome::Failed(_)))
                    || self.legs.iter().any(|leg| !leg.state.is_terminal())
                {
                    return Err(DomainError::InvalidSnapshot(
                        "failed call requires two terminal legs and failed outcome",
                    ));
                }
            }
        }

        if !matches!(
            self.state,
            CallState::Ending | CallState::Ended | CallState::Failed
        ) && self.terminal_outcome.is_some()
        {
            return Err(DomainError::InvalidSnapshot(
                "non-ending call cannot have a terminal outcome",
            ));
        }
        for kind in [
            DeadlineKind::Setup,
            DeadlineKind::Media,
            DeadlineKind::Transfer,
            DeadlineKind::Ending,
        ] {
            if self.deadlines.get(kind).due_at.is_some() {
                let allowed = match kind {
                    DeadlineKind::Setup => self.state == CallState::Connecting,
                    DeadlineKind::Media => {
                        matches!(self.state, CallState::Active | CallState::Transferring)
                    }
                    DeadlineKind::Transfer => self.state == CallState::Transferring,
                    DeadlineKind::Ending => self.state == CallState::Ending,
                };
                if !allowed {
                    return Err(DomainError::InvalidSnapshot(
                        "deadline is armed in an incompatible call state",
                    ));
                }
            }
        }
        if self.state.is_terminal()
            && [
                DeadlineKind::Setup,
                DeadlineKind::Media,
                DeadlineKind::Transfer,
                DeadlineKind::Ending,
            ]
            .into_iter()
            .any(|kind| self.deadlines.get(kind).due_at.is_some())
        {
            return Err(DomainError::InvalidSnapshot(
                "terminal call cannot have armed deadlines",
            ));
        }
        Ok(())
    }
}

/// Serializable command interpreted by [`CallAggregate::decide`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum CallCommand {
    /// Starts both leg executors and arms the setup deadline.
    StartConnecting {
        /// Command time in UTC.
        at: DateTime<Utc>,
        /// UTC setup deadline.
        setup_deadline: DateTime<Utc>,
    },
    /// Applies a state report from the current binding of one leg.
    SetLegState {
        /// Command time in UTC.
        at: DateTime<Utc>,
        /// Target leg.
        leg_id: LegId,
        /// Binding generation that produced the report.
        binding_generation: BindingGeneration,
        /// Requested next leg state.
        state: LegState,
        /// Required only when `state` is `failed`.
        failure: Option<FailureDetails>,
    },
    /// Invalidates a previous inbound/signaling binding and awaits a replacement.
    RotateLegBinding {
        /// Command time in UTC.
        at: DateTime<Utc>,
        /// Target leg.
        leg_id: LegId,
        /// Binding generation being replaced.
        binding_generation: BindingGeneration,
    },
    /// Arms or refreshes a state-compatible deadline.
    ArmDeadline {
        /// Command time in UTC.
        at: DateTime<Utc>,
        /// Deadline kind.
        kind: DeadlineKind,
        /// UTC due time.
        due_at: DateTime<Utc>,
    },
    /// Begins a transfer while preserving the connected two-leg topology.
    BeginTransfer {
        /// Command time in UTC.
        at: DateTime<Utc>,
        /// UTC transfer deadline.
        transfer_deadline: DateTime<Utc>,
    },
    /// Completes or rejects the current transfer generation.
    FinishTransfer {
        /// Command time in UTC.
        at: DateTime<Utc>,
        /// Generation returned when the transfer deadline was armed.
        deadline_generation: DeadlineGeneration,
        /// Provider/signaling result.
        result: TransferResult,
    },
    /// Starts normal peer teardown.
    BeginEnding {
        /// Command time in UTC.
        at: DateTime<Utc>,
        /// Optional UTC teardown deadline.
        ending_deadline: Option<DateTime<Utc>>,
        /// Typed reason exposed to stop-leg effects.
        reason: StopLegReason,
    },
    /// Reports a timer firing. Stale generations are ignored safely.
    DeadlineElapsed {
        /// Observation time in UTC.
        at: DateTime<Utc>,
        /// Deadline kind.
        kind: DeadlineKind,
        /// Generation carried by the timer.
        generation: DeadlineGeneration,
        /// Optional teardown deadline to arm after a non-ending timeout.
        ending_deadline: Option<DateTime<Utc>>,
    },
}

impl CallCommand {
    /// UTC observation time carried by this command.
    ///
    /// Repositories require this value to equal their transaction timestamp
    /// exactly so a caller cannot persist one ordering while asking the pure
    /// aggregate to evaluate another.
    #[must_use]
    pub fn at(&self) -> DateTime<Utc> {
        match self {
            Self::StartConnecting { at, .. }
            | Self::SetLegState { at, .. }
            | Self::RotateLegBinding { at, .. }
            | Self::ArmDeadline { at, .. }
            | Self::BeginTransfer { at, .. }
            | Self::FinishTransfer { at, .. }
            | Self::BeginEnding { at, .. }
            | Self::DeadlineElapsed { at, .. } => *at,
        }
    }
}

/// Outcome of a provider/signaling transfer command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "result", content = "failure", rename_all = "snake_case")]
pub enum TransferResult {
    /// The transfer completed and the call remains active.
    Completed,
    /// The transfer was rejected; compensating work should restore the call.
    Rejected(FailureDetails),
}

/// Typed reason for stopping a leg.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopLegReason {
    /// Administrative or caller-requested hangup.
    Requested,
    /// The peer leg ended.
    PeerEnded,
    /// A leg or call operation failed.
    Failure,
    /// A lifecycle deadline expired.
    DeadlineExpired,
}

/// Serializable side-effect intent produced by a pure state transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "effect", rename_all = "snake_case")]
pub enum EffectIntent {
    /// Start signaling or attachment handling for a leg.
    StartLeg {
        /// Leg to start.
        leg_id: LegId,
        /// Binding generation assigned to the operation.
        binding_generation: BindingGeneration,
        /// Typed leg kind.
        kind: LegKind,
        /// Direction relative to Bridgefu.
        direction: LegDirection,
    },
    /// Await a replacement attachment using a new binding generation.
    AwaitLegAttachment {
        /// Target leg.
        leg_id: LegId,
        /// New binding generation.
        binding_generation: BindingGeneration,
    },
    /// Connect both current leg bindings through the media graph.
    BridgeMedia {
        /// First leg.
        left_leg_id: LegId,
        /// Second leg.
        right_leg_id: LegId,
    },
    /// Remove the current two-leg media graph route.
    UnbridgeMedia {
        /// First leg.
        left_leg_id: LegId,
        /// Second leg.
        right_leg_id: LegId,
    },
    /// Ask a leg executor to terminate its current binding.
    StopLeg {
        /// Target leg.
        leg_id: LegId,
        /// Binding generation to terminate.
        binding_generation: BindingGeneration,
        /// Typed stop reason.
        reason: StopLegReason,
    },
    /// Install a generation-bound UTC timer.
    ScheduleDeadline {
        /// Deadline kind.
        kind: DeadlineKind,
        /// Timer generation.
        generation: DeadlineGeneration,
        /// UTC due time.
        due_at: DateTime<Utc>,
    },
    /// Cancel a previously armed timer.
    CancelDeadline {
        /// Deadline kind.
        kind: DeadlineKind,
        /// Timer generation to cancel.
        generation: DeadlineGeneration,
    },
    /// Execute a transfer for the current call topology.
    ExecuteTransfer {
        /// Transfer timer generation used to correlate the result.
        deadline_generation: DeadlineGeneration,
    },
    /// Compensate a rejected or timed-out transfer.
    CompensateTransfer {
        /// Safe reason for compensation.
        failure: FailureDetails,
    },
}

/// Whether a command changed durable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandDisposition {
    /// The command changed the aggregate and incremented its version.
    Applied,
    /// The command repeated already-represented state.
    IgnoredNoop,
    /// The command came from a superseded binding or timer generation.
    IgnoredStaleGeneration,
}

/// Pure command result ready for atomic persistence and later effect dispatch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CallDecision {
    aggregate: CallAggregate,
    effects: Vec<EffectIntent>,
    disposition: CommandDisposition,
}

impl CallDecision {
    /// Next aggregate snapshot.
    #[must_use]
    pub const fn aggregate(&self) -> &CallAggregate {
        &self.aggregate
    }

    /// Ordered effect intents emitted by the transition.
    #[must_use]
    pub fn effects(&self) -> &[EffectIntent] {
        &self.effects
    }

    /// Command disposition.
    #[must_use]
    pub const fn disposition(&self) -> CommandDisposition {
        self.disposition
    }

    /// Consumes the decision into persistence and dispatch components.
    #[must_use]
    pub fn into_parts(self) -> (CallAggregate, Vec<EffectIntent>, CommandDisposition) {
        (self.aggregate, self.effects, self.disposition)
    }
}

/// Domain validation or transition failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DomainError {
    /// An ID was nil or syntactically invalid.
    #[error("invalid {kind} identifier")]
    InvalidIdentifier {
        /// Identifier kind.
        kind: &'static str,
    },
    /// Tenant ID was empty, oversized, or unsafe for routing keys.
    #[error("invalid tenant identifier")]
    InvalidTenantId,
    /// Failure information was not bounded and single-line.
    #[error("failure details are not sanitized")]
    UnsafeFailureDetails,
    /// Both logical leg slots used the same ID.
    #[error("duplicate leg identifier {0}")]
    DuplicateLegId(LegId),
    /// A command referenced a leg outside this call.
    #[error("unknown leg {0}")]
    UnknownLeg(LegId),
    /// The requested call-state transition is invalid.
    #[error("invalid call transition from {from:?} for {command}")]
    InvalidCallTransition {
        /// Current call state.
        from: CallState,
        /// Command name.
        command: &'static str,
    },
    /// The requested leg-state transition is invalid.
    #[error("invalid leg transition from {from:?} to {to:?}")]
    InvalidLegTransition {
        /// Current leg state.
        from: LegState,
        /// Requested leg state.
        to: LegState,
    },
    /// Failed leg state omitted safe failure details.
    #[error("failed leg state requires failure details")]
    FailureRequired,
    /// Non-failed leg state included failure details.
    #[error("failure details are only valid for failed leg state")]
    UnexpectedFailure,
    /// A command time preceded the latest durable update.
    #[error("command timestamp moved backwards")]
    TimestampRegression,
    /// A newly armed deadline was not later than the command time.
    #[error("deadline must be in the future")]
    DeadlineNotFuture,
    /// A deadline event fired before its UTC due time.
    #[error("deadline has not elapsed")]
    DeadlineNotElapsed,
    /// A command claimed a binding generation newer than the aggregate.
    #[error("future binding generation for leg {leg_id}: current={current}, supplied={supplied}")]
    FutureBindingGeneration {
        /// Leg identifier.
        leg_id: LegId,
        /// Current generation.
        current: u64,
        /// Supplied generation.
        supplied: u64,
    },
    /// A timer/result claimed a deadline generation newer than the aggregate.
    #[error("future {kind:?} deadline generation: current={current}, supplied={supplied}")]
    FutureDeadlineGeneration {
        /// Deadline kind.
        kind: DeadlineKind,
        /// Current generation.
        current: u64,
        /// Supplied generation.
        supplied: u64,
    },
    /// A monotonic version or generation reached `u64::MAX`.
    #[error("{kind} exhausted")]
    GenerationExhausted {
        /// Counter kind.
        kind: &'static str,
    },
    /// A persisted/deserialized aggregate violated a structural invariant.
    #[error("invalid aggregate snapshot: {0}")]
    InvalidSnapshot(&'static str),
}

struct CommandResult {
    at: DateTime<Utc>,
    effects: Vec<EffectIntent>,
    disposition: CommandDisposition,
}

impl CallAggregate {
    fn apply_command(&mut self, command: CallCommand) -> Result<CommandResult, DomainError> {
        match command {
            CallCommand::StartConnecting { at, setup_deadline } => {
                self.start_connecting(at, setup_deadline)
            }
            CallCommand::SetLegState {
                at,
                leg_id,
                binding_generation,
                state,
                failure,
            } => self.set_leg_state(at, leg_id, binding_generation, state, failure),
            CallCommand::RotateLegBinding {
                at,
                leg_id,
                binding_generation,
            } => self.rotate_leg_binding(at, leg_id, binding_generation),
            CallCommand::ArmDeadline { at, kind, due_at } => {
                self.arm_deadline_command(at, kind, due_at)
            }
            CallCommand::BeginTransfer {
                at,
                transfer_deadline,
            } => self.begin_transfer(at, transfer_deadline),
            CallCommand::FinishTransfer {
                at,
                deadline_generation,
                result,
            } => self.finish_transfer(at, deadline_generation, result),
            CallCommand::BeginEnding {
                at,
                ending_deadline,
                reason,
            } => self.begin_ending_command(at, ending_deadline, reason),
            CallCommand::DeadlineElapsed {
                at,
                kind,
                generation,
                ending_deadline,
            } => self.deadline_elapsed(at, kind, generation, ending_deadline),
        }
    }

    fn start_connecting(
        &mut self,
        at: DateTime<Utc>,
        setup_deadline: DateTime<Utc>,
    ) -> Result<CommandResult, DomainError> {
        self.ensure_timestamp(at)?;
        if self.state != CallState::Pending {
            return Err(DomainError::InvalidCallTransition {
                from: self.state,
                command: "start_connecting",
            });
        }
        if setup_deadline <= at {
            return Err(DomainError::DeadlineNotFuture);
        }

        self.set_call_state(CallState::Connecting, at);
        let mut effects = Vec::with_capacity(3);
        for leg in &mut self.legs {
            if leg.direction == LegDirection::Inbound {
                leg.state = LegState::AwaitingAttach;
                leg.state_changed_at = at;
                effects.push(EffectIntent::AwaitLegAttachment {
                    leg_id: leg.id,
                    binding_generation: leg.binding_generation,
                });
            } else {
                effects.push(EffectIntent::StartLeg {
                    leg_id: leg.id,
                    binding_generation: leg.binding_generation,
                    kind: leg.kind,
                    direction: leg.direction,
                });
            }
        }
        self.arm_deadline_internal(DeadlineKind::Setup, setup_deadline, &mut effects)?;
        Ok(applied(at, effects))
    }

    fn set_leg_state(
        &mut self,
        at: DateTime<Utc>,
        leg_id: LegId,
        supplied_generation: BindingGeneration,
        next_state: LegState,
        failure: Option<FailureDetails>,
    ) -> Result<CommandResult, DomainError> {
        let index = self.leg_index(leg_id)?;
        if let Some(result) = compare_binding_generation(
            leg_id,
            self.legs[index].binding_generation,
            supplied_generation,
            at,
        )? {
            return Ok(result);
        }
        self.ensure_timestamp(at)?;
        if self.state.is_terminal() || self.state == CallState::Pending {
            return Err(DomainError::InvalidCallTransition {
                from: self.state,
                command: "set_leg_state",
            });
        }
        if next_state == LegState::Failed && failure.is_none() {
            return Err(DomainError::FailureRequired);
        }
        if next_state != LegState::Failed && failure.is_some() {
            return Err(DomainError::UnexpectedFailure);
        }

        let current_state = self.legs[index].state;
        if current_state == next_state {
            return Ok(ignored(at, CommandDisposition::IgnoredNoop));
        }
        if !valid_leg_transition(current_state, next_state) {
            return Err(DomainError::InvalidLegTransition {
                from: current_state,
                to: next_state,
            });
        }
        if self.state == CallState::Ending && current_state != LegState::Ending {
            return Err(DomainError::InvalidLegTransition {
                from: current_state,
                to: next_state,
            });
        }

        {
            let leg = &mut self.legs[index];
            leg.state = next_state;
            leg.state_changed_at = at;
            if next_state == LegState::Connected && leg.connected_at.is_none() {
                leg.connected_at = Some(at);
            }
            if next_state.is_terminal() {
                leg.ended_at = Some(at);
            }
            leg.failure = failure;
        }

        let mut effects = Vec::new();
        self.reconcile_leg_state(index, at, &mut effects)?;
        Ok(applied(at, effects))
    }

    fn rotate_leg_binding(
        &mut self,
        at: DateTime<Utc>,
        leg_id: LegId,
        supplied_generation: BindingGeneration,
    ) -> Result<CommandResult, DomainError> {
        let index = self.leg_index(leg_id)?;
        if let Some(result) = compare_binding_generation(
            leg_id,
            self.legs[index].binding_generation,
            supplied_generation,
            at,
        )? {
            return Ok(result);
        }
        self.ensure_timestamp(at)?;
        if self.state != CallState::Connecting
            || !matches!(
                self.legs[index].state,
                LegState::AwaitingAttach | LegState::Signaling
            )
        {
            return Err(DomainError::InvalidCallTransition {
                from: self.state,
                command: "rotate_leg_binding",
            });
        }

        let leg = &mut self.legs[index];
        leg.binding_generation = leg.binding_generation.next()?;
        leg.state = LegState::AwaitingAttach;
        leg.state_changed_at = at;
        let effects = vec![EffectIntent::AwaitLegAttachment {
            leg_id,
            binding_generation: leg.binding_generation,
        }];
        Ok(applied(at, effects))
    }

    fn arm_deadline_command(
        &mut self,
        at: DateTime<Utc>,
        kind: DeadlineKind,
        due_at: DateTime<Utc>,
    ) -> Result<CommandResult, DomainError> {
        self.ensure_timestamp(at)?;
        if !self.deadline_allowed(kind) {
            return Err(DomainError::InvalidCallTransition {
                from: self.state,
                command: "arm_deadline",
            });
        }
        if due_at <= at {
            return Err(DomainError::DeadlineNotFuture);
        }
        let mut effects = Vec::new();
        self.arm_deadline_internal(kind, due_at, &mut effects)?;
        Ok(applied(at, effects))
    }

    fn begin_transfer(
        &mut self,
        at: DateTime<Utc>,
        transfer_deadline: DateTime<Utc>,
    ) -> Result<CommandResult, DomainError> {
        self.ensure_timestamp(at)?;
        if self.state != CallState::Active {
            return Err(DomainError::InvalidCallTransition {
                from: self.state,
                command: "begin_transfer",
            });
        }
        if transfer_deadline <= at {
            return Err(DomainError::DeadlineNotFuture);
        }

        self.set_call_state(CallState::Transferring, at);
        let mut effects = Vec::new();
        let generation =
            self.arm_deadline_internal(DeadlineKind::Transfer, transfer_deadline, &mut effects)?;
        effects.push(EffectIntent::ExecuteTransfer {
            deadline_generation: generation,
        });
        Ok(applied(at, effects))
    }

    fn finish_transfer(
        &mut self,
        at: DateTime<Utc>,
        supplied_generation: DeadlineGeneration,
        result: TransferResult,
    ) -> Result<CommandResult, DomainError> {
        if let Some(result) =
            self.compare_deadline_generation(DeadlineKind::Transfer, supplied_generation, at)?
        {
            return Ok(result);
        }
        self.ensure_timestamp(at)?;
        if self.deadlines.get(DeadlineKind::Transfer).due_at.is_none()
            && self.state == CallState::Active
        {
            return Ok(ignored(at, CommandDisposition::IgnoredNoop));
        }
        if self.state != CallState::Transferring
            || self.deadlines.get(DeadlineKind::Transfer).due_at.is_none()
        {
            return Err(DomainError::InvalidCallTransition {
                from: self.state,
                command: "finish_transfer",
            });
        }

        let mut effects = Vec::new();
        self.cancel_deadline_internal(DeadlineKind::Transfer, &mut effects);
        if let TransferResult::Rejected(failure) = result {
            effects.push(EffectIntent::CompensateTransfer { failure });
        }
        self.set_call_state(CallState::Active, at);
        Ok(applied(at, effects))
    }

    fn begin_ending_command(
        &mut self,
        at: DateTime<Utc>,
        ending_deadline: Option<DateTime<Utc>>,
        reason: StopLegReason,
    ) -> Result<CommandResult, DomainError> {
        self.ensure_timestamp(at)?;
        if self.state.is_terminal() {
            return Err(DomainError::InvalidCallTransition {
                from: self.state,
                command: "begin_ending",
            });
        }
        if self.state == CallState::Ending && ending_deadline.is_none() {
            return Ok(ignored(at, CommandDisposition::IgnoredNoop));
        }
        if ending_deadline.is_some_and(|deadline| deadline <= at) {
            return Err(DomainError::DeadlineNotFuture);
        }

        let mut effects = Vec::new();
        self.begin_ending_internal(
            at,
            TerminalOutcome::Ended,
            reason,
            ending_deadline,
            &mut effects,
        )?;
        Ok(applied(at, effects))
    }

    fn deadline_elapsed(
        &mut self,
        at: DateTime<Utc>,
        kind: DeadlineKind,
        supplied_generation: DeadlineGeneration,
        ending_deadline: Option<DateTime<Utc>>,
    ) -> Result<CommandResult, DomainError> {
        if let Some(result) = self.compare_deadline_generation(kind, supplied_generation, at)? {
            return Ok(result);
        }
        let slot = self.deadlines.get(kind);
        let Some(due_at) = slot.due_at else {
            return Ok(ignored(at, CommandDisposition::IgnoredStaleGeneration));
        };
        self.ensure_timestamp(at)?;
        if at < due_at {
            return Err(DomainError::DeadlineNotElapsed);
        }
        if ending_deadline.is_some_and(|deadline| deadline <= at) {
            return Err(DomainError::DeadlineNotFuture);
        }
        self.deadlines.get_mut(kind).due_at = None;

        let mut effects = Vec::new();
        if kind == DeadlineKind::Ending {
            let failure =
                FailureDetails::sanitized("ending_timeout", "leg teardown deadline elapsed", false);
            for leg in &mut self.legs {
                if !leg.state.is_terminal() {
                    leg.state = LegState::Failed;
                    leg.failure = Some(failure.clone());
                    leg.ended_at = Some(at);
                    leg.state_changed_at = at;
                }
            }
            self.terminal_outcome = Some(TerminalOutcome::Failed(failure));
            self.finalize_terminal(at, &mut effects);
            return Ok(applied(at, effects));
        }

        let (code, message) = match kind {
            DeadlineKind::Setup => ("setup_timeout", "call setup deadline elapsed"),
            DeadlineKind::Media => ("media_timeout", "media activity deadline elapsed"),
            DeadlineKind::Transfer => ("transfer_timeout", "call transfer deadline elapsed"),
            DeadlineKind::Ending => unreachable!("ending deadline handled above"),
        };
        let failure = FailureDetails::sanitized(code, message, true);
        if kind == DeadlineKind::Transfer {
            effects.push(EffectIntent::CompensateTransfer {
                failure: failure.clone(),
            });
        }
        self.begin_ending_internal(
            at,
            TerminalOutcome::Failed(failure),
            StopLegReason::DeadlineExpired,
            ending_deadline,
            &mut effects,
        )?;
        Ok(applied(at, effects))
    }

    fn reconcile_leg_state(
        &mut self,
        changed_index: usize,
        at: DateTime<Utc>,
        effects: &mut Vec<EffectIntent>,
    ) -> Result<(), DomainError> {
        let changed = &self.legs[changed_index];
        if self.state == CallState::Connecting
            && self.legs.iter().all(|leg| leg.state == LegState::Connected)
        {
            self.cancel_deadline_internal(DeadlineKind::Setup, effects);
            self.set_call_state(CallState::Active, at);
            effects.push(self.bridge_media_effect());
            return Ok(());
        }

        if self.state == CallState::Ending {
            if let Some(failure) = changed.failure.clone() {
                self.terminal_outcome = Some(TerminalOutcome::Failed(failure));
            }
            if self.legs.iter().all(|leg| leg.state.is_terminal()) {
                self.finalize_terminal(at, effects);
            }
            return Ok(());
        }

        if matches!(
            changed.state,
            LegState::Ending | LegState::Ended | LegState::Failed
        ) {
            let outcome = changed
                .failure
                .clone()
                .map_or(TerminalOutcome::Ended, TerminalOutcome::Failed);
            let reason = if changed.failure.is_some() {
                StopLegReason::Failure
            } else {
                StopLegReason::PeerEnded
            };
            self.begin_ending_internal(at, outcome, reason, None, effects)?;
        }
        Ok(())
    }

    fn begin_ending_internal(
        &mut self,
        at: DateTime<Utc>,
        outcome: TerminalOutcome,
        reason: StopLegReason,
        ending_deadline: Option<DateTime<Utc>>,
        effects: &mut Vec<EffectIntent>,
    ) -> Result<(), DomainError> {
        if matches!(self.state, CallState::Active | CallState::Transferring) {
            effects.push(self.unbridge_media_effect());
        }
        self.cancel_deadline_internal(DeadlineKind::Setup, effects);
        self.cancel_deadline_internal(DeadlineKind::Media, effects);
        self.cancel_deadline_internal(DeadlineKind::Transfer, effects);

        self.terminal_outcome = match (&self.terminal_outcome, outcome) {
            (Some(TerminalOutcome::Failed(existing)), _) => {
                Some(TerminalOutcome::Failed(existing.clone()))
            }
            (_, replacement) => Some(replacement),
        };
        self.set_call_state(CallState::Ending, at);

        for leg in &mut self.legs {
            if !leg.state.is_terminal() && leg.state != LegState::Ending {
                leg.state = LegState::Ending;
                leg.state_changed_at = at;
                effects.push(EffectIntent::StopLeg {
                    leg_id: leg.id,
                    binding_generation: leg.binding_generation,
                    reason,
                });
            }
        }

        if self.legs.iter().all(|leg| leg.state.is_terminal()) {
            self.finalize_terminal(at, effects);
        } else if let Some(deadline) = ending_deadline {
            self.arm_deadline_internal(DeadlineKind::Ending, deadline, effects)?;
        }
        Ok(())
    }

    fn finalize_terminal(&mut self, at: DateTime<Utc>, effects: &mut Vec<EffectIntent>) {
        self.cancel_deadline_internal(DeadlineKind::Setup, effects);
        self.cancel_deadline_internal(DeadlineKind::Media, effects);
        self.cancel_deadline_internal(DeadlineKind::Transfer, effects);
        self.cancel_deadline_internal(DeadlineKind::Ending, effects);

        if let Some(failure) = self.legs.iter().find_map(|leg| leg.failure.clone()) {
            self.terminal_outcome = Some(TerminalOutcome::Failed(failure));
        }
        let final_state = match self.terminal_outcome {
            Some(TerminalOutcome::Failed(_)) => CallState::Failed,
            Some(TerminalOutcome::Ended) | None => {
                self.terminal_outcome = Some(TerminalOutcome::Ended);
                CallState::Ended
            }
        };
        self.set_call_state(final_state, at);
    }

    fn arm_deadline_internal(
        &mut self,
        kind: DeadlineKind,
        due_at: DateTime<Utc>,
        effects: &mut Vec<EffectIntent>,
    ) -> Result<DeadlineGeneration, DomainError> {
        self.cancel_deadline_internal(kind, effects);
        let slot = self.deadlines.get_mut(kind);
        slot.generation = slot.generation.next()?;
        slot.due_at = Some(due_at);
        effects.push(EffectIntent::ScheduleDeadline {
            kind,
            generation: slot.generation,
            due_at,
        });
        Ok(slot.generation)
    }

    fn cancel_deadline_internal(&mut self, kind: DeadlineKind, effects: &mut Vec<EffectIntent>) {
        let slot = self.deadlines.get_mut(kind);
        if slot.due_at.take().is_some() {
            effects.push(EffectIntent::CancelDeadline {
                kind,
                generation: slot.generation,
            });
        }
    }

    fn compare_deadline_generation(
        &self,
        kind: DeadlineKind,
        supplied: DeadlineGeneration,
        at: DateTime<Utc>,
    ) -> Result<Option<CommandResult>, DomainError> {
        let current = self.deadlines.get(kind).generation;
        if supplied < current {
            return Ok(Some(ignored(
                at,
                CommandDisposition::IgnoredStaleGeneration,
            )));
        }
        if supplied > current {
            return Err(DomainError::FutureDeadlineGeneration {
                kind,
                current: current.value(),
                supplied: supplied.value(),
            });
        }
        Ok(None)
    }

    fn deadline_allowed(&self, kind: DeadlineKind) -> bool {
        match kind {
            DeadlineKind::Setup => self.state == CallState::Connecting,
            DeadlineKind::Media => {
                matches!(self.state, CallState::Active | CallState::Transferring)
            }
            DeadlineKind::Transfer => self.state == CallState::Transferring,
            DeadlineKind::Ending => self.state == CallState::Ending,
        }
    }

    fn leg_index(&self, id: LegId) -> Result<usize, DomainError> {
        self.legs
            .iter()
            .position(|leg| leg.id == id)
            .ok_or(DomainError::UnknownLeg(id))
    }

    fn ensure_timestamp(&self, at: DateTime<Utc>) -> Result<(), DomainError> {
        if at < self.updated_at {
            Err(DomainError::TimestampRegression)
        } else {
            Ok(())
        }
    }

    fn set_call_state(&mut self, state: CallState, at: DateTime<Utc>) {
        if self.state != state {
            self.state = state;
            self.state_changed_at = at;
        }
    }

    fn bridge_media_effect(&self) -> EffectIntent {
        EffectIntent::BridgeMedia {
            left_leg_id: self.legs[0].id,
            right_leg_id: self.legs[1].id,
        }
    }

    fn unbridge_media_effect(&self) -> EffectIntent {
        EffectIntent::UnbridgeMedia {
            left_leg_id: self.legs[0].id,
            right_leg_id: self.legs[1].id,
        }
    }
}

fn compare_binding_generation(
    leg_id: LegId,
    current: BindingGeneration,
    supplied: BindingGeneration,
    at: DateTime<Utc>,
) -> Result<Option<CommandResult>, DomainError> {
    if supplied < current {
        return Ok(Some(ignored(
            at,
            CommandDisposition::IgnoredStaleGeneration,
        )));
    }
    if supplied > current {
        return Err(DomainError::FutureBindingGeneration {
            leg_id,
            current: current.value(),
            supplied: supplied.value(),
        });
    }
    Ok(None)
}

fn valid_leg_transition(from: LegState, to: LegState) -> bool {
    match from {
        LegState::Pending => matches!(
            to,
            LegState::AwaitingAttach | LegState::Signaling | LegState::Ending | LegState::Failed
        ),
        LegState::AwaitingAttach => {
            matches!(
                to,
                LegState::Signaling | LegState::Ending | LegState::Failed
            )
        }
        LegState::Signaling => {
            matches!(
                to,
                LegState::Connected | LegState::Ending | LegState::Failed
            )
        }
        LegState::Connected => matches!(
            to,
            LegState::Held | LegState::Ending | LegState::Ended | LegState::Failed
        ),
        LegState::Held => matches!(
            to,
            LegState::Connected | LegState::Ending | LegState::Ended | LegState::Failed
        ),
        LegState::Ending => matches!(to, LegState::Ended | LegState::Failed),
        LegState::Ended | LegState::Failed => false,
    }
}

fn applied(at: DateTime<Utc>, effects: Vec<EffectIntent>) -> CommandResult {
    CommandResult {
        at,
        effects,
        disposition: CommandDisposition::Applied,
    }
}

fn ignored(at: DateTime<Utc>, disposition: CommandDisposition) -> CommandResult {
    CommandResult {
        at,
        effects: Vec::new(),
        disposition,
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use serde_json::json;

    use super::*;

    const ALL_LEG_STATES: [LegState; 8] = [
        LegState::Pending,
        LegState::AwaitingAttach,
        LegState::Signaling,
        LegState::Connected,
        LegState::Held,
        LegState::Ending,
        LegState::Ended,
        LegState::Failed,
    ];

    fn at(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_735_689_600 + seconds, 0)
            .single()
            .expect("valid test time")
    }

    fn test_call() -> CallAggregate {
        CallAggregate::with_ids(
            CallId::from_uuid(Uuid::from_u128(1)).expect("valid call ID"),
            TenantId::parse("tenant-a").expect("valid tenant"),
            [
                (
                    LegId::from_uuid(Uuid::from_u128(2)).expect("valid leg ID"),
                    LegSpec {
                        direction: LegDirection::Inbound,
                        kind: LegKind::Sip,
                    },
                ),
                (
                    LegId::from_uuid(Uuid::from_u128(3)).expect("valid leg ID"),
                    LegSpec {
                        direction: LegDirection::Outbound,
                        kind: LegKind::InteractiveWebRtc,
                    },
                ),
            ],
            at(0),
        )
        .expect("valid call")
    }

    fn decide(call: &CallAggregate, command: CallCommand) -> CallDecision {
        call.decide(command).expect("valid transition")
    }

    fn start(call: &CallAggregate) -> CallAggregate {
        decide(
            call,
            CallCommand::StartConnecting {
                at: at(1),
                setup_deadline: at(60),
            },
        )
        .into_parts()
        .0
    }

    fn set_leg(
        call: &CallAggregate,
        leg_id: LegId,
        state: LegState,
        at: DateTime<Utc>,
    ) -> CallDecision {
        let generation = call
            .leg(leg_id)
            .expect("known test leg")
            .binding_generation();
        decide(
            call,
            CallCommand::SetLegState {
                at,
                leg_id,
                binding_generation: generation,
                state,
                failure: None,
            },
        )
    }

    fn active_call() -> CallAggregate {
        let mut call = start(&test_call());
        let left = call.legs()[0].id();
        let right = call.legs()[1].id();
        call = set_leg(&call, left, LegState::Signaling, at(2))
            .into_parts()
            .0;
        call = set_leg(&call, right, LegState::Signaling, at(3))
            .into_parts()
            .0;
        call = set_leg(&call, left, LegState::Connected, at(4))
            .into_parts()
            .0;
        set_leg(&call, right, LegState::Connected, at(5))
            .into_parts()
            .0
    }

    #[test]
    fn call_has_exactly_two_distinct_typed_legs() {
        let call = test_call();
        assert_eq!(call.legs().len(), 2);
        assert_ne!(call.legs()[0].id(), call.legs()[1].id());
        assert_eq!(call.legs()[0].direction(), LegDirection::Inbound);
        assert_eq!(call.legs()[1].kind(), LegKind::InteractiveWebRtc);

        let duplicate = CallAggregate::with_ids(
            call.id(),
            call.tenant_id().clone(),
            [
                (
                    call.legs()[0].id(),
                    LegSpec {
                        direction: LegDirection::Inbound,
                        kind: LegKind::Sip,
                    },
                ),
                (
                    call.legs()[0].id(),
                    LegSpec {
                        direction: LegDirection::Outbound,
                        kind: LegKind::Whip,
                    },
                ),
            ],
            at(0),
        );
        assert_eq!(
            duplicate,
            Err(DomainError::DuplicateLegId(call.legs()[0].id()))
        );
    }

    #[test]
    fn aggregate_deserialization_enforces_two_leg_invariant() {
        let call = test_call();
        let mut one_leg = serde_json::to_value(&call).expect("serialize");
        one_leg["legs"].as_array_mut().expect("leg array").pop();
        assert!(serde_json::from_value::<CallAggregate>(one_leg).is_err());

        let mut three_legs = serde_json::to_value(&call).expect("serialize");
        let extra = three_legs["legs"][0].clone();
        three_legs["legs"]
            .as_array_mut()
            .expect("leg array")
            .push(extra);
        assert!(serde_json::from_value::<CallAggregate>(three_legs).is_err());

        let mut duplicate = serde_json::to_value(&call).expect("serialize");
        duplicate["legs"][1]["id"] = duplicate["legs"][0]["id"].clone();
        assert!(serde_json::from_value::<CallAggregate>(duplicate).is_err());
    }

    #[test]
    fn start_atomically_awaits_inbound_and_starts_outbound_leg() {
        let call = test_call();
        let decision = decide(
            &call,
            CallCommand::StartConnecting {
                at: at(1),
                setup_deadline: at(60),
            },
        );
        assert_eq!(decision.aggregate().state(), CallState::Connecting);
        assert_eq!(
            decision.aggregate().legs()[0].state(),
            LegState::AwaitingAttach
        );
        assert_eq!(decision.aggregate().legs()[1].state(), LegState::Pending);
        assert!(decision.effects().iter().any(|effect| matches!(
            effect,
            EffectIntent::AwaitLegAttachment { leg_id, .. }
                if *leg_id == call.legs()[0].id()
        )));
        assert!(decision.effects().iter().any(|effect| matches!(
            effect,
            EffectIntent::StartLeg { leg_id, .. } if *leg_id == call.legs()[1].id()
        )));
        assert!(decision.effects().iter().any(|effect| matches!(
            effect,
            EffectIntent::ScheduleDeadline {
                kind: DeadlineKind::Setup,
                generation,
                due_at,
            } if generation.value() == 1 && *due_at == at(60)
        )));
        assert_eq!(call.state(), CallState::Pending, "decision must be pure");
        assert_eq!(decision.aggregate().version().value(), 1);
    }

    #[test]
    fn both_connected_activates_and_bridges_once() {
        let call = active_call();
        assert_eq!(call.state(), CallState::Active);
        assert!(call.deadlines().get(DeadlineKind::Setup).due_at().is_none());

        let before_last = {
            let mut call = start(&test_call());
            let left = call.legs()[0].id();
            let right = call.legs()[1].id();
            call = set_leg(&call, left, LegState::Signaling, at(2))
                .into_parts()
                .0;
            call = set_leg(&call, right, LegState::Signaling, at(3))
                .into_parts()
                .0;
            call = set_leg(&call, left, LegState::Connected, at(4))
                .into_parts()
                .0;
            call
        };
        let right = before_last.legs()[1].id();
        let decision = set_leg(&before_last, right, LegState::Connected, at(5));
        assert_eq!(
            decision
                .effects()
                .iter()
                .filter(|effect| matches!(effect, EffectIntent::BridgeMedia { .. }))
                .count(),
            1
        );
        assert!(decision.effects().iter().any(|effect| matches!(
            effect,
            EffectIntent::CancelDeadline {
                kind: DeadlineKind::Setup,
                ..
            }
        )));
    }

    #[test]
    fn leg_transition_matrix_is_explicit_and_terminal_states_are_closed() {
        for from in ALL_LEG_STATES {
            for to in ALL_LEG_STATES {
                let expected = match from {
                    LegState::Pending => matches!(
                        to,
                        LegState::AwaitingAttach
                            | LegState::Signaling
                            | LegState::Ending
                            | LegState::Failed
                    ),
                    LegState::AwaitingAttach => matches!(
                        to,
                        LegState::Signaling | LegState::Ending | LegState::Failed
                    ),
                    LegState::Signaling => matches!(
                        to,
                        LegState::Connected | LegState::Ending | LegState::Failed
                    ),
                    LegState::Connected => matches!(
                        to,
                        LegState::Held | LegState::Ending | LegState::Ended | LegState::Failed
                    ),
                    LegState::Held => matches!(
                        to,
                        LegState::Connected | LegState::Ending | LegState::Ended | LegState::Failed
                    ),
                    LegState::Ending => matches!(to, LegState::Ended | LegState::Failed),
                    LegState::Ended | LegState::Failed => false,
                };
                assert_eq!(
                    valid_leg_transition(from, to),
                    expected,
                    "transition {from:?} -> {to:?}"
                );
            }
        }
    }

    #[test]
    fn invalid_transitions_leave_original_snapshot_unchanged() {
        let call = start(&test_call());
        let snapshot = call.clone();
        let leg_id = call.legs()[1].id();
        let error = call
            .decide(CallCommand::SetLegState {
                at: at(2),
                leg_id,
                binding_generation: call.legs()[1].binding_generation(),
                state: LegState::Connected,
                failure: None,
            })
            .expect_err("pending cannot jump to connected");
        assert_eq!(
            error,
            DomainError::InvalidLegTransition {
                from: LegState::Pending,
                to: LegState::Connected,
            }
        );
        assert_eq!(call, snapshot);

        assert!(matches!(
            call.decide(CallCommand::StartConnecting {
                at: at(2),
                setup_deadline: at(60),
            }),
            Err(DomainError::InvalidCallTransition { .. })
        ));
    }

    #[test]
    fn binding_rotation_rejects_future_and_ignores_stale_reports() {
        let call = start(&test_call());
        let leg_id = call.legs()[0].id();
        let old_generation = call.legs()[0].binding_generation();
        let rotated = decide(
            &call,
            CallCommand::RotateLegBinding {
                at: at(2),
                leg_id,
                binding_generation: old_generation,
            },
        )
        .into_parts()
        .0;
        assert_eq!(
            rotated
                .leg(leg_id)
                .expect("leg")
                .binding_generation()
                .value(),
            2
        );

        let stale = decide(
            &rotated,
            CallCommand::SetLegState {
                at: at(1),
                leg_id,
                binding_generation: old_generation,
                state: LegState::Signaling,
                failure: None,
            },
        );
        assert_eq!(
            stale.disposition(),
            CommandDisposition::IgnoredStaleGeneration
        );
        assert_eq!(stale.aggregate(), &rotated);
        assert!(stale.effects().is_empty());

        let future = rotated.decide(CallCommand::SetLegState {
            at: at(3),
            leg_id,
            binding_generation: BindingGeneration(3),
            state: LegState::Signaling,
            failure: None,
        });
        assert!(matches!(
            future,
            Err(DomainError::FutureBindingGeneration { supplied: 3, .. })
        ));
    }

    #[test]
    fn refreshed_deadline_ignores_old_generation_without_touching_version() {
        let call = start(&test_call());
        let old_generation = call.deadlines().get(DeadlineKind::Setup).generation();
        let refreshed = decide(
            &call,
            CallCommand::ArmDeadline {
                at: at(2),
                kind: DeadlineKind::Setup,
                due_at: at(90),
            },
        )
        .into_parts()
        .0;
        assert_eq!(
            refreshed
                .deadlines()
                .get(DeadlineKind::Setup)
                .generation()
                .value(),
            2
        );

        let stale = decide(
            &refreshed,
            CallCommand::DeadlineElapsed {
                at: at(60),
                kind: DeadlineKind::Setup,
                generation: old_generation,
                ending_deadline: Some(at(70)),
            },
        );
        assert_eq!(
            stale.disposition(),
            CommandDisposition::IgnoredStaleGeneration
        );
        assert_eq!(stale.aggregate(), &refreshed);
    }

    #[test]
    fn deadline_cannot_fire_early_and_setup_timeout_starts_failed_teardown() {
        let call = start(&test_call());
        let generation = call.deadlines().get(DeadlineKind::Setup).generation();
        assert_eq!(
            call.decide(CallCommand::DeadlineElapsed {
                at: at(59),
                kind: DeadlineKind::Setup,
                generation,
                ending_deadline: Some(at(70)),
            }),
            Err(DomainError::DeadlineNotElapsed)
        );

        let decision = decide(
            &call,
            CallCommand::DeadlineElapsed {
                at: at(60),
                kind: DeadlineKind::Setup,
                generation,
                ending_deadline: Some(at(70)),
            },
        );
        assert_eq!(decision.aggregate().state(), CallState::Ending);
        assert!(matches!(
            decision.aggregate().terminal_outcome(),
            Some(TerminalOutcome::Failed(failure)) if failure.code() == "setup_timeout"
        ));
        assert!(decision
            .aggregate()
            .legs()
            .iter()
            .all(|leg| leg.state() == LegState::Ending));
        assert_eq!(
            decision
                .effects()
                .iter()
                .filter(|effect| matches!(effect, EffectIntent::StopLeg { .. }))
                .count(),
            2
        );
        assert_eq!(
            decision
                .aggregate()
                .deadlines()
                .get(DeadlineKind::Ending)
                .due_at(),
            Some(at(70))
        );
    }

    #[test]
    fn ending_deadline_forces_two_terminal_failed_legs() {
        let call = start(&test_call());
        let ending = decide(
            &call,
            CallCommand::BeginEnding {
                at: at(2),
                ending_deadline: Some(at(10)),
                reason: StopLegReason::Requested,
            },
        )
        .into_parts()
        .0;
        let generation = ending.deadlines().get(DeadlineKind::Ending).generation();
        let terminal = decide(
            &ending,
            CallCommand::DeadlineElapsed {
                at: at(10),
                kind: DeadlineKind::Ending,
                generation,
                ending_deadline: None,
            },
        )
        .into_parts()
        .0;
        assert_eq!(terminal.state(), CallState::Failed);
        assert!(terminal
            .legs()
            .iter()
            .all(|leg| leg.state() == LegState::Failed));
        assert!(terminal.legs().iter().all(|leg| leg
            .failure()
            .is_some_and(|failure| failure.code() == "ending_timeout")));
    }

    #[test]
    fn remote_hangup_unbridges_stops_peer_and_finishes_normally() {
        let call = active_call();
        let left = call.legs()[0].id();
        let right = call.legs()[1].id();
        let ending = set_leg(&call, left, LegState::Ended, at(6));
        assert_eq!(ending.aggregate().state(), CallState::Ending);
        assert_eq!(
            ending.aggregate().leg(right).expect("right").state(),
            LegState::Ending
        );
        assert!(ending
            .effects()
            .iter()
            .any(|effect| matches!(effect, EffectIntent::UnbridgeMedia { .. })));
        assert!(ending.effects().iter().any(|effect| matches!(
            effect,
            EffectIntent::StopLeg {
                leg_id,
                reason: StopLegReason::PeerEnded,
                ..
            } if *leg_id == right
        )));

        let terminal = set_leg(ending.aggregate(), right, LegState::Ended, at(7))
            .into_parts()
            .0;
        assert_eq!(terminal.state(), CallState::Ended);
        assert_eq!(terminal.terminal_outcome(), Some(&TerminalOutcome::Ended));
    }

    #[test]
    fn leg_failure_survives_peer_teardown_and_fails_call() {
        let mut call = start(&test_call());
        let left = call.legs()[0].id();
        let right = call.legs()[1].id();
        call = set_leg(&call, left, LegState::Signaling, at(2))
            .into_parts()
            .0;
        let generation = call.leg(left).expect("left").binding_generation();
        let failure = FailureDetails::new("sip_rejected", "remote rejected INVITE", false)
            .expect("safe failure");
        let ending = decide(
            &call,
            CallCommand::SetLegState {
                at: at(3),
                leg_id: left,
                binding_generation: generation,
                state: LegState::Failed,
                failure: Some(failure.clone()),
            },
        );
        assert_eq!(ending.aggregate().state(), CallState::Ending);
        assert_eq!(
            ending.aggregate().terminal_outcome(),
            Some(&TerminalOutcome::Failed(failure.clone()))
        );
        let terminal = set_leg(ending.aggregate(), right, LegState::Ended, at(4))
            .into_parts()
            .0;
        assert_eq!(terminal.state(), CallState::Failed);
        assert_eq!(
            terminal.terminal_outcome(),
            Some(&TerminalOutcome::Failed(failure))
        );
    }

    #[test]
    fn transfer_generations_correlate_results_and_rejections_compensate() {
        let call = active_call();
        let first = decide(
            &call,
            CallCommand::BeginTransfer {
                at: at(6),
                transfer_deadline: at(20),
            },
        );
        assert_eq!(first.aggregate().state(), CallState::Transferring);
        let first_generation = first
            .aggregate()
            .deadlines()
            .get(DeadlineKind::Transfer)
            .generation();
        let active = decide(
            first.aggregate(),
            CallCommand::FinishTransfer {
                at: at(7),
                deadline_generation: first_generation,
                result: TransferResult::Completed,
            },
        )
        .into_parts()
        .0;
        assert_eq!(active.state(), CallState::Active);

        let second = decide(
            &active,
            CallCommand::BeginTransfer {
                at: at(8),
                transfer_deadline: at(30),
            },
        );
        let second_generation = second
            .aggregate()
            .deadlines()
            .get(DeadlineKind::Transfer)
            .generation();
        assert!(second_generation > first_generation);

        let stale = decide(
            second.aggregate(),
            CallCommand::FinishTransfer {
                at: at(7),
                deadline_generation: first_generation,
                result: TransferResult::Completed,
            },
        );
        assert_eq!(
            stale.disposition(),
            CommandDisposition::IgnoredStaleGeneration
        );
        assert_eq!(stale.aggregate(), second.aggregate());

        let failure = FailureDetails::new("provider_rejected", "transfer rejected", true)
            .expect("safe failure");
        let rejected = decide(
            second.aggregate(),
            CallCommand::FinishTransfer {
                at: at(9),
                deadline_generation: second_generation,
                result: TransferResult::Rejected(failure.clone()),
            },
        );
        assert_eq!(rejected.aggregate().state(), CallState::Active);
        assert!(rejected
            .effects()
            .contains(&EffectIntent::CompensateTransfer { failure }));
    }

    #[test]
    fn failure_details_are_bounded_single_line_and_validated_on_decode() {
        assert!(FailureDetails::new("BAD CODE", "line one\nline two", false).is_err());
        let sanitized =
            FailureDetails::sanitized("Provider Error!", "  first\nsecond\tthird  ", true);
        assert_eq!(sanitized.code(), "provider_error");
        assert_eq!(sanitized.message(), "first second third");
        assert!(sanitized.retryable());

        let unsafe_json = json!({
            "code": "bad code",
            "message": "line one\nline two",
            "retryable": false
        });
        assert!(serde_json::from_value::<FailureDetails>(unsafe_json).is_err());

        let oversized = "x".repeat(MAX_FAILURE_MESSAGE_CHARS + 10);
        let bounded = FailureDetails::sanitized("x", &oversized, false);
        assert_eq!(bounded.message().chars().count(), MAX_FAILURE_MESSAGE_CHARS);
    }

    #[test]
    fn commands_effects_and_aggregate_round_trip_without_losing_types() {
        let call = active_call();
        let command = CallCommand::BeginTransfer {
            at: at(6),
            transfer_deadline: at(20),
        };
        let command_json = serde_json::to_vec(&command).expect("serialize command");
        assert_eq!(
            serde_json::from_slice::<CallCommand>(&command_json).expect("decode command"),
            command
        );

        let decision = decide(&call, command);
        let decision_json = serde_json::to_vec(&decision).expect("serialize decision");
        let decoded =
            serde_json::from_slice::<CallDecision>(&decision_json).expect("decode decision");
        assert_eq!(decoded, decision);

        let aggregate_json = serde_json::to_vec(decision.aggregate()).expect("serialize aggregate");
        assert_eq!(
            serde_json::from_slice::<CallAggregate>(&aggregate_json).expect("decode aggregate"),
            *decision.aggregate()
        );
    }

    #[test]
    fn enum_wire_names_cover_every_supported_leg_and_exact_state() {
        let kinds = [
            LegKind::Sip,
            LegKind::InteractiveWebRtc,
            LegKind::Whip,
            LegKind::Whep,
            LegKind::AmazonConnect,
            LegKind::Twilio,
            LegKind::Telnyx,
            LegKind::Vonage,
        ];
        let expected_kinds = [
            "\"sip\"",
            "\"webrtc\"",
            "\"whip\"",
            "\"whep\"",
            "\"amazon_connect\"",
            "\"twilio\"",
            "\"telnyx\"",
            "\"vonage\"",
        ];
        for (kind, expected) in kinds.into_iter().zip(expected_kinds) {
            assert_eq!(serde_json::to_string(&kind).expect("kind"), expected);
        }

        let call_states = [
            CallState::Pending,
            CallState::Connecting,
            CallState::Active,
            CallState::Transferring,
            CallState::Ending,
            CallState::Ended,
            CallState::Failed,
        ];
        let expected_states = [
            "pending",
            "connecting",
            "active",
            "transferring",
            "ending",
            "ended",
            "failed",
        ];
        for (state, expected) in call_states.into_iter().zip(expected_states) {
            assert_eq!(
                serde_json::to_string(&state).expect("state"),
                format!("\"{expected}\"")
            );
        }

        let expected_leg_states = [
            "pending",
            "awaiting_attach",
            "signaling",
            "connected",
            "held",
            "ending",
            "ended",
            "failed",
        ];
        for (state, expected) in ALL_LEG_STATES.into_iter().zip(expected_leg_states) {
            assert_eq!(
                serde_json::to_string(&state).expect("leg state"),
                format!("\"{expected}\"")
            );
        }
    }

    #[test]
    fn timestamps_and_deadlines_are_monotonic_utc_values() {
        let call = start(&test_call());
        assert_eq!(
            call.decide(CallCommand::ArmDeadline {
                at: at(0),
                kind: DeadlineKind::Setup,
                due_at: at(100),
            }),
            Err(DomainError::TimestampRegression)
        );
        assert_eq!(
            call.decide(CallCommand::ArmDeadline {
                at: at(2),
                kind: DeadlineKind::Setup,
                due_at: at(2),
            }),
            Err(DomainError::DeadlineNotFuture)
        );
        assert_eq!(
            call.decide(CallCommand::ArmDeadline {
                at: at(2),
                kind: DeadlineKind::Transfer,
                due_at: at(3),
            }),
            Err(DomainError::InvalidCallTransition {
                from: CallState::Connecting,
                command: "arm_deadline",
            })
        );

        let serialized = serde_json::to_string(&call).expect("serialize timestamps");
        assert!(serialized.contains("2025-01-01T00:00:01Z"));
    }

    #[test]
    fn counters_fit_signed_database_columns_and_reject_overflow_on_decode() {
        let call = start(&test_call());
        assert_eq!(call.version().as_i64(), 1);
        assert_eq!(call.legs()[0].binding_generation().as_i64(), 1);
        assert_eq!(
            call.deadlines()
                .get(DeadlineKind::Setup)
                .generation()
                .as_i64(),
            1
        );
        let out_of_range = (i64::MAX as u64) + 1;
        assert!(serde_json::from_str::<AggregateVersion>(&out_of_range.to_string()).is_err());
        assert!(serde_json::from_str::<BindingGeneration>("0").is_err());
        assert!(serde_json::from_str::<DeadlineGeneration>(&out_of_range.to_string()).is_err());
    }

    #[test]
    fn property_like_valid_command_sequence_preserves_invariants_and_versions() {
        let mut call = test_call();
        let commands = [
            CallCommand::StartConnecting {
                at: at(1),
                setup_deadline: at(100),
            },
            CallCommand::SetLegState {
                at: at(2),
                leg_id: call.legs()[0].id(),
                binding_generation: BindingGeneration::INITIAL,
                state: LegState::Signaling,
                failure: None,
            },
            CallCommand::SetLegState {
                at: at(3),
                leg_id: call.legs()[1].id(),
                binding_generation: BindingGeneration::INITIAL,
                state: LegState::Signaling,
                failure: None,
            },
            CallCommand::SetLegState {
                at: at(4),
                leg_id: call.legs()[0].id(),
                binding_generation: BindingGeneration::INITIAL,
                state: LegState::Connected,
                failure: None,
            },
            CallCommand::SetLegState {
                at: at(5),
                leg_id: call.legs()[1].id(),
                binding_generation: BindingGeneration::INITIAL,
                state: LegState::Connected,
                failure: None,
            },
            CallCommand::ArmDeadline {
                at: at(6),
                kind: DeadlineKind::Media,
                due_at: at(120),
            },
            CallCommand::BeginTransfer {
                at: at(7),
                transfer_deadline: at(30),
            },
            CallCommand::FinishTransfer {
                at: at(8),
                deadline_generation: DeadlineGeneration(1),
                result: TransferResult::Completed,
            },
            CallCommand::BeginEnding {
                at: at(9),
                ending_deadline: Some(at(40)),
                reason: StopLegReason::Requested,
            },
            CallCommand::SetLegState {
                at: at(10),
                leg_id: call.legs()[0].id(),
                binding_generation: BindingGeneration::INITIAL,
                state: LegState::Ended,
                failure: None,
            },
            CallCommand::SetLegState {
                at: at(11),
                leg_id: call.legs()[1].id(),
                binding_generation: BindingGeneration::INITIAL,
                state: LegState::Ended,
                failure: None,
            },
        ];

        for (index, command) in commands.into_iter().enumerate() {
            let decision = call.decide(command).expect("sequence transition");
            assert_eq!(decision.disposition(), CommandDisposition::Applied);
            call = decision.into_parts().0;
            assert_eq!(call.version().value(), (index + 1) as u64);
            call.validate().expect("invariants after every command");
            let encoded = serde_json::to_vec(&call).expect("encode snapshot");
            call = serde_json::from_slice(&encoded).expect("decode snapshot");
        }
        assert_eq!(call.state(), CallState::Ended);
        assert!(call
            .deadlines()
            .get(DeadlineKind::Ending)
            .due_at()
            .is_none());
        assert!(call.updated_at() - call.created_at() == Duration::seconds(11));
    }
}
