//! Serializable service-layer execution and control models.

use std::fmt;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::call_engine::{
    CallAggregate, LegDirection, LegId, LegKind, ProviderAccountKey, ProviderCallId,
    RepositoryError,
};

/// The only execution-plan schema understood by this release.
pub const CALL_EXECUTION_PLAN_VERSION: u16 = 1;

const MAX_ENDPOINT_BYTES: usize = 2_048;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_DTMF_DIGITS: usize = 64;

/// Provider family selected by a provider-controlled leg.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// Twilio Voice.
    Twilio,
    /// Telnyx Call Control.
    Telnyx,
    /// Vonage Voice API.
    Vonage,
}

/// SIP signaling endpoint. Inbound legs may omit the URI and attach later.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SipEndpointConfig {
    /// Remote SIP or SIPS URI. Required for outbound legs.
    pub uri: Option<String>,
}

/// Interactive WebRTC signaling endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WebRtcEndpointConfig {
    /// Remote HTTP(S) or WS(S) signaling URI. Inbound attachments may omit it.
    pub signaling_uri: Option<String>,
}

/// WHIP endpoint configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WhipEndpointConfig {
    /// Remote HTTP(S) endpoint. Inbound server legs may omit it.
    pub endpoint_uri: Option<String>,
}

/// WHEP endpoint configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WhepEndpointConfig {
    /// Remote HTTP(S) endpoint. Inbound server legs may omit it.
    pub endpoint_uri: Option<String>,
}

/// Amazon Connect WebRTC endpoint identifiers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AmazonConnectEndpointConfig {
    /// Configured Connect instance identifier, never an AWS credential.
    pub instance_id: String,
    /// Contact-flow identifier used by `StartWebRTCContact`.
    pub contact_flow_id: String,
}

/// Provider-controlled call endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderEndpointConfig {
    /// Native provider family.
    pub provider: ProviderKind,
    /// Name of a separately configured credential profile.
    pub account_profile: String,
    /// Provider destination. Inbound provider legs may omit it.
    pub destination: Option<String>,
}

/// Typed, credential-free endpoint configuration for one logical leg.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "config", rename_all = "snake_case")]
pub enum LegEndpointConfig {
    /// SIP/RTP endpoint.
    Sip(SipEndpointConfig),
    /// Interactive WebRTC endpoint.
    WebRtc(WebRtcEndpointConfig),
    /// WHIP endpoint.
    Whip(WhipEndpointConfig),
    /// WHEP endpoint.
    Whep(WhepEndpointConfig),
    /// Amazon Connect specialized WebRTC endpoint.
    AmazonConnect(AmazonConnectEndpointConfig),
    /// Twilio, Telnyx, or Vonage provider-controlled endpoint.
    Provider(ProviderEndpointConfig),
}

impl LegEndpointConfig {
    fn kind(&self) -> LegKind {
        match self {
            Self::Sip(_) => LegKind::Sip,
            Self::WebRtc(_) => LegKind::InteractiveWebRtc,
            Self::Whip(_) => LegKind::Whip,
            Self::Whep(_) => LegKind::Whep,
            Self::AmazonConnect(_) => LegKind::AmazonConnect,
            Self::Provider(config) => match config.provider {
                ProviderKind::Twilio => LegKind::Twilio,
                ProviderKind::Telnyx => LegKind::Telnyx,
                ProviderKind::Vonage => LegKind::Vonage,
            },
        }
    }

    pub(crate) fn validate(&self, direction: LegDirection) -> Result<(), RepositoryError> {
        match self {
            Self::Sip(config) => validate_optional_uri(
                config.uri.as_deref(),
                direction,
                &["sip", "sips"],
                "outbound SIP leg requires a SIP URI",
            ),
            Self::WebRtc(config) => validate_optional_uri(
                config.signaling_uri.as_deref(),
                direction,
                &["http", "https", "ws", "wss"],
                "outbound WebRTC leg requires a signaling URI",
            ),
            Self::Whip(config) => validate_optional_uri(
                config.endpoint_uri.as_deref(),
                direction,
                &["http", "https"],
                "outbound WHIP leg requires an endpoint URI",
            ),
            Self::Whep(config) => validate_optional_uri(
                config.endpoint_uri.as_deref(),
                direction,
                &["http", "https"],
                "outbound WHEP leg requires an endpoint URI",
            ),
            Self::AmazonConnect(config) => {
                validate_identifier(&config.instance_id, "invalid Amazon Connect instance ID")?;
                validate_identifier(
                    &config.contact_flow_id,
                    "invalid Amazon Connect contact-flow ID",
                )
            }
            Self::Provider(config) => {
                validate_identifier(&config.account_profile, "invalid provider account profile")?;
                match config.destination.as_deref() {
                    Some(destination) => validate_bounded_value(
                        destination,
                        MAX_ENDPOINT_BYTES,
                        "invalid provider destination",
                    ),
                    None if direction == LegDirection::Inbound => Ok(()),
                    None => Err(RepositoryError::InvalidInput(
                        "outbound provider leg requires a destination",
                    )),
                }
            }
        }
    }
}

/// Execution details for one aggregate leg.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegExecutionSpec {
    /// Aggregate-owned logical leg identifier.
    pub leg_id: LegId,
    /// Endpoint selected for this leg.
    pub endpoint: LegEndpointConfig,
}

/// Immutable execution plan persisted atomically with call creation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CallExecutionPlan {
    /// Versioned schema discriminator.
    pub version: u16,
    /// Exactly two leg specifications.
    pub legs: [LegExecutionSpec; 2],
}

impl CallExecutionPlan {
    /// Builds and validates the current plan schema against an aggregate.
    pub fn new(
        aggregate: &CallAggregate,
        legs: [LegExecutionSpec; 2],
    ) -> Result<Self, RepositoryError> {
        let plan = Self {
            version: CALL_EXECUTION_PLAN_VERSION,
            legs,
        };
        plan.validate_against(aggregate)?;
        Ok(plan)
    }

    /// Verifies version, exact leg ownership, endpoint kind, and direction rules.
    pub fn validate_against(&self, aggregate: &CallAggregate) -> Result<(), RepositoryError> {
        if self.version != CALL_EXECUTION_PLAN_VERSION {
            return Err(RepositoryError::InvalidInput(
                "unsupported call execution plan version",
            ));
        }
        if self.legs[0].leg_id == self.legs[1].leg_id {
            return Err(RepositoryError::InvalidInput(
                "execution plan contains a duplicate leg",
            ));
        }
        for spec in &self.legs {
            let leg = aggregate
                .leg(spec.leg_id)
                .ok_or(RepositoryError::InvalidInput(
                    "execution plan leg does not belong to call",
                ))?;
            if leg.kind() != spec.endpoint.kind() {
                return Err(RepositoryError::InvalidInput(
                    "execution endpoint kind does not match aggregate leg",
                ));
            }
            spec.endpoint.validate(leg.direction())?;
        }
        if aggregate
            .legs()
            .iter()
            .any(|leg| !self.legs.iter().any(|spec| spec.leg_id == leg.id()))
        {
            return Err(RepositoryError::InvalidInput(
                "execution plan does not cover both aggregate legs",
            ));
        }
        Ok(())
    }
}

/// Transfer destination stored beside an `ExecuteTransfer` effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TransferTarget {
    /// SIP or SIPS transfer target.
    Sip { uri: String },
    /// HTTP(S) or WS(S) WebRTC signaling target.
    WebRtc { uri: String },
    /// Amazon Connect target identifiers.
    AmazonConnect {
        /// Configured Connect instance identifier.
        instance_id: String,
        /// Contact-flow identifier.
        contact_flow_id: String,
    },
    /// Native provider transfer target.
    Provider {
        /// Provider family.
        provider: ProviderKind,
        /// Separately configured account profile.
        account_profile: String,
        /// Provider destination.
        destination: String,
    },
}

impl TransferTarget {
    pub(crate) fn validate(&self) -> Result<(), RepositoryError> {
        match self {
            Self::Sip { uri } => validate_uri(uri, &["sip", "sips"]),
            Self::WebRtc { uri } => validate_uri(uri, &["http", "https", "ws", "wss"]),
            Self::AmazonConnect {
                instance_id,
                contact_flow_id,
            } => {
                validate_identifier(instance_id, "invalid Amazon Connect instance ID")?;
                validate_identifier(contact_flow_id, "invalid Amazon Connect contact-flow ID")
            }
            Self::Provider {
                account_profile,
                destination,
                ..
            } => {
                validate_identifier(account_profile, "invalid provider account profile")?;
                validate_bounded_value(
                    destination,
                    MAX_ENDPOINT_BYTES,
                    "invalid provider destination",
                )
            }
        }
    }
}

/// Additional service-owned data required to execute a core outbox effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServiceEffectPayload {
    /// Concrete destination for the core transfer intent.
    Transfer { target: TransferTarget },
}

impl ServiceEffectPayload {
    pub(crate) fn validate(&self) -> Result<(), RepositoryError> {
        match self {
            Self::Transfer { target } => target.validate(),
        }
    }
}

/// Validated DTMF sequence for a non-state-changing control command.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DtmfSequence {
    /// DTMF symbols (`0-9`, `*`, `#`, and `A-D`).
    pub digits: String,
    /// Tone duration in milliseconds.
    pub duration_ms: u16,
    /// Gap between tones in milliseconds.
    pub gap_ms: u16,
}

impl fmt::Debug for DtmfSequence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DtmfSequence")
            .field("digits", &"[redacted]")
            .field("digit_count", &self.digits.len())
            .field("duration_ms", &self.duration_ms)
            .field("gap_ms", &self.gap_ms)
            .finish()
    }
}

impl DtmfSequence {
    pub(crate) fn validate(&self) -> Result<(), RepositoryError> {
        if self.digits.is_empty()
            || self.digits.len() > MAX_DTMF_DIGITS
            || !self
                .digits
                .bytes()
                .all(|value| matches!(value, b'0'..=b'9' | b'*' | b'#' | b'A'..=b'D'))
        {
            return Err(RepositoryError::InvalidInput("invalid DTMF digits"));
        }
        if !(40..=6_000).contains(&self.duration_ms) || self.gap_ms > 6_000 {
            return Err(RepositoryError::InvalidInput("invalid DTMF timing"));
        }
        Ok(())
    }
}

/// Durable control intent that does not mutate the call aggregate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlIntent {
    /// Send DTMF on one current leg binding.
    Dtmf { sequence: DtmfSequence },
}

impl ControlIntent {
    pub(crate) fn validate(&self) -> Result<(), RepositoryError> {
        match self {
            Self::Dtmf { sequence } => sequence.validate(),
        }
    }
}

/// External identifier returned by a successful leg effect.
#[derive(Clone, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExternalReferenceValue {
    /// Provider call reference used to release callbacks received before originate completed.
    ProviderCall {
        /// Provider account namespace.
        account: ProviderAccountKey,
        /// Provider-owned call identifier.
        provider_call_id: ProviderCallId,
    },
    /// Non-provider signaling reference in an application-defined namespace.
    Signaling {
        /// Bounded namespace such as `webrtc-session`.
        namespace: String,
        /// Opaque external identifier.
        value: String,
    },
}

impl ExternalReferenceValue {
    pub(crate) fn validate(&self) -> Result<(), RepositoryError> {
        match self {
            Self::ProviderCall { .. } => Ok(()),
            Self::Signaling { namespace, value } => {
                validate_identifier(namespace, "invalid external reference namespace")?;
                validate_bounded_value(
                    value,
                    MAX_ENDPOINT_BYTES,
                    "invalid external reference value",
                )
            }
        }
    }
}

impl fmt::Debug for ExternalReferenceValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProviderCall { .. } => formatter
                .debug_struct("ProviderCall")
                .field("value", &"[redacted]")
                .finish(),
            Self::Signaling { namespace, .. } => formatter
                .debug_struct("Signaling")
                .field("namespace", namespace)
                .field("value", &"[redacted]")
                .finish(),
        }
    }
}

fn validate_optional_uri(
    value: Option<&str>,
    direction: LegDirection,
    schemes: &[&str],
    missing: &'static str,
) -> Result<(), RepositoryError> {
    match value {
        Some(value) => validate_uri(value, schemes),
        None if direction == LegDirection::Inbound => Ok(()),
        None => Err(RepositoryError::InvalidInput(missing)),
    }
}

fn validate_uri(value: &str, schemes: &[&str]) -> Result<(), RepositoryError> {
    validate_bounded_value(value, MAX_ENDPOINT_BYTES, "invalid endpoint URI")?;
    let parsed =
        Url::parse(value).map_err(|_| RepositoryError::InvalidInput("invalid endpoint URI"))?;
    if !schemes.contains(&parsed.scheme()) || parsed.password().is_some() {
        return Err(RepositoryError::InvalidInput("invalid endpoint URI"));
    }
    Ok(())
}

fn validate_identifier(value: &str, message: &'static str) -> Result<(), RepositoryError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        Err(RepositoryError::InvalidInput(message))
    } else {
        Ok(())
    }
}

fn validate_bounded_value(
    value: &str,
    max: usize,
    message: &'static str,
) -> Result<(), RepositoryError> {
    if value.is_empty()
        || value.len() > max
        || value
            .bytes()
            .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
    {
        Err(RepositoryError::InvalidInput(message))
    } else {
        Ok(())
    }
}
