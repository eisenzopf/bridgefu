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
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SipEndpointConfig {
    /// Remote SIP or SIPS URI. Required for outbound legs.
    pub uri: Option<String>,
}

impl fmt::Debug for SipEndpointConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SipEndpointConfig")
            .field("uri", &redacted_optional(&self.uri))
            .finish()
    }
}

/// Interactive WebRTC signaling endpoint.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct WebRtcEndpointConfig {
    /// Remote HTTP(S) or WS(S) signaling URI. Inbound attachments may omit it.
    pub signaling_uri: Option<String>,
}

impl fmt::Debug for WebRtcEndpointConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebRtcEndpointConfig")
            .field("signaling_uri", &redacted_optional(&self.signaling_uri))
            .finish()
    }
}

/// WHIP endpoint configuration.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct WhipEndpointConfig {
    /// Remote HTTP(S) endpoint. Inbound server legs may omit it.
    pub endpoint_uri: Option<String>,
}

impl fmt::Debug for WhipEndpointConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WhipEndpointConfig")
            .field("endpoint_uri", &redacted_optional(&self.endpoint_uri))
            .finish()
    }
}

/// WHEP endpoint configuration.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct WhepEndpointConfig {
    /// Remote HTTP(S) endpoint. Inbound server legs may omit it.
    pub endpoint_uri: Option<String>,
}

impl fmt::Debug for WhepEndpointConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WhepEndpointConfig")
            .field("endpoint_uri", &redacted_optional(&self.endpoint_uri))
            .finish()
    }
}

/// Amazon Connect WebRTC endpoint identifiers.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AmazonConnectEndpointConfig {
    /// Configured Connect instance identifier, never an AWS credential.
    pub instance_id: String,
    /// Contact-flow identifier used by `StartWebRTCContact`.
    pub contact_flow_id: String,
}

impl fmt::Debug for AmazonConnectEndpointConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AmazonConnectEndpointConfig")
            .field("instance_id", &"[redacted]")
            .field("contact_flow_id", &"[redacted]")
            .finish()
    }
}

/// Provider-controlled call endpoint.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderEndpointConfig {
    /// Native provider family.
    pub provider: ProviderKind,
    /// Name of a separately configured credential profile.
    pub account_profile: String,
    /// Provider destination. Inbound provider legs may omit it.
    pub destination: Option<String>,
}

impl fmt::Debug for ProviderEndpointConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderEndpointConfig")
            .field("provider", &self.provider)
            .field("account_profile", &"[redacted]")
            .field("destination", &redacted_optional(&self.destination))
            .finish()
    }
}

/// Typed, credential-free endpoint configuration for one logical leg.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "config", rename_all = "snake_case")]
pub enum LegEndpointConfig {
    /// SIP/RTP endpoint.
    Sip(SipEndpointConfig),
    /// Interactive WebRTC endpoint.
    #[serde(rename = "webrtc", alias = "web_rtc")]
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
    /// Signaling/provider kind represented by this endpoint.
    #[must_use]
    pub fn kind(&self) -> LegKind {
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
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
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

impl fmt::Debug for TransferTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sip { .. } => formatter
                .debug_struct("Sip")
                .field("uri", &"[redacted]")
                .finish(),
            Self::WebRtc { .. } => formatter
                .debug_struct("WebRtc")
                .field("uri", &"[redacted]")
                .finish(),
            Self::AmazonConnect { .. } => formatter
                .debug_struct("AmazonConnect")
                .field("instance_id", &"[redacted]")
                .field("contact_flow_id", &"[redacted]")
                .finish(),
            Self::Provider { provider, .. } => formatter
                .debug_struct("Provider")
                .field("provider", provider)
                .field("account_profile", &"[redacted]")
                .field("destination", &"[redacted]")
                .finish(),
        }
    }
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
    let sip_destination = matches!(parsed.scheme(), "sip" | "sips");
    if !schemes.contains(&parsed.scheme())
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || (!sip_destination && has_authority_userinfo(value))
        || (sip_destination && sip_path_has_password(&parsed))
    {
        return Err(RepositoryError::InvalidInput("invalid endpoint URI"));
    }
    Ok(())
}

fn has_authority_userinfo(value: &str) -> bool {
    value
        .split_once(':')
        .and_then(|(_, remainder)| remainder.strip_prefix("//"))
        .and_then(|remainder| remainder.split(['/', '?', '#']).next())
        .is_some_and(|authority| authority.contains('@'))
}

fn sip_path_has_password(parsed: &Url) -> bool {
    parsed
        .path()
        .rsplit_once('@')
        .is_some_and(|(user, _)| user.contains(':'))
}

fn redacted_optional<T>(value: &Option<T>) -> Option<&'static str> {
    value.as_ref().map(|_| "[redacted]")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_debug_redacts_uris_destinations_and_profiles() {
        let rendered = [
            format!(
                "{:?}",
                SipEndpointConfig {
                    uri: Some("sip:+15551234567@sip.example.test".into()),
                }
            ),
            format!(
                "{:?}",
                WebRtcEndpointConfig {
                    signaling_uri: Some("wss://private-session.example.test".into()),
                }
            ),
            format!(
                "{:?}",
                WhipEndpointConfig {
                    endpoint_uri: Some("https://media.example.test/whip/private-token".into()),
                }
            ),
            format!(
                "{:?}",
                WhepEndpointConfig {
                    endpoint_uri: Some("https://media.example.test/whep/private-token".into()),
                }
            ),
            format!(
                "{:?}",
                AmazonConnectEndpointConfig {
                    instance_id: "connect-instance-private".into(),
                    contact_flow_id: "contact-flow-private".into(),
                }
            ),
            format!(
                "{:?}",
                ProviderEndpointConfig {
                    provider: ProviderKind::Twilio,
                    account_profile: "twilio-account-private".into(),
                    destination: Some("+15557654321".into()),
                }
            ),
        ];

        for debug in rendered {
            assert!(debug.contains("[redacted]"));
            for sensitive in [
                "+15551234567",
                "private-session",
                "private-token",
                "connect-instance-private",
                "contact-flow-private",
                "twilio-account-private",
                "+15557654321",
            ] {
                assert!(
                    !debug.contains(sensitive),
                    "debug output leaked {sensitive}"
                );
            }
        }
    }

    #[test]
    fn transfer_debug_redacts_every_sensitive_target_value() {
        let targets = [
            TransferTarget::Sip {
                uri: "sip:+15551234567@sip.example.test".into(),
            },
            TransferTarget::WebRtc {
                uri: "wss://signal.example.test/private-session".into(),
            },
            TransferTarget::AmazonConnect {
                instance_id: "connect-instance-private".into(),
                contact_flow_id: "contact-flow-private".into(),
            },
            TransferTarget::Provider {
                provider: ProviderKind::Telnyx,
                account_profile: "telnyx-account-private".into(),
                destination: "+15557654321".into(),
            },
        ];

        for target in targets {
            let debug = format!("{:?}", ServiceEffectPayload::Transfer { target });
            assert!(debug.contains("[redacted]"));
            for sensitive in [
                "+15551234567",
                "private-session",
                "connect-instance-private",
                "contact-flow-private",
                "telnyx-account-private",
                "+15557654321",
            ] {
                assert!(
                    !debug.contains(sensitive),
                    "debug output leaked {sensitive}"
                );
            }
        }
    }

    #[test]
    fn uri_validation_rejects_credentials_queries_and_fragments() {
        let web_schemes = &["http", "https", "ws", "wss"];
        let sip_schemes = &["sip", "sips"];

        for uri in [
            "https://api-user@signal.example.test/session",
            "https://api-user:password@signal.example.test/session",
            "wss://signal.example.test/session?access_token=private",
            "https://signal.example.test/session#private",
        ] {
            assert!(validate_uri(uri, web_schemes).is_err(), "accepted {uri}");
        }
        for uri in [
            "sip:alice:password@sip.example.test",
            "sips://alice:password@sip.example.test",
            "sip:alice@sip.example.test?token=private",
            "sip:alice@sip.example.test#private",
        ] {
            assert!(validate_uri(uri, sip_schemes).is_err(), "accepted {uri}");
        }
    }

    #[test]
    fn uri_validation_allows_sip_destinations_but_not_web_userinfo() {
        let sip_schemes = &["sip", "sips"];

        assert!(validate_uri("sip:alice@sip.example.test", sip_schemes).is_ok());
        assert!(validate_uri("sip:+15551234567@sip.example.test", sip_schemes).is_ok());
        assert!(validate_uri("sips://alice@sip.example.test", sip_schemes).is_ok());
        assert!(validate_uri(
            "https://signal.example.test/session",
            &["http", "https", "ws", "wss"]
        )
        .is_ok());
    }

    #[test]
    fn redacted_debug_does_not_change_serialization() {
        let endpoint = ProviderEndpointConfig {
            provider: ProviderKind::Vonage,
            account_profile: "provider-profile".into(),
            destination: Some("+15551234567".into()),
        };
        assert_eq!(
            serde_json::to_value(endpoint).unwrap(),
            serde_json::json!({
                "provider": "vonage",
                "account_profile": "provider-profile",
                "destination": "+15551234567",
            })
        );

        let target = TransferTarget::Provider {
            provider: ProviderKind::Twilio,
            account_profile: "provider-profile".into(),
            destination: "+15557654321".into(),
        };
        assert_eq!(
            serde_json::to_value(target).unwrap(),
            serde_json::json!({
                "type": "provider",
                "provider": "twilio",
                "account_profile": "provider-profile",
                "destination": "+15557654321",
            })
        );
    }
}
