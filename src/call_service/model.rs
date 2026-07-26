//! Serializable service-layer execution and control models.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;

use base64::Engine as _;
use rvoip_amazon_connect::{
    AmazonConnectOriginateContext, AmazonConnectTarget, ConnectClientToken, ConnectProfileId,
    MAX_ATTRIBUTE_BYTES as MAX_CONNECT_ATTRIBUTE_BYTES, MAX_CONNECT_ATTRIBUTE_COUNT,
    MAX_CONNECT_ATTRIBUTE_KEY_BYTES, MAX_CONNECT_DESCRIPTION_BYTES, MAX_CONNECT_DISPLAY_NAME_BYTES,
    MAX_CONNECT_PROFILE_ID_BYTES, MAX_CONNECT_RESOURCE_ID_BYTES,
};
use rvoip_sip::{SipInitialHeaders, SipOriginateContext};
use rvoip_webrtc::{
    WebRtcIceExchangePolicy, WebRtcOriginateContext, WebRtcSignalingMode, WebRtcTargetPolicy,
};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::call_engine::{
    CallAggregate, EffectId, LegDirection, LegId, LegKind, LegSemantics, MediaFlow,
    PrincipalFingerprint, ProviderAccountKey, ProviderCallId, RepositoryError, SignalingInitiator,
};
use crate::context::{ContextEnvelope, MAX_CONTEXT_BYTES};

/// Current execution-plan schema written by this release.
pub const CALL_EXECUTION_PLAN_VERSION: u16 = 3;

const LEGACY_CALL_EXECUTION_PLAN_VERSION: u16 = 1;
const AUTHORIZED_CALL_EXECUTION_PLAN_VERSION: u16 = 2;

const MAX_ENDPOINT_BYTES: usize = 2_048;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_DTMF_DIGITS: usize = 64;
const AMAZON_CONNECT_CLIENT_TOKEN_DOMAIN: &[u8] = b"bridgefu.amazon-connect.client-token.v1\0";

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
    /// Whether Bridgefu must durably receive a bound context envelope before
    /// it may activate the first outbound INVITE.
    #[serde(default)]
    pub initial_context: SipInitialContextMode,
}

impl fmt::Debug for SipEndpointConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SipEndpointConfig")
            .field("uri", &redacted_optional(&self.uri))
            .field("initial_context", &self.initial_context)
            .finish()
    }
}

/// First-INVITE context readiness policy for a SIP endpoint.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SipInitialContextMode {
    /// Originate immediately with no initial application headers. Context
    /// received after activation is delivered as an in-dialog SIP MESSAGE.
    #[default]
    None,
    /// Wait for one exact durable `bridgefu.context.v1` envelope and place its
    /// allowlisted values on the first INVITE.
    Required,
}

/// Interactive WebRTC signaling endpoint.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct WebRtcEndpointConfig {
    /// Remote WSS signaling URI. Inbound attachments may omit it.
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
    /// Remote HTTPS endpoint. Inbound server legs may omit it.
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
    /// Remote HTTPS endpoint. Inbound server legs may omit it.
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

/// Immutable, credential-free inputs for one Amazon Connect
/// `StartWebRTCContact` effect.
///
/// A client token is deliberately absent. The executor derives it later from
/// the immutable durable effect identity, so retries cannot persist or invent
/// a second idempotency authority.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct AmazonConnectStartSpec {
    profile: String,
    instance_id: String,
    contact_flow_id: String,
    attributes: BTreeMap<String, String>,
    display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

impl AmazonConnectStartSpec {
    /// Constructs a fully bounded, non-secret Amazon Connect start
    /// specification.
    pub fn new(
        profile: impl Into<String>,
        instance_id: impl Into<String>,
        contact_flow_id: impl Into<String>,
        attributes: BTreeMap<String, String>,
        display_name: impl Into<String>,
        description: Option<String>,
    ) -> Result<Self, RepositoryError> {
        let value = Self {
            profile: profile.into(),
            instance_id: instance_id.into(),
            contact_flow_id: contact_flow_id.into(),
            attributes,
            display_name: display_name.into(),
            description,
        };
        value.validate()?;
        Ok(value)
    }

    /// Non-secret adapter profile selected for this call. Avoid using it as a
    /// metric label.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Exact Amazon Connect instance identifier or ARN.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Exact Amazon Connect contact-flow identifier or ARN.
    #[must_use]
    pub fn contact_flow_id(&self) -> &str {
        &self.contact_flow_id
    }

    /// Exact contact attributes, sorted by key for deterministic persistence.
    #[must_use]
    pub fn attributes(&self) -> &BTreeMap<String, String> {
        &self.attributes
    }

    /// Participant display name supplied to Amazon Connect.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Optional task/contact description supplied to Amazon Connect.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Builds the exact adapter-owned context for one immutable outbox effect.
    ///
    /// The client token has one authority: SHA-256 over a versioned Bridgefu
    /// domain and the effect UUID bytes, encoded as unpadded base64url. No
    /// call, retry, process, or wall-clock value participates in derivation.
    pub fn originate_context(
        &self,
        effect_id: EffectId,
    ) -> Result<AmazonConnectOriginateContext, RepositoryError> {
        self.originate_context_with_attributes(effect_id, BTreeMap::new())
    }

    /// Builds the adapter context after merging one durably authenticated
    /// `bridgefu.context.v1` snapshot into the configured screen-pop fields.
    ///
    /// Persisted route attributes remain authoritative on collisions, so a
    /// browser can add allowlisted context but cannot override server-owned
    /// routing or tenant metadata. The caller must supply only canonical keys
    /// admitted by the configured [`crate::context::ContextPolicy`].
    pub fn originate_context_with_attributes(
        &self,
        effect_id: EffectId,
        context_attributes: BTreeMap<String, String>,
    ) -> Result<AmazonConnectOriginateContext, RepositoryError> {
        let profile_id = ConnectProfileId::new(self.profile.clone()).map_err(|_| {
            RepositoryError::InvalidInput("invalid persisted Amazon Connect profile")
        })?;
        let target =
            AmazonConnectTarget::new(self.instance_id.clone(), self.contact_flow_id.clone())
                .map_err(|_| {
                    RepositoryError::InvalidInput("invalid persisted Amazon Connect target")
                })?;
        let token =
            ConnectClientToken::new(amazon_connect_client_token(effect_id)).map_err(|_| {
                RepositoryError::InvalidInput("invalid derived Amazon Connect client token")
            })?;
        let mut attributes = self.attributes.clone();
        for (key, value) in context_attributes {
            attributes.entry(key).or_insert(value);
        }
        validate_connect_attributes(&attributes)?;
        AmazonConnectOriginateContext::new(
            profile_id,
            target,
            attributes,
            self.display_name.clone(),
            self.description.clone(),
            token,
        )
        .map_err(|_| RepositoryError::InvalidInput("invalid persisted Amazon Connect start spec"))
    }

    pub(crate) fn validate(&self) -> Result<(), RepositoryError> {
        validate_connect_profile(&self.profile)?;
        validate_connect_resource(&self.instance_id, "invalid Amazon Connect instance ID")?;
        validate_connect_resource(
            &self.contact_flow_id,
            "invalid Amazon Connect contact-flow ID",
        )?;
        validate_connect_text(
            &self.display_name,
            MAX_CONNECT_DISPLAY_NAME_BYTES,
            "invalid Amazon Connect display name",
        )?;
        if let Some(description) = self.description.as_deref() {
            validate_connect_text(
                description,
                MAX_CONNECT_DESCRIPTION_BYTES,
                "invalid Amazon Connect description",
            )?;
        }
        validate_connect_attributes(&self.attributes)
    }
}

fn amazon_connect_client_token(effect_id: EffectId) -> String {
    let mut digest = Sha256::new();
    digest.update(AMAZON_CONNECT_CLIENT_TOKEN_DOMAIN);
    digest.update(effect_id.as_uuid().as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.finalize())
}

impl fmt::Debug for AmazonConnectStartSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AmazonConnectStartSpec")
            .field("profile", &"[redacted]")
            .field("instance_id", &"[redacted]")
            .field("contact_flow_id", &"[redacted]")
            .field("attribute_count", &self.attributes.len())
            .field("display_name", &"[redacted]")
            .field("description_present", &self.description.is_some())
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AmazonConnectStartSpecWire {
    profile: String,
    instance_id: String,
    contact_flow_id: String,
    #[serde(deserialize_with = "deserialize_unique_connect_attributes")]
    attributes: BTreeMap<String, String>,
    display_name: String,
    description: Option<String>,
}

impl<'de> Deserialize<'de> for AmazonConnectStartSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AmazonConnectStartSpecWire::deserialize(deserializer)?;
        Self::new(
            wire.profile,
            wire.instance_id,
            wire.contact_flow_id,
            wire.attributes,
            wire.display_name,
            wire.description,
        )
        .map_err(de::Error::custom)
    }
}

fn deserialize_unique_connect_attributes<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct UniqueAttributesVisitor;

    impl<'de> Visitor<'de> for UniqueAttributesVisitor {
        type Value = BTreeMap<String, String>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an Amazon Connect attribute object with unique keys")
        }

        fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut attributes = BTreeMap::new();
            while let Some((key, value)) = access.next_entry::<String, String>()? {
                if attributes.insert(key, value).is_some() {
                    return Err(de::Error::custom("duplicate Amazon Connect attribute key"));
                }
            }
            Ok(attributes)
        }
    }

    deserializer.deserialize_map(UniqueAttributesVisitor)
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

    /// Exact capability a split worker must advertise for this signaling
    /// role. Ingress and egress labels are deliberately distinct so two
    /// asymmetric workers cannot be combined into one impossible call.
    pub fn required_worker_capability(
        &self,
        signaling_initiator: SignalingInitiator,
    ) -> Result<&'static str, RepositoryError> {
        match (signaling_initiator, self) {
            (SignalingInitiator::Remote, Self::Sip(_)) => Ok("sip"),
            (SignalingInitiator::Remote, Self::WebRtc(_) | Self::Whip(_) | Self::Whep(_)) => {
                Ok("webrtc")
            }
            (SignalingInitiator::Bridgefu, Self::Sip(_)) => Ok("sip_egress"),
            (SignalingInitiator::Bridgefu, Self::WebRtc(_) | Self::Whip(_) | Self::Whep(_)) => {
                Ok("webrtc_egress")
            }
            (SignalingInitiator::Bridgefu, Self::AmazonConnect(_)) => Ok("amazon_connect"),
            (
                SignalingInitiator::Bridgefu,
                Self::Provider(ProviderEndpointConfig {
                    provider: ProviderKind::Telnyx,
                    ..
                }),
            ) => Ok("telnyx"),
            (
                SignalingInitiator::Bridgefu,
                Self::Provider(ProviderEndpointConfig {
                    provider: ProviderKind::Twilio | ProviderKind::Vonage,
                    ..
                }),
            ) => Err(RepositoryError::InvalidInput(
                "provider worker capability is deferred",
            )),
            (SignalingInitiator::Remote, Self::AmazonConnect(_) | Self::Provider(_)) => Err(
                RepositoryError::InvalidInput("remote endpoint has no ingress worker capability"),
            ),
        }
    }

    /// Builds a replacement SIP target/context from a trusted persisted
    /// endpoint and a repository-fenced initial header projection.
    ///
    /// The caller must derive `initial_headers` from the immutable,
    /// source-owned context envelope under the current route policy. Live
    /// context continues over SIP MESSAGE only after promotion.
    pub(crate) fn replacement_sip_originate_context(
        &self,
        initial_headers: SipInitialHeaders,
    ) -> Result<(String, SipOriginateContext), RepositoryError> {
        let Self::Sip(config) = self else {
            return Err(RepositoryError::InvalidInput(
                "replacement endpoint is not SIP",
            ));
        };
        let target = config.uri.as_deref().ok_or(RepositoryError::InvalidInput(
            "replacement SIP endpoint has no target",
        ))?;
        validate_uri(target, &["sip", "sips"])?;
        Ok((
            target.to_owned(),
            SipOriginateContext::new().with_initial_headers(initial_headers),
        ))
    }

    /// Builds a replacement WebRTC signaling context with the exact principal
    /// credential partition retained in the replacement payload.
    pub(crate) fn replacement_web_rtc_originate_context(
        &self,
        principal: PrincipalFingerprint,
    ) -> Result<WebRtcOriginateContext, RepositoryError> {
        let (target, signaling_mode) = match self {
            Self::WebRtc(config) => config
                .signaling_uri
                .as_deref()
                .map(|target| (target, WebRtcSignalingMode::WebSocket)),
            Self::Whip(config) => config
                .endpoint_uri
                .as_deref()
                .map(|target| (target, WebRtcSignalingMode::Whip)),
            Self::Whep(config) => config
                .endpoint_uri
                .as_deref()
                .map(|target| (target, WebRtcSignalingMode::Whep)),
            _ => None,
        }
        .ok_or(RepositoryError::InvalidInput(
            "replacement WebRTC endpoint has no target",
        ))?;
        let parsed = Url::parse(target)
            .map_err(|_| RepositoryError::InvalidInput("invalid replacement WebRTC endpoint"))?;
        let context = WebRtcOriginateContext::new(
            target,
            signaling_mode,
            WebRtcIceExchangePolicy::Trickle,
            web_rtc_target_policy(&parsed, principal)?,
            None,
        )
        .map_err(|_| RepositoryError::InvalidInput("invalid replacement WebRTC context"))?;
        if signaling_mode == WebRtcSignalingMode::WebSocket {
            context.require_remote_admission_ready().map_err(|_| {
                RepositoryError::InvalidInput("invalid replacement WebRTC admission policy")
            })
        } else {
            Ok(context)
        }
    }

    pub(crate) fn validate(
        &self,
        direction: LegDirection,
        signaling_initiator: SignalingInitiator,
    ) -> Result<(), RepositoryError> {
        match self {
            Self::Sip(config) => {
                validate_optional_uri(
                    config.uri.as_deref(),
                    signaling_initiator,
                    &["sip", "sips"],
                    "Bridgefu-initiated SIP leg requires a SIP URI",
                )?;
                if config.initial_context == SipInitialContextMode::Required
                    && (direction != LegDirection::Outbound
                        || signaling_initiator != SignalingInitiator::Bridgefu)
                {
                    return Err(RepositoryError::InvalidInput(
                        "initial SIP context may be required only for an outbound Bridgefu-initiated leg",
                    ));
                }
                Ok(())
            }
            Self::WebRtc(config) => validate_optional_uri(
                config.signaling_uri.as_deref(),
                signaling_initiator,
                &["wss"],
                "Bridgefu-initiated WebRTC leg requires a signaling URI",
            ),
            Self::Whip(config) => validate_optional_uri(
                config.endpoint_uri.as_deref(),
                signaling_initiator,
                &["https"],
                "Bridgefu-initiated WHIP leg requires an endpoint URI",
            ),
            Self::Whep(config) => validate_optional_uri(
                config.endpoint_uri.as_deref(),
                signaling_initiator,
                &["https"],
                "Bridgefu-initiated WHEP leg requires an endpoint URI",
            ),
            Self::AmazonConnect(config) => {
                if direction != LegDirection::Outbound
                    || signaling_initiator != SignalingInitiator::Bridgefu
                {
                    return Err(RepositoryError::InvalidInput(
                        "Amazon Connect requires an outbound Bridgefu-initiated leg",
                    ));
                }
                validate_connect_resource(
                    &config.instance_id,
                    "invalid Amazon Connect instance ID",
                )?;
                validate_connect_resource(
                    &config.contact_flow_id,
                    "invalid Amazon Connect contact-flow ID",
                )
            }
            Self::Provider(config) => {
                if signaling_initiator != SignalingInitiator::Bridgefu {
                    return Err(RepositoryError::InvalidInput(
                        "provider-controlled legs require Bridgefu signaling initiation",
                    ));
                }
                validate_identifier(&config.account_profile, "invalid provider account profile")?;
                match config.destination.as_deref() {
                    Some(destination) => validate_bounded_value(
                        destination,
                        MAX_ENDPOINT_BYTES,
                        "invalid provider destination",
                    ),
                    None => Err(RepositoryError::InvalidInput(
                        "provider-controlled leg requires a destination",
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AmazonConnectStartBinding {
    leg_id: LegId,
    spec: AmazonConnectStartSpec,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegSemanticsBinding {
    leg_id: LegId,
    signaling_initiator: SignalingInitiator,
    media_flow: MediaFlow,
}

impl LegSemanticsBinding {
    fn from_aggregate(aggregate: &CallAggregate) -> Vec<Self> {
        aggregate
            .legs()
            .iter()
            .map(|leg| Self {
                leg_id: leg.id(),
                signaling_initiator: leg.signaling_initiator(),
                media_flow: leg.media_flow(),
            })
            .collect()
    }

    const fn semantics(self) -> LegSemantics {
        LegSemantics {
            signaling_initiator: self.signaling_initiator,
            media_flow: self.media_flow,
        }
    }
}

/// Validated media directions for one two-leg bridge effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallMediaBridgePlan {
    left_to_right: bool,
    right_to_left: bool,
}

impl CallMediaBridgePlan {
    /// Whether the left leg's source feeds the right leg's sink.
    #[must_use]
    pub const fn left_to_right(self) -> bool {
        self.left_to_right
    }

    /// Whether the right leg's source feeds the left leg's sink.
    #[must_use]
    pub const fn right_to_left(self) -> bool {
        self.right_to_left
    }
}

/// Sanitized application context supplied when a server-owned named route is
/// selected. Route context deliberately excludes tenant, call, and leg IDs:
/// those identifiers are filled from authenticated durable state at the
/// signaling boundary and may never be overridden by a caller.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedRouteCallContext {
    /// External correlation identifier carried through allowlisted adapters.
    pub correlation_id: String,
    /// Bounded application metadata. Reserved ownership keys are rejected.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

/// Stable family of a named route profile. This discriminator and a
/// non-secret revision are persisted; credential material never enters a call
/// plan.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamedProfileKind {
    VapiIngress,
    Sip,
    WebRtc,
    AmazonConnect,
    Telnyx,
}

/// Whether a profile governs the public source or configured destination.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamedProfileRole {
    Ingress,
    Destination,
}

/// Credential-free profile identity retained with a named-route call.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedProfileBinding {
    role: NamedProfileRole,
    kind: NamedProfileKind,
    profile_id: String,
    /// Lowercase SHA-256 over canonical non-secret profile configuration.
    revision: String,
}

impl NamedProfileBinding {
    pub fn new(
        role: NamedProfileRole,
        kind: NamedProfileKind,
        profile_id: impl Into<String>,
        revision: impl Into<String>,
    ) -> Result<Self, RepositoryError> {
        let binding = Self {
            role,
            kind,
            profile_id: profile_id.into(),
            revision: revision.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    #[must_use]
    pub const fn role(&self) -> NamedProfileRole {
        self.role
    }

    #[must_use]
    pub const fn kind(&self) -> NamedProfileKind {
        self.kind
    }

    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    fn validate(&self) -> Result<(), RepositoryError> {
        validate_named_profile_id(&self.profile_id)?;
        if self.revision.len() != 64
            || !self
                .revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(RepositoryError::InvalidInput(
                "invalid named profile revision",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for NamedRouteCallContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NamedRouteCallContext")
            .field("correlation_id", &"[redacted]")
            .field("metadata_entries", &self.metadata.len())
            .finish()
    }
}

impl NamedRouteCallContext {
    /// Validates the same value and size rules as `bridgefu.context.v1` while
    /// binding ownership fields to safe placeholders owned by Bridgefu.
    pub fn validate(&self) -> Result<(), RepositoryError> {
        let mut envelope = ContextEnvelope::new(
            self.correlation_id.clone(),
            "route-tenant",
            "route-call",
            "route-source-leg",
        );
        envelope.metadata.clone_from(&self.metadata);
        envelope
            .validate()
            .map_err(|_| RepositoryError::InvalidInput("invalid named-route context"))?;
        let encoded = serde_json::to_vec(self)
            .map_err(|_| RepositoryError::InvalidInput("invalid named-route context"))?;
        if encoded.len() > MAX_CONTEXT_BYTES {
            return Err(RepositoryError::InvalidInput(
                "named-route context exceeds the context envelope limit",
            ));
        }
        Ok(())
    }
}

/// Durable server-owned route selection retained beside the execution plan.
/// This is also part of call-create idempotency, so the same key cannot be
/// reused with another route or different context.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedRouteBinding {
    route_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    context: Option<NamedRouteCallContext>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    profiles: Vec<NamedProfileBinding>,
}

impl fmt::Debug for NamedRouteBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NamedRouteBinding")
            .field("route_id", &self.route_id)
            .field("context_present", &self.context.is_some())
            .field("profile_count", &self.profiles.len())
            .finish()
    }
}

impl NamedRouteBinding {
    /// Creates a bounded route binding. Route IDs are configuration keys, not
    /// arbitrary destinations, and use a deliberately small wire alphabet.
    pub fn new(
        route_id: impl Into<String>,
        context: Option<NamedRouteCallContext>,
    ) -> Result<Self, RepositoryError> {
        let binding = Self {
            route_id: route_id.into(),
            context,
            profiles: Vec::new(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Creates a route binding with the exact non-secret profile revisions
    /// that authorized ingress and destination selection.
    pub fn new_with_profiles(
        route_id: impl Into<String>,
        context: Option<NamedRouteCallContext>,
        profiles: Vec<NamedProfileBinding>,
    ) -> Result<Self, RepositoryError> {
        let binding = Self {
            route_id: route_id.into(),
            context,
            profiles,
        };
        binding.validate()?;
        Ok(binding)
    }

    #[must_use]
    pub fn route_id(&self) -> &str {
        &self.route_id
    }

    #[must_use]
    pub const fn context(&self) -> Option<&NamedRouteCallContext> {
        self.context.as_ref()
    }

    #[must_use]
    pub fn profiles(&self) -> &[NamedProfileBinding] {
        &self.profiles
    }

    pub(crate) fn validate(&self) -> Result<(), RepositoryError> {
        let valid_id = !self.route_id.is_empty()
            && self.route_id.len() <= MAX_IDENTIFIER_BYTES
            && self.route_id.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            })
            && self
                .route_id
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric);
        if !valid_id {
            return Err(RepositoryError::InvalidInput("invalid named route ID"));
        }
        if let Some(context) = &self.context {
            context.validate()?;
        }
        let mut identities = BTreeSet::new();
        for profile in &self.profiles {
            profile.validate()?;
            if !identities.insert((profile.role, profile.kind)) {
                return Err(RepositoryError::InvalidInput(
                    "named route contains duplicate profile roles",
                ));
            }
        }
        Ok(())
    }

    /// Validates a replacement route snapshot against the exact persisted
    /// endpoint selected by the trusted route catalog. Replacement context is
    /// inherited from the existing call and must never be injected by a new
    /// route selection.
    pub(crate) fn validate_replacement_destination(
        &self,
        route_id: &str,
        endpoint: &LegEndpointConfig,
    ) -> Result<(), RepositoryError> {
        self.validate()?;
        if self.route_id != route_id {
            return Err(RepositoryError::InvalidInput(
                "replacement route snapshot does not match the selected route ID",
            ));
        }
        if self.context.is_some() {
            return Err(RepositoryError::InvalidInput(
                "replacement route snapshot must not carry new call context",
            ));
        }
        let expected = match endpoint {
            LegEndpointConfig::Sip(_) => NamedProfileKind::Sip,
            LegEndpointConfig::WebRtc(_)
            | LegEndpointConfig::Whip(_)
            | LegEndpointConfig::Whep(_) => NamedProfileKind::WebRtc,
            LegEndpointConfig::AmazonConnect(_) => NamedProfileKind::AmazonConnect,
            LegEndpointConfig::Provider(provider) if provider.provider == ProviderKind::Telnyx => {
                NamedProfileKind::Telnyx
            }
            LegEndpointConfig::Provider(_) => {
                return Err(RepositoryError::InvalidInput(
                    "replacement route provider is deferred",
                ))
            }
        };
        let mut destinations = self
            .profiles
            .iter()
            .filter(|profile| profile.role == NamedProfileRole::Destination);
        let destination = destinations.next().ok_or(RepositoryError::InvalidInput(
            "replacement route has no durable destination profile",
        ))?;
        if destinations.next().is_some() || destination.kind != expected {
            return Err(RepositoryError::InvalidInput(
                "replacement route destination profile does not match its endpoint",
            ));
        }
        match endpoint {
            LegEndpointConfig::Provider(provider)
                if destination.profile_id != provider.account_profile =>
            {
                Err(RepositoryError::InvalidInput(
                    "replacement provider route does not match its account profile",
                ))
            }
            _ => Ok(()),
        }
    }
}

fn validate_named_profile_id(value: &str) -> Result<(), RepositoryError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric);
    if valid {
        Ok(())
    } else {
        Err(RepositoryError::InvalidInput("invalid named profile ID"))
    }
}

/// Scheduling policy for the initial pair of signaling effects.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupPolicy {
    /// Historical low-level API behavior: start every Bridgefu-initiated leg
    /// as soon as the call enters connecting.
    #[default]
    Parallel,
    /// Wait until the public remote-initiated source consumes its one-use
    /// attachment before dialing the configured destination.
    AttachThenDial,
}

/// Immutable execution plan persisted atomically with call creation.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CallExecutionPlan {
    /// Versioned schema discriminator.
    pub version: u16,
    /// Exact API principal that authorized outbound work for this call.
    ///
    /// Version-one plans deserialize with `None` so operators can inspect and
    /// terminate legacy calls after upgrade. They cannot authorize a new
    /// outbound rvoip binding or restart recovery operation.
    #[serde(default)]
    authorization_principal_fingerprint: Option<PrincipalFingerprint>,
    /// Exactly two leg specifications.
    pub legs: [LegExecutionSpec; 2],
    /// Exact Amazon start authority keyed by aggregate leg. Historical plan
    /// versions deserialize without this field but cannot authorize new Amazon
    /// work.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    amazon_connect_starts: Vec<AmazonConnectStartBinding>,
    /// Explicit signaling/media semantics written by all new v3 creates.
    /// Historical v3 bodies omit this field and retain legacy defaults from
    /// their aggregate snapshot.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    leg_semantics: Vec<LegSemanticsBinding>,
    /// Optional named-route selection and sanitized request context. Existing
    /// execution plans omit it and retain their original low-level behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    named_route: Option<NamedRouteBinding>,
    /// Initial effect scheduling. Historical persisted bodies deserialize as
    /// `parallel` for exact behavior compatibility.
    #[serde(default)]
    setup_policy: SetupPolicy,
}

impl fmt::Debug for CallExecutionPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallExecutionPlan")
            .field("version", &self.version)
            .field(
                "authorization_principal_fingerprint",
                &self
                    .authorization_principal_fingerprint
                    .as_ref()
                    .map(|_| "[redacted]"),
            )
            .field("legs", &self.legs)
            .field(
                "amazon_connect_start_count",
                &self.amazon_connect_starts.len(),
            )
            .field("leg_semantics_count", &self.leg_semantics.len())
            .field("named_route", &self.named_route)
            .field("setup_policy", &self.setup_policy)
            .finish()
    }
}

impl CallExecutionPlan {
    /// Builds and validates the current plan schema against an aggregate.
    pub fn new(
        aggregate: &CallAggregate,
        legs: [LegExecutionSpec; 2],
        authorization_principal_fingerprint: PrincipalFingerprint,
    ) -> Result<Self, RepositoryError> {
        let plan = Self {
            version: CALL_EXECUTION_PLAN_VERSION,
            authorization_principal_fingerprint: Some(authorization_principal_fingerprint),
            legs,
            amazon_connect_starts: Vec::new(),
            leg_semantics: LegSemanticsBinding::from_aggregate(aggregate),
            named_route: None,
            setup_policy: SetupPolicy::Parallel,
        };
        plan.validate_for_create(aggregate)?;
        Ok(plan)
    }

    /// Builds the current plan schema with exact Amazon Connect start
    /// specifications keyed by aggregate leg.
    pub fn new_with_amazon_connect_starts(
        aggregate: &CallAggregate,
        legs: [LegExecutionSpec; 2],
        authorization_principal_fingerprint: PrincipalFingerprint,
        starts: BTreeMap<LegId, AmazonConnectStartSpec>,
    ) -> Result<Self, RepositoryError> {
        let plan = Self {
            version: CALL_EXECUTION_PLAN_VERSION,
            authorization_principal_fingerprint: Some(authorization_principal_fingerprint),
            legs,
            amazon_connect_starts: starts
                .into_iter()
                .map(|(leg_id, spec)| AmazonConnectStartBinding { leg_id, spec })
                .collect(),
            leg_semantics: LegSemanticsBinding::from_aggregate(aggregate),
            named_route: None,
            setup_policy: SetupPolicy::Parallel,
        };
        plan.validate_for_create(aggregate)?;
        Ok(plan)
    }

    /// Builds the current schema for a server-owned named route.
    pub fn new_with_named_route(
        aggregate: &CallAggregate,
        legs: [LegExecutionSpec; 2],
        authorization_principal_fingerprint: PrincipalFingerprint,
        starts: BTreeMap<LegId, AmazonConnectStartSpec>,
        named_route: NamedRouteBinding,
    ) -> Result<Self, RepositoryError> {
        let plan = Self {
            version: CALL_EXECUTION_PLAN_VERSION,
            authorization_principal_fingerprint: Some(authorization_principal_fingerprint),
            legs,
            amazon_connect_starts: starts
                .into_iter()
                .map(|(leg_id, spec)| AmazonConnectStartBinding { leg_id, spec })
                .collect(),
            leg_semantics: LegSemanticsBinding::from_aggregate(aggregate),
            named_route: Some(named_route),
            setup_policy: SetupPolicy::AttachThenDial,
        };
        plan.validate_for_create(aggregate)?;
        Ok(plan)
    }

    /// Returns the optional durable named-route selection. Values are never
    /// included in public call reads.
    #[must_use]
    pub const fn named_route(&self) -> Option<&NamedRouteBinding> {
        self.named_route.as_ref()
    }

    /// Initial signaling schedule selected durably at call creation.
    #[must_use]
    pub const fn setup_policy(&self) -> SetupPolicy {
        self.setup_policy
    }

    /// Returns the durable signaling initiator for one current-plan leg.
    /// Historical plans without explicit semantics fail closed.
    pub fn leg_signaling_initiator(
        &self,
        leg_id: LegId,
    ) -> Result<SignalingInitiator, RepositoryError> {
        self.leg_semantics
            .iter()
            .find(|binding| binding.leg_id == leg_id)
            .map(|binding| binding.signaling_initiator)
            .ok_or(RepositoryError::InvalidInput(
                "execution plan has no explicit signaling initiator for leg",
            ))
    }

    /// Concrete adapter set one worker must own to execute this complete
    /// two-leg plan. The set is initiator-aware so ingress and egress support
    /// cannot be satisfied by different workers.
    pub fn required_worker_capabilities(&self) -> Result<BTreeSet<String>, RepositoryError> {
        self.legs
            .iter()
            .map(|leg| {
                let initiator = self.leg_signaling_initiator(leg.leg_id)?;
                leg.endpoint
                    .required_worker_capability(initiator)
                    .map(str::to_owned)
            })
            .collect()
    }

    /// Returns the exact persisted Amazon Connect start specification for a
    /// current outbound leg. Historical plans fail closed.
    pub fn amazon_connect_start_spec(
        &self,
        leg_id: LegId,
    ) -> Result<&AmazonConnectStartSpec, RepositoryError> {
        if self.version != CALL_EXECUTION_PLAN_VERSION {
            return Err(RepositoryError::InvalidInput(
                "Amazon Connect start spec is unavailable in a legacy execution plan",
            ));
        }
        self.amazon_connect_starts
            .iter()
            .find(|binding| binding.leg_id == leg_id)
            .map(|binding| &binding.spec)
            .ok_or(RepositoryError::InvalidInput(
                "execution plan has no Amazon Connect start spec for leg",
            ))
    }

    /// Returns the exact persisted principal allowed to authorize outbound
    /// rvoip work. Legacy plans fail closed instead of deriving authority from
    /// process-local API state.
    pub fn authorization_principal_fingerprint(
        &self,
    ) -> Result<PrincipalFingerprint, RepositoryError> {
        self.authorization_principal_fingerprint
            .ok_or(RepositoryError::InvalidInput(
                "execution plan has no durable outbound authorization",
            ))
    }

    /// Builds the exact rvoip client context for a Bridgefu-initiated
    /// interactive WebRTC, WHIP, or WHEP leg.
    ///
    /// Only the current execution-plan schema can authorize a new signaling
    /// side effect. The principal fingerprint is also used as the WebSocket
    /// pool credential partition, so two durable principals can never share
    /// an authenticated signaling connection accidentally. Credentials and
    /// private trust anchors are intentionally absent until endpoint profiles
    /// can reference them durably without persisting secrets in this plan.
    pub fn web_rtc_originate_context(
        &self,
        leg_id: LegId,
    ) -> Result<WebRtcOriginateContext, RepositoryError> {
        if self.version != CALL_EXECUTION_PLAN_VERSION {
            return Err(RepositoryError::InvalidInput(
                "WebRTC originate context is unavailable in a legacy execution plan",
            ));
        }
        let principal = self.authorization_principal_fingerprint()?;
        let (target, signaling_mode) = self
            .legs
            .iter()
            .find(|spec| spec.leg_id == leg_id)
            .and_then(|spec| match &spec.endpoint {
                LegEndpointConfig::WebRtc(config) => config
                    .signaling_uri
                    .as_deref()
                    .map(|target| (target, WebRtcSignalingMode::WebSocket)),
                LegEndpointConfig::Whip(config) => config
                    .endpoint_uri
                    .as_deref()
                    .map(|target| (target, WebRtcSignalingMode::Whip)),
                LegEndpointConfig::Whep(config) => config
                    .endpoint_uri
                    .as_deref()
                    .map(|target| (target, WebRtcSignalingMode::Whep)),
                _ => None,
            })
            .ok_or(RepositoryError::InvalidInput(
                "execution plan has no outbound WebRTC endpoint for leg",
            ))?;
        let parsed = Url::parse(target).map_err(|_| {
            RepositoryError::InvalidInput("invalid persisted outbound WebRTC endpoint")
        })?;
        let policy = web_rtc_target_policy(&parsed, principal)?;
        let context = WebRtcOriginateContext::new(
            target,
            signaling_mode,
            WebRtcIceExchangePolicy::Trickle,
            policy,
            None,
        )
        .map_err(|_| RepositoryError::InvalidInput("invalid persisted WebRTC originate context"))?;
        if signaling_mode == WebRtcSignalingMode::WebSocket {
            context.require_remote_admission_ready().map_err(|_| {
                RepositoryError::InvalidInput("invalid persisted WebRTC admission policy")
            })
        } else {
            Ok(context)
        }
    }

    /// Builds the exact target and rvoip-owned context for a
    /// Bridgefu-initiated SIP leg.
    ///
    /// Initial application headers are accepted only after the caller has
    /// durably recorded and ownership-bound them. `SipInitialHeaders` is the
    /// final defense-in-depth boundary: stack-managed, authentication,
    /// hop-by-hop, internal, oversized, and multiline fields cannot enter the
    /// first INVITE through this path. A legacy plan cannot authorize a new
    /// signaling side effect.
    pub fn sip_originate_context(
        &self,
        leg_id: LegId,
        initial_headers: SipInitialHeaders,
    ) -> Result<(String, SipOriginateContext), RepositoryError> {
        if self.version != CALL_EXECUTION_PLAN_VERSION {
            return Err(RepositoryError::InvalidInput(
                "SIP originate context is unavailable in a legacy execution plan",
            ));
        }
        let _principal = self.authorization_principal_fingerprint()?;
        let target = self
            .legs
            .iter()
            .find(|spec| spec.leg_id == leg_id)
            .and_then(|spec| match &spec.endpoint {
                LegEndpointConfig::Sip(config) => config.uri.as_deref(),
                _ => None,
            })
            .ok_or(RepositoryError::InvalidInput(
                "execution plan has no outbound SIP endpoint for leg",
            ))?;
        validate_uri(target, &["sip", "sips"])?;
        Ok((
            target.to_owned(),
            SipOriginateContext::new().with_initial_headers(initial_headers),
        ))
    }

    /// Returns the persisted first-INVITE context policy for an exact SIP leg.
    pub fn sip_initial_context_mode(
        &self,
        leg_id: LegId,
    ) -> Result<SipInitialContextMode, RepositoryError> {
        if self.version != CALL_EXECUTION_PLAN_VERSION {
            return Err(RepositoryError::InvalidInput(
                "SIP initial-context policy is unavailable in a legacy execution plan",
            ));
        }
        self.legs
            .iter()
            .find(|spec| spec.leg_id == leg_id)
            .and_then(|spec| match &spec.endpoint {
                LegEndpointConfig::Sip(config) => Some(config.initial_context),
                _ => None,
            })
            .ok_or(RepositoryError::InvalidInput(
                "execution plan has no SIP initial-context policy for leg",
            ))
    }

    /// Returns the optional persisted value for database integrity checks.
    #[must_use]
    pub(crate) const fn persisted_authorization_principal_fingerprint(
        &self,
    ) -> Option<PrincipalFingerprint> {
        self.authorization_principal_fingerprint
    }

    /// Validates a newly created durable plan. Historical schemas remain
    /// readable for inspection and teardown but cannot be inserted as new
    /// executable work.
    pub(crate) fn validate_for_create(
        &self,
        aggregate: &CallAggregate,
    ) -> Result<(), RepositoryError> {
        self.validate_against(aggregate)?;
        if self.version != CALL_EXECUTION_PLAN_VERSION {
            return Err(RepositoryError::InvalidInput(
                "new calls require the current execution plan version",
            ));
        }
        if self.leg_semantics.len() != 2 {
            return Err(RepositoryError::InvalidInput(
                "new calls require explicit signaling and media semantics",
            ));
        }
        Ok(())
    }

    /// Resolves and validates the complete source/sink pairing for a bridge
    /// effect before rvoip can acquire either single-consumer receiver.
    pub fn media_bridge_plan(
        &self,
        aggregate: &CallAggregate,
        left_leg_id: LegId,
        right_leg_id: LegId,
    ) -> Result<CallMediaBridgePlan, RepositoryError> {
        self.validate_against(aggregate)?;
        if left_leg_id == right_leg_id {
            return Err(RepositoryError::InvalidInput(
                "media bridge requires two distinct legs",
            ));
        }
        let left = aggregate
            .leg(left_leg_id)
            .ok_or(RepositoryError::InvalidInput(
                "media bridge left leg does not belong to call",
            ))?;
        let right = aggregate
            .leg(right_leg_id)
            .ok_or(RepositoryError::InvalidInput(
                "media bridge right leg does not belong to call",
            ))?;
        let left_flow = left.media_flow();
        let right_flow = right.media_flow();
        let left_to_right = left_flow.source_enabled() && right_flow.sink_enabled();
        let right_to_left = right_flow.source_enabled() && left_flow.sink_enabled();
        if left_flow.source_enabled() != right_flow.sink_enabled()
            || right_flow.source_enabled() != left_flow.sink_enabled()
        {
            return Err(RepositoryError::InvalidInput(
                "media bridge has an unmatched source or sink",
            ));
        }
        if !left_to_right && !right_to_left {
            return Err(RepositoryError::InvalidInput(
                "media bridge has no enabled direction",
            ));
        }
        Ok(CallMediaBridgePlan {
            left_to_right,
            right_to_left,
        })
    }

    /// Verifies version, exact leg ownership, endpoint kind, and direction rules.
    pub fn validate_against(&self, aggregate: &CallAggregate) -> Result<(), RepositoryError> {
        match self.version {
            CALL_EXECUTION_PLAN_VERSION if self.authorization_principal_fingerprint.is_some() => {}
            AUTHORIZED_CALL_EXECUTION_PLAN_VERSION
                if self.authorization_principal_fingerprint.is_some()
                    && self.amazon_connect_starts.is_empty()
                    && self.leg_semantics.is_empty()
                    && self.named_route.is_none() => {}
            LEGACY_CALL_EXECUTION_PLAN_VERSION
                if self.authorization_principal_fingerprint.is_none()
                    && self.amazon_connect_starts.is_empty()
                    && self.leg_semantics.is_empty()
                    && self.named_route.is_none() => {}
            CALL_EXECUTION_PLAN_VERSION
            | AUTHORIZED_CALL_EXECUTION_PLAN_VERSION
            | LEGACY_CALL_EXECUTION_PLAN_VERSION => {
                return Err(RepositoryError::InvalidInput(
                    "execution plan authorization does not match its version",
                ));
            }
            _ => {
                return Err(RepositoryError::InvalidInput(
                    "unsupported call execution plan version",
                ));
            }
        }
        if self.legs[0].leg_id == self.legs[1].leg_id {
            return Err(RepositoryError::InvalidInput(
                "execution plan contains a duplicate leg",
            ));
        }
        self.validate_leg_semantics(aggregate)?;
        for spec in &self.legs {
            let leg = aggregate
                .leg(spec.leg_id)
                .ok_or(RepositoryError::InvalidInput(
                    "execution plan leg does not belong to call",
                ))?;
            // The plan is the immutable generation-one creation record.
            // Later successful make-before-break generations retain their
            // effective endpoint in the correlated service-effect payload.
            if leg.binding_generation() == crate::call_engine::BindingGeneration::INITIAL
                && leg.kind() != spec.endpoint.kind()
            {
                return Err(RepositoryError::InvalidInput(
                    "execution endpoint kind does not match aggregate leg",
                ));
            }
            spec.endpoint
                .validate(leg.direction(), leg.signaling_initiator())?;
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
        self.validate_amazon_connect_starts(aggregate)?;
        if let Some(named_route) = &self.named_route {
            if self.version != CALL_EXECUTION_PLAN_VERSION {
                return Err(RepositoryError::InvalidInput(
                    "legacy execution plan contains a named route",
                ));
            }
            named_route.validate()?;
        }
        if self.version != CALL_EXECUTION_PLAN_VERSION && self.setup_policy != SetupPolicy::Parallel
        {
            return Err(RepositoryError::InvalidInput(
                "legacy execution plan contains a non-legacy setup policy",
            ));
        }
        if self.setup_policy == SetupPolicy::AttachThenDial && self.named_route.is_none() {
            return Err(RepositoryError::InvalidInput(
                "attach-then-dial requires a durable named route",
            ));
        }
        if self.setup_policy == SetupPolicy::AttachThenDial {
            let remote = self
                .leg_semantics
                .iter()
                .filter(|binding| binding.signaling_initiator == SignalingInitiator::Remote)
                .count();
            let bridgefu = self
                .leg_semantics
                .iter()
                .filter(|binding| binding.signaling_initiator == SignalingInitiator::Bridgefu)
                .count();
            if remote != 1 || bridgefu != 1 {
                return Err(RepositoryError::InvalidInput(
                    "attach-then-dial requires one remote ingress and one Bridgefu destination",
                ));
            }
        }
        Ok(())
    }

    fn validate_leg_semantics(&self, aggregate: &CallAggregate) -> Result<(), RepositoryError> {
        if self.leg_semantics.is_empty() {
            if aggregate.legs().iter().any(|leg| {
                leg.signaling_initiator() != SignalingInitiator::legacy_default(leg.direction())
                    || leg.media_flow() != MediaFlow::SendReceive
            }) {
                return Err(RepositoryError::InvalidInput(
                    "execution plan without semantics requires exact legacy defaults",
                ));
            }
            return Ok(());
        }
        if self.version != CALL_EXECUTION_PLAN_VERSION || self.leg_semantics.len() != 2 {
            return Err(RepositoryError::InvalidInput(
                "execution plan semantics do not match its version",
            ));
        }
        let mut bound_legs = BTreeSet::new();
        for binding in &self.leg_semantics {
            if !bound_legs.insert(binding.leg_id) {
                return Err(RepositoryError::InvalidInput(
                    "execution plan contains duplicate leg semantics",
                ));
            }
            let leg = aggregate
                .leg(binding.leg_id)
                .ok_or(RepositoryError::InvalidInput(
                    "execution plan semantics leg does not belong to call",
                ))?;
            if binding.semantics() != leg.semantics() {
                return Err(RepositoryError::InvalidInput(
                    "execution plan semantics do not match aggregate leg",
                ));
            }
        }
        if aggregate
            .legs()
            .iter()
            .any(|leg| !bound_legs.contains(&leg.id()))
        {
            return Err(RepositoryError::InvalidInput(
                "execution plan semantics do not cover both aggregate legs",
            ));
        }
        Ok(())
    }

    fn validate_amazon_connect_starts(
        &self,
        aggregate: &CallAggregate,
    ) -> Result<(), RepositoryError> {
        if self.version != CALL_EXECUTION_PLAN_VERSION {
            if self.amazon_connect_starts.is_empty() {
                return Ok(());
            }
            return Err(RepositoryError::InvalidInput(
                "legacy execution plan contains an Amazon Connect start spec",
            ));
        }

        let mut bound_legs = BTreeSet::new();
        for binding in &self.amazon_connect_starts {
            if !bound_legs.insert(binding.leg_id) {
                return Err(RepositoryError::InvalidInput(
                    "execution plan contains duplicate Amazon Connect start specs",
                ));
            }
            binding.spec.validate()?;
            let leg = aggregate
                .leg(binding.leg_id)
                .ok_or(RepositoryError::InvalidInput(
                    "Amazon Connect start spec leg does not belong to call",
                ))?;
            if (leg.binding_generation() == crate::call_engine::BindingGeneration::INITIAL
                && leg.kind() != LegKind::AmazonConnect)
                || leg.direction() != LegDirection::Outbound
            {
                return Err(RepositoryError::InvalidInput(
                    "Amazon Connect start spec requires an outbound Amazon leg",
                ));
            }
            let endpoint = self
                .legs
                .iter()
                .find(|spec| spec.leg_id == binding.leg_id)
                .and_then(|spec| match &spec.endpoint {
                    LegEndpointConfig::AmazonConnect(config) => Some(config),
                    _ => None,
                })
                .ok_or(RepositoryError::InvalidInput(
                    "Amazon Connect start spec has no matching endpoint",
                ))?;
            if endpoint.instance_id != binding.spec.instance_id
                || endpoint.contact_flow_id != binding.spec.contact_flow_id
            {
                return Err(RepositoryError::InvalidInput(
                    "Amazon Connect start target does not match endpoint",
                ));
            }
        }

        for spec in &self.legs {
            if matches!(spec.endpoint, LegEndpointConfig::AmazonConnect(_))
                && !bound_legs.contains(&spec.leg_id)
            {
                return Err(RepositoryError::InvalidInput(
                    "current Amazon Connect leg requires a durable start spec",
                ));
            }
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
                validate_connect_resource(instance_id, "invalid Amazon Connect instance ID")?;
                validate_connect_resource(contact_flow_id, "invalid Amazon Connect contact-flow ID")
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
    Transfer {
        /// Exact existing call leg whose signaling session receives transfer.
        target_leg_id: LegId,
        /// Exact target-leg incarnation at transfer acceptance.
        target_binding_generation: crate::call_engine::BindingGeneration,
        /// Typed external transfer destination.
        target: TransferTarget,
    },
    /// Server-controlled endpoint used by a make-before-break logical-leg
    /// replacement. The initial execution plan remains an immutable creation
    /// record; successful later generations resolve their endpoint from this
    /// retained payload.
    LegReplacement {
        /// Stable logical leg.
        leg_id: LegId,
        /// Previous route retained for compensation.
        previous_binding_generation: crate::call_engine::BindingGeneration,
        /// Reserved monotonic route generation.
        pending_binding_generation: crate::call_engine::BindingGeneration,
        /// Server-owned destination endpoint.
        endpoint: LegEndpointConfig,
        /// Exact Amazon start authority when the endpoint is Amazon Connect.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        amazon_connect_start: Option<AmazonConnectStartSpec>,
        /// Named destination route selected by the trusted configuration.
        route_id: String,
        /// Exact credential-free route/profile snapshot selected for this
        /// generation. Historical payloads decode without it and are rejected
        /// before any new signaling side effect executes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        replacement_route: Option<NamedRouteBinding>,
        /// Exact authenticated principal authorizing this outbound attempt.
        authorization_principal_fingerprint: PrincipalFingerprint,
    },
}

impl ServiceEffectPayload {
    pub(crate) fn validate(&self) -> Result<(), RepositoryError> {
        match self {
            Self::Transfer { target, .. } => target.validate(),
            Self::LegReplacement {
                endpoint,
                amazon_connect_start,
                route_id,
                replacement_route,
                ..
            } => {
                validate_identifier(route_id, "invalid replacement route ID")?;
                endpoint.validate(LegDirection::Outbound, SignalingInitiator::Bridgefu)?;
                let replacement_route =
                    replacement_route
                        .as_ref()
                        .ok_or(RepositoryError::InvalidInput(
                            "replacement route snapshot is unavailable",
                        ))?;
                replacement_route.validate_replacement_destination(route_id, endpoint)?;
                if let (LegEndpointConfig::AmazonConnect(_), Some(start)) =
                    (endpoint, amazon_connect_start)
                {
                    let profile = replacement_route
                        .profiles
                        .iter()
                        .find(|profile| profile.role == NamedProfileRole::Destination)
                        .ok_or(RepositoryError::InvalidInput(
                            "replacement Amazon route has no destination profile",
                        ))?;
                    if profile.profile_id != start.profile() {
                        return Err(RepositoryError::InvalidInput(
                            "replacement Amazon route does not match its start profile",
                        ));
                    }
                }
                match (endpoint, amazon_connect_start) {
                    (LegEndpointConfig::AmazonConnect(endpoint), Some(start))
                        if endpoint.instance_id == start.instance_id()
                            && endpoint.contact_flow_id == start.contact_flow_id() =>
                    {
                        Ok(())
                    }
                    (LegEndpointConfig::AmazonConnect(_), _) => Err(RepositoryError::InvalidInput(
                        "replacement Amazon endpoint requires matching start authority",
                    )),
                    (_, None) => Ok(()),
                    (_, Some(_)) => Err(RepositoryError::InvalidInput(
                        "replacement Amazon start authority requires an Amazon endpoint",
                    )),
                }
            }
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
    signaling_initiator: SignalingInitiator,
    schemes: &[&str],
    missing: &'static str,
) -> Result<(), RepositoryError> {
    match value {
        Some(value) => validate_uri(value, schemes),
        None if signaling_initiator == SignalingInitiator::Remote => Ok(()),
        None => Err(RepositoryError::InvalidInput(missing)),
    }
}

fn web_rtc_target_policy(
    endpoint: &Url,
    principal: PrincipalFingerprint,
) -> Result<WebRtcTargetPolicy, RepositoryError> {
    let port = endpoint
        .port_or_known_default()
        .ok_or(RepositoryError::InvalidInput(
            "persisted outbound WebRTC endpoint has no port",
        ))?;
    let mut partition = String::with_capacity(73);
    partition.push_str("bridgefu:");
    for byte in principal.expose_bytes() {
        write!(&mut partition, "{byte:02x}").map_err(|_| {
            RepositoryError::InvalidInput("could not derive WebRTC credential partition")
        })?;
    }
    WebRtcTargetPolicy::default()
        .allow_port(port)
        .with_credential_partition(partition)
        .map_err(|_| RepositoryError::InvalidInput("invalid outbound WebRTC target policy"))
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

fn validate_connect_profile(value: &str) -> Result<(), RepositoryError> {
    if value.is_empty()
        || value.len() > MAX_CONNECT_PROFILE_ID_BYTES
        || !value.is_ascii()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Err(RepositoryError::InvalidInput(
            "invalid Amazon Connect profile",
        ))
    } else {
        Ok(())
    }
}

fn validate_connect_resource(value: &str, message: &'static str) -> Result<(), RepositoryError> {
    if value.is_empty()
        || value.len() > MAX_CONNECT_RESOURCE_ID_BYTES
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        Err(RepositoryError::InvalidInput(message))
    } else {
        Ok(())
    }
}

fn validate_connect_text(
    value: &str,
    max: usize,
    message: &'static str,
) -> Result<(), RepositoryError> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        Err(RepositoryError::InvalidInput(message))
    } else {
        Ok(())
    }
}

fn validate_connect_attributes(
    attributes: &BTreeMap<String, String>,
) -> Result<(), RepositoryError> {
    if attributes.len() > MAX_CONNECT_ATTRIBUTE_COUNT {
        return Err(RepositoryError::InvalidInput(
            "too many Amazon Connect attributes",
        ));
    }
    let mut total = 0usize;
    for (key, value) in attributes {
        if key.is_empty()
            || key.len() > MAX_CONNECT_ATTRIBUTE_KEY_BYTES
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(RepositoryError::InvalidInput(
                "invalid Amazon Connect attribute key",
            ));
        }
        if value.chars().any(char::is_control) {
            return Err(RepositoryError::InvalidInput(
                "invalid Amazon Connect attribute value",
            ));
        }
        total = total
            .checked_add(key.len())
            .and_then(|value_bytes| value_bytes.checked_add(value.len()))
            .ok_or(RepositoryError::InvalidInput(
                "Amazon Connect attributes are too large",
            ))?;
        if total > MAX_CONNECT_ATTRIBUTE_BYTES {
            return Err(RepositoryError::InvalidInput(
                "Amazon Connect attributes are too large",
            ));
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn valid_amazon_start_spec() -> AmazonConnectStartSpec {
        AmazonConnectStartSpec::new(
            "tenant-profile-private",
            "instance-private",
            "flow-private",
            BTreeMap::from([
                ("correlation_id".into(), "customer-private".into()),
                ("tenant".into(), "tenant-private".into()),
            ]),
            "Caller Private",
            Some("Description Private".into()),
        )
        .unwrap()
    }

    fn amazon_aggregate() -> CallAggregate {
        CallAggregate::new(
            crate::call_engine::TenantId::parse("amazon-model-tenant").unwrap(),
            [
                crate::call_engine::LegSpec {
                    direction: LegDirection::Inbound,
                    kind: LegKind::Sip,
                },
                crate::call_engine::LegSpec {
                    direction: LegDirection::Outbound,
                    kind: LegKind::AmazonConnect,
                },
            ],
            Utc.timestamp_opt(1_950_000_000, 0).unwrap(),
        )
    }

    fn amazon_legs(aggregate: &CallAggregate) -> [LegExecutionSpec; 2] {
        [
            LegExecutionSpec {
                leg_id: aggregate.legs()[0].id(),
                endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                    uri: None,
                    initial_context: Default::default(),
                }),
            },
            LegExecutionSpec {
                leg_id: aggregate.legs()[1].id(),
                endpoint: LegEndpointConfig::AmazonConnect(AmazonConnectEndpointConfig {
                    instance_id: "instance-private".into(),
                    contact_flow_id: "flow-private".into(),
                }),
            },
        ]
    }

    fn outbound_web_rtc_plan(endpoint: LegEndpointConfig) -> (CallExecutionPlan, LegId) {
        let aggregate = CallAggregate::new_with_semantics(
            crate::call_engine::TenantId::parse("webrtc-model-tenant").unwrap(),
            [
                crate::call_engine::LegSpec {
                    direction: LegDirection::Inbound,
                    kind: LegKind::Sip,
                },
                crate::call_engine::LegSpec {
                    direction: LegDirection::Outbound,
                    kind: endpoint.kind(),
                },
            ],
            [
                LegSemantics {
                    signaling_initiator: SignalingInitiator::Remote,
                    media_flow: MediaFlow::SendReceive,
                },
                LegSemantics {
                    signaling_initiator: SignalingInitiator::Bridgefu,
                    media_flow: MediaFlow::SendReceive,
                },
            ],
            Utc.timestamp_opt(1_950_000_200, 0).unwrap(),
        )
        .unwrap();
        let outbound_leg = aggregate.legs()[1].id();
        let plan = CallExecutionPlan::new(
            &aggregate,
            [
                LegExecutionSpec {
                    leg_id: aggregate.legs()[0].id(),
                    endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                        uri: None,
                        initial_context: Default::default(),
                    }),
                },
                LegExecutionSpec {
                    leg_id: outbound_leg,
                    endpoint,
                },
            ],
            PrincipalFingerprint::new([0x45; 32]),
        )
        .unwrap();
        (plan, outbound_leg)
    }

    #[test]
    fn outbound_web_rtc_context_preserves_exact_typed_signaling_mode() {
        let cases = [
            (
                LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                    signaling_uri: Some("wss://signal.example.test:8443/session".into()),
                }),
                WebRtcSignalingMode::WebSocket,
                "wss://signal.example.test:8443/session",
            ),
            (
                LegEndpointConfig::Whip(WhipEndpointConfig {
                    endpoint_uri: Some("https://media.example.test/whip/publish".into()),
                }),
                WebRtcSignalingMode::Whip,
                "https://media.example.test/whip/publish",
            ),
            (
                LegEndpointConfig::Whep(WhepEndpointConfig {
                    endpoint_uri: Some("https://media.example.test/whep/play".into()),
                }),
                WebRtcSignalingMode::Whep,
                "https://media.example.test/whep/play",
            ),
        ];

        for (endpoint, expected_mode, expected_target) in cases {
            let (plan, leg_id) = outbound_web_rtc_plan(endpoint);
            let context = plan.web_rtc_originate_context(leg_id).unwrap();
            assert_eq!(context.signaling_mode(), expected_mode);
            assert_eq!(context.ice_policy(), WebRtcIceExchangePolicy::Trickle);
            assert_eq!(context.endpoint().as_str(), expected_target);
            context.validate().unwrap();
        }
    }

    #[test]
    fn outbound_web_rtc_context_fails_closed_without_current_durable_authority() {
        let (mut plan, leg_id) =
            outbound_web_rtc_plan(LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                signaling_uri: Some("wss://signal.example.test/session".into()),
            }));
        plan.authorization_principal_fingerprint = None;
        assert!(plan.web_rtc_originate_context(leg_id).is_err());

        let (mut legacy, leg_id) =
            outbound_web_rtc_plan(LegEndpointConfig::Whip(WhipEndpointConfig {
                endpoint_uri: Some("https://media.example.test/whip".into()),
            }));
        legacy.version = AUTHORIZED_CALL_EXECUTION_PLAN_VERSION;
        legacy.leg_semantics.clear();
        assert!(legacy.web_rtc_originate_context(leg_id).is_err());
    }

    #[test]
    fn outbound_sip_context_preserves_durable_ordered_initial_headers() {
        let (plan, leg_id) = outbound_web_rtc_plan(LegEndpointConfig::Sip(SipEndpointConfig {
            uri: Some("sips:callee@voice.example.test;transport=tls".into()),
            initial_context: SipInitialContextMode::None,
        }));
        let headers = SipInitialHeaders::new([
            ("X-Correlation-Id", "correlation-private"),
            ("X-Account-Tier", "gold"),
            ("X-Account-Tier", "priority"),
        ])
        .unwrap();

        let (target, context) = plan.sip_originate_context(leg_id, headers).unwrap();
        assert_eq!(target, "sips:callee@voice.example.test;transport=tls");
        assert_eq!(context.initial_headers().len(), 3);
        assert_eq!(
            context
                .initial_headers()
                .iter()
                .map(|(name, value)| (name.as_str(), value))
                .collect::<Vec<_>>(),
            vec![
                ("X-Correlation-Id", "correlation-private"),
                ("X-Account-Tier", "gold"),
                ("X-Account-Tier", "priority"),
            ]
        );
        context.validate().unwrap();
        let debug = format!("{context:?}");
        assert!(!debug.contains("correlation-private"));
        assert!(!debug.contains("gold"));
    }

    #[test]
    fn outbound_sip_context_fails_closed_without_current_durable_authority() {
        let (mut plan, leg_id) = outbound_web_rtc_plan(LegEndpointConfig::Sip(SipEndpointConfig {
            uri: Some("sip:callee@voice.example.test".into()),
            initial_context: SipInitialContextMode::None,
        }));
        plan.authorization_principal_fingerprint = None;
        assert!(plan
            .sip_originate_context(leg_id, SipInitialHeaders::default())
            .is_err());

        let (mut legacy, leg_id) =
            outbound_web_rtc_plan(LegEndpointConfig::Sip(SipEndpointConfig {
                uri: Some("sip:callee@voice.example.test".into()),
                initial_context: SipInitialContextMode::None,
            }));
        legacy.version = AUTHORIZED_CALL_EXECUTION_PLAN_VERSION;
        legacy.leg_semantics.clear();
        assert!(legacy
            .sip_originate_context(leg_id, SipInitialHeaders::default())
            .is_err());
    }

    #[test]
    fn sip_initial_context_defaults_to_none_and_required_is_outbound_only() {
        let decoded: SipEndpointConfig = serde_json::from_value(serde_json::json!({
            "uri": "sip:callee@voice.example.test"
        }))
        .unwrap();
        assert_eq!(decoded.initial_context, SipInitialContextMode::None);

        let required = LegEndpointConfig::Sip(SipEndpointConfig {
            uri: Some("sips:callee@voice.example.test".into()),
            initial_context: SipInitialContextMode::Required,
        });
        assert!(required
            .validate(LegDirection::Outbound, SignalingInitiator::Bridgefu)
            .is_ok());
        assert!(required
            .validate(LegDirection::Inbound, SignalingInitiator::Bridgefu)
            .is_err());
        assert!(required
            .validate(LegDirection::Outbound, SignalingInitiator::Remote)
            .is_err());
    }

    #[test]
    fn execution_plan_retains_exact_sip_initial_context_policy() {
        let (plan, leg_id) = outbound_web_rtc_plan(LegEndpointConfig::Sip(SipEndpointConfig {
            uri: Some("sip:callee@voice.example.test".into()),
            initial_context: SipInitialContextMode::Required,
        }));
        assert_eq!(
            plan.sip_initial_context_mode(leg_id).unwrap(),
            SipInitialContextMode::Required
        );
    }

    #[test]
    fn bridgefu_initiated_web_rtc_requires_secure_unambiguous_schemes() {
        for endpoint in [
            LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                signaling_uri: Some("ws://127.0.0.1/session".into()),
            }),
            LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                signaling_uri: Some("https://signal.example.test/session".into()),
            }),
            LegEndpointConfig::Whip(WhipEndpointConfig {
                endpoint_uri: Some("http://127.0.0.1/whip".into()),
            }),
            LegEndpointConfig::Whep(WhepEndpointConfig {
                endpoint_uri: Some("http://127.0.0.1/whep".into()),
            }),
        ] {
            assert!(endpoint
                .validate(LegDirection::Outbound, SignalingInitiator::Bridgefu)
                .is_err());
        }
    }

    #[test]
    fn amazon_start_spec_round_trips_exactly_and_debug_is_metadata_only() {
        let spec = valid_amazon_start_spec();
        let encoded = serde_json::to_string(&spec).unwrap();
        let decoded: AmazonConnectStartSpec = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, spec);
        assert!(!encoded.contains("client_token"));
        assert!(!encoded.contains("credential"));

        let debug = format!("{spec:?}");
        assert!(debug.contains("attribute_count: 2"));
        assert!(debug.contains("description_present: true"));
        for private in [
            "tenant-profile-private",
            "instance-private",
            "flow-private",
            "customer-private",
            "tenant-private",
            "Caller Private",
            "Description Private",
        ] {
            assert!(!debug.contains(private), "debug leaked {private}");
        }
    }

    #[test]
    fn amazon_start_spec_deserialization_rejects_duplicates_unknowns_and_invalid_values() {
        let duplicate = r#"{
            "profile":"profile",
            "instance_id":"instance",
            "contact_flow_id":"flow",
            "attributes":{"correlation_id":"first","correlation_id":"second"},
            "display_name":"Caller"
        }"#;
        assert!(serde_json::from_str::<AmazonConnectStartSpec>(duplicate).is_err());

        for unknown in ["client_token", "access_key_id", "secret_access_key"] {
            let encoded = format!(
                r#"{{
                    "profile":"profile",
                    "instance_id":"instance",
                    "contact_flow_id":"flow",
                    "attributes":{{}},
                    "display_name":"Caller",
                    "{unknown}":"must-not-persist"
                }}"#
            );
            assert!(
                serde_json::from_str::<AmazonConnectStartSpec>(&encoded).is_err(),
                "accepted unknown field {unknown}"
            );
        }

        let invalid_control = r#"{
            "profile":"profile",
            "instance_id":"instance",
            "contact_flow_id":"flow",
            "attributes":{"key":"line\nbreak"},
            "display_name":"Caller"
        }"#;
        assert!(serde_json::from_str::<AmazonConnectStartSpec>(invalid_control).is_err());
    }

    #[test]
    fn amazon_start_spec_enforces_rvoip_bounds_exactly() {
        let create = |profile: String,
                      instance: String,
                      flow: String,
                      attributes: BTreeMap<String, String>,
                      display: String,
                      description: Option<String>| {
            AmazonConnectStartSpec::new(profile, instance, flow, attributes, display, description)
        };

        assert!(create(
            "p".repeat(MAX_CONNECT_PROFILE_ID_BYTES),
            "i".repeat(MAX_CONNECT_RESOURCE_ID_BYTES),
            "f".repeat(MAX_CONNECT_RESOURCE_ID_BYTES),
            BTreeMap::from([("k".repeat(MAX_CONNECT_ATTRIBUTE_KEY_BYTES), String::new(),)]),
            "d".repeat(MAX_CONNECT_DISPLAY_NAME_BYTES),
            Some("x".repeat(MAX_CONNECT_DESCRIPTION_BYTES)),
        )
        .is_ok());

        for profile in [
            String::new(),
            "p".repeat(MAX_CONNECT_PROFILE_ID_BYTES + 1),
            "profile/invalid".into(),
            "prøfile".into(),
        ] {
            assert!(create(
                profile,
                "instance".into(),
                "flow".into(),
                BTreeMap::new(),
                "Caller".into(),
                None,
            )
            .is_err());
        }
        for resource in [
            String::new(),
            "r".repeat(MAX_CONNECT_RESOURCE_ID_BYTES + 1),
            "resource with space".into(),
            "résource".into(),
        ] {
            assert!(create(
                "profile".into(),
                resource,
                "flow".into(),
                BTreeMap::new(),
                "Caller".into(),
                None,
            )
            .is_err());
        }
        for display in [
            String::new(),
            "d".repeat(MAX_CONNECT_DISPLAY_NAME_BYTES + 1),
            "line\nbreak".into(),
        ] {
            assert!(create(
                "profile".into(),
                "instance".into(),
                "flow".into(),
                BTreeMap::new(),
                display,
                None,
            )
            .is_err());
        }
        for description in [
            String::new(),
            "x".repeat(MAX_CONNECT_DESCRIPTION_BYTES + 1),
            "line\nbreak".into(),
        ] {
            assert!(create(
                "profile".into(),
                "instance".into(),
                "flow".into(),
                BTreeMap::new(),
                "Caller".into(),
                Some(description),
            )
            .is_err());
        }

        let exact_attributes =
            BTreeMap::from([("k".into(), "v".repeat(MAX_CONNECT_ATTRIBUTE_BYTES - 1))]);
        assert!(create(
            "profile".into(),
            "instance".into(),
            "flow".into(),
            exact_attributes,
            "Caller".into(),
            None,
        )
        .is_ok());
        let oversized_attributes =
            BTreeMap::from([("k".into(), "v".repeat(MAX_CONNECT_ATTRIBUTE_BYTES))]);
        assert!(create(
            "profile".into(),
            "instance".into(),
            "flow".into(),
            oversized_attributes,
            "Caller".into(),
            None,
        )
        .is_err());

        for invalid_key in [
            String::new(),
            "k".repeat(MAX_CONNECT_ATTRIBUTE_KEY_BYTES + 1),
            "not.allowed".into(),
            "nøn_ascii".into(),
        ] {
            assert!(create(
                "profile".into(),
                "instance".into(),
                "flow".into(),
                BTreeMap::from([(invalid_key, String::new())]),
                "Caller".into(),
                None,
            )
            .is_err());
        }

        let maximum_count = (0..MAX_CONNECT_ATTRIBUTE_COUNT)
            .map(|index| (format!("key_{index}"), String::new()))
            .collect();
        assert!(create(
            "profile".into(),
            "instance".into(),
            "flow".into(),
            maximum_count,
            "Caller".into(),
            None,
        )
        .is_ok());
        let over_count = (0..=MAX_CONNECT_ATTRIBUTE_COUNT)
            .map(|index| (format!("key_{index}"), String::new()))
            .collect();
        assert!(create(
            "profile".into(),
            "instance".into(),
            "flow".into(),
            over_count,
            "Caller".into(),
            None,
        )
        .is_err());
    }

    #[test]
    fn plan_v3_requires_exact_amazon_start_while_v2_remains_inspection_only() {
        let aggregate = amazon_aggregate();
        let amazon_leg = aggregate.legs()[1].id();
        let principal = crate::call_engine::PrincipalFingerprint::new([0xa5; 32]);
        assert!(CallExecutionPlan::new(&aggregate, amazon_legs(&aggregate), principal).is_err());

        let spec = valid_amazon_start_spec();
        let plan = CallExecutionPlan::new_with_amazon_connect_starts(
            &aggregate,
            amazon_legs(&aggregate),
            principal,
            BTreeMap::from([(amazon_leg, spec.clone())]),
        )
        .unwrap();
        assert_eq!(plan.version, CALL_EXECUTION_PLAN_VERSION);
        assert_eq!(plan.amazon_connect_start_spec(amazon_leg).unwrap(), &spec);
        plan.validate_for_create(&aggregate).unwrap();

        let encoded = serde_json::to_value(&plan).unwrap();
        let decoded: CallExecutionPlan = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(decoded, plan);
        let debug = format!("{decoded:?}");
        assert!(debug.contains("amazon_connect_start_count: 1"));
        for private in [
            "tenant-profile-private",
            "instance-private",
            "flow-private",
            "customer-private",
            "Caller Private",
        ] {
            assert!(!debug.contains(private), "plan debug leaked {private}");
        }

        let mut legacy = encoded;
        legacy["version"] = serde_json::json!(AUTHORIZED_CALL_EXECUTION_PLAN_VERSION);
        legacy
            .as_object_mut()
            .unwrap()
            .remove("amazon_connect_starts");
        legacy.as_object_mut().unwrap().remove("leg_semantics");
        let legacy: CallExecutionPlan = serde_json::from_value(legacy).unwrap();
        legacy.validate_against(&aggregate).unwrap();
        assert!(legacy.amazon_connect_start_spec(amazon_leg).is_err());
        assert!(legacy.validate_for_create(&aggregate).is_err());
    }

    #[test]
    fn historical_v3_plan_defaults_are_readable_but_new_creates_require_explicit_semantics() {
        let aggregate = amazon_aggregate();
        let amazon_leg = aggregate.legs()[1].id();
        let plan = CallExecutionPlan::new_with_amazon_connect_starts(
            &aggregate,
            amazon_legs(&aggregate),
            crate::call_engine::PrincipalFingerprint::new([0xa5; 32]),
            BTreeMap::from([(amazon_leg, valid_amazon_start_spec())]),
        )
        .unwrap();
        let mut historical = serde_json::to_value(plan).unwrap();
        historical.as_object_mut().unwrap().remove("leg_semantics");

        let historical: CallExecutionPlan = serde_json::from_value(historical).unwrap();
        historical.validate_against(&aggregate).unwrap();
        assert!(historical.validate_for_create(&aggregate).is_err());
        let directions = historical
            .media_bridge_plan(
                &aggregate,
                aggregate.legs()[0].id(),
                aggregate.legs()[1].id(),
            )
            .unwrap();
        assert!(directions.left_to_right());
        assert!(directions.right_to_left());
    }

    #[test]
    fn named_route_plan_is_attach_then_dial_and_low_level_plan_remains_parallel() {
        let aggregate = CallAggregate::new_with_semantics(
            crate::call_engine::TenantId::parse("named-route-model-tenant").unwrap(),
            [
                crate::call_engine::LegSpec {
                    direction: LegDirection::Inbound,
                    kind: LegKind::InteractiveWebRtc,
                },
                crate::call_engine::LegSpec {
                    direction: LegDirection::Outbound,
                    kind: LegKind::Sip,
                },
            ],
            [
                LegSemantics {
                    signaling_initiator: SignalingInitiator::Remote,
                    media_flow: MediaFlow::SendReceive,
                },
                LegSemantics {
                    signaling_initiator: SignalingInitiator::Bridgefu,
                    media_flow: MediaFlow::SendReceive,
                },
            ],
            Utc.timestamp_opt(1_950_000_300, 0).unwrap(),
        )
        .unwrap();
        let legs = [
            LegExecutionSpec {
                leg_id: aggregate.legs()[0].id(),
                endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                    signaling_uri: None,
                }),
            },
            LegExecutionSpec {
                leg_id: aggregate.legs()[1].id(),
                endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                    uri: Some("sips:agent@example.test".into()),
                    initial_context: SipInitialContextMode::None,
                }),
            },
        ];
        let principal = PrincipalFingerprint::new([0x75; 32]);
        let low_level = CallExecutionPlan::new(&aggregate, legs.clone(), principal).unwrap();
        assert_eq!(low_level.setup_policy(), SetupPolicy::Parallel);
        assert!(low_level.named_route().is_none());

        let context = NamedRouteCallContext {
            correlation_id: "private-correlation".into(),
            metadata: BTreeMap::from([("customer_name".into(), "Private Customer".into())]),
        };
        let named = CallExecutionPlan::new_with_named_route(
            &aggregate,
            legs,
            principal,
            BTreeMap::new(),
            NamedRouteBinding::new("sip-support", Some(context)).unwrap(),
        )
        .unwrap();
        assert_eq!(named.setup_policy(), SetupPolicy::AttachThenDial);
        assert_eq!(named.named_route().unwrap().route_id(), "sip-support");
        assert_eq!(
            named
                .leg_signaling_initiator(aggregate.legs()[0].id())
                .unwrap(),
            SignalingInitiator::Remote
        );
        assert_eq!(
            named
                .leg_signaling_initiator(aggregate.legs()[1].id())
                .unwrap(),
            SignalingInitiator::Bridgefu
        );
        let debug = format!("{named:?}");
        assert!(!debug.contains("private-correlation"));
        assert!(!debug.contains("Private Customer"));

        let mut historical = serde_json::to_value(&low_level).unwrap();
        historical.as_object_mut().unwrap().remove("setup_policy");
        let historical: CallExecutionPlan = serde_json::from_value(historical).unwrap();
        assert_eq!(historical.setup_policy(), SetupPolicy::Parallel);
    }

    #[test]
    fn named_route_context_rejects_ownership_overrides_and_multiline_values() {
        for context in [
            NamedRouteCallContext {
                correlation_id: "correlation".into(),
                metadata: BTreeMap::from([("tenant_id".into(), "other".into())]),
            },
            NamedRouteCallContext {
                correlation_id: "line\nbreak".into(),
                metadata: BTreeMap::new(),
            },
        ] {
            assert!(NamedRouteBinding::new("sip-support", Some(context)).is_err());
        }
    }

    #[test]
    fn missing_plan_semantics_accept_only_exact_historical_defaults() {
        let aggregate = CallAggregate::new_with_semantics(
            crate::call_engine::TenantId::parse("nonlegacy-plan-tenant").unwrap(),
            [
                crate::call_engine::LegSpec {
                    direction: LegDirection::Outbound,
                    kind: LegKind::Sip,
                },
                crate::call_engine::LegSpec {
                    direction: LegDirection::Inbound,
                    kind: LegKind::InteractiveWebRtc,
                },
            ],
            [
                LegSemantics {
                    signaling_initiator: SignalingInitiator::Remote,
                    media_flow: MediaFlow::SendReceive,
                },
                LegSemantics {
                    signaling_initiator: SignalingInitiator::Bridgefu,
                    media_flow: MediaFlow::SendReceive,
                },
            ],
            Utc.timestamp_opt(1_950_000_100, 0).unwrap(),
        )
        .unwrap();
        let plan = CallExecutionPlan::new(
            &aggregate,
            [
                LegExecutionSpec {
                    leg_id: aggregate.legs()[0].id(),
                    endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                        uri: Some("sip:remote@example.test".into()),
                        initial_context: SipInitialContextMode::None,
                    }),
                },
                LegExecutionSpec {
                    leg_id: aggregate.legs()[1].id(),
                    endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                        signaling_uri: Some("wss://signal.example.test/session".into()),
                    }),
                },
            ],
            crate::call_engine::PrincipalFingerprint::new([0xb5; 32]),
        )
        .unwrap();
        let mut encoded = serde_json::to_value(plan).unwrap();
        encoded.as_object_mut().unwrap().remove("leg_semantics");
        let historical: CallExecutionPlan = serde_json::from_value(encoded).unwrap();
        assert_eq!(
            historical.validate_against(&aggregate),
            Err(RepositoryError::InvalidInput(
                "execution plan without semantics requires exact legacy defaults"
            ))
        );
    }

    #[test]
    fn provider_and_amazon_signaling_combinations_fail_before_execution() {
        let amazon = LegEndpointConfig::AmazonConnect(AmazonConnectEndpointConfig {
            instance_id: "instance".into(),
            contact_flow_id: "flow".into(),
        });
        assert!(amazon
            .validate(LegDirection::Outbound, SignalingInitiator::Bridgefu)
            .is_ok());
        assert!(amazon
            .validate(LegDirection::Inbound, SignalingInitiator::Bridgefu)
            .is_err());
        assert!(amazon
            .validate(LegDirection::Outbound, SignalingInitiator::Remote)
            .is_err());

        let provider = LegEndpointConfig::Provider(ProviderEndpointConfig {
            provider: ProviderKind::Telnyx,
            account_profile: "telnyx-test".into(),
            destination: Some("+15551234567".into()),
        });
        assert!(provider
            .validate(LegDirection::Inbound, SignalingInitiator::Bridgefu)
            .is_ok());
        assert!(provider
            .validate(LegDirection::Outbound, SignalingInitiator::Remote)
            .is_err());
    }

    #[test]
    fn endpoint_debug_redacts_uris_destinations_and_profiles() {
        let rendered = [
            format!(
                "{:?}",
                SipEndpointConfig {
                    uri: Some("sip:+15551234567@sip.example.test".into()),
                    initial_context: SipInitialContextMode::None,
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
    fn amazon_client_token_has_one_fixed_effect_id_derivation() {
        let effect_id = "891510ac-f3e4-11e8-af5b-de00688a4901"
            .parse::<crate::call_engine::EffectId>()
            .unwrap();
        let context = valid_amazon_start_spec()
            .originate_context(effect_id)
            .unwrap();

        assert_eq!(
            context.client_token().expose_secret(),
            "jiYZ_C5mDynxpbClrDHvZveoKZ7laNKvDYJkHZXlkMg"
        );
        assert_eq!(context.profile_id().as_str(), "tenant-profile-private");
        assert_eq!(context.target().instance_id(), "instance-private");
        assert_eq!(context.target().contact_flow_id(), "flow-private");
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
            let debug = format!(
                "{:?}",
                ServiceEffectPayload::Transfer {
                    target_leg_id: LegId::new(),
                    target_binding_generation: crate::call_engine::BindingGeneration::INITIAL,
                    target,
                }
            );
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
    fn historical_replacement_payload_decodes_without_route_snapshot_but_fails_validation() {
        let endpoint = LegEndpointConfig::Sip(SipEndpointConfig {
            uri: Some("sips:agent@call-center.example.test".into()),
            initial_context: SipInitialContextMode::None,
        });
        let route = NamedRouteBinding::new_with_profiles(
            "support",
            None,
            vec![NamedProfileBinding::new(
                NamedProfileRole::Destination,
                NamedProfileKind::Sip,
                "support-sip",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap()],
        )
        .unwrap();
        let payload = ServiceEffectPayload::LegReplacement {
            leg_id: LegId::new(),
            previous_binding_generation: crate::call_engine::BindingGeneration::INITIAL,
            pending_binding_generation: crate::call_engine::BindingGeneration::INITIAL
                .next()
                .unwrap(),
            endpoint,
            amazon_connect_start: None,
            route_id: "support".into(),
            replacement_route: Some(route),
            authorization_principal_fingerprint: PrincipalFingerprint::new([0x44; 32]),
        };
        assert!(payload.validate().is_ok());
        let mut historical = serde_json::to_value(payload).unwrap();
        historical
            .as_object_mut()
            .unwrap()
            .remove("replacement_route");
        let decoded: ServiceEffectPayload = serde_json::from_value(historical).unwrap();
        assert!(matches!(
            &decoded,
            ServiceEffectPayload::LegReplacement {
                replacement_route: None,
                ..
            }
        ));
        assert_eq!(
            decoded.validate(),
            Err(RepositoryError::InvalidInput(
                "replacement route snapshot is unavailable"
            ))
        );
    }

    #[test]
    fn replacement_route_requires_one_matching_destination_profile() {
        let sip = LegEndpointConfig::Sip(SipEndpointConfig {
            uri: Some("sips:agent@call-center.example.test".into()),
            initial_context: SipInitialContextMode::None,
        });
        let wrong_kind = NamedRouteBinding::new_with_profiles(
            "support",
            None,
            vec![NamedProfileBinding::new(
                NamedProfileRole::Destination,
                NamedProfileKind::WebRtc,
                "support-web",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .unwrap()],
        )
        .unwrap();
        assert!(wrong_kind
            .validate_replacement_destination("support", &sip)
            .is_err());
        let no_profile = NamedRouteBinding::new("support", None).unwrap();
        assert!(no_profile
            .validate_replacement_destination("support", &sip)
            .is_err());
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
