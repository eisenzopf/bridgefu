//! YAML configuration for bridgefu and the mapping onto the
//! `rvoip-amazon-connect` server types.
//!
//! Multi-tenant SIP-URI routing (CONTRACTS.md B.4): a `tenants:` map keyed by
//! SIP user part routes each INVITE to per-tenant `{instance_id,
//! contact_flow_id, mapping, default_display_name}`. Match order: Request-URI
//! user part → `To:` user part → `default_tenant` → reject `404 Not Found`
//! (+ `bridgefu_unknown_tenant_total`). The legacy single-tenant schema
//! (top-level `aws.instance_id`/`aws.contact_flow_id`) is still accepted and
//! becomes one catch-all tenant named `default`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use ipnet::IpNet;
use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod, BearerValidator};
use rvoip_core::{IdentityAssurance, Jwk, PrincipalOwnershipKey};
use rvoip_sip::{SipAuthService, SipDigestAuthService, SipListenerAuthPolicy};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize;

use bridgefu::broadcast::{PublicUctpBindConfig, SanitizedContextEventPolicy};
use bridgefu::call_engine::{LegDirection, MediaFlow, SignalingInitiator, TenantId, WorkerId};
use bridgefu::call_service::{
    AmazonConnectEndpointConfig, AmazonConnectStartSpec, CallRepositoryBackendConfig,
    CallServiceCoordinationConfig, ConfiguredAttachmentPrincipalResolver, ConfiguredIceServer,
    ConfiguredSipOutboundProfile, ConfiguredSipProfileAuth, ConfiguredWebRtcOutboundProfile,
    LegEndpointConfig, NamedProfileBinding, NamedProfileKind, NamedProfileRole, NamedRouteBinding,
    OutboundProfileResolver, ProviderKind, RequestedLeg, SipEndpointConfig, SipInitialContextMode,
    StaticOutboundProfileResolver, WebRtcEndpointConfig, MAX_CONTROL_KEY_BYTES,
    MIN_CONTROL_KEY_BYTES,
};
use bridgefu::coordination::{DeploymentId, RedisCoordinationConfig};
use bridgefu::gateway_forwarding::{
    GatewayForwardingConfig, MutualTlsFiles, PrivateForwardingLimits, PrivateForwardingTimeouts,
    PrivateTokenKey, PrivateWorkerTarget, WorkerForwardingConfig,
};
use bridgefu::gateway_native_ingress::{
    GatewayNativeIngressConfig, GatewayNativeSipConfig, GatewayNativeWebRtcConfig,
    GatewayNativeWebRtcTlsConfig, SipEgressProfileConfig,
};
use bridgefu::gateway_uctp_ingress::GatewayUctpIngressConfig;
use bridgefu::recipe_admission::{RecipeSipAdmissionCatalog, RecipeSipAdmissionRoute};
use bridgefu::recipes::{
    CompiledRecipe, RecipeAudioCodec, RecipeCatalog, RecipeEndpointSpec, RecipeSelection,
    RecipeSipAuthSpec, SipAdmissionMode, SipAdmissionSpec, SipSecurity,
};
use bridgefu::reference_tenant_canary::{ReferenceTenantCanaryConfig, ReferenceTenantCanaryPolicy};

use rvoip_amazon_connect::{
    request_uri_user, to_uri_user, AmazonConnectAdapter, AttributeMapping, AwsConnectStarter,
    ConnectConfig, ConnectContactStarter, ConnectProfileId, ContactRoute, IncomingCall,
    RouteDecision, ScreenPopServerConfig, SipConfig, UnmappedPolicy,
};

use crate::context::ContextPolicy;
use crate::providers::{ProviderConfigs, ProviderRegistry, SecretRef};

const MIN_BROADCAST_TOKEN_SECRET_BYTES: usize = 32;
const MAX_BROADCAST_TOKEN_TTL_SECS: u64 = 15 * 60;
const MAX_OTLP_ENDPOINT_LENGTH: usize = 2_048;
const MAX_OTLP_SERVICE_NAME_LENGTH: usize = 128;
const MAX_OTLP_QUEUE_SIZE: usize = 65_536;
const MAX_OTLP_EXPORT_BATCH_SIZE: usize = 8_192;
const MIN_OTLP_SCHEDULE_DELAY_MILLIS: u64 = 100;
const MAX_OTLP_SCHEDULE_DELAY_MILLIS: u64 = 60_000;
const MIN_OTLP_EXPORT_TIMEOUT_MILLIS: u64 = 100;
const MAX_OTLP_EXPORT_TIMEOUT_MILLIS: u64 = 60_000;
const MAX_GENERIC_ICE_SERVERS: usize = 16;
const MAX_GENERIC_ICE_URLS_PER_SERVER: usize = 8;
const MAX_GENERIC_ICE_URL_BYTES: usize = 2_048;
const MAX_GENERIC_ICE_IDENTITY_BYTES: usize = 1_024;
const MAX_GENERIC_NAT_IPS: usize = 16;
const MAX_GENERIC_STUN_TARGET_BYTES: usize = 253;
const MAX_GENERIC_SIP_DIGEST_IDENTITY_BYTES: usize = 256;
const MAX_GENERIC_SIP_DIGEST_PASSWORD_BYTES: usize = 1_024;
const MAX_NAMED_PROFILE_ENTRIES: usize = 256;
const MAX_NAMED_PROFILE_LIST_ENTRIES: usize = 64;
const MAX_NAMED_PROFILE_VALUE_BYTES: usize = 2_048;
const MAX_NAMED_PROFILE_SCOPE_BYTES: usize = 256;
const MAX_API_REQUESTS_PER_SECOND: u32 = 100_000;
const MAX_API_BURST: u32 = 1_000_000;
const MAX_API_TRACKED_IDENTITIES: usize = 100_000;
const MAX_API_IDENTITY_IDLE_TTL_SECS: u64 = 3_600;

/// Top-level config (see `config/bridgefu.example.yaml`).
#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_config_version")]
    pub config_version: u32,
    #[serde(default)]
    pub aws: AwsCfg,
    #[serde(default)]
    pub sip: SipCfg,
    /// Optional external, data-only recipe package roots. Built-in packages
    /// are always embedded and available without filesystem access.
    #[serde(default)]
    pub recipe_catalog: RecipeCatalogCfg,
    /// Named recipe instances. Selection uses an exact source:name@version.
    #[serde(default)]
    pub recipes: BTreeMap<String, RecipeSelection>,
    /// Simple public-edge values shared by compiled recipes.
    #[serde(default)]
    pub edge: RecipeEdgeCfg,
    /// Explicit compatibility control for the historical Vapi/Amazon SIP
    /// server. Omission preserves legacy behavior unless recipes are selected.
    #[serde(default)]
    pub legacy_vapi_connect: LegacyVapiConnectCfg,
    /// Runtime-only descriptors retained after deterministic compilation.
    #[serde(skip)]
    pub(crate) compiled_recipes: BTreeMap<String, CompiledRecipe>,
    #[serde(default)]
    pub contact: ContactCfg,
    /// Global header→attribute mapping: the per-tenant default, and the
    /// mapping of the legacy single-tenant schema.
    #[serde(default)]
    pub mapping: MappingCfg,
    #[serde(default)]
    pub observability: ObsCfg,
    /// Tenant to route to when neither the R-URI nor the To user part
    /// matches. `null`/absent → reject unmatched INVITEs with 404.
    #[serde(default)]
    pub default_tenant: Option<String>,
    /// Routing table — key is the SIP user part (e.g. `banking` for
    /// `sip:banking@<eip>`).
    #[serde(default)]
    pub tenants: BTreeMap<String, TenantCfg>,
    #[serde(default)]
    pub runtime: RuntimeCfg,
    /// Private mTLS + UCTP 0.2 transport used only between role-separated
    /// public gateways and call-pinned workers.
    #[serde(default)]
    pub private_forwarding: PrivateForwardingCfg,
    /// Transactional call-state persistence. SQLite is the standalone default;
    /// memory requires an explicit development/test opt-in.
    #[serde(default)]
    pub persistence: PersistenceCfg,
    #[serde(default)]
    pub api: ApiCfg,
    #[serde(default)]
    pub providers: ProviderConfigs,
    /// Authenticated SIP ingress policies for stock Vapi-managed transfers.
    #[serde(default)]
    pub vapi_ingress_profiles: BTreeMap<String, VapiIngressProfileCfg>,
    /// Provider-neutral SIP/SIPS ingress policies generated by recipes or
    /// configured by expert users.
    #[serde(default)]
    pub sip_ingress_profiles: BTreeMap<String, SipIngressProfileCfg>,
    /// Outbound SIP destination policies referenced by named routes.
    #[serde(default)]
    pub sip_profiles: BTreeMap<String, SipProfileCfg>,
    /// Browser ingress and outbound interactive-WSS policies.
    #[serde(default)]
    pub webrtc_profiles: BTreeMap<String, WebRtcProfileCfg>,
    #[serde(default)]
    pub broadcast: BroadcastCfg,
    /// Standalone, role-separated MOQT relay listeners. Required only when
    /// `runtime.mode` is `moq-relay`.
    #[serde(default)]
    pub moq_relay: Option<MoqRelayCfg>,
    #[serde(default)]
    pub context: ContextPolicy,
    #[serde(default)]
    pub generic_bridge: GenericBridgeCfg,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeCatalogCfg {
    #[serde(default)]
    pub paths: Vec<PathBuf>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeEdgeCfg {
    /// Public DNS name used in generated SIP/SIPS attachment URIs.
    #[serde(default)]
    pub public_host: String,
    /// Public RTP/SRTP IP with port zero so each allocated media port is
    /// retained, for example `203.0.113.10:0`.
    #[serde(default)]
    pub media_public_addr: Option<String>,
    /// Server certificate and listener settings for SIPS/SRTP recipes.
    #[serde(default)]
    pub sip_tls: Option<RecipeEdgeSipTlsCfg>,
    /// Public listener settings for the explicit SIP/RTP compatibility
    /// posture.
    #[serde(default)]
    pub sip_rtp: Option<RecipeEdgeSipRtpCfg>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeEdgeSipRtpCfg {
    #[serde(default = "default_recipe_sip_bind")]
    pub bind: String,
    #[serde(default)]
    pub advertised_addr: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeEdgeSipTlsCfg {
    #[serde(default = "default_recipe_sips_bind")]
    pub bind: String,
    #[serde(default)]
    pub advertised_addr: Option<String>,
    pub certificate_chain: String,
    pub private_key: SecretRef,
    #[serde(default)]
    pub client_ca_certificate: Option<String>,
    #[serde(default)]
    pub require_client_certificate: bool,
}

impl fmt::Debug for RecipeEdgeSipTlsCfg {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecipeEdgeSipTlsCfg")
            .field("bind", &self.bind)
            .field("advertised_addr", &self.advertised_addr)
            .field(
                "certificate_chain_configured",
                &!self.certificate_chain.is_empty(),
            )
            .field("private_key", &self.private_key)
            .field(
                "client_ca_configured",
                &self.client_ca_certificate.is_some(),
            )
            .field(
                "require_client_certificate",
                &self.require_client_certificate,
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyVapiConnectCfg {
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct GenericBridgeCfg {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_generic_sip_bind")]
    pub sip_bind: String,
    #[serde(default = "default_webrtc_ws_bind")]
    pub webrtc_ws_bind: String,
    #[serde(default = "default_webrtc_whip_bind")]
    pub webrtc_whip_bind: String,
    /// SIP/RTP address allocation and bounded symmetric-RTP behavior for the
    /// generic bridge. The frozen Amazon listener continues using `sip:`.
    #[serde(default)]
    pub sip: GenericSipNetworkCfg,
    /// ICE/DTLS/TURN behavior for normal rvoip WebRTC legs.
    #[serde(default)]
    pub webrtc: GenericWebRtcNetworkCfg,
    /// Protected compatibility route for `sip:<tenant>` plus
    /// `X-Correlation-Id`. The legacy ReferenceTenant listener remains the
    /// default and this route is inert unless explicitly enabled.
    #[serde(default)]
    pub reference_tenant_canary: ReferenceTenantCanaryCfg,
    #[serde(default)]
    /// Deprecated compatibility field. Generic signaling must use the exact
    /// validator configured at `api.bearer_token`.
    pub bearer_token: Option<SecretRef>,
}

#[derive(Clone, Deserialize)]
pub struct ReferenceTenantCanaryCfg {
    #[serde(default)]
    pub enabled: bool,
    /// The only SIP Request-URI user that can enter the canary route.
    #[serde(default)]
    pub tenant: Option<String>,
    /// Exact authenticated identity. These defaults match the configured
    /// static API-key validator; deployments using another validator must set
    /// both values explicitly.
    #[serde(default = "default_canary_trusted_subject")]
    pub trusted_subject: String,
    #[serde(default = "default_canary_trusted_issuer")]
    pub trusted_issuer: String,
    #[serde(default = "default_canary_correlation_header")]
    pub correlation_header: String,
    /// Non-secret rvoip Amazon profile selector.
    #[serde(default = "default_canary_amazon_profile")]
    pub amazon_profile: String,
}

impl fmt::Debug for ReferenceTenantCanaryCfg {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReferenceTenantCanaryCfg")
            .field("enabled", &self.enabled)
            .field("tenant", &self.tenant)
            .field("trusted_subject", &"[redacted]")
            .field("trusted_issuer", &"[redacted]")
            .field("correlation_header", &self.correlation_header)
            .field("amazon_profile", &"[redacted]")
            .finish()
    }
}

impl Default for ReferenceTenantCanaryCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            tenant: None,
            trusted_subject: default_canary_trusted_subject(),
            trusted_issuer: default_canary_trusted_issuer(),
            correlation_header: default_canary_correlation_header(),
            amazon_profile: default_canary_amazon_profile(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct GenericSipNetworkCfg {
    /// Explicitly permit the shared API Bearer credential on cleartext SIP
    /// transports. This is false by default because UDP/TCP SIP exposes the
    /// reusable credential to every on-path observer. Prefer provider Digest;
    /// enable this only on a separately restricted private/carrier network.
    #[serde(default)]
    pub allow_cleartext_bearer: bool,
    /// Optional first-party Digest identity for a generic SIP peer. This is
    /// the production alternative to a reusable Bearer on UDP/TCP.
    #[serde(default)]
    pub digest: Option<GenericSipDigestCfg>,
    /// Public Via/Contact socket address. Omit to derive it from the bind.
    #[serde(default)]
    pub advertised_addr: Option<String>,
    /// Public SDP address. Port zero retains each allocated RTP port.
    #[serde(default)]
    pub media_public_addr: Option<String>,
    /// Optional one-shot RTP-side STUN discovery target (`host[:port]`).
    #[serde(default)]
    pub stun_server: Option<String>,
    /// Shared SIP TLS listener used by every secure named-route attachment.
    /// A route may advertise `sips:` only when this listener is configured.
    #[serde(default)]
    pub secure_listener: Option<GenericSipSecureListenerCfg>,
    /// Runtime-only Contact owned by a compiled secure-ingress recipe. rvoip
    /// 0.3.7 otherwise falls back to a `sip:` Contact even for an initial
    /// SIPS dialog, which can misroute the 2xx ACK. Expert generic SIP
    /// configurations keep rvoip's existing Contact derivation.
    #[serde(skip)]
    recipe_contact_uri: Option<RecipeSipContactUri>,
    /// SDES-SRTP posture for the inbound/default SIP child. Named outbound
    /// profiles run in independently configured rvoip children.
    #[serde(default = "default_generic_sip_srtp")]
    pub srtp: ProfileSrtpPolicy,
    #[serde(default = "default_generic_rtp_port_start")]
    pub rtp_port_start: u16,
    #[serde(default = "default_generic_rtp_port_end")]
    pub rtp_port_end: u16,
    #[serde(default)]
    pub symmetric_rtp: GenericSymmetricRtpCfg,
}

#[derive(Clone)]
struct RecipeSipContactUri(String);

impl RecipeSipContactUri {
    fn sips_dns(public_host: &str, port: u16) -> Result<Self> {
        validate_recipe_public_dns_name(public_host)?;
        if port == 0 {
            return Err(anyhow!(
                "secure recipe Contact requires a nonzero SIP TLS port"
            ));
        }
        Ok(Self(format!(
            "sips:bridgefu@{public_host}:{port};transport=tls"
        )))
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RecipeSipContactUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenericSipSecureListenerCfg {
    /// Dedicated SIP TLS bind. It may share the IP, but not the port, of the
    /// cleartext SIP listener.
    pub bind: String,
    /// Public TLS Via/Contact socket address. Omit only for a concrete bind.
    #[serde(default)]
    pub advertised_addr: Option<String>,
    /// PEM certificate-chain path.
    pub certificate_chain: String,
    /// Secret reference resolving to the matching PKCS#8 private-key path.
    pub private_key: SecretRef,
    /// Optional PEM CA bundle for inbound client-certificate verification.
    #[serde(default)]
    pub client_ca_certificate: Option<String>,
    /// Require every TLS peer to present a verified client certificate.
    #[serde(default)]
    pub require_client_certificate: bool,
}

impl fmt::Debug for GenericSipSecureListenerCfg {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GenericSipSecureListenerCfg")
            .field("bind", &self.bind)
            .field("advertised_addr", &self.advertised_addr)
            .field(
                "certificate_chain_configured",
                &!self.certificate_chain.is_empty(),
            )
            .field("private_key", &self.private_key)
            .field(
                "client_ca_configured",
                &self.client_ca_certificate.is_some(),
            )
            .field(
                "require_client_certificate",
                &self.require_client_certificate,
            )
            .finish()
    }
}

#[derive(Clone, Deserialize)]
pub struct GenericSipDigestCfg {
    pub realm: String,
    pub username: String,
    pub password: SecretRef,
}

impl fmt::Debug for GenericSipDigestCfg {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GenericSipDigestCfg")
            .field("realm_configured", &!self.realm.is_empty())
            .field("username", &"[redacted]")
            .field("password", &self.password)
            .finish()
    }
}

impl GenericSipDigestCfg {
    fn validate(&self) -> Result<()> {
        let realm_valid = !self.realm.is_empty()
            && self.realm.len() <= MAX_GENERIC_SIP_DIGEST_IDENTITY_BYTES
            && self.realm.trim() == self.realm
            && !self.realm.chars().any(char::is_control);
        if !realm_valid {
            return Err(anyhow!(
                "generic_bridge.sip.digest.realm must be a bounded, trimmed, control-free value"
            ));
        }
        let username_valid = !self.username.is_empty()
            && self.username.len() <= MAX_GENERIC_SIP_DIGEST_IDENTITY_BYTES
            && self.username.trim() == self.username
            && self
                .username
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
        if !username_valid {
            return Err(anyhow!(
                "generic_bridge.sip.digest.username must contain only ASCII letters, digits, dot, dash, or underscore"
            ));
        }
        let mut password = self
            .password
            .resolve()
            .context("resolving generic_bridge.sip.digest.password")?;
        let valid = !password.is_empty()
            && password.len() <= MAX_GENERIC_SIP_DIGEST_PASSWORD_BYTES
            && !password.bytes().any(|byte| byte.is_ascii_control());
        password.zeroize();
        if !valid {
            return Err(anyhow!(
                "generic_bridge.sip.digest.password must resolve to 1..={MAX_GENERIC_SIP_DIGEST_PASSWORD_BYTES} control-free bytes"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub struct GenericSymmetricRtpCfg {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub allow_ip_change: bool,
    #[serde(default = "default_symmetric_rtp_probation")]
    pub probation_packets: u8,
    #[serde(default = "default_symmetric_rtp_rebindings")]
    pub max_rebindings: u8,
    #[serde(default = "default_symmetric_rtp_window")]
    pub rebind_window_secs: u64,
    #[serde(default = "default_symmetric_rtp_sequence_jump")]
    pub max_sequence_jump: u16,
}

#[derive(Clone, Debug, Deserialize)]
pub struct GenericWebRtcNetworkCfg {
    #[serde(default = "default_generic_webrtc_udp_bind")]
    pub udp_bind: String,
    /// Optional bounded alternative to `udp_bind`. Each browser or Amazon
    /// Connect peer atomically claims one socket from this inclusive range.
    #[serde(default)]
    pub udp_port_range: Option<GenericWebRtcUdpPortRangeCfg>,
    /// Primary audio codecs registered by the public WebRTC edge. The
    /// production default is intentionally Opus-only so a browser answer has
    /// one deterministic primary RTP payload mapping.
    #[serde(default = "default_generic_webrtc_audio_codecs")]
    pub audio_codecs: BTreeSet<GenericWebRtcAudioCodec>,
    /// Omitted preserves rvoip's default STUN entry; an explicit empty list
    /// disables external ICE servers.
    #[serde(default)]
    pub ice_servers: Option<Vec<GenericIceServerCfg>>,
    #[serde(default)]
    pub ice_transport_policy: GenericIceTransportPolicy,
    #[serde(default)]
    pub nat_1to1_ips: Vec<String>,
    #[serde(default)]
    pub nat_1to1_candidate_type: GenericNatCandidateType,
    #[serde(default = "default_webrtc_gather_timeout")]
    pub gather_timeout_secs: u64,
    #[serde(default = "default_webrtc_connection_timeout")]
    pub connection_timeout_secs: u64,
    #[serde(default = "default_true")]
    pub trickle_ice: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenericWebRtcUdpPortRangeCfg {
    pub bind_ip: String,
    pub port_start: u16,
    pub port_end: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum GenericWebRtcAudioCodec {
    Opus,
    Pcmu,
    Pcma,
}

#[derive(Clone, Debug, Deserialize)]
pub struct GenericIceServerCfg {
    pub urls: Vec<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub credential: Option<SecretRef>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GenericIceTransportPolicy {
    #[default]
    All,
    Relay,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GenericNatCandidateType {
    #[default]
    Host,
    Srflx,
}

impl GenericBridgeCfg {
    fn validate_networking(&self) -> Result<()> {
        let sip_bind = self
            .sip_bind
            .parse::<SocketAddr>()
            .map_err(|_| anyhow!("generic_bridge.sip_bind must be a socket address"))?;
        self.webrtc_ws_bind
            .parse::<SocketAddr>()
            .map_err(|_| anyhow!("generic_bridge.webrtc_ws_bind must be a socket address"))?;
        self.webrtc_whip_bind
            .parse::<SocketAddr>()
            .map_err(|_| anyhow!("generic_bridge.webrtc_whip_bind must be a socket address"))?;
        self.sip.validate()?;
        if let Some(tls) = &self.sip.secure_listener {
            let tls_bind = tls.bind.parse::<SocketAddr>().map_err(|_| {
                anyhow!("generic_bridge.sip.secure_listener.bind must be a socket address")
            })?;
            if tls_bind.port() == 0 || tls_bind == sip_bind {
                return Err(anyhow!(
                    "generic_bridge.sip.secure_listener.bind must use a nonzero address distinct from sip_bind"
                ));
            }
        }
        let _ = self.webrtc.resolved_config()?;
        Ok(())
    }

    pub(crate) fn sip_stack_config(
        &self,
        name: &str,
        bind: SocketAddr,
    ) -> Result<(rvoip_sip::Config, rvoip_sip::SipNatConfig)> {
        self.sip.runtime_config(name, bind)
    }

    pub(crate) fn webrtc_stack_config(&self) -> Result<rvoip_webrtc::WebRtcConfig> {
        self.webrtc.resolved_config()
    }

    pub(crate) fn sip_auth_service(
        &self,
        providers: &ProviderConfigs,
        validator: Arc<dyn BearerValidator>,
        bearer_scope: &'static str,
    ) -> Result<SipAuthService> {
        self.sip.validate()?;
        let mut authentication = SipAuthService::new()
            .with_bearer_validator("bridgefu", validator)
            .with_bearer_scope(bearer_scope)
            .with_required_bearer_scope(bearer_scope)
            .allow_bearer_over_cleartext(self.sip.allow_cleartext_bearer);

        let generic = self.sip.digest.as_ref();
        let telnyx = providers.telnyx.as_ref();
        if let Some(realm) = generic
            .map(|digest| digest.realm.as_str())
            .or_else(|| telnyx.map(|provider| provider.media_sip_realm.as_str()))
        {
            if generic.is_some_and(|digest| digest.realm != realm)
                || telnyx.is_some_and(|provider| provider.media_sip_realm != realm)
                || generic.zip(telnyx).is_some_and(|(digest, provider)| {
                    digest.username == provider.media_sip_username
                })
            {
                return Err(anyhow!(
                    "generic and Telnyx SIP Digest identities have ambiguous namespaces"
                ));
            }
            let digest_service = SipDigestAuthService::new(realm.to_owned());
            if let Some(digest) = generic {
                digest_service.add_user(
                    digest.username.clone(),
                    digest
                        .password
                        .resolve()
                        .context("resolving generic gateway SIP Digest credential")?,
                );
            }
            if let Some(provider) = telnyx {
                digest_service.add_user(
                    provider.media_sip_username.clone(),
                    provider
                        .media_sip_password
                        .resolve()
                        .context("resolving gateway Telnyx SIP credential")?,
                );
            }
            authentication = authentication.with_digest_service(digest_service);
        }
        Ok(authentication)
    }
}

impl GenericSipNetworkCfg {
    fn validate(&self) -> Result<()> {
        if let Some(digest) = &self.digest {
            digest.validate()?;
        }
        if self.rtp_port_start < 1_024 || self.rtp_port_end < self.rtp_port_start {
            return Err(anyhow!(
                "generic_bridge.sip RTP range must start at or above 1024 and end at or after its start"
            ));
        }
        if self.media_public_addr.is_some() && self.stun_server.is_some() {
            return Err(anyhow!(
                "generic_bridge.sip.media_public_addr and stun_server are mutually exclusive"
            ));
        }
        if let Some(value) = &self.advertised_addr {
            let address = value.parse::<SocketAddr>().map_err(|_| {
                anyhow!("generic_bridge.sip.advertised_addr must be a socket address")
            })?;
            if address.ip().is_unspecified() || address.port() == 0 {
                return Err(anyhow!(
                    "generic_bridge.sip.advertised_addr must have a concrete IP and nonzero port"
                ));
            }
        }
        if let Some(value) = &self.media_public_addr {
            let address = value.parse::<SocketAddr>().map_err(|_| {
                anyhow!("generic_bridge.sip.media_public_addr must be a socket address")
            })?;
            if address.ip().is_unspecified() {
                return Err(anyhow!(
                    "generic_bridge.sip.media_public_addr must have a concrete IP"
                ));
            }
        }
        if let Some(target) = &self.stun_server {
            if target.is_empty()
                || target.len() > MAX_GENERIC_STUN_TARGET_BYTES
                || target.chars().any(char::is_control)
                || target.chars().any(char::is_whitespace)
            {
                return Err(anyhow!(
                    "generic_bridge.sip.stun_server must be a bounded host[:port] without whitespace or controls"
                ));
            }
        }
        if let Some(tls) = &self.secure_listener {
            let bind = tls.bind.parse::<SocketAddr>().map_err(|_| {
                anyhow!("generic_bridge.sip.secure_listener.bind must be a socket address")
            })?;
            if bind.port() == 0 {
                return Err(anyhow!(
                    "generic_bridge.sip.secure_listener.bind must use a nonzero port"
                ));
            }
            if let Some(advertised) = &tls.advertised_addr {
                let advertised = advertised.parse::<SocketAddr>().map_err(|_| {
                    anyhow!("generic_bridge.sip.secure_listener.advertised_addr must be a socket address")
                })?;
                if advertised.ip().is_unspecified() || advertised.port() == 0 {
                    return Err(anyhow!(
                        "generic_bridge.sip.secure_listener.advertised_addr must be concrete"
                    ));
                }
            } else if bind.ip().is_unspecified() {
                return Err(anyhow!(
                    "generic_bridge.sip.secure_listener.advertised_addr is required for an unspecified bind"
                ));
            }
            validate_profile_path(
                &tls.certificate_chain,
                "generic_bridge.sip.secure_listener.certificate_chain",
            )?;
            validate_secret_reference(&tls.private_key)?;
            if let Some(client_ca) = &tls.client_ca_certificate {
                validate_profile_path(
                    client_ca,
                    "generic_bridge.sip.secure_listener.client_ca_certificate",
                )?;
            }
            if tls.require_client_certificate && tls.client_ca_certificate.is_none() {
                return Err(anyhow!(
                    "generic_bridge.sip.secure_listener requires a client CA when client certificates are mandatory"
                ));
            }
        }
        if self.recipe_contact_uri.is_some()
            && (self.secure_listener.is_none() || self.srtp == ProfileSrtpPolicy::Disabled)
        {
            return Err(anyhow!(
                "a secure recipe Contact requires a recipe SIPS listener with SRTP enabled"
            ));
        }
        self.symmetric_rtp
            .policy()
            .validate()
            .map_err(|detail| anyhow!("invalid generic_bridge.sip.symmetric_rtp policy: {detail}"))
    }

    fn runtime_config(
        &self,
        name: &str,
        bind: SocketAddr,
    ) -> Result<(rvoip_sip::Config, rvoip_sip::SipNatConfig)> {
        self.validate()?;
        let mut config = rvoip_sip::Config::on(name, bind.ip(), bind.port())
            .with_media_ports(self.rtp_port_start, self.rtp_port_end);
        if let Some(address) = &self.advertised_addr {
            config = config.with_sip_advertised_addr(
                address
                    .parse()
                    .map_err(|_| anyhow!("invalid generic SIP advertised address"))?,
            );
        }
        if let Some(address) = &self.media_public_addr {
            let media_public_addr = address
                .parse::<SocketAddr>()
                .map_err(|_| anyhow!("invalid generic SIP media public address"))?;
            config = config.with_media_public_addr(media_public_addr);
            // rvoip uses Config::local_ip for RTP socket allocation, while
            // Config::bind_addr owns the clear SIP listener. Secure recipes
            // intentionally keep that clear listener on loopback, but a
            // loopback-bound RTP socket cannot send to or receive from the
            // advertised public media address (Linux sendto returns EINVAL).
            // Preserve the loopback signaling listener and bind media on the
            // matching wildcard family whenever public media is advertised.
            if bind.ip().is_loopback() && !media_public_addr.ip().is_loopback() {
                config.local_ip = match media_public_addr.ip() {
                    IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                };
            }
        }
        config.stun_server.clone_from(&self.stun_server);
        if let Some(tls) = &self.secure_listener {
            let tls_bind = tls
                .bind
                .parse()
                .map_err(|_| anyhow!("invalid generic SIP TLS bind"))?;
            let mut private_key = tls
                .private_key
                .resolve()
                .context("resolving generic SIP TLS private-key path")?;
            let private_key_valid = validate_profile_path(
                &private_key,
                "generic_bridge.sip.secure_listener.private_key",
            );
            if let Err(error) = private_key_valid {
                private_key.zeroize();
                return Err(error);
            }
            config = config.tls_reachable_contact(
                tls_bind,
                tls.certificate_chain.clone(),
                private_key.clone(),
            );
            private_key.zeroize();
            if let Some(advertised) = &tls.advertised_addr {
                config.tls_advertised_addr = Some(
                    advertised
                        .parse()
                        .map_err(|_| anyhow!("invalid generic SIP TLS advertised address"))?,
                );
            }
            if let Some(client_ca) = &tls.client_ca_certificate {
                config = if tls.require_client_certificate {
                    config.require_tls_client_certificate(client_ca.clone())
                } else {
                    config.verify_optional_tls_client_certificate(client_ca.clone())
                };
            }
        }
        if let Some(contact_uri) = &self.recipe_contact_uri {
            config.contact_uri = Some(contact_uri.expose().to_owned());
        }
        config.offer_srtp = self.srtp != ProfileSrtpPolicy::Disabled;
        config.srtp_required = self.srtp == ProfileSrtpPolicy::Required;
        let nat = rvoip_sip::SipNatConfig::default()
            .with_symmetric_rtp_policy(self.symmetric_rtp.policy());
        Ok((config, nat))
    }
}

impl GenericSymmetricRtpCfg {
    fn policy(self) -> rvoip_sip::SymmetricRtpPolicy {
        rvoip_sip::SymmetricRtpPolicy {
            enabled: self.enabled,
            allow_ip_change: self.allow_ip_change,
            probation_packets: self.probation_packets,
            max_rebindings: self.max_rebindings,
            rebind_window: Duration::from_secs(self.rebind_window_secs),
            max_sequence_jump: self.max_sequence_jump,
        }
    }
}

impl GenericWebRtcNetworkCfg {
    fn resolved_config(&self) -> Result<rvoip_webrtc::WebRtcConfig> {
        self.udp_bind
            .parse::<SocketAddr>()
            .map_err(|_| anyhow!("generic_bridge.webrtc.udp_bind must be a socket address"))?;
        if !(1..=60).contains(&self.gather_timeout_secs)
            || !(1..=120).contains(&self.connection_timeout_secs)
            || self.connection_timeout_secs < self.gather_timeout_secs
        {
            return Err(anyhow!(
                "generic_bridge.webrtc timeouts require gather 1..=60 seconds and connection 1..=120 seconds no shorter than gather"
            ));
        }
        if self.nat_1to1_ips.len() > MAX_GENERIC_NAT_IPS {
            return Err(anyhow!(
                "generic_bridge.webrtc.nat_1to1_ips supports at most {MAX_GENERIC_NAT_IPS} addresses"
            ));
        }
        if self.audio_codecs.is_empty() || self.audio_codecs.len() > 3 {
            return Err(anyhow!(
                "generic_bridge.webrtc.audio_codecs must contain 1..=3 distinct supported codecs"
            ));
        }
        let mut seen_nat = BTreeSet::new();
        for raw in &self.nat_1to1_ips {
            let ip = raw.parse::<IpAddr>().map_err(|_| {
                anyhow!("generic_bridge.webrtc.nat_1to1_ips must contain IP addresses")
            })?;
            if ip.is_unspecified() || ip.is_multicast() || !seen_nat.insert(ip) {
                return Err(anyhow!(
                    "generic_bridge.webrtc.nat_1to1_ips must contain distinct concrete unicast addresses"
                ));
            }
        }

        let mut config = rvoip_webrtc::WebRtcConfig::default();
        let available = std::mem::take(&mut config.capabilities.audio_codecs);
        config.capabilities.audio_codecs = self
            .audio_codecs
            .iter()
            .map(|configured| {
                let expected = match configured {
                    GenericWebRtcAudioCodec::Opus => "opus",
                    GenericWebRtcAudioCodec::Pcmu => "g.711-mu",
                    GenericWebRtcAudioCodec::Pcma => "g.711-a",
                };
                available
                    .iter()
                    .find(|codec| codec.name.eq_ignore_ascii_case(expected))
                    .cloned()
                    .ok_or_else(|| anyhow!("rvoip omitted a configured WebRTC audio codec"))
            })
            .collect::<Result<Vec<_>>>()?;
        config.udp_bind.clone_from(&self.udp_bind);
        config.udp_port_range = self
            .udp_port_range
            .as_ref()
            .map(|range| {
                let bind_ip = range.bind_ip.parse::<IpAddr>().map_err(|_| {
                    anyhow!("generic_bridge.webrtc.udp_port_range.bind_ip must be an IP address")
                })?;
                if bind_ip.is_multicast()
                    || range.port_start == 0
                    || range.port_start > range.port_end
                {
                    return Err(anyhow!(
                        "generic_bridge.webrtc.udp_port_range requires a non-multicast bind IP and an inclusive nonzero start <= end"
                    ));
                }
                Ok(rvoip_webrtc::UdpPortRangeConfig {
                    bind_ip,
                    port_start: range.port_start,
                    port_end: range.port_end,
                })
            })
            .transpose()?;
        config.nat_1to1_ips.clone_from(&self.nat_1to1_ips);
        config.nat_1to1_candidate_type = match self.nat_1to1_candidate_type {
            GenericNatCandidateType::Host => rvoip_webrtc::Nat1To1CandidateType::Host,
            GenericNatCandidateType::Srflx => rvoip_webrtc::Nat1To1CandidateType::Srflx,
        };
        config.gather_timeout_secs = self.gather_timeout_secs;
        config.connection_timeout_secs = self.connection_timeout_secs;
        config.trickle_ice = self.trickle_ice;
        config.ice_transport_policy = match self.ice_transport_policy {
            GenericIceTransportPolicy::All => rvoip_webrtc::config::IceTransportPolicy::All,
            GenericIceTransportPolicy::Relay => rvoip_webrtc::config::IceTransportPolicy::Relay,
        };

        if let Some(servers) = &self.ice_servers {
            if servers.len() > MAX_GENERIC_ICE_SERVERS {
                return Err(anyhow!(
                    "generic_bridge.webrtc.ice_servers supports at most {MAX_GENERIC_ICE_SERVERS} entries"
                ));
            }
            let mut resolved = Vec::with_capacity(servers.len());
            for server in servers {
                resolved.push(server.resolve()?);
            }
            config.ice_servers = resolved;
        }

        let has_turn = config
            .ice_servers
            .iter()
            .flat_map(|server| &server.urls)
            .any(|url| is_turn_url(url));
        let has_stun = config
            .ice_servers
            .iter()
            .flat_map(|server| &server.urls)
            .any(|url| is_stun_url(url));
        if self.ice_transport_policy == GenericIceTransportPolicy::Relay && !has_turn {
            return Err(anyhow!(
                "generic_bridge.webrtc relay policy requires at least one TURN URL"
            ));
        }
        if !self.nat_1to1_ips.is_empty()
            && self.nat_1to1_candidate_type == GenericNatCandidateType::Srflx
            && has_stun
        {
            return Err(anyhow!(
                "generic_bridge.webrtc srflx one-to-one NAT mapping cannot be combined with STUN URLs"
            ));
        }
        Ok(config)
    }
}

impl GenericIceServerCfg {
    fn resolve(&self) -> Result<rvoip_webrtc::IceServerConfig> {
        if self.urls.is_empty() || self.urls.len() > MAX_GENERIC_ICE_URLS_PER_SERVER {
            return Err(anyhow!(
                "each generic_bridge.webrtc ICE server requires 1..={MAX_GENERIC_ICE_URLS_PER_SERVER} URLs"
            ));
        }
        let mut has_turn = false;
        for url in &self.urls {
            if url.is_empty()
                || url.len() > MAX_GENERIC_ICE_URL_BYTES
                || url.chars().any(char::is_control)
                || url.chars().any(char::is_whitespace)
                || !(is_stun_url(url) || is_turn_url(url))
            {
                return Err(anyhow!(
                    "generic_bridge.webrtc ICE URLs must use stun, stuns, turn, or turns and be bounded without whitespace or controls"
                ));
            }
            has_turn |= is_turn_url(url);
        }
        if self.username.is_some() != self.credential.is_some()
            || (self.username.is_some() && !has_turn)
        {
            return Err(anyhow!(
                "generic_bridge.webrtc ICE username and credential must be paired and are valid only for TURN"
            ));
        }
        let username = self.username.clone();
        if username.as_deref().is_some_and(|value| {
            value.is_empty()
                || value.len() > MAX_GENERIC_ICE_IDENTITY_BYTES
                || value.chars().any(char::is_control)
        }) {
            return Err(anyhow!(
                "generic_bridge.webrtc TURN username must be bounded and control-free"
            ));
        }
        let credential = match &self.credential {
            Some(secret) => {
                let value = secret.resolve().map_err(|error| {
                    anyhow!("resolving generic_bridge.webrtc TURN credential: {error}")
                })?;
                if value.is_empty()
                    || value.len() > MAX_GENERIC_ICE_IDENTITY_BYTES
                    || value.chars().any(char::is_control)
                {
                    return Err(anyhow!(
                        "generic_bridge.webrtc TURN credential must be bounded and control-free"
                    ));
                }
                Some(value)
            }
            None => None,
        };
        Ok(rvoip_webrtc::IceServerConfig {
            urls: self.urls.clone(),
            username,
            credential,
        })
    }
}

fn is_stun_url(value: &str) -> bool {
    value.starts_with("stun:") || value.starts_with("stuns:")
}

fn is_turn_url(value: &str) -> bool {
    value.starts_with("turn:") || value.starts_with("turns:")
}

#[derive(Debug, Deserialize)]
pub struct RuntimeCfg {
    #[serde(default)]
    pub mode: RuntimeMode,
    #[serde(default = "default_max_calls")]
    pub max_concurrent_calls: usize,
    #[serde(default = "default_setup_timeout")]
    pub setup_timeout_secs: u64,
    /// Maximum idle interval after authoritative media activity begins.
    #[serde(default = "default_media_idle_timeout")]
    pub media_idle_timeout_secs: u64,
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout_secs: u64,
}

#[derive(Debug, Default, Deserialize)]
pub struct PrivateForwardingCfg {
    #[serde(default)]
    pub enabled: bool,
    /// Shared HMAC key for short-lived gateway JWTs. mTLS remains mandatory;
    /// the token binds worker audience, tenant, gateway subject, scopes, and
    /// expiry at the UCTP authorization layer.
    #[serde(default)]
    pub token_signing_secret: Option<SecretRef>,
    #[serde(default)]
    pub gateway: Option<PrivateForwardingGatewayCfg>,
    #[serde(default)]
    pub worker: Option<PrivateForwardingWorkerCfg>,
    #[serde(default)]
    pub limits: PrivateForwardingLimitsCfg,
    #[serde(default)]
    pub timeouts: PrivateForwardingTimeoutsCfg,
}

#[derive(Debug, Deserialize)]
pub struct PrivateForwardingGatewayCfg {
    pub gateway_id: String,
    #[serde(default = "default_private_gateway_bind")]
    pub bind: String,
    pub tls: PrivateForwardingTlsCfg,
    pub workers: Vec<PrivateForwardingWorkerTargetCfg>,
    /// Public UCTP signaling/media listener implemented by the split gateway.
    /// HTTP call control shares the observability bind; native SIP and WebRTC
    /// listeners remain disabled until they can forward complete leg state.
    #[serde(default)]
    pub public_uctp: Option<PublicUctpListenerCfg>,
}

#[derive(Debug, Deserialize)]
pub struct PrivateForwardingWorkerCfg {
    #[serde(default = "default_private_worker_bind")]
    pub bind: String,
    pub tls: PrivateForwardingTlsCfg,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PrivateForwardingWorkerTargetCfg {
    pub worker_id: String,
    pub endpoint: String,
    pub server_name: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PrivateForwardingTlsCfg {
    pub certificate_chain: Vec<String>,
    pub private_key: String,
    pub peer_ca_certificates: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PrivateForwardingLimitsCfg {
    #[serde(default = "default_private_active_routes")]
    pub max_active_routes: usize,
    #[serde(default = "default_private_peer_connections")]
    pub max_peer_connections: usize,
    #[serde(default = "default_private_routes_per_peer")]
    pub max_routes_per_peer: usize,
    #[serde(default = "default_private_media_queue")]
    pub media_queue_capacity: usize,
    #[serde(default = "default_private_reliable_queue")]
    pub reliable_queue_capacity: usize,
    #[serde(default = "default_private_inbound_queue")]
    pub inbound_queue_capacity: usize,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PrivateForwardingTimeoutsCfg {
    #[serde(default = "default_private_connect_timeout")]
    pub connect_secs: u64,
    #[serde(default = "default_private_signaling_timeout")]
    pub signaling_secs: u64,
    #[serde(default = "default_private_token_ttl")]
    pub token_ttl_secs: u64,
    #[serde(default = "default_private_health_interval")]
    pub health_interval_secs: u64,
}

/// Process topology selected for this Bridgefu binary.
///
/// Keeping this typed prevents an unknown role from reaching startup and makes
/// it impossible for role dispatch to silently fall back to all-in-one.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeMode {
    /// Compatibility deployment: public ingress, call execution, and Amazon
    /// Connect media remain in the existing single process.
    #[default]
    AllInOne,
    /// Public signaling/control edge. This remains fail-closed until the
    /// PostgreSQL/Redis call-control authority and private authenticated
    /// gateway-to-worker forwarding dependency are configured and healthy.
    Gateway,
    /// Durable call execution worker with no public signaling or control API.
    Worker,
    /// Standalone MOQT relay. This remains fail-closed until its production
    /// TLS/admission configuration can be represented by Bridgefu config.
    MoqRelay,
}

impl RuntimeMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllInOne => "all-in-one",
            Self::Gateway => "gateway",
            Self::Worker => "worker",
            Self::MoqRelay => "moq-relay",
        }
    }
}

impl std::fmt::Display for RuntimeMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Transactional call-state repository configuration.
#[derive(Debug, Deserialize)]
pub struct PersistenceCfg {
    /// `sqlite` (default), `postgres`, or explicitly ephemeral `memory`.
    #[serde(default)]
    pub backend: PersistenceBackend,
    /// Secret-bearing SQL connection URL. SQLite defaults to a local file.
    #[serde(default)]
    pub database_url: Option<SecretRef>,
    /// Stable non-nil worker UUID. Required for PostgreSQL clusters.
    #[serde(default)]
    pub worker_id: Option<String>,
    /// Required acknowledgement for the non-durable memory backend.
    #[serde(default)]
    pub allow_ephemeral_memory: bool,
    /// Deployment namespace shared by coordination outbox rows and Redis keys.
    #[serde(default = "default_deployment_id")]
    pub deployment_id: String,
    /// Bounded database-authoritative lease duration.
    #[serde(default = "default_worker_lease_ttl")]
    pub worker_lease_ttl_secs: u64,
    /// Supervised database renewal cadence.
    #[serde(default = "default_worker_renew_interval")]
    pub worker_renew_interval_secs: u64,
    /// Capability allowlist requested for this worker. Process construction
    /// intersects it with the concrete adapters/providers actually installed
    /// before registration; configuration alone never creates capability.
    #[serde(default = "default_worker_capabilities")]
    pub worker_capabilities: BTreeSet<String>,
    /// Optional secret-bearing Redis URL for projection and wakeup hints.
    #[serde(default)]
    pub redis_url: Option<SecretRef>,
    /// Require TLS (`rediss://`) for clustered Redis coordination.
    #[serde(default)]
    pub redis_clustered: bool,
    /// Dev/test-only acknowledgement for PostgreSQL without Redis. This is
    /// valid only in all-in-one mode and is never inferred from a missing URL.
    #[serde(default)]
    pub allow_db_only_coordination: bool,
}

/// Supported transactional repository implementations.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PersistenceBackend {
    /// Durable local storage for an all-in-one process.
    #[default]
    Sqlite,
    /// Durable clustered storage.
    #[serde(alias = "postgresql")]
    Postgres,
    /// Explicitly ephemeral development/test storage.
    Memory,
}

#[derive(Debug, Deserialize)]
pub struct ApiCfg {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Dedicated public HTTP bind for role-separated gateway call control and
    /// provider webhooks. Health and metrics remain on
    /// `observability.http_bind` and are never mounted on this listener.
    #[serde(default)]
    pub http_bind: Option<String>,
    /// Server-side TLS for the split gateway API listener. Plain HTTP is
    /// permitted only when `http_bind` is a loopback address.
    #[serde(default)]
    pub tls: Option<ApiTlsCfg>,
    /// Optional shared Bearer API key. Use `env:VARIABLE` in production.
    #[serde(default)]
    pub bearer_token: Option<SecretRef>,
    /// HMAC key for durable idempotency digests and attachment tokens.
    /// The call API remains unavailable when this is unset.
    #[serde(default)]
    pub control_hmac_key: Option<SecretRef>,
    /// Explicit tenant assigned to the compatibility shared API key.
    /// Required when more than one routing tenant is configured.
    #[serde(default)]
    pub static_tenant: Option<String>,
    /// Bounded token-bucket admission for authenticated control principals,
    /// diagnostics, and the unauthenticated provider-webhook ingress.
    #[serde(default)]
    pub rate_limit: ApiRateLimitCfg,
    /// Server-owned route catalog. Public callers select only a map key;
    /// endpoint and provider details never appear in route-create requests.
    #[serde(default)]
    pub routes: BTreeMap<String, NamedRouteCfg>,
    /// Public signaling descriptors used to materialize one-use attachments.
    #[serde(default)]
    pub route_attachments: RouteAttachmentCfg,
}

/// Public ingress accepted by one named route.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NamedRouteIngress {
    Sip,
    Webrtc,
}

fn default_named_route_ingress() -> BTreeSet<NamedRouteIngress> {
    BTreeSet::from([NamedRouteIngress::Sip, NamedRouteIngress::Webrtc])
}

fn default_profile_codecs() -> BTreeSet<ProfileAudioCodec> {
    BTreeSet::from([ProfileAudioCodec::Pcmu, ProfileAudioCodec::Opus])
}

fn default_true_profile_policy() -> bool {
    true
}

fn default_generic_sip_srtp() -> ProfileSrtpPolicy {
    ProfileSrtpPolicy::Disabled
}

/// Audio codecs admitted by a named signaling profile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ProfileAudioCodec {
    Pcmu,
    Pcma,
    Opus,
}

/// Vapi-managed SIP ingress authentication, transport, and codec policy.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VapiIngressProfileCfg {
    pub tenant_id: String,
    pub principal_subject: String,
    pub issuer: String,
    #[serde(default)]
    pub scopes: BTreeSet<String>,
    pub trusted_signaling_cidrs: Vec<String>,
    pub tls: ProfileTlsIdentityCfg,
    #[serde(default)]
    pub digest: Option<ProfileDigestCfg>,
    #[serde(default)]
    pub mtls_peer_ca_certificates: Vec<String>,
    /// Transport-verified client leaf-certificate SHA-256 fingerprints that
    /// map to this profile's explicit principal. A trusted CA by itself never
    /// assigns an application identity.
    #[serde(default)]
    pub mtls_leaf_certificate_sha256_fingerprints: Vec<String>,
    #[serde(default = "default_true_profile_policy")]
    pub srtp_required: bool,
    #[serde(default = "default_profile_codecs")]
    pub codecs: BTreeSet<ProfileAudioCodec>,
}

/// Provider-neutral SIP ingress authentication and transport posture.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SipIngressProfileCfg {
    pub tenant_id: String,
    pub principal_subject: String,
    pub issuer: String,
    #[serde(default)]
    pub scopes: BTreeSet<String>,
    pub trusted_signaling_cidrs: Vec<String>,
    pub security: SipIngressSecurity,
    #[serde(default)]
    pub tls: Option<ProfileTlsIdentityCfg>,
    #[serde(default)]
    pub digest: Option<ProfileDigestCfg>,
    #[serde(default)]
    pub mtls_peer_ca_certificates: Vec<String>,
    #[serde(default)]
    pub mtls_leaf_certificate_sha256_fingerprints: Vec<String>,
    #[serde(default = "default_profile_codecs")]
    pub codecs: BTreeSet<ProfileAudioCodec>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SipIngressSecurity {
    SipsSrtp,
    SipsOptionalSrtp,
    SipRtp,
}

/// Runtime-only projection of one referenced Vapi profile into the shared SIP
/// listener. It deliberately owns rvoip types so Bridgefu's public route and
/// profile models never expose listener implementation details.
struct VapiListenerPrincipalProjection {
    profile_id: String,
    principal: AuthenticatedPrincipal,
    trusted_cidrs: Vec<IpNet>,
    mtls_leaf_fingerprints: Vec<String>,
}

#[derive(Clone, Eq, PartialEq)]
struct VapiProjectedIdentity {
    ownership: PrincipalOwnershipKey,
    scopes: Vec<String>,
}

impl From<&AuthenticatedPrincipal> for VapiProjectedIdentity {
    fn from(principal: &AuthenticatedPrincipal) -> Self {
        Self {
            ownership: principal.ownership_key(),
            scopes: principal.scopes.clone(),
        }
    }
}

/// TLS certificate identity. Private-key references are excluded from profile
/// revisions and remain redacted by `SecretRef`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileTlsIdentityCfg {
    pub certificate_chain: String,
    #[serde(skip_serializing)]
    pub private_key: SecretRef,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileDigestCfg {
    pub realm: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password: SecretRef,
}

/// Per-destination SRTP posture enforced by the selected isolated SIP child.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProfileSrtpPolicy {
    #[default]
    Required,
    Preferred,
    Disabled,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum SipProfileAuthCfg {
    Digest {
        realm: Option<String>,
        username: String,
        #[serde(skip_serializing)]
        password: SecretRef,
    },
    Bearer {
        #[serde(skip_serializing)]
        token: SecretRef,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileClientCertificateCfg {
    pub certificate_chain: String,
    #[serde(skip_serializing)]
    pub private_key: SecretRef,
}

/// Outbound SIP authorization profile. Targets remain in the server-owned
/// route, but must be an exact member of this allowlist.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SipProfileCfg {
    pub allowed_targets: BTreeSet<String>,
    pub from_uri: String,
    #[serde(default)]
    pub outbound_proxy: Option<String>,
    #[serde(default)]
    pub auth: Option<SipProfileAuthCfg>,
    #[serde(default)]
    pub tls_roots: Vec<String>,
    #[serde(default)]
    pub client_certificate: Option<ProfileClientCertificateCfg>,
    #[serde(default)]
    pub srtp: ProfileSrtpPolicy,
    #[serde(default = "default_profile_codecs")]
    pub codecs: BTreeSet<ProfileAudioCodec>,
    #[serde(default)]
    pub metadata_keys: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileIceServerCfg {
    pub urls: Vec<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default, skip_serializing)]
    pub credential: Option<SecretRef>,
}

/// Interactive WebRTC profile used for browser ingress or an outbound WSS
/// peer. Route targets must belong to `allowed_signaling_origins`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WebRtcProfileCfg {
    pub allowed_signaling_origins: BTreeSet<String>,
    #[serde(default, skip_serializing)]
    pub bearer_token: Option<SecretRef>,
    #[serde(default)]
    pub tls_roots: Vec<String>,
    #[serde(default)]
    pub ice_servers: Vec<ProfileIceServerCfg>,
    #[serde(default = "default_profile_codecs")]
    pub codecs: BTreeSet<ProfileAudioCodec>,
    #[serde(default = "default_true_profile_policy")]
    pub data_channels: bool,
}

/// Existing provider/runtime profile selected by a server-owned route.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum RouteDestinationProfileRef {
    Sip { profile_id: String },
    Webrtc { profile_id: String },
    AmazonConnect { profile_id: String },
    Telnyx { profile_id: String },
}

/// One tenant-owned, server-controlled route destination.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamedRouteCfg {
    pub tenant_id: String,
    #[serde(default = "default_named_route_ingress")]
    pub ingress: BTreeSet<NamedRouteIngress>,
    pub destination: RequestedLeg,
    /// Required for new stock-Vapi SIP routes.
    #[serde(default)]
    pub vapi_ingress_profile: Option<String>,
    /// Provider-neutral SIP ingress profile used by recipes.
    #[serde(default)]
    pub sip_ingress_profile: Option<String>,
    /// When set, the named-route call must carry a server-owned correlation
    /// value and the actual SIP INVITE must present this header exactly once
    /// with the same value before its one-use attachment is consumed.
    #[serde(default)]
    pub required_sip_correlation_header: Option<String>,
    /// Runtime-only recipe admission mode. Expert routes and managed recipe
    /// routes retain the ordinary control-API attachment behavior.
    #[serde(skip)]
    pub recipe_sip_admission: Option<SipAdmissionSpec>,
    /// Required for new direct-browser routes.
    #[serde(default)]
    pub webrtc_ingress_profile: Option<String>,
    /// Required for new destination definitions.
    #[serde(default)]
    pub destination_profile: Option<RouteDestinationProfileRef>,
    /// Explicit compatibility escape hatch for pre-profile route definitions.
    #[serde(default)]
    pub legacy_embedded_destination: bool,
    /// Populated only in the resolved runtime catalog and persisted with calls.
    #[serde(skip)]
    pub profile_bindings: Vec<NamedProfileBinding>,
    /// Route-local metadata policy derived from the destination profile. `None`
    /// means the transport has its own bounded DataChannel contract; `Some`
    /// is enforced before a call or attachment is created.
    #[serde(skip)]
    pub context_metadata_allowlist: Option<BTreeSet<String>>,
    /// True only when this route's destination contract requires an initial
    /// bounded context. An allowlist by itself permits metadata but does not
    /// make it mandatory.
    #[serde(skip)]
    pub context_required: bool,
    /// Non-secret, revision-bound destination policy used by route discovery.
    /// Adapter/topology availability is checked separately at request time.
    #[serde(skip)]
    pub capability_policy: NamedRouteCapabilityPolicy,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct NamedRouteCapabilityPolicy {
    pub audio_codecs: BTreeSet<ProfileAudioCodec>,
    pub data_channels: Option<bool>,
    pub sip_message: Option<bool>,
}

/// Public attachment endpoints shared by the named route catalog.
#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouteAttachmentCfg {
    /// Complete secure SIP URI template with exactly one `{token}` user part,
    /// for example `sips:{token}@bridge.example:5061;transport=tls`.
    #[serde(default)]
    pub sip_uri_template: Option<String>,
    #[serde(default)]
    pub webrtc: Option<RouteWebRtcAttachmentCfg>,
}

impl fmt::Debug for RouteAttachmentCfg {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteAttachmentCfg")
            .field(
                "sip_uri_template_configured",
                &self.sip_uri_template.is_some(),
            )
            .field("webrtc_configured", &self.webrtc.is_some())
            .finish()
    }
}

/// Browser-facing WSS and ICE descriptor. ICE credentials are resolved once
/// at startup and are never exposed by route discovery or Debug output.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouteWebRtcAttachmentCfg {
    pub signaling_uri: String,
    #[serde(default)]
    pub ice_servers: Vec<RouteIceServerCfg>,
}

impl fmt::Debug for RouteWebRtcAttachmentCfg {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteWebRtcAttachmentCfg")
            .field("signaling_uri", &"[redacted]")
            .field("ice_server_count", &self.ice_servers.len())
            .finish()
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouteIceServerCfg {
    pub urls: Vec<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub credential: Option<SecretRef>,
}

impl fmt::Debug for RouteIceServerCfg {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteIceServerCfg")
            .field("url_count", &self.urls.len())
            .field("username", &self.username.as_ref().map(|_| "[redacted]"))
            .field(
                "credential",
                &self.credential.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct ResolvedNamedRoutes {
    pub routes: BTreeMap<String, NamedRouteCfg>,
    pub sip_uri_template: Option<String>,
    pub webrtc: Option<ResolvedRouteWebRtcAttachment>,
}

impl fmt::Debug for ResolvedNamedRoutes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedNamedRoutes")
            .field("route_count", &self.routes.len())
            .field(
                "sip_attachment_configured",
                &self.sip_uri_template.is_some(),
            )
            .field("webrtc_attachment_configured", &self.webrtc.is_some())
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct ResolvedRouteWebRtcAttachment {
    pub signaling_uri: String,
    pub ice_servers: Vec<ResolvedRouteIceServer>,
}

impl fmt::Debug for ResolvedRouteWebRtcAttachment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedRouteWebRtcAttachment")
            .field("signaling_uri", &"[redacted]")
            .field("ice_server_count", &self.ice_servers.len())
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct ResolvedRouteIceServer {
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub credential: Option<String>,
}

impl fmt::Debug for ResolvedRouteIceServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedRouteIceServer")
            .field("url_count", &self.urls.len())
            .field("username", &self.username.as_ref().map(|_| "[redacted]"))
            .field(
                "credential",
                &self.credential.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

impl Drop for ResolvedRouteIceServer {
    fn drop(&mut self) {
        if let Some(username) = &mut self.username {
            username.zeroize();
        }
        if let Some(credential) = &mut self.credential {
            credential.zeroize();
        }
    }
}

impl Config {
    /// Build the inbound/default SIP stack. When named egress profiles are
    /// present, its RTP range is the first disjoint slice of the configured
    /// range; each independently secured egress child receives another slice.
    pub(crate) fn generic_sip_stack_config(
        &self,
        name: &str,
        bind: SocketAddr,
    ) -> Result<(rvoip_sip::Config, rvoip_sip::SipNatConfig)> {
        let (mut stack, nat) = self
            .generic_bridge
            .sip_stack_config(name, bind)
            .context("configuring generic SIP stack")?;
        let profile_count = self.referenced_named_sip_profiles()?.len();
        if profile_count > rvoip_sip::MAX_INSTALLED_SIP_EGRESS_PROFILES {
            return Err(anyhow!(
                "too many referenced named SIP egress profiles are configured"
            ));
        }
        let ranges = partition_rtp_port_range(
            stack.media_port_start,
            stack.media_port_end,
            profile_count.saturating_add(1),
        )?;
        stack = stack.with_media_ports(ranges[0].0, ranges[0].1);
        Ok((stack, nat))
    }

    /// Resolve every referenced named SIP destination into an isolated child
    /// stack selected only by its exact durable revision. No TLS identity,
    /// trust root, SRTP posture, codec set, or metadata policy is projected
    /// process-wide onto another route.
    pub(crate) fn sip_egress_profile_configs(
        &self,
        name: &str,
        bind: SocketAddr,
    ) -> Result<Vec<SipEgressProfileConfig>> {
        let profiles = self.referenced_named_sip_profiles()?;
        if profiles.is_empty() {
            return Ok(Vec::new());
        }
        if profiles.len() > rvoip_sip::MAX_INSTALLED_SIP_EGRESS_PROFILES {
            return Err(anyhow!(
                "too many referenced named SIP egress profiles are configured"
            ));
        }
        let (base, nat) = self
            .generic_bridge
            .sip_stack_config(name, bind)
            .context("configuring generic SIP egress base")?;
        let ranges = partition_rtp_port_range(
            base.media_port_start,
            base.media_port_end,
            profiles.len().saturating_add(1),
        )?;
        let mut revisions = BTreeSet::new();
        let mut configured = Vec::with_capacity(profiles.len());
        for (offset, (profile_id, profile)) in profiles.into_iter().enumerate() {
            let revision = profile_revision(profile)?;
            if !revisions.insert(revision.clone()) {
                return Err(anyhow!(
                    "referenced sip_profiles must have distinct non-secret revisions"
                ));
            }
            let revision = rvoip_sip::SipProfileRevision::new(revision)
                .map_err(|_| anyhow!("named SIP profile produced an invalid revision"))?;

            // Clone operational tuning, the RTP bind, and NAT/media
            // advertisement from the public stack, but bind an independent
            // signaling endpoint and remove every inbound TLS-listener
            // credential from the child. Config::local_ip belongs to RTP
            // allocation, not SIP signaling: resetting it to the loopback
            // child bind makes Linux reject sends to a public media peer with
            // EINVAL while the SDP still advertises the public address.
            let child_name = format!("{name}-egress-{}", offset + 1);
            let isolated = rvoip_sip::Config::on(&child_name, bind.ip(), 0);
            let mut stack = base.clone();
            stack.sip_port = isolated.sip_port;
            stack.bind_addr = isolated.bind_addr;
            stack.local_uri = isolated.local_uri;
            stack.sip_advertised_addr = None;
            stack.sip_tls_mode = rvoip_sip::SipTlsMode::ClientOnly;
            stack.contact_uri = Some(profile.from_uri.clone());
            stack.tls_bind_addr = None;
            stack.tls_advertised_addr = None;
            stack.tls_cert_path = None;
            stack.tls_key_path = None;
            stack.tls_server_client_auth = Default::default();
            stack.tls_extra_ca_path = profile.tls_roots.first().map(Into::into);
            stack.tls_client_cert_path = None;
            stack.tls_client_key_path = None;
            if let Some(identity) = &profile.client_certificate {
                let mut private_key = identity
                    .private_key
                    .resolve()
                    .context("resolving named SIP client private-key path")?;
                if let Err(error) =
                    validate_profile_path(&private_key, "sip_profiles client private-key path")
                {
                    private_key.zeroize();
                    return Err(error);
                }
                stack.tls_client_cert_path = Some(identity.certificate_chain.clone().into());
                stack.tls_client_key_path = Some(private_key.clone().into());
                private_key.zeroize();
            }
            stack.offer_srtp = profile.srtp != ProfileSrtpPolicy::Disabled;
            stack.srtp_required = profile.srtp == ProfileSrtpPolicy::Required;
            stack.offered_codecs = profile
                .codecs
                .iter()
                .map(|codec| match codec {
                    ProfileAudioCodec::Pcmu => 0,
                    ProfileAudioCodec::Pcma => 8,
                    ProfileAudioCodec::Opus => 111,
                })
                .chain(std::iter::once(101))
                .collect();
            let (media_start, media_end) = ranges[offset + 1];
            stack = stack.with_media_ports(media_start, media_end);
            stack
                .validate()
                .map_err(|_| anyhow!("named SIP profile produced an invalid child stack"))?;

            let allowed_initial_headers = self
                .context
                .allow_headers
                .iter()
                .filter(|(_, metadata_key)| profile.metadata_keys.contains(*metadata_key))
                .map(|(header, _)| header.clone())
                .collect();
            configured.push(SipEgressProfileConfig {
                revision,
                stack,
                nat,
                allowed_initial_headers,
                sip_message: !profile.metadata_keys.is_empty(),
            });
            tracing::debug!(profile_id, "configured isolated named SIP egress profile");
        }
        Ok(configured)
    }

    fn referenced_named_sip_profiles(&self) -> Result<Vec<(&str, &SipProfileCfg)>> {
        self.api
            .routes
            .values()
            .filter_map(|route| match route.destination_profile.as_ref() {
                Some(RouteDestinationProfileRef::Sip { profile_id }) => Some(profile_id.as_str()),
                _ => None,
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|profile_id| {
                self.sip_profiles
                    .get(profile_id)
                    .map(|profile| (profile_id, profile))
                    .ok_or_else(|| {
                        anyhow!("named SIP transport profile disappeared during stack construction")
                    })
            })
            .collect()
    }

    fn validate_named_profiles(&self) -> Result<()> {
        let profile_count = self
            .vapi_ingress_profiles
            .len()
            .saturating_add(self.sip_ingress_profiles.len())
            .saturating_add(self.sip_profiles.len())
            .saturating_add(self.webrtc_profiles.len());
        if profile_count > MAX_NAMED_PROFILE_ENTRIES {
            return Err(anyhow!("too many named signaling profiles are configured"));
        }
        let tenants = self.tenant_names()?.into_iter().collect::<BTreeSet<_>>();

        for (profile_id, profile) in &self.vapi_ingress_profiles {
            validate_named_profile_id_for_config(profile_id, NamedProfileKind::VapiIngress)?;
            let tenant = TenantId::parse(&profile.tenant_id)
                .map_err(|_| anyhow!("vapi_ingress_profiles contains an invalid tenant_id"))?;
            if !tenants.contains(tenant.as_str()) {
                return Err(anyhow!(
                    "vapi_ingress_profiles tenant_id must name a configured routing tenant"
                ));
            }
            validate_profile_text(
                &profile.principal_subject,
                "vapi_ingress_profiles principal_subject",
            )?;
            validate_profile_text(&profile.issuer, "vapi_ingress_profiles issuer")?;
            if profile.scopes.is_empty() || profile.scopes.len() > MAX_NAMED_PROFILE_LIST_ENTRIES {
                return Err(anyhow!(
                    "vapi_ingress_profiles scopes must contain a bounded non-empty set"
                ));
            }
            for scope in &profile.scopes {
                validate_profile_scope(scope, "vapi_ingress_profiles scope")?;
            }
            if profile.trusted_signaling_cidrs.is_empty()
                || profile.trusted_signaling_cidrs.len() > MAX_NAMED_PROFILE_LIST_ENTRIES
            {
                return Err(anyhow!(
                    "vapi_ingress_profiles trusted_signaling_cidrs must contain a bounded non-empty set"
                ));
            }
            let mut seen_cidrs = BTreeSet::new();
            for cidr in &profile.trusted_signaling_cidrs {
                validate_profile_cidr(cidr)?;
                if !seen_cidrs.insert(cidr) {
                    return Err(anyhow!(
                        "vapi_ingress_profiles trusted_signaling_cidrs must be unique"
                    ));
                }
            }
            validate_profile_path(
                &profile.tls.certificate_chain,
                "vapi_ingress_profiles tls.certificate_chain",
            )?;
            validate_secret_reference(&profile.tls.private_key)?;
            if let Some(digest) = &profile.digest {
                validate_profile_text(&digest.realm, "vapi_ingress_profiles digest.realm")?;
                validate_profile_text(&digest.username, "vapi_ingress_profiles digest.username")?;
                validate_secret_reference(&digest.password)?;
            }
            if profile.mtls_peer_ca_certificates.len() > MAX_NAMED_PROFILE_LIST_ENTRIES {
                return Err(anyhow!(
                    "vapi_ingress_profiles has too many mTLS CA certificates"
                ));
            }
            for path in &profile.mtls_peer_ca_certificates {
                validate_profile_path(path, "vapi_ingress_profiles mTLS CA certificate")?;
            }
            if profile.mtls_leaf_certificate_sha256_fingerprints.len()
                > MAX_NAMED_PROFILE_LIST_ENTRIES
            {
                return Err(anyhow!(
                    "vapi_ingress_profiles has too many mTLS leaf certificate fingerprints"
                ));
            }
            let mut seen_fingerprints = BTreeSet::new();
            for fingerprint in &profile.mtls_leaf_certificate_sha256_fingerprints {
                let normalized = validate_mtls_leaf_sha256_fingerprint(fingerprint)?;
                if !seen_fingerprints.insert(normalized) {
                    return Err(anyhow!(
                        "vapi_ingress_profiles mTLS leaf certificate fingerprints must be unique"
                    ));
                }
            }
            match (
                profile.mtls_peer_ca_certificates.is_empty(),
                profile.mtls_leaf_certificate_sha256_fingerprints.is_empty(),
            ) {
                (false, true) => {
                    return Err(anyhow!(
                        "vapi_ingress_profiles with mtls_peer_ca_certificates must configure mtls_leaf_certificate_sha256_fingerprints; CA verification alone does not assign a principal"
                    ));
                }
                (true, false) => {
                    return Err(anyhow!(
                        "vapi_ingress_profiles mtls_leaf_certificate_sha256_fingerprints require mtls_peer_ca_certificates"
                    ));
                }
                _ => {}
            }
            if !profile.srtp_required {
                return Err(anyhow!(
                    "vapi_ingress_profiles must require SRTP for production attachments"
                ));
            }
            validate_profile_codecs(&profile.codecs, "vapi_ingress_profiles codecs")?;
            let _ = profile_revision(profile)?;
        }

        for (profile_id, profile) in &self.sip_ingress_profiles {
            validate_named_profile_id_for_config(profile_id, NamedProfileKind::SipIngress)?;
            let tenant = TenantId::parse(&profile.tenant_id)
                .map_err(|_| anyhow!("sip_ingress_profiles contains an invalid tenant_id"))?;
            if !tenants.contains(tenant.as_str()) {
                return Err(anyhow!(
                    "sip_ingress_profiles tenant_id must name a configured routing tenant"
                ));
            }
            validate_profile_text(
                &profile.principal_subject,
                "sip_ingress_profiles principal_subject",
            )?;
            validate_profile_text(&profile.issuer, "sip_ingress_profiles issuer")?;
            if profile.scopes.is_empty() || profile.scopes.len() > MAX_NAMED_PROFILE_LIST_ENTRIES {
                return Err(anyhow!(
                    "sip_ingress_profiles scopes must contain a bounded non-empty set"
                ));
            }
            for scope in &profile.scopes {
                validate_profile_scope(scope, "sip_ingress_profiles scope")?;
            }
            if profile.trusted_signaling_cidrs.is_empty()
                || profile.trusted_signaling_cidrs.len() > MAX_NAMED_PROFILE_LIST_ENTRIES
            {
                return Err(anyhow!(
                    "sip_ingress_profiles trusted_signaling_cidrs must contain a bounded non-empty set"
                ));
            }
            let mut seen_cidrs = BTreeSet::new();
            for cidr in &profile.trusted_signaling_cidrs {
                validate_profile_cidr(cidr)?;
                if !seen_cidrs.insert(cidr) {
                    return Err(anyhow!(
                        "sip_ingress_profiles trusted_signaling_cidrs must be unique"
                    ));
                }
            }
            if let Some(tls) = &profile.tls {
                validate_profile_path(
                    &tls.certificate_chain,
                    "sip_ingress_profiles tls.certificate_chain",
                )?;
                validate_secret_reference(&tls.private_key)?;
            }
            if let Some(digest) = &profile.digest {
                validate_profile_text(&digest.realm, "sip_ingress_profiles digest.realm")?;
                validate_profile_text(&digest.username, "sip_ingress_profiles digest.username")?;
                validate_secret_reference(&digest.password)?;
            }
            if profile.mtls_peer_ca_certificates.len() > MAX_NAMED_PROFILE_LIST_ENTRIES
                || profile.mtls_leaf_certificate_sha256_fingerprints.len()
                    > MAX_NAMED_PROFILE_LIST_ENTRIES
            {
                return Err(anyhow!(
                    "sip_ingress_profiles has too many mTLS identity entries"
                ));
            }
            for path in &profile.mtls_peer_ca_certificates {
                validate_profile_path(path, "sip_ingress_profiles mTLS CA certificate")?;
            }
            let mut seen_fingerprints = BTreeSet::new();
            for fingerprint in &profile.mtls_leaf_certificate_sha256_fingerprints {
                let normalized = validate_mtls_leaf_sha256_fingerprint(fingerprint)?;
                if !seen_fingerprints.insert(normalized) {
                    return Err(anyhow!(
                        "sip_ingress_profiles mTLS leaf certificate fingerprints must be unique"
                    ));
                }
            }
            match (
                profile.mtls_peer_ca_certificates.is_empty(),
                profile.mtls_leaf_certificate_sha256_fingerprints.is_empty(),
            ) {
                (false, true) | (true, false) => {
                    return Err(anyhow!(
                        "sip_ingress_profiles mTLS CA and verified leaf fingerprints must be configured together"
                    ));
                }
                _ => {}
            }
            match profile.security {
                SipIngressSecurity::SipsSrtp | SipIngressSecurity::SipsOptionalSrtp
                    if profile.tls.is_none() =>
                {
                    return Err(anyhow!("SIPS sip_ingress_profiles require a TLS identity"));
                }
                SipIngressSecurity::SipRtp
                    if profile.tls.is_some()
                        || !profile.mtls_peer_ca_certificates.is_empty()
                        || !profile.mtls_leaf_certificate_sha256_fingerprints.is_empty() =>
                {
                    return Err(anyhow!(
                        "sip_rtp sip_ingress_profiles cannot declare TLS or mTLS identity"
                    ));
                }
                _ => {}
            }
            validate_profile_codecs(&profile.codecs, "sip_ingress_profiles codecs")?;
            let _ = profile_revision(profile)?;
        }

        for (profile_id, profile) in &self.sip_profiles {
            validate_named_profile_id_for_config(profile_id, NamedProfileKind::Sip)?;
            if profile.allowed_targets.is_empty()
                || profile.allowed_targets.len() > MAX_NAMED_PROFILE_LIST_ENTRIES
            {
                return Err(anyhow!(
                    "sip_profiles allowed_targets must contain a bounded non-empty set"
                ));
            }
            for target in &profile.allowed_targets {
                validate_profile_sip_uri(target, "sip_profiles allowed target")?;
            }
            validate_profile_sip_uri(&profile.from_uri, "sip_profiles from_uri")?;
            if let Some(proxy) = &profile.outbound_proxy {
                validate_profile_sip_uri(proxy, "sip_profiles outbound_proxy")?;
            }
            if let Some(auth) = &profile.auth {
                match auth {
                    SipProfileAuthCfg::Digest {
                        realm,
                        username,
                        password,
                    } => {
                        if let Some(realm) = realm {
                            validate_profile_text(realm, "sip_profiles auth realm")?;
                        }
                        validate_profile_text(username, "sip_profiles auth username")?;
                        validate_secret_reference(password)?;
                    }
                    SipProfileAuthCfg::Bearer { token } => validate_secret_reference(token)?,
                }
            }
            if profile.tls_roots.len() > 1 {
                return Err(anyhow!(
                    "sip_profiles currently supports at most one PEM CA bundle path"
                ));
            }
            for root in &profile.tls_roots {
                validate_profile_path(root, "sip_profiles TLS root")?;
            }
            if let Some(certificate) = &profile.client_certificate {
                validate_profile_path(
                    &certificate.certificate_chain,
                    "sip_profiles client certificate",
                )?;
                validate_secret_reference(&certificate.private_key)?;
            }
            validate_profile_codecs(&profile.codecs, "sip_profiles codecs")?;
            if profile.metadata_keys.len() > MAX_NAMED_PROFILE_LIST_ENTRIES {
                return Err(anyhow!("sip_profiles has too many metadata keys"));
            }
            for key in &profile.metadata_keys {
                validate_profile_metadata_key(key)?;
                if !self.context.allows_metadata_key(key)? {
                    return Err(anyhow!(
                        "sip_profiles metadata key is not reachable through context.allow_headers"
                    ));
                }
            }
            let _ = profile_revision(profile)?;
        }

        for (profile_id, profile) in &self.webrtc_profiles {
            validate_named_profile_id_for_config(profile_id, NamedProfileKind::WebRtc)?;
            if profile.allowed_signaling_origins.is_empty()
                || profile.allowed_signaling_origins.len() > MAX_NAMED_PROFILE_LIST_ENTRIES
            {
                return Err(anyhow!(
                    "webrtc_profiles allowed_signaling_origins must contain a bounded non-empty set"
                ));
            }
            for origin in &profile.allowed_signaling_origins {
                validate_profile_wss_origin(origin)?;
            }
            if let Some(token) = &profile.bearer_token {
                validate_secret_reference(token)?;
            }
            if profile.tls_roots.len() > MAX_NAMED_PROFILE_LIST_ENTRIES {
                return Err(anyhow!("webrtc_profiles has too many TLS roots"));
            }
            for root in &profile.tls_roots {
                validate_profile_path(root, "webrtc_profiles TLS root")?;
            }
            if profile.ice_servers.len() > MAX_GENERIC_ICE_SERVERS {
                return Err(anyhow!("webrtc_profiles has too many ICE servers"));
            }
            for server in &profile.ice_servers {
                validate_profile_ice_server(server)?;
            }
            validate_profile_codecs(&profile.codecs, "webrtc_profiles codecs")?;
            let _ = profile_revision(profile)?;
        }
        Ok(())
    }

    fn validate_named_routes(&self) -> Result<()> {
        if self.api.routes.is_empty() {
            return Ok(());
        }
        if self.runtime.mode == RuntimeMode::Worker {
            if self.api.enabled
                || self.generic_bridge.enabled
                || self.api.control_hmac_key.is_none()
            {
                return Err(anyhow!(
                    "worker route catalogs require disabled public API/signaling and api.control_hmac_key"
                ));
            }
        } else if !self.api.enabled
            || self.api.bearer_token.is_none()
            || self.api.control_hmac_key.is_none()
            || !self.generic_bridge.enabled
        {
            return Err(anyhow!(
                "api.routes require api.enabled, API credentials, and generic_bridge.enabled"
            ));
        }
        let configured_tenants = self.tenant_names()?.into_iter().collect::<BTreeSet<_>>();
        let mut configured_sip_security = None;
        for (route_id, route) in &self.api.routes {
            NamedRouteBinding::new(route_id.clone(), None)
                .map_err(|_| anyhow!("api.routes contains an invalid route ID"))?;
            let tenant = TenantId::parse(&route.tenant_id)
                .map_err(|_| anyhow!("api.routes tenant_id is invalid"))?;
            if !configured_tenants.contains(tenant.as_str()) {
                return Err(anyhow!(
                    "api.routes tenant_id must name a configured routing tenant"
                ));
            }
            if route.ingress.is_empty() {
                return Err(anyhow!("api.routes ingress must not be empty"));
            }
            route
                .destination
                .validate_named_route_destination()
                .map_err(|_| anyhow!("api.routes destination is invalid"))?;
            let _ = self.named_route_profile_bindings(route)?;
            if route.ingress.contains(&NamedRouteIngress::Sip)
                && self.api.route_attachments.sip_uri_template.is_none()
            {
                return Err(anyhow!(
                    "api.route_attachments.sip_uri_template is required by a SIP route ingress"
                ));
            }
            if route.ingress.contains(&NamedRouteIngress::Sip) {
                let security = self.named_route_sip_ingress_security(route)?;
                if configured_sip_security
                    .replace(security)
                    .is_some_and(|existing| existing != security)
                {
                    return Err(anyhow!(
                        "one process cannot mix SIP ingress security profiles"
                    ));
                }
                match security {
                    SipIngressSecurity::SipsSrtp
                        if self.generic_bridge.sip.secure_listener.is_none()
                            || self.generic_bridge.sip.srtp != ProfileSrtpPolicy::Required =>
                    {
                        return Err(anyhow!(
                            "sips_srtp named-route attachments require a SIP TLS listener and mandatory SRTP"
                        ));
                    }
                    SipIngressSecurity::SipsOptionalSrtp
                        if self.generic_bridge.sip.secure_listener.is_none()
                            || self.generic_bridge.sip.srtp != ProfileSrtpPolicy::Preferred =>
                    {
                        return Err(anyhow!(
                            "sips_optional_srtp named-route attachments require a SIP TLS listener with preferred SRTP"
                        ));
                    }
                    SipIngressSecurity::SipRtp
                        if self.generic_bridge.sip.secure_listener.is_some()
                            || self.generic_bridge.sip.srtp != ProfileSrtpPolicy::Disabled =>
                    {
                        return Err(anyhow!(
                            "sip_rtp named-route attachments require a clear-only listener with SRTP disabled"
                        ));
                    }
                    _ => {}
                }
            }
            if let Some(header) = &route.required_sip_correlation_header {
                if !route.ingress.contains(&NamedRouteIngress::Sip)
                    || !self.context.allow_headers.iter().any(|(configured, key)| {
                        configured.eq_ignore_ascii_case(header) && key == "correlation_id"
                    })
                {
                    return Err(anyhow!(
                        "api.routes required_sip_correlation_header must be an allowlisted correlation_id header on a SIP ingress"
                    ));
                }
            }
            if route.ingress.contains(&NamedRouteIngress::Webrtc)
                && self.api.route_attachments.webrtc.is_none()
            {
                return Err(anyhow!(
                    "api.route_attachments.webrtc is required by a WebRTC route ingress"
                ));
            }
        }
        if let Some(template) = &self.api.route_attachments.sip_uri_template {
            validate_route_sip_template(
                template,
                configured_sip_security.unwrap_or(SipIngressSecurity::SipsSrtp),
            )?;
        }
        if let Some(webrtc) = &self.api.route_attachments.webrtc {
            validate_route_webrtc_attachment(webrtc)?;
        }
        if let Some(listener_tenant) = self.sip_projection_listener_tenant()? {
            let _ = self.sip_listener_principal_projections(&listener_tenant)?;
        }
        Ok(())
    }

    fn named_route_sip_ingress_security(
        &self,
        route: &NamedRouteCfg,
    ) -> Result<SipIngressSecurity> {
        if route.vapi_ingress_profile.is_some() && route.sip_ingress_profile.is_some() {
            return Err(anyhow!(
                "api.routes cannot select both vapi_ingress_profile and sip_ingress_profile"
            ));
        }
        if route.vapi_ingress_profile.is_some() {
            return Ok(SipIngressSecurity::SipsSrtp);
        }
        if let Some(profile_id) = &route.sip_ingress_profile {
            return self
                .sip_ingress_profiles
                .get(profile_id)
                .map(|profile| profile.security)
                .ok_or_else(|| anyhow!("api.routes references an unknown sip_ingress_profile"));
        }
        if route.legacy_embedded_destination {
            return Ok(SipIngressSecurity::SipsSrtp);
        }
        Err(anyhow!(
            "new SIP routes require a sip_ingress_profile or compatibility vapi_ingress_profile"
        ))
    }

    fn named_route_profile_bindings(
        &self,
        route: &NamedRouteCfg,
    ) -> Result<Vec<NamedProfileBinding>> {
        if !route.legacy_embedded_destination {
            if route.ingress.contains(&NamedRouteIngress::Sip)
                && route.vapi_ingress_profile.is_none()
                && route.sip_ingress_profile.is_none()
            {
                return Err(anyhow!(
                    "new SIP routes require a sip_ingress_profile or vapi_ingress_profile reference"
                ));
            }
            if route.ingress.contains(&NamedRouteIngress::Webrtc)
                && route.webrtc_ingress_profile.is_none()
            {
                return Err(anyhow!(
                    "new WebRTC routes require a webrtc_ingress_profile reference"
                ));
            }
            if route.destination_profile.is_none() {
                return Err(anyhow!(
                    "new named routes require a destination_profile reference"
                ));
            }
        }

        let mut bindings = Vec::new();
        if let Some(profile_id) = &route.vapi_ingress_profile {
            if !route.ingress.contains(&NamedRouteIngress::Sip) {
                return Err(anyhow!(
                    "vapi_ingress_profile is valid only for a SIP route ingress"
                ));
            }
            let profile = self
                .vapi_ingress_profiles
                .get(profile_id)
                .ok_or_else(|| anyhow!("api.routes references an unknown vapi_ingress_profile"))?;
            if profile.tenant_id != route.tenant_id {
                return Err(anyhow!(
                    "api.routes vapi_ingress_profile belongs to another tenant"
                ));
            }
            self.validate_vapi_listener_projection(profile)?;
            bindings.push(NamedProfileBinding::new(
                NamedProfileRole::Ingress,
                NamedProfileKind::VapiIngress,
                profile_id.clone(),
                profile_revision(profile)?,
            )?);
        }
        if let Some(profile_id) = &route.sip_ingress_profile {
            if !route.ingress.contains(&NamedRouteIngress::Sip)
                || route.vapi_ingress_profile.is_some()
            {
                return Err(anyhow!(
                    "sip_ingress_profile is valid only as the sole SIP ingress profile"
                ));
            }
            let profile = self
                .sip_ingress_profiles
                .get(profile_id)
                .ok_or_else(|| anyhow!("api.routes references an unknown sip_ingress_profile"))?;
            if profile.tenant_id != route.tenant_id {
                return Err(anyhow!(
                    "api.routes sip_ingress_profile belongs to another tenant"
                ));
            }
            self.validate_sip_listener_projection(profile)?;
            bindings.push(NamedProfileBinding::new(
                NamedProfileRole::Ingress,
                NamedProfileKind::SipIngress,
                profile_id.clone(),
                profile_revision(profile)?,
            )?);
        }
        if let Some(profile_id) = &route.webrtc_ingress_profile {
            if !route.ingress.contains(&NamedRouteIngress::Webrtc) {
                return Err(anyhow!(
                    "webrtc_ingress_profile is valid only for a WebRTC route ingress"
                ));
            }
            let profile = self.webrtc_profiles.get(profile_id).ok_or_else(|| {
                anyhow!("api.routes references an unknown webrtc_ingress_profile")
            })?;
            bindings.push(NamedProfileBinding::new(
                NamedProfileRole::Ingress,
                NamedProfileKind::WebRtc,
                profile_id.clone(),
                profile_revision(profile)?,
            )?);
        }

        match (&route.destination_profile, &route.destination.endpoint) {
            (None, _) => {}
            (
                Some(RouteDestinationProfileRef::Sip { profile_id }),
                LegEndpointConfig::Sip(endpoint),
            ) => {
                let profile = self
                    .sip_profiles
                    .get(profile_id)
                    .ok_or_else(|| anyhow!("api.routes references an unknown sip_profile"))?;
                let target = endpoint.uri.as_ref().ok_or_else(|| {
                    anyhow!("named SIP destination requires an explicit server-owned target")
                })?;
                if !profile.allowed_targets.contains(target) {
                    return Err(anyhow!(
                        "named SIP destination is not allowlisted by its sip_profile"
                    ));
                }
                bindings.push(NamedProfileBinding::new(
                    NamedProfileRole::Destination,
                    NamedProfileKind::Sip,
                    profile_id.clone(),
                    profile_revision(profile)?,
                )?);
            }
            (
                Some(RouteDestinationProfileRef::Webrtc { profile_id }),
                LegEndpointConfig::WebRtc(endpoint),
            ) => {
                let profile = self
                    .webrtc_profiles
                    .get(profile_id)
                    .ok_or_else(|| anyhow!("api.routes references an unknown webrtc_profile"))?;
                let target = endpoint.signaling_uri.as_ref().ok_or_else(|| {
                    anyhow!("named WebRTC destination requires an explicit server-owned target")
                })?;
                let origin = normalized_wss_origin(target)?;
                if !profile.allowed_signaling_origins.contains(&origin) {
                    return Err(anyhow!(
                        "named WebRTC destination origin is not allowlisted by its profile"
                    ));
                }
                bindings.push(NamedProfileBinding::new(
                    NamedProfileRole::Destination,
                    NamedProfileKind::WebRtc,
                    profile_id.clone(),
                    profile_revision(profile)?,
                )?);
            }
            (
                Some(RouteDestinationProfileRef::AmazonConnect { profile_id }),
                LegEndpointConfig::AmazonConnect(endpoint),
            ) => {
                let start = route
                    .destination
                    .amazon_connect_start
                    .as_ref()
                    .ok_or_else(|| {
                        anyhow!("named Amazon route is missing its durable start specification")
                    })?;
                if start.profile() != profile_id
                    || endpoint.instance_id != start.instance_id()
                    || endpoint.contact_flow_id != start.contact_flow_id()
                {
                    return Err(anyhow!(
                        "named Amazon destination does not match its selected profile"
                    ));
                }
                let revision = profile_revision(&serde_json::json!({
                    "profile_id": profile_id,
                    "instance_id": start.instance_id(),
                    "contact_flow_id": start.contact_flow_id(),
                }))?;
                bindings.push(NamedProfileBinding::new(
                    NamedProfileRole::Destination,
                    NamedProfileKind::AmazonConnect,
                    profile_id.clone(),
                    revision,
                )?);
            }
            (
                Some(RouteDestinationProfileRef::Telnyx { profile_id }),
                LegEndpointConfig::Provider(endpoint),
            ) if endpoint.provider == ProviderKind::Telnyx => {
                let provider = self
                    .providers
                    .telnyx
                    .as_ref()
                    .ok_or_else(|| anyhow!("named Telnyx route requires providers.telnyx"))?;
                if endpoint.account_profile != *profile_id
                    || provider.account_profile != *profile_id
                {
                    return Err(anyhow!(
                        "named Telnyx destination does not match its account profile"
                    ));
                }
                let revision = profile_revision(&serde_json::json!({
                    "profile_id": profile_id,
                    "connection_id": provider.connection_id,
                    "from": provider.from,
                    "media_sip_authority": provider.media_sip_authority,
                    "media_sip_username": provider.media_sip_username,
                    "media_sip_realm": provider.media_sip_realm,
                    "media_sip_transport": provider.media_sip_transport,
                    "webhook_url": provider.webhook_url,
                    "base_url": provider.base_url,
                    "request_timeout_ms": provider.request_timeout_ms,
                    "max_retries": provider.max_retries,
                }))?;
                bindings.push(NamedProfileBinding::new(
                    NamedProfileRole::Destination,
                    NamedProfileKind::Telnyx,
                    profile_id.clone(),
                    revision,
                )?);
            }
            (Some(_), _) => {
                return Err(anyhow!(
                    "api.routes destination_profile type must match the destination adapter"
                ));
            }
        }
        Ok(bindings)
    }

    fn validate_vapi_listener_projection(&self, profile: &VapiIngressProfileCfg) -> Result<()> {
        let listener = self
            .generic_bridge
            .sip
            .secure_listener
            .as_ref()
            .ok_or_else(|| anyhow!("Vapi SIP ingress requires a shared SIP TLS listener"))?;
        if self.generic_bridge.sip.srtp != ProfileSrtpPolicy::Required
            || listener.certificate_chain != profile.tls.certificate_chain
            || !listener
                .private_key
                .same_reference(&profile.tls.private_key)
        {
            return Err(anyhow!(
                "Vapi ingress TLS/SRTP policy must exactly match the shared SIP listener"
            ));
        }
        if !profile.mtls_peer_ca_certificates.is_empty()
            && (profile.mtls_peer_ca_certificates.len() != 1
                || listener.client_ca_certificate.as_ref()
                    != profile.mtls_peer_ca_certificates.first())
        {
            return Err(anyhow!(
                "Vapi ingress mTLS CA must match the shared SIP listener CA"
            ));
        }
        if let Some(profile_digest) = &profile.digest {
            let runtime_digest = self.generic_bridge.sip.digest.as_ref().ok_or_else(|| {
                anyhow!("Vapi ingress Digest policy is not installed on the SIP listener")
            })?;
            if runtime_digest.realm != profile_digest.realm
                || runtime_digest.username != profile_digest.username
                || !runtime_digest
                    .password
                    .same_reference(&profile_digest.password)
            {
                return Err(anyhow!(
                    "Vapi ingress Digest policy must exactly match the SIP listener"
                ));
            }
        }
        Ok(())
    }

    fn validate_sip_listener_projection(&self, profile: &SipIngressProfileCfg) -> Result<()> {
        match profile.security {
            SipIngressSecurity::SipsSrtp => {
                let listener = self
                    .generic_bridge
                    .sip
                    .secure_listener
                    .as_ref()
                    .ok_or_else(|| {
                        anyhow!("sips_srtp SIP ingress requires a shared SIP TLS listener")
                    })?;
                let tls = profile
                    .tls
                    .as_ref()
                    .ok_or_else(|| anyhow!("sips_srtp SIP ingress requires a TLS identity"))?;
                if self.generic_bridge.sip.srtp != ProfileSrtpPolicy::Required
                    || listener.certificate_chain != tls.certificate_chain
                    || !listener.private_key.same_reference(&tls.private_key)
                {
                    return Err(anyhow!(
                        "SIP ingress TLS/SRTP policy must exactly match the shared listener"
                    ));
                }
                if !profile.mtls_peer_ca_certificates.is_empty()
                    && (profile.mtls_peer_ca_certificates.len() != 1
                        || listener.client_ca_certificate.as_ref()
                            != profile.mtls_peer_ca_certificates.first())
                {
                    return Err(anyhow!(
                        "SIP ingress mTLS CA must match the shared listener CA"
                    ));
                }
            }
            SipIngressSecurity::SipsOptionalSrtp => {
                let listener = self
                    .generic_bridge
                    .sip
                    .secure_listener
                    .as_ref()
                    .ok_or_else(|| {
                        anyhow!("sips_optional_srtp SIP ingress requires a shared SIP TLS listener")
                    })?;
                let tls = profile.tls.as_ref().ok_or_else(|| {
                    anyhow!("sips_optional_srtp SIP ingress requires a TLS identity")
                })?;
                if self.generic_bridge.sip.srtp != ProfileSrtpPolicy::Preferred
                    || listener.certificate_chain != tls.certificate_chain
                    || !listener.private_key.same_reference(&tls.private_key)
                {
                    return Err(anyhow!(
                        "SIP ingress TLS/preferred-SRTP policy must exactly match the shared listener"
                    ));
                }
                if !profile.mtls_peer_ca_certificates.is_empty()
                    && (profile.mtls_peer_ca_certificates.len() != 1
                        || listener.client_ca_certificate.as_ref()
                            != profile.mtls_peer_ca_certificates.first())
                {
                    return Err(anyhow!(
                        "SIP ingress mTLS CA must match the shared listener CA"
                    ));
                }
            }
            SipIngressSecurity::SipRtp => {
                if self.generic_bridge.sip.secure_listener.is_some()
                    || self.generic_bridge.sip.srtp != ProfileSrtpPolicy::Disabled
                {
                    return Err(anyhow!(
                        "sip_rtp SIP ingress requires a clear-only listener with SRTP disabled"
                    ));
                }
            }
        }
        if let Some(profile_digest) = &profile.digest {
            let runtime_digest = self.generic_bridge.sip.digest.as_ref().ok_or_else(|| {
                anyhow!("SIP ingress Digest policy is not installed on the listener")
            })?;
            if runtime_digest.realm != profile_digest.realm
                || runtime_digest.username != profile_digest.username
                || !runtime_digest
                    .password
                    .same_reference(&profile_digest.password)
            {
                return Err(anyhow!(
                    "SIP ingress Digest policy must exactly match the listener"
                ));
            }
        }
        Ok(())
    }

    /// Build the one tenant-bound SIP listener policy used by both all-in-one
    /// and gateway roles. Header authentication remains the existing shared
    /// generic/Telnyx Digest plus Bearer service; referenced Vapi profiles add
    /// only explicit source-network and verified-leaf-certificate mappings.
    pub(crate) fn sip_listener_auth_policy(
        &self,
        listener_tenant: &str,
        validator: Arc<dyn BearerValidator>,
        bearer_scope: &'static str,
    ) -> Result<SipListenerAuthPolicy> {
        self.validate_named_profiles()
            .context("validating SIP listener identity profiles")?;
        self.validate_named_routes()
            .context("validating SIP listener route projections")?;
        let authentication =
            self.generic_bridge
                .sip_auth_service(&self.providers, validator, bearer_scope)?;
        let projections = self.sip_listener_principal_projections(listener_tenant)?;
        let mut policy =
            SipListenerAuthPolicy::authenticated_for_tenant(listener_tenant, authentication)
                .context("configuring tenant-bound SIP listener authentication")?;
        for projection in projections {
            tracing::info!(
                profile_id = %projection.profile_id,
                trusted_cidr_count = projection.trusted_cidrs.len(),
                mtls_leaf_fingerprint_count = projection.mtls_leaf_fingerprints.len(),
                "installed referenced SIP ingress principal projection"
            );
            for cidr in projection.trusted_cidrs {
                policy = policy.with_trusted_cidr(cidr, projection.principal.clone());
            }
            for fingerprint in projection.mtls_leaf_fingerprints {
                policy = policy.with_verified_mtls_peer(fingerprint, projection.principal.clone());
            }
        }
        policy
            .validate()
            .context("validating projected SIP listener authentication")?;
        Ok(policy)
    }

    fn referenced_vapi_profile_ids(&self) -> BTreeSet<&str> {
        self.api
            .routes
            .values()
            .filter_map(|route| route.vapi_ingress_profile.as_deref())
            .collect()
    }

    fn referenced_sip_ingress_profile_ids(&self) -> BTreeSet<&str> {
        self.api
            .routes
            .values()
            .filter_map(|route| route.sip_ingress_profile.as_deref())
            .collect()
    }

    pub(crate) fn has_projected_sip_ingress_identity(&self) -> bool {
        !self.referenced_vapi_profile_ids().is_empty()
            || !self.referenced_sip_ingress_profile_ids().is_empty()
    }

    /// Resolve the process-wide listener tenant only when a route actually
    /// references SIP ingress. An unused profile is configuration inventory,
    /// not ambient network trust.
    fn sip_projection_listener_tenant(&self) -> Result<Option<String>> {
        if self.referenced_vapi_profile_ids().is_empty()
            && self.referenced_sip_ingress_profile_ids().is_empty()
        {
            return Ok(None);
        }
        if let Some(tenant) = &self.api.static_tenant {
            return Ok(Some(tenant.clone()));
        }
        let tenants = self.tenant_names()?;
        if tenants.len() == 1 {
            return Ok(tenants.into_iter().next());
        }
        Err(anyhow!(
            "referenced SIP ingress profiles require one explicit listener tenant via api.static_tenant"
        ))
    }

    fn sip_listener_principal_projections(
        &self,
        listener_tenant: &str,
    ) -> Result<Vec<VapiListenerPrincipalProjection>> {
        let mut projections = Vec::new();
        let mut installed_cidrs: Vec<(String, IpNet, VapiProjectedIdentity)> = Vec::new();
        let mut installed_fingerprints: BTreeMap<String, (String, VapiProjectedIdentity)> =
            BTreeMap::new();
        let mut sources = Vec::new();
        for profile_id in self.referenced_vapi_profile_ids() {
            let profile = self
                .vapi_ingress_profiles
                .get(profile_id)
                .ok_or_else(|| anyhow!("api.routes references an unknown vapi_ingress_profile"))?;
            sources.push((
                profile_id.to_owned(),
                profile.tenant_id.clone(),
                vapi_profile_principal(profile_id, profile),
                profile.trusted_signaling_cidrs.clone(),
                profile.mtls_leaf_certificate_sha256_fingerprints.clone(),
            ));
        }
        for profile_id in self.referenced_sip_ingress_profile_ids() {
            let profile = self
                .sip_ingress_profiles
                .get(profile_id)
                .ok_or_else(|| anyhow!("api.routes references an unknown sip_ingress_profile"))?;
            sources.push((
                profile_id.to_owned(),
                profile.tenant_id.clone(),
                sip_ingress_profile_principal(profile_id, profile),
                profile.trusted_signaling_cidrs.clone(),
                profile.mtls_leaf_certificate_sha256_fingerprints.clone(),
            ));
        }

        for (profile_id, tenant_id, principal, configured_cidrs, configured_fingerprints) in sources
        {
            if tenant_id != listener_tenant {
                return Err(anyhow!(
                    "referenced SIP ingress profile tenant must exactly match the listener tenant"
                ));
            }
            let identity = VapiProjectedIdentity::from(&principal);
            let mut trusted_cidrs = Vec::with_capacity(configured_cidrs.len());
            for configured in &configured_cidrs {
                let cidr = configured
                    .parse::<IpNet>()
                    .map_err(|_| anyhow!("SIP ingress profile contains an invalid trusted CIDR"))?
                    .trunc();
                for (installed_profile_id, installed, installed_identity) in &installed_cidrs {
                    if ip_nets_overlap(&cidr, installed) {
                        let detail = if installed_identity == &identity {
                            "ambiguous overlapping trusted signaling CIDRs"
                        } else {
                            "overlapping trusted signaling CIDRs assign conflicting identities"
                        };
                        return Err(anyhow!(
                            "SIP ingress profiles {installed_profile_id:?} and {profile_id:?} have {detail}"
                        ));
                    }
                }
                installed_cidrs.push((profile_id.to_owned(), cidr, identity.clone()));
                trusted_cidrs.push(cidr);
            }

            let mut mtls_leaf_fingerprints = Vec::with_capacity(configured_fingerprints.len());
            for configured in &configured_fingerprints {
                let fingerprint = validate_mtls_leaf_sha256_fingerprint(configured)?;
                if let Some((installed_profile_id, installed_identity)) =
                    installed_fingerprints.get(&fingerprint)
                {
                    let detail = if installed_identity == &identity {
                        "ambiguously duplicate the same mTLS leaf certificate fingerprint"
                    } else {
                        "assign the same mTLS leaf certificate fingerprint to conflicting identities"
                    };
                    return Err(anyhow!(
                        "SIP ingress profiles {installed_profile_id:?} and {profile_id:?} {detail}"
                    ));
                }
                installed_fingerprints.insert(
                    fingerprint.clone(),
                    (profile_id.to_owned(), identity.clone()),
                );
                mtls_leaf_fingerprints.push(fingerprint);
            }

            projections.push(VapiListenerPrincipalProjection {
                profile_id,
                principal,
                trusted_cidrs,
                mtls_leaf_fingerprints,
            });
        }
        Ok(projections)
    }

    /// Build the signaling-attachment resolver from the same configured Vapi
    /// identity and non-secret profile revision used by the SIP listener and
    /// durable named-route snapshot.
    pub(crate) fn attachment_principal_resolver(
        &self,
        tenants: &[String],
    ) -> Result<ConfiguredAttachmentPrincipalResolver> {
        self.validate_named_profiles()
            .context("validating attachment identity profiles")?;
        self.validate_named_routes()
            .context("validating attachment identity routes")?;
        let mut resolver = self.providers.attachment_principal_resolver(tenants);
        for profile_id in self.referenced_vapi_profile_ids() {
            let profile = self
                .vapi_ingress_profiles
                .get(profile_id)
                .ok_or_else(|| anyhow!("api.routes references an unknown vapi_ingress_profile"))?;
            if !tenants.iter().any(|tenant| tenant == &profile.tenant_id) {
                return Err(anyhow!(
                    "referenced Vapi ingress profile tenant is unavailable to the call runtime"
                ));
            }
            resolver = resolver.with_vapi_ingress(
                profile_id.to_owned(),
                profile_revision(profile)?,
                vapi_profile_principal(profile_id, profile),
            );
        }
        for profile_id in self.referenced_sip_ingress_profile_ids() {
            let profile = self
                .sip_ingress_profiles
                .get(profile_id)
                .ok_or_else(|| anyhow!("api.routes references an unknown sip_ingress_profile"))?;
            if !tenants.iter().any(|tenant| tenant == &profile.tenant_id) {
                return Err(anyhow!(
                    "referenced SIP ingress profile tenant is unavailable to the call runtime"
                ));
            }
            resolver = resolver.with_sip_ingress(
                NamedProfileKind::SipIngress,
                profile_id.to_owned(),
                profile_revision(profile)?,
                sip_ingress_profile_principal(profile_id, profile),
            );
        }
        Ok(resolver)
    }

    /// Build exact recipe-owned stable SIP URI admissions from the same
    /// projected routes, principals, and non-secret profile revisions used by
    /// managed attachments. An empty catalog leaves the listener's ordinary
    /// one-use token behavior unchanged.
    pub(crate) fn recipe_sip_admission_catalog(
        &self,
    ) -> Result<Option<Arc<RecipeSipAdmissionCatalog>>> {
        self.validate_named_routes()
            .context("validating stable recipe SIP admissions")?;
        let mut admissions = Vec::new();
        for (route_id, route) in &self.api.routes {
            let Some(admission) = route.recipe_sip_admission.as_ref() else {
                continue;
            };
            if admission.mode != SipAdmissionMode::StableUri {
                continue;
            }
            let uri_user = admission.uri_user.clone().ok_or_else(|| {
                anyhow!("stable recipe SIP admission is missing its exact URI user")
            })?;
            let profile_id = route
                .sip_ingress_profile
                .as_ref()
                .ok_or_else(|| anyhow!("stable recipe SIP admission has no SIP ingress profile"))?;
            let profile = self
                .sip_ingress_profiles
                .get(profile_id)
                .ok_or_else(|| anyhow!("stable recipe SIP admission profile disappeared"))?;
            admissions.push(RecipeSipAdmissionRoute {
                uri_user,
                recipe_instance: route.tenant_id.clone(),
                route_id: route_id.clone(),
                expected_principal: sip_ingress_profile_principal(profile_id, profile),
                profiles: self.named_route_profile_bindings(route)?,
                required_correlation_header: route.required_sip_correlation_header.clone(),
                destination: route.destination.clone(),
            });
        }
        if admissions.is_empty() {
            return Ok(None);
        }
        RecipeSipAdmissionCatalog::new(admissions)
            .map(Arc::new)
            .map(Some)
            .map_err(|_| anyhow!("invalid or ambiguous stable recipe SIP admission catalog"))
    }

    pub(crate) fn resolved_named_routes(&self) -> Result<ResolvedNamedRoutes> {
        self.validate_named_routes()?;
        let webrtc = self
            .api
            .route_attachments
            .webrtc
            .as_ref()
            .map(|configured| {
                let ice_servers = configured
                    .ice_servers
                    .iter()
                    .map(|server| {
                        let credential = server
                            .credential
                            .as_ref()
                            .map(SecretRef::resolve)
                            .transpose()
                            .map_err(|error| {
                                anyhow!("resolving named-route ICE credential: {error}")
                            })?;
                        Ok(ResolvedRouteIceServer {
                            urls: server.urls.clone(),
                            username: server.username.clone(),
                            credential,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok::<ResolvedRouteWebRtcAttachment, anyhow::Error>(ResolvedRouteWebRtcAttachment {
                    signaling_uri: configured.signaling_uri.clone(),
                    ice_servers,
                })
            })
            .transpose()?;
        let routes = self
            .api
            .routes
            .iter()
            .map(|(route_id, route)| {
                let mut route = route.clone();
                route.profile_bindings = self.named_route_profile_bindings(&route)?;
                route.context_metadata_allowlist = match &route.destination_profile {
                    Some(RouteDestinationProfileRef::Sip { profile_id }) => Some(
                        self.sip_profiles
                            .get(profile_id)
                            .ok_or_else(|| anyhow!("named SIP destination profile disappeared"))?
                            .metadata_keys
                            .clone(),
                    ),
                    Some(RouteDestinationProfileRef::AmazonConnect { .. }) => {
                        route.context_metadata_allowlist.clone()
                    }
                    _ => None,
                };
                route.context_required |= matches!(
                    &route.destination.endpoint,
                    LegEndpointConfig::Sip(SipEndpointConfig {
                        initial_context: SipInitialContextMode::Required,
                        ..
                    })
                );
                route.capability_policy = match &route.destination_profile {
                    Some(RouteDestinationProfileRef::Sip { profile_id }) => {
                        let profile = self
                            .sip_profiles
                            .get(profile_id)
                            .ok_or_else(|| anyhow!("named SIP destination profile disappeared"))?;
                        NamedRouteCapabilityPolicy {
                            audio_codecs: profile.codecs.clone(),
                            data_channels: Some(false),
                            sip_message: Some(!profile.metadata_keys.is_empty()),
                        }
                    }
                    Some(RouteDestinationProfileRef::Webrtc { profile_id }) => {
                        let profile = self.webrtc_profiles.get(profile_id).ok_or_else(|| {
                            anyhow!("named WebRTC destination profile disappeared")
                        })?;
                        NamedRouteCapabilityPolicy {
                            audio_codecs: profile.codecs.clone(),
                            data_channels: Some(profile.data_channels),
                            sip_message: Some(false),
                        }
                    }
                    _ => NamedRouteCapabilityPolicy::default(),
                };
                Ok((route_id.clone(), route))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        Ok(ResolvedNamedRoutes {
            routes,
            sip_uri_template: self.api.route_attachments.sip_uri_template.clone(),
            webrtc,
        })
    }

    /// Build the immutable, credential-reference-only catalog used by call
    /// workers. Secret values and PEM files are intentionally not read here;
    /// the selected exact profile is resolved only when its owned StartLeg
    /// effect executes.
    pub(crate) fn outbound_profile_resolver(&self) -> Result<Arc<dyn OutboundProfileResolver>> {
        self.validate_named_routes()?;
        let mut resolver = StaticOutboundProfileResolver::default();
        for route in self.api.routes.values() {
            let bindings = self.named_route_profile_bindings(route)?;
            let destination = bindings
                .iter()
                .find(|binding| binding.role() == NamedProfileRole::Destination);
            let Some(binding) = destination else {
                continue;
            };
            match binding.kind() {
                NamedProfileKind::Sip => {
                    let profile = self.sip_profiles.get(binding.profile_id()).ok_or_else(|| {
                        anyhow!("named SIP destination profile disappeared during resolution")
                    })?;
                    let auth = profile.auth.as_ref().map(|auth| match auth {
                        SipProfileAuthCfg::Digest {
                            realm,
                            username,
                            password,
                        } => ConfiguredSipProfileAuth::Digest {
                            realm: realm.clone(),
                            username: username.clone(),
                            password: password.clone(),
                        },
                        SipProfileAuthCfg::Bearer { token } => ConfiguredSipProfileAuth::Bearer {
                            token: token.clone(),
                        },
                    });
                    resolver.insert_sip(
                        binding.profile_id().to_owned(),
                        binding.revision().to_owned(),
                        ConfiguredSipOutboundProfile {
                            from_uri: profile.from_uri.clone(),
                            outbound_proxy: profile.outbound_proxy.clone(),
                            auth,
                        },
                    );
                }
                NamedProfileKind::WebRtc => {
                    let profile =
                        self.webrtc_profiles
                            .get(binding.profile_id())
                            .ok_or_else(|| {
                                anyhow!(
                                    "named WebRTC destination profile disappeared during resolution"
                                )
                            })?;
                    resolver.insert_webrtc(
                        binding.profile_id().to_owned(),
                        binding.revision().to_owned(),
                        ConfiguredWebRtcOutboundProfile {
                            bearer_token: profile.bearer_token.clone(),
                            tls_roots: profile.tls_roots.clone(),
                            ice_servers: profile
                                .ice_servers
                                .iter()
                                .map(|server| ConfiguredIceServer {
                                    urls: server.urls.clone(),
                                    username: server.username.clone(),
                                    credential: server.credential.clone(),
                                })
                                .collect(),
                            audio_codecs: profile
                                .codecs
                                .iter()
                                .map(|codec| match codec {
                                    ProfileAudioCodec::Opus => rvoip_webrtc::WebRtcAudioCodec::Opus,
                                    ProfileAudioCodec::Pcmu => rvoip_webrtc::WebRtcAudioCodec::Pcmu,
                                    ProfileAudioCodec::Pcma => rvoip_webrtc::WebRtcAudioCodec::Pcma,
                                })
                                .collect(),
                            data_channels: profile.data_channels,
                        },
                    );
                }
                NamedProfileKind::VapiIngress
                | NamedProfileKind::SipIngress
                | NamedProfileKind::AmazonConnect
                | NamedProfileKind::Telnyx => {}
            }
        }
        Ok(Arc::new(resolver))
    }
}

fn validate_named_profile_id_for_config(value: &str, kind: NamedProfileKind) -> Result<()> {
    NamedProfileBinding::new(
        NamedProfileRole::Ingress,
        kind,
        value.to_owned(),
        "0".repeat(64),
    )
    .map(|_| ())
    .map_err(|_| anyhow!("named profile catalog contains an invalid profile ID"))
}

fn profile_revision<T: Serialize>(profile: &T) -> Result<String> {
    let encoded = serde_json::to_vec(profile)
        .map_err(|_| anyhow!("named profile cannot be canonicalized"))?;
    let digest = Sha256::digest(encoded);
    let mut revision = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut revision, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(revision)
}

/// Split one configured RTP range into disjoint even/odd port-pair slices.
/// Separate rvoip coordinators own separate allocators, so overlapping ranges
/// would otherwise permit two children to reserve the same socket pair.
fn partition_rtp_port_range(start: u16, end: u16, partitions: usize) -> Result<Vec<(u16, u16)>> {
    if partitions == 0 {
        return Err(anyhow!("RTP range partition count must be nonzero"));
    }
    if partitions == 1 {
        return Ok(vec![(start, end)]);
    }
    let first_even = if start.is_multiple_of(2) {
        start
    } else {
        start
            .checked_add(1)
            .ok_or_else(|| anyhow!("generic SIP RTP range has no usable port pair"))?
    };
    let last_odd = if !end.is_multiple_of(2) {
        end
    } else {
        end.checked_sub(1)
            .ok_or_else(|| anyhow!("generic SIP RTP range has no usable port pair"))?
    };
    if first_even >= last_odd {
        return Err(anyhow!("generic SIP RTP range has no usable port pair"));
    }
    let pair_count = (u32::from(last_odd) - u32::from(first_even)).div_ceil(2) as usize;
    if pair_count < partitions {
        return Err(anyhow!(
            "generic SIP RTP range needs at least one port pair for the listener and every referenced SIP profile"
        ));
    }
    let pairs_per_partition = pair_count / partitions;
    let extra = pair_count % partitions;
    let mut ranges = Vec::with_capacity(partitions);
    let mut next = u32::from(first_even);
    for index in 0..partitions {
        let pairs = pairs_per_partition + usize::from(index < extra);
        let width = u32::try_from(pairs)
            .map_err(|_| anyhow!("generic SIP RTP partition is too large"))?
            .checked_mul(2)
            .ok_or_else(|| anyhow!("generic SIP RTP partition overflow"))?;
        let range_end = next
            .checked_add(width - 1)
            .ok_or_else(|| anyhow!("generic SIP RTP partition overflow"))?;
        ranges.push((
            u16::try_from(next).map_err(|_| anyhow!("generic SIP RTP partition overflow"))?,
            u16::try_from(range_end).map_err(|_| anyhow!("generic SIP RTP partition overflow"))?,
        ));
        next = range_end + 1;
    }
    Ok(ranges)
}

fn validate_profile_text(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_NAMED_PROFILE_VALUE_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(anyhow!(
            "{field} must be a bounded, trimmed, control-free value"
        ));
    }
    Ok(())
}

fn validate_profile_scope(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_NAMED_PROFILE_SCOPE_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_' | b'.' | b'*')
        })
    {
        return Err(anyhow!("{field} is invalid"));
    }
    Ok(())
}

fn validate_profile_path(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_NAMED_PROFILE_VALUE_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(anyhow!("{field} must be a bounded path"));
    }
    Ok(())
}

fn validate_secret_reference(value: &SecretRef) -> Result<()> {
    value
        .validate_reference()
        .map_err(|_| anyhow!("named profile contains an invalid secret reference"))
}

fn validate_profile_cidr(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || value.trim() != value
        || value.chars().any(char::is_whitespace)
    {
        return Err(anyhow!(
            "vapi_ingress_profiles contains an invalid trusted signaling CIDR"
        ));
    }
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| anyhow!("vapi_ingress_profiles trusted signaling entries must be CIDRs"))?;
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| anyhow!("vapi_ingress_profiles contains an invalid trusted signaling CIDR"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| anyhow!("vapi_ingress_profiles contains an invalid trusted signaling CIDR"))?;
    let max = if address.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err(anyhow!(
            "vapi_ingress_profiles contains an invalid trusted signaling CIDR"
        ));
    }
    Ok(())
}

fn validate_mtls_leaf_sha256_fingerprint(value: &str) -> Result<String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "vapi_ingress_profiles mTLS leaf certificate SHA-256 fingerprints must contain exactly 64 hexadecimal characters"
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn ip_nets_overlap(left: &IpNet, right: &IpNet) -> bool {
    match (left, right) {
        (IpNet::V4(left), IpNet::V4(right)) => {
            left.contains(&right.network()) || right.contains(&left.network())
        }
        (IpNet::V6(left), IpNet::V6(right)) => {
            left.contains(&right.network()) || right.contains(&left.network())
        }
        _ => false,
    }
}

fn vapi_profile_principal(
    profile_id: &str,
    profile: &VapiIngressProfileCfg,
) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        subject: profile.principal_subject.clone(),
        tenant: Some(profile.tenant_id.clone()),
        scopes: profile.scopes.iter().cloned().collect(),
        issuer: Some(profile.issuer.clone()),
        expires_at: None,
        // rvoip currently has no trusted-network authentication-method tag.
        // `ApiKey` is its existing static-policy identity convention; an mTLS
        // selector is normalized to `MutualTls` by SipListenerAuthPolicy.
        method: AuthenticationMethod::ApiKey,
        assurance: IdentityAssurance::Pseudonymous {
            ephemeral_key: Jwk(serde_json::json!({
                "kty": "bridgefu-profile",
                "profile_id": profile_id,
            })),
        },
    }
}

fn sip_ingress_profile_principal(
    profile_id: &str,
    profile: &SipIngressProfileCfg,
) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        subject: profile.principal_subject.clone(),
        tenant: Some(profile.tenant_id.clone()),
        scopes: profile.scopes.iter().cloned().collect(),
        issuer: Some(profile.issuer.clone()),
        expires_at: None,
        method: AuthenticationMethod::ApiKey,
        assurance: IdentityAssurance::Pseudonymous {
            ephemeral_key: Jwk(serde_json::json!({
                "kty": "bridgefu-sip-ingress-profile",
                "profile_id": profile_id,
            })),
        },
    }
}

fn validate_profile_codecs(codecs: &BTreeSet<ProfileAudioCodec>, field: &str) -> Result<()> {
    if codecs.is_empty() || codecs.len() > 3 {
        return Err(anyhow!(
            "{field} must contain at least one supported audio codec"
        ));
    }
    Ok(())
}

fn validate_profile_sip_uri(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_NAMED_PROFILE_VALUE_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
        || value.contains('?')
        || value.contains('#')
    {
        return Err(anyhow!("{field} must be a bounded credential-free SIP URI"));
    }
    let rest = value
        .strip_prefix("sips:")
        .or_else(|| value.strip_prefix("sip:"))
        .ok_or_else(|| anyhow!("{field} must use sip or sips"))?;
    if rest.is_empty() || rest.matches('@').count() > 1 {
        return Err(anyhow!("{field} is invalid"));
    }
    let authority = if let Some((user, authority)) = rest.split_once('@') {
        if user.is_empty() || user.contains(':') {
            return Err(anyhow!("{field} must not contain credentials"));
        }
        authority
    } else {
        rest
    };
    if authority.split(';').next().unwrap_or_default().is_empty() {
        return Err(anyhow!("{field} is invalid"));
    }
    Ok(())
}

fn normalized_wss_origin(value: &str) -> Result<String> {
    let parsed = url::Url::parse(value)
        .map_err(|_| anyhow!("WebRTC signaling target must be a valid WSS URL"))?;
    if parsed.scheme() != "wss"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(anyhow!(
            "WebRTC signaling target must be a credential-free WSS URL"
        ));
    }
    let host = parsed.host_str().expect("host checked above");
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    Ok(match parsed.port() {
        Some(port) if port != 443 => format!("wss://{host}:{port}"),
        _ => format!("wss://{host}"),
    })
}

fn validate_profile_wss_origin(value: &str) -> Result<()> {
    let parsed = url::Url::parse(value)
        .map_err(|_| anyhow!("webrtc_profiles contains an invalid WSS origin"))?;
    let normalized = normalized_wss_origin(value)?;
    if parsed.path() != "/" || normalized != value.trim_end_matches('/') {
        return Err(anyhow!(
            "webrtc_profiles origins must not contain paths, credentials, queries, or fragments"
        ));
    }
    Ok(())
}

fn validate_profile_ice_server(server: &ProfileIceServerCfg) -> Result<()> {
    if server.urls.is_empty()
        || server.urls.len() > MAX_GENERIC_ICE_URLS_PER_SERVER
        || server.urls.iter().any(|value| {
            value.is_empty()
                || value.len() > MAX_GENERIC_ICE_URL_BYTES
                || value.chars().any(char::is_control)
                || value.chars().any(char::is_whitespace)
                || !matches!(
                    value.split(':').next(),
                    Some("stun" | "stuns" | "turn" | "turns")
                )
        })
        || server
            .username
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_GENERIC_ICE_IDENTITY_BYTES)
        || server.username.is_some() != server.credential.is_some()
    {
        return Err(anyhow!("webrtc_profiles contains an invalid ICE server"));
    }
    if let Some(credential) = &server.credential {
        validate_secret_reference(credential)?;
    }
    Ok(())
}

fn validate_profile_metadata_key(value: &str) -> Result<()> {
    let normalized = value.to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || matches!(
            normalized.as_str(),
            "tenant_id" | "call_id" | "leg_id" | "route_id" | "attachment_token" | "authorization"
        )
    {
        return Err(anyhow!("sip_profiles contains an invalid metadata key"));
    }
    Ok(())
}

fn validate_route_sip_template(template: &str, security: SipIngressSecurity) -> Result<()> {
    if template.len() > 2_048
        || template.matches("{token}").count() != 1
        || template.chars().any(char::is_control)
        || template.chars().any(char::is_whitespace)
    {
        return Err(anyhow!(
            "api.route_attachments.sip_uri_template must be a bounded SIP URI with exactly one token placeholder"
        ));
    }
    let expected_scheme = match security {
        SipIngressSecurity::SipsSrtp | SipIngressSecurity::SipsOptionalSrtp => "sips:",
        SipIngressSecurity::SipRtp => "sip:",
    };
    let rest = template.strip_prefix(expected_scheme).ok_or_else(|| {
        anyhow!(
            "api.route_attachments.sip_uri_template scheme does not match the SIP ingress security posture"
        )
    })?;
    let (user, target) = rest.split_once('@').ok_or_else(|| {
        anyhow!("api.route_attachments.sip_uri_template must put the token in the user part")
    })?;
    if user != "{token}" || target.contains('@') || target.contains('?') || target.contains('#') {
        return Err(anyhow!(
            "api.route_attachments.sip_uri_template must use {{token}} as its complete user part"
        ));
    }
    let authority = target.split(';').next().unwrap_or_default();
    let parsed = url::Url::parse(&format!("https://bridgefu-token@{authority}"))
        .map_err(|_| anyhow!("api.route_attachments.sip_uri_template target is invalid"))?;
    if parsed.host_str().is_none() || parsed.password().is_some() {
        return Err(anyhow!(
            "api.route_attachments.sip_uri_template target is invalid"
        ));
    }
    Ok(())
}

fn validate_recipe_public_host(host: &str) -> Result<()> {
    if host.is_empty()
        || host.len() > 253
        || host.trim() != host
        || host.chars().any(char::is_control)
        || host.chars().any(char::is_whitespace)
    {
        return Err(anyhow!(
            "edge.public_host must be a bounded DNS name or IP address"
        ));
    }
    let parsed = url::Url::parse(&format!("https://{host}/"))
        .map_err(|_| anyhow!("edge.public_host must be a DNS name or IP address"))?;
    if parsed.host_str().is_none()
        || parsed.port().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(anyhow!(
            "edge.public_host must contain only a DNS name or IP address"
        ));
    }
    Ok(())
}

fn validate_recipe_public_dns_name(host: &str) -> Result<()> {
    validate_recipe_public_host(host)?;
    let parsed = url::Url::parse(&format!("https://{host}/"))
        .map_err(|_| anyhow!("edge.public_host must be a bounded DNS name"))?;
    if !matches!(parsed.host(), Some(url::Host::Domain(_)))
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(anyhow!(
            "edge.public_host must be a bounded DNS name for SIPS recipes"
        ));
    }
    Ok(())
}

fn connect_instance_id(instance_arn: &str, configured_region: &str) -> Result<String> {
    let fields = instance_arn.splitn(6, ':').collect::<Vec<_>>();
    if fields.len() != 6
        || fields[0] != "arn"
        || fields[2] != "connect"
        || fields[3].is_empty()
        || fields[4].is_empty()
        || !fields[5].starts_with("instance/")
    {
        return Err(anyhow!(
            "recipe connect_instance_arn must be an Amazon Connect instance ARN"
        ));
    }
    if configured_region.is_empty() || fields[3] != configured_region {
        return Err(anyhow!(
            "recipe Connect instance region must exactly match aws.region"
        ));
    }
    let id = fields[5].trim_start_matches("instance/");
    if id.is_empty()
        || id.len() > 512
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(anyhow!(
            "recipe Connect instance ARN contains an invalid instance ID"
        ));
    }
    Ok(id.to_owned())
}

fn recipe_sip_admission<'a>(
    _instance: &str,
    admission: Option<&'a bridgefu::recipes::SipAdmissionSpec>,
) -> Result<&'a bridgefu::recipes::SipAdmissionSpec> {
    admission.ok_or_else(|| anyhow!("recipe SIP source has no admission policy"))
}

fn recipe_route_id(instance: &str, bridge_id: &str, recipe: &CompiledRecipe) -> Result<String> {
    let route_id = if recipe.spec.bridges.len() == 1 {
        instance.to_owned()
    } else {
        format!("{instance}-{bridge_id}")
    };
    NamedRouteBinding::new(route_id.clone(), None)
        .map_err(|_| anyhow!("compiled recipe route ID is invalid"))?;
    Ok(route_id)
}

fn recipe_sip_ingress_security(security: SipSecurity) -> SipIngressSecurity {
    match security {
        SipSecurity::SipsSrtp => SipIngressSecurity::SipsSrtp,
        SipSecurity::SipsOptionalSrtp => SipIngressSecurity::SipsOptionalSrtp,
        SipSecurity::SipRtp => SipIngressSecurity::SipRtp,
    }
}

fn recipe_srtp_policy(security: SipSecurity) -> ProfileSrtpPolicy {
    match security {
        SipSecurity::SipsSrtp => ProfileSrtpPolicy::Required,
        SipSecurity::SipsOptionalSrtp => ProfileSrtpPolicy::Preferred,
        SipSecurity::SipRtp => ProfileSrtpPolicy::Disabled,
    }
}

fn recipe_profile_codecs(codecs: &BTreeSet<RecipeAudioCodec>) -> BTreeSet<ProfileAudioCodec> {
    codecs
        .iter()
        .map(|codec| match codec {
            RecipeAudioCodec::Pcmu => ProfileAudioCodec::Pcmu,
            RecipeAudioCodec::Pcma => ProfileAudioCodec::Pcma,
            RecipeAudioCodec::Opus => ProfileAudioCodec::Opus,
        })
        .collect()
}

fn recipe_generic_webrtc_codecs(
    codecs: &BTreeSet<RecipeAudioCodec>,
) -> BTreeSet<GenericWebRtcAudioCodec> {
    codecs
        .iter()
        .map(|codec| match codec {
            RecipeAudioCodec::Pcmu => GenericWebRtcAudioCodec::Pcmu,
            RecipeAudioCodec::Pcma => GenericWebRtcAudioCodec::Pcma,
            RecipeAudioCodec::Opus => GenericWebRtcAudioCodec::Opus,
        })
        .collect()
}

fn validate_route_webrtc_attachment(config: &RouteWebRtcAttachmentCfg) -> Result<()> {
    let parsed = url::Url::parse(&config.signaling_uri)
        .map_err(|_| anyhow!("api.route_attachments.webrtc.signaling_uri is invalid"))?;
    if parsed.scheme() != "wss"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(anyhow!(
            "api.route_attachments.webrtc.signaling_uri must be a credential-free WSS endpoint"
        ));
    }
    if config.ice_servers.len() > MAX_GENERIC_ICE_SERVERS {
        return Err(anyhow!(
            "api.route_attachments.webrtc has too many ICE servers"
        ));
    }
    for server in &config.ice_servers {
        if server.urls.is_empty()
            || server.urls.len() > MAX_GENERIC_ICE_URLS_PER_SERVER
            || server.urls.iter().any(|value| {
                value.is_empty()
                    || value.len() > MAX_GENERIC_ICE_URL_BYTES
                    || value.chars().any(char::is_control)
                    || value.chars().any(char::is_whitespace)
                    || !matches!(
                        value.split(':').next(),
                        Some("stun" | "stuns" | "turn" | "turns")
                    )
            })
            || server
                .username
                .as_ref()
                .is_some_and(|value| value.len() > MAX_GENERIC_ICE_IDENTITY_BYTES)
            || server.username.is_some() != server.credential.is_some()
        {
            return Err(anyhow!(
                "api.route_attachments.webrtc contains an invalid ICE server"
            ));
        }
        if let Some(secret) = &server.credential {
            let mut value = secret
                .resolve()
                .map_err(|error| anyhow!("resolving named-route ICE credential: {error}"))?;
            let valid = !value.is_empty()
                && value.len() <= MAX_GENERIC_ICE_IDENTITY_BYTES
                && !value.chars().any(char::is_control);
            value.zeroize();
            if !valid {
                return Err(anyhow!(
                    "api.route_attachments.webrtc ICE credential is invalid"
                ));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiRateLimitCfg {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_api_control_rate")]
    pub control_requests_per_second: u32,
    #[serde(default = "default_api_control_burst")]
    pub control_burst: u32,
    #[serde(default = "default_api_diagnostics_rate")]
    pub diagnostics_requests_per_second: u32,
    #[serde(default = "default_api_diagnostics_burst")]
    pub diagnostics_burst: u32,
    #[serde(default = "default_api_webhook_rate")]
    pub webhook_requests_per_second: u32,
    #[serde(default = "default_api_webhook_burst")]
    pub webhook_burst: u32,
    #[serde(default = "default_api_tracked_identities")]
    pub max_tracked_identities: usize,
    #[serde(default = "default_api_identity_idle_ttl")]
    pub identity_idle_ttl_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct ApiTlsCfg {
    /// PEM file containing the leaf certificate followed by intermediates.
    pub certificate_chain: String,
    /// PEM file containing the matching private key.
    pub private_key: String,
}

#[derive(Debug, Deserialize)]
pub struct BroadcastCfg {
    #[serde(default = "default_broadcast_transport")]
    pub default_transport: String,
    #[serde(default = "default_broadcast_ttl")]
    pub token_ttl_secs: u64,
    #[serde(default = "default_max_broadcasts")]
    pub max_active: usize,
    #[serde(default)]
    pub public_endpoint: Option<String>,
    #[serde(default)]
    pub token_secret: Option<SecretRef>,
    /// Dedicated public raw-QUIC listener for receive-only UCTP broadcast
    /// subscribers. Its endpoint is advertised through `public_endpoint`.
    #[serde(default)]
    pub uctp_listener: Option<PublicUctpListenerCfg>,
    /// Clustered worker origin connection to the separately scalable MOQT
    /// relay tier. Without this, split-gateway broadcast creation fails
    /// closed because no advertised subscriber endpoint can reach a worker.
    #[serde(default)]
    pub moq_origin_relay: Option<MoqOriginRelayCfg>,
    /// Explicit per-tenant permission and bounds for the optional MOQT
    /// sanitized event track. An empty map is the default-off behavior.
    #[serde(default)]
    pub sanitized_events: BroadcastSanitizedEventsCfg,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BroadcastSanitizedEventsCfg {
    #[serde(default)]
    pub tenants: BTreeMap<String, TenantSanitizedEventsCfg>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantSanitizedEventsCfg {
    pub context_metadata_key: String,
    #[serde(default = "default_sanitized_event_queue")]
    pub queue_events: usize,
    #[serde(default = "default_sanitized_event_history")]
    pub history_events: usize,
    #[serde(default = "default_sanitized_event_rate")]
    pub max_events_per_second: u32,
}

impl BroadcastSanitizedEventsCfg {
    pub fn policies(
        &self,
        context_policy: &ContextPolicy,
    ) -> Result<BTreeMap<String, SanitizedContextEventPolicy>> {
        // The process binary and reusable library compile this configuration
        // module in separate crate roots. Copy the already validated public
        // policy shape across that boundary instead of allowing the two
        // nominally distinct Rust types to drift.
        let broadcast_context_policy = bridgefu::context::ContextPolicy {
            allow_headers: context_policy.allow_headers.clone(),
            allow_metadata_keys: context_policy.allow_metadata_keys.clone(),
        };
        self.tenants
            .iter()
            .map(|(tenant, config)| {
                let policy = SanitizedContextEventPolicy::new(
                    config.context_metadata_key.clone(),
                    config.queue_events,
                    config.history_events,
                    config.max_events_per_second,
                    &broadcast_context_policy,
                )
                .map_err(|error| anyhow!("broadcast.sanitized_events.tenants.{tenant}: {error}"))?;
                Ok((tenant.clone(), policy))
            })
            .collect()
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct PublicUctpListenerCfg {
    pub bind: String,
    pub tls: PublicUctpTlsCfg,
    #[serde(default = "default_public_uctp_connections")]
    pub max_concurrent_connections: usize,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PublicUctpTlsCfg {
    pub certificate_chain: Vec<String>,
    pub private_key: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MoqOriginRelayCfg {
    /// Local UDP bind for origin-to-relay raw QUIC (port 0 is allowed).
    pub bind: String,
    /// Private publisher mTLS ingress reached by worker origins.
    pub publisher_endpoint: String,
    /// Public receive-only raw-QUIC or WebTransport listener returned by the
    /// broadcast API. It must not be the publisher ingress.
    pub subscriber_endpoint: String,
    pub root_certificates: Vec<String>,
    pub client_certificate: String,
    pub client_private_key: String,
}

impl MoqOriginRelayCfg {
    fn validate(&self) -> Result<()> {
        self.bind
            .parse::<SocketAddr>()
            .map_err(|_| anyhow!("broadcast.moq_origin_relay.bind must be a socket address"))?;
        let publisher_endpoint = url::Url::parse(&self.publisher_endpoint).map_err(|_| {
            anyhow!("broadcast.moq_origin_relay.publisher_endpoint must be a valid URL")
        })?;
        if publisher_endpoint.scheme() != "moqt"
            || publisher_endpoint.host_str().is_none()
            || publisher_endpoint.port().is_none()
            || !publisher_endpoint.username().is_empty()
            || publisher_endpoint.password().is_some()
            || publisher_endpoint.query().is_some()
            || publisher_endpoint.fragment().is_some()
        {
            return Err(anyhow!(
                "broadcast.moq_origin_relay.publisher_endpoint must be a credential-free moqt:// authority with an explicit port"
            ));
        }
        let subscriber_endpoint = url::Url::parse(&self.subscriber_endpoint).map_err(|_| {
            anyhow!("broadcast.moq_origin_relay.subscriber_endpoint must be a valid URL")
        })?;
        if !matches!(subscriber_endpoint.scheme(), "moqt" | "https")
            || subscriber_endpoint.host_str().is_none()
            || subscriber_endpoint.port().is_none()
            || !subscriber_endpoint.username().is_empty()
            || subscriber_endpoint.password().is_some()
            || subscriber_endpoint.query().is_some()
            || subscriber_endpoint.fragment().is_some()
        {
            return Err(anyhow!(
                "broadcast.moq_origin_relay.subscriber_endpoint must be a credential-free moqt:// or https:// authority with an explicit port"
            ));
        }
        if publisher_endpoint == subscriber_endpoint {
            return Err(anyhow!(
                "broadcast.moq_origin_relay publisher and subscriber endpoints must be distinct"
            ));
        }
        if self.root_certificates.is_empty()
            || self.root_certificates.iter().any(|path| !valid_path(path))
            || !valid_path(&self.client_certificate)
            || !valid_path(&self.client_private_key)
        {
            return Err(anyhow!(
                "broadcast.moq_origin_relay requires bounded mTLS certificate paths"
            ));
        }
        Ok(())
    }
}

fn valid_path(path: &str) -> bool {
    !path.is_empty() && path.len() <= 4_096 && !path.chars().any(char::is_control)
}

#[derive(Clone, Debug, Deserialize)]
pub struct MoqRelayCfg {
    pub publisher: MoqRelayPublisherCfg,
    pub subscriber_webtransport: MoqRelayListenerCfg,
    pub subscriber_raw_quic: MoqRelayListenerCfg,
    pub tls: MoqRelayTlsCfg,
    pub diagnostics_bearer_token: SecretRef,
    #[serde(default)]
    pub limits: MoqRelayLimitsCfg,
    #[serde(default)]
    pub timeouts: MoqRelayTimeoutsCfg,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MoqRelayListenerCfg {
    pub bind: String,
    pub advertised_endpoint: String,
    #[serde(default)]
    pub advertised_socket_addr: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MoqRelayPublisherCfg {
    #[serde(flatten)]
    pub listener: MoqRelayListenerCfg,
    pub certificate_bindings: Vec<MoqRelayCertificateBindingCfg>,
    #[serde(default = "default_moq_sessions_per_certificate")]
    pub max_active_sessions_per_certificate: usize,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MoqRelayCertificateBindingCfg {
    pub certificate_sha256: String,
    pub scope: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MoqRelayTlsCfg {
    pub server_certificates: Vec<String>,
    pub server_private_keys: Vec<String>,
    pub publisher_client_ca_certificates: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MoqRelayLimitsCfg {
    #[serde(default = "default_moq_pending_admissions")]
    pub max_pending_admissions: usize,
    #[serde(default = "default_moq_active_sessions")]
    pub max_active_sessions: usize,
    #[serde(default = "default_moq_tenant_sessions")]
    pub max_active_sessions_per_tenant: usize,
    #[serde(default = "default_moq_replay_claims")]
    pub max_replay_claims: usize,
    #[serde(default = "default_moq_coordinated_namespaces")]
    pub max_coordinated_namespaces: usize,
    #[serde(default = "default_moq_cached_tracks")]
    pub max_cached_tracks_per_namespace: usize,
    #[serde(default = "default_moq_pending_tracks")]
    pub max_pending_track_requests_per_namespace: usize,
    #[serde(default = "default_moq_upstream_connections")]
    pub max_upstream_connections: usize,
    #[serde(default = "default_moq_upstream_tracks")]
    pub max_upstream_tracks: usize,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MoqRelayTimeoutsCfg {
    #[serde(default = "default_moq_setup_timeout")]
    pub setup_secs: u64,
    #[serde(default = "default_moq_admission_timeout")]
    pub admission_secs: u64,
    #[serde(default = "default_moq_admission_operation_timeout")]
    pub admission_operation_secs: u64,
    #[serde(default = "default_moq_cleanup_timeout")]
    pub pre_admission_cleanup_secs: u64,
    #[serde(default = "default_moq_session_close_timeout")]
    pub admission_session_close_secs: u64,
    #[serde(default = "default_moq_revalidation_interval")]
    pub token_revalidation_interval_secs: u64,
    #[serde(default = "default_moq_upstream_track_idle")]
    pub upstream_track_idle_secs: u64,
    #[serde(default = "default_moq_upstream_connection_idle")]
    pub upstream_connection_idle_secs: u64,
    #[serde(default = "default_moq_drop_cleanup")]
    pub drop_cleanup_secs: u64,
    #[serde(default = "default_moq_dependency_check_interval")]
    pub dependency_check_interval_secs: u64,
}

#[derive(Debug, Default, Deserialize)]
pub struct AwsCfg {
    pub region: String,
    /// Legacy single-tenant Connect instance id. Ignored when `tenants:` is
    /// non-empty.
    #[serde(default)]
    pub instance_id: Option<String>,
    /// Legacy single-tenant contact-flow id. Ignored when `tenants:` is
    /// non-empty.
    #[serde(default)]
    pub contact_flow_id: Option<String>,
}

/// One tenant: the Connect target for a SIP user part (CONTRACTS.md B.4).
#[derive(Debug, Deserialize, Clone)]
pub struct TenantCfg {
    pub instance_id: String,
    pub contact_flow_id: String,
    /// Runtime-only routing namespace that has no Amazon Connect ownership.
    /// Recipe projectors use this for SIP/WebRTC bridges so generic routes do
    /// not carry fake Connect identifiers.
    #[serde(default)]
    pub routing_only: bool,
    /// Display name shown to the agent when the INVITE supplies none.
    /// Falls back to `contact.default_display_name`.
    #[serde(default)]
    pub default_display_name: Option<String>,
    /// Per-tenant header→attribute mapping. Falls back to the top-level
    /// `mapping:` block.
    #[serde(default)]
    pub mapping: Option<MappingCfg>,
}

#[derive(Debug, Deserialize)]
pub struct SipCfg {
    #[serde(default = "default_bind_ip")]
    pub bind_ip: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Public IP for SIP Via/Contact. `"auto"` → IMDSv2 public-ipv4.
    #[serde(default = "default_auto")]
    pub advertised_ip: String,
    /// Public IP for SDP media (`c=`/`m=`). `"auto"` → IMDSv2 public-ipv4.
    #[serde(default = "default_auto")]
    pub media_public_ip: String,
}

impl Default for SipCfg {
    fn default() -> Self {
        Self {
            bind_ip: default_bind_ip(),
            port: default_port(),
            advertised_ip: default_auto(),
            media_public_ip: default_auto(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ContactCfg {
    #[serde(default = "default_display_name")]
    pub default_display_name: String,
    #[serde(default = "default_signaling_timeout")]
    pub signaling_timeout_secs: u64,
    #[serde(default = "default_media_timeout")]
    pub media_connect_timeout_secs: u64,
    #[serde(default = "default_keepalive")]
    pub keepalive_interval_secs: u64,
    #[serde(default = "default_idle_ttl")]
    pub session_idle_ttl_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MappingCfg {
    /// `drop` | `pass_prefixed`
    #[serde(default = "default_unmapped")]
    pub unmapped: String,
    #[serde(default = "default_prefix")]
    pub passthrough_prefix: String,
    /// inbound SIP header name → Connect attribute key
    #[serde(default)]
    pub rename: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct ObsCfg {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_log_format")]
    pub log_format: String,
    #[serde(default = "default_http_bind")]
    pub http_bind: String,
    /// Optional OTLP/gRPC trace export. Stdout logs and Prometheus remain
    /// active independently of this exporter.
    #[serde(default)]
    pub otlp: OtlpTracingCfg,
}

#[derive(Debug, Deserialize)]
pub struct OtlpTracingCfg {
    #[serde(default)]
    pub enabled: bool,
    /// Collector origin, for example `https://otel-collector:4317`. No
    /// credentials, query parameters, or request headers are accepted here.
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default = "default_otlp_service_name")]
    pub service_name: String,
    /// Parent-based trace-ID sampling ratio in the inclusive range 0.0..=1.0.
    #[serde(default = "default_otlp_sampling_ratio")]
    pub sampling_ratio: f64,
    #[serde(default = "default_otlp_max_queue_size")]
    pub max_queue_size: usize,
    #[serde(default = "default_otlp_max_export_batch_size")]
    pub max_export_batch_size: usize,
    #[serde(default = "default_otlp_scheduled_delay_millis")]
    pub scheduled_delay_millis: u64,
    #[serde(default = "default_otlp_export_timeout_millis")]
    pub export_timeout_millis: u64,
}

impl OtlpTracingCfg {
    pub(crate) fn validate(&self) -> Result<()> {
        let service_name = self.service_name.trim();
        if service_name.is_empty() || service_name.chars().count() > MAX_OTLP_SERVICE_NAME_LENGTH {
            return Err(anyhow!(
                "observability.otlp.service_name must contain 1 to {MAX_OTLP_SERVICE_NAME_LENGTH} characters"
            ));
        }
        if !self.sampling_ratio.is_finite() || !(0.0..=1.0).contains(&self.sampling_ratio) {
            return Err(anyhow!(
                "observability.otlp.sampling_ratio must be between 0.0 and 1.0"
            ));
        }
        if !(1..=MAX_OTLP_QUEUE_SIZE).contains(&self.max_queue_size) {
            return Err(anyhow!(
                "observability.otlp.max_queue_size must be between 1 and {MAX_OTLP_QUEUE_SIZE}"
            ));
        }
        if !(1..=MAX_OTLP_EXPORT_BATCH_SIZE).contains(&self.max_export_batch_size)
            || self.max_export_batch_size > self.max_queue_size
        {
            return Err(anyhow!(
                "observability.otlp.max_export_batch_size must be between 1 and {}, and no greater than max_queue_size",
                MAX_OTLP_EXPORT_BATCH_SIZE
            ));
        }
        if !(MIN_OTLP_SCHEDULE_DELAY_MILLIS..=MAX_OTLP_SCHEDULE_DELAY_MILLIS)
            .contains(&self.scheduled_delay_millis)
        {
            return Err(anyhow!(
                "observability.otlp.scheduled_delay_millis must be between {MIN_OTLP_SCHEDULE_DELAY_MILLIS} and {MAX_OTLP_SCHEDULE_DELAY_MILLIS}"
            ));
        }
        if !(MIN_OTLP_EXPORT_TIMEOUT_MILLIS..=MAX_OTLP_EXPORT_TIMEOUT_MILLIS)
            .contains(&self.export_timeout_millis)
        {
            return Err(anyhow!(
                "observability.otlp.export_timeout_millis must be between {MIN_OTLP_EXPORT_TIMEOUT_MILLIS} and {MAX_OTLP_EXPORT_TIMEOUT_MILLIS}"
            ));
        }

        match self.endpoint.as_deref() {
            None if self.enabled => {
                return Err(anyhow!(
                    "observability.otlp.endpoint is required when OTLP tracing is enabled"
                ));
            }
            None => {}
            Some(endpoint) => validate_otlp_endpoint(endpoint)?,
        }
        Ok(())
    }
}

fn validate_otlp_endpoint(endpoint: &str) -> Result<()> {
    if endpoint.len() > MAX_OTLP_ENDPOINT_LENGTH {
        return Err(anyhow!(
            "observability.otlp.endpoint must be at most {MAX_OTLP_ENDPOINT_LENGTH} bytes"
        ));
    }
    let parsed = url::Url::parse(endpoint)
        .map_err(|_| anyhow!("observability.otlp.endpoint must be a valid http or https URL"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(anyhow!(
            "observability.otlp.endpoint must be an http or https collector origin without credentials, path, query, or fragment"
        ));
    }
    Ok(())
}

impl Config {
    /// Parse a YAML config file.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let value = effective_value(path)?;
        let mut cfg = deserialize_strict(&value, path)?;
        cfg.apply_recipes()
            .with_context(|| format!("compiling recipes in {}", path.display()))?;
        cfg.validate()?;
        cfg.resolved_tenants()
            .with_context(|| format!("validating {}", path.display()))?;
        Ok(cfg)
    }

    /// Parse and project recipe instances without resolving runtime secrets.
    ///
    /// This is deliberately narrower than [`Self::load`]. It exists for the
    /// redacted `recipe explain` command, which must remain useful before
    /// Secrets Manager, environment, or mounted-file values are available.
    /// Recipe compilation and projection conflicts are still checked; callers
    /// must use the normal validator before starting a runtime.
    pub(crate) fn load_recipe_view(path: &std::path::Path) -> Result<Self> {
        let value = effective_value(path)?;
        let mut cfg = deserialize_strict(&value, path)?;
        cfg.apply_recipes()
            .with_context(|| format!("compiling recipes in {}", path.display()))?;
        Ok(cfg)
    }

    /// Whether the historical ReferenceTenant-compatible public SIP server is
    /// intentionally enabled. Existing configurations retain it by default;
    /// recipe configurations default to the generic durable runtime only.
    #[must_use]
    pub fn legacy_vapi_connect_enabled(&self) -> bool {
        match self.legacy_vapi_connect.enabled {
            Some(enabled) => enabled,
            None => self.recipes.is_empty(),
        }
    }

    fn apply_recipes(&mut self) -> Result<()> {
        if self.recipes.is_empty() {
            self.compiled_recipes.clear();
            return Ok(());
        }
        let catalog = RecipeCatalog::with_external_paths(&self.recipe_catalog.paths)
            .map_err(|error| anyhow!(error))?;
        let selections = self
            .recipes
            .iter()
            .map(|(instance, selection)| (instance.clone(), selection.clone()))
            .collect::<Vec<_>>();
        let mut compiled = BTreeMap::new();
        for (instance, selection) in selections {
            NamedRouteBinding::new(instance.clone(), None)
                .map_err(|_| anyhow!("recipes contains an invalid instance ID"))?;
            let package = catalog
                .resolve(&selection.selector)
                .map_err(|error| anyhow!(error))?;
            let recipe = package
                .compile(&selection.values)
                .map_err(|error| anyhow!(error))?;
            self.project_compiled_recipe(&instance, &recipe)?;
            compiled.insert(instance, recipe);
        }
        // A split worker needs the exact same resolved route/profile catalog as
        // its gateways so assignment fingerprints remain identical. Recipe
        // projection builds that catalog through the normal ingress projection,
        // but a worker must never expose the corresponding API or signaling
        // listeners. Keep the derived catalog and disable both public surfaces
        // before semantic and role preflight validation.
        if self.runtime.mode == RuntimeMode::Worker {
            self.api.enabled = false;
            self.generic_bridge.enabled = false;
        }
        self.compiled_recipes = compiled;
        Ok(())
    }

    fn project_compiled_recipe(&mut self, instance: &str, recipe: &CompiledRecipe) -> Result<()> {
        for (bridge_id, bridge) in &recipe.spec.bridges {
            match (&bridge.source, &bridge.destination) {
                (
                    RecipeEndpointSpec::Sip {
                        security,
                        admission,
                        ..
                    },
                    RecipeEndpointSpec::AmazonConnect {
                        instance_arn,
                        contact_flow_id,
                        ..
                    },
                ) => {
                    let admission = recipe_sip_admission(instance, admission.as_ref())?;
                    self.project_sip_amazon_recipe_bridge(
                        instance,
                        bridge_id,
                        recipe,
                        *security,
                        admission,
                        instance_arn,
                        contact_flow_id,
                    )?;
                }
                (RecipeEndpointSpec::Sip { .. }, RecipeEndpointSpec::Webrtc { .. }) => {
                    self.project_sip_webrtc_recipe_bridge(
                        instance,
                        bridge_id,
                        recipe,
                        &bridge.source,
                        &bridge.destination,
                    )?;
                }
                (RecipeEndpointSpec::Webrtc { .. }, RecipeEndpointSpec::Sip { .. }) => {
                    self.project_webrtc_sip_recipe_bridge(
                        instance,
                        bridge_id,
                        recipe,
                        &bridge.source,
                        &bridge.destination,
                    )?;
                }
                (RecipeEndpointSpec::Webrtc { .. }, RecipeEndpointSpec::AmazonConnect { .. }) => {
                    self.project_webrtc_amazon_recipe_bridge(
                        instance,
                        bridge_id,
                        recipe,
                        &bridge.source,
                        &bridge.destination,
                    )?;
                }
                _ => {
                    return Err(anyhow!(
                        "recipe instance {instance:?} bridge {bridge_id:?} is not yet supported by the runtime projector"
                    ));
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn project_sip_amazon_recipe_bridge(
        &mut self,
        instance: &str,
        bridge_id: &str,
        recipe: &CompiledRecipe,
        security: SipSecurity,
        admission: &SipAdmissionSpec,
        instance_arn: &str,
        contact_flow_id: &str,
    ) -> Result<()> {
        let connect_instance_id = connect_instance_id(instance_arn, &self.aws.region)?;
        validate_recipe_public_host(&self.edge.public_host)?;
        let media_public_addr = self
            .edge
            .media_public_addr
            .as_ref()
            .ok_or_else(|| anyhow!("edge.media_public_addr is required by SIP recipes"))?;
        let media_address = media_public_addr
            .parse::<SocketAddr>()
            .map_err(|_| anyhow!("edge.media_public_addr must be a socket address"))?;
        if media_address.ip().is_unspecified() || media_address.port() != 0 {
            return Err(anyhow!(
                "edge.media_public_addr must use a concrete public IP and port zero"
            ));
        }
        if self.generic_bridge.enabled
            && self
                .generic_bridge
                .sip
                .media_public_addr
                .as_ref()
                .is_some_and(|existing| existing != media_public_addr)
        {
            return Err(anyhow!(
                "recipe media address collides with generic_bridge.sip.media_public_addr"
            ));
        }
        self.generic_bridge.sip.media_public_addr = Some(media_public_addr.clone());

        let (sip_uri_template, profile_security, profile_tls, profile_mtls_ca) = match security {
            SipSecurity::SipsSrtp | SipSecurity::SipsOptionalSrtp => {
                let profile_security = recipe_sip_ingress_security(security);
                let srtp_policy = recipe_srtp_policy(security);
                let edge_tls = self
                    .edge
                    .sip_tls
                    .as_ref()
                    .ok_or_else(|| anyhow!("edge.sip_tls is required by a SIPS recipe"))?;
                let tls_bind = edge_tls
                    .bind
                    .parse::<SocketAddr>()
                    .map_err(|_| anyhow!("edge.sip_tls.bind must be a socket address"))?;
                if tls_bind.port() == 0 {
                    return Err(anyhow!("edge.sip_tls.bind must use a nonzero port"));
                }
                let recipe_contact_uri =
                    RecipeSipContactUri::sips_dns(&self.edge.public_host, tls_bind.port())?;
                validate_profile_path(
                    &edge_tls.certificate_chain,
                    "edge.sip_tls.certificate_chain",
                )?;
                validate_secret_reference(&edge_tls.private_key)?;
                let secure_listener = GenericSipSecureListenerCfg {
                    bind: edge_tls.bind.clone(),
                    advertised_addr: edge_tls.advertised_addr.clone(),
                    certificate_chain: edge_tls.certificate_chain.clone(),
                    private_key: edge_tls.private_key.clone(),
                    client_ca_certificate: edge_tls.client_ca_certificate.clone(),
                    require_client_certificate: edge_tls.require_client_certificate,
                };
                match &self.generic_bridge.sip.secure_listener {
                    Some(existing)
                        if existing.bind != secure_listener.bind
                            || existing.advertised_addr != secure_listener.advertised_addr
                            || existing.certificate_chain != secure_listener.certificate_chain
                            || !existing
                                .private_key
                                .same_reference(&secure_listener.private_key)
                            || existing.client_ca_certificate
                                != secure_listener.client_ca_certificate
                            || existing.require_client_certificate
                                != secure_listener.require_client_certificate =>
                    {
                        return Err(anyhow!(
                            "recipe SIPS listener collides with generic_bridge.sip.secure_listener"
                        ));
                    }
                    Some(_) => {}
                    None => self.generic_bridge.sip.secure_listener = Some(secure_listener),
                }
                if self.generic_bridge.sip.srtp != srtp_policy && self.generic_bridge.enabled {
                    return Err(anyhow!(
                        "recipe SIPS posture collides with the configured generic SIP SRTP policy"
                    ));
                }
                self.generic_bridge.sip.srtp = srtp_policy;
                self.generic_bridge.sip.recipe_contact_uri = Some(recipe_contact_uri);
                // The rvoip stack always owns a clear listener. Keep it on
                // loopback/ephemeral in the secure posture so CIDR admission
                // cannot be reused over clear SIP.
                self.generic_bridge.sip_bind = "127.0.0.1:0".to_owned();
                self.generic_bridge.sip.advertised_addr = None;
                (
                    format!(
                        "sips:{{token}}@{}:{};transport=tls",
                        self.edge.public_host,
                        tls_bind.port()
                    ),
                    profile_security,
                    Some(ProfileTlsIdentityCfg {
                        certificate_chain: edge_tls.certificate_chain.clone(),
                        private_key: edge_tls.private_key.clone(),
                    }),
                    edge_tls.client_ca_certificate.iter().cloned().collect(),
                )
            }
            SipSecurity::SipRtp => {
                let edge_rtp = self
                    .edge
                    .sip_rtp
                    .as_ref()
                    .ok_or_else(|| anyhow!("edge.sip_rtp is required by a sip_rtp recipe"))?;
                let bind = edge_rtp
                    .bind
                    .parse::<SocketAddr>()
                    .map_err(|_| anyhow!("edge.sip_rtp.bind must be a socket address"))?;
                if bind.port() == 0 {
                    return Err(anyhow!("edge.sip_rtp.bind must use a nonzero port"));
                }
                if self.generic_bridge.enabled
                    && (self.generic_bridge.sip.secure_listener.is_some()
                        || self.generic_bridge.sip.srtp != ProfileSrtpPolicy::Disabled)
                {
                    return Err(anyhow!(
                        "recipe sip_rtp posture collides with secure generic SIP configuration"
                    ));
                }
                self.generic_bridge.sip.secure_listener = None;
                self.generic_bridge.sip.recipe_contact_uri = None;
                self.generic_bridge.sip.srtp = ProfileSrtpPolicy::Disabled;
                self.generic_bridge.sip_bind = edge_rtp.bind.clone();
                self.generic_bridge.sip.advertised_addr = edge_rtp.advertised_addr.clone();
                (
                    format!("sip:{{token}}@{}:{}", self.edge.public_host, bind.port()),
                    SipIngressSecurity::SipRtp,
                    None,
                    Vec::new(),
                )
            }
        };
        self.generic_bridge.enabled = true;
        match &self.api.route_attachments.sip_uri_template {
            Some(existing) if existing != &sip_uri_template => {
                return Err(anyhow!(
                    "recipe SIP attachment URI collides with api.route_attachments.sip_uri_template"
                ));
            }
            Some(_) => {}
            None => self.api.route_attachments.sip_uri_template = Some(sip_uri_template),
        }
        self.api.enabled = true;

        let route_id = if recipe.spec.bridges.len() == 1 {
            instance.to_owned()
        } else {
            format!("{instance}-{bridge_id}")
        };
        NamedRouteBinding::new(route_id.clone(), None)
            .map_err(|_| anyhow!("compiled recipe route ID is invalid"))?;
        if self.api.routes.contains_key(&route_id) {
            return Err(anyhow!(
                "recipe route {route_id:?} collides with an explicit api.routes entry"
            ));
        }
        if self.tenants.contains_key(instance) {
            return Err(anyhow!(
                "recipe tenant {instance:?} collides with an explicit tenants entry"
            ));
        }

        let ingress_profile_id = format!("recipe-{instance}-sip-ingress");
        let amazon_profile_id = format!("recipe-{instance}-amazon");
        validate_named_profile_id_for_config(&ingress_profile_id, NamedProfileKind::SipIngress)?;
        if self.sip_ingress_profiles.contains_key(&ingress_profile_id) {
            return Err(anyhow!("compiled recipe ingress profile collides"));
        }
        let ingress_profile = SipIngressProfileCfg {
            tenant_id: instance.to_owned(),
            principal_subject: format!("bridgefu-recipe:{instance}"),
            issuer: "bridgefu:recipe-catalog".to_owned(),
            scopes: BTreeSet::from(["calls:create".to_owned(), "sip:connect".to_owned()]),
            trusted_signaling_cidrs: admission.trusted_cidrs.clone(),
            security: profile_security,
            tls: profile_tls,
            digest: None,
            mtls_peer_ca_certificates: profile_mtls_ca,
            mtls_leaf_certificate_sha256_fingerprints: Vec::new(),
            codecs: BTreeSet::from([
                ProfileAudioCodec::Pcmu,
                ProfileAudioCodec::Pcma,
                ProfileAudioCodec::Opus,
            ]),
        };
        if !ingress_profile.mtls_peer_ca_certificates.is_empty() {
            return Err(anyhow!(
                "recipe mTLS client CA requires explicit verified leaf fingerprints; omit edge.sip_tls.client_ca_certificate for CIDR admission"
            ));
        }
        self.sip_ingress_profiles
            .insert(ingress_profile_id.clone(), ingress_profile);

        let mut attributes = BTreeMap::new();
        attributes.insert("bridgefu_recipe".to_owned(), recipe.name.clone());
        attributes.insert(
            "bridgefu_recipe_version".to_owned(),
            recipe.version.to_string(),
        );
        let start = AmazonConnectStartSpec::new(
            amazon_profile_id.clone(),
            connect_instance_id.clone(),
            contact_flow_id.to_owned(),
            attributes,
            "Bridgefu handoff",
            None,
        )?;
        let destination = RequestedLeg {
            direction: LegDirection::Outbound,
            signaling_initiator: Some(SignalingInitiator::Bridgefu),
            media_flow: MediaFlow::SendReceive,
            endpoint: LegEndpointConfig::AmazonConnect(AmazonConnectEndpointConfig {
                instance_id: connect_instance_id.clone(),
                contact_flow_id: contact_flow_id.to_owned(),
            }),
            amazon_connect_start: Some(start),
        };
        self.api.routes.insert(
            route_id,
            NamedRouteCfg {
                tenant_id: instance.to_owned(),
                ingress: BTreeSet::from([NamedRouteIngress::Sip]),
                destination,
                vapi_ingress_profile: None,
                sip_ingress_profile: Some(ingress_profile_id),
                required_sip_correlation_header: Some("X-Correlation-Id".to_owned()),
                recipe_sip_admission: Some(admission.clone()),
                webrtc_ingress_profile: None,
                destination_profile: Some(RouteDestinationProfileRef::AmazonConnect {
                    profile_id: amazon_profile_id,
                }),
                legacy_embedded_destination: false,
                profile_bindings: Vec::new(),
                context_metadata_allowlist: None,
                context_required: false,
                capability_policy: NamedRouteCapabilityPolicy::default(),
            },
        );

        let mapping = MappingCfg {
            unmapped: "drop".to_owned(),
            passthrough_prefix: "X-".to_owned(),
            rename: BTreeMap::from([("X-Correlation-Id".to_owned(), "correlation_id".to_owned())]),
        };
        self.tenants.insert(
            instance.to_owned(),
            TenantCfg {
                instance_id: connect_instance_id,
                contact_flow_id: contact_flow_id.to_owned(),
                routing_only: false,
                default_display_name: Some("Bridgefu handoff".to_owned()),
                mapping: Some(mapping),
            },
        );
        if let Some(existing) = self.context.allow_headers.get("X-Correlation-Id") {
            if existing != "correlation_id" {
                return Err(anyhow!(
                    "recipe correlation mapping collides with context.allow_headers"
                ));
            }
        } else {
            self.context
                .allow_headers
                .insert("X-Correlation-Id".to_owned(), "correlation_id".to_owned());
        }
        match &self.api.static_tenant {
            Some(existing) if existing != instance => {
                return Err(anyhow!(
                    "recipe tenant collides with api.static_tenant; use separate processes for multiple SIP listener tenants"
                ));
            }
            Some(_) => {}
            None => self.api.static_tenant = Some(instance.to_owned()),
        }
        if self.default_tenant.is_none() {
            self.default_tenant = Some(instance.to_owned());
        }
        Ok(())
    }

    fn project_sip_webrtc_recipe_bridge(
        &mut self,
        instance: &str,
        bridge_id: &str,
        recipe: &CompiledRecipe,
        source: &RecipeEndpointSpec,
        destination: &RecipeEndpointSpec,
    ) -> Result<()> {
        let RecipeEndpointSpec::Sip {
            security,
            admission,
            codecs: source_codecs,
            ..
        } = source
        else {
            return Err(anyhow!(
                "recipe SIP source projection received another endpoint"
            ));
        };
        let RecipeEndpointSpec::Webrtc {
            signaling_uri,
            bearer_token_ref,
            tls_roots,
            codecs,
            data_channels,
        } = destination
        else {
            return Err(anyhow!(
                "recipe WebRTC destination projection received another endpoint"
            ));
        };
        let admission = recipe_sip_admission(instance, admission.as_ref())?;
        let signaling_uri = signaling_uri
            .as_deref()
            .ok_or_else(|| anyhow!("recipe WebRTC destination is missing signaling_uri"))?;
        let route_id = recipe_route_id(instance, bridge_id, recipe)?;
        self.ensure_recipe_route_available(instance, &route_id)?;
        self.generic_bridge.webrtc_ws_bind = "127.0.0.1:0".to_owned();
        self.generic_bridge.webrtc_whip_bind = "127.0.0.1:0".to_owned();
        let ingress_profile_id = self.project_generic_recipe_sip_ingress(
            instance,
            &route_id,
            *security,
            &admission.trusted_cidrs,
            source_codecs,
        )?;
        let destination_profile_id = format!("recipe-{route_id}-webrtc-destination");
        validate_named_profile_id_for_config(&destination_profile_id, NamedProfileKind::WebRtc)?;
        if self.webrtc_profiles.contains_key(&destination_profile_id) {
            return Err(anyhow!("compiled recipe WebRTC profile collides"));
        }
        self.webrtc_profiles.insert(
            destination_profile_id.clone(),
            WebRtcProfileCfg {
                allowed_signaling_origins: BTreeSet::from([normalized_wss_origin(signaling_uri)?]),
                bearer_token: bearer_token_ref
                    .as_ref()
                    .map(|token| SecretRef::new(token.clone())),
                tls_roots: tls_roots.clone(),
                ice_servers: Vec::new(),
                codecs: recipe_profile_codecs(codecs),
                data_channels: *data_channels,
            },
        );
        let destination = RequestedLeg {
            direction: LegDirection::Outbound,
            signaling_initiator: Some(SignalingInitiator::Bridgefu),
            media_flow: MediaFlow::SendReceive,
            endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                signaling_uri: Some(signaling_uri.to_owned()),
            }),
            amazon_connect_start: None,
        };
        self.api.routes.insert(
            route_id,
            NamedRouteCfg {
                tenant_id: instance.to_owned(),
                ingress: BTreeSet::from([NamedRouteIngress::Sip]),
                destination,
                vapi_ingress_profile: None,
                sip_ingress_profile: Some(ingress_profile_id),
                required_sip_correlation_header: None,
                recipe_sip_admission: Some(admission.clone()),
                webrtc_ingress_profile: None,
                destination_profile: Some(RouteDestinationProfileRef::Webrtc {
                    profile_id: destination_profile_id,
                }),
                legacy_embedded_destination: false,
                profile_bindings: Vec::new(),
                context_metadata_allowlist: None,
                context_required: false,
                capability_policy: NamedRouteCapabilityPolicy::default(),
            },
        );
        self.finish_generic_recipe_route(instance)
    }

    fn project_webrtc_sip_recipe_bridge(
        &mut self,
        instance: &str,
        bridge_id: &str,
        recipe: &CompiledRecipe,
        source: &RecipeEndpointSpec,
        destination: &RecipeEndpointSpec,
    ) -> Result<()> {
        let RecipeEndpointSpec::Webrtc {
            signaling_uri: source_signaling_uri,
            codecs: source_codecs,
            data_channels: source_data_channels,
            ..
        } = source
        else {
            return Err(anyhow!(
                "recipe WebRTC source projection received another endpoint"
            ));
        };
        let RecipeEndpointSpec::Sip {
            security,
            target_uri,
            from_uri,
            outbound_proxy,
            auth,
            tls_roots,
            codecs,
            metadata_keys,
            ..
        } = destination
        else {
            return Err(anyhow!(
                "recipe SIP destination projection received another endpoint"
            ));
        };
        let source_signaling_uri = source_signaling_uri
            .as_deref()
            .ok_or_else(|| anyhow!("recipe WebRTC source is missing signaling_uri"))?;
        let target_uri = target_uri
            .as_deref()
            .ok_or_else(|| anyhow!("recipe SIP destination is missing target_uri"))?;
        let from_uri = from_uri
            .as_deref()
            .ok_or_else(|| anyhow!("recipe SIP destination is missing from_uri"))?;
        let route_id = recipe_route_id(instance, bridge_id, recipe)?;
        self.ensure_recipe_route_available(instance, &route_id)?;
        if self.api.tls.is_none() {
            return Err(anyhow!(
                "api.tls is required by WebRTC source recipes so the advertised WSS attachment is real"
            ));
        }
        self.generic_bridge.sip_bind = "127.0.0.1:0".to_owned();
        self.generic_bridge.webrtc_whip_bind = "127.0.0.1:0".to_owned();
        let ingress_profile_id = self.project_recipe_webrtc_ingress(
            &route_id,
            source_signaling_uri,
            source_codecs,
            *source_data_channels,
        )?;
        let destination_profile_id = format!("recipe-{route_id}-sip-destination");
        validate_named_profile_id_for_config(&destination_profile_id, NamedProfileKind::Sip)?;
        if self.sip_profiles.contains_key(&destination_profile_id) {
            return Err(anyhow!("compiled recipe SIP destination profile collides"));
        }
        let media_public_addr = self
            .edge
            .media_public_addr
            .as_ref()
            .ok_or_else(|| anyhow!("edge.media_public_addr is required by SIP recipes"))?;
        let media_address = media_public_addr
            .parse::<SocketAddr>()
            .map_err(|_| anyhow!("edge.media_public_addr must be a socket address"))?;
        if media_address.ip().is_unspecified() || media_address.port() != 0 {
            return Err(anyhow!(
                "edge.media_public_addr must use a concrete public IP and port zero"
            ));
        }
        if self
            .generic_bridge
            .sip
            .media_public_addr
            .as_ref()
            .is_some_and(|existing| existing != media_public_addr)
        {
            return Err(anyhow!(
                "recipe media address collides with generic_bridge.sip.media_public_addr"
            ));
        }
        self.generic_bridge.sip.media_public_addr = Some(media_public_addr.clone());
        let auth = match auth {
            Some(RecipeSipAuthSpec::Digest {
                realm,
                username: Some(username),
                password_ref: Some(password),
            }) => Some(SipProfileAuthCfg::Digest {
                realm: realm.clone(),
                username: username.clone(),
                password: SecretRef::new(password.clone()),
            }),
            Some(RecipeSipAuthSpec::Bearer {
                token_ref: Some(token),
            }) => Some(SipProfileAuthCfg::Bearer {
                token: SecretRef::new(token.clone()),
            }),
            _ => None,
        };
        self.sip_profiles.insert(
            destination_profile_id.clone(),
            SipProfileCfg {
                allowed_targets: BTreeSet::from([target_uri.to_owned()]),
                from_uri: from_uri.to_owned(),
                outbound_proxy: outbound_proxy.clone(),
                auth,
                tls_roots: tls_roots.clone(),
                client_certificate: None,
                srtp: recipe_srtp_policy(*security),
                codecs: recipe_profile_codecs(codecs),
                metadata_keys: metadata_keys.clone(),
            },
        );
        for key in metadata_keys {
            if key == "correlation_id" {
                self.ensure_recipe_correlation_mapping()?;
            }
        }
        let destination = RequestedLeg {
            direction: LegDirection::Outbound,
            signaling_initiator: Some(SignalingInitiator::Bridgefu),
            media_flow: MediaFlow::SendReceive,
            endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                uri: Some(target_uri.to_owned()),
                initial_context: if metadata_keys.is_empty() {
                    SipInitialContextMode::None
                } else {
                    SipInitialContextMode::Required
                },
            }),
            amazon_connect_start: None,
        };
        self.api.routes.insert(
            route_id,
            NamedRouteCfg {
                tenant_id: instance.to_owned(),
                ingress: BTreeSet::from([NamedRouteIngress::Webrtc]),
                destination,
                vapi_ingress_profile: None,
                sip_ingress_profile: None,
                required_sip_correlation_header: None,
                recipe_sip_admission: None,
                webrtc_ingress_profile: Some(ingress_profile_id),
                destination_profile: Some(RouteDestinationProfileRef::Sip {
                    profile_id: destination_profile_id,
                }),
                legacy_embedded_destination: false,
                profile_bindings: Vec::new(),
                context_metadata_allowlist: None,
                context_required: !metadata_keys.is_empty(),
                capability_policy: NamedRouteCapabilityPolicy::default(),
            },
        );
        self.finish_generic_recipe_route(instance)
    }

    fn project_webrtc_amazon_recipe_bridge(
        &mut self,
        instance: &str,
        bridge_id: &str,
        recipe: &CompiledRecipe,
        source: &RecipeEndpointSpec,
        destination: &RecipeEndpointSpec,
    ) -> Result<()> {
        let RecipeEndpointSpec::Webrtc {
            signaling_uri,
            codecs,
            data_channels,
            ..
        } = source
        else {
            return Err(anyhow!(
                "recipe WebRTC source projection received another endpoint"
            ));
        };
        let RecipeEndpointSpec::AmazonConnect {
            instance_arn,
            contact_flow_id,
            context_metadata_keys,
            ..
        } = destination
        else {
            return Err(anyhow!(
                "recipe Amazon Connect projection received another endpoint"
            ));
        };
        let signaling_uri = signaling_uri
            .as_deref()
            .ok_or_else(|| anyhow!("recipe WebRTC source is missing signaling_uri"))?;
        let connect_instance_id = connect_instance_id(instance_arn, &self.aws.region)?;
        let route_id = recipe_route_id(instance, bridge_id, recipe)?;
        self.ensure_recipe_route_available(instance, &route_id)?;
        if self.api.tls.is_none() {
            return Err(anyhow!(
                "api.tls is required by WebRTC source recipes so the advertised WSS attachment is real"
            ));
        }
        self.generic_bridge.sip_bind = "127.0.0.1:0".to_owned();
        self.generic_bridge.webrtc_whip_bind = "127.0.0.1:0".to_owned();
        let ingress_profile_id =
            self.project_recipe_webrtc_ingress(&route_id, signaling_uri, codecs, *data_channels)?;
        for key in context_metadata_keys {
            self.context.allow_metadata_keys.insert(key.clone());
        }

        let amazon_profile_id = format!("recipe-{route_id}-amazon");
        let attributes = BTreeMap::from([
            ("bridgefu_recipe".to_owned(), recipe.name.clone()),
            (
                "bridgefu_recipe_version".to_owned(),
                recipe.version.to_string(),
            ),
        ]);
        let start = AmazonConnectStartSpec::new(
            amazon_profile_id.clone(),
            connect_instance_id.clone(),
            contact_flow_id.clone(),
            attributes,
            "Bridgefu WebRTC handoff",
            None,
        )?;
        let destination = RequestedLeg {
            direction: LegDirection::Outbound,
            signaling_initiator: Some(SignalingInitiator::Bridgefu),
            media_flow: MediaFlow::SendReceive,
            endpoint: LegEndpointConfig::AmazonConnect(AmazonConnectEndpointConfig {
                instance_id: connect_instance_id.clone(),
                contact_flow_id: contact_flow_id.clone(),
            }),
            amazon_connect_start: Some(start),
        };
        self.api.routes.insert(
            route_id,
            NamedRouteCfg {
                tenant_id: instance.to_owned(),
                ingress: BTreeSet::from([NamedRouteIngress::Webrtc]),
                destination,
                vapi_ingress_profile: None,
                sip_ingress_profile: None,
                required_sip_correlation_header: None,
                recipe_sip_admission: None,
                webrtc_ingress_profile: Some(ingress_profile_id),
                destination_profile: Some(RouteDestinationProfileRef::AmazonConnect {
                    profile_id: amazon_profile_id,
                }),
                legacy_embedded_destination: false,
                profile_bindings: Vec::new(),
                context_metadata_allowlist: Some(context_metadata_keys.clone()),
                context_required: recipe
                    .spec
                    .bridges
                    .get(bridge_id)
                    .and_then(|bridge| bridge.context.as_ref())
                    .is_some_and(|context| context.correlation.required),
                capability_policy: NamedRouteCapabilityPolicy::default(),
            },
        );
        self.tenants.insert(
            instance.to_owned(),
            TenantCfg {
                instance_id: connect_instance_id,
                contact_flow_id: contact_flow_id.clone(),
                routing_only: false,
                default_display_name: Some("Bridgefu WebRTC handoff".to_owned()),
                mapping: Some(MappingCfg {
                    unmapped: "drop".to_owned(),
                    passthrough_prefix: "X-".to_owned(),
                    rename: self.context.allow_headers.clone(),
                }),
            },
        );
        match &self.api.static_tenant {
            Some(existing) if existing != instance => {
                return Err(anyhow!(
                    "recipe tenant collides with api.static_tenant; use separate processes for multiple recipe tenants"
                ));
            }
            Some(_) => {}
            None => self.api.static_tenant = Some(instance.to_owned()),
        }
        if self.default_tenant.is_none() {
            self.default_tenant = Some(instance.to_owned());
        }
        Ok(())
    }

    fn project_generic_recipe_sip_ingress(
        &mut self,
        instance: &str,
        route_id: &str,
        security: SipSecurity,
        trusted_cidrs: &[String],
        codecs: &BTreeSet<RecipeAudioCodec>,
    ) -> Result<String> {
        validate_recipe_public_host(&self.edge.public_host)?;
        let media_public_addr = self
            .edge
            .media_public_addr
            .as_ref()
            .ok_or_else(|| anyhow!("edge.media_public_addr is required by SIP recipes"))?;
        let media_address = media_public_addr
            .parse::<SocketAddr>()
            .map_err(|_| anyhow!("edge.media_public_addr must be a socket address"))?;
        if media_address.ip().is_unspecified() || media_address.port() != 0 {
            return Err(anyhow!(
                "edge.media_public_addr must use a concrete public IP and port zero"
            ));
        }
        if self.generic_bridge.enabled
            && self
                .generic_bridge
                .sip
                .media_public_addr
                .as_ref()
                .is_some_and(|existing| existing != media_public_addr)
        {
            return Err(anyhow!(
                "recipe media address collides with generic_bridge.sip.media_public_addr"
            ));
        }
        self.generic_bridge.sip.media_public_addr = Some(media_public_addr.clone());

        let (sip_uri_template, profile_security, profile_tls) = match security {
            SipSecurity::SipsSrtp | SipSecurity::SipsOptionalSrtp => {
                let profile_security = recipe_sip_ingress_security(security);
                let srtp_policy = recipe_srtp_policy(security);
                let edge_tls = self
                    .edge
                    .sip_tls
                    .as_ref()
                    .ok_or_else(|| anyhow!("edge.sip_tls is required by a SIPS recipe"))?;
                let tls_bind = edge_tls
                    .bind
                    .parse::<SocketAddr>()
                    .map_err(|_| anyhow!("edge.sip_tls.bind must be a socket address"))?;
                if tls_bind.port() == 0 {
                    return Err(anyhow!("edge.sip_tls.bind must use a nonzero port"));
                }
                let recipe_contact_uri =
                    RecipeSipContactUri::sips_dns(&self.edge.public_host, tls_bind.port())?;
                if edge_tls.client_ca_certificate.is_some() {
                    return Err(anyhow!(
                        "recipe CIDR admission cannot assign identity from a client CA; use an explicit expert mTLS profile"
                    ));
                }
                let secure_listener = GenericSipSecureListenerCfg {
                    bind: edge_tls.bind.clone(),
                    advertised_addr: edge_tls.advertised_addr.clone(),
                    certificate_chain: edge_tls.certificate_chain.clone(),
                    private_key: edge_tls.private_key.clone(),
                    client_ca_certificate: None,
                    require_client_certificate: false,
                };
                match &self.generic_bridge.sip.secure_listener {
                    Some(existing)
                        if existing.bind != secure_listener.bind
                            || existing.advertised_addr != secure_listener.advertised_addr
                            || existing.certificate_chain != secure_listener.certificate_chain
                            || !existing
                                .private_key
                                .same_reference(&secure_listener.private_key) =>
                    {
                        return Err(anyhow!(
                            "recipe SIPS listener collides with generic_bridge.sip.secure_listener"
                        ));
                    }
                    Some(_) => {}
                    None => self.generic_bridge.sip.secure_listener = Some(secure_listener),
                }
                if self.generic_bridge.enabled && self.generic_bridge.sip.srtp != srtp_policy {
                    return Err(anyhow!(
                        "recipe SIPS posture collides with the configured generic SIP SRTP policy"
                    ));
                }
                self.generic_bridge.sip.srtp = srtp_policy;
                self.generic_bridge.sip.recipe_contact_uri = Some(recipe_contact_uri);
                self.generic_bridge.sip_bind = "127.0.0.1:0".to_owned();
                self.generic_bridge.sip.advertised_addr = None;
                (
                    format!(
                        "sips:{{token}}@{}:{};transport=tls",
                        self.edge.public_host,
                        tls_bind.port()
                    ),
                    profile_security,
                    Some(ProfileTlsIdentityCfg {
                        certificate_chain: edge_tls.certificate_chain.clone(),
                        private_key: edge_tls.private_key.clone(),
                    }),
                )
            }
            SipSecurity::SipRtp => {
                let edge_rtp = self
                    .edge
                    .sip_rtp
                    .as_ref()
                    .ok_or_else(|| anyhow!("edge.sip_rtp is required by a sip_rtp recipe"))?;
                let bind = edge_rtp
                    .bind
                    .parse::<SocketAddr>()
                    .map_err(|_| anyhow!("edge.sip_rtp.bind must be a socket address"))?;
                if bind.port() == 0 {
                    return Err(anyhow!("edge.sip_rtp.bind must use a nonzero port"));
                }
                if self.generic_bridge.enabled
                    && (self.generic_bridge.sip.secure_listener.is_some()
                        || self.generic_bridge.sip.srtp != ProfileSrtpPolicy::Disabled)
                {
                    return Err(anyhow!(
                        "recipe sip_rtp posture collides with secure generic SIP configuration"
                    ));
                }
                self.generic_bridge.sip.secure_listener = None;
                self.generic_bridge.sip.recipe_contact_uri = None;
                self.generic_bridge.sip.srtp = ProfileSrtpPolicy::Disabled;
                self.generic_bridge.sip_bind = edge_rtp.bind.clone();
                self.generic_bridge.sip.advertised_addr = edge_rtp.advertised_addr.clone();
                (
                    format!("sip:{{token}}@{}:{}", self.edge.public_host, bind.port()),
                    SipIngressSecurity::SipRtp,
                    None,
                )
            }
        };
        self.generic_bridge.enabled = true;
        self.api.enabled = true;
        match &self.api.route_attachments.sip_uri_template {
            Some(existing) if existing != &sip_uri_template => {
                return Err(anyhow!(
                    "recipe SIP attachment URI collides with api.route_attachments.sip_uri_template"
                ));
            }
            Some(_) => {}
            None => self.api.route_attachments.sip_uri_template = Some(sip_uri_template),
        }
        self.ensure_recipe_correlation_mapping()?;

        let profile_id = format!("recipe-{route_id}-sip-ingress");
        validate_named_profile_id_for_config(&profile_id, NamedProfileKind::SipIngress)?;
        if self.sip_ingress_profiles.contains_key(&profile_id) {
            return Err(anyhow!("compiled recipe SIP ingress profile collides"));
        }
        self.sip_ingress_profiles.insert(
            profile_id.clone(),
            SipIngressProfileCfg {
                tenant_id: instance.to_owned(),
                principal_subject: format!("bridgefu-recipe:{instance}"),
                issuer: "bridgefu:recipe-catalog".to_owned(),
                scopes: BTreeSet::from(["calls:create".to_owned(), "sip:connect".to_owned()]),
                trusted_signaling_cidrs: trusted_cidrs.to_vec(),
                security: profile_security,
                tls: profile_tls,
                digest: None,
                mtls_peer_ca_certificates: Vec::new(),
                mtls_leaf_certificate_sha256_fingerprints: Vec::new(),
                codecs: recipe_profile_codecs(codecs),
            },
        );
        Ok(profile_id)
    }

    fn project_recipe_webrtc_ingress(
        &mut self,
        route_id: &str,
        signaling_uri: &str,
        codecs: &BTreeSet<RecipeAudioCodec>,
        data_channels: bool,
    ) -> Result<String> {
        let attachment = RouteWebRtcAttachmentCfg {
            signaling_uri: signaling_uri.to_owned(),
            ice_servers: Vec::new(),
        };
        match &self.api.route_attachments.webrtc {
            Some(existing) if existing.signaling_uri != attachment.signaling_uri => {
                return Err(anyhow!(
                    "recipe WebRTC attachment collides with api.route_attachments.webrtc"
                ));
            }
            Some(_) => {}
            None => self.api.route_attachments.webrtc = Some(attachment),
        }
        let public_media = self
            .edge
            .media_public_addr
            .as_ref()
            .ok_or_else(|| anyhow!("edge.media_public_addr is required by WebRTC recipes"))?
            .parse::<SocketAddr>()
            .map_err(|_| anyhow!("edge.media_public_addr must be a socket address"))?;
        if public_media.ip().is_unspecified() || public_media.port() != 0 {
            return Err(anyhow!(
                "edge.media_public_addr must use a concrete public IP and port zero"
            ));
        }
        let public_ip = public_media.ip().to_string();
        if !self.generic_bridge.webrtc.nat_1to1_ips.is_empty()
            && self.generic_bridge.webrtc.nat_1to1_ips != [public_ip.clone()]
        {
            return Err(anyhow!(
                "recipe WebRTC public IP collides with generic_bridge.webrtc.nat_1to1_ips"
            ));
        }
        self.generic_bridge.webrtc.nat_1to1_ips = vec![public_ip];
        self.generic_bridge.webrtc.audio_codecs = recipe_generic_webrtc_codecs(codecs);
        self.generic_bridge.enabled = true;
        self.api.enabled = true;

        let profile_id = format!("recipe-{route_id}-webrtc-ingress");
        validate_named_profile_id_for_config(&profile_id, NamedProfileKind::WebRtc)?;
        if self.webrtc_profiles.contains_key(&profile_id) {
            return Err(anyhow!("compiled recipe WebRTC ingress profile collides"));
        }
        self.webrtc_profiles.insert(
            profile_id.clone(),
            WebRtcProfileCfg {
                allowed_signaling_origins: BTreeSet::from([normalized_wss_origin(signaling_uri)?]),
                bearer_token: None,
                tls_roots: Vec::new(),
                ice_servers: Vec::new(),
                codecs: recipe_profile_codecs(codecs),
                data_channels,
            },
        );
        Ok(profile_id)
    }

    fn ensure_recipe_route_available(&self, instance: &str, route_id: &str) -> Result<()> {
        if self.api.routes.contains_key(route_id) {
            return Err(anyhow!(
                "recipe route {route_id:?} collides with an explicit api.routes entry"
            ));
        }
        if self.tenants.contains_key(instance) {
            return Err(anyhow!(
                "recipe tenant {instance:?} collides with an explicit tenants entry"
            ));
        }
        Ok(())
    }

    fn finish_generic_recipe_route(&mut self, instance: &str) -> Result<()> {
        self.tenants.insert(
            instance.to_owned(),
            TenantCfg {
                instance_id: String::new(),
                contact_flow_id: String::new(),
                routing_only: true,
                default_display_name: Some("Bridgefu bridge".to_owned()),
                mapping: Some(MappingCfg {
                    unmapped: "drop".to_owned(),
                    passthrough_prefix: "X-".to_owned(),
                    rename: BTreeMap::from([(
                        "X-Correlation-Id".to_owned(),
                        "correlation_id".to_owned(),
                    )]),
                }),
            },
        );
        match &self.api.static_tenant {
            Some(existing) if existing != instance => {
                return Err(anyhow!(
                    "recipe tenant collides with api.static_tenant; use separate processes for multiple recipe tenants"
                ));
            }
            Some(_) => {}
            None => self.api.static_tenant = Some(instance.to_owned()),
        }
        if self.default_tenant.is_none() {
            self.default_tenant = Some(instance.to_owned());
        }
        Ok(())
    }

    fn ensure_recipe_correlation_mapping(&mut self) -> Result<()> {
        match self.context.allow_headers.get("X-Correlation-Id") {
            Some(existing) if existing != "correlation_id" => Err(anyhow!(
                "recipe correlation mapping collides with context.allow_headers"
            )),
            Some(_) => Ok(()),
            None => {
                self.context
                    .allow_headers
                    .insert("X-Correlation-Id".to_owned(), "correlation_id".to_owned());
                Ok(())
            }
        }
    }

    /// Effective YAML after `BRIDGEFU__SECTION__KEY` environment overrides,
    /// with credential-bearing values replaced by `[redacted]`.
    pub fn redacted_effective_yaml(path: &std::path::Path) -> Result<String> {
        let mut value = effective_value(path)?;
        // Keep this command useful during secret provisioning: validate the
        // complete typed shape and reject unknown keys, but do not run the
        // semantic preflight that resolves `env:...` secret references.
        let _ = deserialize_strict(&value, path)?;
        redact_secrets(&mut value);
        serde_yaml::to_string(&value).context("serializing effective configuration")
    }

    pub fn validate(&self) -> Result<()> {
        if self.config_version != 1 {
            return Err(anyhow!(
                "unsupported config_version {}",
                self.config_version
            ));
        }
        let amazon_runtime_configured = self.legacy_vapi_connect_enabled()
            || self.api.routes.values().any(|route| {
                matches!(
                    route.destination.endpoint,
                    LegEndpointConfig::AmazonConnect(_)
                )
            });
        if amazon_runtime_configured && self.aws.region.is_empty() {
            return Err(anyhow!(
                "aws.region must not be empty when Amazon Connect is configured"
            ));
        }
        if self.legacy_vapi_connect_enabled() && self.sip.port == 0 {
            return Err(anyhow!("sip.port must be greater than zero"));
        }
        if !self.recipes.is_empty() && self.compiled_recipes.len() != self.recipes.len() {
            return Err(anyhow!(
                "recipe configurations must be loaded through Config::load before validation"
            ));
        }
        if self.contact.signaling_timeout_secs == 0
            || self.contact.media_connect_timeout_secs == 0
            || self.contact.keepalive_interval_secs == 0
            || self.contact.session_idle_ttl_secs == 0
        {
            return Err(anyhow!(
                "contact timeout and interval values must be greater than zero"
            ));
        }
        if self.runtime.max_concurrent_calls == 0 {
            return Err(anyhow!(
                "runtime.max_concurrent_calls must be greater than zero"
            ));
        }
        if self.runtime.setup_timeout_secs == 0 {
            return Err(anyhow!(
                "runtime.setup_timeout_secs must be greater than zero"
            ));
        }
        if self.runtime.media_idle_timeout_secs == 0 {
            return Err(anyhow!(
                "runtime.media_idle_timeout_secs must be greater than zero"
            ));
        }
        if self.runtime.drain_timeout_secs == 0 {
            return Err(anyhow!(
                "runtime.drain_timeout_secs must be greater than zero"
            ));
        }
        if self.observability.log_level.is_empty() {
            return Err(anyhow!("observability.log_level must not be empty"));
        }
        if !matches!(self.observability.log_format.as_str(), "json" | "pretty") {
            return Err(anyhow!("observability.log_format must be json or pretty"));
        }
        let observability_bind = self
            .observability
            .http_bind
            .parse::<SocketAddr>()
            .map_err(|_| anyhow!("observability.http_bind must be a socket address"))?;
        self.observability.otlp.validate()?;
        match (self.runtime.mode, self.api.http_bind.as_deref()) {
            (RuntimeMode::Gateway, Some(bind)) => {
                let bind = bind
                    .parse::<SocketAddr>()
                    .map_err(|_| anyhow!("api.http_bind must be a socket address"))?;
                if bind.port() == 0 {
                    return Err(anyhow!("gateway api.http_bind must use a nonzero port"));
                }
                if bind == observability_bind {
                    return Err(anyhow!(
                        "gateway api.http_bind must differ from observability.http_bind"
                    ));
                }
                if let Some(tls) = &self.api.tls {
                    tls.validate()?;
                } else if !bind.ip().is_loopback() {
                    return Err(anyhow!(
                        "non-loopback gateway api.http_bind requires api.tls"
                    ));
                }
            }
            (RuntimeMode::Gateway, None) => {
                return Err(anyhow!("gateway mode requires api.http_bind"));
            }
            (_, Some(_)) => {
                return Err(anyhow!(
                    "api.http_bind is currently supported only in gateway mode"
                ));
            }
            (_, None) => {}
        }
        if self.runtime.mode != RuntimeMode::Gateway {
            if let Some(tls) = &self.api.tls {
                if self.recipes.is_empty() || !self.generic_bridge.enabled {
                    return Err(anyhow!(
                        "api.tls outside gateway mode is reserved for recipe-projected WebRTC signaling"
                    ));
                }
                tls.validate()?;
            }
        }
        self.api.rate_limit.validate()?;
        self.validate_named_profiles()?;
        self.validate_named_routes()?;
        if self.generic_bridge.bearer_token.is_some() {
            return Err(anyhow!(
                "generic_bridge.bearer_token is no longer supported; use api.bearer_token so HTTP, SIP, and WebRTC share one validator"
            ));
        }
        self.generic_bridge.validate_networking()?;
        if let Some(range) = &self.generic_bridge.webrtc.udp_port_range {
            let available = usize::from(range.port_end)
                .checked_sub(usize::from(range.port_start))
                .and_then(|width| width.checked_add(1))
                .ok_or_else(|| anyhow!("generic WebRTC UDP port range capacity overflow"))?;
            let required = self
                .runtime
                .max_concurrent_calls
                .checked_mul(2)
                .ok_or_else(|| anyhow!("generic WebRTC UDP port requirement overflow"))?;
            if available < required {
                return Err(anyhow!(
                    "generic_bridge.webrtc.udp_port_range provides {available} ports but runtime.max_concurrent_calls requires at least {required} for browser and Amazon Connect peers"
                ));
            }
        }
        if let (Some(generic), Some(telnyx)) = (
            self.generic_bridge.sip.digest.as_ref(),
            self.providers.telnyx.as_ref(),
        ) {
            if generic.realm != telnyx.media_sip_realm {
                return Err(anyhow!(
                    "generic and Telnyx SIP Digest identities must use one exact shared realm"
                ));
            }
            if generic.username == telnyx.media_sip_username {
                return Err(anyhow!(
                    "generic and Telnyx SIP Digest identities must use distinct usernames"
                ));
            }
        }
        self.validate_reference_tenant_canary()?;
        if self.generic_bridge.enabled
            && (!self.api.enabled
                || self.api.bearer_token.is_none()
                || self.api.control_hmac_key.is_none())
        {
            return Err(anyhow!(
                "generic_bridge requires api.enabled, api.bearer_token, and api.control_hmac_key"
            ));
        }
        if self.runtime.mode == RuntimeMode::Gateway && !self.generic_bridge.enabled {
            return Err(anyhow!(
                "gateway mode requires generic_bridge.enabled for native SIP/WebRTC ingress"
            ));
        }
        if self.generic_bridge.enabled && self.runtime.setup_timeout_secs > 30 {
            return Err(anyhow!(
                "generic_bridge requires runtime.setup_timeout_secs at or below 30"
            ));
        }
        if self.runtime.mode == RuntimeMode::Gateway {
            let public_webrtc = [
                self.generic_bridge.webrtc_ws_bind.as_str(),
                self.generic_bridge.webrtc_whip_bind.as_str(),
            ]
            .into_iter()
            .filter_map(|bind| bind.parse::<SocketAddr>().ok())
            .any(|bind| !bind.ip().is_loopback());
            if public_webrtc && self.api.tls.is_none() {
                return Err(anyhow!(
                    "non-loopback gateway WebRTC signaling requires api.tls for WSS and HTTPS"
                ));
            }
        }
        ProviderRegistry::from_config(&self.providers)
            .map(|_| ())
            .map_err(|error| anyhow!(error.to_string()))?;
        self.validate_persistence()?;
        if !matches!(
            self.broadcast.default_transport.as_str(),
            "moqt" | "uctp-quic"
        ) {
            return Err(anyhow!(
                "broadcast.default_transport must be moqt or uctp-quic"
            ));
        }
        if self.broadcast.max_active == 0 {
            return Err(anyhow!("broadcast.max_active must be greater than zero"));
        }
        if !(1..=MAX_BROADCAST_TOKEN_TTL_SECS).contains(&self.broadcast.token_ttl_secs) {
            return Err(anyhow!(
                "broadcast.token_ttl_secs must be between 1 and {MAX_BROADCAST_TOKEN_TTL_SECS}"
            ));
        }
        if let Some(token_secret) = &self.broadcast.token_secret {
            let mut resolved = token_secret
                .resolve()
                .map_err(|error| anyhow!("resolving broadcast.token_secret: {error}"))?;
            let valid = resolved.len() >= MIN_BROADCAST_TOKEN_SECRET_BYTES;
            resolved.zeroize();
            if !valid {
                return Err(anyhow!(
                    "broadcast.token_secret must resolve to at least {MIN_BROADCAST_TOKEN_SECRET_BYTES} bytes"
                ));
            }
        }
        if let Some(listener) = &self.broadcast.uctp_listener {
            listener.validate()?;
            if self.runtime.mode != RuntimeMode::AllInOne || !self.generic_bridge.enabled {
                return Err(anyhow!(
                    "broadcast.uctp_listener currently requires runtime.mode=all-in-one and generic_bridge.enabled"
                ));
            }
            if self.broadcast.token_secret.is_none() {
                return Err(anyhow!(
                    "broadcast.uctp_listener requires broadcast.token_secret"
                ));
            }
            validate_public_uctp_endpoint(self.broadcast.public_endpoint.as_deref().ok_or_else(
                || anyhow!("broadcast.uctp_listener requires broadcast.public_endpoint"),
            )?)?;
        }
        if matches!(
            self.runtime.mode,
            RuntimeMode::Gateway | RuntimeMode::Worker
        ) {
            if self.broadcast.token_secret.is_none() {
                return Err(anyhow!(
                    "split gateway/worker UCTP broadcasts require broadcast.token_secret"
                ));
            }
            validate_public_uctp_endpoint(self.broadcast.public_endpoint.as_deref().ok_or_else(
                || {
                    anyhow!(
                        "split gateway/worker UCTP broadcasts require broadcast.public_endpoint"
                    )
                },
            )?)?;
        }
        if let Some(origin) = &self.broadcast.moq_origin_relay {
            origin.validate()?;
            if !matches!(
                self.runtime.mode,
                RuntimeMode::Gateway | RuntimeMode::Worker
            ) {
                return Err(anyhow!(
                    "broadcast.moq_origin_relay is valid only for gateway and worker modes"
                ));
            }
            if self.broadcast.token_secret.is_none() {
                return Err(anyhow!(
                    "broadcast.moq_origin_relay requires broadcast.token_secret"
                ));
            }
        }
        if let Some(relay) = &self.moq_relay {
            relay.validate()?;
        } else if self.runtime.mode == RuntimeMode::MoqRelay {
            return Err(anyhow!(
                "moq_relay configuration is required when runtime.mode is moq-relay"
            ));
        }
        self.context
            .validate()
            .context("validating context allowlist")?;
        let configured_tenants = self.tenant_names()?.into_iter().collect::<BTreeSet<_>>();
        let sanitized_event_policies = self.broadcast.sanitized_events.policies(&self.context)?;
        for tenant in sanitized_event_policies.keys() {
            if !configured_tenants.contains(tenant) {
                return Err(anyhow!(
                    "broadcast.sanitized_events tenant {tenant:?} is not a configured routing tenant"
                ));
            }
        }
        if let Some(static_tenant) = &self.api.static_tenant {
            let static_tenant = TenantId::parse(static_tenant)
                .map_err(|_| anyhow!("api.static_tenant is not a valid tenant identifier"))?;
            let (tenants, _) = self
                .resolved_tenants()
                .context("validating api.static_tenant against configured tenants")?;
            if !tenants.contains_key(static_tenant.as_str()) {
                return Err(anyhow!(
                    "api.static_tenant must name one configured routing tenant"
                ));
            }
        }
        if let Some(control_key) = &self.api.control_hmac_key {
            let mut resolved = control_key
                .resolve()
                .map_err(|error| anyhow!("resolving api.control_hmac_key: {error}"))?;
            let valid = (MIN_CONTROL_KEY_BYTES..=MAX_CONTROL_KEY_BYTES).contains(&resolved.len());
            resolved.zeroize();
            if !valid {
                return Err(anyhow!(
                    "api.control_hmac_key must resolve to 32 to 4096 bytes"
                ));
            }
        }
        self.private_forwarding
            .validate(self.runtime.mode, self.runtime.max_concurrent_calls)?;
        Ok(())
    }

    fn validate_persistence(&self) -> Result<()> {
        DeploymentId::parse(self.persistence.deployment_id.clone())
            .map_err(|_| anyhow!("persistence.deployment_id is invalid"))?;
        if !(5..=300).contains(&self.persistence.worker_lease_ttl_secs) {
            return Err(anyhow!(
                "persistence.worker_lease_ttl_secs must be between 5 and 300"
            ));
        }
        if self.persistence.worker_renew_interval_secs == 0
            || self.persistence.worker_renew_interval_secs >= self.persistence.worker_lease_ttl_secs
        {
            return Err(anyhow!(
                "persistence.worker_renew_interval_secs must be positive and shorter than the lease TTL"
            ));
        }
        if self.persistence.worker_capabilities.len() > 64
            || self
                .persistence
                .worker_capabilities
                .iter()
                .any(|capability| {
                    capability.is_empty()
                        || capability.len() > 128
                        || capability.chars().any(char::is_control)
                })
        {
            return Err(anyhow!("persistence.worker_capabilities is invalid"));
        }
        if let Some(worker_id) = self.persistence.worker_id.as_deref() {
            WorkerId::from_str(worker_id)
                .map_err(|_| anyhow!("persistence.worker_id must be a non-nil UUID"))?;
        }
        match self.persistence.backend {
            PersistenceBackend::Memory => {
                if !self.persistence.allow_ephemeral_memory {
                    return Err(anyhow!(
                        "persistence.backend memory is dev/test-only and requires allow_ephemeral_memory: true"
                    ));
                }
                if self.persistence.database_url.is_some() {
                    return Err(anyhow!(
                        "persistence.database_url is not valid for the memory backend"
                    ));
                }
                if self.persistence.redis_url.is_some() {
                    return Err(anyhow!(
                        "persistence.redis_url requires a durable SQL backend"
                    ));
                }
                if self.persistence.allow_db_only_coordination {
                    return Err(anyhow!(
                        "persistence.allow_db_only_coordination is valid only with PostgreSQL"
                    ));
                }
            }
            PersistenceBackend::Sqlite => {
                if self.persistence.allow_ephemeral_memory {
                    return Err(anyhow!(
                        "persistence.allow_ephemeral_memory is valid only with the memory backend"
                    ));
                }
                if self.persistence.allow_db_only_coordination {
                    return Err(anyhow!(
                        "persistence.allow_db_only_coordination is valid only with PostgreSQL"
                    ));
                }
            }
            PersistenceBackend::Postgres => {
                if self.persistence.database_url.is_none() {
                    return Err(anyhow!(
                        "persistence.database_url is required for the postgres backend"
                    ));
                }
                if self.persistence.worker_id.is_none() && self.runtime.mode != RuntimeMode::Gateway
                {
                    return Err(anyhow!(
                        "persistence.worker_id is required for postgres execution workers"
                    ));
                }
                if self.persistence.allow_ephemeral_memory {
                    return Err(anyhow!(
                        "persistence.allow_ephemeral_memory is valid only with the memory backend"
                    ));
                }
                if self.persistence.allow_db_only_coordination
                    && self.runtime.mode != RuntimeMode::AllInOne
                {
                    return Err(anyhow!(
                        "persistence.allow_db_only_coordination is dev/test-only and requires runtime.mode all-in-one"
                    ));
                }
                if self.persistence.allow_db_only_coordination
                    && self.persistence.redis_url.is_some()
                {
                    return Err(anyhow!(
                        "persistence.allow_db_only_coordination cannot be combined with persistence.redis_url"
                    ));
                }
                if self.persistence.redis_url.is_none()
                    && !self.persistence.allow_db_only_coordination
                {
                    return Err(anyhow!(
                        "PostgreSQL requires clustered rediss:// coordination or explicit allow_db_only_coordination: true for all-in-one dev/test"
                    ));
                }
                if self.persistence.redis_url.is_some() && !self.persistence.redis_clustered {
                    return Err(anyhow!(
                        "PostgreSQL Redis coordination requires redis_clustered: true"
                    ));
                }
            }
        }
        if let Some(database_url) = &self.persistence.database_url {
            let mut resolved = database_url
                .resolve()
                .map_err(|error| anyhow!("resolving persistence.database_url: {error}"))?;
            let empty = resolved.is_empty();
            resolved.zeroize();
            if empty {
                return Err(anyhow!("persistence.database_url must not be empty"));
            }
        }
        if let Some(redis_url) = &self.persistence.redis_url {
            let mut resolved = redis_url
                .resolve()
                .map_err(|error| anyhow!("resolving persistence.redis_url: {error}"))?;
            let valid_scheme =
                resolved.starts_with("redis://") || resolved.starts_with("rediss://");
            let valid_clustered =
                !self.persistence.redis_clustered || resolved.starts_with("rediss://");
            resolved.zeroize();
            if !valid_scheme {
                return Err(anyhow!(
                    "persistence.redis_url must use redis:// or rediss://"
                ));
            }
            if !valid_clustered {
                return Err(anyhow!(
                    "persistence.redis_clustered requires a rediss:// URL"
                ));
            }
        } else if self.persistence.redis_clustered {
            return Err(anyhow!(
                "persistence.redis_clustered requires persistence.redis_url"
            ));
        }
        Ok(())
    }

    /// Resolves the repository choice only when transactional startup needs it.
    /// The returned SQL URL has a redacted `Debug` implementation in the shared
    /// runtime config and is zeroized after connection.
    pub fn call_repository_backend(&self) -> Result<CallRepositoryBackendConfig> {
        match self.persistence.backend {
            PersistenceBackend::Memory => Ok(CallRepositoryBackendConfig::Memory),
            PersistenceBackend::Sqlite => Ok(CallRepositoryBackendConfig::Sqlite {
                database_url: self
                    .persistence
                    .database_url
                    .as_ref()
                    .map(SecretRef::resolve)
                    .transpose()
                    .map_err(|error| anyhow!("resolving persistence.database_url: {error}"))?
                    .unwrap_or_else(default_sqlite_database_url),
            }),
            PersistenceBackend::Postgres => Ok(CallRepositoryBackendConfig::Postgres {
                database_url: self
                    .persistence
                    .database_url
                    .as_ref()
                    .ok_or_else(|| anyhow!("persistence.database_url is required"))?
                    .resolve()
                    .map_err(|error| anyhow!("resolving persistence.database_url: {error}"))?,
            }),
        }
    }

    /// Stable worker ID used for fencing and reservation accounting.
    pub fn call_worker_id(&self) -> Result<WorkerId> {
        let value = self
            .persistence
            .worker_id
            .as_deref()
            .unwrap_or(DEFAULT_STANDALONE_WORKER_ID);
        WorkerId::from_str(value)
            .map_err(|_| anyhow!("persistence.worker_id must be a non-nil UUID"))
    }

    /// Explicit worker capabilities used by database-authoritative placement.
    pub fn call_worker_capabilities(&self) -> BTreeSet<String> {
        self.persistence.worker_capabilities.clone()
    }

    /// Resolves lease bounds and the optional zeroizing Redis projection URL.
    pub fn call_coordination_config(&self) -> Result<CallServiceCoordinationConfig> {
        let deployment = DeploymentId::parse(self.persistence.deployment_id.clone())
            .map_err(|_| anyhow!("persistence.deployment_id is invalid"))?;
        let mut coordination = CallServiceCoordinationConfig::new(deployment.clone());
        coordination.worker_lease_ttl = Duration::from_secs(self.persistence.worker_lease_ttl_secs);
        coordination.worker_renew_interval =
            Duration::from_secs(self.persistence.worker_renew_interval_secs);
        coordination.allow_db_only_coordination = self.persistence.allow_db_only_coordination;
        if let Some(redis_url) = &self.persistence.redis_url {
            let url = redis_url
                .resolve()
                .map_err(|error| anyhow!("resolving persistence.redis_url: {error}"))?;
            coordination.redis = Some(
                RedisCoordinationConfig::new(url, deployment)
                    .map_err(|_| anyhow!("persistence.redis_url is invalid"))?
                    .clustered(self.persistence.redis_clustered),
            );
        }
        Ok(coordination)
    }

    /// Resolve the effective routing table: `(user part → route, effective
    /// default tenant)`. Applies the legacy single-tenant fallback; an empty
    /// table means every INVITE is rejected 404.
    pub fn resolved_tenants(&self) -> Result<(BTreeMap<String, ContactRoute>, Option<String>)> {
        if !self.tenants.is_empty() {
            let mut table = BTreeMap::new();
            for (name, tenant) in &self.tenants {
                if name.is_empty() {
                    return Err(anyhow!("tenants: empty tenant name (SIP user part)"));
                }
                if tenant.routing_only
                    && (!tenant.instance_id.is_empty() || !tenant.contact_flow_id.is_empty())
                {
                    return Err(anyhow!(
                        "tenants.{name}: routing_only tenants cannot declare Amazon Connect identifiers"
                    ));
                }
                if !tenant.routing_only
                    && (tenant.instance_id.is_empty() || tenant.contact_flow_id.is_empty())
                {
                    return Err(anyhow!(
                        "tenants.{name}: instance_id and contact_flow_id must be non-empty"
                    ));
                }
                let mapping = tenant.mapping.as_ref().unwrap_or(&self.mapping);
                table.insert(
                    name.clone(),
                    ContactRoute {
                        label: name.clone(),
                        instance_id: (!tenant.routing_only).then(|| tenant.instance_id.clone()),
                        contact_flow_id: (!tenant.routing_only)
                            .then(|| tenant.contact_flow_id.clone()),
                        attribute_mapping: Some(attribute_mapping(mapping)?),
                        default_display_name: tenant.default_display_name.clone(),
                    },
                );
            }
            if let Some(d) = &self.default_tenant {
                if !table.contains_key(d) {
                    return Err(anyhow!("default_tenant {d:?} is not a key of tenants"));
                }
            }
            return Ok((table, self.default_tenant.clone()));
        }

        // Legacy single-tenant schema: one catch-all tenant named `default`.
        match (&self.aws.instance_id, &self.aws.contact_flow_id) {
            (Some(instance), Some(flow)) if !instance.is_empty() && !flow.is_empty() => {
                if self.default_tenant.is_some() {
                    return Err(anyhow!(
                        "default_tenant is set but tenants is empty (legacy single-tenant \
                         config routes everything already)"
                    ));
                }
                let route = ContactRoute {
                    label: LEGACY_TENANT.to_string(),
                    instance_id: Some(instance.clone()),
                    contact_flow_id: Some(flow.clone()),
                    attribute_mapping: Some(attribute_mapping(&self.mapping)?),
                    default_display_name: None,
                };
                Ok((
                    BTreeMap::from([(LEGACY_TENANT.to_string(), route)]),
                    Some(LEGACY_TENANT.to_string()),
                ))
            }
            (None, None) => {
                if self.default_tenant.is_some() {
                    return Err(anyhow!("default_tenant is set but tenants is empty"));
                }
                // 0 tenants: valid — serve and reject every INVITE with 404
                // until the reconciler renders a tenant.
                Ok((BTreeMap::new(), None))
            }
            _ => Err(anyhow!(
                "aws.instance_id and aws.contact_flow_id must be set together \
                 (legacy single-tenant schema), or use tenants:"
            )),
        }
    }

    /// The loaded tenant names (for `/healthz` and metric pre-seeding).
    pub fn tenant_names(&self) -> Result<Vec<String>> {
        Ok(self.resolved_tenants()?.0.into_keys().collect())
    }

    fn validate_reference_tenant_canary(&self) -> Result<()> {
        let canary = &self.generic_bridge.reference_tenant_canary;
        if !canary.enabled {
            return Ok(());
        }
        if !self.generic_bridge.enabled || self.runtime.mode != RuntimeMode::AllInOne {
            return Err(anyhow!(
                "generic_bridge.reference_tenant_canary requires generic_bridge.enabled and runtime.mode=all-in-one"
            ));
        }
        let tenant = canary.tenant.as_deref().ok_or_else(|| {
            anyhow!("generic_bridge.reference_tenant_canary.tenant is required when enabled")
        })?;
        if self.api.static_tenant.as_deref() != Some(tenant) {
            return Err(anyhow!(
                "generic_bridge.reference_tenant_canary.tenant must equal api.static_tenant"
            ));
        }
        let context_mapping = self
            .context
            .allow_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(&canary.correlation_header))
            .map(|(_, key)| key.as_str());
        if context_mapping != Some("correlation_id") {
            return Err(anyhow!(
                "generic_bridge.reference_tenant_canary correlation header must be allowlisted as context key correlation_id"
            ));
        }
        self.build_reference_tenant_canary_policy()
            .map(|_| ())
            .context("validating generic_bridge.reference_tenant_canary")
    }

    /// Build the protected durable ReferenceTenant route. `None` is the
    /// complete default behavior and leaves the legacy listener untouched.
    pub(crate) fn reference_tenant_canary_policy(
        &self,
    ) -> Result<Option<Arc<ReferenceTenantCanaryPolicy>>> {
        if !self.generic_bridge.reference_tenant_canary.enabled {
            return Ok(None);
        }
        self.build_reference_tenant_canary_policy()
            .map(Arc::new)
            .map(Some)
    }

    fn build_reference_tenant_canary_policy(&self) -> Result<ReferenceTenantCanaryPolicy> {
        let canary = &self.generic_bridge.reference_tenant_canary;
        let tenant = canary.tenant.clone().ok_or_else(|| {
            anyhow!("generic_bridge.reference_tenant_canary.tenant is required when enabled")
        })?;
        let (routes, _) = self.resolved_tenants()?;
        let route = routes.get(&tenant).ok_or_else(|| {
            anyhow!("generic_bridge.reference_tenant_canary.tenant is not configured")
        })?;
        let instance_id = route
            .instance_id
            .clone()
            .ok_or_else(|| anyhow!("canary tenant has no Amazon Connect instance"))?;
        let contact_flow_id = route
            .contact_flow_id
            .clone()
            .ok_or_else(|| anyhow!("canary tenant has no Amazon Connect contact flow"))?;
        let mapping = self
            .tenants
            .get(&tenant)
            .and_then(|tenant| tenant.mapping.as_ref())
            .unwrap_or(&self.mapping);
        let attribute_mapping = attribute_mapping(mapping)?;
        let canary_probe = attribute_mapping.translate([(
            canary.correlation_header.as_str(),
            "bridgefu-canary-correlation",
        )]);
        if canary_probe.dropped_for_size != 0
            || canary_probe
                .attributes
                .get("correlation_id")
                .map(String::as_str)
                != Some("bridgefu-canary-correlation")
        {
            return Err(anyhow!(
                "canary tenant mapping must translate the correlation header to correlation_id"
            ));
        }
        ReferenceTenantCanaryPolicy::new(ReferenceTenantCanaryConfig {
            tenant,
            trusted_subject: canary.trusted_subject.clone(),
            trusted_issuer: canary.trusted_issuer.clone(),
            correlation_header: canary.correlation_header.clone(),
            profile: canary.amazon_profile.clone(),
            instance_id,
            contact_flow_id,
            default_display_name: route
                .default_display_name
                .clone()
                .unwrap_or_else(|| self.contact.default_display_name.clone()),
            attribute_mapping,
        })
        .map_err(|_| anyhow!("invalid protected ReferenceTenant canary policy"))
    }

    pub(crate) fn gateway_forwarding_config(&self) -> Result<GatewayForwardingConfig> {
        if self.runtime.mode != RuntimeMode::Gateway || !self.private_forwarding.enabled {
            return Err(anyhow!(
                "private_forwarding gateway configuration is not enabled for this role"
            ));
        }
        let gateway =
            self.private_forwarding.gateway.as_ref().ok_or_else(|| {
                anyhow!("private_forwarding.gateway is required for gateway mode")
            })?;
        let token_key = self.private_forwarding.resolve_token_key()?;
        let workers = gateway
            .workers
            .iter()
            .map(|worker| {
                Ok(PrivateWorkerTarget {
                    worker_id: WorkerId::from_str(&worker.worker_id)
                        .map_err(|_| anyhow!("private forwarding worker_id is invalid"))?,
                    endpoint: worker.endpoint.clone(),
                    server_name: worker.server_name.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(GatewayForwardingConfig {
            gateway_id: gateway.gateway_id.clone(),
            bind: gateway
                .bind
                .parse()
                .map_err(|_| anyhow!("private forwarding gateway bind is invalid"))?,
            tls: gateway.tls.runtime(),
            token_key,
            workers,
            limits: self.private_forwarding.limits.runtime(),
            timeouts: self.private_forwarding.timeouts.runtime(),
        })
    }

    pub(crate) fn gateway_uctp_ingress_config(&self) -> Result<GatewayUctpIngressConfig> {
        if self.runtime.mode != RuntimeMode::Gateway || !self.private_forwarding.enabled {
            return Err(anyhow!("public UCTP ingress is not enabled for this role"));
        }
        let listener = self
            .private_forwarding
            .gateway
            .as_ref()
            .and_then(|gateway| gateway.public_uctp.as_ref())
            .ok_or_else(|| anyhow!("private_forwarding.gateway.public_uctp is required"))?;
        listener.validate()?;
        Ok(GatewayUctpIngressConfig {
            bind: listener
                .bind
                .parse()
                .expect("validated gateway public UCTP bind"),
            certificate_chain: listener
                .tls
                .certificate_chain
                .iter()
                .map(Into::into)
                .collect(),
            private_key: listener.tls.private_key.clone().into(),
            max_concurrent_connections: listener.max_concurrent_connections,
            admission_capacity: self
                .runtime
                .max_concurrent_calls
                .checked_mul(2)
                .and_then(|calls| calls.checked_add(listener.max_concurrent_connections))
                .ok_or_else(|| anyhow!("gateway UCTP admission capacity overflow"))?,
            setup_timeout: Duration::from_secs(self.runtime.setup_timeout_secs),
        })
    }

    pub(crate) fn gateway_native_ingress_config(
        &self,
        authentication: rvoip_sip::SipListenerAuthPolicy,
        inbound_context: rvoip_sip::SipInboundContextPolicy,
    ) -> Result<GatewayNativeIngressConfig> {
        if self.runtime.mode != RuntimeMode::Gateway || !self.generic_bridge.enabled {
            return Err(anyhow!(
                "native SIP/WebRTC ingress is not enabled for this role"
            ));
        }
        let sip_bind = self
            .generic_bridge
            .sip_bind
            .parse::<SocketAddr>()
            .map_err(|_| anyhow!("generic_bridge.sip_bind must be a socket address"))?;
        let (stack, nat) = self
            .generic_sip_stack_config("bridgefu-gateway", sip_bind)
            .context("configuring gateway SIP/RTP networking")?;
        let egress_profiles = self
            .sip_egress_profile_configs("bridgefu-gateway", sip_bind)
            .context("configuring gateway named SIP egress profiles")?;
        let mut webrtc_stack = self
            .generic_bridge
            .webrtc_stack_config()
            .context("configuring gateway WebRTC ICE/DTLS networking")?;
        webrtc_stack.max_concurrent_sessions = self
            .runtime
            .max_concurrent_calls
            .checked_mul(2)
            .ok_or_else(|| anyhow!("gateway native WebRTC capacity overflow"))?;
        let tls = self
            .api
            .tls
            .as_ref()
            .map(|tls| GatewayNativeWebRtcTlsConfig {
                certificate_chain: tls.certificate_chain.clone().into(),
                private_key: tls.private_key.clone().into(),
            });
        Ok(GatewayNativeIngressConfig {
            sip: GatewayNativeSipConfig {
                stack,
                nat,
                authentication,
                inbound_context,
                egress_profiles,
            },
            webrtc: GatewayNativeWebRtcConfig {
                stack: webrtc_stack,
                websocket_bind: self.generic_bridge.webrtc_ws_bind.clone(),
                whip_whep_bind: self.generic_bridge.webrtc_whip_bind.clone(),
                tls,
            },
            admission_capacity: self
                .runtime
                .max_concurrent_calls
                .checked_mul(2)
                .ok_or_else(|| anyhow!("gateway native admission capacity overflow"))?,
            setup_timeout: Duration::from_secs(self.runtime.setup_timeout_secs),
        })
    }

    pub(crate) fn worker_forwarding_config(&self) -> Result<WorkerForwardingConfig> {
        if self.runtime.mode != RuntimeMode::Worker || !self.private_forwarding.enabled {
            return Err(anyhow!(
                "private_forwarding worker configuration is not enabled for this role"
            ));
        }
        let worker = self
            .private_forwarding
            .worker
            .as_ref()
            .ok_or_else(|| anyhow!("private_forwarding.worker is required for worker mode"))?;
        Ok(WorkerForwardingConfig {
            worker_id: self.call_worker_id()?,
            bind: worker
                .bind
                .parse()
                .map_err(|_| anyhow!("private forwarding worker bind is invalid"))?,
            tls: worker.tls.runtime(),
            token_key: self.private_forwarding.resolve_token_key()?,
            limits: self.private_forwarding.limits.runtime(),
            timeouts: self.private_forwarding.timeouts.runtime(),
        })
    }

    /// Build the `rvoip-amazon-connect` server config from this YAML. Async
    /// because it resolves AWS credentials and may query IMDS for `auto` IPs.
    pub async fn build_server_config(&self) -> Result<ScreenPopServerConfig> {
        let starter: Arc<dyn ConnectContactStarter> =
            Arc::new(AwsConnectStarter::from_env(Some(self.aws.region.clone())).await);
        self.build_server_config_with_starter(starter).await
    }

    /// Build the outbound-only Amazon Connect adapter used by a split worker.
    ///
    /// Unlike [`Self::build_server_config`], this path never parses, resolves,
    /// or binds the public SIP listener. Split workers receive their source
    /// media over private UCTP and need only Connect control and Chime media.
    pub async fn build_worker_amazon_connect_adapter(&self) -> Result<Arc<AmazonConnectAdapter>> {
        let starter: Arc<dyn ConnectContactStarter> =
            Arc::new(AwsConnectStarter::from_env(Some(self.aws.region.clone())).await);
        self.build_worker_amazon_connect_adapter_with_starter(starter)
    }

    /// Hermetic construction seam for the split-worker Amazon adapter.
    /// Production uses [`Self::build_worker_amazon_connect_adapter`].
    pub fn build_worker_amazon_connect_adapter_with_starter(
        &self,
        starter: Arc<dyn ConnectContactStarter>,
    ) -> Result<Arc<AmazonConnectAdapter>> {
        let mut builder = AmazonConnectAdapter::builder(
            self.build_amazon_connect_config()?,
            Arc::clone(&starter),
        );
        let profile_ids = self
            .api
            .routes
            .values()
            .filter_map(|route| match &route.destination_profile {
                Some(RouteDestinationProfileRef::AmazonConnect { profile_id }) => {
                    Some(profile_id.as_str())
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        for profile_id in profile_ids {
            let profile = ConnectProfileId::new(profile_id.to_owned())
                .map_err(|_| anyhow!("configured Amazon Connect profile ID is invalid"))?;
            if profile == ConnectProfileId::default() {
                continue;
            }
            builder
                .register_profile(profile, Arc::clone(&starter))
                .map_err(|_| anyhow!("configured Amazon Connect profile catalog is invalid"))?;
        }
        let mut webrtc = self
            .generic_bridge
            .webrtc_stack_config()
            .context("configuring Amazon Connect WebRTC UDP allocation")?;
        webrtc.max_concurrent_sessions = self.runtime.max_concurrent_calls;
        Ok(builder.build().with_webrtc_config(webrtc))
    }

    fn build_amazon_connect_config(&self) -> Result<ConnectConfig> {
        let mut connect = ConnectConfig::new(
            self.aws.instance_id.clone().unwrap_or_default(),
            self.aws.contact_flow_id.clone().unwrap_or_default(),
        )
        .with_region(self.aws.region.clone())
        .with_attribute_mapping(attribute_mapping(&self.mapping)?);
        connect.default_display_name = self.contact.default_display_name.clone();
        connect.signaling_timeout = Duration::from_secs(self.contact.signaling_timeout_secs);
        connect.media_connect_timeout =
            Duration::from_secs(self.contact.media_connect_timeout_secs);
        connect.keepalive_interval = Duration::from_secs(self.contact.keepalive_interval_secs);
        connect.session_idle_ttl = Duration::from_secs(self.contact.session_idle_ttl_secs);
        Ok(connect)
    }

    /// Build the server config with an explicit Amazon Connect control-plane
    /// implementation.
    ///
    /// Production uses [`Self::build_server_config`]. This injection seam keeps
    /// the Vapi SIP -> Connect request contract testable without AWS credentials
    /// or a live Connect instance.
    pub async fn build_server_config_with_starter(
        &self,
        starter: Arc<dyn ConnectContactStarter>,
    ) -> Result<ScreenPopServerConfig> {
        let (table, default_tenant) = self.resolved_tenants()?;

        // --- connect defaults (every real call is routed, so the empty
        //     instance/flow placeholders are never used to place a contact) ---
        let connect = self.build_amazon_connect_config()?;

        // --- sip ---
        let bind_ip: IpAddr = self
            .sip
            .bind_ip
            .parse()
            .with_context(|| format!("invalid sip.bind_ip: {}", self.sip.bind_ip))?;
        let mut sip = SipConfig::on("bridgefu", bind_ip, self.sip.port);

        let advertised_ip = resolve_public_ip(&self.sip.advertised_ip)
            .await
            .context("resolving sip.advertised_ip")?;
        sip.sip_advertised_addr = Some(SocketAddr::new(advertised_ip, self.sip.port));

        let media_ip = resolve_public_ip(&self.sip.media_public_ip)
            .await
            .context("resolving sip.media_public_ip")?;
        // Port 0 → keep the dynamically-allocated RTP port, swap in the public IP.
        sip.media_public_addr = Some(SocketAddr::new(media_ip, 0));

        // --- per-INVITE router (B.4 match order) ---
        let router = Arc::new(move |call: &IncomingCall| {
            let ruri_user = request_uri_user(call);
            let to_user = to_uri_user(call);
            match match_tenant(
                &table,
                default_tenant.as_deref(),
                ruri_user.as_deref(),
                to_user.as_deref(),
            ) {
                Some(route) => {
                    metrics::counter!(
                        "bridgefu_calls_routed_total",
                        "tenant" => route.label.clone()
                    )
                    .increment(1);
                    RouteDecision::Route(route.clone())
                }
                None => {
                    metrics::counter!("bridgefu_unknown_tenant_total").increment(1);
                    tracing::warn!(
                        ruri_user = ruri_user.as_deref().unwrap_or("-"),
                        to_user = to_user.as_deref().unwrap_or("-"),
                        "no tenant matches inbound INVITE — rejecting 404"
                    );
                    RouteDecision::Reject {
                        status: 404,
                        reason: "Not Found".into(),
                    }
                }
            }
        });

        Ok(ScreenPopServerConfig::new(sip, connect, starter).with_router(router))
    }
}

impl PrivateForwardingCfg {
    fn validate(&self, mode: RuntimeMode, max_calls: usize) -> Result<()> {
        let role_requires_forwarding = matches!(mode, RuntimeMode::Gateway | RuntimeMode::Worker);
        if role_requires_forwarding && !self.enabled {
            return Err(anyhow!(
                "runtime.mode {mode} requires private_forwarding.enabled: true"
            ));
        }
        if !self.enabled {
            if self.gateway.is_some()
                || self.worker.is_some()
                || self.token_signing_secret.is_some()
            {
                return Err(anyhow!(
                    "private_forwarding role or secret settings require enabled: true"
                ));
            }
            return Ok(());
        }
        if !role_requires_forwarding {
            return Err(anyhow!(
                "private_forwarding is valid only for gateway or worker runtime modes"
            ));
        }
        let mut secret = self
            .token_signing_secret
            .as_ref()
            .ok_or_else(|| anyhow!("private_forwarding.token_signing_secret is required"))?
            .resolve()
            .map_err(|error| anyhow!("resolving private forwarding token secret: {error}"))?;
        let key_is_valid = secret.len() >= 32;
        secret.zeroize();
        if !key_is_valid {
            return Err(anyhow!(
                "private_forwarding.token_signing_secret must resolve to at least 32 bytes"
            ));
        }
        self.limits.validate(max_calls)?;
        self.timeouts.validate()?;
        match mode {
            RuntimeMode::Gateway => {
                if self.worker.is_some() {
                    return Err(anyhow!(
                        "private_forwarding.worker is not valid in gateway mode"
                    ));
                }
                self.gateway
                    .as_ref()
                    .ok_or_else(|| anyhow!("private_forwarding.gateway is required"))?
                    .validate()?;
            }
            RuntimeMode::Worker => {
                if self.gateway.is_some() {
                    return Err(anyhow!(
                        "private_forwarding.gateway is not valid in worker mode"
                    ));
                }
                self.worker
                    .as_ref()
                    .ok_or_else(|| anyhow!("private_forwarding.worker is required"))?
                    .validate()?;
            }
            RuntimeMode::AllInOne | RuntimeMode::MoqRelay => unreachable!("checked above"),
        }
        Ok(())
    }

    fn resolve_token_key(&self) -> Result<PrivateTokenKey> {
        let mut secret = self
            .token_signing_secret
            .as_ref()
            .ok_or_else(|| anyhow!("private forwarding token secret is missing"))?
            .resolve()
            .map_err(|error| anyhow!("resolving private forwarding token secret: {error}"))?;
        let key = PrivateTokenKey::new(secret.as_bytes().to_vec())
            .map_err(|_| anyhow!("private forwarding token secret is invalid"));
        secret.zeroize();
        key
    }
}

impl PrivateForwardingGatewayCfg {
    fn validate(&self) -> Result<()> {
        validate_private_component("gateway_id", &self.gateway_id)?;
        self.bind
            .parse::<SocketAddr>()
            .map_err(|_| anyhow!("private_forwarding.gateway.bind must be a socket address"))?;
        self.tls.validate("gateway")?;
        if let Some(public_uctp) = &self.public_uctp {
            public_uctp
                .validate()
                .context("validating private_forwarding.gateway.public_uctp")?;
        }
        if self.workers.is_empty() {
            return Err(anyhow!(
                "private_forwarding.gateway.workers must contain at least one target"
            ));
        }
        let mut worker_ids = BTreeSet::new();
        for worker in &self.workers {
            WorkerId::from_str(&worker.worker_id).map_err(|_| {
                anyhow!("private_forwarding.gateway worker_id must be a non-nil UUID")
            })?;
            validate_private_worker_endpoint(&worker.endpoint)?;
            validate_private_server_name(&worker.server_name)?;
            if !worker_ids.insert(worker.worker_id.as_str()) {
                return Err(anyhow!(
                    "private_forwarding.gateway worker_id values must be unique"
                ));
            }
        }
        Ok(())
    }
}

impl PrivateForwardingWorkerCfg {
    fn validate(&self) -> Result<()> {
        let bind = self
            .bind
            .parse::<SocketAddr>()
            .map_err(|_| anyhow!("private_forwarding.worker.bind must be a socket address"))?;
        if bind.port() == 0 {
            return Err(anyhow!(
                "private_forwarding.worker.bind must use an explicit nonzero port"
            ));
        }
        self.tls.validate("worker")
    }
}

impl PrivateForwardingTlsCfg {
    fn validate(&self, role: &str) -> Result<()> {
        if self.certificate_chain.is_empty() || self.peer_ca_certificates.is_empty() {
            return Err(anyhow!(
                "private_forwarding {role} TLS requires a certificate chain and peer CA"
            ));
        }
        for path in self
            .certificate_chain
            .iter()
            .chain(std::iter::once(&self.private_key))
            .chain(&self.peer_ca_certificates)
        {
            if path.is_empty() || path.len() > 4_096 || path.chars().any(char::is_control) {
                return Err(anyhow!("private_forwarding TLS path is invalid"));
            }
        }
        Ok(())
    }

    fn runtime(&self) -> MutualTlsFiles {
        MutualTlsFiles {
            certificate_chain: self.certificate_chain.iter().map(Into::into).collect(),
            private_key: self.private_key.clone().into(),
            peer_ca_certificates: self.peer_ca_certificates.iter().map(Into::into).collect(),
        }
    }
}

impl PublicUctpListenerCfg {
    fn validate(&self) -> Result<()> {
        let bind = self
            .bind
            .parse::<SocketAddr>()
            .map_err(|_| anyhow!("public UCTP listener bind must be a socket address"))?;
        if bind.port() == 0 {
            return Err(anyhow!(
                "public UCTP listener bind must use an explicit nonzero port"
            ));
        }
        if self.max_concurrent_connections == 0 {
            return Err(anyhow!(
                "public UCTP listener max_concurrent_connections must be greater than zero"
            ));
        }
        if self.tls.certificate_chain.is_empty() {
            return Err(anyhow!(
                "public UCTP listener TLS requires a certificate chain"
            ));
        }
        for path in self
            .tls
            .certificate_chain
            .iter()
            .chain(std::iter::once(&self.tls.private_key))
        {
            if path.is_empty() || path.len() > 4_096 || path.chars().any(char::is_control) {
                return Err(anyhow!("public UCTP listener TLS path is invalid"));
            }
        }
        Ok(())
    }

    pub fn runtime(&self) -> Result<PublicUctpBindConfig> {
        self.validate()?;
        Ok(PublicUctpBindConfig {
            bind: self.bind.parse().expect("validated public UCTP bind"),
            certificate_chain: self.tls.certificate_chain.iter().map(Into::into).collect(),
            private_key: self.tls.private_key.clone().into(),
            max_concurrent_connections: self.max_concurrent_connections,
        })
    }
}

impl PrivateForwardingLimitsCfg {
    fn validate(&self, max_calls: usize) -> Result<()> {
        let minimum_routes = max_calls
            .checked_mul(2)
            .ok_or_else(|| anyhow!("private forwarding route limit overflow"))?;
        if self.max_active_routes < minimum_routes
            || self.max_peer_connections == 0
            || self.max_routes_per_peer == 0
            || self.max_routes_per_peer > self.max_active_routes
            || self.media_queue_capacity == 0
            || self.media_queue_capacity > 1_024
            || self.reliable_queue_capacity == 0
            || self.reliable_queue_capacity > 4_096
            || self.inbound_queue_capacity == 0
            || self.inbound_queue_capacity > 4_096
        {
            return Err(anyhow!(
                "private_forwarding limits are inconsistent or outside safe bounds"
            ));
        }
        Ok(())
    }

    fn runtime(&self) -> PrivateForwardingLimits {
        PrivateForwardingLimits {
            max_active_routes: self.max_active_routes,
            max_peer_connections: self.max_peer_connections,
            max_routes_per_peer: self.max_routes_per_peer,
            media_queue_capacity: self.media_queue_capacity,
            reliable_queue_capacity: self.reliable_queue_capacity,
            inbound_queue_capacity: self.inbound_queue_capacity,
        }
    }
}

impl PrivateForwardingTimeoutsCfg {
    fn validate(&self) -> Result<()> {
        if !(1..=60).contains(&self.connect_secs)
            || !(1..=60).contains(&self.signaling_secs)
            || !(60..=3_600).contains(&self.token_ttl_secs)
            || !(1..=300).contains(&self.health_interval_secs)
            || self.health_interval_secs >= self.token_ttl_secs
        {
            return Err(anyhow!(
                "private_forwarding timeout values are outside safe bounds"
            ));
        }
        Ok(())
    }

    fn runtime(&self) -> PrivateForwardingTimeouts {
        PrivateForwardingTimeouts {
            connect: Duration::from_secs(self.connect_secs),
            signaling: Duration::from_secs(self.signaling_secs),
            token_ttl: Duration::from_secs(self.token_ttl_secs),
            health_interval: Duration::from_secs(self.health_interval_secs),
        }
    }
}

fn validate_private_component(field: &str, value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(anyhow!("private_forwarding {field} is invalid"))
    }
}

fn validate_private_server_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 253
        || value.chars().any(char::is_control)
        || value.contains('/')
        || value.contains('@')
    {
        Err(anyhow!("private_forwarding worker server_name is invalid"))
    } else {
        Ok(())
    }
}

fn validate_private_worker_endpoint(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 512
        || value.chars().any(char::is_control)
        || value.contains(['/', '@', '?', '#'])
    {
        return Err(anyhow!(
            "private_forwarding worker endpoint authority is invalid"
        ));
    }
    let parsed = url::Url::parse(&format!("uctp+quic://{value}"))
        .map_err(|_| anyhow!("private_forwarding worker endpoint authority is invalid"))?;
    if parsed.host_str().is_none() || parsed.port().is_none() {
        return Err(anyhow!(
            "private_forwarding worker endpoint requires an explicit host and port"
        ));
    }
    Ok(())
}

fn validate_public_uctp_endpoint(value: &str) -> Result<()> {
    let parsed = url::Url::parse(value)
        .map_err(|_| anyhow!("broadcast.public_endpoint must be a valid UCTP URL"))?;
    if parsed.scheme() != "uctp+quic"
        || parsed.host_str().is_none()
        || parsed.port().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != ""
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(anyhow!(
            "broadcast.public_endpoint must be uctp+quic://host:port without credentials or a path"
        ));
    }
    Ok(())
}

impl MoqRelayCfg {
    fn validate(&self) -> Result<()> {
        validate_moq_listener("publisher", &self.publisher.listener)?;
        validate_moq_listener("subscriber_webtransport", &self.subscriber_webtransport)?;
        validate_moq_listener("subscriber_raw_quic", &self.subscriber_raw_quic)?;

        let binds = [
            self.publisher.listener.bind.as_str(),
            self.subscriber_webtransport.bind.as_str(),
            self.subscriber_raw_quic.bind.as_str(),
        ];
        if binds.iter().collect::<BTreeSet<_>>().len() != binds.len() {
            return Err(anyhow!(
                "moq_relay publisher, WebTransport, and raw QUIC listeners require distinct binds"
            ));
        }
        if self.tls.server_certificates.is_empty()
            || self.tls.server_certificates.len() != self.tls.server_private_keys.len()
            || self.tls.publisher_client_ca_certificates.is_empty()
        {
            return Err(anyhow!(
                "moq_relay TLS requires paired server certificates/keys and at least one publisher client CA"
            ));
        }
        for path in self
            .tls
            .server_certificates
            .iter()
            .chain(&self.tls.server_private_keys)
            .chain(&self.tls.publisher_client_ca_certificates)
        {
            if path.is_empty() || path.len() > 4_096 || path.chars().any(char::is_control) {
                return Err(anyhow!("moq_relay TLS path is invalid"));
            }
        }
        if self.publisher.certificate_bindings.is_empty()
            || self.publisher.max_active_sessions_per_certificate == 0
        {
            return Err(anyhow!(
                "moq_relay publisher requires certificate bindings and a positive per-certificate session limit"
            ));
        }
        for binding in &self.publisher.certificate_bindings {
            if binding.certificate_sha256.len() != 64
                || !binding
                    .certificate_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(anyhow!(
                    "moq_relay publisher certificate fingerprint must be 64 hexadecimal characters"
                ));
            }
            let namespace = binding.scope.strip_prefix('/').ok_or_else(|| {
                anyhow!("moq_relay publisher certificate scope must begin with /")
            })?;
            rvoip_moq::MoqNamespace::parse(namespace)
                .map_err(|_| anyhow!("moq_relay publisher certificate scope is invalid"))?;
        }
        let limits = &self.limits;
        let bounded = [
            limits.max_pending_admissions,
            limits.max_active_sessions,
            limits.max_active_sessions_per_tenant,
            limits.max_replay_claims,
            limits.max_coordinated_namespaces,
            limits.max_cached_tracks_per_namespace,
            limits.max_pending_track_requests_per_namespace,
            limits.max_upstream_connections,
            limits.max_upstream_tracks,
        ];
        if bounded.contains(&0)
            || limits.max_active_sessions > 100_000
            || limits.max_active_sessions_per_tenant > limits.max_active_sessions
            || limits.max_replay_claims < limits.max_active_sessions
        {
            return Err(anyhow!(
                "moq_relay limits must be positive, bounded, and replay/session capacities must be consistent"
            ));
        }
        let timeouts = &self.timeouts;
        let seconds = [
            timeouts.setup_secs,
            timeouts.admission_secs,
            timeouts.admission_operation_secs,
            timeouts.pre_admission_cleanup_secs,
            timeouts.admission_session_close_secs,
            timeouts.token_revalidation_interval_secs,
            timeouts.upstream_track_idle_secs,
            timeouts.upstream_connection_idle_secs,
            timeouts.drop_cleanup_secs,
            timeouts.dependency_check_interval_secs,
        ];
        if seconds.iter().any(|seconds| !(1..=3_600).contains(seconds)) {
            return Err(anyhow!(
                "moq_relay timeout and interval values must be between 1 and 3600 seconds"
            ));
        }

        let mut diagnostics = self
            .diagnostics_bearer_token
            .resolve()
            .map_err(|error| anyhow!("resolving moq_relay.diagnostics_bearer_token: {error}"))?;
        let valid_diagnostics = (32..=4_096).contains(&diagnostics.len());
        diagnostics.zeroize();
        if !valid_diagnostics {
            return Err(anyhow!(
                "moq_relay.diagnostics_bearer_token must resolve to 32 to 4096 bytes"
            ));
        }
        Ok(())
    }
}

fn validate_moq_listener(kind: &str, listener: &MoqRelayListenerCfg) -> Result<()> {
    listener
        .bind
        .parse::<SocketAddr>()
        .map_err(|_| anyhow!("moq_relay.{kind}.bind must be a socket address"))?;
    let endpoint = url::Url::parse(&listener.advertised_endpoint)
        .map_err(|_| anyhow!("moq_relay.{kind}.advertised_endpoint is invalid"))?;
    if endpoint.scheme() != "moqt"
        || endpoint.host_str().is_none_or(str::is_empty)
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || !matches!(endpoint.path(), "" | "/")
    {
        return Err(anyhow!(
            "moq_relay.{kind}.advertised_endpoint must be a credential-free authority-only moqt:// URL"
        ));
    }
    if let Some(address) = listener.advertised_socket_addr.as_deref() {
        address.parse::<SocketAddr>().map_err(|_| {
            anyhow!("moq_relay.{kind}.advertised_socket_addr must be a socket address")
        })?;
    }
    Ok(())
}

fn deserialize_strict(value: &serde_yaml::Value, path: &std::path::Path) -> Result<Config> {
    let rendered =
        serde_yaml::to_string(value).with_context(|| format!("normalizing {}", path.display()))?;
    let deserializer = serde_yaml::Deserializer::from_str(&rendered);
    let mut unknown = BTreeSet::new();
    let config = serde_ignored::deserialize(deserializer, |field| {
        unknown.insert(field.to_string());
    })
    .with_context(|| format!("parsing {}", path.display()))?;
    if unknown.is_empty() {
        return Ok(config);
    }
    Err(anyhow!(
        "unknown configuration field{} in {}: {}",
        if unknown.len() == 1 { "" } else { "s" },
        path.display(),
        unknown.into_iter().collect::<Vec<_>>().join(", ")
    ))
}

fn effective_value(path: &std::path::Path) -> Result<serde_yaml::Value> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config file {}", path.display()))?;
    let mut value: serde_yaml::Value =
        serde_yaml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    for (name, raw) in std::env::vars() {
        let Some(path) = name.strip_prefix("BRIDGEFU__") else {
            continue;
        };
        let segments: Vec<String> = path
            .split("__")
            .filter(|segment| !segment.is_empty())
            .map(|segment| segment.to_ascii_lowercase())
            .collect();
        if segments.is_empty() {
            continue;
        }
        let replacement =
            serde_yaml::from_str(&raw).unwrap_or_else(|_| serde_yaml::Value::String(raw));
        set_yaml_path(&mut value, &segments, replacement)?;
    }
    Ok(value)
}

fn set_yaml_path(
    value: &mut serde_yaml::Value,
    path: &[String],
    replacement: serde_yaml::Value,
) -> Result<()> {
    if path.len() == 1 {
        let mapping = value
            .as_mapping_mut()
            .ok_or_else(|| anyhow!("environment override parent is not a mapping"))?;
        mapping.insert(serde_yaml::Value::String(path[0].clone()), replacement);
        return Ok(());
    }
    let mapping = value
        .as_mapping_mut()
        .ok_or_else(|| anyhow!("environment override parent is not a mapping"))?;
    let next = mapping
        .entry(serde_yaml::Value::String(path[0].clone()))
        .or_insert_with(|| serde_yaml::Value::Mapping(Default::default()));
    set_yaml_path(next, &path[1..], replacement)
}

fn redact_secrets(value: &mut serde_yaml::Value) {
    match value {
        serde_yaml::Value::Mapping(mapping) => {
            for (key, value) in mapping.iter_mut() {
                let sensitive = key.as_str().is_some_and(|key| {
                    matches!(
                        key.to_ascii_lowercase().as_str(),
                        "auth_token"
                            | "api_key"
                            | "private_key"
                            | "signature_secret"
                            | "token_secret"
                            | "bearer_token"
                            | "diagnostics_bearer_token"
                            | "control_hmac_key"
                            | "token_signing_secret"
                            | "database_url"
                            | "redis_url"
                            | "password"
                            | "media_sip_password"
                            | "credential"
                            | "trusted_subject"
                            | "trusted_issuer"
                    )
                });
                if sensitive {
                    *value = serde_yaml::Value::String("[redacted]".into());
                } else {
                    redact_secrets(value);
                }
            }
        }
        serde_yaml::Value::Sequence(sequence) => {
            for value in sequence {
                redact_secrets(value);
            }
        }
        _ => {}
    }
}

/// Tenant name used for the legacy single-tenant schema.
pub const LEGACY_TENANT: &str = "default";
/// One stable identity for a single standalone SQLite repository. Clustered
/// PostgreSQL deployments must configure a distinct worker ID explicitly.
const DEFAULT_STANDALONE_WORKER_ID: &str = "00000000-0000-4000-8000-000000000001";

/// B.4 match order: R-URI user part, else `To:` user part, else the default
/// tenant, else `None` (caller rejects 404).
fn match_tenant<'a>(
    table: &'a BTreeMap<String, ContactRoute>,
    default_tenant: Option<&str>,
    ruri_user: Option<&str>,
    to_user: Option<&str>,
) -> Option<&'a ContactRoute> {
    ruri_user
        .and_then(|u| table.get(u))
        .or_else(|| to_user.and_then(|u| table.get(u)))
        .or_else(|| default_tenant.and_then(|d| table.get(d)))
}

/// Translate a YAML mapping block into the crate's `AttributeMapping`.
fn attribute_mapping(cfg: &MappingCfg) -> Result<AttributeMapping> {
    let unmapped = match cfg.unmapped.as_str() {
        "drop" => UnmappedPolicy::Drop,
        "pass_prefixed" => UnmappedPolicy::PassPrefixed,
        other => {
            return Err(anyhow!(
                "invalid mapping.unmapped: {other} (drop|pass_prefixed)"
            ))
        }
    };
    Ok(AttributeMapping {
        rename: cfg.rename.clone(),
        passthrough_prefix: cfg.passthrough_prefix.clone(),
        unmapped,
    })
}

/// Resolve a configured IP value: a literal IP, or `"auto"` → IMDSv2 public-ipv4.
async fn resolve_public_ip(value: &str) -> Result<IpAddr> {
    if value.eq_ignore_ascii_case("auto") {
        let ip = crate::imds::public_ipv4()
            .await
            .context("IMDSv2 public-ipv4 lookup (set a literal IP if not on EC2)")?;
        ip.parse()
            .with_context(|| format!("IMDS returned an unparseable IP: {ip:?}"))
    } else {
        value
            .parse()
            .with_context(|| format!("invalid IP {value:?} (use a literal IP or \"auto\")"))
    }
}

fn default_bind_ip() -> String {
    "0.0.0.0".into()
}
fn default_port() -> u16 {
    5060
}
fn default_auto() -> String {
    "auto".into()
}
fn default_display_name() -> String {
    "bridgefu".into()
}
fn default_signaling_timeout() -> u64 {
    15
}
fn default_media_timeout() -> u64 {
    30
}
fn default_keepalive() -> u64 {
    10
}
fn default_idle_ttl() -> u64 {
    120
}
fn default_unmapped() -> String {
    "drop".into()
}
fn default_prefix() -> String {
    "X-".into()
}
fn default_log_level() -> String {
    "info".into()
}
fn default_log_format() -> String {
    "json".into()
}
fn default_http_bind() -> String {
    "0.0.0.0:9090".into()
}
fn default_otlp_service_name() -> String {
    "bridgefu".into()
}
fn default_otlp_sampling_ratio() -> f64 {
    1.0
}
fn default_otlp_max_queue_size() -> usize {
    2_048
}
fn default_otlp_max_export_batch_size() -> usize {
    512
}
fn default_otlp_scheduled_delay_millis() -> u64 {
    5_000
}
fn default_otlp_export_timeout_millis() -> u64 {
    10_000
}
fn default_config_version() -> u32 {
    1
}
fn default_max_calls() -> usize {
    100
}
fn default_setup_timeout() -> u64 {
    30
}
fn default_media_idle_timeout() -> u64 {
    30
}
fn default_drain_timeout() -> u64 {
    30
}
fn default_private_gateway_bind() -> String {
    "0.0.0.0:0".into()
}
fn default_private_worker_bind() -> String {
    "0.0.0.0:9443".into()
}
fn default_private_active_routes() -> usize {
    2_000
}
fn default_private_peer_connections() -> usize {
    256
}
fn default_private_routes_per_peer() -> usize {
    1_200
}
fn default_private_media_queue() -> usize {
    10
}
fn default_private_reliable_queue() -> usize {
    64
}
fn default_private_inbound_queue() -> usize {
    64
}
fn default_private_connect_timeout() -> u64 {
    5
}
fn default_private_signaling_timeout() -> u64 {
    5
}
fn default_private_token_ttl() -> u64 {
    300
}
fn default_private_health_interval() -> u64 {
    5
}
fn default_deployment_id() -> String {
    "bridgefu".to_owned()
}
fn default_worker_lease_ttl() -> u64 {
    30
}
fn default_worker_renew_interval() -> u64 {
    10
}
fn default_worker_capabilities() -> BTreeSet<String> {
    BTreeSet::from([
        "amazon_connect".to_owned(),
        "sip".to_owned(),
        "sip_egress".to_owned(),
        "telnyx".to_owned(),
        "webrtc".to_owned(),
        "webrtc_egress".to_owned(),
    ])
}
fn default_sqlite_database_url() -> String {
    "sqlite://bridgefu.db".into()
}
fn default_true() -> bool {
    true
}
fn default_api_control_rate() -> u32 {
    50
}
fn default_api_control_burst() -> u32 {
    100
}
fn default_api_diagnostics_rate() -> u32 {
    2
}
fn default_api_diagnostics_burst() -> u32 {
    4
}
fn default_api_webhook_rate() -> u32 {
    100
}
fn default_api_webhook_burst() -> u32 {
    200
}
fn default_api_tracked_identities() -> usize {
    10_000
}
fn default_api_identity_idle_ttl() -> u64 {
    300
}
fn default_broadcast_transport() -> String {
    "moqt".into()
}
fn default_broadcast_ttl() -> u64 {
    300
}
fn default_max_broadcasts() -> usize {
    100
}
fn default_public_uctp_connections() -> usize {
    1_024
}
fn default_sanitized_event_queue() -> usize {
    64
}
fn default_sanitized_event_history() -> usize {
    64
}
fn default_sanitized_event_rate() -> u32 {
    8
}
fn default_moq_sessions_per_certificate() -> usize {
    64
}
fn default_moq_pending_admissions() -> usize {
    256
}
fn default_moq_active_sessions() -> usize {
    2_048
}
fn default_moq_tenant_sessions() -> usize {
    1_000
}
fn default_moq_replay_claims() -> usize {
    8_192
}
fn default_moq_coordinated_namespaces() -> usize {
    100_000
}
fn default_moq_cached_tracks() -> usize {
    4_096
}
fn default_moq_pending_tracks() -> usize {
    1_024
}
fn default_moq_upstream_connections() -> usize {
    128
}
fn default_moq_upstream_tracks() -> usize {
    4_096
}
fn default_moq_setup_timeout() -> u64 {
    5
}
fn default_moq_admission_timeout() -> u64 {
    5
}
fn default_moq_admission_operation_timeout() -> u64 {
    3
}
fn default_moq_cleanup_timeout() -> u64 {
    2
}
fn default_moq_session_close_timeout() -> u64 {
    5
}
fn default_moq_revalidation_interval() -> u64 {
    15
}
fn default_moq_upstream_track_idle() -> u64 {
    30
}
fn default_moq_upstream_connection_idle() -> u64 {
    60
}
fn default_moq_drop_cleanup() -> u64 {
    10
}
fn default_moq_dependency_check_interval() -> u64 {
    5
}
fn default_generic_sip_bind() -> String {
    "0.0.0.0:5070".into()
}
fn default_recipe_sips_bind() -> String {
    "0.0.0.0:5061".into()
}
fn default_recipe_sip_bind() -> String {
    "0.0.0.0:5060".into()
}
fn default_webrtc_ws_bind() -> String {
    "0.0.0.0:8080".into()
}
fn default_webrtc_whip_bind() -> String {
    "0.0.0.0:8081".into()
}
fn default_generic_webrtc_udp_bind() -> String {
    "0.0.0.0:0".into()
}
fn default_generic_webrtc_audio_codecs() -> BTreeSet<GenericWebRtcAudioCodec> {
    BTreeSet::from([GenericWebRtcAudioCodec::Opus])
}
fn default_canary_trusted_subject() -> String {
    "bridgefu-static-api-key".into()
}
fn default_canary_trusted_issuer() -> String {
    "bridgefu:configured-api-key".into()
}
fn default_canary_correlation_header() -> String {
    "X-Correlation-Id".into()
}
fn default_canary_amazon_profile() -> String {
    "default".into()
}
const fn default_generic_rtp_port_start() -> u16 {
    16_384
}
const fn default_generic_rtp_port_end() -> u16 {
    32_767
}
const fn default_symmetric_rtp_probation() -> u8 {
    3
}
const fn default_symmetric_rtp_rebindings() -> u8 {
    2
}
const fn default_symmetric_rtp_window() -> u64 {
    2
}
const fn default_symmetric_rtp_sequence_jump() -> u16 {
    512
}
const fn default_webrtc_gather_timeout() -> u64 {
    5
}
const fn default_webrtc_connection_timeout() -> u64 {
    15
}

impl Default for ContactCfg {
    fn default() -> Self {
        Self {
            default_display_name: default_display_name(),
            signaling_timeout_secs: default_signaling_timeout(),
            media_connect_timeout_secs: default_media_timeout(),
            keepalive_interval_secs: default_keepalive(),
            session_idle_ttl_secs: default_idle_ttl(),
        }
    }
}
impl Default for MappingCfg {
    fn default() -> Self {
        Self {
            unmapped: default_unmapped(),
            passthrough_prefix: default_prefix(),
            rename: BTreeMap::new(),
        }
    }
}
impl Default for ObsCfg {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            log_format: default_log_format(),
            http_bind: default_http_bind(),
            otlp: OtlpTracingCfg::default(),
        }
    }
}
impl Default for OtlpTracingCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            service_name: default_otlp_service_name(),
            sampling_ratio: default_otlp_sampling_ratio(),
            max_queue_size: default_otlp_max_queue_size(),
            max_export_batch_size: default_otlp_max_export_batch_size(),
            scheduled_delay_millis: default_otlp_scheduled_delay_millis(),
            export_timeout_millis: default_otlp_export_timeout_millis(),
        }
    }
}
impl Default for RuntimeCfg {
    fn default() -> Self {
        Self {
            mode: RuntimeMode::default(),
            max_concurrent_calls: default_max_calls(),
            setup_timeout_secs: default_setup_timeout(),
            media_idle_timeout_secs: default_media_idle_timeout(),
            drain_timeout_secs: default_drain_timeout(),
        }
    }
}
impl Default for PrivateForwardingLimitsCfg {
    fn default() -> Self {
        Self {
            max_active_routes: default_private_active_routes(),
            max_peer_connections: default_private_peer_connections(),
            max_routes_per_peer: default_private_routes_per_peer(),
            media_queue_capacity: default_private_media_queue(),
            reliable_queue_capacity: default_private_reliable_queue(),
            inbound_queue_capacity: default_private_inbound_queue(),
        }
    }
}
impl Default for PrivateForwardingTimeoutsCfg {
    fn default() -> Self {
        Self {
            connect_secs: default_private_connect_timeout(),
            signaling_secs: default_private_signaling_timeout(),
            token_ttl_secs: default_private_token_ttl(),
            health_interval_secs: default_private_health_interval(),
        }
    }
}
impl Default for PersistenceCfg {
    fn default() -> Self {
        Self {
            backend: PersistenceBackend::Sqlite,
            database_url: None,
            worker_id: None,
            allow_ephemeral_memory: false,
            deployment_id: default_deployment_id(),
            worker_lease_ttl_secs: default_worker_lease_ttl(),
            worker_renew_interval_secs: default_worker_renew_interval(),
            worker_capabilities: default_worker_capabilities(),
            redis_url: None,
            redis_clustered: false,
            allow_db_only_coordination: false,
        }
    }
}
impl Default for ApiCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            http_bind: None,
            tls: None,
            bearer_token: None,
            control_hmac_key: None,
            static_tenant: None,
            rate_limit: ApiRateLimitCfg::default(),
            routes: BTreeMap::new(),
            route_attachments: RouteAttachmentCfg::default(),
        }
    }
}

impl Default for ApiRateLimitCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            control_requests_per_second: default_api_control_rate(),
            control_burst: default_api_control_burst(),
            diagnostics_requests_per_second: default_api_diagnostics_rate(),
            diagnostics_burst: default_api_diagnostics_burst(),
            webhook_requests_per_second: default_api_webhook_rate(),
            webhook_burst: default_api_webhook_burst(),
            max_tracked_identities: default_api_tracked_identities(),
            identity_idle_ttl_secs: default_api_identity_idle_ttl(),
        }
    }
}

impl ApiRateLimitCfg {
    fn validate(&self) -> Result<()> {
        for (name, value) in [
            (
                "control_requests_per_second",
                self.control_requests_per_second,
            ),
            (
                "diagnostics_requests_per_second",
                self.diagnostics_requests_per_second,
            ),
            (
                "webhook_requests_per_second",
                self.webhook_requests_per_second,
            ),
        ] {
            if !(1..=MAX_API_REQUESTS_PER_SECOND).contains(&value) {
                return Err(anyhow!(
                    "api.rate_limit.{name} must be between 1 and {MAX_API_REQUESTS_PER_SECOND}"
                ));
            }
        }
        for (name, value) in [
            ("control_burst", self.control_burst),
            ("diagnostics_burst", self.diagnostics_burst),
            ("webhook_burst", self.webhook_burst),
        ] {
            if !(1..=MAX_API_BURST).contains(&value) {
                return Err(anyhow!(
                    "api.rate_limit.{name} must be between 1 and {MAX_API_BURST}"
                ));
            }
        }
        if !(1..=MAX_API_TRACKED_IDENTITIES).contains(&self.max_tracked_identities) {
            return Err(anyhow!(
                "api.rate_limit.max_tracked_identities must be between 1 and {MAX_API_TRACKED_IDENTITIES}"
            ));
        }
        if !(1..=MAX_API_IDENTITY_IDLE_TTL_SECS).contains(&self.identity_idle_ttl_secs) {
            return Err(anyhow!(
                "api.rate_limit.identity_idle_ttl_secs must be between 1 and {MAX_API_IDENTITY_IDLE_TTL_SECS}"
            ));
        }
        Ok(())
    }
}

impl ApiTlsCfg {
    pub fn validate(&self) -> Result<()> {
        for path in [&self.certificate_chain, &self.private_key] {
            if path.is_empty() || path.len() > 4_096 || path.chars().any(char::is_control) {
                return Err(anyhow!("api.tls paths must be bounded and control-free"));
            }
        }
        Ok(())
    }
}
impl Default for BroadcastCfg {
    fn default() -> Self {
        Self {
            default_transport: default_broadcast_transport(),
            token_ttl_secs: default_broadcast_ttl(),
            max_active: default_max_broadcasts(),
            public_endpoint: None,
            token_secret: None,
            uctp_listener: None,
            moq_origin_relay: None,
            sanitized_events: BroadcastSanitizedEventsCfg::default(),
        }
    }
}
impl Default for MoqRelayLimitsCfg {
    fn default() -> Self {
        Self {
            max_pending_admissions: default_moq_pending_admissions(),
            max_active_sessions: default_moq_active_sessions(),
            max_active_sessions_per_tenant: default_moq_tenant_sessions(),
            max_replay_claims: default_moq_replay_claims(),
            max_coordinated_namespaces: default_moq_coordinated_namespaces(),
            max_cached_tracks_per_namespace: default_moq_cached_tracks(),
            max_pending_track_requests_per_namespace: default_moq_pending_tracks(),
            max_upstream_connections: default_moq_upstream_connections(),
            max_upstream_tracks: default_moq_upstream_tracks(),
        }
    }
}
impl Default for MoqRelayTimeoutsCfg {
    fn default() -> Self {
        Self {
            setup_secs: default_moq_setup_timeout(),
            admission_secs: default_moq_admission_timeout(),
            admission_operation_secs: default_moq_admission_operation_timeout(),
            pre_admission_cleanup_secs: default_moq_cleanup_timeout(),
            admission_session_close_secs: default_moq_session_close_timeout(),
            token_revalidation_interval_secs: default_moq_revalidation_interval(),
            upstream_track_idle_secs: default_moq_upstream_track_idle(),
            upstream_connection_idle_secs: default_moq_upstream_connection_idle(),
            drop_cleanup_secs: default_moq_drop_cleanup(),
            dependency_check_interval_secs: default_moq_dependency_check_interval(),
        }
    }
}
impl Default for GenericBridgeCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            sip_bind: default_generic_sip_bind(),
            webrtc_ws_bind: default_webrtc_ws_bind(),
            webrtc_whip_bind: default_webrtc_whip_bind(),
            sip: GenericSipNetworkCfg::default(),
            webrtc: GenericWebRtcNetworkCfg::default(),
            reference_tenant_canary: ReferenceTenantCanaryCfg::default(),
            bearer_token: None,
        }
    }
}

impl Default for GenericSipNetworkCfg {
    fn default() -> Self {
        Self {
            allow_cleartext_bearer: false,
            digest: None,
            advertised_addr: None,
            media_public_addr: None,
            stun_server: None,
            secure_listener: None,
            recipe_contact_uri: None,
            srtp: default_generic_sip_srtp(),
            rtp_port_start: default_generic_rtp_port_start(),
            rtp_port_end: default_generic_rtp_port_end(),
            symmetric_rtp: GenericSymmetricRtpCfg::default(),
        }
    }
}

impl Default for GenericSymmetricRtpCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_ip_change: false,
            probation_packets: default_symmetric_rtp_probation(),
            max_rebindings: default_symmetric_rtp_rebindings(),
            rebind_window_secs: default_symmetric_rtp_window(),
            max_sequence_jump: default_symmetric_rtp_sequence_jump(),
        }
    }
}

impl Default for GenericWebRtcNetworkCfg {
    fn default() -> Self {
        Self {
            udp_bind: default_generic_webrtc_udp_bind(),
            udp_port_range: None,
            audio_codecs: default_generic_webrtc_audio_codecs(),
            ice_servers: None,
            ice_transport_policy: GenericIceTransportPolicy::All,
            nat_1to1_ips: Vec::new(),
            nat_1to1_candidate_type: GenericNatCandidateType::Host,
            gather_timeout_secs: default_webrtc_gather_timeout(),
            connection_timeout_secs: default_webrtc_connection_timeout(),
            trickle_ice: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bridgefu::call_engine::{LegId, PrincipalFingerprint};
    use bridgefu::call_service::{
        AttachmentPrincipalRequest, AttachmentPrincipalResolver, LegExecutionSpec,
        SipEndpointConfig, SipInitialContextMode,
    };

    struct UnusedConnectStarter;

    #[async_trait::async_trait]
    impl ConnectContactStarter for UnusedConnectStarter {
        async fn start_webrtc_contact(
            &self,
            _request: rvoip_amazon_connect::StartContactRequest,
        ) -> rvoip_amazon_connect::Result<rvoip_amazon_connect::ConnectionData> {
            Err(rvoip_amazon_connect::ConnectError::Control(
                "unused config-test starter".into(),
            ))
        }
    }

    /// The B.4 render the reconciler produces for two tenants.
    const B4_TWO_TENANTS: &str = r#"
aws: {"region": "us-west-2"}
sip: {"advertised_ip": "1.2.3.4", "bind_ip": "0.0.0.0", "media_public_ip": "1.2.3.4", "port": 5060}
observability: {"http_bind": "0.0.0.0:9090", "log_format": "json"}
default_tenant: null
tenants:
  "banking": {"contact_flow_id": "flow-banking", "default_display_name": "Vapi caller", "instance_id": "inst-banking", "mapping": {"rename": {"X-Correlation-Id": "correlation_id"}, "unmapped": "drop"}}
  "retail": {"contact_flow_id": "flow-retail", "instance_id": "inst-retail"}
"#;

    /// Today's single-tenant schema (bridgefu.example.yaml shape).
    const LEGACY: &str = r#"
aws:
  region: us-west-2
  instance_id: inst-legacy
  contact_flow_id: flow-legacy
sip: {advertised_ip: 1.2.3.4, media_public_ip: 1.2.3.4}
mapping:
  unmapped: drop
  rename: {X-Correlation-Id: correlation_id}
"#;

    const RECIPE_ONLY: &str = r#"
config_version: 1
aws:
  region: us-west-2
edge:
  public_host: sip.recipe.example
  media_public_addr: 192.0.2.10:0
  sip_tls:
    bind: 127.0.0.1:5061
    advertised_addr: 192.0.2.10:5061
    certificate_chain: /run/bridgefu/tls/fullchain.pem
    private_key: /run/bridgefu/tls/private-key.pem
api:
  enabled: true
  bearer_token: recipe-api-token
  control_hmac_key: 0123456789abcdef0123456789abcdef
recipes:
  support:
    use: builtin:vapi-amazon-connect-screen-pop@1
    with:
      vapi_signaling_cidrs: [198.51.100.0/24]
      connect_instance_arn: arn:aws:connect:us-west-2:123456789012:instance/11111111-1111-1111-1111-111111111111
      connect_entry_contact_flow_id: 22222222-2222-2222-2222-222222222222
      sip_security: sips_srtp
"#;

    const WEBRTC_SIP_RECIPE_ONLY: &str = r#"
config_version: 1
edge:
  public_host: bridge.example.test
  media_public_addr: 192.0.2.20:0
api:
  enabled: true
  bearer_token: recipe-api-token
  control_hmac_key: 0123456789abcdef0123456789abcdef
  tls:
    certificate_chain: /run/bridgefu/tls/fullchain.pem
    private_key: /run/bridgefu/tls/private-key.pem
recipes:
  browser-support:
    use: builtin:webrtc-sip-bridge@1
    with:
      webrtc_signaling_uri: wss://bridge.example.test/webrtc
      sip_target_uri: sips:agents@sbc.example.test:5061;transport=tls
      sip_from_uri: sips:bridgefu@bridge.example.test
      sip_outbound_proxy: sips:sbc.example.test:5061;lr
      sip_security: sips_srtp
"#;

    const SIP_WEBRTC_RECIPE_ONLY: &str = r#"
config_version: 1
edge:
  public_host: sip.bridge.example.test
  media_public_addr: 192.0.2.30:0
  sip_tls:
    bind: 127.0.0.1:5061
    advertised_addr: 192.0.2.30:5061
    certificate_chain: /run/bridgefu/tls/fullchain.pem
    private_key: /run/bridgefu/tls/private-key.pem
api:
  enabled: true
  bearer_token: recipe-api-token
  control_hmac_key: 0123456789abcdef0123456789abcdef
recipes:
  sip-support:
    use: builtin:sip-webrtc-bridge@1
    with:
      sip_signaling_cidrs: [198.51.100.0/24]
      sip_security: sips_srtp
      webrtc_signaling_uri: wss://agents.example.test/signaling
"#;

    const WEBRTC_AMAZON_RECIPE_ONLY: &str = r#"
config_version: 1
aws:
  region: us-west-2
edge:
  public_host: bridge.example.test
  media_public_addr: 192.0.2.40:0
api:
  enabled: true
  bearer_token: recipe-api-token
  control_hmac_key: 0123456789abcdef0123456789abcdef
  tls:
    certificate_chain: /run/bridgefu/tls/fullchain.pem
    private_key: /run/bridgefu/tls/private-key.pem
recipes:
  browser-connect:
    use: builtin:webrtc-amazon-connect-bridge@1
    with:
      webrtc_signaling_uri: wss://bridge.example.test/webrtc
      connect_instance_arn: arn:aws:connect:us-west-2:123456789012:instance/11111111-1111-1111-1111-111111111111
      connect_contact_flow_id: 22222222-2222-2222-2222-222222222222
"#;

    #[test]
    fn recipe_only_config_compiles_into_exact_named_route_without_legacy_listener() {
        let mut config: Config = serde_yaml::from_str(RECIPE_ONLY).unwrap();
        config.apply_recipes().unwrap();
        config.validate().unwrap();
        assert!(!config.legacy_vapi_connect_enabled());
        assert_eq!(config.compiled_recipes.len(), 1);
        assert_eq!(config.api.static_tenant.as_deref(), Some("support"));
        assert_eq!(
            config.api.route_attachments.sip_uri_template.as_deref(),
            Some("sips:{token}@sip.recipe.example:5061;transport=tls")
        );
        let (sip, _) = config
            .generic_sip_stack_config(
                "secure-recipe-contact",
                config.generic_bridge.sip_bind.parse().unwrap(),
            )
            .unwrap();
        assert_eq!(
            sip.contact_uri.as_deref(),
            Some("sips:bridgefu@sip.recipe.example:5061;transport=tls")
        );
        assert_eq!(sip.bind_addr.ip().to_string(), "127.0.0.1");
        assert_eq!(sip.local_ip.to_string(), "0.0.0.0");
        assert!(sip.offer_srtp);
        assert!(sip.srtp_required);
        let debug = format!("{:?}", config.generic_bridge.sip);
        assert!(!debug.contains("sips:bridgefu@sip.recipe.example:5061;transport=tls"));
        assert!(debug.contains("recipe_contact_uri: Some([redacted])"));
        assert_eq!(
            config.context.allow_headers.get("X-Correlation-Id"),
            Some(&"correlation_id".to_owned())
        );
        let route = config.api.routes.get("support").unwrap();
        assert_eq!(route.tenant_id, "support");
        assert_eq!(
            route.sip_ingress_profile.as_deref(),
            Some("recipe-support-sip-ingress")
        );
        assert!(route.vapi_ingress_profile.is_none());
        assert_eq!(
            route.required_sip_correlation_header.as_deref(),
            Some("X-Correlation-Id")
        );
        assert_eq!(
            config
                .sip_ingress_profiles
                .get("recipe-support-sip-ingress")
                .unwrap()
                .security,
            SipIngressSecurity::SipsSrtp
        );
        let resolved = config.resolved_named_routes().unwrap();
        let route = resolved.routes.get("support").unwrap();
        assert_eq!(route.profile_bindings.len(), 2);
        let tenant = config.tenants.get("support").unwrap();
        assert_eq!(tenant.instance_id, "11111111-1111-1111-1111-111111111111");
        assert_eq!(
            tenant.contact_flow_id,
            "22222222-2222-2222-2222-222222222222"
        );
    }

    #[test]
    fn recipe_projection_can_keep_tls_and_prefer_srtp_without_requiring_it() {
        let optional = RECIPE_ONLY.replace(
            "sip_security: sips_srtp",
            "sip_security: sips_optional_srtp",
        );
        let mut config: Config = serde_yaml::from_str(&optional).unwrap();
        config.apply_recipes().unwrap();
        config.validate().unwrap();

        assert_eq!(
            config.api.route_attachments.sip_uri_template.as_deref(),
            Some("sips:{token}@sip.recipe.example:5061;transport=tls")
        );
        assert_eq!(config.generic_bridge.sip.srtp, ProfileSrtpPolicy::Preferred);
        assert!(config.generic_bridge.sip.secure_listener.is_some());
        assert_eq!(
            config
                .sip_ingress_profiles
                .get("recipe-support-sip-ingress")
                .unwrap()
                .security,
            SipIngressSecurity::SipsOptionalSrtp
        );

        let (sip, _) = config
            .generic_sip_stack_config(
                "optional-srtp-recipe",
                config.generic_bridge.sip_bind.parse().unwrap(),
            )
            .unwrap();
        assert_eq!(
            sip.contact_uri.as_deref(),
            Some("sips:bridgefu@sip.recipe.example:5061;transport=tls")
        );
        assert!(sip.offer_srtp);
        assert!(!sip.srtp_required);
    }

    #[tokio::test]
    async fn secure_recipe_contact_is_emitted_on_the_rvoip_uas_200_wire_response() {
        use rvoip_sip_core::{HeaderName, Message, Method, TypedHeader};
        use tokio::net::UdpSocket;

        const EXPECTED_CONTACT: &str = "sips:bridgefu@sip.recipe.example:5061;transport=tls";

        let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let uas_addr = reservation.local_addr().unwrap();
        drop(reservation);

        let mut config: Config = serde_yaml::from_str(RECIPE_ONLY).unwrap();
        config.apply_recipes().unwrap();
        config.validate().unwrap();
        let (mut sip, _) = config
            .generic_sip_stack_config("secure-recipe-contact-wire", uas_addr)
            .unwrap();
        assert_eq!(sip.contact_uri.as_deref(), Some(EXPECTED_CONTACT));

        // The response renderer is transport-independent. Keep the exact
        // recipe-owned Contact while using a signaling-only UDP listener so
        // this regression remains hermetic and needs no private key material.
        sip.sip_tls_mode = rvoip_sip::SipTlsMode::Disabled;
        sip.tls_bind_addr = None;
        sip.tls_advertised_addr = None;
        sip.tls_cert_path = None;
        sip.tls_key_path = None;
        sip.offer_srtp = false;
        sip.srtp_required = false;
        sip.media_mode = rvoip_sip::MediaMode::SignalingOnly { sdp_rtp_port: 9 };
        sip.auto_180_ringing = false;
        sip.fast_auto_accept_incoming_calls = true;

        let coordinator = rvoip_sip::UnifiedCoordinator::new(sip).await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let invite = format!(
            "INVITE sip:bridgefu@{uas_addr} SIP/2.0\r\n\
             Via: SIP/2.0/UDP {client_addr};branch=z9hG4bK-contact-wire;rport\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:probe@{client_addr}>;tag=contact-wire\r\n\
             To: <sip:bridgefu@{uas_addr}>\r\n\
             Call-ID: bridgefu-secure-contact-wire@example.test\r\n\
             CSeq: 1 INVITE\r\n\
             Contact: <sip:probe@{client_addr}>\r\n\
             Content-Length: 0\r\n\r\n"
        );
        client.send_to(invite.as_bytes(), uas_addr).await.unwrap();

        let response = tokio::time::timeout(Duration::from_secs(5), async {
            let mut packet = vec![0_u8; 65_535];
            loop {
                let (length, _) = client.recv_from(&mut packet).await.unwrap();
                let Ok(Message::Response(response)) =
                    rvoip_sip_core::parse_message(&packet[..length])
                else {
                    continue;
                };
                if response.status_code() >= 200
                    && response
                        .cseq()
                        .is_some_and(|cseq| cseq.method() == &Method::Invite)
                {
                    break response;
                }
            }
        })
        .await
        .expect("rvoip UAS did not emit a final INVITE response");

        assert_eq!(response.status_code(), 200);
        let TypedHeader::Contact(contact) = response
            .header(&HeaderName::Contact)
            .expect("rvoip UAS 200 must contain Contact")
        else {
            panic!("rvoip UAS 200 Contact was not typed");
        };
        assert_eq!(
            contact
                .address()
                .expect("one Contact address")
                .uri
                .to_string(),
            EXPECTED_CONTACT
        );

        coordinator
            .shutdown_gracefully(Some(Duration::ZERO))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn optional_srtp_recipe_accepts_a_plain_rtp_avp_offer_without_disabling_tls() {
        use rvoip_sip_core::{Message, Method};
        use tokio::net::UdpSocket;

        let optional = RECIPE_ONLY.replace(
            "sip_security: sips_srtp",
            "sip_security: sips_optional_srtp",
        );
        let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let uas_addr = reservation.local_addr().unwrap();
        drop(reservation);

        let mut config: Config = serde_yaml::from_str(&optional).unwrap();
        config.apply_recipes().unwrap();
        config.validate().unwrap();
        let (mut sip, _) = config
            .generic_sip_stack_config("optional-srtp-plain-offer", uas_addr)
            .unwrap();
        assert!(sip.offer_srtp);
        assert!(!sip.srtp_required);

        // The projection assertions above prove the deployed listener remains
        // TLS-only. This local wire test swaps only the transport fixture to
        // UDP so it can exercise the same rvoip 0.3.7 SDP policy without key
        // material or external network dependencies.
        sip.sip_tls_mode = rvoip_sip::SipTlsMode::Disabled;
        sip.tls_bind_addr = None;
        sip.tls_advertised_addr = None;
        sip.tls_cert_path = None;
        sip.tls_key_path = None;
        sip.media_mode = rvoip_sip::MediaMode::SignalingOnly { sdp_rtp_port: 9 };
        sip.auto_180_ringing = false;
        sip.fast_auto_accept_incoming_calls = true;

        let coordinator = rvoip_sip::UnifiedCoordinator::new(sip).await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 127.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 127.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 40000 RTP/AVP 0 101\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
            "a=rtpmap:101 telephone-event/8000\r\n",
            "a=sendrecv\r\n",
        );
        let invite = format!(
            "INVITE sip:bridgefu@{uas_addr} SIP/2.0\r\n\
             Via: SIP/2.0/UDP {client_addr};branch=z9hG4bK-optional-srtp;rport\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:probe@{client_addr}>;tag=optional-srtp\r\n\
             To: <sip:bridgefu@{uas_addr}>\r\n\
             Call-ID: bridgefu-optional-srtp@example.test\r\n\
             CSeq: 1 INVITE\r\n\
             Contact: <sip:probe@{client_addr}>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\r\n{}",
            sdp.len(),
            sdp
        );
        client.send_to(invite.as_bytes(), uas_addr).await.unwrap();

        let response = tokio::time::timeout(Duration::from_secs(5), async {
            let mut packet = vec![0_u8; 65_535];
            loop {
                let (length, _) = client.recv_from(&mut packet).await.unwrap();
                let Ok(Message::Response(response)) =
                    rvoip_sip_core::parse_message(&packet[..length])
                else {
                    continue;
                };
                if response.status_code() >= 200
                    && response
                        .cseq()
                        .is_some_and(|cseq| cseq.method() == &Method::Invite)
                {
                    break response;
                }
            }
        })
        .await
        .expect("rvoip UAS did not emit a final INVITE response");

        assert_eq!(response.status_code(), 200);
        let answer = std::str::from_utf8(response.body()).unwrap();
        assert!(
            answer.contains("m=audio 9 RTP/AVP"),
            "answer was {answer:?}"
        );
        assert!(!answer.contains("RTP/SAVP"));
        assert!(!answer.contains("a=crypto:"));

        coordinator
            .shutdown_gracefully(Some(Duration::ZERO))
            .await
            .unwrap();
    }

    #[test]
    fn flagship_recipe_projects_one_identical_split_gateway_worker_catalog() {
        let gateway_yaml = RECIPE_ONLY.replace(
                "  control_hmac_key: 0123456789abcdef0123456789abcdef\n",
                "  control_hmac_key: 0123456789abcdef0123456789abcdef\n  http_bind: 127.0.0.1:9080\n  tls:\n    certificate_chain: /run/bridgefu/tls/fullchain.pem\n    private_key: /run/bridgefu/tls/private-key.pem\n",
        ) + r#"
runtime:
  mode: gateway
  max_concurrent_calls: 8
persistence:
  backend: postgres
  database_url: postgres://bridgefu:password@database.internal/bridgefu?sslmode=require
  deployment_id: recipe-ha-test
  worker_capabilities: [amazon_connect]
  redis_url: rediss://bridgefu:password@redis.internal:6379
  redis_clustered: true
broadcast:
  public_endpoint: uctp+quic://sip.recipe.example:4433
  token_secret: split-broadcast-token-secret-32-bytes
private_forwarding:
  enabled: true
  token_signing_secret: private-forwarding-token-secret-32-bytes
  gateway:
    gateway_id: gateway-a
    bind: 0.0.0.0:0
    tls:
      certificate_chain: [/run/bridgefu/tls/gateway.crt]
      private_key: /run/bridgefu/tls/gateway.key
      peer_ca_certificates: [/run/bridgefu/tls/ca.crt]
    public_uctp:
      bind: 127.0.0.1:4433
      tls:
        certificate_chain: [/run/bridgefu/tls/fullchain.pem]
        private_key: /run/bridgefu/tls/private-key.pem
      max_concurrent_connections: 32
    workers:
      - worker_id: 00000000-0000-4000-8000-000000000011
        endpoint: worker.internal:9443
        server_name: worker.internal
"#;
        let worker_yaml = format!(
            r#"{RECIPE_ONLY}
runtime:
  mode: worker
  max_concurrent_calls: 8
persistence:
  backend: postgres
  database_url: postgres://bridgefu:password@database.internal/bridgefu?sslmode=require
  worker_id: 00000000-0000-4000-8000-000000000011
  deployment_id: recipe-ha-test
  worker_capabilities: [amazon_connect]
  redis_url: rediss://bridgefu:password@redis.internal:6379
  redis_clustered: true
broadcast:
  public_endpoint: uctp+quic://sip.recipe.example:4433
  token_secret: split-broadcast-token-secret-32-bytes
private_forwarding:
  enabled: true
  token_signing_secret: private-forwarding-token-secret-32-bytes
  worker:
    bind: 0.0.0.0:9443
    tls:
      certificate_chain: [/run/bridgefu/tls/worker.crt]
      private_key: /run/bridgefu/tls/worker.key
      peer_ca_certificates: [/run/bridgefu/tls/ca.crt]
"#
        );

        let mut gateway: Config = serde_yaml::from_str(&gateway_yaml).unwrap();
        gateway.apply_recipes().unwrap();
        gateway.validate().unwrap();
        let gateway_catalog = gateway.resolved_named_routes().unwrap();

        let mut worker: Config = serde_yaml::from_str(&worker_yaml).unwrap();
        worker.apply_recipes().unwrap();
        worker.validate().unwrap();
        assert!(!worker.api.enabled);
        assert!(!worker.generic_bridge.enabled);
        let worker_catalog = worker.resolved_named_routes().unwrap();
        assert_eq!(
            gateway.call_worker_capabilities(),
            worker.call_worker_capabilities()
        );
        assert_eq!(gateway_catalog.routes.len(), worker_catalog.routes.len());
        for (route_id, gateway_route) in gateway_catalog.routes {
            let worker_route = worker_catalog.routes.get(&route_id).unwrap();
            assert_eq!(gateway_route.tenant_id, worker_route.tenant_id);
            assert_eq!(gateway_route.ingress, worker_route.ingress);
            assert_eq!(
                serde_json::to_vec(&gateway_route.destination).unwrap(),
                serde_json::to_vec(&worker_route.destination).unwrap()
            );
            assert_eq!(
                gateway_route
                    .profile_bindings
                    .iter()
                    .map(|value| serde_json::to_vec(value).unwrap())
                    .collect::<Vec<_>>(),
                worker_route
                    .profile_bindings
                    .iter()
                    .map(|value| serde_json::to_vec(value).unwrap())
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                gateway_route.context_metadata_allowlist,
                worker_route.context_metadata_allowlist
            );
            assert_eq!(
                gateway_route.context_required,
                worker_route.context_required
            );
            assert_eq!(
                gateway_route.capability_policy.audio_codecs,
                worker_route.capability_policy.audio_codecs
            );
        }
    }

    #[test]
    fn recipe_projection_supports_explicit_sip_rtp_compatibility_posture() {
        let clear = RECIPE_ONLY
            .replace(
                "  sip_tls:\n    bind: 127.0.0.1:5061\n    advertised_addr: 192.0.2.10:5061\n    certificate_chain: /run/bridgefu/tls/fullchain.pem\n    private_key: /run/bridgefu/tls/private-key.pem\n",
                "  sip_rtp:\n    bind: 127.0.0.1:5060\n    advertised_addr: 192.0.2.10:5060\n",
            )
            .replace("sip_security: sips_srtp", "sip_security: sip_rtp");
        let mut config: Config = serde_yaml::from_str(&clear).unwrap();
        config.apply_recipes().unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.api.route_attachments.sip_uri_template.as_deref(),
            Some("sip:{token}@sip.recipe.example:5060")
        );
        assert_eq!(config.generic_bridge.sip.srtp, ProfileSrtpPolicy::Disabled);
        assert!(config.generic_bridge.sip.secure_listener.is_none());
        let (sip, _) = config
            .generic_sip_stack_config(
                "plain-recipe-contact",
                config.generic_bridge.sip_bind.parse().unwrap(),
            )
            .unwrap();
        assert!(sip.contact_uri.is_none());
        assert_eq!(
            sip.sip_advertised_addr.unwrap().to_string(),
            "192.0.2.10:5060"
        );
        assert!(!sip.offer_srtp);
        assert!(!sip.srtp_required);
        assert_eq!(
            config
                .sip_ingress_profiles
                .get("recipe-support-sip-ingress")
                .unwrap()
                .security,
            SipIngressSecurity::SipRtp
        );
    }

    #[test]
    fn secure_recipe_contact_requires_dns_while_plain_recipe_retains_ip_support() {
        let secure = RECIPE_ONLY.replace("sip.recipe.example", "192.0.2.10");
        let mut config: Config = serde_yaml::from_str(&secure).unwrap();
        let error = config.apply_recipes().unwrap_err().to_string();
        assert!(error.contains("bounded DNS name for SIPS recipes"));

        let clear = secure
            .replace(
                "  sip_tls:\n    bind: 127.0.0.1:5061\n    advertised_addr: 192.0.2.10:5061\n    certificate_chain: /run/bridgefu/tls/fullchain.pem\n    private_key: /run/bridgefu/tls/private-key.pem\n",
                "  sip_rtp:\n    bind: 127.0.0.1:5060\n    advertised_addr: 192.0.2.10:5060\n",
            )
            .replace("sip_security: sips_srtp", "sip_security: sip_rtp");
        let mut config: Config = serde_yaml::from_str(&clear).unwrap();
        config.apply_recipes().unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn clear_recipe_projection_builds_an_exact_stable_uri_catalog() {
        let clear = RECIPE_ONLY
            .replace(
                "  sip_tls:\n    bind: 127.0.0.1:5061\n    advertised_addr: 192.0.2.10:5061\n    certificate_chain: /run/bridgefu/tls/fullchain.pem\n    private_key: /run/bridgefu/tls/private-key.pem\n",
                "  sip_rtp:\n    bind: 127.0.0.1:5060\n    advertised_addr: 192.0.2.10:5060\n",
            )
            .replace("sip_security: sips_srtp", "sip_security: sip_rtp");
        let mut config: Config = serde_yaml::from_str(&clear).unwrap();
        config.apply_recipes().unwrap();
        let admission = config
            .api
            .routes
            .get_mut("support")
            .unwrap()
            .recipe_sip_admission
            .as_mut()
            .unwrap();
        admission.mode = SipAdmissionMode::StableUri;
        admission.uri_user = Some("fixed-support".to_owned());
        config.validate().unwrap();
        let catalog = config.recipe_sip_admission_catalog().unwrap().unwrap();
        assert_eq!(catalog.len(), 1);
        assert!(!format!("{catalog:?}").contains("bridgefu-recipe:support"));
    }

    #[test]
    fn recipe_projection_supports_webrtc_to_digest_ready_sips() {
        let mut config: Config = serde_yaml::from_str(WEBRTC_SIP_RECIPE_ONLY).unwrap();
        config.apply_recipes().unwrap();
        config.validate().unwrap();
        let route = config.api.routes.get("browser-support").unwrap();
        assert_eq!(route.ingress, BTreeSet::from([NamedRouteIngress::Webrtc]));
        assert_eq!(
            route.webrtc_ingress_profile.as_deref(),
            Some("recipe-browser-support-webrtc-ingress")
        );
        assert!(matches!(
            route.destination_profile,
            Some(RouteDestinationProfileRef::Sip { .. })
        ));
        assert!(config.generic_bridge.sip_bind.starts_with("127.0.0.1:"));
        assert_eq!(
            config.generic_bridge.sip.media_public_addr.as_deref(),
            Some("192.0.2.20:0")
        );
        let (sip, _) = config
            .generic_sip_stack_config(
                "webrtc-sip-public-media",
                config.generic_bridge.sip_bind.parse().unwrap(),
            )
            .unwrap();
        assert_eq!(sip.bind_addr.ip().to_string(), "127.0.0.1");
        assert_eq!(sip.local_ip.to_string(), "0.0.0.0");
        let egress = config
            .sip_egress_profile_configs(
                "webrtc-sip-public-media",
                config.generic_bridge.sip_bind.parse().unwrap(),
            )
            .unwrap();
        assert_eq!(egress.len(), 1);
        assert_eq!(egress[0].stack.bind_addr.ip().to_string(), "127.0.0.1");
        assert_eq!(egress[0].stack.local_ip.to_string(), "0.0.0.0");
        assert_eq!(
            egress[0].stack.media_public_addr.unwrap().to_string(),
            "192.0.2.20:0"
        );
        assert_eq!(
            config
                .context
                .allow_headers
                .get("X-Correlation-Id")
                .map(String::as_str),
            Some("correlation_id")
        );
        let tenant = config.tenants.get("browser-support").unwrap();
        assert!(tenant.routing_only);
        assert!(tenant.instance_id.is_empty());
        assert!(config.resolved_named_routes().is_ok());
    }

    #[test]
    fn recipe_projection_supports_sips_to_interactive_webrtc() {
        let mut config: Config = serde_yaml::from_str(SIP_WEBRTC_RECIPE_ONLY).unwrap();
        config.apply_recipes().unwrap();
        config.validate().unwrap();
        let route = config.api.routes.get("sip-support").unwrap();
        assert_eq!(route.ingress, BTreeSet::from([NamedRouteIngress::Sip]));
        assert_eq!(
            route.sip_ingress_profile.as_deref(),
            Some("recipe-sip-support-sip-ingress")
        );
        assert!(matches!(
            route.destination_profile,
            Some(RouteDestinationProfileRef::Webrtc { .. })
        ));
        assert_eq!(config.generic_bridge.webrtc_ws_bind, "127.0.0.1:0");
        assert_eq!(
            config.api.route_attachments.sip_uri_template.as_deref(),
            Some("sips:{token}@sip.bridge.example.test:5061;transport=tls")
        );
        assert!(config.resolved_named_routes().is_ok());
    }

    #[test]
    fn recipe_projection_supports_webrtc_to_amazon_connect_with_bounded_context() {
        let mut config: Config = serde_yaml::from_str(WEBRTC_AMAZON_RECIPE_ONLY).unwrap();
        config.apply_recipes().unwrap();
        config.validate().unwrap();
        let route = config.api.routes.get("browser-connect").unwrap();
        assert_eq!(route.ingress, BTreeSet::from([NamedRouteIngress::Webrtc]));
        assert!(matches!(
            route.destination_profile,
            Some(RouteDestinationProfileRef::AmazonConnect { .. })
        ));
        assert!(route.destination.amazon_connect_start.is_some());
        for key in [
            "correlation_id",
            "customer_name",
            "issue_summary",
            "intent",
            "verification_status",
            "source_call_reference",
        ] {
            assert!(config.context.allow_metadata_keys.contains(key));
        }
        let tenant = config.tenants.get("browser-connect").unwrap();
        assert!(!tenant.routing_only);
        assert_eq!(tenant.instance_id, "11111111-1111-1111-1111-111111111111");
        let resolved = config.resolved_named_routes().unwrap();
        assert_eq!(
            resolved
                .routes
                .get("browser-connect")
                .unwrap()
                .context_metadata_allowlist,
            Some(config.context.allow_metadata_keys.clone())
        );
    }

    #[test]
    fn webrtc_recipe_refuses_to_advertise_wss_without_tls() {
        let without_tls = WEBRTC_SIP_RECIPE_ONLY.replace(
            "  tls:\n    certificate_chain: /run/bridgefu/tls/fullchain.pem\n    private_key: /run/bridgefu/tls/private-key.pem\n",
            "",
        );
        let mut config: Config = serde_yaml::from_str(&without_tls).unwrap();
        let error = config.apply_recipes().unwrap_err().to_string();
        assert!(error.contains("api.tls is required"));
    }

    #[test]
    fn config_load_applies_recipe_projection_before_semantic_validation() {
        let path = std::env::temp_dir().join(format!(
            "bridgefu-recipe-config-{}.yaml",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, RECIPE_ONLY).unwrap();
        let config = Config::load(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(config.compiled_recipes.len(), 1);
        assert!(config.api.routes.contains_key("support"));
        assert!(!config.legacy_vapi_connect_enabled());
    }

    #[test]
    fn recipe_projection_rejects_region_and_route_collisions() {
        let mut wrong_region: Config = serde_yaml::from_str(
            &RECIPE_ONLY.replace("arn:aws:connect:us-west-2", "arn:aws:connect:us-east-1"),
        )
        .unwrap();
        assert!(wrong_region
            .apply_recipes()
            .unwrap_err()
            .to_string()
            .contains("region"));

        let mut collision: Config = serde_yaml::from_str(&format!(
            "{RECIPE_ONLY}\ntenants:\n  support: {{instance_id: existing, contact_flow_id: existing}}\n"
        ))
        .unwrap();
        assert!(collision
            .apply_recipes()
            .unwrap_err()
            .to_string()
            .contains("collides"));
    }

    #[test]
    fn split_worker_amazon_adapter_does_not_parse_or_resolve_public_sip() {
        let mut config = parse(LEGACY);
        config.sip.bind_ip = "not-an-ip".into();
        config.sip.advertised_ip = "not-a-resolvable-public-address".into();
        config.sip.media_public_ip = "not-a-resolvable-media-address".into();

        let starter: Arc<dyn ConnectContactStarter> = Arc::new(UnusedConnectStarter);
        let adapter = config
            .build_worker_amazon_connect_adapter_with_starter(starter)
            .expect("worker construction is independent of public SIP");
        assert_eq!(adapter.configured_profile_count(), 1);
    }

    #[test]
    fn recipe_amazon_adapter_registers_every_projected_profile() {
        let mut config: Config = serde_yaml::from_str(RECIPE_ONLY).unwrap();
        config.apply_recipes().unwrap();
        let starter: Arc<dyn ConnectContactStarter> = Arc::new(UnusedConnectStarter);
        let adapter = config
            .build_worker_amazon_connect_adapter_with_starter(starter)
            .expect("recipe Amazon profile catalog");
        assert_eq!(adapter.configured_profile_count(), 2);
    }

    #[test]
    fn public_uctp_listener_config_is_explicit_and_runtime_ready() {
        let listener: PublicUctpListenerCfg = serde_yaml::from_str(
            r#"
bind: 127.0.0.1:4446
max_concurrent_connections: 321
tls:
  certificate_chain: [/run/tls/uctp.pem]
  private_key: /run/tls/uctp.key
"#,
        )
        .unwrap();
        listener.validate().unwrap();
        let runtime = listener.runtime().unwrap();
        assert_eq!(
            runtime.bind,
            "127.0.0.1:4446".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(runtime.max_concurrent_connections, 321);
        assert_eq!(runtime.certificate_chain.len(), 1);
        assert!(format!("{runtime:?}").contains("private_key_configured: true"));
        assert!(!format!("{runtime:?}").contains("uctp.key"));
    }

    #[test]
    fn private_forwarding_defaults_support_one_thousand_direct_listener_routes() {
        let limits = PrivateForwardingLimitsCfg::default();
        assert_eq!(limits.max_active_routes, 2_000);
        assert_eq!(limits.max_routes_per_peer, 1_200);
        assert!(limits.max_active_routes >= 1_000);
        assert!(limits.max_routes_per_peer >= 1_000);
        limits.validate(default_max_calls()).unwrap();
    }

    #[test]
    fn public_uctp_endpoint_and_listener_reject_ambiguous_configuration() {
        assert!(validate_public_uctp_endpoint("uctp+quic://bridge.example:4446").is_ok());
        for invalid in [
            "https://bridge.example:4446",
            "uctp+quic://bridge.example",
            "uctp+quic://user@bridge.example:4446",
            "uctp+quic://bridge.example:4446/path",
        ] {
            assert!(validate_public_uctp_endpoint(invalid).is_err(), "{invalid}");
        }
        let zero_bind: PublicUctpListenerCfg = serde_yaml::from_str(
            r#"
bind: 127.0.0.1:0
tls:
  certificate_chain: [/run/tls/uctp.pem]
  private_key: /run/tls/uctp.key
"#,
        )
        .unwrap();
        assert!(zero_bind.validate().is_err());
    }

    #[test]
    fn moq_origin_relay_separates_private_publisher_and_public_subscriber_endpoints() {
        let valid: MoqOriginRelayCfg = serde_yaml::from_str(
            r#"
bind: 127.0.0.1:0
publisher_endpoint: moqt://relay.internal.invalid:4443
subscriber_endpoint: https://relay.public.invalid:4444
root_certificates: [/run/tls/relay-ca.pem]
client_certificate: /run/tls/origin.pem
client_private_key: /run/tls/origin.key
"#,
        )
        .unwrap();
        valid.validate().unwrap();

        let same: MoqOriginRelayCfg = serde_yaml::from_str(
            r#"
bind: 127.0.0.1:0
publisher_endpoint: moqt://relay.invalid:4443
subscriber_endpoint: moqt://relay.invalid:4443
root_certificates: [/run/tls/relay-ca.pem]
client_certificate: /run/tls/origin.pem
client_private_key: /run/tls/origin.key
"#,
        )
        .unwrap();
        assert!(same.validate().is_err());
    }

    const MOQ_RELAY: &str = r#"
runtime: {mode: moq-relay}
api: {enabled: false}
persistence:
  deployment_id: relay-test
  redis_url: rediss://redis.invalid
  redis_clustered: true
broadcast:
  token_secret: 0123456789abcdef0123456789abcdef
moq_relay:
  publisher:
    bind: 127.0.0.1:4443
    advertised_endpoint: moqt://relay.invalid:4443
    certificate_bindings:
      - certificate_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        scope: /tenant-a/broadcast-a
  subscriber_webtransport:
    bind: 127.0.0.1:4444
    advertised_endpoint: moqt://relay.invalid:4444
  subscriber_raw_quic:
    bind: 127.0.0.1:4445
    advertised_endpoint: moqt://relay.invalid:4445
  tls:
    server_certificates: [/run/tls/server.pem]
    server_private_keys: [/run/tls/server.key]
    publisher_client_ca_certificates: [/run/tls/publisher-ca.pem]
  diagnostics_bearer_token: 0123456789abcdef0123456789abcdef
"#;

    fn parse(yaml: &str) -> Config {
        serde_yaml::from_str(yaml).expect("yaml parses")
    }

    fn vapi_projection_yaml() -> String {
        format!(
            r#"{LEGACY}
api:
  enabled: true
  bearer_token: shared-private
  control_hmac_key: 0123456789abcdef0123456789abcdef
  static_tenant: default
  route_attachments:
    sip_uri_template: "sips:{{token}}@bridge.example.test:5061;transport=tls"
  routes:
    support:
      tenant_id: default
      ingress: [sip]
      vapi_ingress_profile: vapi-public
      destination_profile:
        type: sip
        profile_id: support-sbc
      destination:
        direction: outbound
        signaling_initiator: bridgefu
        media_flow: send_receive
        endpoint:
          type: sip
          config:
            uri: "sips:agent@support.example.test:5061;transport=tls"
vapi_ingress_profiles:
  vapi-public:
    tenant_id: default
    principal_subject: vapi-edge
    issuer: vapi-managed
    scopes: [calls:create]
    trusted_signaling_cidrs: [192.0.2.0/24]
    tls:
      certificate_chain: /run/tls/sip.pem
      private_key: /run/tls/sip-key.pem
    srtp_required: true
    codecs: [pcmu, opus]
sip_profiles:
  support-sbc:
    allowed_targets: ["sips:agent@support.example.test:5061;transport=tls"]
    from_uri: "sips:bridgefu@bridge.example.test"
    srtp: required
    codecs: [pcmu, opus]
    metadata_keys: [correlation_id]
context:
  allow_headers:
    X-Correlation-Id: correlation_id
generic_bridge:
  enabled: true
  sip_bind: 127.0.0.1:5070
  sip:
    secure_listener:
      bind: 127.0.0.1:5061
      certificate_chain: /run/tls/sip.pem
      private_key: /run/tls/sip-key.pem
    srtp: required
    symmetric_rtp:
      enabled: true
      allow_ip_change: true
      probation_packets: 5
      max_rebindings: 4
      rebind_window_secs: 6
      max_sequence_jump: 900
"#
        )
    }

    #[test]
    fn media_idle_timeout_defaults_and_rejects_zero() {
        let defaults = parse(LEGACY);
        assert_eq!(defaults.runtime.media_idle_timeout_secs, 30);
        defaults.validate().unwrap();

        let invalid = parse(&format!(
            "{LEGACY}\nruntime:\n  media_idle_timeout_secs: 0\n"
        ));
        assert!(invalid
            .validate()
            .unwrap_err()
            .to_string()
            .contains("media_idle_timeout_secs must be greater than zero"));
    }

    #[test]
    fn role_separated_moq_relay_configuration_is_complete_and_bounded() {
        let config = parse(&format!("{LEGACY}\n{MOQ_RELAY}"));
        config.validate().unwrap();
        let relay = config.moq_relay.unwrap();
        assert_eq!(relay.limits.max_active_sessions, 2_048);
        assert_eq!(relay.limits.max_active_sessions_per_tenant, 1_000);
        assert_eq!(relay.timeouts.token_revalidation_interval_secs, 15);

        let duplicate = parse(&format!(
            "{LEGACY}\n{}",
            MOQ_RELAY.replace("127.0.0.1:4445", "127.0.0.1:4444")
        ));
        assert!(duplicate
            .validate()
            .unwrap_err()
            .to_string()
            .contains("require distinct binds"));

        let weak_diagnostics = parse(&format!(
            "{LEGACY}\n{}",
            MOQ_RELAY.replace(
                "diagnostics_bearer_token: 0123456789abcdef0123456789abcdef",
                "diagnostics_bearer_token: too-short"
            )
        ));
        assert!(weak_diagnostics
            .validate()
            .unwrap_err()
            .to_string()
            .contains("diagnostics_bearer_token must resolve to 32 to 4096 bytes"));
    }

    #[test]
    fn config_v1_scalar_bounds_are_enforced_by_runtime_validation() {
        let mut config = parse(LEGACY);
        config.aws.region.clear();
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("aws.region must not be empty"));

        let mut config = parse(LEGACY);
        config.sip.port = 0;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("sip.port must be greater than zero"));

        for field in ["signaling", "media", "keepalive", "idle"] {
            let mut config = parse(LEGACY);
            match field {
                "signaling" => config.contact.signaling_timeout_secs = 0,
                "media" => config.contact.media_connect_timeout_secs = 0,
                "keepalive" => config.contact.keepalive_interval_secs = 0,
                "idle" => config.contact.session_idle_ttl_secs = 0,
                _ => unreachable!(),
            }
            assert!(config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("contact timeout and interval values must be greater than zero"));
        }

        for field in ["setup", "drain"] {
            let mut config = parse(LEGACY);
            match field {
                "setup" => config.runtime.setup_timeout_secs = 0,
                "drain" => config.runtime.drain_timeout_secs = 0,
                _ => unreachable!(),
            }
            let error = config.validate().unwrap_err().to_string();
            assert!(error.contains(&format!(
                "runtime.{field}_timeout_secs must be greater than zero"
            )));
        }

        let mut config = parse(LEGACY);
        config.observability.log_level.clear();
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("observability.log_level must not be empty"));

        let mut config = parse(LEGACY);
        config.observability.log_format = "human-ish".into();
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("observability.log_format must be json or pretty"));

        let mut config = parse(LEGACY);
        config.observability.http_bind = "not-a-socket".into();
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("observability.http_bind must be a socket address"));

        let mut config = parse(LEGACY);
        config.broadcast.token_ttl_secs = 0;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("broadcast.token_ttl_secs must be between 1 and 900"));

        let mut config = parse(LEGACY);
        config.broadcast.token_ttl_secs = 901;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("broadcast.token_ttl_secs must be between 1 and 900"));

        let mut config = parse(LEGACY);
        config.broadcast.token_secret =
            Some(serde_yaml::from_str("'too-short'").expect("secret ref parses"));
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("broadcast.token_secret must resolve to at least 32 bytes"));

        let mut config = parse(LEGACY);
        config
            .context
            .allow_headers
            .insert("Authorization".into(), "unsafe".into());
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("validating context allowlist"));
    }

    #[test]
    fn sanitized_moq_events_are_default_off_and_require_exact_tenant_and_header_policy() {
        let default = parse(LEGACY);
        assert!(default.broadcast.sanitized_events.tenants.is_empty());
        assert!(default
            .broadcast
            .sanitized_events
            .policies(&default.context)
            .unwrap()
            .is_empty());
        default.validate().unwrap();

        let valid = parse(&format!(
            r#"{LEGACY}
context:
  allow_headers:
    X-Bridgefu-Event: broadcast_event
broadcast:
  sanitized_events:
    tenants:
      default:
        context_metadata_key: broadcast_event
        queue_events: 16
        history_events: 8
        max_events_per_second: 4
"#
        ));
        valid.validate().unwrap();
        let policies = valid
            .broadcast
            .sanitized_events
            .policies(&valid.context)
            .unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies["default"].max_events_per_second(), 4);

        let unmapped = parse(&format!(
            r#"{LEGACY}
broadcast:
  sanitized_events:
    tenants:
      default:
        context_metadata_key: broadcast_event
"#
        ));
        assert!(unmapped
            .validate()
            .unwrap_err()
            .to_string()
            .contains("not mapped by context.allow_headers"));

        let foreign_tenant = parse(&format!(
            r#"{LEGACY}
context:
  allow_headers:
    X-Bridgefu-Event: broadcast_event
broadcast:
  sanitized_events:
    tenants:
      another-tenant:
        context_metadata_key: broadcast_event
"#
        ));
        assert!(foreign_tenant
            .validate()
            .unwrap_err()
            .to_string()
            .contains("is not a configured routing tenant"));

        let identifier_override = parse(&format!(
            r#"{LEGACY}
context:
  allow_headers:
    X-Correlation-Id: correlation_id
broadcast:
  sanitized_events:
    tenants:
      default:
        context_metadata_key: correlation_id
"#
        ));
        assert!(identifier_override.validate().is_err());
    }

    #[test]
    fn otlp_is_disabled_without_a_collector_by_default() {
        let config = parse(LEGACY);
        assert!(!config.observability.otlp.enabled);
        assert!(config.observability.otlp.endpoint.is_none());
        config.validate().unwrap();
    }

    #[test]
    fn enabled_otlp_requires_safe_endpoint_service_and_sampling() {
        let mut config = parse(LEGACY);
        config.observability.otlp.enabled = true;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("endpoint is required"));

        config.observability.otlp.endpoint = Some("https://collector.example:4317".into());
        config.validate().unwrap();

        config.observability.otlp.endpoint = Some("https://token@collector.example:4317".into());
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("without credentials, path, query, or fragment"));

        config.observability.otlp.endpoint = Some("https://collector.example:4317".into());
        config.observability.otlp.service_name = "   ".into();
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("service_name"));

        config.observability.otlp.service_name = "bridgefu-test".into();
        config.observability.otlp.sampling_ratio = 1.01;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("sampling_ratio"));

        config.observability.otlp.sampling_ratio = f64::NAN;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("sampling_ratio"));
    }

    #[test]
    fn otlp_batching_is_explicitly_bounded() {
        let mut config = parse(LEGACY);
        config.observability.otlp.max_queue_size = MAX_OTLP_QUEUE_SIZE + 1;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("max_queue_size"));

        config.observability.otlp.max_queue_size = 10;
        config.observability.otlp.max_export_batch_size = 11;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("no greater than max_queue_size"));

        config.observability.otlp.max_export_batch_size = 10;
        config.observability.otlp.scheduled_delay_millis = 0;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("scheduled_delay_millis"));

        config.observability.otlp.scheduled_delay_millis = MIN_OTLP_SCHEDULE_DELAY_MILLIS;
        config.observability.otlp.export_timeout_millis = MAX_OTLP_EXPORT_TIMEOUT_MILLIS + 1;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("export_timeout_millis"));
    }

    #[test]
    fn config_v1_compatibility_fixture_preserves_model_defaults() {
        let value: serde_yaml::Value =
            serde_yaml::from_str(include_str!("../config/fixtures/config-v1.yaml")).unwrap();
        let config = deserialize_strict(
            &value,
            std::path::Path::new("config/fixtures/config-v1.yaml"),
        )
        .unwrap();
        config.validate().unwrap();
        config.resolved_tenants().unwrap();

        assert_eq!(config.config_version, 1);
        assert_eq!(config.runtime.mode, RuntimeMode::AllInOne);
        assert_eq!(config.runtime.max_concurrent_calls, 100);
        assert_eq!(config.broadcast.default_transport, "moqt");
        assert_eq!(config.broadcast.token_ttl_secs, 300);
        assert_eq!(config.persistence.backend, PersistenceBackend::Sqlite);
        assert!(config.api.enabled);
        assert!(config.api.rate_limit.enabled);
        assert_eq!(config.api.rate_limit.control_requests_per_second, 50);
        assert_eq!(config.api.rate_limit.control_burst, 100);
        assert_eq!(config.api.rate_limit.diagnostics_requests_per_second, 2);
        assert_eq!(config.api.rate_limit.diagnostics_burst, 4);
        assert_eq!(config.api.rate_limit.webhook_requests_per_second, 100);
        assert_eq!(config.api.rate_limit.webhook_burst, 200);
        assert_eq!(config.api.rate_limit.max_tracked_identities, 10_000);
        assert_eq!(config.api.rate_limit.identity_idle_ttl_secs, 300);
        assert!(!config.generic_bridge.enabled);
        assert!(!config.generic_bridge.sip.allow_cleartext_bearer);
        assert!(!config.observability.otlp.enabled);
        assert!(config.observability.otlp.endpoint.is_none());
    }

    #[test]
    fn api_rate_limit_policy_is_strictly_bounded() {
        let mut config = parse(LEGACY);
        config.api.rate_limit.control_requests_per_second = 0;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("control_requests_per_second"));

        config.api.rate_limit.control_requests_per_second = 1;
        config.api.rate_limit.diagnostics_burst = MAX_API_BURST + 1;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("diagnostics_burst"));

        config.api.rate_limit.diagnostics_burst = 1;
        config.api.rate_limit.max_tracked_identities = 0;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("max_tracked_identities"));

        config.api.rate_limit.max_tracked_identities = 1;
        config.api.rate_limit.identity_idle_ttl_secs = MAX_API_IDENTITY_IDLE_TTL_SECS + 1;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("identity_idle_ttl_secs"));
    }

    #[test]
    fn runtime_mode_is_typed_defaults_and_rejects_unknown_values() {
        let defaults = parse(LEGACY);
        assert_eq!(defaults.runtime.mode, RuntimeMode::AllInOne);
        assert_eq!(defaults.runtime.mode.as_str(), "all-in-one");

        for (value, expected) in [
            ("all-in-one", RuntimeMode::AllInOne),
            ("gateway", RuntimeMode::Gateway),
            ("worker", RuntimeMode::Worker),
            ("moq-relay", RuntimeMode::MoqRelay),
        ] {
            let parsed: Config =
                serde_yaml::from_str(&format!("{LEGACY}\nruntime:\n  mode: {value}\n")).unwrap();
            assert_eq!(parsed.runtime.mode, expected);
            assert_eq!(parsed.runtime.mode.to_string(), value);
        }

        let error = serde_yaml::from_str::<Config>(&format!(
            "{LEGACY}\nruntime:\n  mode: accidental-fallback\n"
        ))
        .unwrap_err()
        .to_string();
        assert!(error.contains("unknown variant"));
        assert!(error.contains("accidental-fallback"));
    }

    #[test]
    fn b4_schema_resolves_two_tenants_no_default() {
        let cfg = parse(B4_TWO_TENANTS);
        let (table, default) = cfg.resolved_tenants().unwrap();
        assert_eq!(
            table.keys().cloned().collect::<Vec<_>>(),
            vec!["banking", "retail"]
        );
        assert_eq!(default, None);

        let banking = &table["banking"];
        assert_eq!(banking.label, "banking");
        assert_eq!(banking.instance_id.as_deref(), Some("inst-banking"));
        assert_eq!(banking.contact_flow_id.as_deref(), Some("flow-banking"));
        assert_eq!(banking.default_display_name.as_deref(), Some("Vapi caller"));
        let mapping = banking.attribute_mapping.as_ref().unwrap();
        assert_eq!(
            mapping.rename.get("X-Correlation-Id").unwrap(),
            "correlation_id"
        );
        assert_eq!(mapping.unmapped, UnmappedPolicy::Drop);

        // retail has no mapping block → inherits the (default) top-level one.
        let retail = &table["retail"];
        assert_eq!(retail.default_display_name, None);
        assert_eq!(
            retail.attribute_mapping.as_ref().unwrap().unmapped,
            UnmappedPolicy::Drop // top-level default is `drop`
        );
    }

    #[test]
    fn match_order_is_ruri_then_to_then_default() {
        let cfg = parse(B4_TWO_TENANTS);
        let (table, _) = cfg.resolved_tenants().unwrap();

        // R-URI wins over To.
        let hit = match_tenant(&table, None, Some("banking"), Some("retail")).unwrap();
        assert_eq!(hit.label, "banking");
        // Unknown R-URI user falls through to To.
        let hit = match_tenant(&table, None, Some("nope"), Some("retail")).unwrap();
        assert_eq!(hit.label, "retail");
        // Nothing matches, no default → None (→ 404).
        assert!(match_tenant(&table, None, Some("nope"), Some("also-nope")).is_none());
        assert!(match_tenant(&table, None, None, None).is_none());
        // default_tenant catches the rest.
        let hit = match_tenant(&table, Some("banking"), Some("nope"), None).unwrap();
        assert_eq!(hit.label, "banking");
    }

    #[test]
    fn legacy_schema_becomes_catch_all_default_tenant() {
        let cfg = parse(LEGACY);
        let (table, default) = cfg.resolved_tenants().unwrap();
        assert_eq!(table.len(), 1);
        assert_eq!(default.as_deref(), Some(LEGACY_TENANT));
        let route = &table[LEGACY_TENANT];
        assert_eq!(route.instance_id.as_deref(), Some("inst-legacy"));
        assert_eq!(route.contact_flow_id.as_deref(), Some("flow-legacy"));
        // Any user part routes to it via the default.
        let hit = match_tenant(&table, default.as_deref(), Some("bridgefu"), None).unwrap();
        assert_eq!(hit.label, LEGACY_TENANT);
    }

    #[test]
    fn single_tenant_b4_render_with_legacy_keys_prefers_tenants() {
        // The reconciler's single-tenant render carries BOTH the tenants map
        // and the legacy aws keys; the tenants map must win.
        let yaml = r#"
aws: {"region": "us-west-2", "instance_id": "inst-x", "contact_flow_id": "flow-x"}
sip: {advertised_ip: 1.2.3.4, media_public_ip: 1.2.3.4}
default_tenant: null
contact: {"default_display_name": "Vapi caller"}
mapping: {"rename": {"X-Correlation-Id": "correlation_id"}, "unmapped": "drop"}
tenants:
  "banking": {"contact_flow_id": "flow-x", "instance_id": "inst-x", "mapping": {"unmapped": "drop"}}
"#;
        let cfg = parse(yaml);
        let (table, default) = cfg.resolved_tenants().unwrap();
        assert_eq!(table.keys().cloned().collect::<Vec<_>>(), vec!["banking"]);
        assert_eq!(default, None); // explicit null → unmatched user parts get 404
    }

    #[test]
    fn zero_tenants_is_valid_and_rejects_everything() {
        let yaml = r#"
aws: {"region": "us-west-2"}
sip: {advertised_ip: 1.2.3.4, media_public_ip: 1.2.3.4}
default_tenant: null
tenants: {}
"#;
        let cfg = parse(yaml);
        let (table, default) = cfg.resolved_tenants().unwrap();
        assert!(table.is_empty());
        assert_eq!(default, None);
        assert!(match_tenant(&table, default.as_deref(), Some("any"), None).is_none());
    }

    #[test]
    fn bad_default_tenant_is_rejected() {
        let yaml = r#"
aws: {"region": "us-west-2"}
sip: {advertised_ip: 1.2.3.4, media_public_ip: 1.2.3.4}
default_tenant: missing
tenants:
  "banking": {"contact_flow_id": "f", "instance_id": "i"}
"#;
        let err = parse(yaml).resolved_tenants().unwrap_err().to_string();
        assert!(err.contains("default_tenant"), "unexpected error: {err}");
    }

    #[test]
    fn half_configured_legacy_aws_is_rejected() {
        let yaml = r#"
aws: {"region": "us-west-2", "instance_id": "inst-only"}
sip: {advertised_ip: 1.2.3.4, media_public_ip: 1.2.3.4}
"#;
        let err = parse(yaml).resolved_tenants().unwrap_err().to_string();
        assert!(
            err.contains("must be set together"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn tenant_names_lists_loaded_tenants() {
        assert_eq!(
            parse(B4_TWO_TENANTS).tenant_names().unwrap(),
            vec!["banking".to_string(), "retail".to_string()]
        );
        assert_eq!(
            parse(LEGACY).tenant_names().unwrap(),
            vec![LEGACY_TENANT.to_string()]
        );
    }

    #[test]
    fn effective_config_redacts_control_hmac_key() {
        let mut value: serde_yaml::Value = serde_yaml::from_str(
            "api:\n  bearer_token: bearer-private\n  control_hmac_key: hmac-private\npersistence:\n  database_url: postgres://private-database\n  redis_url: rediss://private-redis\n  allow_db_only_coordination: true\nproviders:\n  telnyx:\n    media_sip_password: provider-media-private\ngeneric_bridge:\n  webrtc:\n    ice_servers:\n      - urls: [turn:turn.example.test]\n        credential: turn-private\n",
        )
        .unwrap();
        redact_secrets(&mut value);
        let rendered = serde_yaml::to_string(&value).unwrap();
        assert!(!rendered.contains("bearer-private"));
        assert!(!rendered.contains("hmac-private"));
        assert!(!rendered.contains("private-database"));
        assert!(!rendered.contains("private-redis"));
        assert!(!rendered.contains("provider-media-private"));
        assert!(!rendered.contains("turn-private"));
        assert!(rendered.contains("allow_db_only_coordination: true"));
        assert_eq!(rendered.matches("[redacted]").count(), 6);
    }

    #[test]
    fn strict_deserialization_rejects_unknown_fields_at_every_depth() {
        let value: serde_yaml::Value = serde_yaml::from_str(&format!(
            "{LEGACY}\nruntime:\n  setup_timeout_secondz: 30\nproviders:\n  telnyx:\n    api_key: test-key\n    connection_id: test-connection\n    webhook_public_key: test-public-key\n    from: '+14155550100'\n    media_sip_authority: bridgefu.example:5060\n    media_sip_username: telnyx\n    media_sip_password: test-password\n    unexpected_credential: private\nobservability:\n  otlp:\n    headers:\n      authorization: private-otel-header\nunknown_top_level: true\n"
        ))
        .unwrap();
        let error = deserialize_strict(&value, std::path::Path::new("strict-test.yaml"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown configuration fields"), "{error}");
        assert!(error.contains("setup_timeout_secondz"), "{error}");
        assert!(error.contains("unexpected_credential"), "{error}");
        assert!(error.contains("observability.otlp.headers"), "{error}");
        assert!(error.contains("unknown_top_level"), "{error}");
        assert!(!error.contains("private"), "{error}");
    }

    #[test]
    fn redacted_effective_config_does_not_resolve_secret_references() {
        let path = std::env::temp_dir().join(format!(
            "bridgefu-effective-config-{}.yaml",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            format!(
                "{LEGACY}\napi:\n  enabled: true\n  bearer_token: env:BRIDGEFU_TEST_UNPROVISIONED_BEARER\n  control_hmac_key: env:BRIDGEFU_TEST_UNPROVISIONED_CONTROL_KEY\n"
            ),
        )
        .unwrap();

        let rendered = Config::redacted_effective_yaml(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(!rendered.contains("BRIDGEFU_TEST_UNPROVISIONED"));
        assert_eq!(rendered.matches("[redacted]").count(), 2);
    }

    #[test]
    fn persistence_defaults_to_durable_sqlite_with_stable_worker() {
        let cfg = parse(LEGACY);
        cfg.validate().unwrap();
        assert_eq!(cfg.persistence.backend, PersistenceBackend::Sqlite);
        assert_eq!(
            cfg.call_worker_id().unwrap().to_string(),
            DEFAULT_STANDALONE_WORKER_ID
        );
        let backend = cfg.call_repository_backend().unwrap();
        assert!(matches!(
            &backend,
            CallRepositoryBackendConfig::Sqlite { .. }
        ));
        assert!(!format!("{backend:?}").contains("bridgefu.db"));
        assert_eq!(
            cfg.call_worker_capabilities(),
            BTreeSet::from([
                "amazon_connect".to_owned(),
                "sip".to_owned(),
                "sip_egress".to_owned(),
                "telnyx".to_owned(),
                "webrtc".to_owned(),
                "webrtc_egress".to_owned(),
            ])
        );
        for unsupported in ["twilio", "vonage"] {
            assert!(!cfg.call_worker_capabilities().contains(unsupported));
        }
    }

    #[test]
    fn generic_bridge_requires_the_shared_durable_auth_authority() {
        let legacy_token = parse(&format!(
            "{LEGACY}\ngeneric_bridge:\n  enabled: true\n  bearer_token: legacy-private\n"
        ));
        let error = legacy_token.validate().unwrap_err().to_string();
        assert!(error.contains("generic_bridge.bearer_token"));
        assert!(!error.contains("legacy-private"));

        let incomplete = parse(&format!(
            "{LEGACY}\ngeneric_bridge:\n  enabled: true\napi:\n  enabled: true\n  bearer_token: shared-private\n"
        ));
        let error = incomplete.validate().unwrap_err().to_string();
        assert!(error.contains("api.control_hmac_key"));
        assert!(!error.contains("shared-private"));

        let complete = parse(&format!(
            "{LEGACY}\ngeneric_bridge:\n  enabled: true\napi:\n  enabled: true\n  bearer_token: shared-private\n  control_hmac_key: 0123456789abcdef0123456789abcdef\n"
        ));
        complete.validate().unwrap();
    }

    #[test]
    fn generic_sip_cleartext_bearer_requires_explicit_opt_in() {
        let defaulted = parse(&format!(
            "{LEGACY}\napi:\n  enabled: true\n  bearer_token: shared-private\n  control_hmac_key: 0123456789abcdef0123456789abcdef\ngeneric_bridge:\n  enabled: true\n"
        ));
        defaulted.validate().unwrap();
        assert!(!defaulted.generic_bridge.sip.allow_cleartext_bearer);

        let opted_in = parse(&format!(
            "{LEGACY}\napi:\n  enabled: true\n  bearer_token: shared-private\n  control_hmac_key: 0123456789abcdef0123456789abcdef\ngeneric_bridge:\n  enabled: true\n  sip:\n    allow_cleartext_bearer: true\n"
        ));
        opted_in.validate().unwrap();
        assert!(opted_in.generic_bridge.sip.allow_cleartext_bearer);
    }

    #[test]
    fn generic_and_telnyx_digest_merge_only_with_one_realm_and_distinct_users() {
        let base = format!(
            r#"{LEGACY}
api:
  enabled: true
  bearer_token: shared-private
  control_hmac_key: 0123456789abcdef0123456789abcdef
generic_bridge:
  enabled: true
  sip:
    digest:
      realm: bridgefu
      username: generic-media
      password: generic-secret
providers:
  telnyx:
    api_key: secret
    connection_id: connection-a
    webhook_public_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    from: "+12065550100"
    media_sip_authority: bridgefu.test:5060
    media_sip_username: telnyx-media
    media_sip_password: telnyx-secret
"#
        );
        parse(&base).validate().unwrap();

        let mismatched_realm = parse(&base.replace(
            "realm: bridgefu\n      username: generic-media",
            "realm: generic-realm\n      username: generic-media",
        ));
        let error = mismatched_realm.validate().unwrap_err().to_string();
        assert!(error.contains("one exact shared realm"));
        assert!(!error.contains("generic-secret"));
        assert!(!error.contains("telnyx-secret"));

        let colliding_user =
            parse(&base.replace("username: generic-media", "username: telnyx-media"));
        let error = colliding_user.validate().unwrap_err().to_string();
        assert!(error.contains("distinct usernames"));
        assert!(!error.contains("generic-secret"));
        assert!(!error.contains("telnyx-secret"));
    }

    #[test]
    fn generic_networking_maps_nat_turn_deadlines_and_symmetric_rtp() {
        let yaml = format!(
            "{LEGACY}\napi:\n  enabled: true\n  bearer_token: shared-private\n  control_hmac_key: 0123456789abcdef0123456789abcdef\ngeneric_bridge:\n  enabled: true\n  sip_bind: 127.0.0.1:5070\n  webrtc_ws_bind: 127.0.0.1:8080\n  webrtc_whip_bind: 127.0.0.1:8081\n  sip:\n    advertised_addr: 192.0.2.10:5070\n    media_public_addr: 192.0.2.11:0\n    rtp_port_start: 20000\n    rtp_port_end: 20199\n    symmetric_rtp:\n      enabled: true\n      allow_ip_change: true\n      probation_packets: 4\n      max_rebindings: 3\n      rebind_window_secs: 3\n      max_sequence_jump: 1000\n  webrtc:\n    udp_bind: 127.0.0.1:0\n    ice_servers:\n      - urls: [turn:turn.example.test:3478?transport=udp]\n        username: bridgefu\n        credential: turn-private\n    ice_transport_policy: relay\n    nat_1to1_ips: [192.0.2.12]\n    nat_1to1_candidate_type: host\n    gather_timeout_secs: 6\n    connection_timeout_secs: 20\n    trickle_ice: false\n"
        );
        let config = parse(&yaml);
        config.validate().unwrap();
        let bind = config.generic_bridge.sip_bind.parse().unwrap();
        let (sip, nat) = config
            .generic_bridge
            .sip_stack_config("test", bind)
            .unwrap();
        assert_eq!(
            sip.sip_advertised_addr.unwrap().to_string(),
            "192.0.2.10:5070"
        );
        assert_eq!(sip.media_public_addr.unwrap().to_string(), "192.0.2.11:0");
        assert_eq!((sip.media_port_start, sip.media_port_end), (20_000, 20_199));
        assert!(nat.symmetric_rtp.enabled);
        assert!(nat.symmetric_rtp.allow_ip_change);
        assert_eq!(nat.symmetric_rtp.probation_packets, 4);

        let webrtc = config.generic_bridge.webrtc_stack_config().unwrap();
        assert_eq!(webrtc.udp_bind, "127.0.0.1:0");
        assert_eq!(webrtc.ice_servers.len(), 1);
        assert_eq!(
            webrtc.ice_servers[0].credential.as_deref(),
            Some("turn-private")
        );
        assert_eq!(webrtc.nat_1to1_ips, vec!["192.0.2.12"]);
        assert_eq!(webrtc.gather_timeout_secs, 6);
        assert_eq!(webrtc.connection_timeout_secs, 20);
        assert!(!webrtc.trickle_ice);
        assert_eq!(webrtc.capabilities.audio_codecs.len(), 1);
        assert_eq!(webrtc.capabilities.audio_codecs[0].name, "opus");
        assert_eq!(
            webrtc.ice_transport_policy,
            rvoip_webrtc::config::IceTransportPolicy::Relay
        );

        let debug = format!("{:?}", config.generic_bridge);
        assert!(!debug.contains("turn-private"));
        assert!(debug.contains("[redacted]"));
    }

    #[test]
    fn generic_secure_sip_listener_projects_tls_and_strict_srtp_into_rvoip() {
        let yaml = format!(
            "{LEGACY}\napi:\n  enabled: true\n  bearer_token: shared-private\n  control_hmac_key: 0123456789abcdef0123456789abcdef\ngeneric_bridge:\n  enabled: true\n  sip_bind: 127.0.0.1:5070\n  sip:\n    secure_listener:\n      bind: 0.0.0.0:5061\n      advertised_addr: 192.0.2.10:5061\n      certificate_chain: /run/tls/sip.pem\n      private_key: /run/tls/sip-key.pem\n      client_ca_certificate: /run/tls/vapi-ca.pem\n      require_client_certificate: true\n    srtp: required\n"
        );
        let config = parse(&yaml);
        config.validate().unwrap();
        let (sip, _) = config
            .generic_bridge
            .sip_stack_config("secure-test", "127.0.0.1:5070".parse().unwrap())
            .unwrap();
        assert_eq!(sip.sip_tls_mode, rvoip_sip::SipTlsMode::ClientAndServer);
        assert_eq!(sip.tls_bind_addr.unwrap().to_string(), "0.0.0.0:5061");
        assert_eq!(
            sip.tls_advertised_addr.unwrap().to_string(),
            "192.0.2.10:5061"
        );
        assert_eq!(
            sip.tls_cert_path.unwrap().to_string_lossy(),
            "/run/tls/sip.pem"
        );
        assert_eq!(
            sip.tls_key_path.unwrap().to_string_lossy(),
            "/run/tls/sip-key.pem"
        );
        assert!(sip.offer_srtp);
        assert!(sip.srtp_required);
    }

    #[test]
    fn named_profile_revisions_exclude_secrets_and_track_non_secret_policy() {
        let yaml = format!(
            r#"{LEGACY}
api:
  enabled: true
  bearer_token: shared-private
  control_hmac_key: 0123456789abcdef0123456789abcdef
  static_tenant: default
  route_attachments:
    sip_uri_template: "sips:{{token}}@bridge.example.test:5061;transport=tls"
  routes:
    support:
      tenant_id: default
      ingress: [sip]
      vapi_ingress_profile: vapi-public
      destination_profile:
        type: sip
        profile_id: support-sbc
      destination:
        direction: outbound
        signaling_initiator: bridgefu
        media_flow: send_receive
        endpoint:
          type: sip
          config:
            uri: "sips:agent@support.example.test:5061;transport=tls"
vapi_ingress_profiles:
  vapi-public:
    tenant_id: default
    principal_subject: vapi-edge
    issuer: vapi-managed
    scopes: [calls:create]
    trusted_signaling_cidrs: [192.0.2.0/24]
    tls:
      certificate_chain: /run/tls/sip.pem
      private_key: /run/tls/sip-key.pem
    srtp_required: true
    codecs: [pcmu, opus]
sip_profiles:
  support-sbc:
    allowed_targets: ["sips:agent@support.example.test:5061;transport=tls"]
    from_uri: "sips:bridgefu@bridge.example.test"
    outbound_proxy: "sips:edge.support.example.test:5061;lr"
    auth:
      type: bearer
      token: env:OUTBOUND_TOKEN_A
    tls_roots: [/run/tls/support-ca.pem]
    client_certificate:
      certificate_chain: /run/tls/support-client.pem
      private_key: /run/tls/support-client-key.pem
    srtp: required
    codecs: [pcmu, opus]
    metadata_keys: [correlation_id]
context:
  allow_headers:
    X-Correlation-Id: correlation_id
generic_bridge:
  enabled: true
  sip_bind: 127.0.0.1:5070
  sip:
    secure_listener:
      bind: 127.0.0.1:5061
      certificate_chain: /run/tls/sip.pem
      private_key: /run/tls/sip-key.pem
    srtp: required
    symmetric_rtp:
      enabled: true
      allow_ip_change: true
      probation_packets: 5
      max_rebindings: 4
      rebind_window_secs: 6
      max_sequence_jump: 900
"#
        );
        let config = parse(&yaml);
        config.validate().unwrap();
        let resolved = config.resolved_named_routes().unwrap();
        let profile_bindings = resolved
            .routes
            .get("support")
            .unwrap()
            .profile_bindings
            .clone();
        let revision = profile_bindings
            .iter()
            .find(|profile| profile.kind() == NamedProfileKind::Sip)
            .unwrap()
            .revision()
            .to_owned();

        // Building the catalog does not resolve the deliberately missing env
        // secret. The exact selected effect fails closed only when executed.
        let resolver = config.outbound_profile_resolver().unwrap();
        let route =
            NamedRouteBinding::new_with_profiles("support", None, profile_bindings).unwrap();
        assert_eq!(
            resolver
                .apply_sip(Some(&route), rvoip_sip::SipOriginateContext::new())
                .unwrap_err(),
            bridgefu::call_service::OutboundProfileError::MaterialUnavailable
        );
        let (sip, _) = config
            .generic_sip_stack_config("profile-test", "127.0.0.1:5070".parse().unwrap())
            .unwrap();
        assert!(sip.tls_extra_ca_path.is_none());
        assert!(sip.tls_client_cert_path.is_none());
        assert!(sip.tls_client_key_path.is_none());
        let profiles = config
            .sip_egress_profile_configs("profile-test", "127.0.0.1:5070".parse().unwrap())
            .unwrap();
        assert_eq!(profiles.len(), 1);
        let configured = &profiles[0];
        assert_eq!(configured.revision.expose_opaque(), revision);
        assert_eq!(configured.allowed_initial_headers, ["X-Correlation-Id"]);
        assert!(configured.sip_message);
        assert_eq!(configured.stack.offered_codecs, [0, 111, 101]);
        assert_eq!(
            configured.stack.contact_uri.as_deref(),
            Some("sips:bridgefu@bridge.example.test")
        );
        assert!(configured.stack.offer_srtp);
        assert!(configured.stack.srtp_required);
        assert!(configured.nat.symmetric_rtp.allow_ip_change);
        assert_eq!(configured.nat.symmetric_rtp.probation_packets, 5);
        assert_eq!(configured.nat.symmetric_rtp.max_rebindings, 4);
        assert_eq!(
            configured.nat.symmetric_rtp.rebind_window,
            Duration::from_secs(6)
        );
        assert_eq!(configured.nat.symmetric_rtp.max_sequence_jump, 900);
        assert!(sip.media_port_end < configured.stack.media_port_start);
        assert_eq!(
            configured
                .stack
                .tls_extra_ca_path
                .as_ref()
                .unwrap()
                .to_string_lossy(),
            "/run/tls/support-ca.pem"
        );
        assert_eq!(
            configured
                .stack
                .tls_client_cert_path
                .as_ref()
                .unwrap()
                .to_string_lossy(),
            "/run/tls/support-client.pem"
        );
        assert_eq!(
            configured
                .stack
                .tls_client_key_path
                .as_ref()
                .unwrap()
                .to_string_lossy(),
            "/run/tls/support-client-key.pem"
        );

        let rotated = parse(&yaml.replace("OUTBOUND_TOKEN_A", "OUTBOUND_TOKEN_B"));
        rotated.validate().unwrap();
        let rotated_revision = rotated
            .resolved_named_routes()
            .unwrap()
            .routes
            .get("support")
            .unwrap()
            .profile_bindings
            .iter()
            .find(|profile| profile.kind() == NamedProfileKind::Sip)
            .unwrap()
            .revision()
            .to_owned();
        assert_eq!(revision, rotated_revision);

        let changed_yaml = yaml
            .replace(
                "agent@support.example.test",
                "agent@new-support.example.test",
            )
            .replace("OUTBOUND_TOKEN_A", "OUTBOUND_TOKEN_PRIVATE_CANARY");
        let changed = parse(&changed_yaml);
        changed.validate().unwrap();
        let changed_revision = changed
            .resolved_named_routes()
            .unwrap()
            .routes
            .get("support")
            .unwrap()
            .profile_bindings
            .iter()
            .find(|profile| profile.kind() == NamedProfileKind::Sip)
            .unwrap()
            .revision()
            .to_owned();
        assert_ne!(revision, changed_revision);
        let debug = format!("{config:?}");
        assert!(!debug.contains("OUTBOUND_TOKEN_A"));
        assert!(!debug.contains("OUTBOUND_TOKEN_PRIVATE_CANARY"));

        let insecure = parse(&yaml.replace("    srtp: required\n", "    srtp: disabled\n"));
        let error = insecure.validate().unwrap_err().to_string();
        assert!(error.contains("TLS/SRTP") || error.contains("mandatory SRTP"));
    }

    #[test]
    fn conflicting_named_sip_security_policies_build_isolated_children() {
        let mut config = parse(&vapi_projection_yaml());
        let mut support = config.sip_profiles.get("support-sbc").unwrap().clone();
        support.tls_roots = vec!["/run/tls/support-a-ca.pem".into()];
        support.client_certificate = Some(ProfileClientCertificateCfg {
            certificate_chain: "/run/tls/support-a-client.pem".into(),
            private_key: serde_yaml::from_str("/run/tls/support-a-key.pem").unwrap(),
        });
        support.srtp = ProfileSrtpPolicy::Preferred;
        support.codecs = BTreeSet::from([ProfileAudioCodec::Pcmu, ProfileAudioCodec::Opus]);
        config.sip_profiles.insert("support-sbc".into(), support);

        let backup_target = "sip:agent@backup.example.test:5060";
        config.sip_profiles.insert(
            "backup-sbc".into(),
            SipProfileCfg {
                allowed_targets: BTreeSet::from([backup_target.into()]),
                from_uri: "sip:bridgefu@bridge.example.test".into(),
                outbound_proxy: None,
                auth: None,
                tls_roots: vec!["/run/tls/support-b-ca.pem".into()],
                client_certificate: None,
                srtp: ProfileSrtpPolicy::Disabled,
                codecs: BTreeSet::from([ProfileAudioCodec::Pcma]),
                metadata_keys: BTreeSet::new(),
            },
        );
        let mut backup_route = config.api.routes.get("support").unwrap().clone();
        backup_route.destination_profile = Some(RouteDestinationProfileRef::Sip {
            profile_id: "backup-sbc".into(),
        });
        match &mut backup_route.destination.endpoint {
            LegEndpointConfig::Sip(endpoint) => endpoint.uri = Some(backup_target.into()),
            _ => panic!("fixture destination must be SIP"),
        }
        config.api.routes.insert("backup".into(), backup_route);

        config.validate().unwrap();
        let bind = "127.0.0.1:5070".parse().unwrap();
        let (listener, _) = config
            .generic_sip_stack_config("isolated-profile-test", bind)
            .unwrap();
        let profiles = config
            .sip_egress_profile_configs("isolated-profile-test", bind)
            .unwrap();
        assert_eq!(profiles.len(), 2);
        assert!(profiles
            .iter()
            .all(|profile| profile.stack.bind_addr.ip().is_loopback()));
        assert!(profiles
            .iter()
            .all(|profile| profile.stack.local_ip == listener.local_ip));
        let pcma = profiles
            .iter()
            .find(|profile| profile.stack.offered_codecs == [8, 101])
            .unwrap();
        let pcmu_opus = profiles
            .iter()
            .find(|profile| profile.stack.offered_codecs == [0, 111, 101])
            .unwrap();
        assert!(!pcma.stack.offer_srtp);
        assert!(!pcma.stack.srtp_required);
        assert_eq!(
            pcma.stack.tls_extra_ca_path.as_deref(),
            Some(std::path::Path::new("/run/tls/support-b-ca.pem"))
        );
        assert!(pcmu_opus.stack.offer_srtp);
        assert!(!pcmu_opus.stack.srtp_required);
        assert!(pcmu_opus.stack.tls_client_cert_path.is_some());
        let mut media_ranges = profiles
            .iter()
            .map(|profile| (profile.stack.media_port_start, profile.stack.media_port_end))
            .collect::<Vec<_>>();
        media_ranges.sort_unstable();
        assert!(listener.media_port_end < media_ranges[0].0);
        assert!(media_ranges[0].1 < media_ranges[1].0);
    }

    #[tokio::test]
    async fn referenced_vapi_profile_projects_one_identity_into_listener_and_attachment_resolver() {
        let config = parse(&vapi_projection_yaml());
        config.validate().unwrap();

        let projections = config
            .sip_listener_principal_projections("default")
            .unwrap();
        assert_eq!(projections.len(), 1);
        let projection = &projections[0];
        assert_eq!(projection.profile_id, "vapi-public");
        assert_eq!(projection.principal.subject, "vapi-edge");
        assert_eq!(projection.principal.tenant.as_deref(), Some("default"));
        assert_eq!(projection.principal.issuer.as_deref(), Some("vapi-managed"));
        assert_eq!(projection.principal.scopes, vec!["calls:create"]);
        assert_eq!(
            projection.trusted_cidrs,
            vec!["192.0.2.0/24".parse().unwrap()]
        );

        let policy = config
            .sip_listener_auth_policy("default", rvoip_auth_core::bearer_stub(), "sip:connect")
            .unwrap();
        assert_eq!(
            format!("{policy:?}"),
            "SipListenerAuthPolicy { enabled: true, tenant_configured: true, auth_service_configured: true, trusted_source_count: 1, mtls_principal_count: 0 }"
        );

        let catalog = config.resolved_named_routes().unwrap();
        let configured_route = catalog.routes.get("support").unwrap();
        let route = NamedRouteBinding::new_with_profiles(
            "support",
            None,
            configured_route.profile_bindings.clone(),
        )
        .unwrap();
        let resolver = config
            .attachment_principal_resolver(&["default".into()])
            .unwrap();
        let tenant = TenantId::parse("default").unwrap();
        let leg = LegExecutionSpec {
            leg_id: LegId::new(),
            endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                uri: None,
                initial_context: SipInitialContextMode::None,
            }),
        };
        let api_principal = PrincipalFingerprint::new([0x91; 32]);
        assert_eq!(
            resolver
                .resolve_principal(AttachmentPrincipalRequest {
                    tenant: &tenant,
                    leg: &leg,
                    named_route: Some(&route),
                    api_principal,
                })
                .await
                .unwrap(),
            None
        );
        let attachment_principal = resolver
            .resolve_authenticated_principal(AttachmentPrincipalRequest {
                tenant: &tenant,
                leg: &leg,
                named_route: Some(&route),
                api_principal,
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(attachment_principal.subject, projection.principal.subject);
        assert_eq!(attachment_principal.tenant, projection.principal.tenant);
        assert_eq!(attachment_principal.issuer, projection.principal.issuer);
        assert_eq!(attachment_principal.scopes, projection.principal.scopes);
        assert_eq!(attachment_principal.method, projection.principal.method);
    }

    #[test]
    fn unreferenced_vapi_profile_never_expands_listener_trust() {
        let yaml = vapi_projection_yaml().replace(
            "sip_profiles:\n",
            r#"  unused-inventory:
    tenant_id: default
    principal_subject: unused-edge
    issuer: unused-provider
    scopes: [calls:create]
    trusted_signaling_cidrs: [198.51.100.0/24]
    tls:
      certificate_chain: /run/tls/unused.pem
      private_key: /run/tls/unused-key.pem
    srtp_required: true
    codecs: [pcmu]
sip_profiles:
"#,
        );
        let config = parse(&yaml);
        config.validate().unwrap();
        let projections = config
            .sip_listener_principal_projections("default")
            .unwrap();
        assert_eq!(projections.len(), 1);
        assert_eq!(projections[0].profile_id, "vapi-public");
        assert!(!projections[0]
            .trusted_cidrs
            .iter()
            .any(|cidr| cidr.contains(&"198.51.100.42".parse::<IpAddr>().unwrap())));
    }

    #[test]
    fn vapi_projection_rejects_cross_tenant_listener_and_conflicting_cidrs() {
        let config = parse(&vapi_projection_yaml());
        let error = config
            .sip_listener_auth_policy("retail", rvoip_auth_core::bearer_stub(), "sip:connect")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("tenant must exactly match the listener tenant"),
            "unexpected error: {error}"
        );

        let yaml = vapi_projection_yaml()
            .replace(
                "vapi_ingress_profiles:\n",
                r#"    support-secondary:
      tenant_id: default
      ingress: [sip]
      vapi_ingress_profile: vapi-secondary
      destination_profile:
        type: sip
        profile_id: support-sbc
      destination:
        direction: outbound
        signaling_initiator: bridgefu
        media_flow: send_receive
        endpoint:
          type: sip
          config:
            uri: "sips:agent@support.example.test:5061;transport=tls"
vapi_ingress_profiles:
"#,
            )
            .replace(
                "sip_profiles:\n",
                r#"  vapi-secondary:
    tenant_id: default
    principal_subject: another-vapi-edge
    issuer: another-vapi-provider
    scopes: [calls:create]
    trusted_signaling_cidrs: [192.0.2.128/25]
    tls:
      certificate_chain: /run/tls/sip.pem
      private_key: /run/tls/sip-key.pem
    srtp_required: true
    codecs: [pcmu]
sip_profiles:
"#,
            );
        let error = parse(&yaml).validate().unwrap_err().to_string();
        assert!(error.contains("overlapping trusted signaling CIDRs"));
        assert!(error.contains("conflicting identities"));
    }

    #[test]
    fn vapi_mtls_requires_explicit_leaf_mapping_and_projects_verified_identity() {
        let missing_leaf = vapi_projection_yaml().replace(
            "    srtp_required: true\n    codecs: [pcmu, opus]\n",
            "    mtls_peer_ca_certificates: [/run/tls/vapi-ca.pem]\n    srtp_required: true\n    codecs: [pcmu, opus]\n",
        );
        let error = parse(&missing_leaf).validate().unwrap_err().to_string();
        assert!(error.contains("mtls_leaf_certificate_sha256_fingerprints"));
        assert!(error.contains("CA verification alone does not assign a principal"));

        let fingerprint = "AB".repeat(32);
        let configured = vapi_projection_yaml()
            .replace(
                "    srtp_required: true\n    codecs: [pcmu, opus]\n",
                &format!(
                    "    mtls_peer_ca_certificates: [/run/tls/vapi-ca.pem]\n    mtls_leaf_certificate_sha256_fingerprints: [{fingerprint}]\n    srtp_required: true\n    codecs: [pcmu, opus]\n"
                ),
            )
            .replace(
                "      private_key: /run/tls/sip-key.pem\n    srtp: required\n",
                "      private_key: /run/tls/sip-key.pem\n      client_ca_certificate: /run/tls/vapi-ca.pem\n      require_client_certificate: true\n    srtp: required\n",
            );
        let config = parse(&configured);
        config.validate().unwrap();
        let policy = config
            .sip_listener_auth_policy("default", rvoip_auth_core::bearer_stub(), "sip:connect")
            .unwrap();
        assert_eq!(
            format!("{policy:?}"),
            "SipListenerAuthPolicy { enabled: true, tenant_configured: true, auth_service_configured: true, trusted_source_count: 1, mtls_principal_count: 1 }"
        );
        assert!(!format!("{policy:?}").contains(&fingerprint));
    }

    #[test]
    fn generic_networking_rejects_unsafe_or_incoherent_nat_configuration() {
        let base = format!(
            "{LEGACY}\napi:\n  enabled: true\n  bearer_token: shared-private\n  control_hmac_key: 0123456789abcdef0123456789abcdef\n"
        );
        let relay_without_turn = parse(&format!(
            "{base}generic_bridge:\n  webrtc:\n    ice_servers: []\n    ice_transport_policy: relay\n"
        ))
        .validate()
        .unwrap_err()
        .to_string();
        assert!(relay_without_turn.contains("requires at least one TURN"));

        let conflicting_sip = parse(&format!(
            "{base}generic_bridge:\n  sip:\n    media_public_addr: 192.0.2.5:0\n    stun_server: stun.example.test:3478\n"
        ))
        .validate()
        .unwrap_err()
        .to_string();
        assert!(conflicting_sip.contains("mutually exclusive"));

        let conflicting_srflx = parse(&format!(
            "{base}generic_bridge:\n  webrtc:\n    nat_1to1_ips: [192.0.2.6]\n    nat_1to1_candidate_type: srflx\n"
        ))
        .validate()
        .unwrap_err()
        .to_string();
        assert!(conflicting_srflx.contains("cannot be combined with STUN"));

        let empty_codecs = parse(&format!(
            "{base}generic_bridge:\n  webrtc:\n    audio_codecs: []\n"
        ))
        .validate()
        .unwrap_err()
        .to_string();
        assert!(empty_codecs.contains("audio_codecs must contain 1..=3"));

        let explicit_codecs = parse(&format!(
            "{base}generic_bridge:\n  webrtc:\n    audio_codecs: [opus, pcmu, pcma]\n"
        ));
        explicit_codecs.validate().unwrap();
        let names = explicit_codecs
            .generic_bridge
            .webrtc_stack_config()
            .unwrap()
            .capabilities
            .audio_codecs
            .into_iter()
            .map(|codec| codec.name)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            names,
            BTreeSet::from(["g.711-a".into(), "g.711-mu".into(), "opus".into()])
        );

        let bounded = parse(&format!(
            "{base}generic_bridge:\n  webrtc:\n    udp_port_range:\n      bind_ip: 0.0.0.0\n      port_start: 40000\n      port_end: 40199\n"
        ));
        bounded.validate().unwrap();
        let range = bounded
            .generic_bridge
            .webrtc_stack_config()
            .unwrap()
            .udp_port_range
            .expect("bounded WebRTC range");
        assert_eq!(range.bind_ip, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!((range.port_start, range.port_end), (40000, 40199));

        let too_small = parse(&format!(
            "{base}generic_bridge:\n  webrtc:\n    udp_port_range:\n      bind_ip: 0.0.0.0\n      port_start: 40000\n      port_end: 40198\n"
        ))
        .validate()
        .unwrap_err()
        .to_string();
        assert!(too_small.contains("requires at least 200"));

        let reversed = parse(&format!(
            "{base}generic_bridge:\n  webrtc:\n    udp_port_range:\n      bind_ip: 0.0.0.0\n      port_start: 40100\n      port_end: 40000\n"
        ))
        .validate()
        .unwrap_err()
        .to_string();
        assert!(reversed.contains("inclusive nonzero start <= end"));
    }

    #[test]
    fn reference_tenant_canary_is_explicit_tenant_bound_and_false_by_default() {
        assert!(parse(B4_TWO_TENANTS)
            .reference_tenant_canary_policy()
            .unwrap()
            .is_none());

        let config = parse(&format!(
            "{B4_TWO_TENANTS}\napi:\n  enabled: true\n  bearer_token: canary-private\n  control_hmac_key: 0123456789abcdef0123456789abcdef\n  static_tenant: banking\ncontext:\n  allow_headers:\n    X-Correlation-Id: correlation_id\ngeneric_bridge:\n  enabled: true\n  reference_tenant_canary:\n    enabled: true\n    tenant: banking\n"
        ));
        config.validate().unwrap();
        let policy = config
            .reference_tenant_canary_policy()
            .unwrap()
            .expect("explicit canary policy");
        assert_eq!(policy.tenant().as_str(), "banking");
        let debug = format!("{policy:?}");
        assert!(!debug.contains("inst-banking"));
        assert!(!debug.contains("flow-banking"));
    }

    #[test]
    fn reference_tenant_canary_rejects_implicit_or_cross_tenant_routes() {
        let missing_context = parse(&format!(
            "{B4_TWO_TENANTS}\napi:\n  bearer_token: canary-private\n  control_hmac_key: 0123456789abcdef0123456789abcdef\n  static_tenant: banking\ngeneric_bridge:\n  enabled: true\n  reference_tenant_canary:\n    enabled: true\n    tenant: banking\n"
        ));
        assert!(missing_context.validate().is_err());

        let wrong_tenant = parse(&format!(
            "{B4_TWO_TENANTS}\napi:\n  bearer_token: canary-private\n  control_hmac_key: 0123456789abcdef0123456789abcdef\n  static_tenant: retail\ncontext:\n  allow_headers:\n    X-Correlation-Id: correlation_id\ngeneric_bridge:\n  enabled: true\n  reference_tenant_canary:\n    enabled: true\n    tenant: banking\n"
        ));
        assert!(wrong_tenant.validate().is_err());
    }

    #[test]
    fn ephemeral_memory_requires_explicit_dev_test_acknowledgement() {
        let rejected = parse(&format!("{LEGACY}\npersistence:\n  backend: memory\n"));
        let error = rejected.validate().unwrap_err().to_string();
        assert!(error.contains("dev/test-only"));

        let accepted = parse(&format!(
            "{LEGACY}\npersistence:\n  backend: memory\n  allow_ephemeral_memory: true\n"
        ));
        accepted.validate().unwrap();
        assert!(matches!(
            accepted.call_repository_backend().unwrap(),
            CallRepositoryBackendConfig::Memory
        ));
    }

    #[test]
    fn postgres_requires_secret_url_and_explicit_valid_worker() {
        let missing = parse(&format!("{LEGACY}\npersistence:\n  backend: postgres\n"));
        assert!(missing
            .validate()
            .unwrap_err()
            .to_string()
            .contains("database_url is required"));

        for invalid in ["not-a-uuid", "00000000-0000-0000-0000-000000000000"] {
            let cfg = parse(&format!(
                "{LEGACY}\npersistence:\n  backend: postgres\n  database_url: postgres://private.example/bridgefu\n  worker_id: '{invalid}'\n"
            ));
            let error = cfg.validate().unwrap_err().to_string();
            assert!(error.contains("non-nil UUID"), "unexpected error: {error}");
            assert!(!error.contains("private.example"));
        }

        let valid = parse(&format!(
            "{LEGACY}\npersistence:\n  backend: postgres\n  database_url: postgres://private.example/bridgefu\n  worker_id: 00000000-0000-4000-8000-000000000002\n  allow_db_only_coordination: true\n"
        ));
        valid.validate().unwrap();
        let backend = valid.call_repository_backend().unwrap();
        let debug = format!("{backend:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("private.example"));
    }

    #[test]
    fn coordination_bounds_and_clustered_redis_are_validated_and_redacted() {
        let insecure = parse(&format!(
            "{LEGACY}\npersistence:\n  backend: postgres\n  database_url: postgres://private.example/bridgefu\n  worker_id: 00000000-0000-4000-8000-000000000002\n  redis_url: redis://redis-private.example\n  redis_clustered: true\n"
        ));
        let error = insecure.validate().unwrap_err().to_string();
        assert!(error.contains("requires a rediss:// URL"));
        assert!(!error.contains("redis-private.example"));

        let invalid_lease = parse(&format!(
            "{LEGACY}\npersistence:\n  worker_lease_ttl_secs: 4\n"
        ));
        assert!(invalid_lease
            .validate()
            .unwrap_err()
            .to_string()
            .contains("between 5 and 300"));

        let valid = parse(&format!(
            "{LEGACY}\npersistence:\n  backend: postgres\n  database_url: postgres://private.example/bridgefu\n  worker_id: 00000000-0000-4000-8000-000000000002\n  deployment_id: cluster-a\n  worker_lease_ttl_secs: 60\n  worker_renew_interval_secs: 20\n  worker_capabilities: [sip, webrtc]\n  redis_url: rediss://redis-private.example\n  redis_clustered: true\n"
        ));
        valid.validate().unwrap();
        let coordination = valid.call_coordination_config().unwrap();
        let debug = format!("{coordination:?}");
        assert!(debug.contains("cluster-a"));
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("redis-private.example"));
        assert_eq!(valid.call_worker_capabilities().len(), 2);

        let unsafe_mode = parse(&format!(
            "{LEGACY}\nruntime:\n  mode: worker\npersistence:\n  backend: postgres\n  database_url: postgres://private.example/bridgefu\n  worker_id: 00000000-0000-4000-8000-000000000002\n  allow_db_only_coordination: true\n"
        ));
        assert!(unsafe_mode
            .validate()
            .unwrap_err()
            .to_string()
            .contains("requires runtime.mode all-in-one"));

        let missing_coordination = parse(&format!(
            "{LEGACY}\npersistence:\n  backend: postgres\n  database_url: postgres://private.example/bridgefu\n  worker_id: 00000000-0000-4000-8000-000000000002\n"
        ));
        assert!(missing_coordination
            .validate()
            .unwrap_err()
            .to_string()
            .contains("requires clustered rediss:// coordination"));
    }

    #[test]
    fn redis_secret_reference_schema_matches_resolved_cluster_validation() {
        const VARIABLE: &str = "BRIDGEFU_TEST_COORDINATION_REDIS_URL";
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../config/schema.json")).unwrap();
        assert_eq!(
            schema["properties"]["persistence"]["properties"]["redis_url"]["pattern"],
            "^(?:rediss?://|env:[A-Za-z_][A-Za-z0-9_]*)$"
        );

        std::env::set_var(VARIABLE, "rediss://redis-secret.example");
        let configured = parse(&format!(
            "{LEGACY}\npersistence:\n  backend: postgres\n  database_url: postgres://private.example/bridgefu\n  worker_id: 00000000-0000-4000-8000-000000000002\n  redis_url: env:{VARIABLE}\n  redis_clustered: true\n"
        ));
        configured.validate().unwrap();
        std::env::remove_var(VARIABLE);
    }

    #[test]
    fn telnyx_profile_and_media_defaults_match_schema_while_deferred_providers_fail() {
        let configured = parse(&format!(
            r#"{LEGACY}
providers:
  telnyx:
    api_key: secret
    connection_id: connection-a
    webhook_public_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    from: "+12065550100"
    media_sip_authority: bridgefu.test:5060
    media_sip_username: telnyx-media
    media_sip_password: media-secret
"#
        ));
        configured.validate().unwrap();
        let telnyx = configured.providers.telnyx.as_ref().unwrap();
        assert_eq!(telnyx.account_profile, "telnyx");
        assert_eq!(telnyx.media_sip_realm, "bridgefu");
        assert_eq!(telnyx.media_sip_transport, "UDP");

        for provider in [
            "twilio:\n    account_sid: AC-account\n    auth_token: secret",
            "vonage:\n    application_id: application-a\n    private_key: private\n    signature_secret: secret",
        ] {
            let deferred = parse(&format!("{LEGACY}\nproviders:\n  {provider}\n"));
            assert!(deferred
                .validate()
                .unwrap_err()
                .to_string()
                .contains("deferred"));
        }

        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../config/schema.json")).unwrap();
        for (provider, default) in [
            ("twilio", "twilio"),
            ("telnyx", "telnyx"),
            ("vonage", "vonage"),
        ] {
            let profile = &schema["properties"]["providers"]["properties"][provider]["properties"]
                ["account_profile"];
            assert_eq!(profile["default"], default);
            assert_eq!(profile["pattern"], "^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$");
        }
    }

    #[test]
    fn api_static_tenant_must_be_valid_and_configured() {
        let valid = parse(&format!(
            "{B4_TWO_TENANTS}\napi:\n  static_tenant: banking\n"
        ));
        valid.validate().unwrap();

        let missing = parse(&format!(
            "{B4_TWO_TENANTS}\napi:\n  static_tenant: wholesale\n"
        ));
        let error = missing.validate().unwrap_err().to_string();
        assert!(error.contains("must name one configured routing tenant"));

        let invalid = parse(&format!(
            "{B4_TWO_TENANTS}\napi:\n  static_tenant: 'invalid tenant'\n"
        ));
        let error = invalid.validate().unwrap_err().to_string();
        assert!(error.contains("not a valid tenant identifier"));
    }

    #[test]
    fn control_hmac_key_preflight_resolves_bounds_and_redacts_secret() {
        let valid_secret = "v".repeat(MIN_CONTROL_KEY_BYTES);
        let valid = parse(&format!(
            "{LEGACY}\napi:\n  control_hmac_key: '{valid_secret}'\n"
        ));
        valid.validate().unwrap();

        let private_short_secret = "private-short-control-secret";
        let short = parse(&format!(
            "{LEGACY}\napi:\n  control_hmac_key: '{private_short_secret}'\n"
        ));
        let error = short.validate().unwrap_err().to_string();
        assert!(error.contains("must resolve to 32 to 4096 bytes"));
        assert!(!error.contains(private_short_secret));

        const MISSING_ENV: &str = "BRIDGEFU_TEST_MISSING_CONTROL_HMAC_KEY";
        std::env::remove_var(MISSING_ENV);
        let missing = parse(&format!(
            "{LEGACY}\napi:\n  control_hmac_key: 'env:{MISSING_ENV}'\n"
        ));
        let error = missing.validate().unwrap_err().to_string();
        assert!(error.contains("referenced environment secret is unavailable"));
        assert!(!error.contains(MISSING_ENV));
        assert!(!error.contains(&valid_secret));
    }

    #[test]
    fn private_forwarding_is_role_bound_bounded_and_secret_redacted() {
        const TOKEN_SECRET: &str = "private-forwarding-token-secret-32-bytes";
        const BROADCAST_SECRET: &str = "split-broadcast-token-secret-32-bytes";
        let gateway = parse(&format!(
            r#"{LEGACY}
runtime: {{mode: gateway, max_concurrent_calls: 1}}
api:
  http_bind: 127.0.0.1:9080
  bearer_token: gateway-public-token
  control_hmac_key: 0123456789abcdef0123456789abcdef
generic_bridge:
  enabled: true
  sip_bind: 127.0.0.1:5070
  webrtc_ws_bind: 127.0.0.1:8080
  webrtc_whip_bind: 127.0.0.1:8081
broadcast:
  public_endpoint: uctp+quic://gateway.invalid:4444
  token_secret: {BROADCAST_SECRET}
private_forwarding:
  enabled: true
  token_signing_secret: {TOKEN_SECRET}
  gateway:
    gateway_id: gateway-a
    bind: 127.0.0.1:0
    tls:
      certificate_chain: [/run/tls/gateway.pem]
      private_key: /run/tls/gateway.key
      peer_ca_certificates: [/run/tls/worker-ca.pem]
    workers:
      - worker_id: 00000000-0000-4000-8000-000000000002
        endpoint: worker.internal:9443
        server_name: worker.internal
  limits:
    max_active_routes: 2
    max_peer_connections: 1
    max_routes_per_peer: 2
    media_queue_capacity: 10
    reliable_queue_capacity: 16
    inbound_queue_capacity: 16
"#
        ));
        gateway.validate().unwrap();
        let runtime = gateway.gateway_forwarding_config().unwrap();
        assert_eq!(runtime.gateway_id, "gateway-a");
        assert_eq!(runtime.workers.len(), 1);
        assert_eq!(runtime.workers[0].endpoint, "worker.internal:9443");
        assert_eq!(
            format!("{:?}", runtime.token_key),
            "PrivateTokenKey([redacted])"
        );

        let worker = parse(&format!(
            r#"{LEGACY}
runtime: {{mode: worker, max_concurrent_calls: 1}}
persistence:
  backend: postgres
  database_url: postgres://database.invalid/bridgefu
  worker_id: 00000000-0000-4000-8000-000000000002
  redis_url: rediss://redis.invalid
  redis_clustered: true
api: {{enabled: false}}
broadcast:
  public_endpoint: uctp+quic://gateway.invalid:4444
  token_secret: {BROADCAST_SECRET}
private_forwarding:
  enabled: true
  token_signing_secret: {TOKEN_SECRET}
  worker:
    bind: 127.0.0.1:9443
    tls:
      certificate_chain: [/run/tls/worker.pem]
      private_key: /run/tls/worker.key
      peer_ca_certificates: [/run/tls/gateway-ca.pem]
  limits:
    max_active_routes: 2
    max_peer_connections: 1
    max_routes_per_peer: 2
    media_queue_capacity: 10
    reliable_queue_capacity: 16
    inbound_queue_capacity: 16
"#
        ));
        worker.validate().unwrap();
        let runtime = worker.worker_forwarding_config().unwrap();
        assert_eq!(
            runtime.worker_id.to_string(),
            "00000000-0000-4000-8000-000000000002"
        );
        assert_eq!(
            runtime.bind,
            "127.0.0.1:9443".parse::<SocketAddr>().unwrap()
        );

        let too_small = parse(&format!(
            r#"{LEGACY}
runtime: {{mode: gateway, max_concurrent_calls: 2}}
api:
  http_bind: 127.0.0.1:9080
  bearer_token: gateway-public-token
  control_hmac_key: 0123456789abcdef0123456789abcdef
generic_bridge:
  enabled: true
  sip_bind: 127.0.0.1:5070
  webrtc_ws_bind: 127.0.0.1:8080
  webrtc_whip_bind: 127.0.0.1:8081
broadcast:
  public_endpoint: uctp+quic://gateway.invalid:4444
  token_secret: {BROADCAST_SECRET}
private_forwarding:
  enabled: true
  token_signing_secret: {TOKEN_SECRET}
  gateway:
    gateway_id: gateway-a
    tls:
      certificate_chain: [/run/tls/gateway.pem]
      private_key: /run/tls/gateway.key
      peer_ca_certificates: [/run/tls/worker-ca.pem]
    workers:
      - worker_id: 00000000-0000-4000-8000-000000000002
        endpoint: worker.internal:9443
        server_name: worker.internal
  limits: {{max_active_routes: 2}}
"#
        ));
        let error = too_small.validate().unwrap_err().to_string();
        assert!(error.contains("limits are inconsistent"));
        assert!(!error.contains(TOKEN_SECRET));
        assert!(!error.contains(BROADCAST_SECRET));

        let mut value: serde_yaml::Value = serde_yaml::from_str(&format!(
            "private_forwarding:\n  token_signing_secret: {TOKEN_SECRET}\n  worker:\n    tls:\n      private_key: /private/worker.key\n"
        ))
        .unwrap();
        redact_secrets(&mut value);
        let rendered = serde_yaml::to_string(&value).unwrap();
        assert!(!rendered.contains(TOKEN_SECRET));
        assert!(!rendered.contains("/private/worker.key"));
        assert_eq!(rendered.matches("[redacted]").count(), 2);
    }
}
