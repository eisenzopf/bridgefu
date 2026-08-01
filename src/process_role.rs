//! Process-role selection and split-worker lifecycle ownership.
//!
//! A role never falls back to all-in-one. Roles whose private transport or
//! production security configuration is not available fail before binding a
//! socket or advertising readiness.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bridgefu::api_principal::ConfiguredApiKeyValidator;
use bridgefu::broadcast::{
    BroadcastCommandExecutor, BroadcastCommandExecutorConfig, BroadcastCommandRepository,
    BroadcastGrantRegistry, BroadcastGrantVerifier, BroadcastTokenService, MoqRelayTarget,
    PostgresBroadcastCommandRepository, RedisBroadcastGrantConfig, RedisBroadcastGrantStore,
    WorkerBroadcastSubscriptionAuthority,
};
use bridgefu::call_engine::RouteCatalogFingerprint;
use bridgefu::call_service::{
    build_call_service_runtime, AttachmentPrincipalResolver, CallControlRuntimeHealth,
    CallExecutionSupervisor, CallServiceRuntime, CallServiceRuntimeConfig, CallTimeoutPolicy,
    OutboundProfileResolver, ProviderLegExecutor, RuntimeSupervisorHealth, SystemCallServiceClock,
};
#[cfg(test)]
use bridgefu::call_service::{
    DisabledOutboundProfileResolver, DisabledProviderLegExecutor, SamePrincipalAttachmentResolver,
};
use bridgefu::coordination::{CoordinationProjection, RedisCoordinator};
use bridgefu::gateway_attachment::GatewayAttachmentResolver;
use bridgefu::gateway_forwarding::{ForwardingHealth, GatewayForwarder, WorkerForwardingRuntime};
use bridgefu::gateway_native_ingress::{GatewayNativeIngress, GatewayNativeIngressHealth};
use bridgefu::gateway_uctp_ingress::{
    DurableGatewayBroadcastAuthority, GatewayBroadcastAuthority, GatewayIngressAdmission,
    GatewayUctpIngress, GatewayUctpIngressError, GatewayUctpIngressHealth,
};
use bridgefu::private_egress::{
    PrivateEgressCommandService, PrivateEgressControlClient, PrivateEgressError,
    PrivateEgressGatewayEpoch, PrivateEgressProfile, PrivateEgressServiceConfig,
    PrivateEgressStateStore, PrivateEgressTransport, RedisPrivateEgressStateConfig,
    RedisPrivateEgressStateStore,
};
use bridgefu::private_egress_stream::{
    PrivateEgressGatewayAdapters, PrivateEgressGatewayProfileResolver,
    PrivateEgressGatewayProxyConfig, PrivateEgressGatewayProxyHandler,
    PrivateEgressResolvedOriginate, PrivateEgressStreamAdmissionRegistry,
    PrivateEgressWorkerRouteCatalog, PrivateEgressWorkerRouteDescriptor,
    PrivateEgressWorkerRuntime,
};
use bridgefu::signaling_token::{SignalingTokenService, WebRtcSignalingBearerValidator};
use metrics_exporter_prometheus::PrometheusHandle;
use rvoip_amazon_connect::AmazonConnectAdapter;
use rvoip_core::adapter::ConnectionAdapter;
use rvoip_core::adapter::OriginateContext;
use rvoip_core::capability::{CapabilityDescriptor, CodecInfo};
use rvoip_core::config::Config as CoreConfig;
use rvoip_core::Orchestrator;
#[cfg(test)]
use rvoip_sip::SipAuthService;
use rvoip_sip::{
    SipInboundContextPolicy, SipInitialHeaders, SipListenerAuthPolicy, SipOriginateContext,
};
use rvoip_webrtc::{WebRtcOriginateContext, WebRtcTargetPolicy};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::config::{Config, NamedRouteCfg, PersistenceBackend, ProfileAudioCodec, RuntimeMode};
use crate::context::ContextPolicy;
use crate::observability::{role_health_router, serve_role_health, RoleHealth, RoleLifecycle};
use crate::providers::ProviderRegistry;

const GATEWAY_SIP_BEARER_SCOPE: &str = "sip:connect";
const WORKER_STARTUP_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
// One admitted route-create or replacement can emit Prepare plus Activate.
const PRIVATE_EGRESS_COMMANDS_PER_CONTROL_REQUEST: usize = 2;
// Reserve End plus immediate DTMF/Data/compensation control for every live
// route independently of the public control-request replay window.
const PRIVATE_EGRESS_REPLAY_HEADROOM_PER_ACTIVE_ROUTE: usize = 4;
const MIN_PRIVATE_EGRESS_REPLAY_ENTRIES: usize = 64;
const MAX_PRIVATE_EGRESS_REPLAY_ENTRIES: usize = 262_144;

fn gateway_private_egress_replay_capacity(config: &Config, replay_ttl: Duration) -> Result<usize> {
    let rate_limit = &config.api.rate_limit;
    if !rate_limit.enabled {
        return Err(anyhow!(
            "split gateway private-egress requires bounded API control rate limiting"
        ));
    }
    let partial_second = if replay_ttl.subsec_nanos() == 0 { 0 } else { 1 };
    let ttl_seconds = replay_ttl
        .as_secs()
        .checked_add(partial_second)
        .and_then(|seconds| usize::try_from(seconds).ok())
        .ok_or_else(|| anyhow!("private-egress replay TTL exceeds platform capacity"))?;
    let requests_per_second = usize::try_from(rate_limit.control_requests_per_second)
        .map_err(|_| anyhow!("private-egress control rate exceeds platform capacity"))?;
    let burst = usize::try_from(rate_limit.control_burst)
        .map_err(|_| anyhow!("private-egress control burst exceeds platform capacity"))?;
    let admitted_requests = requests_per_second
        .checked_mul(ttl_seconds)
        .and_then(|sustained| sustained.checked_add(burst))
        .ok_or_else(|| anyhow!("private-egress replay request window overflow"))?;
    let control_commands = admitted_requests
        .checked_mul(PRIVATE_EGRESS_COMMANDS_PER_CONTROL_REQUEST)
        .ok_or_else(|| anyhow!("private-egress replay command capacity overflow"))?;
    let route_headroom = config
        .private_forwarding
        .limits
        .max_active_routes
        .checked_mul(PRIVATE_EGRESS_REPLAY_HEADROOM_PER_ACTIVE_ROUTE)
        .ok_or_else(|| anyhow!("private-egress active-route headroom overflow"))?;
    let required = control_commands
        .checked_add(route_headroom)
        .map(|capacity| capacity.max(MIN_PRIVATE_EGRESS_REPLAY_ENTRIES))
        .ok_or_else(|| anyhow!("private-egress replay capacity overflow"))?;
    if required > MAX_PRIVATE_EGRESS_REPLAY_ENTRIES {
        return Err(anyhow!(
            "private-egress replay capacity {required} exceeds the per-gateway safety bound {MAX_PRIVATE_EGRESS_REPLAY_ENTRIES}; reduce API control rate/burst or split gateway capacity"
        ));
    }
    Ok(required)
}

#[derive(Clone)]
struct GatewayEgressProfileEntry {
    tenant_id: bridgefu::call_engine::TenantId,
    transport: PrivateEgressTransport,
    profile: PrivateEgressProfile,
    target: String,
    route: bridgefu::call_service::NamedRouteBinding,
    codecs: Vec<CodecInfo>,
    sip_metadata_keys: std::collections::BTreeSet<String>,
}

struct ConfiguredGatewayEgressProfiles {
    entries: Vec<GatewayEgressProfileEntry>,
    outbound: Arc<dyn OutboundProfileResolver>,
}

#[async_trait]
impl PrivateEgressGatewayProfileResolver for ConfiguredGatewayEgressProfiles {
    async fn resolve(
        &self,
        tenant_id: &bridgefu::call_engine::TenantId,
        transport: PrivateEgressTransport,
        profile: &PrivateEgressProfile,
        codec: &CodecInfo,
        target: &str,
        initial_context: &[(String, String)],
    ) -> std::result::Result<PrivateEgressResolvedOriginate, PrivateEgressError> {
        let entry = self
            .entries
            .iter()
            .find(|entry| {
                entry.tenant_id == *tenant_id
                    && entry.transport == transport
                    && entry.profile == *profile
                    && entry.target == target
            })
            .ok_or(PrivateEgressError::HandlerRejected)?;
        if !entry
            .codecs
            .iter()
            .any(|candidate| private_codec_compatible(candidate, codec))
        {
            return Err(PrivateEgressError::HandlerRejected);
        }
        let context = match transport {
            PrivateEgressTransport::Sip => {
                if !initial_context.iter().all(|(name, _)| {
                    entry
                        .sip_metadata_keys
                        .iter()
                        .any(|allowed| allowed.eq_ignore_ascii_case(name))
                }) {
                    return Err(PrivateEgressError::HandlerRejected);
                }
                let headers = SipInitialHeaders::new(initial_context.iter().cloned())
                    .map_err(|_| PrivateEgressError::HandlerRejected)?;
                let context = self
                    .outbound
                    .apply_sip(
                        Some(&entry.route),
                        SipOriginateContext::new().with_initial_headers(headers),
                    )
                    .map_err(|_| PrivateEgressError::HandlerRejected)?;
                OriginateContext::new(context)
            }
            PrivateEgressTransport::WebRtc => {
                if !initial_context.is_empty() {
                    return Err(PrivateEgressError::HandlerRejected);
                }
                let endpoint =
                    url::Url::parse(target).map_err(|_| PrivateEgressError::HandlerRejected)?;
                let port = endpoint
                    .port_or_known_default()
                    .ok_or(PrivateEgressError::HandlerRejected)?;
                // The target itself is an exact, server-owned route value.
                // Permit private/loopback addresses only because the exact
                // value was already matched above; arbitrary worker input can
                // never broaden this policy.
                let policy = WebRtcTargetPolicy::default()
                    .allow_port(port)
                    .allow_loopback(true)
                    .allow_private_networks(true)
                    .with_credential_partition(format!("bridgefu:{}", entry.profile.revision))
                    .map_err(|_| PrivateEgressError::HandlerRejected)?;
                let context = WebRtcOriginateContext::websocket(target, policy)
                    .map_err(|_| PrivateEgressError::HandlerRejected)?
                    .require_remote_admission_ready()
                    .map_err(|_| PrivateEgressError::HandlerRejected)?;
                let context = self
                    .outbound
                    .apply_webrtc(Some(&entry.route), context)
                    .map_err(|_| PrivateEgressError::HandlerRejected)?;
                OriginateContext::new(context)
            }
        };
        Ok(PrivateEgressResolvedOriginate {
            capabilities: CapabilityDescriptor {
                audio_codecs: vec![codec.clone()],
                ..CapabilityDescriptor::default()
            },
            context,
        })
    }
}

fn private_profile_codecs(
    configured: &std::collections::BTreeSet<ProfileAudioCodec>,
) -> Vec<CodecInfo> {
    configured
        .iter()
        .map(|codec| match codec {
            ProfileAudioCodec::Pcmu => CodecInfo::from_name_with_defaults("g.711-mu"),
            ProfileAudioCodec::Pcma => CodecInfo::from_name_with_defaults("g.711-a"),
            ProfileAudioCodec::Opus => CodecInfo::from_name_with_defaults("opus"),
        })
        .collect()
}

fn private_codec_compatible(left: &CodecInfo, right: &CodecInfo) -> bool {
    left.clock_rate_hz == right.clock_rate_hz
        && left.channels == right.channels
        && match (
            left.name.to_ascii_lowercase().as_str(),
            right.name.to_ascii_lowercase().as_str(),
        ) {
            ("pcmu" | "g.711-mu", "pcmu" | "g.711-mu")
            | ("pcma" | "g.711-a", "pcma" | "g.711-a") => true,
            (left, right) => left == right,
        }
}

fn gateway_egress_profile_entry(
    config: &Config,
    route_id: &str,
    route: &NamedRouteCfg,
) -> Result<Option<GatewayEgressProfileEntry>> {
    let destination = route
        .profile_bindings
        .iter()
        .find(|binding| binding.role() == bridgefu::call_service::NamedProfileRole::Destination);
    let Some(destination) = destination else {
        return Ok(None);
    };
    let route_binding = bridgefu::call_service::NamedRouteBinding::new_with_profiles(
        route_id.to_owned(),
        None,
        route.profile_bindings.clone(),
    )?;
    let tenant_id = bridgefu::call_engine::TenantId::parse(&route.tenant_id)
        .map_err(|_| anyhow!("configured private egress route tenant is invalid"))?;
    let entry = match (&route.destination.endpoint, destination.kind()) {
        (
            bridgefu::call_service::LegEndpointConfig::Sip(endpoint),
            bridgefu::call_service::NamedProfileKind::Sip,
        ) => {
            let target = endpoint
                .uri
                .clone()
                .ok_or_else(|| anyhow!("private SIP egress route target is absent"))?;
            let configured = config
                .sip_profiles
                .get(destination.profile_id())
                .ok_or_else(|| anyhow!("private SIP egress profile disappeared"))?;
            GatewayEgressProfileEntry {
                tenant_id,
                transport: PrivateEgressTransport::Sip,
                profile: PrivateEgressProfile {
                    profile_id: destination.profile_id().to_owned(),
                    revision: destination.revision().to_owned(),
                },
                target,
                route: route_binding,
                codecs: private_profile_codecs(&configured.codecs),
                sip_metadata_keys: configured.metadata_keys.clone(),
            }
        }
        (
            bridgefu::call_service::LegEndpointConfig::WebRtc(endpoint),
            bridgefu::call_service::NamedProfileKind::WebRtc,
        ) => {
            let target = endpoint
                .signaling_uri
                .clone()
                .ok_or_else(|| anyhow!("private WebRTC egress route target is absent"))?;
            let configured = config
                .webrtc_profiles
                .get(destination.profile_id())
                .ok_or_else(|| anyhow!("private WebRTC egress profile disappeared"))?;
            GatewayEgressProfileEntry {
                tenant_id,
                transport: PrivateEgressTransport::WebRtc,
                profile: PrivateEgressProfile {
                    profile_id: destination.profile_id().to_owned(),
                    revision: destination.revision().to_owned(),
                },
                target,
                route: route_binding,
                codecs: private_profile_codecs(&configured.codecs),
                sip_metadata_keys: std::collections::BTreeSet::new(),
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(entry))
}

fn gateway_egress_profiles(
    config: &Config,
) -> Result<Arc<dyn PrivateEgressGatewayProfileResolver>> {
    let resolved = config.resolved_named_routes()?;
    let entries = resolved
        .routes
        .iter()
        .map(|(route_id, route)| gateway_egress_profile_entry(config, route_id, route))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    Ok(Arc::new(ConfiguredGatewayEgressProfiles {
        entries,
        outbound: config.outbound_profile_resolver()?,
    }))
}

fn route_catalog_configuration_fingerprint(
    configured_capabilities: &std::collections::BTreeSet<String>,
    routes: &std::collections::BTreeMap<String, NamedRouteCfg>,
) -> Result<RouteCatalogFingerprint> {
    let capabilities = configured_capabilities
        .iter()
        .filter(|capability| !capability.starts_with("bridgefu.route_catalog.sha256:"))
        .collect::<Vec<_>>();
    let mut hasher = Sha256::new();
    hash_catalog_field(&mut hasher, b"bridgefu.route-catalog-configuration.v2");
    hash_catalog_count(&mut hasher, capabilities.len());
    for capability in capabilities {
        hash_catalog_field(&mut hasher, capability.as_bytes());
    }

    hash_catalog_count(&mut hasher, routes.len());
    for (route_id, route) in routes {
        hash_catalog_field(&mut hasher, route_id.as_bytes());
        hash_catalog_field(&mut hasher, route.tenant_id.as_bytes());
        hasher.update([u8::from(route.legacy_embedded_destination)]);

        hash_catalog_count(&mut hasher, route.ingress.len());
        for ingress in &route.ingress {
            hasher.update([match ingress {
                crate::config::NamedRouteIngress::Sip => 1,
                crate::config::NamedRouteIngress::Webrtc => 2,
            }]);
        }

        let destination = serde_json::to_vec(&route.destination)
            .context("encoding credential-free route destination for fingerprinting")?;
        hash_catalog_field(&mut hasher, &destination);

        let mut profiles = route
            .profile_bindings
            .iter()
            .map(serde_json::to_vec)
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("encoding route profile identities for fingerprinting")?;
        profiles.sort();
        hash_catalog_count(&mut hasher, profiles.len());
        for profile in profiles {
            hash_catalog_field(&mut hasher, &profile);
        }

        let metadata_keys = route
            .context_metadata_allowlist
            .iter()
            .flat_map(|keys| keys.iter())
            .collect::<Vec<_>>();
        hash_catalog_count(&mut hasher, metadata_keys.len());
        for key in metadata_keys {
            hash_catalog_field(&mut hasher, key.as_bytes());
        }

        hash_catalog_count(&mut hasher, route.capability_policy.audio_codecs.len());
        for codec in &route.capability_policy.audio_codecs {
            hasher.update([match codec {
                ProfileAudioCodec::Pcmu => 1,
                ProfileAudioCodec::Pcma => 2,
                ProfileAudioCodec::Opus => 3,
            }]);
        }
        hash_catalog_optional_bool(&mut hasher, route.capability_policy.data_channels);
        hash_catalog_optional_bool(&mut hasher, route.capability_policy.sip_message);
    }
    Ok(RouteCatalogFingerprint::new(hasher.finalize().into()))
}

fn hash_catalog_optional_bool(hasher: &mut Sha256, value: Option<bool>) {
    hasher.update([match value {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    }]);
}

fn hash_catalog_count(hasher: &mut Sha256, count: usize) {
    hasher.update(u64::try_from(count).unwrap_or(u64::MAX).to_be_bytes());
}

fn hash_catalog_field(hasher: &mut Sha256, value: &[u8]) {
    hash_catalog_count(hasher, value.len());
    hasher.update(value);
}

pub(crate) fn worker_egress_routes(
    config: &Config,
) -> Result<Arc<PrivateEgressWorkerRouteCatalog>> {
    let resolved = config.resolved_named_routes()?;
    let fingerprint = route_catalog_configuration_fingerprint(
        &config.call_worker_capabilities(),
        &resolved.routes,
    )?;
    let entries = resolved
        .routes
        .iter()
        .map(|(route_id, route)| gateway_egress_profile_entry(config, route_id, route))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .map(|entry| {
            let mut codecs = entry.codecs;
            codecs.sort_by_key(|codec| private_codec_rank(entry.transport, codec));
            PrivateEgressWorkerRouteDescriptor {
                tenant_id: entry.tenant_id,
                route_id: entry.route.route_id().to_owned(),
                transport: entry.transport,
                profile: entry.profile,
                target: entry.target,
                codecs,
            }
        })
        .collect();
    PrivateEgressWorkerRouteCatalog::new_with_fingerprint(entries, fingerprint)
        .map_err(anyhow::Error::from)
        .context("building exact worker private-egress route catalog")
}

fn private_codec_rank(transport: PrivateEgressTransport, codec: &CodecInfo) -> u8 {
    let name = codec.name.to_ascii_lowercase();
    match transport {
        PrivateEgressTransport::Sip => match name.as_str() {
            "pcmu" | "g.711-mu" => 0,
            "pcma" | "g.711-a" => 1,
            "opus" => 2,
            _ => 3,
        },
        PrivateEgressTransport::WebRtc => match name.as_str() {
            "opus" => 0,
            "pcmu" | "g.711-mu" => 1,
            "pcma" | "g.711-a" => 2,
            _ => 3,
        },
    }
}

/// Static component boundary for a process role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RolePlan {
    pub public_control_http: bool,
    pub public_signaling: bool,
    pub public_sip: bool,
    pub public_webrtc: bool,
    pub public_uctp: bool,
    pub amazon_connect_media: bool,
    pub durable_call_worker: bool,
    pub moq_relay: bool,
}

impl RolePlan {
    #[must_use]
    pub const fn for_mode(mode: RuntimeMode) -> Self {
        match mode {
            RuntimeMode::AllInOne => Self {
                public_control_http: true,
                public_signaling: true,
                public_sip: true,
                public_webrtc: true,
                public_uctp: true,
                amazon_connect_media: true,
                durable_call_worker: true,
                moq_relay: false,
            },
            RuntimeMode::Gateway => Self {
                public_control_http: true,
                public_signaling: true,
                public_sip: true,
                public_webrtc: true,
                public_uctp: true,
                amazon_connect_media: false,
                durable_call_worker: false,
                moq_relay: false,
            },
            RuntimeMode::Worker => Self {
                public_control_http: false,
                public_signaling: false,
                public_sip: false,
                public_webrtc: false,
                public_uctp: false,
                amazon_connect_media: true,
                durable_call_worker: true,
                moq_relay: false,
            },
            RuntimeMode::MoqRelay => Self {
                public_control_http: false,
                public_signaling: false,
                public_sip: false,
                public_webrtc: false,
                public_uctp: false,
                amazon_connect_media: false,
                durable_call_worker: false,
                moq_relay: true,
            },
        }
    }
}

/// Safe, non-secret role preflight failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RolePreflightError {
    #[error(
        "gateway mode requires enabled private_forwarding gateway, mTLS, token, and worker target configuration"
    )]
    GatewayForwardingConfigurationMissing,
    #[error(
        "gateway mode requires private_forwarding.gateway.public_uctp TLS listener configuration"
    )]
    GatewayPublicUctpConfigurationMissing,
    #[error("gateway mode requires clustered rediss:// attachment routing projection")]
    GatewayRequiresClusteredRedis,
    #[error("gateway public UCTP ingress requires api.bearer_token, api.control_hmac_key, and one static tenant")]
    GatewayAttachmentAuthenticationMissing,
    #[error("gateway mode requires persistence.backend postgres")]
    GatewayRequiresPostgres,
    #[error("gateway mode requires api.enabled=true for authenticated call control and provider webhooks")]
    GatewayPublicApiDisabled,
    #[error(
        "gateway mode requires a dedicated api.http_bind distinct from observability.http_bind"
    )]
    GatewayPublicApiBindMissing,
    #[error(
        "non-loopback gateway api.http_bind requires api.tls certificate_chain and private_key"
    )]
    GatewayPublicApiTlsMissing,
    #[error("gateway mode requires generic_bridge.enabled for native SIP/WebRTC ingress")]
    GatewayNativeSignalingConfigurationMissing,
    #[error(
        "gateway SIP ingress requires generic_bridge.sip.digest, Telnyx Digest, or an explicit cleartext Bearer opt-in"
    )]
    GatewaySipAuthenticationMissing,
    #[error("non-loopback gateway WebRTC signaling requires api.tls for WSS and HTTPS")]
    GatewayNativeSignalingTlsMissing,
    #[error(
        "worker mode requires enabled private_forwarding worker, mTLS, and token configuration"
    )]
    WorkerForwardingConfigurationMissing,
    #[error("moq-relay mode requires moq_relay listener, TLS, admission, and limit configuration")]
    MoqRelayConfigurationMissing,
    #[error("moq-relay mode requires clustered rediss:// grant and session-lease coordination")]
    MoqRelayRequiresClusteredRedis,
    #[error("moq-relay mode requires broadcast.token_secret")]
    MoqRelayTokenSecretMissing,
    #[error("moq-relay mode cannot expose the public control API; set api.enabled to false")]
    MoqRelayPublicApiEnabled,
    #[error("moq-relay mode cannot bind generic SIP or WebRTC signaling listeners")]
    MoqRelayPublicSignalingEnabled,
    #[error("worker mode requires persistence.backend postgres")]
    WorkerRequiresPostgres,
    #[error("worker mode requires clustered rediss:// coordination")]
    WorkerRequiresClusteredRedis,
    #[error("worker mode requires api.control_hmac_key")]
    WorkerControlKeyMissing,
    #[error("worker mode cannot expose the public control API; set api.enabled to false")]
    WorkerPublicApiEnabled,
    #[error("worker mode cannot bind generic public signaling listeners")]
    WorkerPublicSignalingEnabled,
}

/// Validate that the selected role can run its real component set. This is
/// intentionally separate from YAML validation: a syntactically valid future
/// role must still fail closed in binaries that do not implement it yet.
pub fn preflight(config: &Config) -> std::result::Result<RolePlan, RolePreflightError> {
    let plan = RolePlan::for_mode(config.runtime.mode);
    match config.runtime.mode {
        RuntimeMode::AllInOne => Ok(plan),
        RuntimeMode::Gateway => {
            if !config.private_forwarding.enabled
                || config.private_forwarding.gateway.is_none()
                || config.private_forwarding.token_signing_secret.is_none()
            {
                return Err(RolePreflightError::GatewayForwardingConfigurationMissing);
            }
            if config
                .private_forwarding
                .gateway
                .as_ref()
                .and_then(|gateway| gateway.public_uctp.as_ref())
                .is_none()
            {
                return Err(RolePreflightError::GatewayPublicUctpConfigurationMissing);
            }
            if config.persistence.redis_url.is_none() || !config.persistence.redis_clustered {
                return Err(RolePreflightError::GatewayRequiresClusteredRedis);
            }
            if config.persistence.backend != PersistenceBackend::Postgres {
                return Err(RolePreflightError::GatewayRequiresPostgres);
            }
            if config.api.bearer_token.is_none()
                || config.api.control_hmac_key.is_none()
                || gateway_static_tenant(config).is_none()
            {
                return Err(RolePreflightError::GatewayAttachmentAuthenticationMissing);
            }
            if !config.api.enabled {
                return Err(RolePreflightError::GatewayPublicApiDisabled);
            }
            let Some(api_bind) = config
                .api
                .http_bind
                .as_deref()
                .and_then(|bind| bind.parse::<SocketAddr>().ok())
            else {
                return Err(RolePreflightError::GatewayPublicApiBindMissing);
            };
            if api_bind.port() == 0
                || config
                    .observability
                    .http_bind
                    .parse::<SocketAddr>()
                    .is_ok_and(|operations_bind| operations_bind == api_bind)
            {
                return Err(RolePreflightError::GatewayPublicApiBindMissing);
            }
            if !api_bind.ip().is_loopback() && config.api.tls.is_none() {
                return Err(RolePreflightError::GatewayPublicApiTlsMissing);
            }
            if !config.generic_bridge.enabled {
                return Err(RolePreflightError::GatewayNativeSignalingConfigurationMissing);
            }
            if !config.generic_bridge.sip.allow_cleartext_bearer
                && config.generic_bridge.sip.digest.is_none()
                && config.providers.telnyx.is_none()
            {
                return Err(RolePreflightError::GatewaySipAuthenticationMissing);
            }
            let public_webrtc = [
                config.generic_bridge.webrtc_ws_bind.as_str(),
                config.generic_bridge.webrtc_whip_bind.as_str(),
            ]
            .into_iter()
            .filter_map(|bind| bind.parse::<SocketAddr>().ok())
            .any(|bind| !bind.ip().is_loopback());
            if public_webrtc && config.api.tls.is_none() {
                return Err(RolePreflightError::GatewayNativeSignalingTlsMissing);
            }
            Ok(plan)
        }
        RuntimeMode::MoqRelay => {
            if config.moq_relay.is_none() {
                return Err(RolePreflightError::MoqRelayConfigurationMissing);
            }
            if config.persistence.redis_url.is_none() || !config.persistence.redis_clustered {
                return Err(RolePreflightError::MoqRelayRequiresClusteredRedis);
            }
            if config.broadcast.token_secret.is_none() {
                return Err(RolePreflightError::MoqRelayTokenSecretMissing);
            }
            if config.api.enabled {
                return Err(RolePreflightError::MoqRelayPublicApiEnabled);
            }
            if config.generic_bridge.enabled {
                return Err(RolePreflightError::MoqRelayPublicSignalingEnabled);
            }
            Ok(plan)
        }
        RuntimeMode::Worker => {
            if config.api.enabled {
                return Err(RolePreflightError::WorkerPublicApiEnabled);
            }
            if config.generic_bridge.enabled {
                return Err(RolePreflightError::WorkerPublicSignalingEnabled);
            }
            if config.persistence.backend != PersistenceBackend::Postgres {
                return Err(RolePreflightError::WorkerRequiresPostgres);
            }
            if config.persistence.redis_url.is_none() || !config.persistence.redis_clustered {
                return Err(RolePreflightError::WorkerRequiresClusteredRedis);
            }
            if config.api.control_hmac_key.is_none() {
                return Err(RolePreflightError::WorkerControlKeyMissing);
            }
            if !config.private_forwarding.enabled
                || config.private_forwarding.worker.is_none()
                || config.private_forwarding.token_signing_secret.is_none()
            {
                return Err(RolePreflightError::WorkerForwardingConfigurationMissing);
            }
            Ok(plan)
        }
    }
}

fn gateway_static_tenant(config: &Config) -> Option<String> {
    if let Some(tenant) = &config.api.static_tenant {
        return Some(tenant.clone());
    }
    let tenants = config.tenant_names().ok()?;
    (tenants.len() == 1).then(|| tenants[0].clone())
}

fn gateway_sip_listener_auth(
    config: &Config,
    tenant: &str,
    validator: Arc<dyn rvoip_auth_core::BearerValidator>,
) -> Result<SipListenerAuthPolicy> {
    config
        .sip_listener_auth_policy(tenant, validator, GATEWAY_SIP_BEARER_SCOPE)
        .context("configuring tenant-bound gateway SIP authentication")
}

#[cfg(test)]
fn gateway_sip_auth_service(
    config: &Config,
    validator: Arc<dyn rvoip_auth_core::BearerValidator>,
) -> Result<SipAuthService> {
    config
        .generic_bridge
        .sip_auth_service(&config.providers, validator, GATEWAY_SIP_BEARER_SCOPE)
}

fn gateway_sip_inbound_context_policy(config: &Config) -> Result<SipInboundContextPolicy> {
    config
        .context
        .validate()
        .context("validating gateway SIP context policy")?;
    let inbound_names = config.context.allow_headers.keys().filter(|name| {
        let normalized = name.to_ascii_lowercase();
        normalized != "x-bridgefu"
            && normalized != "x-rvoip"
            && !normalized.starts_with("x-bridgefu-")
            && !normalized.starts_with("x-rvoip-")
    });
    SipInboundContextPolicy::new(inbound_names)
        .map_err(|error| anyhow!(error))
        .context("constructing gateway SIP inbound context allowlist")
}

/// Health reported by the concrete public-edge/private-forwarding runtime.
pub(crate) type GatewayEdgeHealth = ForwardingHealth;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GatewayAdmissionState {
    Starting,
    Open,
    Paused,
    Draining,
}

#[derive(Debug)]
struct GatewayAdmissionStatus {
    state: GatewayAdmissionState,
    active: usize,
}

#[derive(Debug)]
struct GatewayAdmissionInner {
    #[allow(dead_code)] // Enforced by public handlers through `try_admit`.
    capacity: usize,
    status: StdMutex<GatewayAdmissionStatus>,
    idle: tokio::sync::Notify,
}

/// Linearizable admission boundary shared with the concrete gateway
/// edge. Readiness pauses new work; drain closes admission permanently while
/// already-admitted work retains its permit until it reaches a safe boundary.
#[derive(Clone, Debug)]
pub(crate) struct GatewayAdmission {
    inner: Arc<GatewayAdmissionInner>,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[allow(dead_code)] // Returned to concrete public-edge handlers as they land.
pub(crate) enum GatewayAdmissionError {
    #[error("gateway dependency is not ready")]
    NotReady,
    #[error("gateway is draining")]
    Draining,
    #[error("gateway admission capacity is exhausted")]
    CapacityExceeded,
}

#[derive(Debug)]
#[allow(dead_code)] // Owned by admitted work in the future concrete edge.
pub(crate) struct GatewayAdmissionPermit {
    inner: Option<Arc<GatewayAdmissionInner>>,
}

impl GatewayAdmission {
    fn new(capacity: usize) -> Result<Self> {
        if capacity == 0 {
            return Err(anyhow!("gateway admission capacity must be positive"));
        }
        Ok(Self {
            inner: Arc::new(GatewayAdmissionInner {
                capacity,
                status: StdMutex::new(GatewayAdmissionStatus {
                    state: GatewayAdmissionState::Starting,
                    active: 0,
                }),
                idle: tokio::sync::Notify::new(),
            }),
        })
    }

    fn set_dependency_ready(&self, ready: bool) {
        let mut status = self
            .inner
            .status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if status.state != GatewayAdmissionState::Draining {
            status.state = if ready {
                GatewayAdmissionState::Open
            } else {
                GatewayAdmissionState::Paused
            };
        }
    }

    #[allow(dead_code)] // Consumed by public control/signaling handlers.
    pub(crate) fn try_admit(
        &self,
    ) -> std::result::Result<GatewayAdmissionPermit, GatewayAdmissionError> {
        let mut status = self
            .inner
            .status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match status.state {
            GatewayAdmissionState::Open if status.active < self.inner.capacity => {
                status.active += 1;
                Ok(GatewayAdmissionPermit {
                    inner: Some(Arc::clone(&self.inner)),
                })
            }
            GatewayAdmissionState::Open => Err(GatewayAdmissionError::CapacityExceeded),
            GatewayAdmissionState::Draining => Err(GatewayAdmissionError::Draining),
            GatewayAdmissionState::Starting | GatewayAdmissionState::Paused => {
                Err(GatewayAdmissionError::NotReady)
            }
        }
    }

    fn begin_drain(&self) {
        let mut status = self
            .inner
            .status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        status.state = GatewayAdmissionState::Draining;
        if status.active == 0 {
            self.inner.idle.notify_waiters();
        }
    }

    async fn wait_idle(&self, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.inner.idle.notified();
            if self
                .inner
                .status
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .active
                == 0
            {
                return true;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return false;
            }
        }
    }

    #[cfg(test)]
    fn active(&self) -> usize {
        self.inner
            .status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .active
    }
}

impl Drop for GatewayAdmissionPermit {
    fn drop(&mut self) {
        let Some(inner) = self.inner.take() else {
            return;
        };
        let mut status = inner
            .status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        debug_assert!(status.active > 0, "gateway permit count underflow");
        status.active = status.active.saturating_sub(1);
        if status.active == 0 {
            inner.idle.notify_waiters();
        }
    }
}

impl GatewayIngressAdmission for GatewayAdmission {
    fn try_admit(
        &self,
    ) -> std::result::Result<
        Box<dyn bridgefu::gateway_uctp_ingress::GatewayIngressAdmissionLease>,
        GatewayUctpIngressError,
    > {
        GatewayAdmission::try_admit(self)
            .map(|permit| {
                Box::new(permit)
                    as Box<dyn bridgefu::gateway_uctp_ingress::GatewayIngressAdmissionLease>
            })
            .map_err(|error| match error {
                GatewayAdmissionError::NotReady => GatewayUctpIngressError::NotReady,
                GatewayAdmissionError::Draining => GatewayUctpIngressError::Draining,
                GatewayAdmissionError::CapacityExceeded => {
                    GatewayUctpIngressError::CapacityExceeded
                }
            })
    }
}

#[async_trait]
pub(crate) trait GatewayEdgeRuntime: Send + Sync {
    fn subscribe_health(&self) -> tokio::sync::watch::Receiver<GatewayEdgeHealth>;
    fn begin_drain(&self);
    async fn shutdown(&self, timeout: Duration) -> Result<()>;
}

#[async_trait]
pub(crate) trait GatewayEdgeFactory: Send + Sync {
    async fn start(
        &self,
        config: &Config,
        admission: GatewayAdmission,
    ) -> Result<Arc<dyn GatewayEdgeRuntime>>;
}

#[derive(Clone, Copy, Debug, Default)]
struct AuthenticatedGatewayEdgeFactory;

struct AuthenticatedGatewayEdge {
    forwarder: Arc<GatewayForwarder>,
    ingress: Arc<GatewayUctpIngress>,
    native: Arc<GatewayNativeIngress>,
    health: tokio::sync::watch::Sender<ForwardingHealth>,
    monitor_cancel: CancellationToken,
    monitor: StdMutex<Option<tokio::task::JoinHandle<()>>>,
}

impl AuthenticatedGatewayEdge {
    fn new(
        forwarder: Arc<GatewayForwarder>,
        ingress: Arc<GatewayUctpIngress>,
        native: Arc<GatewayNativeIngress>,
    ) -> Arc<Self> {
        let mut forwarding_health = forwarder.subscribe_health();
        let mut ingress_health = ingress.subscribe_health();
        let mut native_health = native.subscribe_health();
        let initial = combined_gateway_health(
            *forwarding_health.borrow(),
            *ingress_health.borrow(),
            *native_health.borrow(),
        );
        let (health, _) = tokio::sync::watch::channel(initial);
        let monitor_cancel = CancellationToken::new();
        let monitor_health = health.clone();
        let cancel = monitor_cancel.clone();
        let monitor = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    changed = forwarding_health.changed() => {
                        if changed.is_err() { break; }
                    }
                    changed = ingress_health.changed() => {
                        if changed.is_err() { break; }
                    }
                    changed = native_health.changed() => {
                        if changed.is_err() { break; }
                    }
                }
                monitor_health.send_replace(combined_gateway_health(
                    *forwarding_health.borrow_and_update(),
                    *ingress_health.borrow_and_update(),
                    *native_health.borrow_and_update(),
                ));
            }
        });
        Arc::new(Self {
            forwarder,
            ingress,
            native,
            health,
            monitor_cancel,
            monitor: StdMutex::new(Some(monitor)),
        })
    }
}

fn combined_gateway_health(
    forwarding: ForwardingHealth,
    ingress: GatewayUctpIngressHealth,
    native: GatewayNativeIngressHealth,
) -> ForwardingHealth {
    if forwarding == ForwardingHealth::Stopped
        || ingress == GatewayUctpIngressHealth::Stopped
        || native == GatewayNativeIngressHealth::Stopped
    {
        ForwardingHealth::Stopped
    } else if forwarding == ForwardingHealth::Draining
        || ingress == GatewayUctpIngressHealth::Draining
        || native == GatewayNativeIngressHealth::Draining
    {
        ForwardingHealth::Draining
    } else if forwarding == ForwardingHealth::Healthy
        && ingress == GatewayUctpIngressHealth::Healthy
        && native == GatewayNativeIngressHealth::Healthy
    {
        ForwardingHealth::Healthy
    } else {
        ForwardingHealth::Degraded
    }
}

#[async_trait]
impl GatewayEdgeRuntime for AuthenticatedGatewayEdge {
    fn subscribe_health(&self) -> tokio::sync::watch::Receiver<GatewayEdgeHealth> {
        self.health.subscribe()
    }

    fn begin_drain(&self) {
        self.native.begin_drain();
        self.ingress.begin_drain();
        self.forwarder.begin_drain();
    }

    async fn shutdown(&self, timeout: Duration) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        // Public ingress stops first. Keep the private forwarder and native
        // adapters alive until source End/Abort and lifecycle delivery have
        // crossed their awaited drain boundary; native sockets close last.
        let ingress_result = self
            .ingress
            .shutdown(shutdown_budget(deadline))
            .await
            .map_err(|error| anyhow!(error));
        let forwarding_result = self
            .forwarder
            .shutdown(shutdown_budget(deadline))
            .await
            .map_err(|error| anyhow!(error));
        let native_result = self
            .native
            .shutdown(shutdown_budget(deadline))
            .await
            .map_err(|error| anyhow!(error));
        self.monitor_cancel.cancel();
        let monitor = self
            .monitor
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(mut monitor) = monitor {
            if tokio::time::timeout(shutdown_budget(deadline), &mut monitor)
                .await
                .is_err()
            {
                monitor.abort();
                let _ = monitor.await;
            }
        }
        self.health.send_replace(ForwardingHealth::Stopped);
        ingress_result.context("draining authenticated gateway ingress")?;
        forwarding_result.context("draining authenticated private forwarder")?;
        native_result.context("draining authenticated native transports")
    }
}

#[async_trait]
impl GatewayEdgeFactory for AuthenticatedGatewayEdgeFactory {
    async fn start(
        &self,
        config: &Config,
        admission: GatewayAdmission,
    ) -> Result<Arc<dyn GatewayEdgeRuntime>> {
        // Redis and both QUIC edges share rustls in this process. Select the
        // reviewed provider before the first TLS client is constructed so a
        // missing dependency remains a normal fail-closed startup error
        // instead of a process-level rustls panic.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let forwarding_config = config.gateway_forwarding_config()?;
        let private_egress_gateway_id = forwarding_config.gateway_id.clone();
        let private_egress_replay_ttl = Duration::from_secs(120);
        let private_egress_max_replay_entries =
            gateway_private_egress_replay_capacity(config, private_egress_replay_ttl)?;
        let ingress_config = config.gateway_uctp_ingress_config()?;
        let mut tenants = config
            .tenant_names()?
            .into_iter()
            .map(bridgefu::call_engine::TenantId::parse)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| anyhow!("configured forwarding tenant is invalid"))?;
        if tenants.is_empty() {
            tenants.push(
                bridgefu::call_engine::TenantId::parse("bridgefu-health")
                    .expect("static health tenant is valid"),
            );
        }
        let static_tenant = gateway_static_tenant(config)
            .ok_or(RolePreflightError::GatewayAttachmentAuthenticationMissing)?;
        let bearer = config
            .api
            .bearer_token
            .as_ref()
            .ok_or(RolePreflightError::GatewayAttachmentAuthenticationMissing)?
            .resolve()
            .context("resolving gateway public UCTP bearer validator")?;
        let validator: Arc<dyn rvoip_auth_core::BearerValidator> = Arc::new(
            ConfiguredApiKeyValidator::new(bearer, [static_tenant.clone()])
                .context("configuring gateway public UCTP bearer validator")?,
        );
        let sip_auth = gateway_sip_listener_auth(config, &static_tenant, Arc::clone(&validator))?;
        let inbound_context = gateway_sip_inbound_context_policy(config)?;
        let native_config = config
            .gateway_native_ingress_config(sip_auth, inbound_context)
            .context("configuring native gateway SIP/WebRTC ingress")?;
        let fingerprint_key = config
            .api
            .control_hmac_key
            .as_ref()
            .ok_or(RolePreflightError::GatewayAttachmentAuthenticationMissing)?
            .resolve()
            .context("resolving gateway attachment fingerprint key")?
            .into_bytes();
        let signaling_tokens = Arc::new(
            SignalingTokenService::new(fingerprint_key.clone())
                .context("configuring gateway WebRTC signaling credentials")?,
        );
        let signaling_validator: Arc<dyn rvoip_auth_core::BearerValidator> =
            Arc::new(WebRtcSignalingBearerValidator::new(
                Arc::clone(&validator),
                Arc::clone(&signaling_tokens),
            ));
        let signaling_binding: Arc<dyn rvoip_webrtc::signaling::auth::WsBearerSessionBinding> =
            signaling_tokens;
        let mut coordination = config.call_coordination_config()?;
        let redis = coordination
            .redis
            .take()
            .ok_or(RolePreflightError::GatewayRequiresClusteredRedis)?;
        let projection: Arc<dyn CoordinationProjection> = Arc::new(
            RedisCoordinator::connect(redis)
                .await
                .map_err(|_| anyhow!("gateway attachment routing projection is unavailable"))?,
        );
        let route_catalog_fingerprint = worker_egress_routes(config)?.fingerprint();
        let resolver = Arc::new(
            GatewayAttachmentResolver::new(projection, fingerprint_key)
                .map_err(|_| anyhow!("gateway attachment resolver configuration is invalid"))?
                .with_route_catalog_fingerprint(route_catalog_fingerprint),
        );
        let database_url = config
            .persistence
            .database_url
            .as_ref()
            .ok_or_else(|| anyhow!("gateway broadcast authority requires PostgreSQL"))?
            .resolve()
            .context("resolving gateway broadcast command database")?;
        let deployment = config.call_coordination_config()?.deployment;
        let broadcast_repository: Arc<dyn BroadcastCommandRepository> =
            PostgresBroadcastCommandRepository::connect(database_url, deployment).await?;
        let redis_url = config
            .persistence
            .redis_url
            .as_ref()
            .ok_or_else(|| anyhow!("gateway broadcast authority requires Redis"))?
            .resolve()
            .context("resolving gateway broadcast grant authority")?;
        let broadcast_grants = RedisBroadcastGrantStore::connect(RedisBroadcastGrantConfig::new(
            redis_url,
            config.persistence.deployment_id.clone(),
        ))
        .await?;
        let broadcast_secret = config
            .broadcast
            .token_secret
            .as_ref()
            .ok_or_else(|| {
                anyhow!("gateway broadcast subscriber validation requires token_secret")
            })?
            .resolve()
            .context("resolving gateway broadcast token secret")?
            .into_bytes();
        let verifier: Arc<dyn BroadcastGrantVerifier> = broadcast_grants.clone();
        let broadcast_validator = Arc::new(
            BroadcastTokenService::new(
                broadcast_secret,
                BroadcastGrantRegistry::new(),
                Duration::from_secs(config.broadcast.token_ttl_secs),
            )?
            .with_shared_verifier(verifier),
        );
        let broadcast_authority: Arc<dyn GatewayBroadcastAuthority> =
            DurableGatewayBroadcastAuthority::new(
                broadcast_repository,
                Arc::clone(&broadcast_grants),
            );
        let forwarder = GatewayForwarder::start(forwarding_config, tenants)
            .await
            .map_err(|error| anyhow!(error))?;
        let ingress = match GatewayUctpIngress::start(
            ingress_config,
            Arc::clone(&validator),
            broadcast_validator,
            broadcast_authority,
            Arc::clone(&resolver),
            Arc::clone(&forwarder),
            Arc::new(admission.clone()),
        )
        .await
        {
            Ok(ingress) => ingress,
            Err(error) => {
                let _ = forwarder.shutdown(Duration::from_secs(2)).await;
                return Err(anyhow!(error)).context("starting public UCTP attachment ingress");
            }
        };
        let native = match GatewayNativeIngress::start_with_session_binding(
            native_config,
            signaling_validator,
            signaling_binding,
            resolver,
            Arc::clone(&forwarder),
            Arc::new(admission),
        )
        .await
        {
            Ok(native) => native,
            Err(error) => {
                let _ = ingress.shutdown(Duration::from_secs(2)).await;
                let _ = forwarder.shutdown(Duration::from_secs(2)).await;
                return Err(anyhow!(error)).context("starting native SIP/WebRTC gateway ingress");
            }
        };
        let egress_install = async {
            let profiles = gateway_egress_profiles(config)
                .context("building exact gateway egress profile catalog")?;
            let adapters = PrivateEgressGatewayAdapters::new(
                Some(native.sip_egress_adapter()),
                Some(native.webrtc_egress_adapter()),
            )
            .map_err(anyhow::Error::from)
            .context("validating staged gateway egress adapters")?;
            let handler = PrivateEgressGatewayProxyHandler::new_with_lifecycle(
                Arc::clone(&forwarder),
                native.egress_orchestrator(),
                adapters,
                profiles,
                native.egress_event_router(),
                PrivateEgressGatewayProxyConfig {
                    media_setup_timeout: Duration::from_secs(
                        config.runtime.setup_timeout_secs.clamp(1, 30),
                    ),
                    operation_timeout: Duration::from_secs(
                        config
                            .private_forwarding
                            .timeouts
                            .signaling_secs
                            .clamp(1, 30),
                    ),
                },
            )
            .map_err(anyhow::Error::from)
            .context("constructing authoritative gateway egress proxy")?;
            if !handler.has_authoritative_lifecycle() {
                return Err(anyhow!("gateway egress lifecycle authority is unavailable"));
            }
            let max_active_routes = config.private_forwarding.limits.max_active_routes;
            let redis_url = config
                .persistence
                .redis_url
                .as_ref()
                .ok_or_else(|| anyhow!("gateway private-egress state requires Redis"))?
                .resolve()
                .context("resolving gateway private-egress state authority")?;
            let mut state_config = RedisPrivateEgressStateConfig::new(
                redis_url,
                config.persistence.deployment_id.clone(),
            );
            state_config.entry_ttl = private_egress_replay_ttl;
            state_config.max_entries = private_egress_max_replay_entries;
            state_config.operation_timeout = Duration::from_secs(
                config
                    .private_forwarding
                    .timeouts
                    .signaling_secs
                    .clamp(1, 10),
            );
            let state_store: Arc<dyn PrivateEgressStateStore> =
                RedisPrivateEgressStateStore::connect(state_config)
                    .await
                    .map_err(anyhow::Error::from)
                    .context("opening durable gateway private-egress state")?;
            let gateway_epoch =
                PrivateEgressGatewayEpoch::new(private_egress_gateway_id, uuid::Uuid::new_v4())
                    .map_err(anyhow::Error::from)
                    .context("constructing gateway private-egress epoch")?;
            let service = PrivateEgressCommandService::new_with_state_store(
                handler,
                PrivateEgressServiceConfig {
                    max_active_routes,
                    max_replay_entries: private_egress_max_replay_entries,
                    replay_ttl: private_egress_replay_ttl,
                    operation_timeout: Duration::from_secs(
                        config
                            .private_forwarding
                            .timeouts
                            .signaling_secs
                            .clamp(1, 30),
                    ),
                },
                gateway_epoch,
                state_store,
            )
            .await
            .map_err(anyhow::Error::from)
            .context("constructing gateway private-egress command authority")?;
            require_clustered_private_egress_state(&service)?;
            forwarder
                .install_private_egress_service(service)
                .map_err(anyhow::Error::from)
                .context("installing gateway private-egress command authority")
        }
        .await;
        if let Err(error) = egress_install {
            let _ = ingress.shutdown(Duration::from_secs(2)).await;
            let _ = forwarder.shutdown(Duration::from_secs(2)).await;
            let _ = native.shutdown(Duration::from_secs(2)).await;
            return Err(error);
        }
        tracing::info!(
            public_uctp_addr = %ingress.local_addr(),
            sip_addr = %native.sip_addr(),
            webrtc_websocket_addr = %native.websocket_addr(),
            whip_whep_addr = %native.whip_whep_addr(),
            secure_webrtc_signaling = native.secure_signaling(),
            "split gateway started authenticated UCTP, SIP/RTP, and WebRTC attachment ingress"
        );
        Ok(AuthenticatedGatewayEdge::new(forwarder, ingress, native)
            as Arc<dyn GatewayEdgeRuntime>)
    }
}

fn require_clustered_private_egress_state(service: &PrivateEgressCommandService) -> Result<()> {
    if service.has_durable_state() {
        Ok(())
    } else {
        Err(anyhow!(
            "split gateway private-egress requires a shared durable state store; the hermetic memory store is permitted only in all-in-one mode"
        ))
    }
}

#[async_trait]
impl GatewayEdgeRuntime for GatewayForwarder {
    fn subscribe_health(&self) -> tokio::sync::watch::Receiver<GatewayEdgeHealth> {
        GatewayForwarder::subscribe_health(self)
    }

    fn begin_drain(&self) {
        GatewayForwarder::begin_drain(self);
    }

    async fn shutdown(&self, timeout: Duration) -> Result<()> {
        GatewayForwarder::shutdown(self, timeout)
            .await
            .map_err(|error| anyhow!(error))
    }
}

struct GatewayRoleRuntime {
    health: RoleHealth,
    admission: GatewayAdmission,
    edge: Arc<dyn GatewayEdgeRuntime>,
    edge_health: tokio::sync::watch::Receiver<GatewayEdgeHealth>,
    draining: std::sync::atomic::AtomicBool,
}

impl GatewayRoleRuntime {
    #[cfg(test)]
    async fn start(config: &Config, factory: &dyn GatewayEdgeFactory) -> Result<Self> {
        Self::start_with_health(config, factory, RoleHealth::new(RuntimeMode::Gateway)).await
    }

    async fn start_with_health(
        config: &Config,
        factory: &dyn GatewayEdgeFactory,
        health: RoleHealth,
    ) -> Result<Self> {
        let capacity = config
            .runtime
            .max_concurrent_calls
            .checked_mul(2)
            .and_then(|calls| {
                config
                    .private_forwarding
                    .gateway
                    .as_ref()
                    .and_then(|gateway| gateway.public_uctp.as_ref())
                    .map_or(Some(calls), |listener| {
                        calls.checked_add(listener.max_concurrent_connections)
                    })
            })
            .ok_or_else(|| anyhow!("gateway admission capacity overflow"))?;
        let admission = GatewayAdmission::new(capacity)?;
        let edge = match factory.start(config, admission.clone()).await {
            Ok(edge) => edge,
            Err(error) => {
                health.transition(RoleLifecycle::Failed);
                return Err(error).context("starting authenticated gateway edge dependency");
            }
        };
        let edge_health = edge.subscribe_health();
        Ok(Self {
            health,
            admission,
            edge,
            edge_health,
            draining: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn apply_dependency_health_with_control(
        &self,
        dependency: GatewayEdgeHealth,
        control: Option<CallControlRuntimeHealth>,
    ) {
        if matches!(control, Some(CallControlRuntimeHealth::Stopped)) {
            self.admission.begin_drain();
            self.health.transition(RoleLifecycle::Failed);
            return;
        }
        if matches!(control, Some(CallControlRuntimeHealth::Draining)) {
            self.admission.begin_drain();
            self.health.transition(RoleLifecycle::Draining);
            return;
        }
        if matches!(control, Some(CallControlRuntimeHealth::Degraded)) {
            self.admission.set_dependency_ready(false);
            self.health.transition(RoleLifecycle::Degraded);
            return;
        }
        match dependency {
            GatewayEdgeHealth::Healthy => {
                self.admission.set_dependency_ready(true);
                self.health.transition(RoleLifecycle::Ready);
            }
            GatewayEdgeHealth::Degraded => {
                self.admission.set_dependency_ready(false);
                self.health.transition(RoleLifecycle::Degraded);
            }
            GatewayEdgeHealth::Draining => {
                self.admission.begin_drain();
                self.health.transition(RoleLifecycle::Draining);
            }
            GatewayEdgeHealth::Stopped => {
                self.admission.begin_drain();
                self.health.transition(RoleLifecycle::Failed);
            }
        }
    }

    fn begin_drain(&self) {
        if !self
            .draining
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            self.admission.begin_drain();
            self.edge.begin_drain();
        }
    }

    async fn shutdown(self, timeout: Duration) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        self.begin_drain();
        let admission_idle = self.admission.wait_idle(shutdown_budget(deadline)).await;
        let edge_result = self.edge.shutdown(shutdown_budget(deadline)).await;
        if !admission_idle {
            return Err(anyhow!("gateway admission drain timed out"));
        }
        edge_result.context("draining authenticated gateway edge dependency")
    }
}

/// Run the gateway role lifecycle shell.
///
/// The shell owns operational health, bounded admission, and ordered drain.
/// The concrete dependency owns mutually authenticated UCTP 0.2 peers and
/// remains non-ready until every configured worker target authenticates.
pub async fn run_gateway(
    config: &Config,
    metrics: PrometheusHandle,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<()> {
    run_gateway_with_factory(config, metrics, shutdown, &AuthenticatedGatewayEdgeFactory).await
}

async fn run_gateway_with_factory(
    config: &Config,
    metrics: PrometheusHandle,
    shutdown: impl Future<Output = ()> + Send,
    factory: &dyn GatewayEdgeFactory,
) -> Result<()> {
    let plan = preflight(config)?;
    debug_assert!(plan.public_control_http && plan.public_signaling);
    debug_assert!(plan.public_sip && plan.public_webrtc && plan.public_uctp);
    debug_assert!(!plan.amazon_connect_media && !plan.durable_call_worker);
    let http_bind: SocketAddr = config.observability.http_bind.parse().with_context(|| {
        format!(
            "invalid observability.http_bind: {}",
            config.observability.http_bind
        )
    })?;
    let api_bind: SocketAddr = config
        .api
        .http_bind
        .as_deref()
        .ok_or(RolePreflightError::GatewayPublicApiBindMissing)?
        .parse()
        .context("invalid gateway api.http_bind")?;
    // The call-control Redis client and the QUIC edges share rustls. Select
    // the reviewed provider before constructing either dependency.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let health = RoleHealth::new(RuntimeMode::Gateway);
    let api_tls = match &config.api.tls {
        Some(tls) => match axum_server::tls_rustls::RustlsConfig::from_pem_file(
            &tls.certificate_chain,
            &tls.private_key,
        )
        .await
        {
            Ok(tls) => Some(tls),
            Err(error) => {
                health.transition(RoleLifecycle::Failed);
                return Err(error).context("loading gateway public API TLS certificate and key");
            }
        },
        None => None,
    };
    // The transport-free API authority is opened before either public socket.
    // PostgreSQL/Redis/configuration failure therefore cannot leave a briefly
    // reachable UCTP or HTTP edge, and this process never registers a worker.
    let tenants = config.tenant_names()?;
    let api_state = match crate::api::ApiState::from_gateway_config(
        config,
        metrics.clone(),
        tenants,
        health.clone(),
    )
    .await
    {
        Ok(state) => state,
        Err(error) => {
            health.transition(RoleLifecycle::Failed);
            return Err(error).context("starting split gateway call-control authority");
        }
    };
    let control_runtime = api_state
        .call_control_runtime()
        .ok_or_else(|| anyhow!("split gateway call-control authority is unavailable"))?;
    let runtime = match GatewayRoleRuntime::start_with_health(config, factory, health).await {
        Ok(runtime) => runtime,
        Err(error) => {
            drop(api_state);
            shutdown_gateway_control_runtime(
                control_runtime,
                Duration::from_secs(config.runtime.drain_timeout_secs.max(1)),
            )
            .await?;
            return Err(error);
        }
    };
    let api_listener = match tokio::net::TcpListener::bind(api_bind).await {
        Ok(listener) => listener,
        Err(error) => {
            runtime.health.transition(RoleLifecycle::Failed);
            let _ = runtime
                .shutdown(Duration::from_secs(
                    config.runtime.drain_timeout_secs.max(1),
                ))
                .await;
            drop(api_state);
            shutdown_gateway_control_runtime(
                control_runtime,
                Duration::from_secs(config.runtime.drain_timeout_secs.max(1)),
            )
            .await?;
            return Err(error)
                .with_context(|| format!("binding gateway public API endpoint {api_bind}"));
        }
    };
    let operations_listener = match tokio::net::TcpListener::bind(http_bind).await {
        Ok(listener) => listener,
        Err(error) => {
            drop(api_listener);
            runtime.health.transition(RoleLifecycle::Failed);
            let _ = runtime
                .shutdown(Duration::from_secs(
                    config.runtime.drain_timeout_secs.max(1),
                ))
                .await;
            drop(api_state);
            shutdown_gateway_control_runtime(
                control_runtime,
                Duration::from_secs(config.runtime.drain_timeout_secs.max(1)),
            )
            .await?;
            return Err(error)
                .with_context(|| format!("binding gateway operations endpoint {http_bind}"));
        }
    };
    let operations_app = role_health_router(runtime.health.clone(), metrics);
    run_gateway_runtime_with_app(
        runtime,
        GatewayHttpSurfaces {
            operations_listener,
            operations_app,
            public_api: Some(GatewayPublicApiSurface {
                listener: api_listener,
                app: crate::api::public_router(api_state),
                tls: api_tls,
            }),
            control_runtime: Some(control_runtime),
            close_http_before_edge_drain: true,
        },
        shutdown,
        Duration::from_secs(config.runtime.drain_timeout_secs.max(1)),
    )
    .await
}

struct GatewayPublicApiSurface {
    listener: tokio::net::TcpListener,
    app: axum::Router,
    tls: Option<axum_server::tls_rustls::RustlsConfig>,
}

struct GatewayHttpSurfaces {
    operations_listener: tokio::net::TcpListener,
    operations_app: axum::Router,
    public_api: Option<GatewayPublicApiSurface>,
    control_runtime: Option<Arc<bridgefu::call_service::CallControlRuntime>>,
    close_http_before_edge_drain: bool,
}

#[cfg(test)]
async fn run_gateway_runtime(
    runtime: GatewayRoleRuntime,
    listener: tokio::net::TcpListener,
    metrics: PrometheusHandle,
    shutdown: impl Future<Output = ()> + Send,
    drain_timeout: Duration,
) -> Result<()> {
    let app = role_health_router(runtime.health.clone(), metrics);
    run_gateway_runtime_with_app(
        runtime,
        GatewayHttpSurfaces {
            operations_listener: listener,
            operations_app: app,
            public_api: None,
            control_runtime: None,
            close_http_before_edge_drain: false,
        },
        shutdown,
        drain_timeout,
    )
    .await
}

async fn run_gateway_runtime_with_app(
    mut runtime: GatewayRoleRuntime,
    surfaces: GatewayHttpSurfaces,
    shutdown: impl Future<Output = ()> + Send,
    drain_timeout: Duration,
) -> Result<()> {
    let GatewayHttpSurfaces {
        operations_listener: listener,
        operations_app: app,
        public_api: secondary_http,
        control_runtime,
        close_http_before_edge_drain,
    } = surfaces;
    let (http_shutdown, http_shutdown_rx) = tokio::sync::watch::channel(false);
    let bind = listener
        .local_addr()
        .context("reading gateway HTTP listener address")?;
    let secondary_bind = secondary_http
        .as_ref()
        .map(|secondary| secondary.listener.local_addr())
        .transpose()
        .context("reading gateway public API listener address")?;
    let secondary_tls = secondary_http
        .as_ref()
        .is_some_and(|secondary| secondary.tls.is_some());
    let secondary_shutdown_rx = http_shutdown.subscribe();
    tracing::info!(operations_bind = %bind, public_api_bind = ?secondary_bind, public_api_tls = secondary_tls, "Bridgefu gateway HTTP surfaces listening");
    let mut http = tokio::spawn(async move {
        let primary = async {
            axum::serve(listener, app)
                .with_graceful_shutdown(wait_for_stop(http_shutdown_rx))
                .await
                .context("serving gateway operations HTTP surface")
        };
        match secondary_http {
            Some(secondary) => {
                let secondary = serve_gateway_public_api(
                    secondary.listener,
                    secondary.app,
                    secondary.tls,
                    secondary_shutdown_rx,
                    drain_timeout,
                );
                tokio::try_join!(primary, secondary).map(|_| ())
            }
            None => primary.await,
        }
    });
    let mut http_finished = false;
    let mut edge_state = *runtime.edge_health.borrow_and_update();
    let mut control_health = control_runtime
        .as_ref()
        .map(|runtime| runtime.subscribe_health());
    let mut control_state = control_health
        .as_mut()
        .map(|health| *health.borrow_and_update());
    runtime.apply_dependency_health_with_control(edge_state, control_state);
    tracing::info!(
        edge_dependency = ?edge_state,
        control_dependency = ?control_state,
        "Bridgefu gateway lifecycle shell started"
    );

    tokio::pin!(shutdown);
    let mut run_error = match edge_state {
        GatewayEdgeHealth::Healthy | GatewayEdgeHealth::Degraded => None,
        GatewayEdgeHealth::Draining => {
            Some(anyhow!("gateway dependency began draining during startup"))
        }
        GatewayEdgeHealth::Stopped => {
            Some(anyhow!("gateway dependency was unavailable during startup"))
        }
    };
    if matches!(
        control_state,
        Some(CallControlRuntimeHealth::Draining | CallControlRuntimeHealth::Stopped)
    ) {
        run_error = Some(anyhow!(
            "gateway call-control dependency was unavailable during startup"
        ));
    }
    while run_error.is_none() {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received; draining gateway");
                break;
            }
            result = &mut http => {
                http_finished = true;
                runtime.health.transition(RoleLifecycle::Failed);
                run_error = Some(match result {
                    Ok(Ok(())) => anyhow!("gateway health server stopped before process drain"),
                    Ok(Err(error)) => error.context("gateway health server failed"),
                    Err(error) => anyhow!(error).context("gateway health server task failed"),
                });
            }
            changed = runtime.edge_health.changed() => {
                edge_state = if changed.is_err() {
                    GatewayEdgeHealth::Stopped
                } else {
                    *runtime.edge_health.borrow_and_update()
                };
                runtime.apply_dependency_health_with_control(edge_state, control_state);
                if matches!(
                    edge_state,
                    GatewayEdgeHealth::Draining
                        | GatewayEdgeHealth::Stopped
                ) {
                    run_error = Some(anyhow!("gateway dependency stopped serving"));
                }
            }
            next = wait_for_control_health_change(&mut control_health) => {
                control_state = Some(next);
                runtime.apply_dependency_health_with_control(edge_state, control_state);
                if matches!(
                    next,
                    CallControlRuntimeHealth::Draining | CallControlRuntimeHealth::Stopped
                ) {
                    run_error = Some(anyhow!("gateway call-control dependency stopped serving"));
                }
            }
        }
    }

    if run_error.is_none() {
        runtime.health.transition(RoleLifecycle::Draining);
    }
    let health = runtime.health.clone();
    let shutdown_deadline = tokio::time::Instant::now() + drain_timeout;
    runtime.begin_drain();
    if close_http_before_edge_drain {
        // Stop accepting authenticated mutations before the public UCTP edge
        // enters drain. In-flight requests retain their normal transactional
        // outcome and no request is rerouted to local execution.
        let _ = http_shutdown.send(true);
    }

    // The production API owns the final Arc to call control. Release its HTTP
    // router first, then drain call control while the private forwarder and
    // native adapters remain available for End/Abort and lifecycle delivery.
    if close_http_before_edge_drain && !http_finished {
        if tokio::time::timeout(shutdown_budget(shutdown_deadline), &mut http)
            .await
            .is_err()
        {
            tracing::warn!(
                "gateway HTTP surfaces did not release call control before the configured deadline; aborting task"
            );
            http.abort();
            let _ = (&mut http).await;
        }
        http_finished = true;
    }
    let control_shutdown = match control_runtime {
        Some(control_runtime) => {
            shutdown_gateway_control_runtime(control_runtime, shutdown_budget(shutdown_deadline))
                .await
        }
        None => Ok(()),
    };
    let shutdown_result = runtime.shutdown(shutdown_budget(shutdown_deadline)).await;

    let _ = http_shutdown.send(true);
    if !http_finished
        && tokio::time::timeout(shutdown_budget(shutdown_deadline), &mut http)
            .await
            .is_err()
    {
        tracing::warn!(
            "gateway HTTP surfaces did not drain before the configured deadline; aborting task"
        );
        http.abort();
        let _ = (&mut http).await;
    }

    if let Some(error) = run_error {
        health.transition(RoleLifecycle::Failed);
        let _ = shutdown_result;
        let _ = control_shutdown;
        return Err(error);
    }
    match (shutdown_result, control_shutdown) {
        (Ok(()), Ok(())) => {
            health.transition(RoleLifecycle::Stopped);
            tracing::info!("Bridgefu gateway lifecycle shell stopped");
            Ok(())
        }
        (Err(error), _) | (_, Err(error)) => {
            health.transition(RoleLifecycle::Failed);
            Err(error)
        }
    }
}

async fn wait_for_control_health_change(
    health: &mut Option<tokio::sync::watch::Receiver<CallControlRuntimeHealth>>,
) -> CallControlRuntimeHealth {
    let Some(health) = health.as_mut() else {
        return std::future::pending().await;
    };
    if health.changed().await.is_err() {
        CallControlRuntimeHealth::Stopped
    } else {
        *health.borrow_and_update()
    }
}

async fn serve_gateway_public_api(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    tls: Option<axum_server::tls_rustls::RustlsConfig>,
    shutdown: tokio::sync::watch::Receiver<bool>,
    drain_timeout: Duration,
) -> Result<()> {
    let Some(tls) = tls else {
        return axum::serve(listener, app)
            .with_graceful_shutdown(wait_for_stop(shutdown))
            .await
            .context("serving loopback gateway public API surface");
    };

    let listener = listener
        .into_std()
        .context("converting gateway public API TLS listener")?;
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    let shutdown_task = tokio::spawn(async move {
        wait_for_stop(shutdown).await;
        shutdown_handle.graceful_shutdown(Some(drain_timeout));
    });
    let result = axum_server::from_tcp_rustls(listener, tls)
        .handle(handle)
        .serve(app.into_make_service())
        .await
        .context("serving TLS gateway public API surface");
    shutdown_task.abort();
    let _ = shutdown_task.await;
    result
}

async fn shutdown_gateway_control_runtime(
    runtime: Arc<bridgefu::call_service::CallControlRuntime>,
    timeout: Duration,
) -> Result<()> {
    let strong_count = Arc::strong_count(&runtime);
    let runtime = Arc::try_unwrap(runtime).map_err(|_| {
        anyhow!("gateway call-control runtime retained {strong_count} owners during drain")
    })?;
    runtime.shutdown(timeout).await;
    Ok(())
}

/// Run a durable worker and a health/metrics-only operational endpoint.
/// Public call control, SIP, WebRTC, provider webhooks, and Connect SIP ingress
/// are never constructed in this role.
pub async fn run_worker(
    config: &Config,
    metrics: PrometheusHandle,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<()> {
    let plan = preflight(config)?;
    debug_assert!(plan.durable_call_worker);
    debug_assert!(!plan.public_control_http && !plan.public_signaling);

    // Validate the only worker listener before registering a durable worker
    // fence. A bad bind must not leave a briefly admitted worker behind.
    let http_bind: SocketAddr = config.observability.http_bind.parse().with_context(|| {
        format!(
            "invalid observability.http_bind: {}",
            config.observability.http_bind
        )
    })?;
    let health = RoleHealth::new(RuntimeMode::Worker);
    let worker = match WorkerRoleRuntime::start(config).await {
        Ok(worker) => worker,
        Err(error) => {
            health.transition(RoleLifecycle::Failed);
            return Err(error);
        }
    };
    let mut worker_health = worker.subscribe_health();
    let mut forwarding_health = worker
        .subscribe_forwarding_health()
        .ok_or_else(|| anyhow!("worker private forwarding health is unavailable"))?;

    let listener = match tokio::net::TcpListener::bind(http_bind).await {
        Ok(listener) => listener,
        Err(error) => {
            health.transition(RoleLifecycle::Failed);
            worker
                .shutdown(Duration::from_secs(
                    config.runtime.drain_timeout_secs.max(1),
                ))
                .await
                .context("draining worker after operational listener bind failure")?;
            return Err(error)
                .with_context(|| format!("binding worker health endpoint {http_bind}"));
        }
    };
    let (http_shutdown, http_shutdown_rx) = tokio::sync::watch::channel(false);
    let app = role_health_router(health.clone(), metrics);
    let mut http = tokio::spawn(serve_role_health(
        listener,
        app,
        wait_for_stop(http_shutdown_rx),
    ));
    let mut http_finished = false;

    let mut durable_state = *worker_health.borrow_and_update();
    let mut forwarding_state = *forwarding_health.borrow_and_update();
    let initial_dependency = worker_dependency_lifecycle(durable_state, forwarding_state);
    match initial_dependency {
        Ok(state) => health.transition(state),
        Err(_) => health.transition(RoleLifecycle::Failed),
    }
    tracing::info!(
        backend = worker.call_runtime.backend().as_str(),
        worker_id = %worker.call_runtime.worker().lease.worker_id,
        worker_fence = worker.call_runtime.worker().lease.fence.as_i64(),
        durable_dependency = ?durable_state,
        forwarding_dependency = ?forwarding_state,
        "durable Bridgefu worker started without public signaling or control listeners"
    );

    tokio::pin!(shutdown);
    let run_error = loop {
        if let Err(error) = initial_dependency {
            break Some(anyhow!(error));
        }
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received; draining worker");
                break None;
            }
            result = &mut http => {
                http_finished = true;
                health.transition(RoleLifecycle::Failed);
                let error = match result {
                    Ok(Ok(())) => anyhow!("worker health server stopped before process drain"),
                    Ok(Err(error)) => error.context("worker health server failed"),
                    Err(error) => anyhow!(error).context("worker health server task failed"),
                };
                break Some(error);
            }
            changed = worker_health.changed() => {
                durable_state = if changed.is_err() {
                    RuntimeSupervisorHealth::Stopped
                } else {
                    *worker_health.borrow_and_update()
                };
                match worker_dependency_lifecycle(durable_state, forwarding_state) {
                    Ok(state) => health.transition(state),
                    Err(error) => {
                        health.transition(RoleLifecycle::Failed);
                        break Some(anyhow!(error));
                    }
                }
            }
            changed = forwarding_health.changed() => {
                forwarding_state = if changed.is_err() {
                    ForwardingHealth::Stopped
                } else {
                    *forwarding_health.borrow_and_update()
                };
                match worker_dependency_lifecycle(durable_state, forwarding_state) {
                    Ok(state) => health.transition(state),
                    Err(error) => {
                        health.transition(RoleLifecycle::Failed);
                        break Some(anyhow!(error));
                    }
                }
            }
        }
    };

    if run_error.is_none() {
        health.transition(RoleLifecycle::Draining);
    }
    let drain_timeout = Duration::from_secs(config.runtime.drain_timeout_secs.max(1));
    let shutdown_deadline = tokio::time::Instant::now() + drain_timeout;
    let shutdown_result = worker.shutdown(shutdown_budget(shutdown_deadline)).await;

    let _ = http_shutdown.send(true);
    if !http_finished
        && tokio::time::timeout(
            shutdown_budget(shutdown_deadline).min(Duration::from_secs(3)),
            &mut http,
        )
        .await
        .is_err()
    {
        tracing::warn!("worker health server did not drain; aborting task");
        http.abort();
        let _ = http.await;
    }

    if let Some(error) = run_error {
        let _ = shutdown_result;
        return Err(error);
    }
    match shutdown_result {
        Ok(()) => {
            health.transition(RoleLifecycle::Stopped);
            tracing::info!("Bridgefu worker stopped");
            Ok(())
        }
        Err(error) => {
            health.transition(RoleLifecycle::Failed);
            Err(error)
        }
    }
}

fn worker_dependency_lifecycle(
    durable: RuntimeSupervisorHealth,
    forwarding: ForwardingHealth,
) -> std::result::Result<RoleLifecycle, &'static str> {
    if matches!(
        durable,
        RuntimeSupervisorHealth::LeaseLost | RuntimeSupervisorHealth::Stopped
    ) {
        return Err("durable worker authority was lost");
    }
    if forwarding == ForwardingHealth::Stopped {
        return Err("worker private forwarding listener stopped");
    }
    if durable == RuntimeSupervisorHealth::Draining || forwarding == ForwardingHealth::Draining {
        return Ok(RoleLifecycle::Draining);
    }
    if durable == RuntimeSupervisorHealth::Degraded || forwarding == ForwardingHealth::Degraded {
        return Ok(RoleLifecycle::Degraded);
    }
    Ok(RoleLifecycle::Ready)
}

fn required_public_uctp_endpoint(value: Option<&str>) -> Result<url::Url> {
    let value = value.ok_or_else(|| {
        anyhow!("split worker requires broadcast.public_endpoint for UCTP subscribers")
    })?;
    let endpoint = value
        .parse::<url::Url>()
        .context("parsing broadcast.public_endpoint")?;
    if endpoint.scheme() != "uctp+quic"
        || endpoint.host_str().is_none()
        || endpoint.port().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.path() != ""
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(anyhow!(
            "broadcast.public_endpoint must be uctp+quic://host:port"
        ));
    }
    Ok(endpoint)
}

fn worker_capabilities_for_registered_adapters(
    mut configured: std::collections::BTreeSet<String>,
    amazon_connect_registered: bool,
    registered_providers: &std::collections::BTreeSet<String>,
    private_egress_routes: Option<&PrivateEgressWorkerRouteCatalog>,
) -> std::collections::BTreeSet<String> {
    if let Some(routes) = private_egress_routes {
        configured.insert(routes.fingerprint().advertisement_capability());
    }
    let sip_requested = configured.remove("sip_egress");
    if sip_requested
        && private_egress_routes
            .is_some_and(|routes| routes.supports_transport(PrivateEgressTransport::Sip))
    {
        configured.insert("sip_egress".to_owned());
    }
    let webrtc_requested = configured.remove("webrtc_egress");
    if webrtc_requested
        && private_egress_routes
            .is_some_and(|routes| routes.supports_transport(PrivateEgressTransport::WebRtc))
    {
        configured.insert("webrtc_egress".to_owned());
    }

    // Outbound adapters and provider executors are capability authorities,
    // not YAML. Retain the operator's allowlist only when the corresponding
    // concrete implementation was constructed in this process.
    let amazon_connect_configured = configured.remove("amazon_connect");
    if amazon_connect_configured && amazon_connect_registered {
        configured.insert("amazon_connect".to_owned());
    }
    for provider in ["telnyx", "twilio", "vonage"] {
        let requested = configured.remove(provider);
        if requested && registered_providers.contains(provider) {
            configured.insert(provider.to_owned());
        }
    }
    configured
}

struct PrivateEgressWorkerOptions {
    routes: Arc<PrivateEgressWorkerRouteCatalog>,
    max_pending_commands: usize,
    max_active_admissions: usize,
    command_timeout: Duration,
}

struct WorkerRoleRuntime {
    call_runtime: Arc<CallServiceRuntime>,
    orchestrator: Arc<Orchestrator>,
    amazon_connect: Option<Arc<AmazonConnectAdapter>>,
    broadcast_subscription_authority: Arc<WorkerBroadcastSubscriptionAuthority>,
    private_egress: Option<Arc<PrivateEgressWorkerRuntime>>,
    execution: Option<CallExecutionSupervisor>,
    forwarding: Option<Arc<WorkerForwardingRuntime>>,
    broadcasts: Option<Arc<BroadcastCommandExecutor>>,
}

impl WorkerRoleRuntime {
    async fn start(config: &Config) -> Result<Self> {
        let control_key = config
            .api
            .control_hmac_key
            .as_ref()
            .ok_or(RolePreflightError::WorkerControlKeyMissing)?
            .resolve()
            .context("resolving worker control key")?
            .into_bytes();
        let runtime_config = CallServiceRuntimeConfig {
            backend: config.call_repository_backend()?,
            worker_id: config.call_worker_id()?,
            max_calls: config.runtime.max_concurrent_calls,
            worker_capabilities: config.call_worker_capabilities(),
            control_key,
            timeouts: CallTimeoutPolicy {
                setup: Duration::from_secs(config.runtime.setup_timeout_secs),
                media_idle: Duration::from_secs(config.runtime.media_idle_timeout_secs),
                transfer: Duration::from_secs(30),
                ending: Duration::from_secs(config.runtime.drain_timeout_secs.max(1)),
            },
            coordination: config.call_coordination_config()?,
        };
        let admission_capacity = config
            .runtime
            .max_concurrent_calls
            .checked_mul(2)
            .ok_or_else(|| anyhow!("worker admission capacity overflow"))?;
        let tenants = config.tenant_names()?;
        let attachment_principals: Arc<dyn AttachmentPrincipalResolver> =
            Arc::new(config.attachment_principal_resolver(&tenants)?);
        let provider_registry = ProviderRegistry::from_config(&config.providers)?;
        let registered_providers = provider_registry.names().into_iter().collect();
        let provider_executor: Arc<dyn ProviderLegExecutor> = Arc::new(provider_registry);
        let amazon_connect = config
            .build_worker_amazon_connect_adapter()
            .await
            .context("building split-worker Amazon Connect adapter")?;
        let outbound_profiles = config
            .outbound_profile_resolver()
            .context("configuring split-worker outbound signaling profiles")?;
        let private_egress_options = PrivateEgressWorkerOptions {
            routes: worker_egress_routes(config)?,
            max_pending_commands: config.private_forwarding.limits.max_active_routes,
            max_active_admissions: config.private_forwarding.limits.max_active_routes,
            command_timeout: Duration::from_secs(
                config
                    .private_forwarding
                    .timeouts
                    .signaling_secs
                    .clamp(1, 30),
            ),
        };
        let mut worker = Self::start_with_components(
            runtime_config,
            admission_capacity,
            Duration::from_secs(config.runtime.setup_timeout_secs),
            attachment_principals,
            provider_executor,
            Arc::new(config.context.clone()),
            Some(amazon_connect),
            outbound_profiles,
            registered_providers,
            Some(private_egress_options),
        )
        .await?;

        if let Err(error) = worker.configure_post_start(config).await {
            return Err(Self::cleanup_failed_start(worker, error).await);
        }
        Ok(worker)
    }

    /// Complete every fallible operation after the durable worker and its
    /// execution owner exist. Keeping this as one result boundary guarantees
    /// that configuration, secret resolution, dependency connection, and
    /// broadcast-policy failures all converge through the same bounded drain.
    async fn configure_post_start(&mut self, config: &Config) -> Result<()> {
        let broadcast_subscription_authority = Arc::clone(&self.broadcast_subscription_authority);
        let private_egress = self
            .private_egress
            .as_ref()
            .ok_or_else(|| anyhow!("split worker private-egress owner is unavailable"))?;
        let forwarding = WorkerForwardingRuntime::start_with_broadcast_and_private_egress(
            config
                .worker_forwarding_config()
                .context("configuring private UCTP worker listener")?,
            Arc::clone(&self.orchestrator),
            Arc::clone(&broadcast_subscription_authority),
            private_egress.admissions(),
        )
        .await
        .map_err(anyhow::Error::from)
        .context("starting private UCTP worker listener")?;
        self.forwarding = Some(forwarding);
        let database_url = config
            .persistence
            .database_url
            .as_ref()
            .ok_or_else(|| anyhow!("worker broadcast command repository requires PostgreSQL"))?
            .resolve()
            .context("resolving worker broadcast command database")?;
        let deployment = config.call_coordination_config()?.deployment;
        let command_repository =
            PostgresBroadcastCommandRepository::connect(database_url, deployment)
                .await
                .map_err(anyhow::Error::from)
                .context("opening durable broadcast command queue")?;
        let redis_url = config
            .persistence
            .redis_url
            .as_ref()
            .ok_or_else(|| anyhow!("worker broadcast authority requires Redis"))?
            .resolve()
            .context("resolving worker broadcast grant authority")?;
        let shared_grants = RedisBroadcastGrantStore::connect(RedisBroadcastGrantConfig::new(
            redis_url,
            config.persistence.deployment_id.clone(),
        ))
        .await
        .map_err(anyhow::Error::from)
        .context("opening shared broadcast grant authority")?;
        let public_uctp_endpoint =
            required_public_uctp_endpoint(config.broadcast.public_endpoint.as_deref())?;
        let moq_relay = config
            .broadcast
            .moq_origin_relay
            .as_ref()
            .map(|relay| {
                let bind = relay
                    .bind
                    .parse::<SocketAddr>()
                    .context("parsing broadcast.moq_origin_relay.bind")?;
                let client = rvoip_moq::MoqRelayClient::bind(
                    bind,
                    rvoip_moq::MoqRelayTlsConfig {
                        root_certificates: relay.root_certificates.iter().map(Into::into).collect(),
                        client_certificate: Some(relay.client_certificate.clone().into()),
                        client_private_key: Some(relay.client_private_key.clone().into()),
                    },
                )
                .context("binding MOQT origin relay client")?;
                Ok::<_, anyhow::Error>(MoqRelayTarget {
                    client,
                    publisher_endpoint: relay
                        .publisher_endpoint
                        .parse()
                        .context("parsing broadcast.moq_origin_relay.publisher_endpoint")?,
                    subscriber_endpoint: relay
                        .subscriber_endpoint
                        .parse()
                        .context("parsing broadcast.moq_origin_relay.subscriber_endpoint")?,
                })
            })
            .transpose()?;
        let command_repository: Arc<dyn BroadcastCommandRepository> = command_repository;
        let executor = BroadcastCommandExecutor::start_with_subscription_authority(
            command_repository,
            Arc::clone(&self.call_runtime),
            Arc::clone(&self.orchestrator),
            Some(shared_grants),
            BroadcastCommandExecutorConfig {
                public_uctp_endpoint,
                moq_relay,
                sanitized_event_policies: config
                    .broadcast
                    .sanitized_events
                    .policies(&config.context)?,
            },
            broadcast_subscription_authority,
        )
        .map_err(anyhow::Error::from)
        .context("starting durable broadcast command executor")?;
        self.broadcasts = Some(executor);
        Ok(())
    }

    async fn cleanup_failed_start(worker: Self, startup_error: anyhow::Error) -> anyhow::Error {
        let deadline = tokio::time::Instant::now() + WORKER_STARTUP_CLEANUP_TIMEOUT;
        match tokio::time::timeout_at(deadline, worker.shutdown(shutdown_budget(deadline))).await {
            Ok(Ok(())) => startup_error,
            Ok(Err(cleanup_error)) => startup_error.context(format!(
                "bounded worker startup cleanup also failed: {cleanup_error:#}"
            )),
            Err(_) => startup_error.context("bounded worker startup cleanup timed out"),
        }
    }

    #[cfg(test)]
    async fn start_with_runtime_config(
        runtime_config: CallServiceRuntimeConfig,
        admission_capacity: usize,
        setup_timeout: Duration,
    ) -> Result<Self> {
        Self::start_with_runtime_config_and_amazon(
            runtime_config,
            admission_capacity,
            setup_timeout,
            None,
        )
        .await
    }

    #[cfg(test)]
    async fn start_with_runtime_config_and_amazon(
        runtime_config: CallServiceRuntimeConfig,
        admission_capacity: usize,
        setup_timeout: Duration,
        amazon_connect: Option<Arc<AmazonConnectAdapter>>,
    ) -> Result<Self> {
        Self::start_with_components(
            runtime_config,
            admission_capacity,
            setup_timeout,
            Arc::new(SamePrincipalAttachmentResolver),
            Arc::new(DisabledProviderLegExecutor),
            Arc::new(ContextPolicy::default()),
            amazon_connect,
            Arc::new(DisabledOutboundProfileResolver),
            std::collections::BTreeSet::new(),
            None,
        )
        .await
    }

    // Startup keeps independently fallible authorities explicit so cleanup
    // can report and drain the exact component that failed to initialize.
    #[allow(clippy::too_many_arguments)]
    async fn start_with_components(
        runtime_config: CallServiceRuntimeConfig,
        admission_capacity: usize,
        setup_timeout: Duration,
        attachment_principals: Arc<dyn AttachmentPrincipalResolver>,
        provider_executor: Arc<dyn ProviderLegExecutor>,
        context_policy: Arc<ContextPolicy>,
        amazon_connect: Option<Arc<AmazonConnectAdapter>>,
        outbound_profiles: Arc<dyn OutboundProfileResolver>,
        registered_providers: std::collections::BTreeSet<String>,
        private_egress_options: Option<PrivateEgressWorkerOptions>,
    ) -> Result<Self> {
        let mut runtime_config = runtime_config;
        runtime_config.worker_capabilities = worker_capabilities_for_registered_adapters(
            std::mem::take(&mut runtime_config.worker_capabilities),
            amazon_connect.is_some(),
            &registered_providers,
            private_egress_options
                .as_ref()
                .map(|options| options.routes.as_ref()),
        );
        let call_runtime = Arc::new(
            build_call_service_runtime(
                runtime_config,
                attachment_principals,
                Arc::new(SystemCallServiceClock),
            )
            .await
            .context("starting durable call-service worker")?,
        );
        let orchestrator = Orchestrator::new(CoreConfig::default());
        let broadcast_subscription_authority =
            WorkerBroadcastSubscriptionAuthority::new(call_runtime.worker().lease);
        let private_egress = match private_egress_options {
            Some(options) => {
                let control = PrivateEgressControlClient::start_authoritative(
                    Arc::clone(&orchestrator),
                    call_runtime.worker().lease,
                    options.max_pending_commands,
                    options.command_timeout,
                );
                let admissions = PrivateEgressStreamAdmissionRegistry::new(
                    call_runtime.worker().lease,
                    options.max_active_admissions,
                );
                match control.and_then(|control| {
                    admissions
                        .map_err(|_| PrivateEgressError::InvalidCommand)
                        .and_then(|admissions| {
                            PrivateEgressWorkerRuntime::new_with_routes(
                                control,
                                admissions,
                                options.routes,
                                false,
                            )
                            .map_err(|_| PrivateEgressError::InvalidCommand)
                        })
                }) {
                    Ok(runtime) => Some(runtime),
                    Err(error) => {
                        let strong_count = Arc::strong_count(&call_runtime);
                        if let Ok(runtime) = Arc::try_unwrap(call_runtime) {
                            let _ = runtime.shutdown(Duration::from_secs(2)).await;
                        } else {
                            tracing::error!(
                                strong_count,
                                "failed private-egress startup retained call runtime"
                            );
                        }
                        return Err(anyhow!(error))
                            .context("constructing split-worker private-egress owner");
                    }
                }
            }
            None => None,
        };
        let execution =
            match CallExecutionSupervisor::install_with_leg_executors_context_canary_broadcast_profiles_and_private_egress(
                Arc::clone(&orchestrator),
                Arc::clone(&call_runtime),
                provider_executor,
                amazon_connect.clone(),
                context_policy,
                None,
                Some(Arc::clone(&broadcast_subscription_authority)),
                outbound_profiles,
                private_egress.clone(),
                admission_capacity,
                setup_timeout,
            )
            .await
            {
                Ok(execution) => execution,
                Err(error) => {
                    let strong_count = Arc::strong_count(&call_runtime);
                    if let Ok(runtime) = Arc::try_unwrap(call_runtime) {
                        let _ = runtime.shutdown(Duration::from_secs(2)).await;
                    } else {
                        tracing::error!(
                            strong_count,
                            "failed worker startup retained call runtime"
                        );
                    }
                    return Err(error).context("installing durable call execution supervisor");
                }
            };
        if let Some(adapter) = amazon_connect.as_ref() {
            if let Err(error) =
                orchestrator.register(Arc::clone(adapter) as Arc<dyn ConnectionAdapter>)
            {
                execution.begin_drain();
                adapter.begin_drain();
                execution.shutdown(Duration::from_secs(2)).await;
                let _ = adapter
                    .drain_until(
                        std::time::Instant::now()
                            .checked_add(Duration::from_secs(2))
                            .unwrap_or_else(std::time::Instant::now),
                    )
                    .await;
                let strong_count = Arc::strong_count(&call_runtime);
                if let Ok(runtime) = Arc::try_unwrap(call_runtime) {
                    let _ = runtime.shutdown(Duration::from_secs(2)).await;
                } else {
                    tracing::error!(
                        strong_count,
                        "failed Amazon adapter registration retained call runtime"
                    );
                }
                return Err(error).context("registering split-worker Amazon Connect adapter");
            }
        }
        Ok(Self {
            call_runtime,
            orchestrator,
            amazon_connect,
            broadcast_subscription_authority,
            private_egress,
            execution: Some(execution),
            forwarding: None,
            broadcasts: None,
        })
    }

    fn subscribe_health(&self) -> tokio::sync::watch::Receiver<RuntimeSupervisorHealth> {
        self.call_runtime.subscribe_supervisor_health()
    }

    fn subscribe_forwarding_health(
        &self,
    ) -> Option<tokio::sync::watch::Receiver<ForwardingHealth>> {
        self.forwarding
            .as_ref()
            .map(|forwarding| forwarding.subscribe_health())
    }

    async fn shutdown(mut self, timeout: Duration) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut drain_error = None;
        if let Some(forwarding) = self.forwarding.as_ref() {
            forwarding.begin_drain();
        }
        if let Some(private_egress) = self.private_egress.as_ref() {
            private_egress.begin_drain();
        }
        if let Some(execution) = self.execution.as_ref() {
            execution.begin_drain();
        }
        if let Some(amazon_connect) = self.amazon_connect.as_ref() {
            amazon_connect.begin_drain();
        }
        if let Some(broadcasts) = self.broadcasts.take() {
            broadcasts.shutdown(shutdown_budget(deadline)).await;
        }
        if let Some(amazon_connect) = self.amazon_connect.take() {
            let report = amazon_connect
                .drain_until(
                    std::time::Instant::now()
                        .checked_add(shutdown_budget(deadline))
                        .unwrap_or_else(std::time::Instant::now),
                )
                .await;
            if !report.is_complete() && drain_error.is_none() {
                drain_error = Some(anyhow!(
                    "worker Amazon Connect adapter drain incomplete: remaining_routes={}, pending_cleanups={}, in_flight_setups={}, failed_routes={}, detached_cleanups={}",
                    report.remaining_routes,
                    report.pending_contact_cleanups,
                    report.in_flight_setups,
                    report.failed_routes,
                    report.detached_cleanups,
                ));
            }
        }
        if let Some(execution) = self.execution.take() {
            execution.shutdown(shutdown_budget(deadline)).await;
        }
        if let Some(private_egress) = self.private_egress.take() {
            private_egress.shutdown().await;
        }
        if let Some(forwarding) = self.forwarding.take() {
            if let Err(error) = forwarding.shutdown(shutdown_budget(deadline)).await {
                drain_error = Some(anyhow!(error).context("draining private UCTP worker listener"));
            }
        }
        if tokio::time::timeout(
            shutdown_budget(deadline),
            self.orchestrator.drain_prepared_outbound_connections(),
        )
        .await
        .is_err()
        {
            drain_error = Some(anyhow!("worker prepared outbound drain timed out"));
        }
        if tokio::time::timeout(
            shutdown_budget(deadline),
            self.orchestrator.drain_connection_lifecycle_tasks(),
        )
        .await
        .is_err()
            && drain_error.is_none()
        {
            drain_error = Some(anyhow!("worker rvoip lifecycle drain timed out"));
        }

        let strong_count = Arc::strong_count(&self.call_runtime);
        let call_runtime = Arc::try_unwrap(self.call_runtime).map_err(|_| {
            anyhow!("worker call-service runtime retained {strong_count} owners during drain")
        })?;
        let call_runtime_result = call_runtime
            .shutdown(shutdown_budget(deadline))
            .await
            .context("shutting down durable call-service worker");
        match (drain_error, call_runtime_result) {
            (Some(error), _) => Err(error),
            (None, result) => result,
        }
    }
}

fn shutdown_budget(deadline: tokio::time::Instant) -> Duration {
    deadline.saturating_duration_since(tokio::time::Instant::now())
}

async fn wait_for_stop(mut stop: tokio::sync::watch::Receiver<bool>) {
    if *stop.borrow() {
        return;
    }
    while stop.changed().await.is_ok() {
        if *stop.borrow() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Instant;

    use axum::extract::State;
    use bridgefu::api_principal::ApiPrincipal;
    use bridgefu::call_engine::{LegDirection, MediaFlow, SignalingInitiator, WorkerId};
    use bridgefu::call_service::{
        AmazonConnectEndpointConfig, AmazonConnectStartSpec, CallRepositoryBackendConfig,
        CallServiceCoordinationConfig, CreateCallInput, IdempotencyKey, LegEndpointConfig,
        NamedProfileBinding, NamedProfileKind, NamedProfileRole, ProviderEndpointConfig,
        ProviderKind, RequestedLeg, WebRtcEndpointConfig,
    };
    use bridgefu::coordination::DeploymentId;
    use bridgefu::private_egress::{
        PrivateEgressCommand, PrivateEgressHandler, PrivateEgressHandlerResult,
        PrivateEgressRouteAuthority,
    };
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use rvoip_amazon_connect::{
        ConnectConfig, ConnectContactStarter, ConnectMediaCloseOutcome, ConnectMediaConnectOptions,
        ConnectMediaConnector, ConnectMediaHealth, ConnectMediaSession, ConnectMediaTerminalCause,
        ConnectionData, MediaPlacement, StartContactRequest, StopContactRequest,
    };
    use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod};
    use rvoip_core::capability::NegotiatedCodecs;
    use rvoip_core::connection::Transport;
    use rvoip_core::stream::MediaStream;
    use rvoip_core::{IdentityAssurance, Jwk};
    use tokio::sync::{mpsc, watch};

    const BASE: &str = r#"
aws:
  region: us-west-2
  instance_id: instance
  contact_flow_id: flow
sip: {advertised_ip: 127.0.0.1, media_public_ip: 127.0.0.1}
"#;

    fn parse(extra: &str) -> Config {
        serde_yaml::from_str(&format!("{BASE}\n{extra}")).expect("config parses")
    }

    fn provider_route(destination: &str, revision: char) -> NamedRouteCfg {
        NamedRouteCfg {
            tenant_id: "tenant-catalog".into(),
            ingress: BTreeSet::from([crate::config::NamedRouteIngress::Webrtc]),
            destination: RequestedLeg {
                direction: LegDirection::Outbound,
                signaling_initiator: Some(SignalingInitiator::Bridgefu),
                media_flow: MediaFlow::SendReceive,
                endpoint: LegEndpointConfig::Provider(ProviderEndpointConfig {
                    provider: ProviderKind::Telnyx,
                    account_profile: "telnyx-primary".into(),
                    destination: Some(destination.into()),
                }),
                amazon_connect_start: None,
            },
            vapi_ingress_profile: None,
            webrtc_ingress_profile: Some("browser-primary".into()),
            destination_profile: Some(crate::config::RouteDestinationProfileRef::Telnyx {
                profile_id: "telnyx-primary".into(),
            }),
            legacy_embedded_destination: false,
            profile_bindings: vec![
                NamedProfileBinding::new(
                    NamedProfileRole::Ingress,
                    NamedProfileKind::WebRtc,
                    "browser-primary",
                    "a".repeat(64),
                )
                .unwrap(),
                NamedProfileBinding::new(
                    NamedProfileRole::Destination,
                    NamedProfileKind::Telnyx,
                    "telnyx-primary",
                    revision.to_string().repeat(64),
                )
                .unwrap(),
            ],
            context_metadata_allowlist: None,
            capability_policy: crate::config::NamedRouteCapabilityPolicy::default(),
        }
    }

    #[test]
    fn catalog_fingerprint_is_canonical_and_tracks_provider_routes_and_capabilities() {
        let capabilities = BTreeSet::from([
            "telnyx".to_owned(),
            "webrtc".to_owned(),
            "webrtc_egress".to_owned(),
        ]);
        let routes = BTreeMap::from([
            ("support".to_owned(), provider_route("+12065550100", 'b')),
            ("sales".to_owned(), provider_route("+12065550101", 'c')),
        ]);
        let baseline = route_catalog_configuration_fingerprint(&capabilities, &routes).unwrap();

        let reordered_capabilities = BTreeSet::from([
            "webrtc_egress".to_owned(),
            "webrtc".to_owned(),
            "telnyx".to_owned(),
        ]);
        let reordered_routes = BTreeMap::from([
            ("sales".to_owned(), provider_route("+12065550101", 'c')),
            ("support".to_owned(), provider_route("+12065550100", 'b')),
        ]);
        assert_eq!(
            baseline,
            route_catalog_configuration_fingerprint(&reordered_capabilities, &reordered_routes)
                .unwrap()
        );

        let mut changed_destination = routes.clone();
        changed_destination.insert("support".into(), provider_route("+12065550999", 'b'));
        assert_ne!(
            baseline,
            route_catalog_configuration_fingerprint(&capabilities, &changed_destination).unwrap()
        );

        let mut changed_profile = routes.clone();
        changed_profile.insert("support".into(), provider_route("+12065550100", 'd'));
        assert_ne!(
            baseline,
            route_catalog_configuration_fingerprint(&capabilities, &changed_profile).unwrap()
        );

        let mut changed_capabilities = capabilities;
        changed_capabilities.insert("amazon_connect".into());
        assert_ne!(
            baseline,
            route_catalog_configuration_fingerprint(&changed_capabilities, &routes).unwrap()
        );
    }

    struct NoopPrivateEgressHandler;

    #[async_trait]
    impl PrivateEgressHandler for NoopPrivateEgressHandler {
        async fn execute(
            &self,
            _authority: &PrivateEgressRouteAuthority,
            _command: &PrivateEgressCommand,
        ) -> std::result::Result<PrivateEgressHandlerResult, PrivateEgressError> {
            Ok(PrivateEgressHandlerResult {
                external_reference: None,
            })
        }
    }

    #[test]
    fn split_gateway_replay_capacity_covers_100_calls_at_10_cps_for_120_seconds() {
        let mut config = parse("");
        config.api.rate_limit.enabled = true;
        config.api.rate_limit.control_requests_per_second = 10;
        config.api.rate_limit.control_burst = 20;
        config.private_forwarding.limits.max_active_routes = 100;

        let capacity =
            gateway_private_egress_replay_capacity(&config, Duration::from_secs(120)).unwrap();
        let successful_setup_commands = 10usize * 120 * 2;
        assert_eq!(capacity, 2_840);
        assert!(capacity >= successful_setup_commands);
        assert_eq!(
            capacity - successful_setup_commands,
            20 * 2 + 100 * PRIVATE_EGRESS_REPLAY_HEADROOM_PER_ACTIVE_ROUTE,
            "burst traffic and every live route retain separate replay headroom"
        );
    }

    #[test]
    fn split_gateway_replay_capacity_requires_an_enforced_safe_bound() {
        let mut config = parse("");
        config.api.rate_limit.enabled = false;
        assert!(
            gateway_private_egress_replay_capacity(&config, Duration::from_secs(120))
                .unwrap_err()
                .to_string()
                .contains("bounded API control rate limiting")
        );

        config.api.rate_limit.enabled = true;
        config.api.rate_limit.control_requests_per_second = 100_000;
        config.api.rate_limit.control_burst = 1_000_000;
        assert!(
            gateway_private_egress_replay_capacity(&config, Duration::from_secs(120))
                .unwrap_err()
                .to_string()
                .contains("per-gateway safety bound")
        );
    }

    #[test]
    fn split_gateway_rejects_the_hermetic_private_egress_store() {
        let service = PrivateEgressCommandService::new(
            Arc::new(NoopPrivateEgressHandler),
            PrivateEgressServiceConfig {
                max_active_routes: 4,
                max_replay_entries: 16,
                replay_ttl: Duration::from_secs(60),
                operation_timeout: Duration::from_secs(1),
            },
        )
        .unwrap();
        let error = require_clustered_private_egress_state(&service).unwrap_err();
        assert!(error.to_string().contains("shared durable state store"));
    }

    #[derive(Default)]
    struct WorkerAmazonStarter {
        starts: AtomicUsize,
        stops: AtomicUsize,
    }

    #[async_trait]
    impl ConnectContactStarter for WorkerAmazonStarter {
        async fn start_webrtc_contact(
            &self,
            _request: StartContactRequest,
        ) -> rvoip_amazon_connect::Result<ConnectionData> {
            let sequence = self.starts.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(ConnectionData {
                contact_id: format!("worker-contact-{sequence}"),
                participant_id: format!("worker-participant-{sequence}"),
                participant_token: "worker-participant-token".into(),
                meeting_id: format!("worker-meeting-{sequence}"),
                media_region: "us-west-2".into(),
                attendee_id: format!("worker-attendee-{sequence}"),
                join_token: "worker-join-token".into(),
                media_placement: MediaPlacement {
                    signaling_url: "wss://worker.invalid/signaling".into(),
                    audio_host_url: "https://worker.invalid/audio".into(),
                    ..MediaPlacement::default()
                },
            })
        }

        async fn stop_contact(
            &self,
            _request: StopContactRequest,
        ) -> rvoip_amazon_connect::Result<()> {
            self.stops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct WorkerAmazonMediaSession {
        _terminal_tx: watch::Sender<Option<ConnectMediaTerminalCause>>,
        terminal_rx: watch::Receiver<Option<ConnectMediaTerminalCause>>,
        closes: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ConnectMediaSession for WorkerAmazonMediaSession {
        fn negotiated_codecs(&self) -> NegotiatedCodecs {
            NegotiatedCodecs::default()
        }

        fn streams(&self) -> Vec<Arc<dyn MediaStream>> {
            Vec::new()
        }

        fn take_dtmf_events(
            &self,
        ) -> Option<mpsc::Receiver<rvoip_amazon_connect::ConnectMediaDtmfEvent>> {
            None
        }

        fn subscribe_terminal(&self) -> watch::Receiver<Option<ConnectMediaTerminalCause>> {
            self.terminal_rx.clone()
        }

        fn health(&self) -> ConnectMediaHealth {
            ConnectMediaHealth {
                peer_connected: true,
                signaling_running: true,
                last_signaling_activity_ago: Duration::ZERO,
                last_pong_ago: None,
                terminal: *self.terminal_rx.borrow(),
            }
        }

        async fn hold(&self) -> rvoip_amazon_connect::Result<()> {
            Ok(())
        }

        async fn resume(&self) -> rvoip_amazon_connect::Result<()> {
            Ok(())
        }

        async fn send_dtmf(
            &self,
            _digits: &str,
            _duration_ms: u32,
        ) -> rvoip_amazon_connect::Result<()> {
            Ok(())
        }

        async fn close_until(
            &self,
            _deadline: Instant,
        ) -> rvoip_amazon_connect::Result<ConnectMediaCloseOutcome> {
            self.closes.fetch_add(1, Ordering::SeqCst);
            Ok(ConnectMediaCloseOutcome::Graceful)
        }

        fn abort(&self) {}
    }

    struct WorkerAmazonMediaConnector {
        connects: AtomicUsize,
        closes: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ConnectMediaConnector for WorkerAmazonMediaConnector {
        async fn connect(
            &self,
            _connection: &ConnectionData,
            _options: ConnectMediaConnectOptions,
        ) -> rvoip_amazon_connect::Result<Arc<dyn ConnectMediaSession>> {
            self.connects.fetch_add(1, Ordering::SeqCst);
            let (terminal_tx, terminal_rx) = watch::channel(None);
            Ok(Arc::new(WorkerAmazonMediaSession {
                _terminal_tx: terminal_tx,
                terminal_rx,
                closes: Arc::clone(&self.closes),
            }))
        }
    }

    fn worker_amazon_principal() -> ApiPrincipal {
        ApiPrincipal::new(
            AuthenticatedPrincipal {
                subject: "split-worker-test".into(),
                tenant: Some("split-worker-tenant".into()),
                scopes: vec![
                    "*".into(),
                    bridgefu::api_principal::CallScope::ArbitraryDestination
                        .as_str()
                        .into(),
                ],
                issuer: Some("split-worker-test".into()),
                expires_at: None,
                method: AuthenticationMethod::Jwt,
                assurance: IdentityAssurance::Pseudonymous {
                    ephemeral_key: Jwk(serde_json::json!({"kty": "test"})),
                },
            },
            Utc::now(),
        )
        .unwrap()
    }

    #[derive(Clone)]
    struct DelayedRequestState {
        started: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    async fn delayed_api_response(State(state): State<DelayedRequestState>) -> &'static str {
        state.started.notify_one();
        state.release.notified().await;
        "committed"
    }

    #[tokio::test]
    async fn tls_public_api_drain_waits_for_an_admitted_request() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_pem = cert.pem();
        let directory = std::env::temp_dir().join(format!(
            "bridgefu-api-tls-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let certificate_path = directory.join("certificate.pem");
        let private_key_path = directory.join("private-key.pem");
        std::fs::write(&certificate_path, &cert_pem).unwrap();
        std::fs::write(&private_key_path, signing_key.serialize_pem()).unwrap();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            &certificate_path,
            &private_key_path,
        )
        .await
        .unwrap();

        let state = DelayedRequestState {
            started: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
        };
        let app = axum::Router::new()
            .route("/commit", axum::routing::get(delayed_api_response))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stop_rx) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(serve_gateway_public_api(
            listener,
            app,
            Some(tls),
            stop_rx,
            Duration::from_secs(2),
        ));
        let trusted = reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap();
        let client = reqwest::Client::builder()
            .add_root_certificate(trusted)
            .https_only(true)
            .build()
            .unwrap();
        let request = tokio::spawn(async move {
            client
                .get(format!("https://localhost:{}/commit", address.port()))
                .send()
                .await
                .unwrap()
        });

        tokio::time::timeout(Duration::from_secs(2), state.started.notified())
            .await
            .expect("TLS request entered the handler");
        stop.send_replace(true);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !request.is_finished(),
            "graceful shutdown aborted an admitted API request"
        );
        state.release.notify_one();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), request)
                .await
                .expect("admitted API request completed")
                .expect("request task joined")
                .status(),
            reqwest::StatusCode::OK
        );
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("TLS API server honored the drain deadline")
            .expect("TLS API task joined")
            .expect("TLS API server stopped cleanly");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn role_plan_never_places_public_ingress_on_worker() {
        let all = RolePlan::for_mode(RuntimeMode::AllInOne);
        assert!(all.public_control_http && all.public_signaling);
        assert!(all.amazon_connect_media && all.durable_call_worker);

        let gateway = RolePlan::for_mode(RuntimeMode::Gateway);
        assert!(gateway.public_control_http && gateway.public_signaling);
        assert!(gateway.public_sip && gateway.public_webrtc && gateway.public_uctp);
        assert!(!gateway.amazon_connect_media && !gateway.durable_call_worker);

        let worker = RolePlan::for_mode(RuntimeMode::Worker);
        assert!(!worker.public_control_http && !worker.public_signaling);
        assert!(worker.amazon_connect_media && worker.durable_call_worker);

        let relay = RolePlan::for_mode(RuntimeMode::MoqRelay);
        assert!(relay.moq_relay);
        assert!(!relay.public_control_http);
        assert!(!relay.public_signaling);
        assert!(!relay.amazon_connect_media && !relay.durable_call_worker);
    }

    #[test]
    fn split_worker_preserves_only_the_canonical_public_uctp_endpoint() {
        let endpoint =
            required_public_uctp_endpoint(Some("uctp+quic://broadcast.example.test:4444"))
                .expect("canonical UCTP endpoint");
        assert_eq!(endpoint.as_str(), "uctp+quic://broadcast.example.test:4444");

        for rejected in [
            None,
            Some("uctp://broadcast.example.test:4444"),
            Some("quic://broadcast.example.test:4444"),
            Some("uctp+quic://broadcast.example.test"),
            Some("uctp+quic://user@broadcast.example.test:4444"),
            Some("uctp+quic://broadcast.example.test:4444/path"),
            Some("uctp+quic://broadcast.example.test:4444?draft=19"),
            Some("uctp+quic://broadcast.example.test:4444#fragment"),
        ] {
            assert!(
                required_public_uctp_endpoint(rejected).is_err(),
                "non-canonical endpoint was accepted: {rejected:?}"
            );
        }
    }

    #[test]
    fn worker_readiness_requires_both_durable_authority_and_private_forwarding() {
        assert_eq!(
            worker_dependency_lifecycle(
                RuntimeSupervisorHealth::Healthy,
                ForwardingHealth::Healthy,
            ),
            Ok(RoleLifecycle::Ready)
        );
        assert_eq!(
            worker_dependency_lifecycle(
                RuntimeSupervisorHealth::Degraded,
                ForwardingHealth::Healthy,
            ),
            Ok(RoleLifecycle::Degraded)
        );
        assert_eq!(
            worker_dependency_lifecycle(
                RuntimeSupervisorHealth::Healthy,
                ForwardingHealth::Degraded,
            ),
            Ok(RoleLifecycle::Degraded)
        );
        assert_eq!(
            worker_dependency_lifecycle(
                RuntimeSupervisorHealth::Healthy,
                ForwardingHealth::Draining,
            ),
            Ok(RoleLifecycle::Draining)
        );
        assert_eq!(
            worker_dependency_lifecycle(
                RuntimeSupervisorHealth::LeaseLost,
                ForwardingHealth::Healthy,
            ),
            Err("durable worker authority was lost")
        );
        assert_eq!(
            worker_dependency_lifecycle(
                RuntimeSupervisorHealth::Healthy,
                ForwardingHealth::Stopped,
            ),
            Err("worker private forwarding listener stopped")
        );
    }

    #[test]
    fn gateway_requires_private_forwarding_and_unconfigured_relay_fails_closed() {
        let gateway = parse("runtime: {mode: gateway}");
        assert_eq!(
            preflight(&gateway),
            Err(RolePreflightError::GatewayForwardingConfigurationMissing)
        );
        let configured_gateway = parse(
            r#"
runtime: {mode: gateway}
api:
  enabled: true
  http_bind: 127.0.0.1:9080
  bearer_token: gateway-public-token
  control_hmac_key: 0123456789abcdef0123456789abcdef
generic_bridge:
  enabled: true
  sip_bind: 127.0.0.1:5070
  webrtc_ws_bind: 127.0.0.1:8080
  webrtc_whip_bind: 127.0.0.1:8081
persistence:
  backend: postgres
  database_url: postgres://database.invalid/bridgefu
  redis_url: rediss://redis.invalid
  redis_clustered: true
private_forwarding:
  enabled: true
  token_signing_secret: 0123456789abcdef0123456789abcdef
  gateway:
    gateway_id: gateway-a
    tls:
      certificate_chain: [/run/tls/gateway.pem]
      private_key: /run/tls/gateway.key
      peer_ca_certificates: [/run/tls/worker-ca.pem]
    public_uctp:
      bind: 127.0.0.1:4433
      tls:
        certificate_chain: [/run/tls/gateway-public.pem]
        private_key: /run/tls/gateway-public.key
    workers:
      - worker_id: 00000000-0000-4000-8000-000000000002
        endpoint: 127.0.0.1:9443
        server_name: worker.internal
"#,
        );
        assert_eq!(
            preflight(&configured_gateway),
            Err(RolePreflightError::GatewaySipAuthenticationMissing)
        );
        assert!(
            !configured_gateway.generic_bridge.sip.allow_cleartext_bearer,
            "gateway preflight must retain the secure SIP Bearer default"
        );
        let mut explicitly_opted_in = configured_gateway;
        explicitly_opted_in
            .generic_bridge
            .sip
            .allow_cleartext_bearer = true;
        assert_eq!(
            preflight(&explicitly_opted_in),
            Ok(RolePlan::for_mode(RuntimeMode::Gateway))
        );
        explicitly_opted_in
            .generic_bridge
            .sip
            .allow_cleartext_bearer = false;
        explicitly_opted_in.generic_bridge.sip.digest = Some(
            serde_yaml::from_str(
                "realm: bridgefu-generic\nusername: generic-peer\npassword: generic-secret\n",
            )
            .unwrap(),
        );
        assert_eq!(
            preflight(&explicitly_opted_in),
            Ok(RolePlan::for_mode(RuntimeMode::Gateway))
        );
        let relay = parse("runtime: {mode: moq-relay}");
        assert_eq!(
            preflight(&relay),
            Err(RolePreflightError::MoqRelayConfigurationMissing)
        );
    }

    #[tokio::test]
    async fn gateway_sip_bearer_is_cleartext_denied_until_explicitly_enabled() {
        let mut config = parse(
            r#"
api:
  bearer_token: gateway-public-token
generic_bridge:
  enabled: true
"#,
        );
        assert!(!config.generic_bridge.sip.allow_cleartext_bearer);

        let validator = || -> Arc<dyn rvoip_auth_core::BearerValidator> {
            Arc::new(
                ConfiguredApiKeyValidator::new("gateway-public-token".into(), ["gateway-tenant"])
                    .unwrap(),
            )
        };
        let listener_policy =
            gateway_sip_listener_auth(&config, "gateway-tenant", validator()).unwrap();
        assert_eq!(
            format!("{listener_policy:?}"),
            "SipListenerAuthPolicy { enabled: true, tenant_configured: true, auth_service_configured: true, trusted_source_count: 0, mtls_principal_count: 0 }"
        );
        let denied = gateway_sip_auth_service(&config, validator())
            .unwrap()
            .authenticate_authorization(
                Some("Bearer gateway-public-token"),
                "INVITE",
                "sip:attachment@example.invalid",
                None,
                rvoip_sip::SipAuthSource::Origin,
                false,
            )
            .await
            .unwrap();
        assert!(matches!(
            denied,
            rvoip_sip::SipAuthDecision::Rejected { .. }
        ));

        config.generic_bridge.sip.digest = Some(
            serde_yaml::from_str(
                "realm: bridgefu-generic\nusername: generic-peer\npassword: generic-secret\n",
            )
            .unwrap(),
        );
        let digest_challenges = gateway_sip_auth_service(&config, validator())
            .unwrap()
            .challenges(rvoip_sip::SipAuthSource::Origin);
        assert!(digest_challenges
            .iter()
            .any(|challenge| challenge.scheme == rvoip_sip::SipAuthScheme::Digest));

        config.generic_bridge.sip.allow_cleartext_bearer = true;
        let accepted = gateway_sip_auth_service(&config, validator())
            .unwrap()
            .authenticate_authorization(
                Some("Bearer gateway-public-token"),
                "INVITE",
                "sip:attachment@example.invalid",
                None,
                rvoip_sip::SipAuthSource::Origin,
                false,
            )
            .await
            .unwrap();
        assert!(matches!(
            accepted,
            rvoip_sip::SipAuthDecision::Authorized(identity)
                if identity.scheme == rvoip_sip::SipAuthScheme::Bearer
        ));
    }

    #[test]
    fn gateway_preflight_requires_http_native_signaling_and_public_tls() {
        let base = r#"
runtime: {mode: gateway}
api:
  enabled: true
  http_bind: 127.0.0.1:9080
  bearer_token: gateway-public-token
  control_hmac_key: 0123456789abcdef0123456789abcdef
generic_bridge:
  enabled: true
  sip_bind: 127.0.0.1:5070
  sip: {allow_cleartext_bearer: true}
  webrtc_ws_bind: 127.0.0.1:8080
  webrtc_whip_bind: 127.0.0.1:8081
persistence:
  backend: postgres
  database_url: postgres://database.invalid/bridgefu
  redis_url: rediss://redis.invalid
  redis_clustered: true
private_forwarding:
  enabled: true
  token_signing_secret: 0123456789abcdef0123456789abcdef
  gateway:
    gateway_id: gateway-a
    tls:
      certificate_chain: [/run/tls/gateway.pem]
      private_key: /run/tls/gateway.key
      peer_ca_certificates: [/run/tls/worker-ca.pem]
    public_uctp:
      bind: 127.0.0.1:4433
      tls:
        certificate_chain: [/run/tls/public.pem]
        private_key: /run/tls/public.key
    workers:
      - worker_id: 00000000-0000-4000-8000-000000000002
        endpoint: 127.0.0.1:9443
        server_name: worker.internal
"#;
        assert_eq!(
            preflight(&parse(&base.replacen(
                "api:\n  enabled: true",
                "api:\n  enabled: false",
                1,
            ))),
            Err(RolePreflightError::GatewayPublicApiDisabled)
        );
        assert_eq!(
            preflight(&parse(&base.replace(
                "enabled: true\n  sip_bind",
                "enabled: false\n  sip_bind"
            ),)),
            Err(RolePreflightError::GatewayNativeSignalingConfigurationMissing)
        );
        let public_webrtc_without_tls = base
            .replace(
                "webrtc_ws_bind: 127.0.0.1:8080",
                "webrtc_ws_bind: 0.0.0.0:8080",
            )
            .replace(
                "webrtc_whip_bind: 127.0.0.1:8081",
                "webrtc_whip_bind: 0.0.0.0:8081",
            );
        assert_eq!(
            preflight(&parse(&public_webrtc_without_tls)),
            Err(RolePreflightError::GatewayNativeSignalingTlsMissing)
        );
        let public_without_tls =
            base.replace("http_bind: 127.0.0.1:9080", "http_bind: 0.0.0.0:9080");
        assert_eq!(
            preflight(&parse(&public_without_tls)),
            Err(RolePreflightError::GatewayPublicApiTlsMissing)
        );
        let public_with_tls = public_without_tls.replace(
            "http_bind: 0.0.0.0:9080",
            "http_bind: 0.0.0.0:9080\n  tls:\n    certificate_chain: /run/tls/api.pem\n    private_key: /run/tls/api.key",
        );
        assert_eq!(
            preflight(&parse(&public_with_tls)),
            Ok(RolePlan::for_mode(RuntimeMode::Gateway))
        );
    }

    #[test]
    fn moq_relay_requires_private_cluster_dependencies_and_no_public_ingress() {
        let configured = r#"
runtime: {mode: moq-relay}
api: {enabled: false}
persistence:
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
        let valid = parse(configured);
        assert_eq!(
            preflight(&valid),
            Ok(RolePlan::for_mode(RuntimeMode::MoqRelay))
        );

        let public_api =
            parse(&configured.replace("api: {enabled: false}", "api: {enabled: true}"));
        assert_eq!(
            preflight(&public_api),
            Err(RolePreflightError::MoqRelayPublicApiEnabled)
        );
        let no_redis = parse(&configured.replace(
            "persistence:\n  redis_url: rediss://redis.invalid\n  redis_clustered: true",
            "persistence: {}",
        ));
        assert_eq!(
            preflight(&no_redis),
            Err(RolePreflightError::MoqRelayRequiresClusteredRedis)
        );
    }

    #[tokio::test]
    async fn production_gateway_fails_on_missing_dependency_before_binding_any_socket() {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = occupied.local_addr().unwrap();
        let config = parse(&format!(
            r#"
runtime: {{mode: gateway}}
observability: {{http_bind: {address}}}
api:
  enabled: true
  http_bind: 127.0.0.1:9080
  bearer_token: gateway-public-token
  control_hmac_key: 0123456789abcdef0123456789abcdef
generic_bridge:
  enabled: true
  sip_bind: 127.0.0.1:5070
  sip: {{allow_cleartext_bearer: true}}
  webrtc_ws_bind: 127.0.0.1:8080
  webrtc_whip_bind: 127.0.0.1:8081
persistence:
  backend: postgres
  database_url: postgres://127.0.0.1:1/bridgefu
  redis_url: rediss://127.0.0.1:1
  redis_clustered: true
private_forwarding:
  enabled: true
  token_signing_secret: 0123456789abcdef0123456789abcdef
  gateway:
    gateway_id: gateway-a
    tls:
      certificate_chain: [/definitely/missing/gateway.pem]
      private_key: /definitely/missing/gateway.key
      peer_ca_certificates: [/definitely/missing/worker-ca.pem]
    public_uctp:
      bind: 127.0.0.1:4433
      tls:
        certificate_chain: [/definitely/missing/public.pem]
        private_key: /definitely/missing/public.key
    workers:
      - worker_id: 00000000-0000-4000-8000-000000000002
        endpoint: 127.0.0.1:9443
        server_name: worker.internal
"#
        ));
        let error = run_gateway(
            &config,
            PrometheusBuilder::new().build_recorder().handle(),
            std::future::pending(),
        )
        .await
        .expect_err("missing gateway edge dependency unexpectedly started");
        assert!(error
            .to_string()
            .contains("starting split gateway call-control authority"));
        assert_eq!(occupied.local_addr().unwrap(), address);
    }

    #[test]
    fn gateway_admission_is_bounded_paused_by_health_and_permanently_closed_by_drain() {
        let admission = GatewayAdmission::new(1).unwrap();
        assert_eq!(
            admission.try_admit().unwrap_err(),
            GatewayAdmissionError::NotReady
        );
        admission.set_dependency_ready(true);
        let permit = admission.try_admit().unwrap();
        assert_eq!(admission.active(), 1);
        assert_eq!(
            admission.try_admit().unwrap_err(),
            GatewayAdmissionError::CapacityExceeded
        );
        admission.set_dependency_ready(false);
        assert_eq!(
            admission.try_admit().unwrap_err(),
            GatewayAdmissionError::NotReady
        );
        drop(permit);
        admission.set_dependency_ready(true);
        assert!(admission.try_admit().is_ok());
        admission.begin_drain();
        admission.set_dependency_ready(true);
        assert_eq!(
            admission.try_admit().unwrap_err(),
            GatewayAdmissionError::Draining
        );
    }

    struct TestGatewayEdge {
        health: tokio::sync::watch::Sender<GatewayEdgeHealth>,
        admission: GatewayAdmission,
        began_drain: AtomicBool,
        shutdown: AtomicBool,
        events: StdMutex<Vec<&'static str>>,
    }

    impl TestGatewayEdge {
        fn set_health(&self, health: GatewayEdgeHealth) {
            self.health.send_replace(health);
        }
    }

    #[async_trait]
    impl GatewayEdgeRuntime for TestGatewayEdge {
        fn subscribe_health(&self) -> tokio::sync::watch::Receiver<GatewayEdgeHealth> {
            self.health.subscribe()
        }

        fn begin_drain(&self) {
            self.began_drain.store(true, Ordering::SeqCst);
            self.events.lock().unwrap().push("begin-drain");
            self.health.send_replace(GatewayEdgeHealth::Draining);
        }

        async fn shutdown(&self, _timeout: Duration) -> Result<()> {
            self.shutdown.store(true, Ordering::SeqCst);
            self.events.lock().unwrap().push("shutdown");
            self.health.send_replace(GatewayEdgeHealth::Stopped);
            Ok(())
        }
    }

    struct TestGatewayFactory {
        initial: GatewayEdgeHealth,
        edge: StdMutex<Option<Arc<TestGatewayEdge>>>,
    }

    impl TestGatewayFactory {
        fn healthy() -> Self {
            Self {
                initial: GatewayEdgeHealth::Healthy,
                edge: StdMutex::new(None),
            }
        }

        fn edge(&self) -> Arc<TestGatewayEdge> {
            Arc::clone(
                self.edge
                    .lock()
                    .unwrap()
                    .as_ref()
                    .expect("test gateway edge started"),
            )
        }
    }

    #[async_trait]
    impl GatewayEdgeFactory for TestGatewayFactory {
        async fn start(
            &self,
            _config: &Config,
            admission: GatewayAdmission,
        ) -> Result<Arc<dyn GatewayEdgeRuntime>> {
            let (health, _) = tokio::sync::watch::channel(self.initial);
            let edge = Arc::new(TestGatewayEdge {
                health,
                admission,
                began_drain: AtomicBool::new(false),
                shutdown: AtomicBool::new(false),
                events: StdMutex::new(Vec::new()),
            });
            *self.edge.lock().unwrap() = Some(Arc::clone(&edge));
            Ok(edge)
        }
    }

    async fn wait_for_role(health: &RoleHealth, expected: RoleLifecycle) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while health.current() != expected {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("gateway role reached expected lifecycle");
    }

    async fn wait_for_flag(flag: &AtomicBool) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !flag.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("gateway lifecycle flag was observed");
    }

    #[tokio::test]
    async fn gateway_readiness_tracks_dependency_and_drain_closes_admission_before_shutdown() {
        let config = parse("runtime: {mode: gateway, drain_timeout_secs: 2}");
        let factory = TestGatewayFactory::healthy();
        let runtime = GatewayRoleRuntime::start(&config, &factory).await.unwrap();
        let health = runtime.health.clone();
        let edge = factory.edge();
        assert_eq!(
            edge.admission.try_admit().unwrap_err(),
            GatewayAdmissionError::NotReady
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stop_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(run_gateway_runtime(
            runtime,
            listener,
            PrometheusBuilder::new().build_recorder().handle(),
            wait_for_stop(stop_rx),
            Duration::from_secs(2),
        ));

        wait_for_role(&health, RoleLifecycle::Ready).await;
        assert_eq!(
            reqwest::get(format!(
                "http://{address}/v1/providers/not-configured/capabilities"
            ))
            .await
            .unwrap()
            .status(),
            reqwest::StatusCode::NOT_FOUND
        );
        assert_eq!(
            reqwest::get(format!("http://{address}/readyz"))
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::OK
        );
        edge.set_health(GatewayEdgeHealth::Degraded);
        wait_for_role(&health, RoleLifecycle::Degraded).await;
        assert_eq!(
            edge.admission.try_admit().unwrap_err(),
            GatewayAdmissionError::NotReady
        );
        assert_eq!(
            reqwest::get(format!("http://{address}/readyz"))
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        );

        edge.set_health(GatewayEdgeHealth::Healthy);
        wait_for_role(&health, RoleLifecycle::Ready).await;
        let active = edge.admission.try_admit().unwrap();
        stop.send_replace(true);
        wait_for_role(&health, RoleLifecycle::Draining).await;
        wait_for_flag(&edge.began_drain).await;
        assert_eq!(
            edge.admission.try_admit().unwrap_err(),
            GatewayAdmissionError::Draining
        );
        assert!(!edge.shutdown.load(Ordering::SeqCst));
        assert_eq!(
            reqwest::get(format!("http://{address}/readyz"))
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            reqwest::get(format!("http://{address}/livez"))
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::OK
        );

        drop(active);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("gateway drain completed")
            .expect("gateway task joined")
            .expect("gateway stopped cleanly");
        assert!(edge.shutdown.load(Ordering::SeqCst));
        assert_eq!(edge.admission.active(), 0);
        assert_eq!(health.current(), RoleLifecycle::Stopped);
        assert_eq!(
            *edge.events.lock().unwrap(),
            vec!["begin-drain", "shutdown"]
        );
    }

    #[tokio::test]
    async fn gateway_dependency_failure_is_terminal_and_still_runs_bounded_cleanup() {
        let config = parse("runtime: {mode: gateway, drain_timeout_secs: 2}");
        let factory = TestGatewayFactory::healthy();
        let runtime = GatewayRoleRuntime::start(&config, &factory).await.unwrap();
        let health = runtime.health.clone();
        let edge = factory.edge();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let task = tokio::spawn(run_gateway_runtime(
            runtime,
            listener,
            PrometheusBuilder::new().build_recorder().handle(),
            std::future::pending(),
            Duration::from_secs(2),
        ));

        wait_for_role(&health, RoleLifecycle::Ready).await;
        edge.set_health(GatewayEdgeHealth::Stopped);
        wait_for_role(&health, RoleLifecycle::Failed).await;
        let error = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("failed gateway converged")
            .expect("failed gateway task joined")
            .expect_err("dependency failure must fail the role");
        assert!(error
            .to_string()
            .contains("gateway dependency stopped serving"));
        assert!(edge.began_drain.load(Ordering::SeqCst));
        assert!(edge.shutdown.load(Ordering::SeqCst));
        assert_eq!(health.current(), RoleLifecycle::Failed);
    }

    #[test]
    fn worker_requires_private_cluster_dependencies_and_no_public_listeners() {
        let local_store = parse(
            r#"
runtime: {mode: worker}
api:
  enabled: false
  control_hmac_key: 01234567890123456789012345678901
"#,
        );
        assert_eq!(
            preflight(&local_store),
            Err(RolePreflightError::WorkerRequiresPostgres)
        );

        let no_coordination = parse(
            r#"
runtime: {mode: worker}
persistence:
  backend: postgres
  database_url: postgres://database/bridgefu
  worker_id: 00000000-0000-4000-8000-000000000002
api:
  enabled: false
  control_hmac_key: 01234567890123456789012345678901
"#,
        );
        assert_eq!(
            preflight(&no_coordination),
            Err(RolePreflightError::WorkerRequiresClusteredRedis)
        );

        let no_control_key = parse(
            r#"
runtime: {mode: worker}
persistence:
  backend: postgres
  database_url: postgres://database/bridgefu
  worker_id: 00000000-0000-4000-8000-000000000002
  redis_url: rediss://redis
  redis_clustered: true
api: {enabled: false}
"#,
        );
        assert_eq!(
            preflight(&no_control_key),
            Err(RolePreflightError::WorkerControlKeyMissing)
        );

        let public_signaling = parse(
            r#"
runtime: {mode: worker}
api: {enabled: false}
generic_bridge: {enabled: true}
"#,
        );
        assert_eq!(
            preflight(&public_signaling),
            Err(RolePreflightError::WorkerPublicSignalingEnabled)
        );

        let public_api = parse(
            r#"
runtime: {mode: worker}
persistence:
  backend: postgres
  database_url: postgres://database/bridgefu
  worker_id: 00000000-0000-4000-8000-000000000002
  redis_url: rediss://redis
  redis_clustered: true
api:
  enabled: true
  control_hmac_key: 01234567890123456789012345678901
"#,
        );
        assert_eq!(
            preflight(&public_api),
            Err(RolePreflightError::WorkerPublicApiEnabled)
        );

        let valid = parse(
            r#"
runtime: {mode: worker}
persistence:
  backend: postgres
  database_url: postgres://database/bridgefu
  worker_id: 00000000-0000-4000-8000-000000000002
  redis_url: rediss://redis
  redis_clustered: true
api:
  enabled: false
  control_hmac_key: 01234567890123456789012345678901
private_forwarding:
  enabled: true
  token_signing_secret: 0123456789abcdef0123456789abcdef
  worker:
    bind: 127.0.0.1:9443
    tls:
      certificate_chain: [/run/tls/worker.pem]
      private_key: /run/tls/worker.key
      peer_ca_certificates: [/run/tls/gateway-ca.pem]
"#,
        );
        assert_eq!(
            preflight(&valid),
            Ok(RolePlan::for_mode(RuntimeMode::Worker))
        );
    }

    #[tokio::test]
    async fn worker_installs_real_execution_owner_and_drains_worker_lease() {
        let mut coordination = CallServiceCoordinationConfig::new(
            DeploymentId::parse("process-role-worker-test").unwrap(),
        );
        coordination.worker_lease_ttl = Duration::from_secs(300);
        coordination.worker_renew_interval = Duration::from_secs(100);
        let worker = WorkerRoleRuntime::start_with_runtime_config(
            CallServiceRuntimeConfig {
                backend: CallRepositoryBackendConfig::Memory,
                worker_id: WorkerId::new(),
                max_calls: 2,
                worker_capabilities: BTreeSet::from(["amazon_connect".into()]),
                control_key: vec![0x52; 32],
                timeouts: CallTimeoutPolicy {
                    setup: Duration::from_secs(30),
                    media_idle: Duration::from_secs(30),
                    transfer: Duration::from_secs(30),
                    ending: Duration::from_secs(30),
                },
                coordination,
            },
            4,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(
            *worker.subscribe_health().borrow(),
            RuntimeSupervisorHealth::Healthy
        );
        let repository = worker.call_runtime.repository();
        let worker_id = worker.call_runtime.worker().lease.worker_id;
        worker.shutdown(Duration::from_secs(2)).await.unwrap();
        assert!(
            repository
                .worker_snapshot(worker_id)
                .await
                .unwrap()
                .draining
        );
    }

    #[test]
    fn split_worker_advertises_only_concrete_destination_executors() {
        let configured = BTreeSet::from([
            "sip".to_owned(),
            "webrtc".to_owned(),
            "sip_egress".to_owned(),
            "webrtc_egress".to_owned(),
            "amazon_connect".to_owned(),
            "telnyx".to_owned(),
            "twilio".to_owned(),
            "vonage".to_owned(),
        ]);
        assert_eq!(
            worker_capabilities_for_registered_adapters(
                configured.clone(),
                false,
                &BTreeSet::new(),
                None,
            ),
            BTreeSet::from(["sip".to_owned(), "webrtc".to_owned()])
        );
        assert_eq!(
            worker_capabilities_for_registered_adapters(
                configured,
                true,
                &BTreeSet::from(["telnyx".to_owned()]),
                None,
            ),
            BTreeSet::from([
                "amazon_connect".to_owned(),
                "sip".to_owned(),
                "telnyx".to_owned(),
                "webrtc".to_owned(),
            ])
        );

        let sip_routes =
            PrivateEgressWorkerRouteCatalog::new(vec![PrivateEgressWorkerRouteDescriptor {
                tenant_id: bridgefu::call_engine::TenantId::parse("tenant-capability").unwrap(),
                route_id: "sip-support".into(),
                transport: PrivateEgressTransport::Sip,
                profile: PrivateEgressProfile {
                    profile_id: "sip-primary".into(),
                    revision: "a".repeat(64),
                },
                target: "sips:queue@example.test".into(),
                codecs: vec![CodecInfo::from_name_with_defaults("g.711-mu")],
            }])
            .unwrap();
        assert_eq!(
            worker_capabilities_for_registered_adapters(
                BTreeSet::from([
                    "sip".to_owned(),
                    "webrtc".to_owned(),
                    "sip_egress".to_owned(),
                    "webrtc_egress".to_owned(),
                ]),
                false,
                &BTreeSet::new(),
                Some(sip_routes.as_ref()),
            ),
            BTreeSet::from([
                sip_routes.fingerprint().advertisement_capability(),
                "sip".to_owned(),
                "sip_egress".to_owned(),
                "webrtc".to_owned(),
            ])
        );
    }

    #[tokio::test]
    async fn split_worker_retains_and_drains_private_egress_owner() {
        let mut coordination = CallServiceCoordinationConfig::new(
            DeploymentId::parse("process-role-private-egress-owner-test").unwrap(),
        );
        coordination.worker_lease_ttl = Duration::from_secs(300);
        coordination.worker_renew_interval = Duration::from_secs(100);
        let route =
            PrivateEgressWorkerRouteCatalog::new(vec![PrivateEgressWorkerRouteDescriptor {
                tenant_id: bridgefu::call_engine::TenantId::parse("tenant-private-egress").unwrap(),
                route_id: "sip-support".into(),
                transport: PrivateEgressTransport::Sip,
                profile: PrivateEgressProfile {
                    profile_id: "sip-primary".into(),
                    revision: "a".repeat(64),
                },
                target: "sips:queue@example.test".into(),
                codecs: vec![CodecInfo::from_name_with_defaults("g.711-mu")],
            }])
            .unwrap();
        let route_catalog_capability = route.fingerprint().advertisement_capability();
        let worker = WorkerRoleRuntime::start_with_components(
            CallServiceRuntimeConfig {
                backend: CallRepositoryBackendConfig::Memory,
                worker_id: WorkerId::new(),
                max_calls: 2,
                worker_capabilities: BTreeSet::from([
                    "sip".into(),
                    "webrtc".into(),
                    "sip_egress".into(),
                    "webrtc_egress".into(),
                ]),
                control_key: vec![0x63; 32],
                timeouts: CallTimeoutPolicy {
                    setup: Duration::from_secs(5),
                    media_idle: Duration::from_secs(30),
                    transfer: Duration::from_secs(30),
                    ending: Duration::from_secs(5),
                },
                coordination,
            },
            4,
            Duration::from_secs(2),
            Arc::new(SamePrincipalAttachmentResolver),
            Arc::new(DisabledProviderLegExecutor),
            Arc::new(ContextPolicy::default()),
            None,
            Arc::new(DisabledOutboundProfileResolver),
            BTreeSet::new(),
            Some(PrivateEgressWorkerOptions {
                routes: route,
                max_pending_commands: 4,
                max_active_admissions: 4,
                command_timeout: Duration::from_secs(1),
            }),
        )
        .await
        .unwrap();
        assert!(worker
            .call_runtime
            .worker()
            .capabilities
            .contains("sip_egress"));
        assert!(worker
            .call_runtime
            .worker()
            .capabilities
            .contains(&route_catalog_capability));
        assert!(!worker
            .call_runtime
            .worker()
            .capabilities
            .contains("webrtc_egress"));
        let private_egress = Arc::clone(worker.private_egress.as_ref().unwrap());
        let lease = worker.call_runtime.worker().lease;
        worker.shutdown(Duration::from_secs(3)).await.unwrap();

        let tenant = bridgefu::call_engine::TenantId::parse("tenant-private-egress").unwrap();
        let command = bridgefu::private_egress::PrivateEgressCommand::new(
            uuid::Uuid::new_v4(),
            chrono::Utc::now().timestamp_millis(),
            Duration::from_secs(1),
            lease,
            bridgefu::private_egress::PrivateEgressSource {
                tenant_id: tenant,
                call_id: bridgefu::call_engine::CallId::new(),
                leg_id: bridgefu::call_engine::LegId::new(),
                binding_generation: bridgefu::call_engine::BindingGeneration::INITIAL,
            },
            bridgefu::private_egress::PrivateEgressTarget {
                leg_id: bridgefu::call_engine::LegId::new(),
                binding_generation: bridgefu::call_engine::BindingGeneration::INITIAL,
            },
            bridgefu::private_egress::PrivateEgressOperation::Prepare {
                transport: PrivateEgressTransport::Sip,
                profile: PrivateEgressProfile {
                    profile_id: "sip-primary".into(),
                    revision: "a".repeat(64),
                },
                codec: CodecInfo::from_name_with_defaults("g.711-mu"),
                target: "sips:queue@example.test".into(),
                initial_context: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(
            private_egress
                .control()
                .execute(rvoip_core::ids::ConnectionId::new(), command)
                .await,
            Err(PrivateEgressError::Draining)
        );
    }

    #[tokio::test]
    async fn split_worker_registers_executes_and_drains_amazon_connect() {
        let mut coordination = CallServiceCoordinationConfig::new(
            DeploymentId::parse("process-role-amazon-worker-test").unwrap(),
        );
        coordination.worker_lease_ttl = Duration::from_secs(300);
        coordination.worker_renew_interval = Duration::from_secs(100);

        let starter = Arc::new(WorkerAmazonStarter::default());
        let closes = Arc::new(AtomicUsize::new(0));
        let connector = Arc::new(WorkerAmazonMediaConnector {
            connects: AtomicUsize::new(0),
            closes: Arc::clone(&closes),
        });
        let starter_trait: Arc<dyn ConnectContactStarter> = starter.clone();
        let connector_trait: Arc<dyn ConnectMediaConnector> = connector.clone();
        let amazon_connect = AmazonConnectAdapter::builder(
            ConnectConfig::new("unused-worker-instance", "unused-worker-flow"),
            starter_trait,
        )
        .with_media_connector(connector_trait)
        .build();

        let worker = WorkerRoleRuntime::start_with_runtime_config_and_amazon(
            CallServiceRuntimeConfig {
                backend: CallRepositoryBackendConfig::Memory,
                worker_id: WorkerId::new(),
                max_calls: 2,
                worker_capabilities: BTreeSet::from(["amazon_connect".into(), "webrtc".into()]),
                control_key: vec![0x62; 32],
                timeouts: CallTimeoutPolicy {
                    setup: Duration::from_secs(30),
                    media_idle: Duration::from_secs(30),
                    transfer: Duration::from_secs(30),
                    ending: Duration::from_secs(30),
                },
                coordination,
            },
            4,
            Duration::from_secs(2),
            Some(Arc::clone(&amazon_connect)),
        )
        .await
        .unwrap();

        assert!(worker
            .orchestrator
            .adapter(Transport::AmazonConnect)
            .is_ok());
        assert!(worker
            .call_runtime
            .repository()
            .worker_snapshot(worker.call_runtime.worker().lease.worker_id)
            .await
            .unwrap()
            .capabilities
            .contains("amazon_connect"));

        let amazon_endpoint = AmazonConnectEndpointConfig {
            instance_id: "worker-instance".into(),
            contact_flow_id: "worker-flow".into(),
        };
        let amazon_start = AmazonConnectStartSpec::new(
            "default",
            amazon_endpoint.instance_id.clone(),
            amazon_endpoint.contact_flow_id.clone(),
            Default::default(),
            "split worker test",
            None,
        )
        .unwrap();
        worker
            .call_runtime
            .service()
            .create_call(
                &worker_amazon_principal(),
                &IdempotencyKey::parse("split-worker-amazon-executes").unwrap(),
                CreateCallInput {
                    tenant_id: None,
                    legs: [
                        RequestedLeg {
                            direction: LegDirection::Inbound,
                            signaling_initiator: Some(SignalingInitiator::Remote),
                            media_flow: MediaFlow::SendReceive,
                            endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                                signaling_uri: None,
                            }),
                            amazon_connect_start: None,
                        },
                        RequestedLeg {
                            direction: LegDirection::Outbound,
                            signaling_initiator: Some(SignalingInitiator::Bridgefu),
                            media_flow: MediaFlow::SendReceive,
                            endpoint: LegEndpointConfig::AmazonConnect(amazon_endpoint),
                            amazon_connect_start: Some(amazon_start),
                        },
                    ],
                },
            )
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if starter.starts.load(Ordering::SeqCst) == 1
                    && connector.connects.load(Ordering::SeqCst) == 1
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the worker executed its registered Amazon destination");

        worker.shutdown(Duration::from_secs(3)).await.unwrap();
        assert!(amazon_connect.is_draining());
        assert_eq!(starter.starts.load(Ordering::SeqCst), 1);
        assert_eq!(starter.stops.load(Ordering::SeqCst), 1);
        assert_eq!(closes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn worker_post_start_failure_drains_every_started_owner_and_listener() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut coordination = CallServiceCoordinationConfig::new(
            DeploymentId::parse("process-role-worker-startup-cleanup-test").unwrap(),
        );
        coordination.worker_lease_ttl = Duration::from_secs(300);
        coordination.worker_renew_interval = Duration::from_secs(100);
        let starter = Arc::new(WorkerAmazonStarter::default());
        let starter_trait: Arc<dyn ConnectContactStarter> = starter;
        let amazon_connect = AmazonConnectAdapter::new(
            ConnectConfig::new("unused-rollback-instance", "unused-rollback-flow"),
            starter_trait,
        );
        let mut worker = WorkerRoleRuntime::start_with_runtime_config_and_amazon(
            CallServiceRuntimeConfig {
                backend: CallRepositoryBackendConfig::Memory,
                worker_id: WorkerId::new(),
                max_calls: 2,
                worker_capabilities: BTreeSet::from(["amazon_connect".into()]),
                control_key: vec![0x53; 32],
                timeouts: CallTimeoutPolicy {
                    setup: Duration::from_secs(30),
                    media_idle: Duration::from_secs(30),
                    transfer: Duration::from_secs(30),
                    ending: Duration::from_secs(30),
                },
                coordination,
            },
            4,
            Duration::from_secs(2),
            Some(Arc::clone(&amazon_connect)),
        )
        .await
        .unwrap();

        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "bridgefu-worker-startup-cleanup-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let certificate_path = directory.join("worker.pem");
        let private_key_path = directory.join("worker.key");
        std::fs::write(&certificate_path, cert.pem()).unwrap();
        std::fs::write(&private_key_path, signing_key.serialize_pem()).unwrap();

        let forwarding = WorkerForwardingRuntime::start_with_broadcast_authority(
            bridgefu::gateway_forwarding::WorkerForwardingConfig {
                worker_id: worker.call_runtime.worker().lease.worker_id,
                bind: "127.0.0.1:0".parse().unwrap(),
                tls: bridgefu::gateway_forwarding::MutualTlsFiles {
                    certificate_chain: vec![certificate_path.clone()],
                    private_key: private_key_path,
                    peer_ca_certificates: vec![certificate_path],
                },
                token_key: bridgefu::gateway_forwarding::PrivateTokenKey::new(vec![0x54; 32])
                    .unwrap(),
                limits: bridgefu::gateway_forwarding::PrivateForwardingLimits::default(),
                timeouts: bridgefu::gateway_forwarding::PrivateForwardingTimeouts::default(),
            },
            Arc::clone(&worker.orchestrator),
            Arc::clone(&worker.broadcast_subscription_authority),
        )
        .await
        .unwrap();
        let listener_address = forwarding.local_addr().unwrap();
        let forwarding_health = forwarding.subscribe_health();
        worker.forwarding = Some(forwarding);

        let repository = worker.call_runtime.repository();
        let worker_lease = worker.call_runtime.worker().lease;
        let observation_time = worker.call_runtime.observation_time();
        let mut runtime_health = worker.subscribe_health();
        let orchestrator = Arc::clone(&worker.orchestrator);
        let started = tokio::time::Instant::now();
        let error = WorkerRoleRuntime::cleanup_failed_start(
            worker,
            anyhow!("representative post-start broadcast configuration failure"),
        )
        .await;

        assert!(
            started.elapsed() <= WORKER_STARTUP_CLEANUP_TIMEOUT + Duration::from_millis(250),
            "startup cleanup exceeded its bounded deadline"
        );
        assert_eq!(
            error.to_string(),
            "representative post-start broadcast configuration failure"
        );
        assert_eq!(*forwarding_health.borrow(), ForwardingHealth::Stopped);
        assert!(amazon_connect.is_draining());
        assert_eq!(orchestrator.connection_lifecycle_task_count(), 0);
        assert!(
            repository
                .worker_snapshot(worker_lease.worker_id)
                .await
                .unwrap()
                .draining
        );
        assert!(
            repository
                .active_worker_snapshot(worker_lease, observation_time)
                .await
                .is_err(),
            "the failed startup worker lease remained admissible"
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while runtime_health.changed().await.is_ok() {}
        })
        .await
        .expect("the durable runtime health owner was dropped");

        drop(orchestrator);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match tokio::net::UdpSocket::bind(listener_address).await {
                    Ok(socket) => break drop(socket),
                    Err(_) => tokio::task::yield_now().await,
                }
            }
        })
        .await
        .expect("the private forwarding UDP listener was released");
        std::fs::remove_dir_all(directory).unwrap();
    }
}
