//! Versioned Bridgefu control and broadcast API.

mod calls;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, Extension, OriginalUri, Path, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use metrics_exporter_prometheus::PrometheusHandle;
use opentelemetry::global;
use opentelemetry::propagation::Extractor;
use rvoip_amazon_connect::ConnectScreenPopServer;
use rvoip_auth_core::BearerValidator;
use rvoip_core::broadcast::{BroadcastDrainReason, BroadcastLifecycleState};
use rvoip_moq::MoqPublisherConfig;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use uuid::Uuid;
use zeroize::Zeroize;

use bridgefu::api_principal::{
    ApiBearerAuthenticator, ApiPrincipal, ApiPrincipalError, CallScope, ConfiguredApiKeyValidator,
    MAX_API_BEARER_BYTES,
};
use bridgefu::broadcast::{
    BroadcastCommandError, BroadcastCommandRepository, BroadcastGrantRegistry,
    BroadcastGrantVerifier, BroadcastOperationIdentity, BroadcastTokenService,
    DurableBroadcastRecord, DurableBroadcastSpec, DurableBroadcastState, DurableBroadcastTransport,
    ManagedBroadcast, ManagedBroadcastError, ManagedBroadcastService, ManagedBroadcastTransport,
    ManagedSanitizedEventBinding, PostgresBroadcastCommandRepository, RedisBroadcastGrantConfig,
    RedisBroadcastGrantStore, SanitizedContextEventPolicy,
};
use bridgefu::call_engine::{
    CallId, CallRepository, LegId, ProviderAccountKey, ProviderCallId, ProviderEventDigest,
    ProviderEventInput, ProviderEventOutcome, ProviderPayloadDigest, RepositoryError,
};
use bridgefu::call_service::{
    build_call_control_runtime, build_call_service_runtime, CallControlRuntime,
    CallControlRuntimeConfig, CallControlRuntimeHealth, CallRepositoryBackendConfig, CallService,
    CallServiceError, CallServiceRuntime, CallServiceRuntimeConfig, CallTimeoutPolicy,
    ControlCryptoError, RuntimeSupervisorHealth, SystemCallServiceClock,
};
use url::Url;

use crate::api_rate_limit::{ApiRateLimiter, ApiRateSurface, RateLimitRejection};
use crate::config::{Config, ResolvedNamedRoutes};
use crate::context::ContextPolicy;
use crate::observability::{RoleHealth, RoleLifecycle};
use crate::providers::{NormalizedProviderEvent, ProviderError, ProviderRegistry, WebhookRequest};
use crate::runtime::GenericBridgeRuntime;
use crate::screen_pop_evidence::{
    ScreenPopEvidence, ScreenPopEvidenceStore, DEFAULT_SCREEN_POP_EVIDENCE_CAPACITY,
    DEFAULT_SCREEN_POP_EVIDENCE_TTL,
};
use bridgefu::signaling_token::{SignalingTokenService, WebRtcSignalingBearerValidator};
use rvoip_webrtc::signaling::auth::WsBearerSessionBinding;

#[derive(Clone)]
pub struct ApiState {
    server: Option<Arc<ConnectScreenPopServer>>,
    providers: ProviderRegistry,
    broadcasts: Arc<DashMap<String, Arc<ActiveBroadcast>>>,
    provider_events: Option<Arc<dyn ProviderEventPersistence>>,
    metrics: PrometheusHandle,
    tenants: Vec<String>,
    bearer_authenticator: Option<ApiBearerAuthenticator>,
    legacy_bearer_token: Option<Arc<LegacyBearerToken>>,
    call_service: Option<Arc<CallService>>,
    call_runtime: Option<Arc<CallServiceRuntime>>,
    call_control_runtime: Option<Arc<CallControlRuntime>>,
    broadcast_tokens: Arc<BroadcastTokenService>,
    shared_broadcast_grants: Option<Arc<RedisBroadcastGrantStore>>,
    token_ttl: Duration,
    max_broadcasts: usize,
    default_transport: BroadcastKind,
    public_endpoint: String,
    api_enabled: bool,
    context_policy: ContextPolicy,
    generic_runtime: Option<Arc<GenericBridgeRuntime>>,
    local_capability_allowlist: BTreeSet<String>,
    local_execution_capabilities: BTreeSet<String>,
    managed_broadcast_service: Option<Arc<ManagedBroadcastService>>,
    broadcast_commands: Option<Arc<dyn BroadcastCommandRepository>>,
    clustered_uctp_gateway: bool,
    clustered_moq_relay: bool,
    sanitized_event_policies: Arc<BTreeMap<String, SanitizedContextEventPolicy>>,
    screen_pop_evidence: ScreenPopEvidenceStore,
    role_health: Option<RoleHealth>,
    api_rate_limiter: ApiRateLimiter,
    named_routes: Arc<ResolvedNamedRoutes>,
    /// Exact configured split-worker identities. `None` means this API owns
    /// the local worker; `Some` means destination discovery must be backed by
    /// a live worker's concrete capability projection.
    split_worker_ids: Option<Arc<Vec<bridgefu::call_engine::WorkerId>>>,
    signaling_tokens: Option<Arc<SignalingTokenService>>,
    webrtc_signaling_bearer_validator: Option<Arc<dyn BearerValidator>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApiCallRuntimeKind {
    LocalWorker,
    RemoteWorkerControl,
}

#[async_trait]
trait ProviderEventPersistence: Send + Sync {
    async fn ingest_provider_event(
        &self,
        request: ProviderEventInput,
    ) -> Result<ProviderEventOutcome, RepositoryError>;
}

struct RepositoryProviderEventPersistence {
    repository: Arc<dyn CallRepository>,
}

#[async_trait]
impl ProviderEventPersistence for RepositoryProviderEventPersistence {
    async fn ingest_provider_event(
        &self,
        request: ProviderEventInput,
    ) -> Result<ProviderEventOutcome, RepositoryError> {
        self.repository.ingest_provider_event(request).await
    }
}

struct LegacyBearerToken(Vec<u8>);

impl fmt::Debug for LegacyBearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LegacyBearerToken([redacted])")
    }
}

impl Drop for LegacyBearerToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct ActiveBroadcast {
    call_id: CallId,
    source_leg_id: LegId,
    transport: BroadcastKind,
    managed: Arc<ManagedBroadcast>,
}

impl ApiState {
    pub async fn from_config(
        config: &Config,
        server: Arc<ConnectScreenPopServer>,
        metrics: PrometheusHandle,
        tenants: Vec<String>,
        generic_runtime: Option<Arc<GenericBridgeRuntime>>,
    ) -> anyhow::Result<Self> {
        let attachment_principals = Arc::new(config.attachment_principal_resolver(&tenants)?);
        Self::from_config_inner(
            config,
            Some(server),
            metrics,
            tenants,
            generic_runtime,
            attachment_principals,
            ApiCallRuntimeKind::LocalWorker,
            None,
        )
        .await
    }

    /// Constructs the local all-in-one control plane without the historical
    /// `ConnectScreenPopServer`. Recipe-only processes use the same durable
    /// call runtime, attachment authority, and API surface while the generic
    /// SIP/WebRTC runtime owns every media adapter.
    pub async fn from_recipe_config(
        config: &Config,
        metrics: PrometheusHandle,
        tenants: Vec<String>,
    ) -> anyhow::Result<Self> {
        let attachment_principals = Arc::new(config.attachment_principal_resolver(&tenants)?);
        Self::from_config_inner(
            config,
            None,
            metrics,
            tenants,
            None,
            attachment_principals,
            ApiCallRuntimeKind::LocalWorker,
            None,
        )
        .await
    }

    /// Constructs the public API for a role-separated gateway. This opens the
    /// shared PostgreSQL/Redis control plane but never registers a worker or
    /// constructs an rvoip media runtime.
    pub async fn from_gateway_config(
        config: &Config,
        metrics: PrometheusHandle,
        tenants: Vec<String>,
        role_health: RoleHealth,
    ) -> anyhow::Result<Self> {
        let attachment_principals = Arc::new(config.attachment_principal_resolver(&tenants)?);
        Self::from_config_inner(
            config,
            None,
            metrics,
            tenants,
            None,
            attachment_principals,
            ApiCallRuntimeKind::RemoteWorkerControl,
            Some(role_health),
        )
        .await
    }

    #[cfg(test)]
    async fn from_config_with_attachment_principals(
        config: &Config,
        server: Arc<ConnectScreenPopServer>,
        metrics: PrometheusHandle,
        tenants: Vec<String>,
        generic_runtime: Option<Arc<GenericBridgeRuntime>>,
        attachment_principals: Arc<dyn bridgefu::call_service::AttachmentPrincipalResolver>,
    ) -> anyhow::Result<Self> {
        Self::from_config_inner(
            config,
            Some(server),
            metrics,
            tenants,
            generic_runtime,
            attachment_principals,
            ApiCallRuntimeKind::LocalWorker,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn from_config_inner(
        config: &Config,
        server: Option<Arc<ConnectScreenPopServer>>,
        metrics: PrometheusHandle,
        tenants: Vec<String>,
        generic_runtime: Option<Arc<GenericBridgeRuntime>>,
        attachment_principals: Arc<dyn bridgefu::call_service::AttachmentPrincipalResolver>,
        runtime_kind: ApiCallRuntimeKind,
        role_health: Option<RoleHealth>,
    ) -> anyhow::Result<Self> {
        let providers = ProviderRegistry::from_config(&config.providers)?;
        let named_routes = Arc::new(config.resolved_named_routes()?);
        let split_worker_ids = match runtime_kind {
            ApiCallRuntimeKind::LocalWorker => None,
            ApiCallRuntimeKind::RemoteWorkerControl => {
                let gateway =
                    config.private_forwarding.gateway.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("split gateway worker targets are missing")
                    })?;
                let workers = gateway
                    .workers
                    .iter()
                    .map(|worker| {
                        bridgefu::call_engine::WorkerId::from_str(&worker.worker_id)
                            .map_err(|_| anyhow::anyhow!("split gateway worker ID is invalid"))
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                Some(Arc::new(workers))
            }
        };
        let mut bearer_token = config
            .api
            .bearer_token
            .as_ref()
            .map(|secret| secret.resolve())
            .transpose()?;
        let token_secret = match &config.broadcast.token_secret {
            Some(secret) => secret.resolve()?.into_bytes(),
            None => {
                tracing::warn!(
                    "broadcast.token_secret is unset; generated tokens will not survive a restart"
                );
                let mut generated = Vec::with_capacity(32);
                generated.extend_from_slice(Uuid::new_v4().as_bytes());
                generated.extend_from_slice(Uuid::new_v4().as_bytes());
                generated
            }
        };
        let shared_broadcast_grants = match config.persistence.redis_url.as_ref() {
            Some(redis_url) if config.persistence.redis_clustered => Some(
                RedisBroadcastGrantStore::connect(RedisBroadcastGrantConfig::new(
                    redis_url.resolve()?,
                    config.persistence.deployment_id.clone(),
                ))
                .await?,
            ),
            _ => None,
        };
        let mut broadcast_token_service = BroadcastTokenService::new(
            token_secret,
            BroadcastGrantRegistry::new(),
            Duration::from_secs(config.broadcast.token_ttl_secs),
        )?;
        if let Some(store) = &shared_broadcast_grants {
            let verifier: Arc<dyn BroadcastGrantVerifier> = store.clone();
            broadcast_token_service = broadcast_token_service.with_shared_verifier(verifier);
        }
        let broadcast_tokens = Arc::new(broadcast_token_service);
        let sanitized_event_policies = Arc::new(
            config
                .broadcast
                .sanitized_events
                .policies(&config.context)?,
        );
        if config.api.enabled && bearer_token.is_none() {
            tracing::warn!(
                "control API has no bearer token; configure api.bearer_token in production"
            );
        }

        let static_tenant = config
            .api
            .static_tenant
            .clone()
            .or_else(|| (tenants.len() == 1).then(|| tenants[0].clone()));
        let bearer_authenticator = match (bearer_token.take(), static_tenant.as_deref()) {
            (Some(token), Some(tenant)) => Some(ApiBearerAuthenticator::new(Arc::new(
                ConfiguredApiKeyValidator::new(token, [tenant])?,
            ))),
            (Some(token), None) => {
                tracing::warn!(
                    "transactional call API is disabled: api.static_tenant is required with multiple tenants"
                );
                bearer_token = Some(token);
                None
            }
            (None, _) => None,
        };
        let legacy_bearer_token = bearer_token
            .map(String::into_bytes)
            .map(LegacyBearerToken)
            .map(Arc::new);
        let (signaling_tokens, webrtc_signaling_bearer_validator) = match (
            bearer_authenticator.as_ref(),
            config.api.control_hmac_key.as_ref(),
        ) {
            (Some(authenticator), Some(control_key)) => {
                let service = Arc::new(SignalingTokenService::new(
                    control_key.resolve()?.into_bytes(),
                )?);
                let validator: Arc<dyn BearerValidator> =
                    Arc::new(WebRtcSignalingBearerValidator::new(
                        authenticator.validator(),
                        Arc::clone(&service),
                    ));
                (Some(service), Some(validator))
            }
            _ => (None, None),
        };

        let local_capability_allowlist = match runtime_kind {
            ApiCallRuntimeKind::LocalWorker => config.call_worker_capabilities(),
            ApiCallRuntimeKind::RemoteWorkerControl => BTreeSet::new(),
        };
        // All-in-one workers register with no execution claims. GenericBridge
        // publishes the exact installed adapter inventory on the same fence
        // only after every adapter and execution supervisor is ready.
        let local_worker_capabilities = BTreeSet::new();
        let local_execution_capabilities = BTreeSet::new();
        let (call_runtime, call_control_runtime) = if let (true, Some(_), Some(control_key)) = (
            config.api.enabled,
            bearer_authenticator.as_ref(),
            config.api.control_hmac_key.as_ref(),
        ) {
            let timeouts = CallTimeoutPolicy {
                setup: Duration::from_secs(config.runtime.setup_timeout_secs),
                media_idle: Duration::from_secs(config.runtime.media_idle_timeout_secs),
                transfer: Duration::from_secs(30),
                ending: Duration::from_secs(config.runtime.drain_timeout_secs.max(1)),
            };
            match runtime_kind {
                ApiCallRuntimeKind::LocalWorker => {
                    let runtime = build_call_service_runtime(
                        CallServiceRuntimeConfig {
                            backend: config.call_repository_backend()?,
                            worker_id: config.call_worker_id()?,
                            max_calls: config.runtime.max_concurrent_calls,
                            worker_capabilities: local_worker_capabilities,
                            control_key: control_key.resolve()?.into_bytes(),
                            timeouts,
                            coordination: config.call_coordination_config()?,
                        },
                        attachment_principals,
                        Arc::new(SystemCallServiceClock),
                    )
                    .await?;
                    tracing::info!(
                        backend = runtime.backend().as_str(),
                        worker_id = %runtime.worker().lease.worker_id,
                        worker_fence = runtime.worker().lease.fence.as_i64(),
                        reserved_calls = runtime.worker().reserved_calls,
                        "transactional call service ready"
                    );
                    (Some(Arc::new(runtime)), None)
                }
                ApiCallRuntimeKind::RemoteWorkerControl => {
                    let runtime = build_call_control_runtime(
                        CallControlRuntimeConfig {
                            backend: config.call_repository_backend()?,
                            control_key: control_key.resolve()?.into_bytes(),
                            timeouts,
                            eligible_workers: split_worker_ids
                                .as_ref()
                                .expect("remote worker control has configured worker targets")
                                .iter()
                                .copied()
                                .collect(),
                            route_catalog_fingerprint: crate::process_role::worker_egress_routes(
                                config,
                            )?
                            .fingerprint(),
                            coordination: config.call_coordination_config()?,
                        },
                        attachment_principals,
                        Arc::new(SystemCallServiceClock),
                    )
                    .await?;
                    tracing::info!(
                        backend = runtime.backend().as_str(),
                        worker_registered = false,
                        "role-separated transactional call control ready"
                    );
                    (None, Some(Arc::new(runtime)))
                }
            }
        } else {
            if config.api.enabled {
                tracing::warn!(
                    "transactional call API is unavailable until api.bearer_token, one static tenant, and api.control_hmac_key are configured"
                );
            }
            (None, None)
        };
        let call_service = call_runtime
            .as_ref()
            .map(|runtime| runtime.service())
            .or_else(|| {
                call_control_runtime
                    .as_ref()
                    .map(|runtime| runtime.service())
            });
        let call_repository = call_runtime
            .as_ref()
            .map(|runtime| runtime.repository())
            .or_else(|| {
                call_control_runtime
                    .as_ref()
                    .map(|runtime| runtime.repository())
            });
        let provider_events = call_repository.map(|repository| {
            Arc::new(RepositoryProviderEventPersistence { repository })
                as Arc<dyn ProviderEventPersistence>
        });
        let broadcast_commands: Option<Arc<dyn BroadcastCommandRepository>> =
            if runtime_kind == ApiCallRuntimeKind::RemoteWorkerControl {
                let mut backend = config.call_repository_backend()?;
                let database_url = match &mut backend {
                    CallRepositoryBackendConfig::Postgres { database_url } => {
                        std::mem::take(database_url)
                    }
                    _ => anyhow::bail!("split gateway broadcast commands require PostgreSQL"),
                };
                let deployment = config.call_coordination_config()?.deployment;
                Some(
                    PostgresBroadcastCommandRepository::connect(database_url, deployment).await?
                        as Arc<dyn BroadcastCommandRepository>,
                )
            } else {
                None
            };
        let screen_pop_evidence = ScreenPopEvidenceStore::new(
            DEFAULT_SCREEN_POP_EVIDENCE_TTL,
            DEFAULT_SCREEN_POP_EVIDENCE_CAPACITY,
        )?;
        let mut state = Self {
            server,
            providers,
            broadcasts: Arc::new(DashMap::new()),
            provider_events,
            metrics,
            tenants,
            bearer_authenticator,
            legacy_bearer_token,
            call_service,
            call_runtime,
            call_control_runtime,
            broadcast_tokens,
            shared_broadcast_grants,
            token_ttl: Duration::from_secs(config.broadcast.token_ttl_secs),
            max_broadcasts: config.broadcast.max_active,
            default_transport: config.broadcast.default_transport.parse()?,
            public_endpoint: config
                .broadcast
                .public_endpoint
                .clone()
                .unwrap_or_else(|| "moqt://127.0.0.1:4443".into()),
            api_enabled: config.api.enabled,
            context_policy: config.context.clone(),
            generic_runtime: None,
            local_capability_allowlist,
            local_execution_capabilities,
            managed_broadcast_service: None,
            broadcast_commands,
            clustered_uctp_gateway: runtime_kind == ApiCallRuntimeKind::RemoteWorkerControl
                && config
                    .broadcast
                    .public_endpoint
                    .as_deref()
                    .is_some_and(|endpoint| parse_uctp_endpoint(endpoint).is_ok()),
            clustered_moq_relay: config.broadcast.moq_origin_relay.is_some(),
            sanitized_event_policies,
            screen_pop_evidence,
            role_health,
            api_rate_limiter: ApiRateLimiter::from_config(&config.api.rate_limit),
            named_routes,
            split_worker_ids,
            signaling_tokens,
            webrtc_signaling_bearer_validator,
        };
        if let Some(runtime) = generic_runtime {
            state.set_generic_runtime(runtime).await?;
        }
        Ok(state)
    }

    /// Clone the handle that the rvoip lifecycle-event bridge will feed.
    pub fn screen_pop_evidence_store(&self) -> ScreenPopEvidenceStore {
        self.screen_pop_evidence.clone()
    }

    /// Shared durable service bundle used by both HTTP and signaling ingress.
    #[must_use]
    pub fn call_runtime(&self) -> Option<Arc<CallServiceRuntime>> {
        self.call_runtime.as_ref().map(Arc::clone)
    }

    /// Transport-free control-plane owner used only by split gateway mode.
    #[must_use]
    pub fn call_control_runtime(&self) -> Option<Arc<CallControlRuntime>> {
        self.call_control_runtime.as_ref().map(Arc::clone)
    }

    /// Whether the current runtime can execute all capabilities on one worker.
    /// Split mode reads authoritative live worker snapshots; all-in-one mode
    /// derives support from concrete adapters/providers installed in this
    /// process rather than trusting configured capability strings.
    async fn runtime_supports_capabilities(&self, capabilities: &[&str]) -> Result<bool, ApiError> {
        let Some(worker_ids) = &self.split_worker_ids else {
            return Ok(capabilities
                .iter()
                .all(|capability| self.local_execution_capabilities.contains(*capability)));
        };
        let runtime = self.call_control_runtime.as_ref().ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "call_service_unavailable",
                "split call-control runtime is unavailable",
            )
        })?;
        let repository = runtime.repository();
        let now = Utc::now();
        for worker_id in worker_ids.iter().copied() {
            match repository.worker_snapshot(worker_id).await {
                Ok(worker)
                    if !worker.draining
                        && worker.lease_expires_at > now
                        && capabilities
                            .iter()
                            .all(|capability| worker.capabilities.contains(*capability)) =>
                {
                    return Ok(true);
                }
                Ok(_) | Err(RepositoryError::NotFound) => {}
                Err(error) => return Err(ApiError::from(error)),
            }
        }
        Ok(false)
    }

    #[must_use]
    const fn is_split_gateway(&self) -> bool {
        self.split_worker_ids.is_some()
    }

    /// Native provider executor sharing the exact registry used for webhook
    /// verification and capability discovery.
    #[must_use]
    pub fn provider_registry(&self) -> ProviderRegistry {
        self.providers.clone()
    }

    /// Exact bearer validator used to construct control-plane principals.
    #[must_use]
    pub fn bearer_validator(&self) -> Option<Arc<dyn BearerValidator>> {
        self.bearer_authenticator
            .as_ref()
            .map(ApiBearerAuthenticator::validator)
    }

    /// Validator accepted only by the WebRTC signaling listener. It supports
    /// the configured control credential for privileged compatibility and
    /// the domain-prefixed, attachment-bound browser credential returned by
    /// named-route creation.
    #[must_use]
    pub fn webrtc_signaling_bearer_validator(&self) -> Option<Arc<dyn BearerValidator>> {
        self.webrtc_signaling_bearer_validator
            .as_ref()
            .map(Arc::clone)
    }

    /// Exact pre-upgrade attachment-binding authority paired with
    /// [`Self::webrtc_signaling_bearer_validator`].
    #[must_use]
    pub fn webrtc_session_binding(&self) -> Option<Arc<dyn WsBearerSessionBinding>> {
        self.signaling_tokens
            .as_ref()
            .map(|service| Arc::clone(service) as Arc<dyn WsBearerSessionBinding>)
    }

    fn signaling_token_service(&self) -> Option<Arc<SignalingTokenService>> {
        self.signaling_tokens.as_ref().map(Arc::clone)
    }

    /// Exact subscriber-token validator and active-grant authority shared by
    /// UCTP and MOQT network admission.
    #[must_use]
    pub fn broadcast_token_service(&self) -> Arc<BroadcastTokenService> {
        Arc::clone(&self.broadcast_tokens)
    }

    /// Closes every process-local publication after HTTP admission has
    /// stopped and before the underlying media runtime is drained. Split
    /// workers use their durable command executor instead, so their map is
    /// empty and this is a no-op.
    pub async fn shutdown_local_broadcasts(&self) -> usize {
        let active = self
            .broadcasts
            .iter()
            .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
            .collect::<Vec<_>>();
        let mut closed = 0;
        for (broadcast_id, broadcast) in active {
            if self
                .broadcasts
                .remove_if(&broadcast_id, |_, current| Arc::ptr_eq(current, &broadcast))
                .is_none()
            {
                continue;
            }
            if let Err(error) = broadcast
                .managed
                .close(BroadcastDrainReason::Shutdown)
                .await
            {
                tracing::warn!(%error, "local broadcast shutdown cleanup failed");
            }
            metrics::gauge!(
                "bridgefu_active_broadcasts",
                "transport" => broadcast_label(broadcast.transport)
            )
            .decrement(1.0);
            closed += 1;
        }
        closed
    }

    /// Installs the generic signaling runtime after the durable authority is
    /// ready and before the API router is exposed.
    pub async fn set_generic_runtime(
        &mut self,
        runtime: Arc<GenericBridgeRuntime>,
    ) -> anyhow::Result<()> {
        let capabilities = concrete_local_worker_capabilities(
            self.local_capability_allowlist.clone(),
            true,
            &self.providers.names(),
        );
        let call_runtime = self
            .call_runtime
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("generic runtime has no local call worker authority"))?;
        let managed_broadcast_service = Arc::new(
            match &self.shared_broadcast_grants {
                Some(store) => ManagedBroadcastService::with_shared_grants(
                    runtime.orchestrator(),
                    self.broadcast_tokens.grants(),
                    store.clone(),
                    bridgefu::broadcast::MAX_DIRECT_UCTP_SUBSCRIBERS,
                ),
                None => ManagedBroadcastService::new(
                    runtime.orchestrator(),
                    self.broadcast_tokens.grants(),
                    bridgefu::broadcast::MAX_DIRECT_UCTP_SUBSCRIBERS,
                ),
            }
            .expect("the release-bounded direct UCTP limit is valid"),
        );
        let activated = call_runtime
            .activate_worker_capabilities(capabilities.clone())
            .await
            .map_err(|error| anyhow::anyhow!("activating concrete worker capabilities: {error}"))?;
        if activated.capabilities != capabilities {
            anyhow::bail!("activated worker capabilities do not match installed adapters");
        }
        self.local_execution_capabilities = capabilities;
        self.managed_broadcast_service = Some(managed_broadcast_service);
        self.generic_runtime = Some(runtime);
        Ok(())
    }

    #[cfg(test)]
    fn set_local_execution_capabilities_for_test(
        &mut self,
        capabilities: impl IntoIterator<Item = &'static str>,
    ) {
        self.local_execution_capabilities = capabilities.into_iter().map(str::to_owned).collect();
    }

    #[cfg(test)]
    fn set_broadcast_orchestrator_for_test(&mut self, orchestrator: Arc<rvoip_core::Orchestrator>) {
        self.managed_broadcast_service = Some(Arc::new(
            ManagedBroadcastService::new(
                orchestrator,
                self.broadcast_tokens.grants(),
                bridgefu::broadcast::MAX_DIRECT_UCTP_SUBSCRIBERS,
            )
            .expect("test broadcast service configuration is valid"),
        ));
    }
}

fn local_runtime_supports_capabilities(
    generic_runtime_registered: bool,
    registered_providers: &[String],
    capabilities: &[&str],
) -> bool {
    if !generic_runtime_registered {
        return false;
    }
    capabilities.iter().all(|capability| match *capability {
        "sip" | "webrtc" | "sip_egress" | "webrtc_egress" | "amazon_connect" => true,
        "telnyx" => registered_providers
            .iter()
            .any(|provider| provider == "telnyx"),
        // Deferred and unknown executors are never inferred from YAML.
        _ => false,
    })
}

fn concrete_local_worker_capabilities(
    requested: BTreeSet<String>,
    generic_runtime_registered: bool,
    registered_providers: &[String],
) -> BTreeSet<String> {
    requested
        .into_iter()
        .filter(|capability| {
            local_runtime_supports_capabilities(
                generic_runtime_registered,
                registered_providers,
                &[capability.as_str()],
            )
        })
        .collect()
}

pub fn router(state: ApiState) -> Router {
    let operational = Router::new()
        .route("/healthz", get(readiness))
        .route("/livez", get(liveness))
        .route("/readyz", get(readiness))
        .route("/metrics", get(metrics));
    finish_router(operational.merge(public_routes(&state)), state)
}

/// Public split-gateway router. Operational health and Prometheus metrics are
/// intentionally absent; they remain on `observability.http_bind`.
pub fn public_router(state: ApiState) -> Router {
    let routes = public_routes(&state);
    finish_router(routes, state)
}

fn public_routes(state: &ApiState) -> Router<ApiState> {
    let protected = if state.api_enabled {
        let calls = Router::new()
            .route("/v1/calls", post(calls::create_call))
            .route("/v1/routes", get(calls::list_routes))
            .route("/v1/routes/:route_id/calls", post(calls::create_route_call))
            .route("/v1/calls/:call_id", get(calls::get_call))
            .route("/v1/calls/:call_id/hangup", post(calls::hangup_call))
            .route("/v1/calls/:call_id/transfer", post(calls::transfer_call))
            .route(
                "/v1/calls/:call_id/legs/:leg_id/replace",
                post(calls::replace_leg),
            )
            .route("/v1/calls/:call_id/dtmf", post(calls::dtmf_call))
            .layer(DefaultBodyLimit::max(64 * 1024));
        Router::new()
            .merge(calls)
            .route(
                "/v1/providers/:provider/capabilities",
                get(provider_capabilities),
            )
            .route("/v1/calls/:call_id/broadcasts", post(create_broadcast))
            .route(
                "/v1/broadcasts/:broadcast_id",
                get(get_broadcast).delete(delete_broadcast),
            )
            .route(
                "/v1/broadcasts/:broadcast_id/tokens",
                post(create_broadcast_token),
            )
            .route("/diagnostics", get(diagnostics))
            .route(
                "/v1/diagnostics/screen-pop/:correlation_id",
                get(get_screen_pop_evidence),
            )
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                require_api_auth,
            ))
    } else {
        Router::new()
    };

    let webhooks = Router::new()
        .route("/v1/providers/:provider/webhooks", post(provider_webhook))
        .layer(DefaultBodyLimit::max(256 * 1024))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_webhook_rate_admission,
        ));

    Router::new().merge(webhooks).merge(protected)
}

fn finish_router(routes: Router<ApiState>, state: ApiState) -> Router {
    routes
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(TraceLayer::new_for_http().make_span_with(http_request_span))
        .with_state(state)
}

struct RequestHeaderExtractor<'a>(&'a HeaderMap);

impl Extractor for RequestHeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(axum::http::HeaderName::as_str).collect()
    }
}

fn http_request_span<B>(request: &Request<B>) -> tracing::Span {
    // Do not record the raw URI: queries and provider callback paths can carry
    // untrusted or sensitive values. Route handlers add only contract-owned
    // durable identifiers to their child spans.
    let span = tracing::info_span!(
        "bridgefu.http.request",
        http.request.method = %request.method(),
        network.protocol.version = ?request.version(),
    );
    let remote_context = global::get_text_map_propagator(|propagator| {
        propagator.extract(&RequestHeaderExtractor(request.headers()))
    });
    let _ = span.set_parent(remote_context);
    span
}

pub async fn serve(
    bind: SocketAddr,
    app: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, "Bridgefu HTTP API listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

async fn require_api_auth(
    State(state): State<ApiState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    if state
        .role_health
        .as_ref()
        .is_some_and(|health| health.current() != RoleLifecycle::Ready)
    {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "gateway_not_ready",
            "gateway call admission is not ready",
        ));
    }
    let rate_identity = if let Some(authenticator) = &state.bearer_authenticator {
        let principal = authenticator
            .authenticate(request.headers(), Utc::now())
            .await
            .map_err(ApiError::from)?;
        let identity = principal_rate_identity(&principal);
        request.extensions_mut().insert(principal);
        identity
    } else if let Some(expected) = &state.legacy_bearer_token {
        if !legacy_bearer(request.headers())
            .is_some_and(|value| constant_time_eq(value.as_bytes(), &expected.0))
        {
            metrics::counter!("bridgefu_auth_failures_total", "surface" => "api").increment(1);
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "valid Bearer token required",
            )
            .with_header(axum::http::header::WWW_AUTHENTICATE, "Bearer"));
        }
        principal_rate_identity_legacy()
    } else {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
            "control API authentication is not configured",
        ));
    };
    let surface = if is_diagnostics_path(request.uri().path()) {
        ApiRateSurface::Diagnostics
    } else {
        ApiRateSurface::Control
    };
    state
        .api_rate_limiter
        .check(surface, &rate_identity)
        .map_err(ApiError::rate_limited)?;
    Ok(next.run(request).await)
}

async fn require_webhook_rate_admission(
    State(state): State<ApiState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    // A provider/tenant identity cannot be trusted until the handler verifies
    // the provider signature. Use one bounded gateway ingress bucket so
    // attacker-controlled path values never create rate-limit state.
    state
        .api_rate_limiter
        .check(ApiRateSurface::Webhook, b"provider-webhook-ingress")
        .map_err(ApiError::rate_limited)?;
    Ok(next.run(request).await)
}

fn is_diagnostics_path(path: &str) -> bool {
    path == "/diagnostics" || path.starts_with("/v1/diagnostics/")
}

fn principal_rate_identity(principal: &ApiPrincipal) -> [u8; 32] {
    let authenticated = principal.authenticated();
    let mut hasher = Sha256::new();
    hasher.update(b"bridgefu.api-principal-rate-key.v1\0");
    for component in [
        authenticated.issuer.as_deref().unwrap_or(""),
        principal.tenant().as_str(),
        authenticated.subject.as_str(),
    ] {
        hasher.update((component.len() as u64).to_be_bytes());
        hasher.update(component.as_bytes());
    }
    hasher.finalize().into()
}

fn principal_rate_identity_legacy() -> [u8; 32] {
    Sha256::digest(b"bridgefu.api-principal-rate-key.v1\0legacy-static-key").into()
}

fn legacy_bearer(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(axum::http::header::AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let value = value.to_str().ok()?;
    if value.contains(',') {
        return None;
    }
    let (scheme, credential) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || credential.is_empty()
        || credential.len() > MAX_API_BEARER_BYTES
        || credential
            .bytes()
            .any(|byte| !(0x21..=0x7e).contains(&byte))
    {
        return None;
    }
    Some(credential)
}

async fn liveness(State(state): State<ApiState>) -> (StatusCode, Json<Value>) {
    let live = state
        .role_health
        .as_ref()
        .is_none_or(|health| health.current().is_live());
    let status = if live {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "ok": live,
            // Operational probes are intentionally unauthenticated. Expose
            // only an aggregate so configured tenant identifiers never cross
            // that public infrastructure boundary.
            "tenant_count": state.tenants.len(),
            "mode": state.role_health.as_ref().map(|health| health.mode().as_str()).unwrap_or("all-in-one"),
            "state": state.role_health.as_ref().map(RoleHealth::current),
        })),
    )
}

async fn readiness(State(state): State<ApiState>) -> (StatusCode, Json<Value>) {
    let legacy_ready = state
        .server
        .as_ref()
        .is_none_or(|server| !server.is_draining());
    let call_runtime = state.call_runtime.as_ref().map(|runtime| {
        let health = *runtime.subscribe_supervisor_health().borrow();
        (
            matches!(health, RuntimeSupervisorHealth::Healthy),
            match health {
                RuntimeSupervisorHealth::Healthy => "healthy",
                RuntimeSupervisorHealth::Degraded => "degraded",
                RuntimeSupervisorHealth::Draining => "draining",
                RuntimeSupervisorHealth::LeaseLost => "lease_lost",
                RuntimeSupervisorHealth::Stopped => "stopped",
            },
        )
    });
    let call_control_runtime = state.call_control_runtime.as_ref().map(|runtime| {
        let health = *runtime.subscribe_health().borrow();
        (
            matches!(health, CallControlRuntimeHealth::Healthy),
            match health {
                CallControlRuntimeHealth::Healthy => "healthy",
                CallControlRuntimeHealth::Degraded => "degraded",
                CallControlRuntimeHealth::Draining => "draining",
                CallControlRuntimeHealth::Stopped => "stopped",
            },
        )
    });
    let role_ready = state
        .role_health
        .as_ref()
        .is_none_or(|health| health.current().is_ready());
    let ready = legacy_ready
        && role_ready
        && call_runtime.as_ref().is_none_or(|(ready, _)| *ready)
        && call_control_runtime
            .as_ref()
            .is_none_or(|(ready, _)| *ready);
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "ok": ready,
            "tenant_count": state.tenants.len(),
            "mode": if ready { "ready" } else { "not_ready" },
            "dependencies": {
                "process_role": state.role_health.as_ref().map(RoleHealth::current),
                "legacy_amazon_listener": if state.server.is_none() { "not_configured" } else if legacy_ready { "ready" } else { "draining" },
                "call_runtime": call_runtime.map(|(_, state)| state).unwrap_or("not_configured"),
                "call_control_runtime": call_control_runtime.map(|(_, state)| state).unwrap_or("not_configured"),
                "generic_bridge": if state.generic_runtime.is_some() { "configured" } else { "not_configured" },
            }
        })),
    )
}

async fn metrics(State(state): State<ApiState>) -> String {
    state.metrics.render()
}

async fn provider_capabilities(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    Path(provider): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let _principal = require_api_principal_for(principal, CallScope::Read)?;
    let adapter = state
        .providers
        .get(&provider)
        .ok_or_else(|| ApiError::not_found("provider is not configured"))?;
    Ok(Json(
        serde_json::to_value(adapter.capabilities()).expect("capabilities serialize"),
    ))
}

#[tracing::instrument(
    name = "bridgefu.api.provider_webhook",
    skip_all,
    fields(provider = tracing::field::Empty, event_id_present = tracing::field::Empty)
)]
async fn provider_webhook(
    State(state): State<ApiState>,
    Path(provider): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let adapter = state
        .providers
        .get(&provider)
        .ok_or_else(|| ApiError::not_found("provider is not configured"))?;
    tracing::Span::current().record("provider", adapter.name());
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let request = WebhookRequest {
        url: format!("{scheme}://{host}{uri}"),
        headers: headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.to_string(), v.to_string()))
            })
            .collect(),
        content_type: headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .into(),
        body: body.to_vec(),
    };
    let event = adapter.verify_webhook(&request)?;
    tracing::Span::current().record(
        "event_id_present",
        tracing::field::display(!event.event_id.is_empty()),
    );
    let persistence = state.provider_events.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "call_service_unavailable",
            "call service is unavailable",
        )
    })?;
    let input = provider_event_input(adapter.account_key(), adapter.name(), &event, Utc::now())?;
    match persistence
        .ingest_provider_event(input)
        .await
        .map_err(map_provider_event_repository_error)?
    {
        ProviderEventOutcome::Accepted(_) => {
            metrics::counter!("bridgefu_provider_webhooks_total", "provider" => provider, "result" => "accepted").increment(1);
            Ok((StatusCode::ACCEPTED, Json(json!({"status": "accepted"}))))
        }
        ProviderEventOutcome::Duplicate(_) => {
            metrics::counter!("bridgefu_provider_webhooks_total", "provider" => provider, "result" => "duplicate").increment(1);
            Ok((StatusCode::OK, Json(json!({"status": "duplicate"}))))
        }
    }
}

fn provider_event_input(
    account: ProviderAccountKey,
    expected_provider: &str,
    event: &NormalizedProviderEvent,
    received_at: DateTime<Utc>,
) -> Result<ProviderEventInput, ApiError> {
    if event.provider != expected_provider || !valid_provider_identifier(&event.event_id) {
        return Err(invalid_provider_event());
    }
    let provider_call_id = event
        .provider_call_id
        .as_ref()
        .ok_or_else(invalid_provider_event)
        .and_then(|value| {
            if valid_provider_identifier(value) {
                ProviderCallId::parse(value.clone()).map_err(|_| invalid_provider_event())
            } else {
                Err(invalid_provider_event())
            }
        })?;
    let occurred_at = event
        .occurred_at
        .as_deref()
        .map(parse_provider_timestamp)
        .transpose()?;
    let payload = canonicalize_provider_json(&event.raw);
    let payload_bytes = serde_json::to_vec(&payload).map_err(|_| invalid_provider_event())?;

    Ok(ProviderEventInput {
        account,
        event_digest: ProviderEventDigest::new(provider_digest(
            b"event-id",
            event.event_id.as_bytes(),
        )),
        payload_digest: ProviderPayloadDigest::new(provider_digest(b"payload", &payload_bytes)),
        provider_call_id,
        kind: event.event_type.clone(),
        payload,
        occurred_at,
        received_at,
    })
}

fn valid_provider_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn parse_provider_timestamp(value: &str) -> Result<DateTime<Utc>, ApiError> {
    DateTime::parse_from_rfc3339(value)
        .or_else(|_| DateTime::parse_from_rfc2822(value))
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| invalid_provider_event())
}

fn canonicalize_provider_json(value: &Value) -> Value {
    match value {
        Value::Array(values) => {
            Value::Array(values.iter().map(canonicalize_provider_json).collect())
        }
        Value::Object(values) => {
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key.clone(), canonicalize_provider_json(value)))
                    .collect(),
            )
        }
        _ => value.clone(),
    }
}

fn provider_digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"bridgefu.provider-webhook.v1\0");
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
    digest.finalize().into()
}

fn invalid_provider_event() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "invalid_provider_event",
        "provider webhook event is invalid",
    )
}

fn map_provider_event_repository_error(error: RepositoryError) -> ApiError {
    match error {
        RepositoryError::ProviderEventConflict => ApiError::new(
            StatusCode::CONFLICT,
            "provider_event_conflict",
            "provider webhook conflicts with an existing event",
        ),
        RepositoryError::InvalidInput(_) => invalid_provider_event(),
        error => ApiError::from(error),
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum BroadcastKind {
    Moqt,
    UctpQuic,
}

impl std::str::FromStr for BroadcastKind {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "moqt" => Ok(Self::Moqt),
            "uctp-quic" => Ok(Self::UctpQuic),
            _ => anyhow::bail!("unsupported broadcast transport {value}"),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateBroadcastRequest {
    source_leg_id: LegId,
    #[serde(default)]
    transport: Option<BroadcastKind>,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    language: Option<String>,
    /// Explicit request-level opt-in. The tenant must also have a validated
    /// configuration policy; omission/false creates no event track.
    #[serde(default)]
    sanitized_events: bool,
}

#[derive(Clone, Debug, Serialize)]
struct BroadcastView {
    broadcast_id: String,
    call_id: CallId,
    tenant_id: String,
    source_leg_id: LegId,
    transport: BroadcastKind,
    state: DurableBroadcastState,
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint: Option<Value>,
    expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lifecycle: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    health: Option<Value>,
    sanitized_events: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_code: Option<String>,
}

impl ActiveBroadcast {
    fn tenant_id(&self) -> &str {
        self.managed.tenant_id()
    }

    fn view(&self) -> BroadcastView {
        BroadcastView {
            broadcast_id: self.managed.broadcast_id().to_owned(),
            call_id: self.call_id,
            tenant_id: self.managed.tenant_id().to_owned(),
            source_leg_id: self.source_leg_id,
            transport: self.transport,
            state: DurableBroadcastState::Active,
            endpoint: serde_json::to_value(self.managed.endpoint()).ok(),
            expires_at: self.managed.diagnostics().expires_at,
            protocol: serde_json::to_value(self.managed.protocol()).ok(),
            lifecycle: serde_json::to_value(self.managed.lifecycle()).ok(),
            health: serde_json::to_value(self.managed.health()).ok(),
            sanitized_events: self.managed.diagnostics().sanitized_events.enabled,
            failure_code: None,
        }
    }

    fn diagnostics(&self) -> Value {
        let diagnostics = self.managed.diagnostics();
        // The process-local rvoip ConnectionId deliberately does not cross
        // the authenticated diagnostics boundary.
        json!({
            "broadcast_id": diagnostics.broadcast_id,
            "call_id": self.call_id,
            "tenant_id": diagnostics.tenant_id,
            "source_leg_id": self.source_leg_id,
            "transport": diagnostics.transport,
            "endpoint": diagnostics.endpoint,
            "protocol": diagnostics.protocol,
            "lifecycle": diagnostics.lifecycle,
            "health": diagnostics.health,
            "expires_at": diagnostics.expires_at,
            "graph_id": diagnostics.graph_id,
            "route_state": diagnostics.route_state,
            "source_frames": diagnostics.source_frames,
            "graph_dropped_frames": diagnostics.graph_dropped_frames,
            "graph_evictions": diagnostics.graph_evictions,
            "transcode_operations": diagnostics.transcode_operations,
            "route_queue_depth": diagnostics.route_queue_depth,
            "route_queue_capacity": diagnostics.route_queue_capacity,
            "route_offered_frames": diagnostics.route_offered_frames,
            "route_dropped_frames": diagnostics.route_dropped_frames,
            "sanitized_events": diagnostics.sanitized_events,
        })
    }
}

impl BroadcastView {
    fn from_durable(record: DurableBroadcastRecord) -> Self {
        // A retained runtime on failed stale-fence rows is cleanup metadata,
        // not a reachable subscriber endpoint.
        let runtime = (record.state == DurableBroadcastState::Active)
            .then_some(record.runtime)
            .flatten();
        Self {
            broadcast_id: record.specification.broadcast_id,
            call_id: record.specification.call_id,
            tenant_id: record.specification.tenant_id.as_str().to_owned(),
            source_leg_id: record.specification.source_leg_id,
            transport: match record.specification.transport {
                DurableBroadcastTransport::Moqt => BroadcastKind::Moqt,
                DurableBroadcastTransport::UctpQuic => BroadcastKind::UctpQuic,
            },
            state: record.state,
            endpoint: runtime.as_ref().map(|runtime| runtime.endpoint.clone()),
            expires_at: record.specification.expires_at,
            protocol: runtime.as_ref().map(|runtime| runtime.protocol.clone()),
            lifecycle: runtime.as_ref().map(|runtime| runtime.lifecycle.clone()),
            health: runtime.as_ref().map(|runtime| runtime.health.clone()),
            sanitized_events: runtime
                .as_ref()
                .is_some_and(|runtime| runtime.sanitized_events),
            failure_code: record.failure_code,
        }
    }
}

async fn prune_terminal_local_broadcasts(state: &ApiState) {
    let terminal = state
        .broadcasts
        .iter()
        .filter(|entry| {
            entry.managed.diagnostics().expires_at <= Utc::now()
                || matches!(
                    entry.managed.lifecycle().state,
                    BroadcastLifecycleState::Closed | BroadcastLifecycleState::Failed
                )
        })
        .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
        .collect::<Vec<_>>();
    for (broadcast_id, active) in terminal {
        if state
            .broadcasts
            .remove_if(&broadcast_id, |_, current| Arc::ptr_eq(current, &active))
            .is_none()
        {
            continue;
        }
        let _ = active
            .managed
            .close(BroadcastDrainReason::Reconfigure)
            .await;
        metrics::gauge!(
            "bridgefu_active_broadcasts",
            "transport" => broadcast_label(active.transport)
        )
        .decrement(1.0);
    }
}

async fn create_broadcast(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    Path(call_id): Path<String>,
    headers: HeaderMap,
    input: Result<Json<CreateBroadcastRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<BroadcastView>), ApiError> {
    let principal = require_api_principal_for(principal, CallScope::Read)?;
    let Json(request) = input.map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_broadcast_request",
            "broadcast request is invalid",
        )
    })?;
    let call_id = parse_broadcast_call_id(&call_id)?;
    if state.call_control_runtime.is_some() {
        return create_remote_broadcast(&state, &principal, call_id, &headers, request).await;
    }
    prune_terminal_local_broadcasts(&state).await;
    let call_runtime = state.call_runtime.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "call_service_unavailable",
            "transactional call service is not configured",
        )
    })?;
    let managed_service = state.managed_broadcast_service.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "broadcast_runtime_unavailable",
            "generic media runtime is not configured",
        )
    })?;
    if state.broadcasts.len() >= state.max_broadcasts {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "capacity_exceeded",
            "worker broadcast capacity reached",
        ));
    }
    let service = call_runtime.service();
    let source = service
        .resolve_broadcast_source(
            &principal,
            call_id,
            request.source_leg_id,
            request.tenant_id.as_deref(),
            call_runtime.worker().lease,
        )
        .await?;
    let broadcast_id = Uuid::new_v4().to_string();
    let transport = request.transport.unwrap_or(state.default_transport);
    let expires_at = Utc::now() + chrono::Duration::hours(24);
    let sanitized_events = if request.sanitized_events {
        if transport != BroadcastKind::Moqt {
            return Err(ApiError::capability(
                "sanitized events are available only for MOQT broadcasts",
            ));
        }
        let policy = state
            .sanitized_event_policies
            .get(source.tenant_id().as_str())
            .cloned()
            .ok_or_else(|| {
                ApiError::capability(
                    "sanitized events are not enabled for the authenticated tenant",
                )
            })?;
        Some(
            ManagedSanitizedEventBinding::new(
                call_id.to_string(),
                request.source_leg_id.to_string(),
                policy,
            )
            .map_err(map_managed_broadcast_error)?,
        )
    } else {
        None
    };
    let managed_transport = match transport {
        BroadcastKind::Moqt => ManagedBroadcastTransport::Moqt {
            publisher: MoqPublisherConfig {
                tenant_id: source.tenant_id().as_str().to_owned(),
                broadcast_id: broadcast_id.clone(),
                bitrate: 24_000,
                language: request.language,
                queue_frames: 10,
            },
            relay: None,
            sanitized_events,
        },
        BroadcastKind::UctpQuic => ManagedBroadcastTransport::UctpQuic {
            endpoint: parse_uctp_endpoint(&state.public_endpoint)?,
        },
    };
    let managed = managed_service
        .start(
            source.tenant_id().as_str(),
            broadcast_id.clone(),
            source.connection_id(),
            expires_at,
            managed_transport,
        )
        .await
        .map_err(map_managed_broadcast_error)?;

    // A transport route may have rotated while its graph was being attached.
    // Re-read the durable binding and tear down the exact new publication if
    // it is no longer current.
    let revalidated = service
        .resolve_broadcast_source(
            &principal,
            call_id,
            request.source_leg_id,
            request.tenant_id.as_deref(),
            call_runtime.worker().lease,
        )
        .await;
    match revalidated {
        Ok(current) if current == source => {}
        Ok(_) => {
            let _ = managed.close(BroadcastDrainReason::Reconfigure).await;
            return Err(ApiError::from(CallServiceError::InvalidTransition));
        }
        Err(error) => {
            let _ = managed.close(BroadcastDrainReason::Reconfigure).await;
            return Err(ApiError::from(error));
        }
    }
    let active = Arc::new(ActiveBroadcast {
        call_id,
        source_leg_id: request.source_leg_id,
        transport,
        managed,
    });
    let view = active.view();
    state.broadcasts.insert(broadcast_id, active);
    metrics::gauge!("bridgefu_active_broadcasts", "transport" => broadcast_label(transport))
        .increment(1.0);
    Ok((StatusCode::CREATED, Json(view)))
}

async fn create_remote_broadcast(
    state: &ApiState,
    principal: &ApiPrincipal,
    call_id: CallId,
    headers: &HeaderMap,
    request: CreateBroadcastRequest,
) -> Result<(StatusCode, Json<BroadcastView>), ApiError> {
    let commands = state.broadcast_commands.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "broadcast_runtime_unavailable",
            "durable broadcast command service is unavailable",
        )
    })?;
    let service = state.call_service.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "call_service_unavailable",
            "transactional call service is not configured",
        )
    })?;
    let request_bytes = serde_json::to_vec(&request).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_broadcast_request",
            "broadcast request is invalid",
        )
    })?;
    let identity = broadcast_operation_identity(
        headers,
        principal.tenant().as_str(),
        "create",
        call_id.to_string().as_bytes(),
        &request_bytes,
    )?;
    let source = service
        .resolve_assigned_broadcast_source(
            principal,
            call_id,
            request.source_leg_id,
            request.tenant_id.as_deref(),
        )
        .await?;
    let transport = request.transport.unwrap_or(state.default_transport);
    validate_clustered_broadcast_transport(
        transport,
        state.clustered_uctp_gateway,
        state.clustered_moq_relay,
    )?;
    if request.sanitized_events {
        if transport != BroadcastKind::Moqt {
            return Err(ApiError::capability(
                "sanitized events are available only for MOQT broadcasts",
            ));
        }
        if !state
            .sanitized_event_policies
            .contains_key(source.tenant_id().as_str())
        {
            return Err(ApiError::capability(
                "sanitized events are not enabled for the authenticated tenant",
            ));
        }
    }
    let outcome = commands
        .enqueue_start(
            DurableBroadcastSpec {
                broadcast_id: Uuid::new_v4().to_string(),
                tenant_id: source.tenant_id().clone(),
                call_id,
                source_leg_id: source.leg_id(),
                source_binding_generation: source.binding_generation(),
                worker: source.worker(),
                transport: match transport {
                    BroadcastKind::Moqt => DurableBroadcastTransport::Moqt,
                    BroadcastKind::UctpQuic => DurableBroadcastTransport::UctpQuic,
                },
                language: request.language,
                sanitized_events: request.sanitized_events,
                expires_at: Utc::now() + chrono::Duration::hours(24),
            },
            identity,
            state.max_broadcasts,
        )
        .await
        .map_err(ApiError::from)?;
    metrics::counter!(
        "bridgefu_broadcast_commands_total",
        "operation" => "start",
        "result" => if outcome.replayed { "replayed" } else { "accepted" }
    )
    .increment(1);
    let status = if outcome.record.state == DurableBroadcastState::Active {
        StatusCode::CREATED
    } else {
        StatusCode::ACCEPTED
    };
    Ok((status, Json(BroadcastView::from_durable(outcome.record))))
}

async fn get_broadcast(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    Path(id): Path<String>,
) -> Result<Json<BroadcastView>, ApiError> {
    let principal = require_api_principal_for(principal, CallScope::Read)?;
    if let Some(commands) = &state.broadcast_commands {
        return commands
            .get(principal.tenant(), &id)
            .await
            .map_err(ApiError::from)?
            .filter(|record| record.state != DurableBroadcastState::Deleted)
            .map(BroadcastView::from_durable)
            .map(Json)
            .ok_or_else(|| ApiError::not_found("broadcast not found"));
    }
    prune_terminal_local_broadcasts(&state).await;
    state
        .broadcasts
        .get(&id)
        .filter(|record| record.tenant_id() == principal.tenant().as_str())
        .map(|record| Json(record.view()))
        .ok_or_else(|| ApiError::not_found("broadcast not found"))
}

async fn delete_broadcast(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let principal = require_api_principal_for(principal, CallScope::Read)?;
    if let Some(commands) = &state.broadcast_commands {
        let identity = broadcast_operation_identity(
            &headers,
            principal.tenant().as_str(),
            "delete",
            id.as_bytes(),
            &[],
        )?;
        commands
            .enqueue_stop(principal.tenant(), &id, identity)
            .await
            .map_err(ApiError::from)?;
        metrics::counter!(
            "bridgefu_broadcast_commands_total",
            "operation" => "stop",
            "result" => "accepted"
        )
        .increment(1);
        return Ok(StatusCode::ACCEPTED);
    }
    prune_terminal_local_broadcasts(&state).await;
    let Some((_, active)) = state.broadcasts.remove_if(&id, |_, active| {
        active.tenant_id() == principal.tenant().as_str()
    }) else {
        return Err(ApiError::not_found("broadcast not found"));
    };
    active
        .managed
        .close(BroadcastDrainReason::OperatorRequest)
        .await
        .map_err(map_managed_broadcast_error)?;
    metrics::gauge!("bridgefu_active_broadcasts", "transport" => broadcast_label(active.transport))
        .decrement(1.0);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    #[serde(default)]
    ttl_secs: Option<u64>,
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
    expires_at: DateTime<Utc>,
    scope: String,
}

async fn create_broadcast_token(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    Path(id): Path<String>,
    Json(request): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    let principal = require_api_principal_for(principal, CallScope::Read)?;
    if let Some(commands) = &state.broadcast_commands {
        let record = commands
            .get(principal.tenant(), &id)
            .await
            .map_err(ApiError::from)?
            .filter(|record| record.state == DurableBroadcastState::Active)
            .ok_or_else(|| ApiError::not_found("broadcast not found"))?;
        let ttl = Duration::from_secs(
            request
                .ttl_secs
                .unwrap_or(state.token_ttl.as_secs())
                .min(state.token_ttl.as_secs())
                .max(1),
        );
        let issued = state
            .broadcast_token_service()
            .issue_authorized(record.specification.tenant_id.as_str(), &id, ttl)
            .await
            .map_err(|_| {
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "broadcast_authority_unavailable",
                    "broadcast subscriber authority is unavailable",
                )
            })?;
        return Ok(Json(TokenResponse {
            token: issued.token,
            expires_at: issued.expires_at,
            scope: issued.scope,
        }));
    }
    prune_terminal_local_broadcasts(&state).await;
    let active = state
        .broadcasts
        .get(&id)
        .filter(|active| active.tenant_id() == principal.tenant().as_str())
        .ok_or_else(|| ApiError::not_found("broadcast not found"))?;
    let ttl = Duration::from_secs(
        request
            .ttl_secs
            .unwrap_or(state.token_ttl.as_secs())
            .min(state.token_ttl.as_secs())
            .max(1),
    );
    let issued = state
        .broadcast_token_service()
        .issue(active.tenant_id(), &id, ttl)
        .map_err(|error| ApiError::internal(error.to_string()))?;
    Ok(Json(TokenResponse {
        token: issued.token,
        expires_at: issued.expires_at,
        scope: issued.scope,
    }))
}

async fn diagnostics(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
) -> Result<Json<Value>, ApiError> {
    let principal = require_api_principal_for(principal, CallScope::Read)?;
    prune_terminal_local_broadcasts(&state).await;
    let broadcasts: Vec<_> = state
        .broadcasts
        .iter()
        .filter(|entry| entry.tenant_id() == principal.tenant().as_str())
        .map(|entry| entry.diagnostics())
        .collect();
    let mut response = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "tenant_id": principal.tenant(),
        "transactional_call_api": state.call_service.is_some(),
        "call_repository": state.call_runtime.as_ref().map(|runtime| runtime.backend().as_str()).or_else(|| state.call_control_runtime.as_ref().map(|runtime| runtime.backend().as_str())),
        "call_execution": if state.call_runtime.is_some() { "local-worker" } else if state.call_control_runtime.is_some() { "remote-worker" } else { "not-configured" },
        "providers": state.providers.names(),
        "api_rate_limit": state.api_rate_limiter.diagnostics(),
        "broadcasts": broadcasts,
        "moqt_target_draft": rvoip_moq::TARGET_MOQT_DRAFT,
        "context_headers": state.context_policy.allow_headers.keys().collect::<Vec<_>>(),
        "generic_bridge": state.generic_runtime.as_ref().map(|runtime| json!({
            "sip": runtime.sip_addr,
            "ws": runtime.ws_addr,
            "whip": runtime.whip_addr,
        })),
    });
    if let Some(server) = state.server.as_ref().filter(
        |_| matches!(state.tenants.as_slice(), [tenant] if tenant == principal.tenant().as_str()),
    ) {
        response["active_amazon_calls"] = json!(server.active_call_ids());
    }
    Ok(Json(response))
}

async fn get_screen_pop_evidence(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    Path(correlation_id): Path<String>,
) -> Result<Json<ScreenPopEvidence>, ApiError> {
    let principal = require_api_principal_for(principal, CallScope::Read)?;
    ensure_legacy_amazon_tenant(&state, &principal)?;
    match state.screen_pop_evidence.get(&correlation_id) {
        Some(evidence) => {
            metrics::counter!(
                "bridgefu_screen_pop_evidence_lookups_total",
                "result" => "hit"
            )
            .increment(1);
            Ok(Json(evidence))
        }
        None => {
            metrics::counter!(
                "bridgefu_screen_pop_evidence_lookups_total",
                "result" => "miss"
            )
            .increment(1);
            Err(ApiError::not_found("screen-pop evidence not found"))
        }
    }
}

fn require_api_principal_for(
    principal: Option<Extension<ApiPrincipal>>,
    scope: CallScope,
) -> Result<ApiPrincipal, ApiError> {
    let principal = principal.map(|value| value.0).ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "tenant_authentication_unavailable",
            "tenant-scoped authentication is required for this resource",
        )
    })?;
    principal.authorize(scope, Utc::now())?;
    Ok(principal)
}

fn parse_broadcast_call_id(value: &str) -> Result<CallId, ApiError> {
    value.parse().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_call_id",
            "call ID must be a non-nil UUID",
        )
    })
}

fn validate_clustered_broadcast_transport(
    transport: BroadcastKind,
    uctp_gateway_configured: bool,
    relay_configured: bool,
) -> Result<(), ApiError> {
    match transport {
        BroadcastKind::UctpQuic if uctp_gateway_configured => Ok(()),
        BroadcastKind::UctpQuic => Err(ApiError::capability(
            "clustered UCTP broadcasts require a configured public gateway endpoint",
        )),
        BroadcastKind::Moqt if !relay_configured => Err(ApiError::capability(
            "clustered MOQT broadcasts require broadcast.moq_origin_relay",
        )),
        BroadcastKind::Moqt => Err(ApiError::capability(
            "clustered MOQT random namespaces remain disabled until exact-namespace dynamic publisher authorization is reviewed and enabled",
        )),
    }
}

fn broadcast_operation_identity(
    headers: &HeaderMap,
    tenant_id: &str,
    operation: &str,
    resource_id: &[u8],
    canonical_body: &[u8],
) -> Result<BroadcastOperationIdentity, ApiError> {
    let key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_idempotency_key",
                "Idempotency-Key is required for clustered broadcast mutations",
            )
        })?;
    let mut idempotency = Sha256::new();
    idempotency.update(b"bridgefu.broadcast.idempotency.v1\0");
    idempotency.update((tenant_id.len() as u64).to_be_bytes());
    idempotency.update(tenant_id.as_bytes());
    idempotency.update((key.len() as u64).to_be_bytes());
    idempotency.update(key.as_bytes());

    let mut request = Sha256::new();
    request.update(b"bridgefu.broadcast.request.v1\0");
    request.update((tenant_id.len() as u64).to_be_bytes());
    request.update(tenant_id.as_bytes());
    request.update((operation.len() as u64).to_be_bytes());
    request.update(operation.as_bytes());
    request.update((resource_id.len() as u64).to_be_bytes());
    request.update(resource_id);
    request.update((canonical_body.len() as u64).to_be_bytes());
    request.update(canonical_body);
    Ok(BroadcastOperationIdentity {
        idempotency_digest: idempotency.finalize().into(),
        request_digest: request.finalize().into(),
    })
}

fn parse_uctp_endpoint(value: &str) -> Result<Url, ApiError> {
    let endpoint = Url::parse(value).map_err(|_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "broadcast_runtime_unavailable",
            "UCTP subscriber endpoint is not configured",
        )
    })?;
    if endpoint.scheme() != "uctp+quic"
        || endpoint.host_str().is_none()
        || endpoint.port().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.path() != ""
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "broadcast_runtime_unavailable",
            "UCTP subscriber endpoint is not configured",
        ));
    }
    Ok(endpoint)
}

fn map_managed_broadcast_error(_error: ManagedBroadcastError) -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "broadcast_runtime_unavailable",
        "broadcast media runtime is unavailable",
    )
}

fn ensure_legacy_amazon_tenant(state: &ApiState, principal: &ApiPrincipal) -> Result<(), ApiError> {
    if matches!(state.tenants.as_slice(), [tenant] if tenant == principal.tenant().as_str()) {
        Ok(())
    } else {
        Err(ApiError::capability(
            "legacy Amazon call ownership is unavailable in a multi-tenant runtime",
        ))
    }
}

fn broadcast_label(kind: BroadcastKind) -> &'static str {
    match kind {
        BroadcastKind::Moqt => "moqt",
        BroadcastKind::UctpQuic => "uctp-quic",
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    headers: Vec<(axum::http::header::HeaderName, axum::http::HeaderValue)>,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            headers: Vec::new(),
        }
    }
    fn with_header(mut self, name: axum::http::header::HeaderName, value: &'static str) -> Self {
        self.headers
            .push((name, axum::http::HeaderValue::from_static(value)));
        self
    }
    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }
    fn capability(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "unsupported_capability", message)
    }
    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
    }
    fn rate_limited(rejection: RateLimitRejection) -> Self {
        let retry_after =
            axum::http::HeaderValue::from_str(&rejection.retry_after_seconds().to_string())
                .expect("positive integer is a valid Retry-After header");
        let mut error = Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "request rate limit exceeded",
        );
        error
            .headers
            .push((axum::http::header::RETRY_AFTER, retry_after));
        error
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let headers = self.headers.into_iter().collect::<HeaderMap>();
        (
            self.status,
            headers,
            Json(json!({"error": {"code": self.code, "message": self.message}})),
        )
            .into_response()
    }
}

impl From<ApiPrincipalError> for ApiError {
    fn from(error: ApiPrincipalError) -> Self {
        match error {
            ApiPrincipalError::MissingCredential
            | ApiPrincipalError::MalformedCredential
            | ApiPrincipalError::InvalidCredential
            | ApiPrincipalError::ExpiredCredential
            | ApiPrincipalError::TenantRequired => Self::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "valid Bearer token required",
            )
            .with_header(axum::http::header::WWW_AUTHENTICATE, "Bearer"),
            ApiPrincipalError::MissingScope(_) | ApiPrincipalError::TenantOverrideForbidden => {
                Self::new(
                    StatusCode::FORBIDDEN,
                    "forbidden",
                    "authenticated principal is not authorized for this operation",
                )
            }
            ApiPrincipalError::InvalidTenant => Self::new(
                StatusCode::BAD_REQUEST,
                "invalid_tenant",
                "tenant identifier is invalid",
            ),
            ApiPrincipalError::AuthenticationUnavailable
            | ApiPrincipalError::AmbiguousStaticTenant
            | ApiPrincipalError::InvalidStaticApiKey
            | ApiPrincipalError::InvalidFingerprintKey => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication_unavailable",
                "authentication service is unavailable",
            ),
        }
    }
}

impl From<RepositoryError> for ApiError {
    fn from(error: RepositoryError) -> Self {
        match error {
            RepositoryError::NotFound => Self::not_found("call not found"),
            RepositoryError::CapacityExceeded => Self::new(
                StatusCode::TOO_MANY_REQUESTS,
                "capacity_exceeded",
                "worker call capacity reached",
            )
            .with_header(axum::http::header::RETRY_AFTER, "1"),
            RepositoryError::WorkerCapabilityUnavailable => {
                Self::capability("the selected call route is not installed on an eligible worker")
            }
            RepositoryError::InvalidInput(_) => Self::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "call request is invalid",
            ),
            RepositoryError::StaleWorkerFence
            | RepositoryError::CounterExhausted
            | RepositoryError::Unavailable => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "call_service_unavailable",
                "call service is unavailable",
            ),
            RepositoryError::VersionConflict
            | RepositoryError::CommandConflict
            | RepositoryError::IdempotencyConflict
            | RepositoryError::AttachmentRejected
            | RepositoryError::AttachmentConflict
            | RepositoryError::ProviderEventConflict
            | RepositoryError::ProviderReferenceConflict
            | RepositoryError::StaleClaim
            | RepositoryError::DomainRejected => Self::new(
                StatusCode::CONFLICT,
                "call_conflict",
                "call state or idempotency receipt conflicts with this request",
            ),
        }
    }
}

impl From<ControlCryptoError> for ApiError {
    fn from(error: ControlCryptoError) -> Self {
        match error {
            ControlCryptoError::MissingIdempotencyKey
            | ControlCryptoError::DuplicateIdempotencyKey
            | ControlCryptoError::MalformedIdempotencyKey => Self::new(
                StatusCode::BAD_REQUEST,
                "invalid_idempotency_key",
                error.to_string(),
            ),
            ControlCryptoError::InvalidControlKey | ControlCryptoError::TimestampOverflow => {
                Self::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "call_service_unavailable",
                    "call service is unavailable",
                )
            }
        }
    }
}

impl From<CallServiceError> for ApiError {
    fn from(error: CallServiceError) -> Self {
        match error {
            CallServiceError::Principal(error) => Self::from(error),
            CallServiceError::Crypto(error) => Self::from(error),
            CallServiceError::Repository(error) => Self::from(error),
            CallServiceError::CapacityExceeded => Self::new(
                StatusCode::TOO_MANY_REQUESTS,
                "capacity_exceeded",
                "worker call capacity reached",
            )
            .with_header(axum::http::header::RETRY_AFTER, "1"),
            CallServiceError::DependencyUnavailable => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "call_service_unavailable",
                "call service is unavailable",
            ),
            CallServiceError::AttachmentPrincipalUnresolved => {
                Self::capability("inbound leg has no configured authenticated signaling profile")
            }
            CallServiceError::ProviderDeferred => Self::capability(
                "Twilio and Vonage provider control are deferred beyond Bridgefu 1.0",
            ),
            CallServiceError::UnsupportedCapability => Self::capability(
                "the selected call leg does not support the requested transfer target",
            ),
            CallServiceError::InvalidInput(_) => Self::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "call request is invalid",
            ),
            CallServiceError::InvalidTransition => Self::new(
                StatusCode::CONFLICT,
                "invalid_transition",
                "call state does not allow this operation",
            ),
        }
    }
}

impl From<ProviderError> for ApiError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::InvalidSignature => Self::new(
                StatusCode::UNAUTHORIZED,
                "invalid_signature",
                error.to_string(),
            ),
            ProviderError::Unsupported | ProviderError::AccountProfileMismatch => {
                Self::capability(error.to_string())
            }
            ProviderError::Remote { .. }
            | ProviderError::Http(_)
            | ProviderError::Telnyx { .. }
            | ProviderError::CircuitOpen => {
                Self::new(StatusCode::BAD_GATEWAY, "provider_error", error.to_string())
            }
            ProviderError::Configuration(_) => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "provider_configuration",
                error.to_string(),
            ),
            _ => Self::new(
                StatusCode::BAD_REQUEST,
                "provider_request",
                error.to_string(),
            ),
        }
    }
}

impl From<BroadcastCommandError> for ApiError {
    fn from(error: BroadcastCommandError) -> Self {
        match error {
            BroadcastCommandError::NotFound => Self::not_found("broadcast not found"),
            BroadcastCommandError::IdempotencyConflict => Self::new(
                StatusCode::CONFLICT,
                "idempotency_conflict",
                "Idempotency-Key was already used for a different broadcast operation",
            ),
            BroadcastCommandError::CapacityExceeded => Self::new(
                StatusCode::TOO_MANY_REQUESTS,
                "capacity_exceeded",
                "worker broadcast capacity reached",
            )
            .with_header(axum::http::header::RETRY_AFTER, "1"),
            BroadcastCommandError::InvalidTransition => Self::new(
                StatusCode::CONFLICT,
                "invalid_transition",
                "broadcast state does not allow this operation",
            ),
            BroadcastCommandError::InvalidData => Self::new(
                StatusCode::BAD_REQUEST,
                "invalid_broadcast_request",
                "broadcast request is invalid",
            ),
            BroadcastCommandError::Unavailable | BroadcastCommandError::StaleClaim => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "broadcast_runtime_unavailable",
                "durable broadcast command service is unavailable",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bridgefu::call_engine::ProviderReferenceRole;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;

    use async_trait::async_trait;
    use axum::body::{to_bytes, Body};
    use bridgefu::call_engine::{
        CallCommand, CallId, CommandCommit, CommandId, EffectIntent, LegId, LegState,
        ProviderEventState, TenantId,
    };
    use bridgefu::call_service::{
        AttachmentPrincipalResolver, ConfiguredAttachmentPrincipalResolver, EffectResultOutcome,
        EffectResultReconciliation, ExternalReferenceBinding, ExternalReferenceValue,
        InboundAttachmentRequest, ProviderEndpointConfig, ProviderKind, ServiceCommandTransaction,
        ServiceEffectResult,
    };
    use rvoip_amazon_connect::{
        ConnectContactStarter, ConnectError, ConnectionData, StartContactRequest,
    };
    use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod};
    use rvoip_core::adapter::{
        AdapterEvent, AdapterKind, ConnectionAdapter, ConnectionHandle, EndReason,
        OriginateRequest, RejectReason, SignatureHeaders, TransferTarget as RvoipTransferTarget,
    };
    use rvoip_core::capability::{CapabilityDescriptor, CodecInfo, NegotiatedCodecs};
    use rvoip_core::connection::{
        Connection, ConnectionState, Direction, Transport, TransportHandle,
    };
    use rvoip_core::ids::{ConnectionId, ParticipantId, SessionId, StreamId};
    use rvoip_core::message::Message;
    use rvoip_core::stream::{MediaStream, QualitySnapshot, StreamKind};
    use rvoip_core::{
        Config as RvoipConfig, CredentialKind, IdentityAssurance, Jwk, MediaFrame, Orchestrator,
        Result as RvoipResult, RvoipError,
    };
    use tokio::sync::mpsc;
    use tower::ServiceExt;

    use crate::providers::{
        BridgeCommand, DtmfCommand, HangupCommand, OriginateCommand, ProviderCall,
        ProviderCapabilities, ProviderControl, TransferCommand,
    };
    use crate::screen_pop_evidence::ScreenPopStage;

    #[test]
    fn all_in_one_capabilities_require_concrete_runtime_and_provider() {
        let configured_but_unregistered =
            ["sip_egress", "webrtc_egress", "telnyx", "twilio", "vonage"];
        assert!(!local_runtime_supports_capabilities(
            false,
            &["telnyx".to_owned()],
            &configured_but_unregistered,
        ));
        assert!(!local_runtime_supports_capabilities(true, &[], &["telnyx"],));
        assert!(!local_runtime_supports_capabilities(
            true,
            &["telnyx".to_owned()],
            &["twilio"],
        ));
        assert!(local_runtime_supports_capabilities(
            true,
            &["telnyx".to_owned()],
            &["sip", "sip_egress", "telnyx"],
        ));
        assert!(concrete_local_worker_capabilities(
            BTreeSet::from([
                "sip_egress".to_owned(),
                "telnyx".to_owned(),
                "twilio".to_owned(),
            ]),
            false,
            &["telnyx".to_owned()],
        )
        .is_empty());
        assert_eq!(
            concrete_local_worker_capabilities(
                BTreeSet::from([
                    "sip_egress".to_owned(),
                    "telnyx".to_owned(),
                    "vonage".to_owned(),
                ]),
                true,
                &[],
            ),
            BTreeSet::from(["sip_egress".to_owned()])
        );
    }

    struct UnusedStarter;

    struct BroadcastTestStream {
        id: StreamId,
        inbound: StdMutex<Option<mpsc::Receiver<MediaFrame>>>,
        outbound: mpsc::Sender<MediaFrame>,
    }

    impl BroadcastTestStream {
        fn source() -> (Arc<Self>, mpsc::Sender<MediaFrame>) {
            let (source, inbound) = mpsc::channel(32);
            let (outbound, _) = mpsc::channel(1);
            (
                Arc::new(Self {
                    id: StreamId::new(),
                    inbound: StdMutex::new(Some(inbound)),
                    outbound,
                }),
                source,
            )
        }
    }

    #[async_trait]
    impl MediaStream for BroadcastTestStream {
        fn id(&self) -> StreamId {
            self.id.clone()
        }

        fn kind(&self) -> StreamKind {
            StreamKind::Audio
        }

        fn codec(&self) -> CodecInfo {
            CodecInfo::from_name_with_defaults("opus")
        }

        fn direction(&self) -> Direction {
            Direction::Inbound
        }

        fn frames_in(&self) -> mpsc::Receiver<MediaFrame> {
            self.inbound
                .lock()
                .expect("broadcast test stream lock")
                .take()
                .unwrap_or_else(|| mpsc::channel(1).1)
        }

        fn try_frames_in(&self) -> RvoipResult<mpsc::Receiver<MediaFrame>> {
            self.inbound
                .lock()
                .expect("broadcast test stream lock")
                .take()
                .ok_or(RvoipError::InvalidState(
                    "broadcast test receiver already acquired",
                ))
        }

        fn frames_out(&self) -> mpsc::Sender<MediaFrame> {
            self.outbound.clone()
        }

        fn quality_snapshot(&self) -> QualitySnapshot {
            QualitySnapshot::default()
        }

        async fn close(self: Arc<Self>) -> RvoipResult<()> {
            Ok(())
        }
    }

    struct BroadcastTestAdapter {
        streams: DashMap<ConnectionId, Vec<Arc<dyn MediaStream>>>,
        events: StdMutex<Option<mpsc::Receiver<AdapterEvent>>>,
    }

    impl BroadcastTestAdapter {
        fn new() -> (Arc<Self>, mpsc::Sender<AdapterEvent>) {
            let (events, receiver) = mpsc::channel(32);
            (
                Arc::new(Self {
                    streams: DashMap::new(),
                    events: StdMutex::new(Some(receiver)),
                }),
                events,
            )
        }

        fn add_source(&self, connection_id: ConnectionId, stream: Arc<dyn MediaStream>) {
            self.streams.insert(connection_id, vec![stream]);
        }
    }

    #[async_trait]
    impl ConnectionAdapter for BroadcastTestAdapter {
        fn transport(&self) -> Transport {
            Transport::Sip
        }

        fn kind(&self) -> AdapterKind {
            AdapterKind::Substrate
        }

        async fn originate(&self, _: OriginateRequest) -> RvoipResult<ConnectionHandle> {
            Err(RvoipError::NotImplemented("broadcast test originate"))
        }

        async fn accept(&self, _: ConnectionId) -> RvoipResult<()> {
            Ok(())
        }

        async fn reject(&self, _: ConnectionId, _: RejectReason) -> RvoipResult<()> {
            Ok(())
        }

        async fn end(&self, _: ConnectionId, _: EndReason) -> RvoipResult<()> {
            Ok(())
        }

        async fn hold(&self, _: ConnectionId) -> RvoipResult<()> {
            Ok(())
        }

        async fn resume(&self, _: ConnectionId) -> RvoipResult<()> {
            Ok(())
        }

        async fn transfer(&self, _: ConnectionId, _: RvoipTransferTarget) -> RvoipResult<()> {
            Ok(())
        }

        async fn streams(
            &self,
            connection_id: ConnectionId,
        ) -> RvoipResult<Vec<Arc<dyn MediaStream>>> {
            Ok(self
                .streams
                .get(&connection_id)
                .map(|streams| streams.value().clone())
                .unwrap_or_default())
        }

        async fn send_message(&self, _: ConnectionId, _: Message) -> RvoipResult<()> {
            Ok(())
        }

        async fn send_dtmf(&self, _: ConnectionId, _: &str, _: u32) -> RvoipResult<()> {
            Ok(())
        }

        async fn renegotiate_media(
            &self,
            _: ConnectionId,
            _: CapabilityDescriptor,
        ) -> RvoipResult<NegotiatedCodecs> {
            Ok(NegotiatedCodecs::default())
        }

        fn subscribe_events(&self) -> mpsc::Receiver<AdapterEvent> {
            self.events
                .lock()
                .expect("broadcast test adapter event lock")
                .take()
                .expect("broadcast test adapter subscribed once")
        }

        fn capabilities(&self) -> CapabilityDescriptor {
            CapabilityDescriptor::default()
        }

        async fn verify_request_signature(
            &self,
            _: ConnectionId,
            _: SignatureHeaders,
        ) -> RvoipResult<IdentityAssurance> {
            Ok(IdentityAssurance::Anonymous)
        }
    }

    struct VerifiedTestProvider {
        verifications: Arc<AtomicUsize>,
    }

    impl VerifiedTestProvider {
        fn new(verifications: Arc<AtomicUsize>) -> Self {
            Self { verifications }
        }
    }

    #[async_trait]
    impl ProviderControl for VerifiedTestProvider {
        fn name(&self) -> &'static str {
            "telnyx"
        }

        fn kind(&self) -> bridgefu::call_service::ProviderKind {
            bridgefu::call_service::ProviderKind::Telnyx
        }

        fn account_key(&self) -> ProviderAccountKey {
            ProviderAccountKey::parse("test-profile").unwrap()
        }

        fn capabilities(&self) -> ProviderCapabilities {
            ProviderCapabilities::default()
        }

        async fn originate(
            &self,
            _command: OriginateCommand,
        ) -> Result<ProviderCall, ProviderError> {
            Err(ProviderError::Unsupported)
        }

        async fn bridge(&self, _command: BridgeCommand) -> Result<(), ProviderError> {
            Err(ProviderError::Unsupported)
        }

        async fn transfer(&self, _command: TransferCommand) -> Result<(), ProviderError> {
            Err(ProviderError::Unsupported)
        }

        async fn hangup(&self, _command: HangupCommand) -> Result<(), ProviderError> {
            Err(ProviderError::Unsupported)
        }

        async fn send_dtmf(&self, _command: DtmfCommand) -> Result<(), ProviderError> {
            Err(ProviderError::Unsupported)
        }

        fn verify_webhook(
            &self,
            request: &WebhookRequest,
        ) -> Result<NormalizedProviderEvent, ProviderError> {
            self.verifications.fetch_add(1, Ordering::SeqCst);
            if !request.headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("x-test-signature") && value == "valid"
            }) {
                return Err(ProviderError::InvalidSignature);
            }
            serde_json::from_slice(&request.body).map_err(ProviderError::Json)
        }
    }

    struct UnavailableProviderEventPersistence;

    #[async_trait]
    impl ProviderEventPersistence for UnavailableProviderEventPersistence {
        async fn ingest_provider_event(
            &self,
            _request: ProviderEventInput,
        ) -> Result<ProviderEventOutcome, RepositoryError> {
            Err(RepositoryError::Unavailable)
        }
    }

    #[async_trait]
    impl ConnectContactStarter for UnusedStarter {
        async fn start_webrtc_contact(
            &self,
            _request: StartContactRequest,
        ) -> rvoip_amazon_connect::Result<ConnectionData> {
            Err(ConnectError::Control(
                "diagnostics test never starts a contact".into(),
            ))
        }
    }

    fn available_udp_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("reserve diagnostics test port")
            .local_addr()
            .expect("reserved diagnostics test address")
            .port()
    }

    async fn diagnostics_test_state() -> ApiState {
        test_state(false, 100, true).await
    }

    fn test_rate_limit_config() -> crate::config::ApiRateLimitCfg {
        crate::config::ApiRateLimitCfg {
            enabled: true,
            control_requests_per_second: 1,
            control_burst: 1,
            diagnostics_requests_per_second: 1,
            diagnostics_burst: 1,
            webhook_requests_per_second: 1,
            webhook_burst: 1,
            max_tracked_identities: 16,
            identity_idle_ttl_secs: 60,
        }
    }

    async fn call_api_test_state(max_calls: usize) -> ApiState {
        test_state(true, max_calls, true).await
    }

    async fn unactivated_call_api_test_state(max_calls: usize) -> ApiState {
        test_state_with_attachment_principals(true, max_calls, true, None, false).await
    }

    fn test_worker_capabilities() -> BTreeSet<String> {
        [
            "sip",
            "webrtc",
            "sip_egress",
            "webrtc_egress",
            "amazon_connect",
            "telnyx",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    async fn activate_test_worker(state: &ApiState) {
        state
            .call_runtime()
            .expect("test call runtime exists")
            .activate_worker_capabilities(test_worker_capabilities())
            .await
            .expect("test worker capabilities activate");
    }

    fn named_route_vapi_principal() -> AuthenticatedPrincipal {
        AuthenticatedPrincipal {
            subject: "vapi-edge".into(),
            tenant: Some("tenant-a".into()),
            scopes: vec!["calls:create".into()],
            issuer: Some("vapi-managed".into()),
            expires_at: None,
            method: AuthenticationMethod::ApiKey,
            assurance: IdentityAssurance::Pseudonymous {
                ephemeral_key: Jwk(json!({
                    "kty": "bridgefu-profile",
                    "profile_id": "vapi-public",
                })),
            },
        }
    }

    async fn named_route_test_state() -> ApiState {
        let yaml = format!(
            r#"
aws:
  region: us-west-2
sip:
  bind_ip: 127.0.0.1
  port: {}
  advertised_ip: 127.0.0.1
  media_public_ip: 127.0.0.1
tenants:
  tenant-a:
    instance_id: instance-a
    contact_flow_id: flow-a
  tenant-b:
    instance_id: instance-b
    contact_flow_id: flow-b
vapi_ingress_profiles:
  vapi-public:
    tenant_id: tenant-a
    principal_subject: vapi-edge
    issuer: vapi-managed
    scopes: [calls:create]
    trusted_signaling_cidrs: [192.0.2.0/24]
    tls:
      certificate_chain: /run/bridgefu/tls/sip.pem
      private_key: /run/bridgefu/tls/sip-key.pem
    srtp_required: true
    codecs: [pcmu, opus]
sip_profiles:
  support-sbc:
    allowed_targets: ["sips:private-agent@callcenter.example.test:5061;transport=tls"]
    from_uri: "sips:bridgefu@bridge.example.test"
    srtp: required
    codecs: [pcmu, opus]
    metadata_keys: [customer_name]
webrtc_profiles:
  browser-public:
    allowed_signaling_origins: ["wss://bridge.example.test"]
    codecs: [opus]
    data_channels: true
api:
  enabled: true
  bearer_token: diagnostics-secret
  control_hmac_key: "0123456789abcdef0123456789abcdef"
  static_tenant: tenant-a
  rate_limit:
    enabled: false
  route_attachments:
    sip_uri_template: "sips:{{token}}@bridge.example.test:5061;transport=tls"
    webrtc:
      signaling_uri: "wss://bridge.example.test/signal"
      ice_servers:
        - urls: ["turn:turn.example.test:3478?transport=udp"]
          username: private-turn-user
          credential: turn-private-credential
  routes:
    sip-support:
      tenant_id: tenant-a
      ingress: [sip, webrtc]
      vapi_ingress_profile: vapi-public
      webrtc_ingress_profile: browser-public
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
            uri: "sips:private-agent@callcenter.example.test:5061;transport=tls"
            initial_context: required
    foreign-support:
      tenant_id: tenant-b
      ingress: [sip]
      legacy_embedded_destination: true
      destination:
        direction: outbound
        signaling_initiator: bridgefu
        media_flow: send_receive
        endpoint:
          type: sip
          config:
            uri: "sips:foreign-agent@callcenter.example.test:5061;transport=tls"
generic_bridge:
  enabled: true
  sip_bind: 127.0.0.1:{}
  webrtc_ws_bind: 127.0.0.1:0
  webrtc_whip_bind: 127.0.0.1:0
  sip:
    allow_cleartext_bearer: true
    secure_listener:
      bind: 127.0.0.1:5061
      certificate_chain: /run/bridgefu/tls/sip.pem
      private_key: /run/bridgefu/tls/sip-key.pem
    srtp: required
context:
  allow_headers:
    X-Customer-Name: customer_name
runtime:
  max_concurrent_calls: 8
broadcast:
  token_secret: "0123456789abcdef0123456789abcdef"
persistence:
  backend: memory
  allow_ephemeral_memory: true
"#,
            available_udp_port(),
            available_udp_port(),
        );
        let config: Config = serde_yaml::from_str(&yaml).expect("named-route config parses");
        config.validate().expect("named-route config is valid");
        let server_config = config
            .build_server_config_with_starter(Arc::new(UnusedStarter))
            .await
            .expect("named-route server config builds");
        let server = ConnectScreenPopServer::build(server_config)
            .await
            .expect("named-route SIP server builds");
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let mut state = ApiState::from_config(
            &config,
            server,
            recorder.handle(),
            config.tenant_names().unwrap(),
            None,
        )
        .await
        .expect("named-route API state builds");
        activate_test_worker(&state).await;
        // This transport-free API fixture does not bind real signaling
        // sockets. Install only the capabilities exercised by its route
        // serialization/idempotency tests; production obtains these solely
        // from `set_generic_runtime` after adapter registration succeeds.
        state.set_local_execution_capabilities_for_test([
            "sip",
            "webrtc",
            "sip_egress",
            "webrtc_egress",
            "amazon_connect",
        ]);
        state
    }

    async fn provider_call_api_test_state(max_calls: usize) -> ApiState {
        let principal = AuthenticatedPrincipal {
            subject: "telnyx-media".into(),
            tenant: Some("default".into()),
            scopes: Vec::new(),
            issuer: Some("sip-digest:bridgefu".into()),
            expires_at: None,
            method: AuthenticationMethod::SipDigest,
            assurance: IdentityAssurance::Identified {
                credential_kind: CredentialKind::SipDigest,
            },
        };
        let resolver = ConfiguredAttachmentPrincipalResolver::new()
            .with_provider(ProviderKind::Telnyx, "test-profile", principal.clone())
            .with_provider(ProviderKind::Telnyx, "other-profile", principal);
        test_state_with_attachment_principals(true, max_calls, true, Some(Arc::new(resolver)), true)
            .await
    }

    async fn no_auth_test_state() -> ApiState {
        test_state(false, 100, false).await
    }

    #[tokio::test]
    async fn persistence_is_opened_only_for_enabled_complete_transactional_auth() {
        for (api, should_open) in [
            (
                "  enabled: true\n  control_hmac_key: \"0123456789abcdef0123456789abcdef\"",
                false,
            ),
            (
                "  enabled: false\n  bearer_token: diagnostics-secret\n  control_hmac_key: \"0123456789abcdef0123456789abcdef\"",
                false,
            ),
            (
                "  enabled: true\n  bearer_token: diagnostics-secret\n  control_hmac_key: \"0123456789abcdef0123456789abcdef\"",
                true,
            ),
        ] {
            let unavailable_root = std::env::temp_dir()
                .join(format!("bridgefu-no-api-db-{}", Uuid::new_v4()));
            let private_url = format!(
                "sqlite://{}/missing/bridgefu.sqlite",
                unavailable_root.display()
            );
            let yaml = format!(
                r#"
aws:
  region: us-west-2
  instance_id: instance-test
  contact_flow_id: flow-test
sip:
  bind_ip: 127.0.0.1
  port: {}
  advertised_ip: 127.0.0.1
  media_public_ip: 127.0.0.1
api:
{api}
persistence:
  backend: sqlite
  database_url: "{private_url}"
broadcast:
  token_secret: "0123456789abcdef0123456789abcdef"
"#,
                available_udp_port()
            );
            let config: Config = serde_yaml::from_str(&yaml).unwrap();
            config.validate().unwrap();
            let server_config = config
                .build_server_config_with_starter(Arc::new(UnusedStarter))
                .await
                .unwrap();
            let server = ConnectScreenPopServer::build(server_config).await.unwrap();
            let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
            let result = ApiState::from_config(
                &config,
                server,
                recorder.handle(),
                config.tenant_names().unwrap(),
                None,
            )
            .await;
            if should_open {
                let error = result.err().expect("requested SQLite startup fails closed");
                assert_eq!(
                    error.to_string(),
                    "transactional call repository unavailable"
                );
                assert!(!error.to_string().contains(&private_url));
            } else {
                assert!(result.unwrap().call_runtime.is_none());
            }
            assert!(!unavailable_root.exists());
        }
    }

    async fn test_state(call_control: bool, max_calls: usize, bearer_enabled: bool) -> ApiState {
        test_state_with_attachment_principals(
            call_control,
            max_calls,
            bearer_enabled,
            None,
            call_control,
        )
        .await
    }

    async fn test_state_with_attachment_principals(
        call_control: bool,
        max_calls: usize,
        bearer_enabled: bool,
        attachment_principals: Option<Arc<dyn AttachmentPrincipalResolver>>,
        activate_worker: bool,
    ) -> ApiState {
        let control = if call_control {
            "  control_hmac_key: \"0123456789abcdef0123456789abcdef\"\n"
        } else {
            ""
        };
        let bearer = if bearer_enabled {
            "  bearer_token: diagnostics-secret\n"
        } else {
            ""
        };
        let yaml = format!(
            r#"
aws:
  region: us-west-2
  instance_id: instance-test
  contact_flow_id: flow-test
sip:
  bind_ip: 127.0.0.1
  port: {}
  advertised_ip: 127.0.0.1
  media_public_ip: 127.0.0.1
api:
  enabled: true
{bearer}{control}  rate_limit:
    enabled: false
runtime:
  max_concurrent_calls: {max_calls}
broadcast:
  token_secret: "0123456789abcdef0123456789abcdef"
persistence:
  backend: memory
  allow_ephemeral_memory: true
"#,
            available_udp_port()
        );
        let config: Config = serde_yaml::from_str(&yaml).expect("diagnostics config parses");
        config.validate().expect("diagnostics config is valid");
        let server_config = config
            .build_server_config_with_starter(Arc::new(UnusedStarter))
            .await
            .expect("diagnostics server config builds");
        let server = ConnectScreenPopServer::build(server_config)
            .await
            .expect("diagnostics SIP server builds");
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let tenants = config.tenant_names().unwrap();
        let state = match attachment_principals {
            Some(attachment_principals) => {
                ApiState::from_config_with_attachment_principals(
                    &config,
                    server,
                    recorder.handle(),
                    tenants,
                    None,
                    attachment_principals,
                )
                .await
            }
            None => ApiState::from_config(&config, server, recorder.handle(), tenants, None).await,
        }
        .expect("diagnostics API state builds");
        if activate_worker {
            activate_test_worker(&state).await;
        }
        state
    }

    async fn sqlite_test_state(database_url: &str) -> ApiState {
        let yaml = format!(
            r#"
aws:
  region: us-west-2
  instance_id: instance-test
  contact_flow_id: flow-test
sip:
  bind_ip: 127.0.0.1
  port: {}
  advertised_ip: 127.0.0.1
  media_public_ip: 127.0.0.1
api:
  enabled: true
  bearer_token: diagnostics-secret
  control_hmac_key: "0123456789abcdef0123456789abcdef"
runtime:
  max_concurrent_calls: 8
broadcast:
  token_secret: "0123456789abcdef0123456789abcdef"
persistence:
  backend: sqlite
  database_url: "{database_url}"
  deployment_id: provider-webhook-restart-test
"#,
            available_udp_port()
        );
        let config: Config = serde_yaml::from_str(&yaml).expect("SQLite API config parses");
        config.validate().expect("SQLite API config is valid");
        let server_config = config
            .build_server_config_with_starter(Arc::new(UnusedStarter))
            .await
            .expect("SQLite API server config builds");
        let server = ConnectScreenPopServer::build(server_config)
            .await
            .expect("SQLite API SIP server builds");
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        ApiState::from_config(
            &config,
            server,
            recorder.handle(),
            config.tenant_names().unwrap(),
            None,
        )
        .await
        .expect("SQLite API state builds")
    }

    fn install_verified_test_provider(state: &ApiState, verifications: Arc<AtomicUsize>) {
        state
            .providers
            .insert(Arc::new(VerifiedTestProvider::new(verifications)))
            .unwrap();
    }

    fn verified_event(event_id: &str, provider_call_id: Option<&str>) -> NormalizedProviderEvent {
        NormalizedProviderEvent {
            provider: "telnyx".into(),
            event_id: event_id.into(),
            provider_call_id: provider_call_id.map(str::to_owned),
            event_type: "call.answered".into(),
            occurred_at: Some("2026-07-12T12:34:56.789Z".into()),
            raw: json!({
                "data": {
                    "call_control_id": provider_call_id,
                    "event": "answered"
                }
            }),
        }
    }

    async fn post_verified_webhook(app: &Router, event: &NormalizedProviderEvent) -> Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/providers/telnyx/webhooks")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .header("x-test-signature", "valid")
                    .body(Body::from(serde_json::to_vec(event).unwrap()))
                    .unwrap(),
            )
            .await
            .expect("verified webhook request completes")
    }

    async fn reconcile_provider_start(
        runtime: &CallServiceRuntime,
        call_id: CallId,
        provider_leg: LegId,
        account_profile: &str,
        provider_call_id: &str,
    ) -> Result<EffectResultOutcome, RepositoryError> {
        let worker = runtime.worker().lease;
        let at = Utc::now() + chrono::Duration::milliseconds(1);
        let claimed = runtime
            .repository()
            .claim_outbox(worker, at, Duration::from_secs(10), 1)
            .await?
            .into_iter()
            .next()
            .ok_or(RepositoryError::NotFound)?;
        let (leg_id, binding_generation) = match claimed.record.intent {
            EffectIntent::StartLeg {
                leg_id,
                binding_generation,
                ..
            } => (leg_id, binding_generation),
            _ => {
                return Err(RepositoryError::InvalidInput(
                    "expected provider start effect",
                ))
            }
        };
        if leg_id != provider_leg {
            return Err(RepositoryError::InvalidInput(
                "provider start effect targeted the wrong leg",
            ));
        }
        let tenant = TenantId::parse("default").expect("test tenant is valid");
        let stored = runtime
            .service_repository()
            .load_service_call(&tenant, call_id)
            .await?;
        runtime
            .service_repository()
            .reconcile_effect_result(EffectResultReconciliation {
                tenant_id: tenant.clone(),
                call_id,
                effect_id: claimed.record.effect_id,
                worker,
                claim_generation: claimed.claim_generation,
                result: ServiceEffectResult::Succeeded,
                external_reference: Some(ExternalReferenceBinding {
                    leg_id,
                    binding_generation,
                    role: ProviderReferenceRole::Media,
                    value: ExternalReferenceValue::ProviderCall {
                        account: ProviderAccountKey::parse(account_profile)?,
                        provider_call_id: ProviderCallId::parse(provider_call_id)?,
                    },
                }),
                additional_external_references: Vec::new(),
                follow_up: Some(ServiceCommandTransaction {
                    command: CommandCommit {
                        tenant_id: tenant,
                        call_id,
                        expected_version: stored.call.aggregate.version(),
                        command_id: CommandId::new(),
                        command: CallCommand::SetLegState {
                            at,
                            leg_id,
                            binding_generation,
                            state: LegState::Signaling,
                            failure: None,
                        },
                        worker,
                        attachments: Vec::new(),
                        deadline_claim: None,
                        at,
                    },
                    effect_payloads: Vec::new(),
                    operation_idempotency: None,
                    bound_connection: None,
                    media_activity: None,
                    replacement_connection: None,
                }),
                at,
            })
            .await
    }

    async fn legacy_multi_tenant_state() -> ApiState {
        multi_tenant_state(None).await
    }

    async fn scoped_multi_tenant_state() -> ApiState {
        multi_tenant_state(Some("tenant-a")).await
    }

    async fn multi_tenant_state(static_tenant: Option<&str>) -> ApiState {
        let static_tenant = static_tenant
            .map(|tenant| format!("  static_tenant: {tenant}\n"))
            .unwrap_or_default();
        let yaml = format!(
            r#"
aws:
  region: us-west-2
sip:
  bind_ip: 127.0.0.1
  port: {}
  advertised_ip: 127.0.0.1
  media_public_ip: 127.0.0.1
tenants:
  tenant-a:
    instance_id: instance-a
    contact_flow_id: flow-a
  tenant-b:
    instance_id: instance-b
    contact_flow_id: flow-b
api:
  enabled: true
  bearer_token: diagnostics-secret
  control_hmac_key: "0123456789abcdef0123456789abcdef"
{static_tenant}runtime:
  max_concurrent_calls: 8
broadcast:
  token_secret: "0123456789abcdef0123456789abcdef"
persistence:
  backend: memory
  allow_ephemeral_memory: true
"#,
            available_udp_port()
        );
        let config: Config = serde_yaml::from_str(&yaml).unwrap();
        config.validate().unwrap();
        let server_config = config
            .build_server_config_with_starter(Arc::new(UnusedStarter))
            .await
            .unwrap();
        let server = ConnectScreenPopServer::build(server_config).await.unwrap();
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let state = ApiState::from_config(
            &config,
            server,
            recorder.handle(),
            config.tenant_names().unwrap(),
            None,
        )
        .await
        .unwrap();
        // A multi-tenant legacy bearer without `api.static_tenant` exposes
        // only the legacy diagnostics surfaces and intentionally has no
        // transactional call runtime to activate.
        if state.call_runtime().is_some() {
            activate_test_worker(&state).await;
        }
        state
    }

    async fn get(app: &Router, uri: &str, bearer: Option<&str>) -> Response {
        let mut request = Request::builder().uri(uri);
        if let Some(token) = bearer {
            request = request.header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        app.clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .expect("diagnostics request completes")
    }

    async fn raw_get(
        app: &Router,
        uri: &str,
        authorization: &[axum::http::HeaderValue],
    ) -> Response {
        let mut request = Request::builder().uri(uri).body(Body::empty()).unwrap();
        for value in authorization {
            request
                .headers_mut()
                .append(axum::http::header::AUTHORIZATION, value.clone());
        }
        app.clone().oneshot(request).await.unwrap()
    }

    async fn response_json(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("diagnostics response body");
        serde_json::from_slice(&bytes).expect("diagnostics response JSON")
    }

    #[tokio::test]
    async fn unsupported_transfer_capability_maps_to_explicit_conflict() {
        let response = ApiError::from(CallServiceError::UnsupportedCapability).into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = response_json(response).await;
        assert_eq!(body["error"]["code"], "unsupported_capability");
    }

    async fn post_json(
        app: &Router,
        uri: &str,
        bearer: Option<&str>,
        idempotency_keys: &[&str],
        body: Value,
    ) -> Response {
        let mut request = Request::builder()
            .method("POST")
            .uri(uri)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        if let Some(token) = bearer {
            request.headers_mut().insert(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
            );
        }
        for key in idempotency_keys {
            request.headers_mut().append(
                "idempotency-key",
                axum::http::HeaderValue::from_str(key).unwrap(),
            );
        }
        app.clone()
            .oneshot(request)
            .await
            .expect("call API request completes")
    }

    async fn post_empty(app: &Router, uri: &str, bearer: &str, idempotency_key: &str) -> Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header(
                        axum::http::header::AUTHORIZATION,
                        format!("Bearer {bearer}"),
                    )
                    .header("idempotency-key", idempotency_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn delete(app: &Router, uri: &str, bearer: &str) -> Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(uri)
                    .header(
                        axum::http::header::AUTHORIZATION,
                        format!("Bearer {bearer}"),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    fn test_api_principal(tenant: &str) -> ApiPrincipal {
        ApiPrincipal::new(
            AuthenticatedPrincipal {
                subject: format!("api:{tenant}"),
                tenant: Some(tenant.to_owned()),
                scopes: vec!["*".into(), CallScope::ArbitraryDestination.as_str().into()],
                issuer: Some("bridgefu-api-test".into()),
                expires_at: None,
                method: AuthenticationMethod::Bearer,
                assurance: IdentityAssurance::UserAuthorized {
                    identity: rvoip_core::ids::IdentityId::from_string(format!("api:{tenant}")),
                    user_id: rvoip_core::ids::IdentityId::from_string(format!("api:{tenant}")),
                    scopes: vec!["*".into(), CallScope::ArbitraryDestination.as_str().into()],
                },
            },
            Utc::now(),
        )
        .unwrap()
    }

    #[test]
    fn tenant_scoped_non_call_handlers_require_read_scope() {
        let principal = ApiPrincipal::new(
            AuthenticatedPrincipal {
                subject: "api:no-read".into(),
                tenant: Some("default".into()),
                scopes: vec!["calls:create".into()],
                issuer: Some("bridgefu-api-test".into()),
                expires_at: None,
                method: AuthenticationMethod::Bearer,
                assurance: IdentityAssurance::UserAuthorized {
                    identity: rvoip_core::ids::IdentityId::from_string("api:no-read"),
                    user_id: rvoip_core::ids::IdentityId::from_string("api:no-read"),
                    scopes: vec!["calls:create".into()],
                },
            },
            Utc::now(),
        )
        .unwrap();

        let error = require_api_principal_for(Some(Extension(principal)), CallScope::Read)
            .expect_err("calls:create must not authorize tenant-scoped read surfaces");
        assert_eq!(error.status, StatusCode::FORBIDDEN);
        assert_eq!(error.code, "forbidden");
    }

    async fn create_durable_test_call(
        state: &ApiState,
        principal: &ApiPrincipal,
        key: &str,
    ) -> bridgefu::call_service::CreateCallView {
        let input = serde_json::from_value(create_body()).unwrap();
        state
            .call_runtime()
            .expect("call runtime")
            .service()
            .create_call(
                principal,
                &bridgefu::call_service::IdempotencyKey::parse(key).unwrap(),
                input,
            )
            .await
            .unwrap()
            .value
    }

    async fn connect_durable_source_leg(
        state: &ApiState,
        principal: &ApiPrincipal,
        created: &mut bridgefu::call_service::CreateCallView,
        connection_id: ConnectionId,
    ) -> LegId {
        let runtime = state.call_runtime().expect("call runtime");
        let service = runtime.service();
        let (leg_id, token, transport) = {
            let leg = &mut created.call.legs[0];
            let attachment = leg.attachment.as_mut().expect("source attachment");
            (
                leg.leg_id,
                std::mem::take(&mut attachment.token),
                attachment.transport,
            )
        };
        let attached = service
            .consume_inbound_attachment(InboundAttachmentRequest::new(
                principal.authenticated().clone(),
                Some(token),
                transport,
                runtime.worker().lease,
                connection_id.clone(),
            ))
            .await
            .expect("source attachment is consumed");
        let tenant = principal.tenant().clone();
        let stored = runtime
            .service_repository()
            .load_service_call(&tenant, created.call.call_id)
            .await
            .unwrap();
        service
            .commit_bound_connection_state(bridgefu::call_service::BoundConnectionStateCommit {
                tenant_id: tenant,
                call_id: created.call.call_id,
                expected_version: stored.call.aggregate.version(),
                command_id: CommandId::new(),
                leg_id,
                binding_generation: attached.binding.binding_generation,
                connection_id,
                worker: runtime.worker().lease,
                state: LegState::Connected,
                failure: None,
                at: runtime.observation_time() + chrono::Duration::milliseconds(1),
            })
            .await
            .expect("source leg becomes connected");
        leg_id
    }

    fn broadcast_test_connection(connection_id: ConnectionId) -> Connection {
        Connection {
            id: connection_id,
            session_id: SessionId::new(),
            participant_id: ParticipantId::new(),
            transport: Transport::Sip,
            direction: Direction::Inbound,
            state: ConnectionState::Connecting,
            capabilities: CapabilityDescriptor::default(),
            negotiated_codecs: NegotiatedCodecs::default(),
            streams: Vec::new(),
            messaging_enabled: false,
            transport_handle: TransportHandle(Arc::new(())),
            opened_at: Utc::now(),
            closed_at: None,
        }
    }

    async fn install_broadcast_source(
        state: &mut ApiState,
        connection_id: ConnectionId,
        expose_source: bool,
    ) -> (
        Arc<Orchestrator>,
        Option<mpsc::Sender<MediaFrame>>,
        Option<mpsc::Sender<AdapterEvent>>,
    ) {
        let orchestrator = Orchestrator::new(RvoipConfig::default());
        if expose_source {
            let (adapter, events) = BroadcastTestAdapter::new();
            let (source, sender) = BroadcastTestStream::source();
            adapter.add_source(connection_id.clone(), source);
            orchestrator
                .register(adapter as Arc<dyn ConnectionAdapter>)
                .unwrap();
            events
                .send(AdapterEvent::InboundConnection {
                    connection: broadcast_test_connection(connection_id),
                })
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            state.set_broadcast_orchestrator_for_test(Arc::clone(&orchestrator));
            state.public_endpoint = "uctp+quic://127.0.0.1:4444".into();
            (orchestrator, Some(sender), Some(events))
        } else {
            state.set_broadcast_orchestrator_for_test(Arc::clone(&orchestrator));
            state.public_endpoint = "uctp+quic://127.0.0.1:4444".into();
            (orchestrator, None, None)
        }
    }

    fn create_body() -> Value {
        json!({
            "legs": [
                {
                    "direction": "inbound",
                    "endpoint": {"type": "sip", "config": {"uri": null}}
                },
                {
                    "direction": "outbound",
                    "endpoint": {
                        "type": "webrtc",
                        "config": {"signaling_uri": "wss://signal.example.test/private-session"}
                    }
                }
            ]
        })
    }

    fn provider_create_body(provider: &str, account_profile: &str) -> Value {
        json!({
            "legs": [
                {
                    "direction": "outbound",
                    "endpoint": {
                        "type": "provider",
                        "config": {
                            "provider": provider,
                            "account_profile": account_profile,
                            "destination": "+12065550100"
                        }
                    }
                },
                {
                    "direction": "inbound",
                    "endpoint": {"type": "sip", "config": {"uri": null}}
                }
            ]
        })
    }

    #[tokio::test]
    async fn screen_pop_diagnostics_require_auth_and_redact_correlation() {
        let state = diagnostics_test_state().await;
        let correlation_id = "+14155550199";
        let evidence = state.screen_pop_evidence_store();
        evidence
            .record_now(correlation_id, ScreenPopStage::SipInviteReceived, None)
            .unwrap();
        evidence
            .record_now(correlation_id, ScreenPopStage::AttributesMapped, None)
            .unwrap();
        let app = router(state);
        let path = "/v1/diagnostics/screen-pop/%2B14155550199";

        assert_eq!(
            get(&app, path, None).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            get(&app, path, Some("wrong-secret")).await.status(),
            StatusCode::UNAUTHORIZED
        );

        let missing = get(
            &app,
            "/v1/diagnostics/screen-pop/unknown-correlation",
            Some("diagnostics-secret"),
        )
        .await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let missing_body = serde_json::to_string(&response_json(missing).await).unwrap();
        assert!(!missing_body.contains("unknown-correlation"));

        let response = get(&app, path, Some("diagnostics-secret")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(!serialized.contains(correlation_id));
        assert_eq!(body.as_object().unwrap().len(), 2);
        assert_eq!(body["correlation_fingerprint"], "e8d461284346");
        assert_eq!(body["stages"]["sip_invite_received"]["observed"], true);
        assert_eq!(body["stages"]["attributes_mapped"]["observed"], true);
        assert!(body["stages"]["sip_invite_received"]["at"].is_string());
    }

    #[tokio::test]
    async fn durable_call_routes_require_auth_idempotency_and_replay_exactly() {
        let app = router(call_api_test_state(1).await);
        assert_eq!(
            post_json(&app, "/v1/calls", None, &["create-1"], create_body())
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let unauthorized = post_json(
            &app,
            "/v1/calls",
            Some("wrong-secret"),
            &["create-1"],
            create_body(),
        )
        .await;
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            unauthorized
                .headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .unwrap(),
            "Bearer"
        );
        assert_eq!(
            post_json(
                &app,
                "/v1/calls",
                Some("diagnostics-secret"),
                &[],
                create_body(),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            post_json(
                &app,
                "/v1/calls",
                Some("diagnostics-secret"),
                &["duplicate", "duplicate"],
                create_body(),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );

        let created = post_json(
            &app,
            "/v1/calls",
            Some("diagnostics-secret"),
            &["create-1"],
            create_body(),
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let created_body = response_json(created).await;
        let call_id = created_body["call_id"].as_str().unwrap().to_owned();
        let token = created_body["legs"][0]["attachment"]["token"]
            .as_str()
            .unwrap();
        assert_eq!(token.len(), 43);
        let serialized = serde_json::to_string(&created_body).unwrap();
        assert!(!serialized.contains("private-session"));
        assert!(!serialized.contains("signaling_uri"));

        let replayed = post_json(
            &app,
            "/v1/calls",
            Some("diagnostics-secret"),
            &["create-1"],
            create_body(),
        )
        .await;
        assert_eq!(replayed.status(), StatusCode::CREATED);
        assert_eq!(response_json(replayed).await, created_body);

        let loaded = get(
            &app,
            &format!("/v1/calls/{call_id}"),
            Some("diagnostics-secret"),
        )
        .await;
        assert_eq!(loaded.status(), StatusCode::OK);
        let loaded_body = response_json(loaded).await;
        assert!(loaded_body["legs"][0].get("attachment").is_none());

        let mut changed = create_body();
        changed["legs"][1]["endpoint"]["config"]["signaling_uri"] =
            Value::String("wss://signal.example.test/changed".into());
        assert_eq!(
            post_json(
                &app,
                "/v1/calls",
                Some("diagnostics-secret"),
                &["create-1"],
                changed,
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );

        let capacity = post_json(
            &app,
            "/v1/calls",
            Some("diagnostics-secret"),
            &["create-2"],
            create_body(),
        )
        .await;
        assert_eq!(capacity.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            capacity
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .unwrap(),
            "1"
        );
    }

    #[tokio::test]
    async fn raw_call_capabilities_activate_atomically_and_replay_after_drain() {
        let state = unactivated_call_api_test_state(1).await;
        let runtime = state.call_runtime().expect("local call runtime");
        let worker = runtime.worker().lease;
        let app = router(state);

        let unavailable = post_json(
            &app,
            "/v1/calls",
            Some("diagnostics-secret"),
            &["activation-gated-call"],
            create_body(),
        )
        .await;
        assert_eq!(unavailable.status(), StatusCode::CONFLICT);
        assert_eq!(
            runtime
                .repository()
                .worker_snapshot(worker.worker_id)
                .await
                .unwrap()
                .reserved_calls,
            0
        );

        runtime
            .activate_worker_capabilities(test_worker_capabilities())
            .await
            .unwrap();
        let created = post_json(
            &app,
            "/v1/calls",
            Some("diagnostics-secret"),
            &["activation-gated-call"],
            create_body(),
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let created_body = response_json(created).await;

        runtime
            .repository()
            .set_worker_draining(worker, true, Utc::now())
            .await
            .unwrap();
        let replayed = post_json(
            &app,
            "/v1/calls",
            Some("diagnostics-secret"),
            &["activation-gated-call"],
            create_body(),
        )
        .await;
        assert_eq!(replayed.status(), StatusCode::CREATED);
        assert_eq!(response_json(replayed).await, created_body);
    }

    #[tokio::test]
    async fn all_in_one_route_creation_rejects_configured_but_unregistered_egress() {
        let mut state = named_route_test_state().await;
        let runtime = state.call_runtime().expect("named-route call runtime");
        let worker_id = runtime.worker().lease.worker_id;
        // Retain the configured route and worker allowlist while simulating a
        // process where concrete signaling/provider construction did not
        // register any executable capability.
        state.local_execution_capabilities.clear();
        let app = router(state);

        let listed = get(&app, "/v1/routes", Some("diagnostics-secret")).await;
        assert_eq!(listed.status(), StatusCode::OK);
        assert!(response_json(listed).await["routes"]
            .as_array()
            .unwrap()
            .is_empty());
        let rejected = post_json(
            &app,
            "/v1/routes/sip-support/calls",
            Some("diagnostics-secret"),
            &["unregistered-local-egress"],
            json!({"ingress": "sip"}),
        )
        .await;
        assert_eq!(rejected.status(), StatusCode::CONFLICT);
        assert_eq!(
            response_json(rejected).await["error"]["code"],
            "unsupported_capability"
        );
        assert_eq!(
            runtime
                .repository()
                .worker_snapshot(worker_id)
                .await
                .unwrap()
                .reserved_calls,
            0
        );
    }

    #[tokio::test]
    async fn named_routes_are_tenant_scoped_redacted_and_create_complete_sip_attachments() {
        let state = named_route_test_state().await;
        let runtime = state.call_runtime().expect("named-route call runtime");
        let mut authorization = HeaderMap::new();
        authorization.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("Bearer diagnostics-secret"),
        );
        let _api_principal = state
            .bearer_authenticator
            .as_ref()
            .unwrap()
            .authenticate(&authorization, Utc::now())
            .await
            .unwrap();
        let configured_debug = format!("{:?}", state.named_routes);
        assert!(!configured_debug.contains("private-agent"));
        assert!(!configured_debug.contains("turn-private-credential"));
        let app = router(state.clone());

        assert_eq!(
            get(&app, "/v1/routes", None).await.status(),
            StatusCode::UNAUTHORIZED
        );
        let listed = get(&app, "/v1/routes", Some("diagnostics-secret")).await;
        assert_eq!(listed.status(), StatusCode::OK);
        let listed = response_json(listed).await;
        assert_eq!(listed["routes"].as_array().unwrap().len(), 1);
        assert_eq!(listed["routes"][0]["route_id"], "sip-support");
        assert_eq!(listed["routes"][0]["destination"], "sip");
        assert_eq!(
            listed["routes"][0]["capabilities"],
            json!({
                "full_duplex_audio": true,
                "audio_codecs": ["pcmu", "opus"],
                "dtmf": "bidirectional",
                "context": "sip_headers_and_message",
                "initial_context": true,
                "live_data_channel_context": false,
                "sip_message": true
            })
        );
        let listed_json = serde_json::to_string(&listed).unwrap();
        for private in [
            "foreign-support",
            "private-agent",
            "callcenter.example.test",
            "bridge.example.test",
            "private-turn-user",
            "turn-private-credential",
        ] {
            assert!(
                !listed_json.contains(private),
                "route list leaked {private}"
            );
        }

        for route in ["missing", "foreign-support"] {
            let key = format!("unknown-{route}");
            let response = post_json(
                &app,
                &format!("/v1/routes/{route}/calls"),
                Some("diagnostics-secret"),
                &[&key],
                json!({"ingress": "sip"}),
            )
            .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        let request = json!({
            "ingress": "sip",
            "context": {
                "correlation_id": "managed-widget-123",
                "metadata": {"customer_name": "Ada"}
            }
        });
        let created = post_json(
            &app,
            "/v1/routes/sip-support/calls",
            Some("diagnostics-secret"),
            &["route-create-1"],
            request.clone(),
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let created = response_json(created).await;
        assert_eq!(created["route_id"], "sip-support");
        assert_eq!(created["attachment"]["type"], "sip");
        assert!(created["legs"]
            .as_array()
            .unwrap()
            .iter()
            .all(|leg| leg.get("attachment").is_none()));
        let uri = created["attachment"]["uri"].as_str().unwrap();
        assert!(uri.starts_with("sips:"));
        assert!(uri.ends_with("@bridge.example.test:5061;transport=tls"));
        let token = uri
            .strip_prefix("sips:")
            .and_then(|value| value.split_once('@').map(|(token, _)| token))
            .unwrap()
            .to_owned();
        assert_eq!(token.len(), 43);
        let expires_at =
            DateTime::parse_from_rfc3339(created["attachment"]["expires_at"].as_str().unwrap())
                .unwrap()
                .with_timezone(&Utc);
        let ttl = expires_at.signed_duration_since(Utc::now()).num_seconds();
        assert!((100..=120).contains(&ttl));
        let serialized = serde_json::to_string(&created).unwrap();
        assert!(!serialized.contains("private-agent"));
        assert!(!serialized.contains("callcenter.example.test"));

        let replayed = post_json(
            &app,
            "/v1/routes/sip-support/calls",
            Some("diagnostics-secret"),
            &["route-create-1"],
            request.clone(),
        )
        .await;
        assert_eq!(replayed.status(), StatusCode::CREATED);
        assert_eq!(response_json(replayed).await, created);

        let changed_context = json!({
            "ingress": "sip",
            "context": {
                "correlation_id": "managed-widget-CHANGED",
                "metadata": {"customer_name": "Ada"}
            }
        });
        assert_eq!(
            post_json(
                &app,
                "/v1/routes/sip-support/calls",
                Some("diagnostics-secret"),
                &["route-create-1"],
                changed_context,
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            post_json(
                &app,
                "/v1/routes/sip-support/calls",
                Some("diagnostics-secret"),
                &["route-invalid-context"],
                json!({
                    "ingress": "sip",
                    "context": {
                        "correlation_id": "managed-widget-123",
                        "metadata": {"tenant_id": "tenant-b"}
                    }
                }),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let disallowed = post_json(
            &app,
            "/v1/routes/sip-support/calls",
            Some("diagnostics-secret"),
            &["route-disallowed-context"],
            json!({
                "ingress": "webrtc",
                "context": {
                    "correlation_id": "managed-widget-123",
                    "metadata": {"handoff_token": "not-enabled-for-this-profile"}
                }
            }),
        )
        .await;
        assert_eq!(disallowed.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(disallowed).await["error"]["code"],
            "context_metadata_not_allowed"
        );
        let missing_context = post_json(
            &app,
            "/v1/routes/sip-support/calls",
            Some("diagnostics-secret"),
            &["route-missing-context"],
            json!({"ingress": "webrtc"}),
        )
        .await;
        assert_eq!(missing_context.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(missing_context).await["error"]["code"],
            "context_required"
        );

        let call_id = created["call_id"]
            .as_str()
            .unwrap()
            .parse::<CallId>()
            .unwrap();
        let stored = runtime
            .service_repository()
            .load_service_call(&TenantId::parse("tenant-a").unwrap(), call_id)
            .await
            .unwrap();
        assert_eq!(
            stored.plan.setup_policy(),
            bridgefu::call_service::SetupPolicy::AttachThenDial
        );
        let route = stored.plan.named_route().expect("durable named route");
        assert_eq!(route.route_id(), "sip-support");
        assert_eq!(route.profiles().len(), 2);
        assert!(route.profiles().iter().any(|profile| {
            profile.role() == bridgefu::call_service::NamedProfileRole::Ingress
                && profile.kind() == bridgefu::call_service::NamedProfileKind::VapiIngress
                && profile.profile_id() == "vapi-public"
                && profile.revision().len() == 64
        }));
        assert!(route.profiles().iter().any(|profile| {
            profile.role() == bridgefu::call_service::NamedProfileRole::Destination
                && profile.kind() == bridgefu::call_service::NamedProfileKind::Sip
                && profile.profile_id() == "support-sbc"
                && profile.revision().len() == 64
        }));
        assert_eq!(
            route.context().unwrap().correlation_id,
            "managed-widget-123"
        );
        let persisted_plan = serde_json::to_string(&stored.plan).unwrap();
        assert!(persisted_plan.contains("vapi-public"));
        assert!(persisted_plan.contains("support-sbc"));
        assert!(!persisted_plan.contains("sip-key.pem"));
        assert!(!persisted_plan.contains("turn-private-credential"));

        let consume = |connection: &str| {
            InboundAttachmentRequest::new(
                named_route_vapi_principal(),
                Some(token.clone()),
                bridgefu::call_engine::AttachmentTransport::Sip,
                runtime.worker().lease,
                ConnectionId::from_string(connection),
            )
        };
        runtime
            .service()
            .consume_inbound_attachment(consume("route-sip-first"))
            .await
            .expect("first named-route attachment consumption succeeds");
        assert!(runtime
            .service()
            .consume_inbound_attachment(consume("route-sip-replay"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn named_route_webrtc_response_carries_session_hint_and_ice_without_endpoint_leaks() {
        let app = router(named_route_test_state().await);
        let response = post_json(
            &app,
            "/v1/routes/sip-support/calls",
            Some("diagnostics-secret"),
            &["route-webrtc-1"],
            json!({
                "ingress": "webrtc",
                "context": {
                    "correlation_id": "managed-widget-webrtc-1",
                    "metadata": {"customer_name": "Ada"}
                }
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response_json(response).await;
        let attachment = &body["attachment"];
        assert_eq!(attachment["type"], "webrtc");
        assert_eq!(
            attachment["signaling_uri"],
            "wss://bridge.example.test/signal"
        );
        let token = attachment["token"].as_str().unwrap();
        assert_eq!(token.len(), 43);
        assert_eq!(attachment["subprotocols"][0], "rvoip.webrtc.v1");
        let signaling_token = attachment["signaling_credential"]["token"]
            .as_str()
            .unwrap();
        assert_eq!(
            attachment["signaling_credential"]["usage"],
            bridgefu::signaling_token::SIGNALING_TOKEN_USAGE
        );
        assert!(signaling_token.starts_with(bridgefu::signaling_token::SIGNALING_TOKEN_PREFIX));
        assert_eq!(
            attachment["subprotocols"][1],
            format!("token.{signaling_token}")
        );
        assert_eq!(
            attachment["subprotocols"][2],
            format!("bridgefu.attach.{token}")
        );
        assert_eq!(
            attachment["ice_servers"][0]["username"],
            "private-turn-user"
        );
        assert_eq!(
            attachment["ice_servers"][0]["credential"],
            "turn-private-credential"
        );
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(!serialized.contains("private-agent"));
        assert!(!serialized.contains("callcenter.example.test"));
        assert!(body["legs"]
            .as_array()
            .unwrap()
            .iter()
            .all(|leg| leg.get("attachment").is_none()));
    }

    #[tokio::test]
    async fn call_routes_map_malformed_forbidden_and_invalid_transition_without_fallback() {
        let app = router(call_api_test_state(4).await);
        assert_eq!(
            post_json(
                &app,
                "/v1/calls",
                Some("diagnostics-secret"),
                &["bad-shape"],
                json!({"legs": []}),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let mut override_body = create_body();
        override_body["tenant_id"] = Value::String("other-tenant".into());
        assert_eq!(
            post_json(
                &app,
                "/v1/calls",
                Some("diagnostics-secret"),
                &["override"],
                override_body,
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let created = post_json(
            &app,
            "/v1/calls",
            Some("diagnostics-secret"),
            &["create-transition"],
            create_body(),
        )
        .await;
        let created = response_json(created).await;
        let call_id = created["call_id"].as_str().unwrap().to_owned();
        let target_leg_id = created["legs"][0]["leg_id"].as_str().unwrap();
        assert_eq!(
            post_json(
                &app,
                &format!("/v1/calls/{call_id}/transfer"),
                Some("diagnostics-secret"),
                &["transfer-invalid"],
                json!({"target_leg_id": target_leg_id, "target": {"type": "sip", "uri": "sip:queue@sip.example.test"}}),
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            post_json(
                &app,
                &format!("/v1/calls/{call_id}/hangup"),
                Some("diagnostics-secret"),
                &[],
                json!({}),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            post_empty(
                &app,
                &format!("/v1/calls/{call_id}/hangup"),
                "diagnostics-secret",
                "hangup-empty",
            )
            .await
            .status(),
            StatusCode::ACCEPTED
        );

        let unconfigured = router(diagnostics_test_state().await);
        let unavailable = post_json(
            &unconfigured,
            "/v1/calls/00000000-0000-4000-8000-000000000001/hangup",
            Some("diagnostics-secret"),
            &["no-fallback"],
            json!({}),
        )
        .await;
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);

        let oversized = post_json(
            &app,
            "/v1/calls",
            Some("diagnostics-secret"),
            &["oversized"],
            json!({"legs": [], "padding": "x".repeat(70_000)}),
        )
        .await;
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn protected_routes_fail_closed_without_auth_configuration() {
        let app = router(no_auth_test_state().await);
        for path in [
            "/diagnostics",
            "/v1/diagnostics/screen-pop/missing",
            "/v1/providers/twilio/capabilities",
            "/v1/broadcasts/00000000-0000-4000-8000-000000000001",
            "/v1/calls/00000000-0000-4000-8000-000000000001",
        ] {
            assert_eq!(
                get(&app, path, None).await.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "protected route was reachable: {path}"
            );
        }
        let id = "00000000-0000-4000-8000-000000000001";
        for (path, body) in [
            ("/v1/calls".to_owned(), create_body()),
            (format!("/v1/calls/{id}/hangup"), json!({})),
            (
                format!("/v1/calls/{id}/transfer"),
                json!({"target_leg_id": id, "target": {"type": "sip", "uri": "sip:test@example.test"}}),
            ),
            (
                format!("/v1/calls/{id}/dtmf"),
                json!({"leg_id": id, "digits": "1"}),
            ),
            (
                format!("/v1/calls/{id}/broadcasts"),
                json!({"source_leg_id": "sip"}),
            ),
            (format!("/v1/broadcasts/{id}/tokens"), json!({})),
        ] {
            assert_eq!(
                post_json(&app, &path, None, &[], body).await.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "protected route was reachable: {path}"
            );
        }
        let deleted = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/broadcasts/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(deleted.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(get(&app, "/healthz", None).await.status(), StatusCode::OK);
        assert_eq!(get(&app, "/metrics", None).await.status(), StatusCode::OK);
        let webhook = post_json(
            &app,
            "/v1/providers/not-configured/webhooks",
            None,
            &[],
            json!({}),
        )
        .await;
        assert_eq!(webhook.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn readiness_follows_dependency_drain_while_liveness_stays_up() {
        let state = no_auth_test_state().await;
        let server = Arc::clone(state.server.as_ref().expect("test legacy server"));
        let app = router(state);
        assert_eq!(get(&app, "/readyz", None).await.status(), StatusCode::OK);
        assert_eq!(get(&app, "/livez", None).await.status(), StatusCode::OK);

        server.begin_drain();
        assert_eq!(
            get(&app, "/readyz", None).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            get(&app, "/healthz", None).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(get(&app, "/livez", None).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn unauthenticated_health_responses_never_disclose_tenant_identifiers() {
        let app = router(legacy_multi_tenant_state().await);
        for path in ["/healthz", "/livez", "/readyz"] {
            let response = get(&app, path, None).await;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let body = response_json(response).await;
            assert_eq!(body["tenant_count"], 2, "{path}");
            assert!(body.get("tenants").is_none(), "{path}: {body}");
            let encoded = serde_json::to_string(&body).unwrap();
            assert!(!encoded.contains("tenant-a"), "{path}: {encoded}");
            assert!(!encoded.contains("tenant-b"), "{path}: {encoded}");
        }
    }

    #[tokio::test]
    async fn split_public_router_never_mounts_health_or_metrics() {
        let app = public_router(no_auth_test_state().await);
        for path in ["/healthz", "/livez", "/readyz", "/metrics"] {
            assert_eq!(
                get(&app, path, None).await.status(),
                StatusCode::NOT_FOUND,
                "operational route leaked onto public API: {path}"
            );
        }
        assert_eq!(
            post_json(
                &app,
                "/v1/providers/not-configured/webhooks",
                None,
                &[],
                json!({}),
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn api_rate_policy_returns_429_with_retry_after_per_surface() {
        let mut state = diagnostics_test_state().await;
        state.api_rate_limiter = ApiRateLimiter::from_config(&test_rate_limit_config());
        let verifications = Arc::new(AtomicUsize::new(0));
        install_verified_test_provider(&state, Arc::clone(&verifications));
        let app = router(state);

        assert_eq!(
            get(&app, "/diagnostics", Some("diagnostics-secret"))
                .await
                .status(),
            StatusCode::OK
        );
        let diagnostics_limited = get(&app, "/diagnostics", Some("diagnostics-secret")).await;
        assert_eq!(diagnostics_limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            diagnostics_limited
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .unwrap(),
            "1"
        );
        assert_eq!(
            response_json(diagnostics_limited).await["error"]["code"],
            "rate_limited"
        );

        // The principal's control budget is separate from diagnostics.
        assert_eq!(
            get(
                &app,
                "/v1/providers/not-configured/capabilities",
                Some("diagnostics-secret"),
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get(
                &app,
                "/v1/providers/not-configured/capabilities",
                Some("diagnostics-secret"),
            )
            .await
            .status(),
            StatusCode::TOO_MANY_REQUESTS
        );

        let event = verified_event("rate-limit", Some("call-rate-limit"));
        let first = post_verified_webhook(&app, &event).await;
        assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(verifications.load(Ordering::SeqCst), 1);
        let webhook_limited = post_verified_webhook(&app, &event).await;
        assert_eq!(webhook_limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            webhook_limited
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .unwrap(),
            "1"
        );
        assert_eq!(verifications.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn authenticated_diagnostics_match_the_documented_release_inventory() {
        let app = router(diagnostics_test_state().await);
        let response = get(&app, "/diagnostics", Some("diagnostics-secret")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        let keys = body
            .as_object()
            .expect("diagnostics response object")
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            keys,
            std::collections::BTreeSet::from([
                "active_amazon_calls",
                "api_rate_limit",
                "broadcasts",
                "call_execution",
                "call_repository",
                "context_headers",
                "generic_bridge",
                "moqt_target_draft",
                "providers",
                "tenant_id",
                "transactional_call_api",
                "version",
            ])
        );
        let rendered = body.to_string();
        assert_eq!(body["api_rate_limit"]["enabled"], false);
        assert_eq!(body["api_rate_limit"]["tracked_identities"], 0);
        assert_eq!(body["api_rate_limit"]["max_tracked_identities"], 10_000);
        for private in [
            "diagnostics-secret",
            "authorization",
            "control_hmac_key",
            "token_secret",
            "context_values",
            "media_bytes",
        ] {
            assert!(!rendered.contains(private), "diagnostics leaked {private}");
        }
        let docs = include_str!("../docs/observability.md");
        for documented in [
            "binary version",
            "authenticated tenant",
            "call-control",
            "repository kind",
            "execution placement",
            "configured provider",
            "target MOQT draft",
            "context-header names",
            "listener addresses",
        ] {
            assert!(
                docs.contains(documented),
                "diagnostic inventory description is missing {documented}"
            );
        }
    }

    #[tokio::test]
    async fn webhook_body_limit_precedes_signature_and_persistence_work() {
        let state = diagnostics_test_state().await;
        let verifications = Arc::new(AtomicUsize::new(0));
        install_verified_test_provider(&state, Arc::clone(&verifications));
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/providers/telnyx/webhooks")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .header("x-test-signature", "valid")
                    .body(Body::from(vec![b'x'; 256 * 1024 + 1]))
                    .unwrap(),
            )
            .await
            .expect("oversized webhook request completes");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(verifications.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn request_trace_context_extractor_accepts_only_valid_w3c_headers() {
        use opentelemetry::propagation::TextMapPropagator;
        use opentelemetry::trace::TraceContextExt;
        use opentelemetry_sdk::propagation::TraceContextPropagator;

        let mut headers = HeaderMap::new();
        headers.insert(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .unwrap(),
        );
        let context = TraceContextPropagator::new().extract(&RequestHeaderExtractor(&headers));
        let context_span = context.span();
        let span_context = context_span.span_context();
        assert!(span_context.is_valid());
        assert!(span_context.is_remote());
        assert_eq!(
            span_context.trace_id().to_string(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );

        headers.insert("traceparent", "not-a-trace-context".parse().unwrap());
        let rejected = TraceContextPropagator::new().extract(&RequestHeaderExtractor(&headers));
        let rejected_span = rejected.span();
        assert!(!rejected_span.span_context().is_valid());
    }

    #[test]
    fn provider_event_canonicalization_is_stable_and_redacted() {
        let received_at = DateTime::parse_from_rfc3339("2026-07-12T12:35:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let account = ProviderAccountKey::parse("test-profile").unwrap();
        let mut left = verified_event("event-canonical", Some("call-canonical"));
        let mut right = left.clone();
        left.raw = serde_json::from_str(r#"{"z":1,"a":{"y":2,"b":3}}"#).unwrap();
        right.raw = serde_json::from_str(r#"{"a":{"b":3,"y":2},"z":1}"#).unwrap();

        let left = provider_event_input(account.clone(), "telnyx", &left, received_at).unwrap();
        let right = provider_event_input(account, "telnyx", &right, received_at).unwrap();

        assert_eq!(left.event_digest, right.event_digest);
        assert_eq!(left.payload_digest, right.payload_digest);
        assert_eq!(left.payload, right.payload);
        assert_eq!(left.received_at, received_at);
        assert_eq!(
            left.occurred_at,
            Some(
                DateTime::parse_from_rfc3339("2026-07-12T12:34:56.789Z")
                    .unwrap()
                    .with_timezone(&Utc)
            )
        );
        let debug = format!("{left:?}");
        assert!(!debug.contains("call-canonical"));
        assert!(!debug.contains("event-canonical"));
        assert!(!debug.contains("\"z\""));
    }

    #[tokio::test]
    async fn verified_provider_webhook_is_accepted_deduplicated_and_conflict_checked() {
        let state = call_api_test_state(8).await;
        install_verified_test_provider(&state, Arc::new(AtomicUsize::new(0)));
        let app = router(state);
        let event = verified_event("event-1", Some("call-1"));

        let accepted = post_verified_webhook(&app, &event).await;
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);
        assert_eq!(response_json(accepted).await, json!({"status": "accepted"}));

        let duplicate = post_verified_webhook(&app, &event).await;
        assert_eq!(duplicate.status(), StatusCode::OK);
        assert_eq!(
            response_json(duplicate).await,
            json!({"status": "duplicate"})
        );

        let mut conflicting = event;
        conflicting.raw["sensitive"] = Value::String("must-not-leak".into());
        let conflict = post_verified_webhook(&app, &conflicting).await;
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        let conflict_body = response_json(conflict).await;
        assert_eq!(conflict_body["error"]["code"], "provider_event_conflict");
        assert!(!conflict_body.to_string().contains("must-not-leak"));
    }

    #[tokio::test]
    async fn verified_webhook_reaches_only_the_matching_provider_profile_and_kind() {
        let state = provider_call_api_test_state(8).await;
        install_verified_test_provider(&state, Arc::new(AtomicUsize::new(0)));
        let runtime = state.call_runtime().unwrap();
        let matching_endpoint = ProviderEndpointConfig {
            provider: ProviderKind::Telnyx,
            account_profile: "test-profile".into(),
            destination: Some("+12065550100".into()),
        };
        assert!(state.providers.resolve_endpoint(&matching_endpoint).is_ok());
        for endpoint in [
            ProviderEndpointConfig {
                account_profile: "other-profile".into(),
                ..matching_endpoint.clone()
            },
            ProviderEndpointConfig {
                provider: ProviderKind::Twilio,
                ..matching_endpoint.clone()
            },
        ] {
            assert!(matches!(
                state.providers.resolve_endpoint(&endpoint),
                Err(ProviderError::AccountProfileMismatch)
            ));
        }
        let app = router(state);
        let event = verified_event("event-linked", Some("call-linked"));
        assert_eq!(
            post_verified_webhook(&app, &event).await.status(),
            StatusCode::ACCEPTED
        );
        let created = post_json(
            &app,
            "/v1/calls",
            Some("diagnostics-secret"),
            &["provider-profile-match"],
            provider_create_body("telnyx", "test-profile"),
        )
        .await;
        let created_status = created.status();
        if created_status != StatusCode::CREATED {
            panic!(
                "provider-profile-match call creation failed with {created_status}: {}",
                response_json(created).await
            );
        }
        let created = response_json(created).await;
        let call_id = created["call_id"].as_str().unwrap().parse().unwrap();
        let provider_leg = created["legs"][0]["leg_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let outcome = reconcile_provider_start(
            runtime.as_ref(),
            call_id,
            provider_leg,
            "test-profile",
            "call-linked",
        )
        .await
        .unwrap();
        let EffectResultOutcome::Reconciled(view) = outcome else {
            panic!("first provider reference must reconcile")
        };
        assert!(matches!(
            view.released_provider_events.as_slice(),
            [released]
                if released.target.as_ref().is_some_and(|target|
                    target.call_id == call_id
                        && target.leg_id == provider_leg
                        && released.state == ProviderEventState::Ready)
        ));

        let state = provider_call_api_test_state(8).await;
        install_verified_test_provider(&state, Arc::new(AtomicUsize::new(0)));
        let runtime = state.call_runtime().unwrap();
        let app = router(state);
        assert_eq!(
            post_verified_webhook(&app, &event).await.status(),
            StatusCode::ACCEPTED
        );
        let created = post_json(
            &app,
            "/v1/calls",
            Some("diagnostics-secret"),
            &["provider-profile-mismatch"],
            provider_create_body("telnyx", "other-profile"),
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let created = response_json(created).await;
        let call_id = created["call_id"].as_str().unwrap().parse().unwrap();
        let provider_leg = created["legs"][0]["leg_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            reconcile_provider_start(
                runtime.as_ref(),
                call_id,
                provider_leg,
                "test-profile",
                "call-linked",
            )
            .await,
            Err(RepositoryError::ProviderReferenceConflict)
        );

        // A mismatched call must not consume or retarget the pending event. A
        // later call on the exact provider profile can still bind the external
        // reference and release that event to only its own provider leg.
        let created = post_json(
            &app,
            "/v1/calls",
            Some("diagnostics-secret"),
            &["provider-profile-later-match"],
            provider_create_body("telnyx", "test-profile"),
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let created = response_json(created).await;
        let matching_call_id = created["call_id"].as_str().unwrap().parse().unwrap();
        let matching_provider_leg = created["legs"][0]["leg_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let outcome = reconcile_provider_start(
            runtime.as_ref(),
            matching_call_id,
            matching_provider_leg,
            "test-profile",
            "call-linked",
        )
        .await
        .unwrap();
        let EffectResultOutcome::Reconciled(view) = outcome else {
            panic!("later exact provider reference must reconcile")
        };
        assert!(matches!(
            view.released_provider_events.as_slice(),
            [released]
                if released.target.as_ref().is_some_and(|target|
                    target.call_id == matching_call_id
                        && target.leg_id == matching_provider_leg
                        && released.state == ProviderEventState::Ready)
        ));
    }

    #[tokio::test]
    async fn provider_webhook_rejects_missing_and_invalid_provider_call_ids() {
        let state = call_api_test_state(8).await;
        install_verified_test_provider(&state, Arc::new(AtomicUsize::new(0)));
        let app = router(state);

        for (event_id, provider_call_id) in [
            ("missing-call", None),
            ("empty-call", Some("")),
            ("blank-call", Some("   ")),
            ("control-call", Some("call\r\ninjected")),
        ] {
            let response =
                post_verified_webhook(&app, &verified_event(event_id, provider_call_id)).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{event_id}");
            assert_eq!(
                response_json(response).await["error"]["code"],
                "invalid_provider_event"
            );
        }
    }

    #[tokio::test]
    async fn provider_webhook_fails_closed_without_or_during_persistence() {
        let verifications = Arc::new(AtomicUsize::new(0));
        let state = diagnostics_test_state().await;
        install_verified_test_provider(&state, Arc::clone(&verifications));
        let unavailable = post_verified_webhook(
            &router(state),
            &verified_event("no-persistence", Some("call-no-persistence")),
        )
        .await;
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(verifications.load(Ordering::SeqCst), 1);

        let mut state = call_api_test_state(8).await;
        install_verified_test_provider(&state, Arc::clone(&verifications));
        state.provider_events = Some(Arc::new(UnavailableProviderEventPersistence));
        let outage = post_verified_webhook(
            &router(state),
            &verified_event("store-outage", Some("call-store-outage")),
        )
        .await;
        assert_eq!(outage.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(verifications.load(Ordering::SeqCst), 2);
        let body = response_json(outage).await;
        assert_eq!(body["error"]["code"], "call_service_unavailable");
    }

    #[tokio::test]
    async fn provider_webhook_deduplication_survives_sqlite_restart() {
        let path = std::env::temp_dir().join(format!(
            "bridgefu-provider-webhook-restart-{}.sqlite",
            Uuid::new_v4()
        ));
        let database_url = format!("sqlite://{}", path.display());
        let event = verified_event("restart-event", Some("restart-call"));

        let first_state = sqlite_test_state(&database_url).await;
        install_verified_test_provider(&first_state, Arc::new(AtomicUsize::new(0)));
        let first_app = router(first_state);
        let accepted = post_verified_webhook(&first_app, &event).await;
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);
        drop(first_app);
        tokio::task::yield_now().await;

        let second_state = sqlite_test_state(&database_url).await;
        install_verified_test_provider(&second_state, Arc::new(AtomicUsize::new(0)));
        let second_app = router(second_state);
        let duplicate = post_verified_webhook(&second_app, &event).await;
        assert_eq!(duplicate.status(), StatusCode::OK);
        assert_eq!(
            response_json(duplicate).await,
            json!({"status": "duplicate"})
        );
        drop(second_app);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    }

    #[tokio::test]
    async fn scoped_tenant_cannot_reach_unowned_legacy_amazon_resources() {
        let mut state = scoped_multi_tenant_state().await;
        let _ = install_broadcast_source(&mut state, ConnectionId::new(), false).await;
        state
            .screen_pop_evidence_store()
            .record_now(
                "tenant-b-correlation",
                ScreenPopStage::SipInviteReceived,
                None,
            )
            .unwrap();
        let app = router(state);

        let diagnostics = get(&app, "/diagnostics", Some("diagnostics-secret")).await;
        assert_eq!(diagnostics.status(), StatusCode::OK);
        assert!(response_json(diagnostics).await["active_amazon_calls"].is_null());

        let evidence = get(
            &app,
            "/v1/diagnostics/screen-pop/tenant-b-correlation",
            Some("diagnostics-secret"),
        )
        .await;
        assert_eq!(evidence.status(), StatusCode::CONFLICT);
        assert!(!serde_json::to_string(&response_json(evidence).await)
            .unwrap()
            .contains("tenant-b-correlation"));

        let unknown_call = CallId::new();
        let unknown_leg = LegId::new();
        let forged_tenant = post_json(
            &app,
            &format!("/v1/calls/{unknown_call}/broadcasts"),
            Some("diagnostics-secret"),
            &[],
            json!({"source_leg_id": unknown_leg, "tenant_id": "tenant-b"}),
        )
        .await;
        assert_eq!(forged_tenant.status(), StatusCode::FORBIDDEN);
        let unowned_call = post_json(
            &app,
            &format!("/v1/calls/{unknown_call}/broadcasts"),
            Some("diagnostics-secret"),
            &[],
            json!({"source_leg_id": unknown_leg}),
        )
        .await;
        assert_eq!(unowned_call.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn broadcast_crud_and_tokens_are_hidden_from_other_tenants() {
        let mut state = scoped_multi_tenant_state().await;
        let tenant_b_principal = test_api_principal("tenant-b");
        let mut created =
            create_durable_test_call(&state, &tenant_b_principal, "tenant-b-broadcast").await;
        let connection_id = ConnectionId::new();
        let source_leg_id = connect_durable_source_leg(
            &state,
            &tenant_b_principal,
            &mut created,
            connection_id.clone(),
        )
        .await;
        let (orchestrator, _source, _events) =
            install_broadcast_source(&mut state, connection_id, true).await;
        let broadcasts = state.broadcasts.clone();
        let broadcast_tokens = state.broadcast_token_service();
        let mut tenant_b_state = state.clone();
        tenant_b_state.bearer_authenticator = Some(ApiBearerAuthenticator::new(Arc::new(
            ConfiguredApiKeyValidator::new("tenant-b-secret".into(), ["tenant-b"]).unwrap(),
        )));
        tenant_b_state.legacy_bearer_token = None;
        let tenant_a = router(state);
        let tenant_b = router(tenant_b_state);
        let created_broadcast = post_json(
            &tenant_b,
            &format!("/v1/calls/{}/broadcasts", created.call.call_id),
            Some("tenant-b-secret"),
            &[],
            json!({"source_leg_id": source_leg_id, "transport": "uctp-quic"}),
        )
        .await;
        assert_eq!(created_broadcast.status(), StatusCode::CREATED);
        let created_broadcast = response_json(created_broadcast).await;
        let broadcast_id = created_broadcast["broadcast_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let resource = format!("/v1/broadcasts/{broadcast_id}");

        assert_eq!(
            get(&tenant_a, &resource, Some("diagnostics-secret"))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            post_json(
                &tenant_a,
                &format!("{resource}/tokens"),
                Some("diagnostics-secret"),
                &[],
                json!({}),
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            delete(&tenant_a, &resource, "diagnostics-secret")
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        assert!(broadcasts.contains_key(&broadcast_id));

        assert_eq!(
            get(&tenant_b, &resource, Some("tenant-b-secret"))
                .await
                .status(),
            StatusCode::OK
        );
        let token_response = post_json(
            &tenant_b,
            &format!("{resource}/tokens"),
            Some("tenant-b-secret"),
            &[],
            json!({}),
        )
        .await;
        assert_eq!(token_response.status(), StatusCode::OK);
        let token_body = response_json(token_response).await;
        let token = token_body["token"].as_str().expect("subscriber token");
        let validated = broadcast_tokens
            .validate_credential(token)
            .await
            .expect("API token validates through network admission authority");
        assert_eq!(validated.principal.tenant.as_deref(), Some("tenant-b"));
        assert!(validated
            .principal
            .has_scope(&format!("broadcast:subscribe:{broadcast_id}")));
        assert_eq!(
            delete(&tenant_b, &resource, "tenant-b-secret")
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
        assert!(!broadcasts.contains_key(&broadcast_id));
        assert!(broadcast_tokens.validate_credential(token).await.is_err());
        assert!(orchestrator
            .publisher_registry()
            .entry(&SessionId::from_string(&broadcast_id), "audio/main",)
            .is_none());
    }

    #[tokio::test]
    async fn local_terminal_broadcast_is_pruned_before_get_and_capacity_use() {
        let mut state = call_api_test_state(8).await;
        let owner = test_api_principal("default");
        let mut created = create_durable_test_call(&state, &owner, "broadcast-local-prune").await;
        let connection_id = ConnectionId::new();
        let source_leg =
            connect_durable_source_leg(&state, &owner, &mut created, connection_id.clone()).await;
        let (_orchestrator, _source, _events) =
            install_broadcast_source(&mut state, connection_id, true).await;
        let broadcasts = Arc::clone(&state.broadcasts);
        let shutdown_owner = state.clone();
        let app = router(state);
        let call_path = format!("/v1/calls/{}/broadcasts", created.call.call_id);
        let response = post_json(
            &app,
            &call_path,
            Some("diagnostics-secret"),
            &[],
            json!({"source_leg_id": source_leg, "transport": "uctp-quic"}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let id = response_json(response).await["broadcast_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let managed = Arc::clone(&broadcasts.get(&id).unwrap().managed);
        managed.close(BroadcastDrainReason::Shutdown).await.unwrap();
        assert_eq!(
            get(
                &app,
                &format!("/v1/broadcasts/{id}"),
                Some("diagnostics-secret"),
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert!(!broadcasts.contains_key(&id));

        let replacement = post_json(
            &app,
            &call_path,
            Some("diagnostics-secret"),
            &[],
            json!({"source_leg_id": source_leg, "transport": "uctp-quic"}),
        )
        .await;
        assert_eq!(replacement.status(), StatusCode::CREATED);
        assert_eq!(shutdown_owner.shutdown_local_broadcasts().await, 1);
        assert!(broadcasts.is_empty());
    }

    #[tokio::test]
    async fn durable_broadcast_rejects_invalid_foreign_disconnected_and_stale_sources() {
        let mut state = call_api_test_state(8).await;
        let owner = test_api_principal("default");
        let mut first = create_durable_test_call(&state, &owner, "broadcast-negative-first").await;
        let second = create_durable_test_call(&state, &owner, "broadcast-negative-second").await;
        let bearer = "diagnostics-secret";
        let app_without_media = router(state.clone());

        assert_eq!(
            post_json(
                &app_without_media,
                "/v1/calls/not-a-call/broadcasts",
                Some(bearer),
                &[],
                json!({"source_leg_id": first.call.legs[0].leg_id}),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            post_json(
                &app_without_media,
                &format!("/v1/calls/{}/broadcasts", first.call.call_id),
                Some(bearer),
                &[],
                json!({"source_leg_id": "not-a-leg"}),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            post_json(
                &app_without_media,
                &format!("/v1/calls/{}/broadcasts", first.call.call_id),
                Some(bearer),
                &[],
                json!({"source_leg_id": first.call.legs[0].leg_id, "transport": "uctp-quic"}),
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        let _ = install_broadcast_source(&mut state, ConnectionId::new(), false).await;
        let app = router(state.clone());
        assert_eq!(
            post_json(
                &app,
                &format!("/v1/calls/{}/broadcasts", first.call.call_id),
                Some(bearer),
                &[],
                json!({"source_leg_id": second.call.legs[0].leg_id, "transport": "uctp-quic"}),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            post_json(
                &app,
                &format!("/v1/calls/{}/broadcasts", first.call.call_id),
                Some(bearer),
                &[],
                json!({"source_leg_id": first.call.legs[0].leg_id, "transport": "uctp-quic"}),
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );

        let stale_connection = ConnectionId::new();
        let source_leg =
            connect_durable_source_leg(&state, &owner, &mut first, stale_connection).await;
        assert_eq!(
            post_json(
                &app,
                &format!("/v1/calls/{}/broadcasts", first.call.call_id),
                Some(bearer),
                &[],
                json!({"source_leg_id": source_leg, "transport": "uctp-quic"}),
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(state.broadcasts.is_empty());
        assert_eq!(state.broadcast_tokens.grants().active_count(), 0);
    }

    #[tokio::test]
    async fn durable_broadcasts_share_real_source_and_cleanup_managed_state() {
        let mut state = call_api_test_state(8).await;
        let owner = test_api_principal("default");
        let mut created = create_durable_test_call(&state, &owner, "broadcast-shared-source").await;
        let connection_id = ConnectionId::new();
        let source_leg =
            connect_durable_source_leg(&state, &owner, &mut created, connection_id.clone()).await;
        let (orchestrator, source, _events) =
            install_broadcast_source(&mut state, connection_id.clone(), true).await;
        let source = source.expect("real source sender");
        let broadcasts = Arc::clone(&state.broadcasts);
        let token_service = state.broadcast_token_service();
        let app = router(state);
        let call_path = format!("/v1/calls/{}/broadcasts", created.call.call_id);

        let mut ids = Vec::new();
        for _ in 0..2 {
            let response = post_json(
                &app,
                &call_path,
                Some("diagnostics-secret"),
                &[],
                json!({"source_leg_id": source_leg, "transport": "uctp-quic"}),
            )
            .await;
            assert_eq!(response.status(), StatusCode::CREATED);
            let body = response_json(response).await;
            assert_eq!(body["call_id"], created.call.call_id.to_string());
            assert_eq!(body["source_leg_id"], source_leg.to_string());
            assert_eq!(body["endpoint"]["resource"]["kind"], "uctp");
            assert!(!body.to_string().contains(&connection_id.to_string()));
            ids.push(body["broadcast_id"].as_str().unwrap().to_owned());
        }

        source
            .send(MediaFrame {
                stream_id: StreamId::new(),
                kind: StreamKind::Audio,
                payload: vec![0x78, 0x01].into(),
                timestamp_rtp: 960,
                captured_at: Utc::now(),
                payload_type: Some(111),
            })
            .await
            .unwrap();

        let diagnostics = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let response = get(&app, "/diagnostics", Some("diagnostics-secret")).await;
                assert_eq!(response.status(), StatusCode::OK);
                let body = response_json(response).await;
                if body["broadcasts"].as_array().is_some_and(|broadcasts| {
                    broadcasts.len() == 2
                        && broadcasts
                            .iter()
                            .all(|broadcast| broadcast["source_frames"].as_u64().unwrap_or(0) > 0)
                }) {
                    break body;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("managed broadcast diagnostics observe source media");
        let diagnostic_broadcasts = diagnostics["broadcasts"].as_array().unwrap();
        assert_eq!(
            diagnostic_broadcasts[0]["graph_id"],
            diagnostic_broadcasts[1]["graph_id"]
        );
        assert!(!diagnostics.to_string().contains(&connection_id.to_string()));

        let token_response = post_json(
            &app,
            &format!("/v1/broadcasts/{}/tokens", ids[0]),
            Some("diagnostics-secret"),
            &[],
            json!({}),
        )
        .await;
        assert_eq!(token_response.status(), StatusCode::OK);
        let token = response_json(token_response).await["token"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(token_service.validate_credential(&token).await.is_ok());

        for id in &ids {
            assert_eq!(
                delete(&app, &format!("/v1/broadcasts/{id}"), "diagnostics-secret",)
                    .await
                    .status(),
                StatusCode::NO_CONTENT
            );
            assert!(orchestrator
                .publisher_registry()
                .entry(&SessionId::from_string(id), "audio/main")
                .is_none());
        }
        assert!(broadcasts.is_empty());
        assert_eq!(token_service.grants().active_count(), 0);
        assert!(token_service.validate_credential(&token).await.is_err());
    }

    #[tokio::test]
    async fn sanitized_moq_events_are_double_opt_in_bound_and_cleaned_up() {
        let mut state = call_api_test_state(8).await;
        let owner = test_api_principal("default");
        let mut created =
            create_durable_test_call(&state, &owner, "broadcast-sanitized-events").await;
        let connection_id = ConnectionId::new();
        let source_leg =
            connect_durable_source_leg(&state, &owner, &mut created, connection_id.clone()).await;
        let (_orchestrator, _source, events) =
            install_broadcast_source(&mut state, connection_id.clone(), true).await;
        let events = events.expect("test adapter event sender");
        let managed_service = state
            .managed_broadcast_service
            .clone()
            .expect("managed broadcast service");
        let token_service = state.broadcast_token_service();
        let call_path = format!("/v1/calls/{}/broadcasts", created.call.call_id);

        let default_off = router(state.clone());
        let denied = post_json(
            &default_off,
            &call_path,
            Some("diagnostics-secret"),
            &[],
            json!({
                "source_leg_id": source_leg,
                "transport": "moqt",
                "sanitized_events": true
            }),
        )
        .await;
        assert_eq!(denied.status(), StatusCode::CONFLICT);
        assert_eq!(
            response_json(denied).await["error"]["code"],
            "unsupported_capability"
        );
        assert!(state.broadcasts.is_empty());
        assert_eq!(managed_service.sanitized_event_route_count(), 0);

        let context_policy = ContextPolicy {
            allow_headers: BTreeMap::from([("X-Bridgefu-Event".into(), "broadcast_event".into())]),
            ..ContextPolicy::default()
        };
        let event_policy =
            SanitizedContextEventPolicy::new("broadcast_event", 8, 8, 8, &context_policy).unwrap();
        state.context_policy = context_policy;
        state.sanitized_event_policies =
            Arc::new(BTreeMap::from([("default".into(), event_policy)]));
        let app = router(state.clone());

        let no_request_opt_in = post_json(
            &app,
            &call_path,
            Some("diagnostics-secret"),
            &[],
            json!({"source_leg_id": source_leg, "transport": "moqt"}),
        )
        .await;
        assert_eq!(no_request_opt_in.status(), StatusCode::CREATED);
        let no_request_opt_in = response_json(no_request_opt_in).await;
        assert_eq!(no_request_opt_in["sanitized_events"], false);
        assert!(no_request_opt_in["endpoint"]["resource"]["events_track"].is_null());
        assert_eq!(managed_service.sanitized_event_route_count(), 0);
        let first_id = no_request_opt_in["broadcast_id"].as_str().unwrap();
        assert_eq!(
            delete(
                &app,
                &format!("/v1/broadcasts/{first_id}"),
                "diagnostics-secret",
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );

        let wrong_transport = post_json(
            &app,
            &call_path,
            Some("diagnostics-secret"),
            &[],
            json!({
                "source_leg_id": source_leg,
                "transport": "uctp-quic",
                "sanitized_events": true
            }),
        )
        .await;
        assert_eq!(wrong_transport.status(), StatusCode::CONFLICT);
        assert_eq!(managed_service.sanitized_event_route_count(), 0);

        let enabled = post_json(
            &app,
            &call_path,
            Some("diagnostics-secret"),
            &[],
            json!({
                "source_leg_id": source_leg,
                "transport": "moqt",
                "sanitized_events": true
            }),
        )
        .await;
        assert_eq!(enabled.status(), StatusCode::CREATED);
        let enabled = response_json(enabled).await;
        let broadcast_id = enabled["broadcast_id"].as_str().unwrap().to_owned();
        assert_eq!(enabled["sanitized_events"], true);
        assert_eq!(
            enabled["endpoint"]["resource"]["events_track"],
            rvoip_moq::EVENTS_TRACK
        );
        assert_eq!(managed_service.sanitized_event_route_count(), 1);
        let token_response = post_json(
            &app,
            &format!("/v1/broadcasts/{broadcast_id}/tokens"),
            Some("diagnostics-secret"),
            &[],
            json!({}),
        )
        .await;
        assert_eq!(token_response.status(), StatusCode::OK);
        let token = response_json(token_response).await["token"]
            .as_str()
            .unwrap()
            .to_owned();
        let credential = token_service.validate_credential(&token).await.unwrap();
        assert_eq!(credential.principal.tenant.as_deref(), Some("default"));
        assert!(credential
            .principal
            .has_scope(&format!("broadcast:subscribe:{broadcast_id}")));

        let context_message = |tenant: &str, call: &str| {
            let mut envelope = crate::context::ContextEnvelope::new(
                "private-correlation-canary",
                tenant,
                call,
                source_leg.to_string(),
            );
            envelope
                .metadata
                .insert("broadcast_event".into(), "transfer-completed".into());
            envelope
                .metadata
                .insert("provider_token".into(), "private-provider-canary".into());
            envelope.to_data_message().unwrap()
        };
        events
            .send(AdapterEvent::DataMessage {
                connection_id: connection_id.clone(),
                message: context_message("other-tenant", &created.call.call_id.to_string()),
            })
            .await
            .unwrap();
        events
            .send(AdapterEvent::DataMessage {
                connection_id,
                message: context_message("default", &created.call.call_id.to_string()),
            })
            .await
            .unwrap();

        let diagnostics = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let response = get(&app, "/diagnostics", Some("diagnostics-secret")).await;
                assert_eq!(response.status(), StatusCode::OK);
                let body = response_json(response).await;
                let Some(record) = body["broadcasts"].as_array().and_then(|broadcasts| {
                    broadcasts
                        .iter()
                        .find(|broadcast| broadcast["broadcast_id"] == broadcast_id)
                }) else {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                };
                if record["sanitized_events"]["published"] == 1
                    && record["sanitized_events"]["rejected_invalid_or_unauthorized"] == 1
                {
                    break body;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("sanitized event API diagnostics deadline");
        let rendered = diagnostics.to_string();
        assert!(!rendered.contains("private-correlation-canary"));
        assert!(!rendered.contains("private-provider-canary"));
        assert!(!rendered.contains("provider_token"));

        assert_eq!(
            delete(
                &app,
                &format!("/v1/broadcasts/{broadcast_id}"),
                "diagnostics-secret",
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(managed_service.sanitized_event_route_count(), 0);
        assert!(token_service.validate_credential(&token).await.is_err());
    }

    #[tokio::test]
    async fn clustered_broadcast_identity_scopes_same_key_and_body_to_call_path() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "idempotency-key",
            axum::http::HeaderValue::from_static("same-cross-call-key"),
        );
        let first_call = CallId::new();
        let second_call = CallId::new();
        let body = br#"{"source_leg_id":"00000000-0000-4000-8000-000000000001"}"#;
        let first_identity = broadcast_operation_identity(
            &headers,
            "tenant-a",
            "create",
            first_call.to_string().as_bytes(),
            body,
        )
        .unwrap();
        let second_identity = broadcast_operation_identity(
            &headers,
            "tenant-a",
            "create",
            second_call.to_string().as_bytes(),
            body,
        )
        .unwrap();
        assert_eq!(
            first_identity.idempotency_digest,
            second_identity.idempotency_digest
        );
        assert_ne!(
            first_identity.request_digest,
            second_identity.request_digest
        );

        let repository = bridgefu::broadcast::MemoryBroadcastCommandRepository::new();
        let worker = bridgefu::call_engine::WorkerLease {
            worker_id: bridgefu::call_engine::WorkerId::new(),
            fence: bridgefu::call_engine::WorkerFence::INITIAL,
        };
        let first = DurableBroadcastSpec {
            broadcast_id: Uuid::new_v4().to_string(),
            tenant_id: TenantId::parse("tenant-a").unwrap(),
            call_id: first_call,
            source_leg_id: LegId::new(),
            source_binding_generation: bridgefu::call_engine::BindingGeneration::INITIAL,
            worker,
            transport: DurableBroadcastTransport::Moqt,
            language: None,
            sanitized_events: false,
            expires_at: Utc::now() + chrono::TimeDelta::minutes(5),
        };
        repository
            .enqueue_start(first.clone(), first_identity, 2)
            .await
            .unwrap();
        let mut second = first;
        second.broadcast_id = Uuid::new_v4().to_string();
        second.call_id = second_call;
        assert_eq!(
            repository
                .enqueue_start(second, second_identity, 2)
                .await
                .unwrap_err(),
            BroadcastCommandError::IdempotencyConflict
        );
    }

    #[test]
    fn split_broadcast_transport_admission_fails_closed() {
        assert!(
            validate_clustered_broadcast_transport(BroadcastKind::UctpQuic, false, false).is_err()
        );
        assert!(
            validate_clustered_broadcast_transport(BroadcastKind::UctpQuic, true, false).is_ok()
        );
        assert!(validate_clustered_broadcast_transport(BroadcastKind::Moqt, false, false).is_err());
        assert!(validate_clustered_broadcast_transport(BroadcastKind::Moqt, true, true).is_err());
    }

    #[tokio::test]
    async fn legacy_bearer_rejects_duplicate_merged_and_malformed_credentials() {
        let app = router(legacy_multi_tenant_state().await);
        let valid = axum::http::HeaderValue::from_static("bEaReR diagnostics-secret");
        assert_eq!(
            raw_get(&app, "/diagnostics", &[valid]).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            get(
                &app,
                "/v1/broadcasts/00000000-0000-4000-8000-000000000001",
                Some("diagnostics-secret"),
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            get(
                &app,
                "/v1/diagnostics/screen-pop/legacy-correlation",
                Some("diagnostics-secret"),
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        for values in [
            vec![
                axum::http::HeaderValue::from_static("Bearer diagnostics-secret"),
                axum::http::HeaderValue::from_static("Bearer diagnostics-secret"),
            ],
            vec![axum::http::HeaderValue::from_static(
                "Bearer diagnostics-secret,Bearer diagnostics-secret",
            )],
            vec![axum::http::HeaderValue::from_static(
                "Bearer diagnostics-secret extra",
            )],
            vec![axum::http::HeaderValue::from_bytes(b"Bearer \xff").unwrap()],
        ] {
            assert_eq!(
                raw_get(&app, "/diagnostics", &values).await.status(),
                StatusCode::UNAUTHORIZED
            );
        }
    }
}
