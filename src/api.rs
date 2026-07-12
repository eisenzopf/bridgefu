//! Versioned Bridgefu control and broadcast API.

mod calls;

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, OriginalUri, Path, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use metrics_exporter_prometheus::PrometheusHandle;
use rvoip_amazon_connect::{ConnectScreenPopServer, ScreenPopMediaLeg};
use rvoip_core::broadcast::{BroadcastDescriptor, BroadcastPublisher};
use rvoip_core::ids::MediaRouteId;
use rvoip_core::media_graph::MediaGraphHandle;
use rvoip_moq::{MoqBroadcastPublisher, MoqPublisherConfig};
use rvoip_quic::UctpBroadcastPublisher;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;
use uuid::Uuid;
use zeroize::Zeroize;

use bridgefu::api_principal::{
    ApiBearerAuthenticator, ApiPrincipal, ApiPrincipalError, ConfiguredApiKeyValidator,
    MAX_API_BEARER_BYTES,
};
use bridgefu::call_engine::{RepositoryError, TenantId};
use bridgefu::call_service::{
    build_call_service_runtime, CallServiceError, CallServiceRuntime, CallServiceRuntimeConfig,
    CallTimeoutPolicy, ControlCryptoError, SamePrincipalAttachmentResolver, SystemCallServiceClock,
};

use crate::config::Config;
use crate::context::ContextPolicy;
use crate::providers::{NormalizedProviderEvent, ProviderError, ProviderRegistry, WebhookRequest};
use crate::runtime::GenericBridgeRuntime;
use crate::screen_pop_evidence::{
    ScreenPopEvidence, ScreenPopEvidenceStore, DEFAULT_SCREEN_POP_EVIDENCE_CAPACITY,
    DEFAULT_SCREEN_POP_EVIDENCE_TTL,
};

#[derive(Clone)]
pub struct ApiState {
    server: Arc<ConnectScreenPopServer>,
    providers: ProviderRegistry,
    broadcasts: Arc<DashMap<String, Arc<ActiveBroadcast>>>,
    webhook_events: Arc<DashMap<String, DateTime<Utc>>>,
    metrics: PrometheusHandle,
    tenants: Vec<String>,
    bearer_authenticator: Option<ApiBearerAuthenticator>,
    legacy_bearer_token: Option<Arc<LegacyBearerToken>>,
    call_runtime: Option<Arc<CallServiceRuntime>>,
    token_secret: Arc<Vec<u8>>,
    token_ttl: Duration,
    max_broadcasts: usize,
    default_transport: BroadcastKind,
    public_endpoint: String,
    api_enabled: bool,
    context_policy: ContextPolicy,
    generic_runtime: Option<Arc<GenericBridgeRuntime>>,
    screen_pop_evidence: ScreenPopEvidenceStore,
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
    view: BroadcastView,
    graph: MediaGraphHandle,
    route: MediaRouteId,
    publisher: Arc<dyn BroadcastPublisher>,
}

impl ApiState {
    pub async fn from_config(
        config: &Config,
        server: Arc<ConnectScreenPopServer>,
        metrics: PrometheusHandle,
        tenants: Vec<String>,
        generic_runtime: Option<Arc<GenericBridgeRuntime>>,
    ) -> anyhow::Result<Self> {
        let providers = ProviderRegistry::from_config(&config.providers)?;
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
                Uuid::new_v4().as_bytes().to_vec()
            }
        };
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

        let call_runtime = if let (true, Some(_), Some(control_key)) = (
            config.api.enabled,
            bearer_authenticator.as_ref(),
            config.api.control_hmac_key.as_ref(),
        ) {
            let runtime = build_call_service_runtime(
                CallServiceRuntimeConfig {
                    backend: config.call_repository_backend()?,
                    worker_id: config.call_worker_id()?,
                    max_calls: config.runtime.max_concurrent_calls,
                    control_key: control_key.resolve()?.into_bytes(),
                    timeouts: CallTimeoutPolicy {
                        setup: Duration::from_secs(config.runtime.setup_timeout_secs),
                        transfer: Duration::from_secs(30),
                        ending: Duration::from_secs(config.runtime.drain_timeout_secs.max(1)),
                    },
                },
                Arc::new(SamePrincipalAttachmentResolver),
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
            Some(Arc::new(runtime))
        } else {
            if config.api.enabled {
                tracing::warn!(
                    "transactional call API is unavailable until api.bearer_token, one static tenant, and api.control_hmac_key are configured"
                );
            }
            None
        };
        let screen_pop_evidence = ScreenPopEvidenceStore::new(
            DEFAULT_SCREEN_POP_EVIDENCE_TTL,
            DEFAULT_SCREEN_POP_EVIDENCE_CAPACITY,
        )?;
        Ok(Self {
            server,
            providers,
            broadcasts: Arc::new(DashMap::new()),
            webhook_events: Arc::new(DashMap::new()),
            metrics,
            tenants,
            bearer_authenticator,
            legacy_bearer_token,
            call_runtime,
            token_secret: Arc::new(token_secret),
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
            generic_runtime,
            screen_pop_evidence,
        })
    }

    /// Clone the handle that the rvoip lifecycle-event bridge will feed.
    pub fn screen_pop_evidence_store(&self) -> ScreenPopEvidenceStore {
        self.screen_pop_evidence.clone()
    }
}

pub fn router(state: ApiState) -> Router {
    let protected = if state.api_enabled {
        let calls = Router::new()
            .route("/v1/calls", post(calls::create_call))
            .route("/v1/calls/:call_id", get(calls::get_call))
            .route("/v1/calls/:call_id/hangup", post(calls::hangup_call))
            .route("/v1/calls/:call_id/transfer", post(calls::transfer_call))
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

    Router::new()
        .route("/healthz", get(health))
        .route("/livez", get(health))
        .route("/readyz", get(health))
        .route("/metrics", get(metrics))
        .route("/v1/providers/:provider/webhooks", post(provider_webhook))
        .merge(protected)
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
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
    if let Some(authenticator) = &state.bearer_authenticator {
        let principal = authenticator
            .authenticate(request.headers(), Utc::now())
            .await
            .map_err(ApiError::from)?;
        request.extensions_mut().insert(principal);
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
    } else {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
            "control API authentication is not configured",
        ));
    }
    Ok(next.run(request).await)
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

async fn health(State(state): State<ApiState>) -> Json<Value> {
    Json(json!({"ok": true, "tenants": state.tenants, "mode": "ready"}))
}

async fn metrics(State(state): State<ApiState>) -> String {
    state.metrics.render()
}

async fn provider_capabilities(
    State(state): State<ApiState>,
    Path(provider): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let adapter = state
        .providers
        .get(&provider)
        .ok_or_else(|| ApiError::not_found("provider is not configured"))?;
    Ok(Json(
        serde_json::to_value(adapter.capabilities()).expect("capabilities serialize"),
    ))
}

async fn provider_webhook(
    State(state): State<ApiState>,
    Path(provider): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<NormalizedProviderEvent>), ApiError> {
    let adapter = state
        .providers
        .get(&provider)
        .ok_or_else(|| ApiError::not_found("provider is not configured"))?;
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
    let dedupe_key = format!("{}:{}", event.provider, event.event_id);
    if state
        .webhook_events
        .insert(dedupe_key, Utc::now())
        .is_some()
    {
        metrics::counter!("bridgefu_provider_webhooks_total", "provider" => provider, "result" => "duplicate").increment(1);
        return Ok((StatusCode::OK, Json(event)));
    }
    metrics::counter!("bridgefu_provider_webhooks_total", "provider" => provider, "result" => "accepted").increment(1);
    Ok((StatusCode::ACCEPTED, Json(event)))
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SourceLeg {
    Sip,
    Connect,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
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

#[derive(Debug, Deserialize)]
struct CreateBroadcastRequest {
    source_leg_id: SourceLeg,
    #[serde(default)]
    transport: Option<BroadcastKind>,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    language: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct BroadcastView {
    broadcast_id: String,
    call_id: String,
    tenant_id: String,
    source_leg_id: SourceLeg,
    transport: BroadcastKind,
    endpoint: String,
    expires_at: DateTime<Utc>,
    descriptor: BroadcastDescriptor,
}

async fn create_broadcast(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    Path(call_id): Path<String>,
    Json(request): Json<CreateBroadcastRequest>,
) -> Result<(StatusCode, Json<BroadcastView>), ApiError> {
    let principal = require_api_principal(principal)?;
    let tenant_id = inherit_principal_tenant(&principal, request.tenant_id.as_deref())?;
    ensure_legacy_amazon_tenant(&state, &principal)?;
    if state.broadcasts.len() >= state.max_broadcasts {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "capacity_exceeded",
            "worker broadcast capacity reached",
        ));
    }
    let leg = match request.source_leg_id {
        SourceLeg::Sip => ScreenPopMediaLeg::Sip,
        SourceLeg::Connect => ScreenPopMediaLeg::Connect,
    };
    let graph = state
        .server
        .media_graph(&call_id, leg)
        .ok_or_else(|| ApiError::not_found("active source leg not found"))?;
    let broadcast_id = Uuid::new_v4().to_string();
    let transport = request.transport.unwrap_or(state.default_transport);
    let publisher: Arc<dyn BroadcastPublisher> = match transport {
        BroadcastKind::Moqt => MoqBroadcastPublisher::new(MoqPublisherConfig {
            tenant_id: tenant_id.clone(),
            broadcast_id: broadcast_id.clone(),
            bitrate: 24_000,
            language: request.language,
            queue_frames: 10,
        })
        .map_err(|e| ApiError::internal(e.to_string()))?,
        BroadcastKind::UctpQuic => {
            UctpBroadcastPublisher::new(broadcast_id.clone(), "audio/main", 10, 1_000)
                .map_err(|e| ApiError::internal(e.to_string()))?
        }
    };
    let route = graph
        .add_sink(publisher.codec(), publisher.frames_out())
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let descriptor = publisher.descriptor();
    let endpoint = format!(
        "{}/{}",
        state.public_endpoint.trim_end_matches('/'),
        descriptor.namespace
    );
    let view = BroadcastView {
        broadcast_id: broadcast_id.clone(),
        call_id,
        tenant_id,
        source_leg_id: request.source_leg_id,
        transport,
        endpoint,
        expires_at: Utc::now() + chrono::Duration::hours(24),
        descriptor,
    };
    state.broadcasts.insert(
        broadcast_id,
        Arc::new(ActiveBroadcast {
            view: view.clone(),
            graph,
            route,
            publisher,
        }),
    );
    metrics::gauge!("bridgefu_active_broadcasts", "transport" => broadcast_label(transport))
        .increment(1.0);
    Ok((StatusCode::CREATED, Json(view)))
}

async fn get_broadcast(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    Path(id): Path<String>,
) -> Result<Json<BroadcastView>, ApiError> {
    let principal = require_api_principal(principal)?;
    state
        .broadcasts
        .get(&id)
        .filter(|record| record.view.tenant_id == principal.tenant().as_str())
        .map(|record| Json(record.view.clone()))
        .ok_or_else(|| ApiError::not_found("broadcast not found"))
}

async fn delete_broadcast(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let principal = require_api_principal(principal)?;
    let Some((_, active)) = state.broadcasts.remove_if(&id, |_, active| {
        active.view.tenant_id == principal.tenant().as_str()
    }) else {
        return Err(ApiError::not_found("broadcast not found"));
    };
    active.graph.remove_sink(active.route.clone());
    active
        .publisher
        .clone()
        .close()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    metrics::gauge!("bridgefu_active_broadcasts", "transport" => broadcast_label(active.view.transport)).decrement(1.0);
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

#[derive(Serialize)]
struct BroadcastClaims<'a> {
    sub: &'a str,
    tenant_id: &'a str,
    broadcast_id: &'a str,
    scope: String,
    iat: i64,
    exp: i64,
    jti: String,
}

async fn create_broadcast_token(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    Path(id): Path<String>,
    Json(request): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    let principal = require_api_principal(principal)?;
    let active = state
        .broadcasts
        .get(&id)
        .filter(|active| active.view.tenant_id == principal.tenant().as_str())
        .ok_or_else(|| ApiError::not_found("broadcast not found"))?;
    let ttl = Duration::from_secs(
        request
            .ttl_secs
            .unwrap_or(state.token_ttl.as_secs())
            .min(state.token_ttl.as_secs())
            .max(1),
    );
    let now = Utc::now();
    let expires_at =
        now + chrono::Duration::from_std(ttl).map_err(|e| ApiError::internal(e.to_string()))?;
    let scope = format!("broadcast:subscribe:{id}");
    let token = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &BroadcastClaims {
            sub: "bridgefu-listener",
            tenant_id: &active.view.tenant_id,
            broadcast_id: &id,
            scope: scope.clone(),
            iat: now.timestamp(),
            exp: expires_at.timestamp(),
            jti: Uuid::new_v4().to_string(),
        },
        &EncodingKey::from_secret(&state.token_secret),
    )
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(TokenResponse {
        token,
        expires_at,
        scope,
    }))
}

async fn diagnostics(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
) -> Result<Json<Value>, ApiError> {
    let principal = require_api_principal(principal)?;
    ensure_legacy_amazon_tenant(&state, &principal)?;
    let broadcasts: Vec<_> = state
        .broadcasts
        .iter()
        .filter(|entry| entry.view.tenant_id == principal.tenant().as_str())
        .map(|entry| entry.view.clone())
        .collect();
    Ok(Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "tenant_id": principal.tenant(),
        "active_amazon_calls": state.server.active_call_ids(),
        "transactional_call_api": state.call_runtime.is_some(),
        "call_repository": state.call_runtime.as_ref().map(|runtime| runtime.backend().as_str()),
        "providers": state.providers.names(),
        "broadcasts": broadcasts,
        "moqt_target_draft": rvoip_moq::TARGET_MOQT_DRAFT,
        "context_headers": state.context_policy.allow_headers.keys().collect::<Vec<_>>(),
        "generic_bridge": state.generic_runtime.as_ref().map(|runtime| json!({
            "sip": runtime.sip_addr,
            "ws": runtime.ws_addr,
            "whip": runtime.whip_addr,
        })),
    })))
}

async fn get_screen_pop_evidence(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    Path(correlation_id): Path<String>,
) -> Result<Json<ScreenPopEvidence>, ApiError> {
    let principal = require_api_principal(principal)?;
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

fn require_api_principal(
    principal: Option<Extension<ApiPrincipal>>,
) -> Result<ApiPrincipal, ApiError> {
    principal.map(|value| value.0).ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "tenant_authentication_unavailable",
            "tenant-scoped authentication is required for this resource",
        )
    })
}

fn inherit_principal_tenant(
    principal: &ApiPrincipal,
    requested: Option<&str>,
) -> Result<String, ApiError> {
    if let Some(requested) = requested {
        let requested = TenantId::parse(requested)
            .map_err(|_| ApiError::from(ApiPrincipalError::InvalidTenant))?;
        if &requested != principal.tenant() {
            return Err(ApiError::from(ApiPrincipalError::TenantOverrideForbidden));
        }
    }
    Ok(principal.tenant().as_str().to_owned())
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
            ProviderError::Unsupported => Self::capability(error.to_string()),
            ProviderError::Remote { .. } | ProviderError::Http(_) => {
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

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::body::{to_bytes, Body};
    use rvoip_amazon_connect::{
        ConnectContactStarter, ConnectError, ConnectionData, StartContactRequest,
    };
    use rvoip_core::{start_media_graph, CodecInfo, MediaFrame};
    use tower::ServiceExt;

    use crate::screen_pop_evidence::ScreenPopStage;

    struct UnusedStarter;

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

    async fn call_api_test_state(max_calls: usize) -> ApiState {
        test_state(true, max_calls, true).await
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
  token_secret: test-broadcast-secret
"#,
                available_udp_port()
            );
            let config: Config = serde_yaml::from_str(&yaml).unwrap();
            config.validate().unwrap();
            let server_config = config
                .into_server_config_with_starter(Arc::new(UnusedStarter))
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
{bearer}{control}runtime:
  max_concurrent_calls: {max_calls}
broadcast:
  token_secret: test-broadcast-secret
persistence:
  backend: memory
  allow_ephemeral_memory: true
"#,
            available_udp_port()
        );
        let config: Config = serde_yaml::from_str(&yaml).expect("diagnostics config parses");
        config.validate().expect("diagnostics config is valid");
        let server_config = config
            .into_server_config_with_starter(Arc::new(UnusedStarter))
            .await
            .expect("diagnostics server config builds");
        let server = ConnectScreenPopServer::build(server_config)
            .await
            .expect("diagnostics SIP server builds");
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        ApiState::from_config(
            &config,
            server,
            recorder.handle(),
            config.tenant_names().unwrap(),
            None,
        )
        .await
        .expect("diagnostics API state builds")
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
{static_tenant}runtime:
  max_concurrent_calls: 8
broadcast:
  token_secret: test-broadcast-secret
persistence:
  backend: memory
  allow_ephemeral_memory: true
"#,
            available_udp_port()
        );
        let config: Config = serde_yaml::from_str(&yaml).unwrap();
        config.validate().unwrap();
        let server_config = config
            .into_server_config_with_starter(Arc::new(UnusedStarter))
            .await
            .unwrap();
        let server = ConnectScreenPopServer::build(server_config).await.unwrap();
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        ApiState::from_config(
            &config,
            server,
            recorder.handle(),
            config.tenant_names().unwrap(),
            None,
        )
        .await
        .unwrap()
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

    fn seed_broadcast(
        state: &ApiState,
        tenant: &str,
    ) -> (String, tokio::sync::mpsc::Sender<MediaFrame>) {
        let broadcast_id = Uuid::new_v4().to_string();
        let (source_tx, source_rx) = tokio::sync::mpsc::channel(1);
        let graph = start_media_graph(
            source_rx,
            CodecInfo::from_name_with_defaults("opus"),
            Default::default(),
        )
        .unwrap();
        let publisher: Arc<dyn BroadcastPublisher> =
            UctpBroadcastPublisher::new(broadcast_id.clone(), "audio/main", 10, 1_000).unwrap();
        let route = graph
            .add_sink(publisher.codec(), publisher.frames_out())
            .unwrap();
        let view = BroadcastView {
            broadcast_id: broadcast_id.clone(),
            call_id: "legacy-call-private".into(),
            tenant_id: tenant.into(),
            source_leg_id: SourceLeg::Sip,
            transport: BroadcastKind::UctpQuic,
            endpoint: format!("uctp://example.test/{broadcast_id}"),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            descriptor: publisher.descriptor(),
        };
        state.broadcasts.insert(
            broadcast_id.clone(),
            Arc::new(ActiveBroadcast {
                view,
                graph,
                route,
                publisher,
            }),
        );
        (broadcast_id, source_tx)
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
        let call_id = response_json(created).await["call_id"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            post_json(
                &app,
                &format!("/v1/calls/{call_id}/transfer"),
                Some("diagnostics-secret"),
                &["transfer-invalid"],
                json!({"target": {"type": "sip", "uri": "sip:queue@sip.example.test"}}),
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
                json!({"target": {"type": "sip", "uri": "sip:test@example.test"}}),
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
    async fn scoped_tenant_cannot_reach_unowned_legacy_amazon_resources() {
        let state = scoped_multi_tenant_state().await;
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
        assert_eq!(diagnostics.status(), StatusCode::CONFLICT);
        assert!(!serde_json::to_string(&response_json(diagnostics).await)
            .unwrap()
            .contains("active_amazon_calls"));

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

        let forged_tenant = post_json(
            &app,
            "/v1/calls/tenant-b-call/broadcasts",
            Some("diagnostics-secret"),
            &[],
            json!({"source_leg_id": "sip", "tenant_id": "tenant-b"}),
        )
        .await;
        assert_eq!(forged_tenant.status(), StatusCode::FORBIDDEN);
        let unowned_call = post_json(
            &app,
            "/v1/calls/tenant-b-call/broadcasts",
            Some("diagnostics-secret"),
            &[],
            json!({"source_leg_id": "sip"}),
        )
        .await;
        assert_eq!(unowned_call.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn broadcast_crud_and_tokens_are_hidden_from_other_tenants() {
        let state = scoped_multi_tenant_state().await;
        let (broadcast_id, _source_tx) = seed_broadcast(&state, "tenant-b");
        let broadcasts = state.broadcasts.clone();
        let mut tenant_b_state = state.clone();
        tenant_b_state.bearer_authenticator = Some(ApiBearerAuthenticator::new(Arc::new(
            ConfiguredApiKeyValidator::new("tenant-b-secret".into(), ["tenant-b"]).unwrap(),
        )));
        tenant_b_state.legacy_bearer_token = None;
        let tenant_a = router(state);
        let tenant_b = router(tenant_b_state);
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
        assert_eq!(
            post_json(
                &tenant_b,
                &format!("{resource}/tokens"),
                Some("tenant-b-secret"),
                &[],
                json!({}),
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            delete(&tenant_b, &resource, "tenant-b-secret")
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
        assert!(!broadcasts.contains_key(&broadcast_id));
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
