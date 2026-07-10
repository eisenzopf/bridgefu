//! Versioned Bridgefu control and broadcast API.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{OriginalUri, Path, State};
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

use crate::config::Config;
use crate::context::ContextPolicy;
use crate::providers::{
    NormalizedProviderEvent, OriginateCommand, ProviderError, ProviderRegistry, WebhookRequest,
};
use crate::runtime::GenericBridgeRuntime;
use crate::screen_pop_evidence::{
    ScreenPopEvidence, ScreenPopEvidenceStore, DEFAULT_SCREEN_POP_EVIDENCE_CAPACITY,
    DEFAULT_SCREEN_POP_EVIDENCE_TTL,
};

#[derive(Clone)]
pub struct ApiState {
    server: Arc<ConnectScreenPopServer>,
    providers: ProviderRegistry,
    calls: Arc<DashMap<String, CallRecord>>,
    broadcasts: Arc<DashMap<String, Arc<ActiveBroadcast>>>,
    webhook_events: Arc<DashMap<String, DateTime<Utc>>>,
    metrics: PrometheusHandle,
    tenants: Vec<String>,
    bearer_token: Option<String>,
    token_secret: Arc<Vec<u8>>,
    token_ttl: Duration,
    max_calls: usize,
    max_broadcasts: usize,
    default_transport: BroadcastKind,
    public_endpoint: String,
    api_enabled: bool,
    context_policy: ContextPolicy,
    generic_runtime: Option<Arc<GenericBridgeRuntime>>,
    screen_pop_evidence: ScreenPopEvidenceStore,
}

struct ActiveBroadcast {
    view: BroadcastView,
    graph: MediaGraphHandle,
    route: MediaRouteId,
    publisher: Arc<dyn BroadcastPublisher>,
}

impl ApiState {
    pub fn from_config(
        config: &Config,
        server: Arc<ConnectScreenPopServer>,
        metrics: PrometheusHandle,
        tenants: Vec<String>,
        generic_runtime: Option<Arc<GenericBridgeRuntime>>,
    ) -> anyhow::Result<Self> {
        let providers = ProviderRegistry::from_config(&config.providers)?;
        let bearer_token = config
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
        let screen_pop_evidence = ScreenPopEvidenceStore::new(
            DEFAULT_SCREEN_POP_EVIDENCE_TTL,
            DEFAULT_SCREEN_POP_EVIDENCE_CAPACITY,
        )?;
        Ok(Self {
            server,
            providers,
            calls: Arc::new(DashMap::new()),
            broadcasts: Arc::new(DashMap::new()),
            webhook_events: Arc::new(DashMap::new()),
            metrics,
            tenants,
            bearer_token,
            token_secret: Arc::new(token_secret),
            token_ttl: Duration::from_secs(config.broadcast.token_ttl_secs),
            max_calls: config.runtime.max_concurrent_calls,
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
        Router::new()
            .route("/v1/calls", post(create_call))
            .route("/v1/calls/:call_id", get(get_call))
            .route("/v1/calls/:call_id/hangup", post(hangup_call))
            .route("/v1/calls/:call_id/transfer", post(transfer_call))
            .route("/v1/calls/:call_id/dtmf", post(dtmf_call))
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
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    if let Some(expected) = &state.bearer_token {
        let supplied = request
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        if !supplied
            .map(|value| constant_time_eq(value.as_bytes(), expected.as_bytes()))
            .unwrap_or(false)
        {
            metrics::counter!("bridgefu_auth_failures_total", "surface" => "api").increment(1);
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "valid Bearer token required",
            ));
        }
    }
    Ok(next.run(request).await)
}

async fn health(State(state): State<ApiState>) -> Json<Value> {
    Json(json!({"ok": true, "tenants": state.tenants, "mode": "ready"}))
}

async fn metrics(State(state): State<ApiState>) -> String {
    state.metrics.render()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum LegSpec {
    Sip {
        uri: String,
    },
    WebRtc {
        endpoint: Option<String>,
    },
    AmazonConnect {
        tenant_id: String,
    },
    Provider {
        provider: String,
        from: String,
        to: String,
        answer_url: Option<String>,
        event_url: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
struct CreateCallRequest {
    #[serde(default)]
    tenant_id: Option<String>,
    legs: Vec<LegSpec>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
    #[serde(default)]
    idempotency_key: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct CallRecord {
    call_id: String,
    tenant_id: String,
    state: String,
    legs: Vec<LegSpec>,
    provider: Option<String>,
    provider_call_id: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

async fn create_call(
    State(state): State<ApiState>,
    Json(request): Json<CreateCallRequest>,
) -> Result<(StatusCode, Json<CallRecord>), ApiError> {
    if state.calls.len() + state.server.active_call_ids().len() >= state.max_calls {
        metrics::counter!("bridgefu_admission_rejections_total", "resource" => "calls")
            .increment(1);
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "capacity_exceeded",
            "worker call capacity reached",
        ));
    }
    if request.legs.len() != 1 {
        return Err(ApiError::capability(
            "1.0 originate currently requires exactly one provider-controlled leg",
        ));
    }
    let LegSpec::Provider {
        provider,
        from,
        to,
        answer_url,
        event_url,
    } = &request.legs[0]
    else {
        return Err(ApiError::capability("direct SIP/WebRTC legs are accepted by the signaling listeners, not the provider originate API"));
    };
    let adapter = state
        .providers
        .get(provider)
        .ok_or_else(|| ApiError::not_found("provider is not configured"))?;
    let call_id = Uuid::new_v4().to_string();
    let provider_call = adapter
        .originate(OriginateCommand {
            from: from.clone(),
            to: to.clone(),
            answer_url: answer_url.clone(),
            event_url: event_url.clone(),
            idempotency_key: request.idempotency_key.unwrap_or_else(|| call_id.clone()),
            metadata: request.metadata,
        })
        .await?;
    let now = Utc::now();
    let record = CallRecord {
        call_id: call_id.clone(),
        tenant_id: request.tenant_id.unwrap_or_else(|| "default".into()),
        state: provider_call.state,
        legs: request.legs,
        provider: Some(provider_call.provider),
        provider_call_id: Some(provider_call.provider_call_id),
        created_at: now,
        updated_at: now,
    };
    state.calls.insert(call_id, record.clone());
    metrics::counter!("bridgefu_call_operations_total", "operation" => "originate", "result" => "ok").increment(1);
    Ok((StatusCode::CREATED, Json(record)))
}

async fn get_call(
    State(state): State<ApiState>,
    Path(call_id): Path<String>,
) -> Result<Json<CallRecord>, ApiError> {
    if let Some(call) = state.calls.get(&call_id) {
        return Ok(Json(call.clone()));
    }
    if state
        .server
        .active_call_ids()
        .iter()
        .any(|id| id == &call_id)
    {
        let now = Utc::now();
        return Ok(Json(CallRecord {
            call_id,
            tenant_id: "routed".into(),
            state: "connected".into(),
            legs: vec![
                LegSpec::Sip {
                    uri: "inbound".into(),
                },
                LegSpec::AmazonConnect {
                    tenant_id: "routed".into(),
                },
            ],
            provider: Some("amazon-connect".into()),
            provider_call_id: None,
            created_at: now,
            updated_at: now,
        }));
    }
    Err(ApiError::not_found("call not found"))
}

async fn hangup_call(
    State(state): State<ApiState>,
    Path(call_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if let Some(mut call) = state.calls.get_mut(&call_id) {
        let provider_name = call
            .provider
            .clone()
            .ok_or_else(|| ApiError::capability("call has no provider control adapter"))?;
        let provider_id = call
            .provider_call_id
            .clone()
            .ok_or_else(|| ApiError::capability("call has no provider call ID"))?;
        state
            .providers
            .get(&provider_name)
            .ok_or_else(|| ApiError::not_found("provider is not configured"))?
            .hangup(&provider_id)
            .await?;
        call.state = "ended".into();
        call.updated_at = Utc::now();
        return Ok(StatusCode::NO_CONTENT);
    }
    if state.server.end_by_call_id(&call_id).await {
        return Ok(StatusCode::NO_CONTENT);
    }
    Err(ApiError::not_found("call not found"))
}

#[derive(Debug, Deserialize)]
struct TransferRequest {
    target: String,
}

async fn transfer_call(
    State(state): State<ApiState>,
    Path(call_id): Path<String>,
    Json(request): Json<TransferRequest>,
) -> Result<StatusCode, ApiError> {
    let call = state
        .calls
        .get(&call_id)
        .ok_or_else(|| ApiError::capability("native transfer is unavailable for this call type"))?;
    let provider_name = call
        .provider
        .as_deref()
        .ok_or_else(|| ApiError::capability("call has no provider control adapter"))?;
    let provider_id = call
        .provider_call_id
        .as_deref()
        .ok_or_else(|| ApiError::capability("call has no provider call ID"))?;
    state
        .providers
        .get(provider_name)
        .ok_or_else(|| ApiError::not_found("provider is not configured"))?
        .transfer(provider_id, &request.target)
        .await?;
    Ok(StatusCode::ACCEPTED)
}

#[derive(Debug, Deserialize)]
struct DtmfRequest {
    digits: String,
}

async fn dtmf_call(
    State(state): State<ApiState>,
    Path(call_id): Path<String>,
    Json(request): Json<DtmfRequest>,
) -> Result<StatusCode, ApiError> {
    if request.digits.is_empty()
        || !request.digits.chars().all(|c| {
            c.is_ascii_digit() || matches!(c, '*' | '#' | 'A'..='D' | 'a'..='d' | ',' | 'w' | 'W')
        })
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_dtmf",
            "digits contain unsupported characters",
        ));
    }
    let call = state
        .calls
        .get(&call_id)
        .ok_or_else(|| ApiError::capability("native DTMF is unavailable for this call type"))?;
    let provider_name = call
        .provider
        .as_deref()
        .ok_or_else(|| ApiError::capability("call has no provider control adapter"))?;
    let provider_id = call
        .provider_call_id
        .as_deref()
        .ok_or_else(|| ApiError::capability("call has no provider call ID"))?;
    state
        .providers
        .get(provider_name)
        .ok_or_else(|| ApiError::not_found("provider is not configured"))?
        .send_dtmf(provider_id, &request.digits)
        .await?;
    Ok(StatusCode::ACCEPTED)
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
    if let Some(provider_call_id) = &event.provider_call_id {
        for mut call in state.calls.iter_mut() {
            if call.provider_call_id.as_deref() == Some(provider_call_id) {
                call.state = event.event_type.clone();
                call.updated_at = Utc::now();
            }
        }
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
    Path(call_id): Path<String>,
    Json(request): Json<CreateBroadcastRequest>,
) -> Result<(StatusCode, Json<BroadcastView>), ApiError> {
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
    let tenant_id = request.tenant_id.unwrap_or_else(|| "default".into());
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
    Path(id): Path<String>,
) -> Result<Json<BroadcastView>, ApiError> {
    state
        .broadcasts
        .get(&id)
        .map(|record| Json(record.view.clone()))
        .ok_or_else(|| ApiError::not_found("broadcast not found"))
}

async fn delete_broadcast(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let Some((_, active)) = state.broadcasts.remove(&id) else {
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
    Path(id): Path<String>,
    Json(request): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    let active = state
        .broadcasts
        .get(&id)
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

async fn diagnostics(State(state): State<ApiState>) -> Json<Value> {
    let broadcasts: Vec<_> = state
        .broadcasts
        .iter()
        .map(|entry| entry.view.clone())
        .collect();
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "active_amazon_calls": state.server.active_call_ids(),
        "controlled_calls": state.calls.len(),
        "providers": state.providers.names(),
        "broadcasts": broadcasts,
        "moqt_target_draft": rvoip_moq::TARGET_MOQT_DRAFT,
        "context_headers": state.context_policy.allow_headers.keys().collect::<Vec<_>>(),
        "generic_bridge": state.generic_runtime.as_ref().map(|runtime| json!({
            "sip": runtime.sip_addr,
            "ws": runtime.ws_addr,
            "whip": runtime.whip_addr,
        })),
    }))
}

async fn get_screen_pop_evidence(
    State(state): State<ApiState>,
    Path(correlation_id): Path<String>,
) -> Result<Json<ScreenPopEvidence>, ApiError> {
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
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
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
        (
            self.status,
            Json(json!({"error": {"code": self.code, "message": self.message}})),
        )
            .into_response()
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
broadcast:
  token_secret: test-broadcast-secret
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
        .expect("diagnostics API state builds")
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

    async fn response_json(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("diagnostics response body");
        serde_json::from_slice(&bytes).expect("diagnostics response JSON")
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
}
