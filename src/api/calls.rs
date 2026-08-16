//! Authenticated `/v1/calls` handlers over the durable transactional service.

use std::str::FromStr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use bridgefu::api_principal::{ApiPrincipal, CallScope};
use bridgefu::call_engine::{
    AttachmentTransport, CallId, LegDirection, LegId, LegKind, MediaFlow, RepositoryError,
    SignalingInitiator,
};
use bridgefu::call_service::{
    CallService, CallServiceError, CallView, CreateCallInput, CreateCallView, DtmfAcceptedView,
    DtmfCallInput, GetCallInput, IdempotencyKey, LegEndpointConfig, NamedProfileKind,
    NamedProfileRole, NamedRouteBinding, NamedRouteCallContext, ReplaceLegInput, RequestedLeg,
    SipEndpointConfig, SipInitialContextMode, TransferCallInput, WebRtcEndpointConfig,
};
use bridgefu::recipes::SipAdmissionMode;

use crate::config::{NamedRouteCfg, NamedRouteIngress, ProfileAudioCodec, ResolvedRouteIceServer};

use super::{ApiError, ApiState};
use bridgefu::signaling_token::SIGNALING_TOKEN_USAGE;

const WEBRTC_SIGNALING_SUBPROTOCOL: &str = "rvoip.webrtc.v1";
const WEBRTC_ATTACHMENT_PREFIX: &str = "bridgefu.attach.";
// Media activity advances the same durable aggregate version used by control
// mutations. A replacement must therefore tolerate a bounded version-only
// race between its authoritative load and commit. Every retry reruns the full
// service validation with the same idempotency key; no other conflict class is
// retried.
const LEG_REPLACEMENT_VERSION_RACE_ATTEMPTS: usize = 32;

fn retryable_leg_replacement_version_race(error: &CallServiceError, attempt: usize) -> bool {
    attempt + 1 < LEG_REPLACEMENT_VERSION_RACE_ATTEMPTS
        && matches!(
            error,
            CallServiceError::Repository(RepositoryError::VersionConflict)
        )
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RouteIngressInput {
    Sip,
    Webrtc,
}

impl RouteIngressInput {
    const fn configured(self) -> NamedRouteIngress {
        match self {
            Self::Sip => NamedRouteIngress::Sip,
            Self::Webrtc => NamedRouteIngress::Webrtc,
        }
    }

    const fn transport(self) -> AttachmentTransport {
        match self {
            Self::Sip => AttachmentTransport::Sip,
            Self::Webrtc => AttachmentTransport::WebRtc,
        }
    }

    const fn worker_capability(self) -> &'static str {
        match self {
            Self::Sip => "sip",
            Self::Webrtc => "webrtc",
        }
    }

    fn requested_leg(self) -> RequestedLeg {
        let endpoint = match self {
            Self::Sip => LegEndpointConfig::Sip(SipEndpointConfig {
                uri: None,
                initial_context: SipInitialContextMode::None,
            }),
            Self::Webrtc => LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                signaling_uri: None,
            }),
        };
        RequestedLeg {
            direction: LegDirection::Inbound,
            signaling_initiator: Some(SignalingInitiator::Remote),
            media_flow: MediaFlow::SendReceive,
            endpoint,
            amazon_connect_start: None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateRouteCallInput {
    ingress: RouteIngressInput,
    #[serde(default)]
    context: Option<NamedRouteCallContext>,
}

#[derive(Debug, Serialize)]
pub(super) struct RouteListView {
    routes: Vec<RouteView>,
}

#[derive(Debug, Serialize)]
struct RouteView {
    route_id: String,
    ingress: Vec<RouteIngressInput>,
    destination: LegKind,
    capabilities: RouteCapabilitiesView,
}

#[derive(Debug, Serialize)]
struct RouteCapabilitiesView {
    full_duplex_audio: bool,
    audio_codecs: Vec<&'static str>,
    dtmf: &'static str,
    /// Backward-compatible compact summary retained for early v1 clients.
    context: &'static str,
    initial_context: bool,
    live_data_channel_context: bool,
    sip_message: bool,
}

#[derive(Serialize)]
pub(super) struct RouteCallView {
    #[serde(flatten)]
    call: CreateCallView,
    route_id: String,
    attachment: RouteAttachmentView,
}

impl std::fmt::Debug for RouteCallView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RouteCallView")
            .field("call_id", &self.call.call.call_id)
            .field("route_id", &self.route_id)
            .field("attachment", &self.attachment)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum RouteAttachmentView {
    Sip {
        uri: String,
        expires_at: DateTime<Utc>,
    },
    Webrtc {
        signaling_uri: String,
        token: String,
        signaling_credential: RouteSignalingCredentialView,
        subprotocols: [String; 3],
        ice_servers: Vec<RouteIceServerView>,
        expires_at: DateTime<Utc>,
    },
}

#[derive(Serialize)]
struct RouteSignalingCredentialView {
    usage: &'static str,
    token: String,
    expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for RouteSignalingCredentialView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RouteSignalingCredentialView")
            .field("usage", &self.usage)
            .field("token", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Drop for RouteSignalingCredentialView {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl std::fmt::Debug for RouteAttachmentView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sip { expires_at, .. } => formatter
                .debug_struct("Sip")
                .field("uri", &"[redacted]")
                .field("expires_at", expires_at)
                .finish(),
            Self::Webrtc {
                signaling_credential,
                ice_servers,
                expires_at,
                ..
            } => formatter
                .debug_struct("Webrtc")
                .field("signaling_uri", &"[redacted]")
                .field("token", &"[redacted]")
                .field("subprotocols", &"[redacted]")
                .field("signaling_credential", signaling_credential)
                .field("ice_server_count", &ice_servers.len())
                .field("expires_at", expires_at)
                .finish(),
        }
    }
}

impl Drop for RouteAttachmentView {
    fn drop(&mut self) {
        match self {
            Self::Sip { uri, .. } => uri.zeroize(),
            Self::Webrtc {
                token,
                signaling_credential,
                subprotocols,
                ..
            } => {
                token.zeroize();
                signaling_credential.token.zeroize();
                for protocol in subprotocols {
                    protocol.zeroize();
                }
            }
        }
    }
}

#[derive(Clone, Serialize)]
struct RouteIceServerView {
    urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential: Option<String>,
}

impl std::fmt::Debug for RouteIceServerView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RouteIceServerView")
            .field("url_count", &self.urls.len())
            .field("username", &self.username.as_ref().map(|_| "[redacted]"))
            .field(
                "credential",
                &self.credential.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

impl Drop for RouteIceServerView {
    fn drop(&mut self) {
        if let Some(username) = &mut self.username {
            username.zeroize();
        }
        if let Some(credential) = &mut self.credential {
            credential.zeroize();
        }
    }
}

impl From<&ResolvedRouteIceServer> for RouteIceServerView {
    fn from(value: &ResolvedRouteIceServer) -> Self {
        Self {
            urls: value.urls.clone(),
            username: value.username.clone(),
            credential: value.credential.clone(),
        }
    }
}

pub(super) async fn list_routes(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
) -> Result<Json<RouteListView>, ApiError> {
    let (_, principal) = call_context(&state, principal)?;
    principal.authorize(CallScope::Read, Utc::now())?;
    record_tenant(&principal);
    let mut routes = Vec::new();
    for (route_id, route) in &state.named_routes.routes {
        if route.tenant_id != principal.tenant().as_str() {
            continue;
        }
        let mut ingress = Vec::new();
        for configured in &route.ingress {
            let view = match configured {
                NamedRouteIngress::Sip => RouteIngressInput::Sip,
                NamedRouteIngress::Webrtc => RouteIngressInput::Webrtc,
            };
            if route_ingress_is_advertised(&state, view, &route.destination.endpoint).await? {
                ingress.push(view);
            }
        }
        if ingress.is_empty() {
            continue;
        }
        routes.push(RouteView {
            route_id: route_id.clone(),
            ingress,
            destination: route.destination.endpoint.kind(),
            capabilities: route_capabilities(route),
        });
    }
    Ok(Json(RouteListView { routes }))
}

#[tracing::instrument(
    name = "bridgefu.api.route_call.create",
    skip_all,
    fields(tenant_id = tracing::field::Empty, call_id = tracing::field::Empty)
)]
pub(super) async fn create_route_call(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    Path(route_id): Path<String>,
    headers: HeaderMap,
    input: Result<Json<CreateRouteCallInput>, JsonRejection>,
) -> Result<(StatusCode, Json<RouteCallView>), ApiError> {
    let Json(input) = parse_json(input)?;
    let (service, principal) = call_context(&state, principal)?;
    record_tenant(&principal);
    let route = state
        .named_routes
        .routes
        .get(&route_id)
        .filter(|route| route.tenant_id == principal.tenant().as_str())
        .ok_or_else(|| ApiError::not_found("route not found"))?;
    if !route.ingress.contains(&input.ingress.configured()) {
        return Err(ApiError::capability(
            "named route does not support the requested ingress",
        ));
    }
    if input.ingress == RouteIngressInput::Sip
        && route
            .recipe_sip_admission
            .as_ref()
            .is_some_and(|admission| admission.mode == SipAdmissionMode::StableUri)
    {
        return Err(ApiError::capability(
            "this recipe uses its configured stable SIP URI instead of a managed attachment",
        ));
    }
    require_local_route_execution(&state, input.ingress, &route.destination.endpoint).await?;
    if let (Some(context), Some(allowlist)) = (
        input.context.as_ref(),
        route.context_metadata_allowlist.as_ref(),
    ) {
        if context.metadata.keys().any(|key| !allowlist.contains(key)) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "context_metadata_not_allowed",
                "named-route context contains metadata not allowed by its destination profile",
            ));
        }
    }
    if route.context_required && input.context.is_none() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "context_required",
            "this route requires bounded server-owned context",
        ));
    }
    if route.required_sip_correlation_header.is_some() && input.context.is_none() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "correlation_context_required",
            "this SIP route requires a server-owned correlation context",
        ));
    }
    let key = IdempotencyKey::from_headers(&headers)?;
    let profiles = route
        .profile_bindings
        .iter()
        .filter(|profile| {
            profile.role() == NamedProfileRole::Destination
                || (profile.role() == NamedProfileRole::Ingress
                    && match input.ingress {
                        RouteIngressInput::Sip => matches!(
                            profile.kind(),
                            NamedProfileKind::VapiIngress | NamedProfileKind::SipIngress
                        ),
                        RouteIngressInput::Webrtc => profile.kind() == NamedProfileKind::WebRtc,
                    })
        })
        .cloned()
        .collect();
    let mut binding =
        NamedRouteBinding::new_with_profiles(route_id.clone(), input.context, profiles)?;
    if let Some(header) = &route.required_sip_correlation_header {
        binding = binding.with_required_sip_correlation_header(header.clone())?;
    }
    let create = CreateCallInput {
        tenant_id: None,
        legs: [input.ingress.requested_leg(), route.destination.clone()],
    };
    let mut result = service
        .create_named_route_call(&principal, &key, create, binding)
        .await?;
    let expected_transport = input.ingress.transport();
    let inbound_leg = result
        .value
        .call
        .legs
        .iter_mut()
        .find(|leg| leg.direction == LegDirection::Inbound)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "call_service_unavailable",
                "named route inbound leg is unavailable",
            )
        })?;
    let inbound_leg_id = inbound_leg.leg_id;
    let mut attachment = inbound_leg
        .attachment
        .take()
        .filter(|attachment| attachment.transport == expected_transport)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "call_service_unavailable",
                "named route attachment is unavailable",
            )
        })?;
    let expires_at = attachment.expires_at;
    let mut token = std::mem::take(&mut attachment.token);
    let descriptor = match input.ingress {
        RouteIngressInput::Sip => {
            let Some(template) = state.named_routes.sip_uri_template.as_deref() else {
                token.zeroize();
                return Err(ApiError::capability(
                    "SIP route attachment is not configured",
                ));
            };
            let uri = template.replace("{token}", &token);
            token.zeroize();
            RouteAttachmentView::Sip { uri, expires_at }
        }
        RouteIngressInput::Webrtc => {
            let Some(configured) = state.named_routes.webrtc.as_ref() else {
                token.zeroize();
                return Err(ApiError::capability(
                    "WebRTC route attachment is not configured",
                ));
            };
            let attachment_protocol = format!("{WEBRTC_ATTACHMENT_PREFIX}{token}");
            let signaling_tokens = state.signaling_token_service().ok_or_else(|| {
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "call_service_unavailable",
                    "WebRTC signaling credential authority is unavailable",
                )
            })?;
            let mut credential = signaling_tokens
                .issue(
                    principal.authenticated(),
                    result.value.call.call_id,
                    inbound_leg_id,
                    &token,
                    expires_at,
                    Utc::now(),
                )
                .map_err(|_| {
                    ApiError::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "call_service_unavailable",
                        "WebRTC signaling credential could not be issued",
                    )
                })?;
            let credential_protocol = format!("token.{}", credential.token);
            RouteAttachmentView::Webrtc {
                signaling_uri: configured.signaling_uri.clone(),
                token,
                signaling_credential: RouteSignalingCredentialView {
                    usage: SIGNALING_TOKEN_USAGE,
                    token: std::mem::take(&mut credential.token),
                    expires_at: credential.expires_at,
                },
                subprotocols: [
                    WEBRTC_SIGNALING_SUBPROTOCOL.into(),
                    credential_protocol,
                    attachment_protocol,
                ],
                ice_servers: configured
                    .ice_servers
                    .iter()
                    .map(RouteIceServerView::from)
                    .collect(),
                expires_at,
            }
        }
    };
    metrics::counter!(
        "bridgefu_call_operations_total",
        "operation" => "route_create",
        "result" => if result.replayed { "replayed" } else { "created" }
    )
    .increment(1);
    tracing::Span::current().record(
        "call_id",
        tracing::field::display(result.value.call.call_id),
    );
    Ok((
        StatusCode::CREATED,
        Json(RouteCallView {
            call: result.value,
            route_id,
            attachment: descriptor,
        }),
    ))
}

fn route_capabilities(route: &NamedRouteCfg) -> RouteCapabilitiesView {
    let endpoint = &route.destination.endpoint;
    let full_duplex_audio = matches!(
        endpoint,
        LegEndpointConfig::Sip(_)
            | LegEndpointConfig::WebRtc(_)
            | LegEndpointConfig::AmazonConnect(_)
            | LegEndpointConfig::Provider(_)
    );
    let (dtmf, context, initial_context, live_data_channel_context, sip_message) = match endpoint {
        LegEndpointConfig::WebRtc(_) => {
            let data_channels = route.capability_policy.data_channels.unwrap_or(true);
            (
                "bidirectional",
                if data_channels { "datachannel" } else { "none" },
                data_channels,
                data_channels,
                false,
            )
        }
        LegEndpointConfig::Sip(_) => {
            let sip_message = route.capability_policy.sip_message.unwrap_or(true);
            (
                "bidirectional",
                if sip_message {
                    "sip_headers_and_message"
                } else {
                    "sip_headers"
                },
                true,
                false,
                sip_message,
            )
        }
        LegEndpointConfig::AmazonConnect(_) | LegEndpointConfig::Provider(_) => {
            ("source_to_destination", "initial_only", true, false, false)
        }
        LegEndpointConfig::Whip(_) | LegEndpointConfig::Whep(_) => {
            ("none", "none", false, false, false)
        }
    };
    RouteCapabilitiesView {
        full_duplex_audio,
        audio_codecs: route
            .capability_policy
            .audio_codecs
            .iter()
            .map(|codec| match codec {
                ProfileAudioCodec::Pcmu => "pcmu",
                ProfileAudioCodec::Pcma => "pcma",
                ProfileAudioCodec::Opus => "opus",
            })
            .collect(),
        dtmf,
        context,
        initial_context,
        live_data_channel_context,
        sip_message,
    }
}

async fn route_ingress_is_advertised(
    state: &ApiState,
    ingress: RouteIngressInput,
    endpoint: &LegEndpointConfig,
) -> Result<bool, ApiError> {
    let Ok(destination_capability) =
        endpoint.required_worker_capability(SignalingInitiator::Bridgefu)
    else {
        return Ok(false);
    };
    state
        .runtime_supports_capabilities(&[ingress.worker_capability(), destination_capability])
        .await
}

async fn require_local_route_execution(
    state: &ApiState,
    ingress: RouteIngressInput,
    endpoint: &LegEndpointConfig,
) -> Result<(), ApiError> {
    // Split creation is authorized again inside repository placement, after
    // durable create replay has had priority. Repeating the live-worker check
    // here would let a later drain hide an already committed idempotent result.
    if state.is_split_gateway() {
        return Ok(());
    }
    if route_ingress_is_advertised(state, ingress, endpoint).await? {
        Ok(())
    } else {
        Err(ApiError::capability(
            "destination is not executable in the current runtime topology",
        ))
    }
}

#[tracing::instrument(
    name = "bridgefu.api.call.create",
    skip_all,
    fields(tenant_id = tracing::field::Empty, call_id = tracing::field::Empty)
)]
pub(super) async fn create_call(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    headers: HeaderMap,
    input: Result<Json<CreateCallInput>, JsonRejection>,
) -> Result<(StatusCode, Json<CreateCallView>), ApiError> {
    let Json(input) = parse_json(input)?;
    let (service, principal) = call_context(&state, principal)?;
    record_tenant(&principal);
    let key = IdempotencyKey::from_headers(&headers)?;
    let result = service.create_call(&principal, &key, input).await?;
    metrics::counter!(
        "bridgefu_call_operations_total",
        "operation" => "create",
        "result" => if result.replayed { "replayed" } else { "created" }
    )
    .increment(1);
    tracing::Span::current().record(
        "call_id",
        tracing::field::display(result.value.call.call_id),
    );
    Ok((StatusCode::CREATED, Json(result.value)))
}

#[tracing::instrument(
    name = "bridgefu.api.call.get",
    skip_all,
    fields(tenant_id = tracing::field::Empty, call_id = tracing::field::Empty)
)]
pub(super) async fn get_call(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    Path(call_id): Path<String>,
    Query(input): Query<GetCallInput>,
) -> Result<Json<CallView>, ApiError> {
    let (service, principal) = call_context(&state, principal)?;
    record_tenant(&principal);
    let call_id = parse_call_id(&call_id)?;
    record_call_id(call_id);
    Ok(Json(service.get_call(&principal, call_id, input).await?))
}

#[tracing::instrument(
    name = "bridgefu.api.call.hangup",
    skip_all,
    fields(tenant_id = tracing::field::Empty, call_id = tracing::field::Empty)
)]
pub(super) async fn hangup_call(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    Path(call_id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<CallView>), ApiError> {
    let input = parse_optional_json(body)?;
    let (service, principal) = call_context(&state, principal)?;
    record_tenant(&principal);
    let key = IdempotencyKey::from_headers(&headers)?;
    let call_id = parse_call_id(&call_id)?;
    record_call_id(call_id);
    let result = service
        .hangup_call(&principal, call_id, &key, input)
        .await?;
    metrics::counter!(
        "bridgefu_call_operations_total",
        "operation" => "hangup",
        "result" => if result.replayed { "replayed" } else { "accepted" }
    )
    .increment(1);
    Ok((StatusCode::ACCEPTED, Json(result.value)))
}

#[tracing::instrument(
    name = "bridgefu.api.call.transfer",
    skip_all,
    fields(tenant_id = tracing::field::Empty, call_id = tracing::field::Empty)
)]
pub(super) async fn transfer_call(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    Path(call_id): Path<String>,
    headers: HeaderMap,
    input: Result<Json<TransferCallInput>, JsonRejection>,
) -> Result<(StatusCode, Json<CallView>), ApiError> {
    let Json(input) = parse_json(input)?;
    let (service, principal) = call_context(&state, principal)?;
    record_tenant(&principal);
    let key = IdempotencyKey::from_headers(&headers)?;
    let call_id = parse_call_id(&call_id)?;
    record_call_id(call_id);
    let result = service
        .transfer_call(&principal, call_id, &key, input)
        .await?;
    metrics::counter!(
        "bridgefu_call_operations_total",
        "operation" => "transfer",
        "result" => if result.replayed { "replayed" } else { "accepted" }
    )
    .increment(1);
    Ok((StatusCode::ACCEPTED, Json(result.value)))
}

#[tracing::instrument(
    name = "bridgefu.api.call.leg.replace",
    skip_all,
    fields(tenant_id = tracing::field::Empty, call_id = tracing::field::Empty, leg_id = tracing::field::Empty)
)]
pub(super) async fn replace_leg(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    Path((call_id, leg_id)): Path<(String, String)>,
    headers: HeaderMap,
    input: Result<Json<ReplaceLegInput>, JsonRejection>,
) -> Result<(StatusCode, Json<CallView>), ApiError> {
    let Json(input) = parse_json(input)?;
    let (service, principal) = call_context(&state, principal)?;
    record_tenant(&principal);
    let route = state
        .named_routes
        .routes
        .get(&input.route_id)
        .filter(|route| route.tenant_id == principal.tenant().as_str())
        .ok_or_else(|| ApiError::not_found("replacement route not found"))?;
    let replacement_route = NamedRouteBinding::new_with_profiles(
        input.route_id.clone(),
        None,
        route.profile_bindings.clone(),
    )
    .map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "replacement_route_invalid",
            "the configured replacement route is unavailable",
        )
    })?;
    let key = IdempotencyKey::from_headers(&headers)?;
    let call_id = parse_call_id(&call_id)?;
    let leg_id = LegId::from_str(&leg_id).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_leg_id",
            "leg ID must be a non-nil UUID",
        )
    })?;
    record_call_id(call_id);
    tracing::Span::current().record("leg_id", tracing::field::display(leg_id));
    let mut accepted = None;
    for attempt_index in 0..LEG_REPLACEMENT_VERSION_RACE_ATTEMPTS {
        let outcome = service
            .replace_leg(
                &principal,
                call_id,
                leg_id,
                &key,
                input.clone(),
                route.destination.clone(),
                replacement_route.clone(),
            )
            .await;
        match outcome {
            Ok(result) => {
                accepted = Some(result);
                break;
            }
            Err(error) if retryable_leg_replacement_version_race(&error, attempt_index) => {
                tokio::task::yield_now().await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let result = accepted.expect("bounded replacement loop either accepts or returns an error");
    metrics::counter!(
        "bridgefu_call_operations_total",
        "operation" => "replace_leg",
        "result" => if result.replayed { "replayed" } else { "accepted" }
    )
    .increment(1);
    Ok((StatusCode::ACCEPTED, Json(result.value)))
}

#[tracing::instrument(
    name = "bridgefu.api.call.dtmf",
    skip_all,
    fields(tenant_id = tracing::field::Empty, call_id = tracing::field::Empty)
)]
pub(super) async fn dtmf_call(
    State(state): State<ApiState>,
    principal: Option<Extension<ApiPrincipal>>,
    Path(call_id): Path<String>,
    headers: HeaderMap,
    input: Result<Json<DtmfCallInput>, JsonRejection>,
) -> Result<(StatusCode, Json<DtmfAcceptedView>), ApiError> {
    let Json(input) = parse_json(input)?;
    let (service, principal) = call_context(&state, principal)?;
    record_tenant(&principal);
    let key = IdempotencyKey::from_headers(&headers)?;
    let call_id = parse_call_id(&call_id)?;
    record_call_id(call_id);
    let result = service.send_dtmf(&principal, call_id, &key, input).await?;
    metrics::counter!(
        "bridgefu_call_operations_total",
        "operation" => "dtmf",
        "result" => if result.replayed { "replayed" } else { "accepted" }
    )
    .increment(1);
    Ok((StatusCode::ACCEPTED, Json(result.value)))
}

fn record_tenant(principal: &ApiPrincipal) {
    tracing::Span::current().record(
        "tenant_id",
        tracing::field::display(principal.tenant().as_str()),
    );
}

fn record_call_id(call_id: CallId) {
    tracing::Span::current().record("call_id", tracing::field::display(call_id));
}

fn call_context(
    state: &ApiState,
    principal: Option<Extension<ApiPrincipal>>,
) -> Result<(Arc<CallService>, ApiPrincipal), ApiError> {
    let service = state.call_service.as_ref().map(Arc::clone).ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "call_service_unavailable",
            "transactional call service is not configured",
        )
    })?;
    let principal = principal.map(|value| value.0).ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "call_service_unavailable",
            "transactional call authentication is not configured",
        )
    })?;
    Ok((service, principal))
}

fn parse_call_id(value: &str) -> Result<CallId, ApiError> {
    CallId::from_str(value).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_call_id",
            "call ID must be a non-nil UUID",
        )
    })
}

fn parse_json<T>(input: Result<Json<T>, JsonRejection>) -> Result<Json<T>, ApiError> {
    input.map_err(|rejection| {
        if rejection.into_response().status() == StatusCode::PAYLOAD_TOO_LARGE {
            return ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
                "call request body exceeds 65536 bytes",
            );
        }
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_json",
            "request body is not valid for this operation",
        )
    })
}

fn parse_optional_json<T>(body: Result<Bytes, BytesRejection>) -> Result<T, ApiError>
where
    T: serde::de::DeserializeOwned + Default,
{
    let body = body.map_err(|rejection| {
        if rejection.into_response().status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
                "call request body exceeds 65536 bytes",
            )
        } else {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_body",
                "request body could not be read",
            )
        }
    })?;
    if body.is_empty() {
        Ok(T::default())
    } else {
        serde_json::from_slice(&body).map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_json",
                "request body is not valid for this operation",
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bridgefu::call_service::{
        AmazonConnectEndpointConfig, ProviderEndpointConfig, ProviderKind, WebRtcEndpointConfig,
    };

    #[test]
    fn leg_replacement_retries_only_bounded_aggregate_version_races() {
        let version_race = CallServiceError::Repository(RepositoryError::VersionConflict);
        assert!(retryable_leg_replacement_version_race(&version_race, 0));
        assert!(retryable_leg_replacement_version_race(
            &version_race,
            LEG_REPLACEMENT_VERSION_RACE_ATTEMPTS - 2,
        ));
        assert!(!retryable_leg_replacement_version_race(
            &version_race,
            LEG_REPLACEMENT_VERSION_RACE_ATTEMPTS - 1,
        ));

        for error in [
            CallServiceError::Repository(RepositoryError::CommandConflict),
            CallServiceError::Repository(RepositoryError::IdempotencyConflict),
            CallServiceError::InvalidTransition,
            CallServiceError::DependencyUnavailable,
        ] {
            assert!(!retryable_leg_replacement_version_race(&error, 0));
        }
    }

    #[test]
    fn split_destination_capabilities_do_not_alias_ingress_transports() {
        assert_eq!(
            LegEndpointConfig::Sip(SipEndpointConfig {
                uri: Some("sips:agent@example.test".into()),
                initial_context: SipInitialContextMode::None,
            })
            .required_worker_capability(SignalingInitiator::Bridgefu)
            .unwrap(),
            "sip_egress",
        );
        assert_eq!(
            LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                signaling_uri: Some("wss://example.test/call".into()),
            })
            .required_worker_capability(SignalingInitiator::Bridgefu)
            .unwrap(),
            "webrtc_egress",
        );
        assert_eq!(
            LegEndpointConfig::AmazonConnect(AmazonConnectEndpointConfig {
                instance_id: "instance".into(),
                contact_flow_id: "flow".into(),
            },)
            .required_worker_capability(SignalingInitiator::Bridgefu)
            .unwrap(),
            "amazon_connect",
        );
        assert_eq!(
            LegEndpointConfig::Provider(ProviderEndpointConfig {
                provider: ProviderKind::Telnyx,
                account_profile: "telnyx".into(),
                destination: Some("+15551234567".into()),
            })
            .required_worker_capability(SignalingInitiator::Bridgefu)
            .unwrap(),
            "telnyx",
        );
    }

    #[test]
    fn route_capabilities_enforce_selected_profile_policy() {
        let mut webrtc: NamedRouteCfg = serde_yaml::from_str(
            r#"
tenant_id: tenant-a
ingress: [sip]
legacy_embedded_destination: true
destination:
  direction: outbound
  signaling_initiator: bridgefu
  media_flow: send_receive
  endpoint:
    type: webrtc
    config:
      signaling_uri: wss://agent.example.test/call
"#,
        )
        .expect("WebRTC route");
        webrtc.capability_policy.audio_codecs =
            std::collections::BTreeSet::from([ProfileAudioCodec::Opus]);
        webrtc.capability_policy.data_channels = Some(false);
        let capabilities = route_capabilities(&webrtc);
        assert_eq!(capabilities.audio_codecs, vec!["opus"]);
        assert_eq!(capabilities.context, "none");
        assert!(!capabilities.initial_context);
        assert!(!capabilities.live_data_channel_context);

        let mut sip: NamedRouteCfg = serde_yaml::from_str(
            r#"
tenant_id: tenant-a
ingress: [webrtc]
legacy_embedded_destination: true
destination:
  direction: outbound
  signaling_initiator: bridgefu
  media_flow: send_receive
  endpoint:
    type: sip
    config:
      uri: sips:agent@example.test
"#,
        )
        .expect("SIP route");
        sip.capability_policy.audio_codecs =
            std::collections::BTreeSet::from([ProfileAudioCodec::Pcmu, ProfileAudioCodec::Pcma]);
        sip.capability_policy.sip_message = Some(false);
        let capabilities = route_capabilities(&sip);
        assert_eq!(capabilities.audio_codecs, vec!["pcmu", "pcma"]);
        assert_eq!(capabilities.context, "sip_headers");
        assert!(!capabilities.sip_message);
    }
}
