//! Hermetic all-in-one qualification for the two supported ingress shapes
//! terminating at a Telnyx Call Control destination.
//!
//! The HTTP service is a protocol-faithful local Telnyx boundary, but all
//! Bridgefu and rvoip components are production implementations: the
//! crates.io `telnyx` client, `ProviderRegistry`, durable call engine,
//! one-use attachments, WSS/WebRTC, SIPS/TLS, SIP Digest, SRTP, MediaGraph,
//! provider-event reconciliation, and provider cleanup.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use bridgefu::api_principal::ApiPrincipal;
use bridgefu::call_engine::{
    BindingGeneration, CallId, CallState, LegDirection, LegId, MediaFlow, ProviderCallId,
    ProviderEventDigest, ProviderEventInput, ProviderEventOutcome, ProviderPayloadDigest,
    ProviderReferenceRole, SignalingInitiator, TenantId, WorkerId,
};
use bridgefu::call_service::{
    build_call_service_runtime, CallExecutionSupervisor, CallRepositoryBackendConfig,
    CallServiceCoordinationConfig, CallServiceRuntime, CallServiceRuntimeConfig, CallTimeoutPolicy,
    ConfiguredSipOutboundProfile, ConfiguredSipProfileAuth, CreateCallInput, DtmfCallInput,
    ExternalReferenceValue, IdempotencyKey, LegEndpointConfig, NamedProfileBinding,
    NamedProfileKind, NamedProfileRole, NamedRouteBinding, NamedRouteCallContext,
    ProviderDialClientState, ProviderDialRole, ProviderEndpointConfig, ProviderKind,
    ReplaceLegInput, RequestedLeg, SipEndpointConfig, SipInitialContextMode,
    StaticOutboundProfileResolver, SystemCallServiceClock, WebRtcEndpointConfig,
};
use bridgefu::context::{ContextEnvelope, ContextPolicy, CONTEXT_LABEL};
use bridgefu::coordination::DeploymentId;
use bridgefu::handoff_status::{HandoffStatusEnvelope, HandoffStatusKind, HANDOFF_STATUS_LABEL};
use bridgefu::providers::{
    ProviderConfigs, ProviderError, ProviderRegistry, SecretRef, TelnyxConfig, WebhookRequest,
};
use chrono::{DateTime, Utc};
use ring::signature::KeyPair as _;
use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod};
use rvoip_core::adapter::{AdapterEvent, ConnectionAdapter, EndReason, OriginateRequest};
use rvoip_core::config::Config as CoreConfig;
use rvoip_core::connection::{Direction, Transport};
use rvoip_core::ids::{ConnectionId, ParticipantId, SessionId};
use rvoip_core::stream::{MediaFrame, MediaStream, StreamKind};
use rvoip_core::{DataReliability, Event, IdentityAssurance, Jwk, Orchestrator};
use rvoip_sip::{
    Config as SipConfig, Event as SipEvent, EventReceiver as SipEventReceiver,
    MediaSecurityProfile, SessionHandle, SipAdapter, SipAuthService, SipClientAuth,
    SipInboundContextPolicy, SipInitialHeaders, SipListenerAuthPolicy, SipOriginateContext,
};
use rvoip_webrtc::signaling::auth::{AuthContext, AuthRejection, WsAuthHook};
use rvoip_webrtc::signaling::websocket::serve_tls_listener_with_auth_and_shutdown;
use rvoip_webrtc::tls::TlsConfig;
use rvoip_webrtc::{
    StaticWebRtcBearerCredentialProvider, WebRtcAdapter, WebRtcBearerCredential, WebRtcConfig,
    WebRtcOriginateContext, WebRtcTargetPolicy, WebRtcTlsClientTrust,
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tokio::sync::{mpsc, Notify};

#[path = "support/browser_sdk.rs"]
mod browser_sdk;
#[path = "support/sip_fixture.rs"]
mod sip_fixture;
use sip_fixture::{reserve_tcp, reserve_udp, tls_sip_config, TestTlsFiles};

const TENANT: &str = "telnyx-qualification-tenant";
const PROFILE: &str = "telnyx-hermetic";
const PROFILE_REVISION: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const VAPI_INGRESS_PROFILE: &str = "telnyx-vapi-ingress";
const VAPI_INGRESS_PROFILE_REVISION: &str =
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const VAPI_INGRESS_SUBJECT: &str = "telnyx-vapi-transport";
const VAPI_INGRESS_SCOPE: &str = "sip:connect";
const DIGEST_REALM: &str = "bridgefu-telnyx-media";
const DIGEST_USER: &str = "telnyx-media";
const DIGEST_PASSWORD: &str = "telnyx-media-password";
const API_KEY: &str = "KEY-hermetic-telnyx";
const CONNECTION_ID: &str = "telnyx-connection-hermetic";
const DESTINATION: &str = "+12065550123";
const ASSISTANT_PROFILE: &str = "telnyx-vapi-assistant";
const ASSISTANT_PROFILE_REVISION: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ASSISTANT_REALM: &str = "bridgefu-telnyx-vapi-assistant";
const ASSISTANT_USER: &str = "bridgefu-telnyx-browser";
const ASSISTANT_PASSWORD: &str = "hermetic-telnyx-assistant-password";
static TELNYX_QUALIFICATION_TEST_LOCK: Mutex<()> = Mutex::new(());

async fn bounded<T>(label: &'static str, future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(20), future)
        .await
        .unwrap_or_else(|_| panic!("{label} deadline"))
}

fn routable_local_ipv4() -> Ipv4Addr {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("local address probe socket");
    socket
        .connect("192.0.2.1:9")
        .expect("local address probe route");
    match socket
        .local_addr()
        .expect("local address probe result")
        .ip()
    {
        IpAddr::V4(address) if !address.is_loopback() && !address.is_unspecified() => address,
        address => panic!("no routable local IPv4 address for trusted-CIDR fixture: {address}"),
    }
}

fn reserve_udp_on(address: Ipv4Addr) -> SocketAddr {
    let socket =
        std::net::UdpSocket::bind((address, 0)).expect("reserve address-specific UDP socket");
    socket.local_addr().expect("reserved Vapi UDP address")
}

fn reserve_tcp_on(address: Ipv4Addr) -> SocketAddr {
    let listener =
        std::net::TcpListener::bind((address, 0)).expect("reserve address-specific TCP socket");
    listener.local_addr().expect("reserved Vapi TCP address")
}

fn sip_tls_files_for(address: Ipv4Addr) -> TestTlsFiles {
    let directory =
        std::env::temp_dir().join(format!("bridgefu-telnyx-sip-tls-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("create Telnyx SIP TLS fixture directory");
    let cert = directory.join("sip-cert.pem");
    let key = directory.join("sip-key.pem");
    let generated =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), address.to_string()])
            .expect("generate Telnyx SIP certificate");
    std::fs::write(&cert, generated.cert.pem()).expect("write Telnyx SIP certificate");
    std::fs::write(&key, generated.signing_key.serialize_pem())
        .expect("write Telnyx SIP private key");
    TestTlsFiles {
        directory,
        cert,
        key,
    }
}

fn owner() -> ApiPrincipal {
    ApiPrincipal::new(
        AuthenticatedPrincipal {
            subject: "telnyx-route-owner".into(),
            tenant: Some(TENANT.into()),
            scopes: vec![
                "*".into(),
                bridgefu::api_principal::CallScope::ArbitraryDestination
                    .as_str()
                    .into(),
            ],
            issuer: Some("telnyx-qualification".into()),
            expires_at: None,
            method: AuthenticationMethod::Jwt,
            assurance: IdentityAssurance::Pseudonymous {
                ephemeral_key: Jwk(json!({"kty":"test"})),
            },
        },
        Utc::now(),
    )
    .unwrap()
}

fn vapi_ingress_principal() -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        subject: VAPI_INGRESS_SUBJECT.into(),
        tenant: Some(TENANT.into()),
        scopes: vec![VAPI_INGRESS_SCOPE.into()],
        issuer: Some("telnyx-vapi-ingress-profile".into()),
        expires_at: None,
        // Match the static trusted-network identity used by production Vapi
        // ingress profiles instead of borrowing the privileged API owner.
        method: AuthenticationMethod::ApiKey,
        assurance: IdentityAssurance::Pseudonymous {
            ephemeral_key: Jwk(json!({
                "kty": "bridgefu-profile",
                "profile_id": VAPI_INGRESS_PROFILE,
            })),
        },
    }
}

struct AttachmentAuth {
    principal: AuthenticatedPrincipal,
}

#[async_trait::async_trait]
impl WsAuthHook for AttachmentAuth {
    async fn authenticate(
        &self,
        subprotocols: &[String],
        _query_token: Option<&str>,
        _peer_addr: SocketAddr,
    ) -> Result<AuthContext, AuthRejection> {
        let token = subprotocols
            .iter()
            .find_map(|value| value.strip_prefix("token."))
            .filter(|value| !value.is_empty() && value.len() <= 512)
            .ok_or(AuthRejection::Unauthorized {
                www_authenticate: "Bearer realm=\"bridgefu-telnyx-test\"".into(),
            })?;
        Ok(AuthContext {
            subject: self.principal.subject.clone(),
            scopes: vec!["webrtc:connect".into()],
            session_hint: Some(token.to_owned()),
            principal: Some(self.principal.clone()),
        })
    }
}

#[derive(Clone, Debug)]
struct CapturedRequest {
    path: String,
    authorization: Option<String>,
    body: Value,
}

#[derive(Clone, Default)]
struct TelnyxMock {
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    dial_count: Arc<AtomicUsize>,
    dtmf_attempts: Arc<AtomicUsize>,
    gate_destination: Arc<AtomicBool>,
    reject_destination: Arc<AtomicBool>,
    destination_waiting: Arc<AtomicBool>,
    destination_entered: Arc<Notify>,
    destination_release: Arc<Notify>,
}

impl TelnyxMock {
    fn snapshot(&self) -> Vec<CapturedRequest> {
        self.requests.lock().unwrap().clone()
    }

    async fn wait_for(&self, expected: usize) -> Vec<CapturedRequest> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let requests = self.snapshot();
                if requests.len() >= expected {
                    return requests;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "Telnyx HTTP request deadline waiting for {expected}; observed {:?}",
                self.snapshot()
            )
        })
    }

    fn gate_next_destination(&self) {
        self.gate_destination.store(true, Ordering::Release);
    }

    fn reject_next_destination(&self) {
        self.reject_destination.store(true, Ordering::Release);
    }

    async fn wait_for_destination_gate(&self) {
        bounded("Telnyx destination dial gate", async {
            loop {
                let notified = self.destination_entered.notified();
                if self.destination_waiting.load(Ordering::Acquire) {
                    return;
                }
                notified.await;
            }
        })
        .await;
    }

    fn release_destination(&self) {
        self.destination_release.notify_one();
    }
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

async fn telnyx_dial(
    State(state): State<TelnyxMock>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let dial = state.dial_count.fetch_add(1, Ordering::SeqCst);
    state.requests.lock().unwrap().push(CapturedRequest {
        path: "calls".into(),
        authorization: bearer(&headers),
        body,
    });
    let call = dial / 2 + 1;
    let role = if dial % 2 == 0 {
        "media"
    } else {
        "destination"
    };
    if role == "destination" && state.gate_destination.swap(false, Ordering::AcqRel) {
        state.destination_waiting.store(true, Ordering::Release);
        state.destination_entered.notify_waiters();
        state.destination_release.notified().await;
        state.destination_waiting.store(false, Ordering::Release);
    }
    if role == "destination" && state.reject_destination.swap(false, Ordering::AcqRel) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"errors":[{"code":"destination_rejected","title":"rejected"}]})),
        )
            .into_response();
    }
    Json(json!({"data": {"call_control_id": format!("telnyx-{role}-{call}")}})).into_response()
}

fn telnyx_rate_limited() -> Response {
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({"errors":[{"code":"rate_limit","title":"retry"}]})),
    )
        .into_response();
    response
        .headers_mut()
        .insert("x-ratelimit-reset", HeaderValue::from_static("0"));
    response
}

async fn telnyx_action(
    State(state): State<TelnyxMock>,
    Path((call_id, action)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    state.requests.lock().unwrap().push(CapturedRequest {
        path: format!("{call_id}/{action}"),
        authorization: bearer(&headers),
        body,
    });
    if action == "send_dtmf" && state.dtmf_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
        telnyx_rate_limited()
    } else {
        Json(json!({"data":{"result":"ok"}})).into_response()
    }
}

async fn spawn_telnyx_mock() -> (TelnyxMock, String, tokio::task::JoinHandle<()>) {
    let state = TelnyxMock::default();
    let app = Router::new()
        .route("/v2/calls", post(telnyx_dial))
        .route("/v2/calls/:call_id/actions/:action", post(telnyx_action))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (state, format!("http://{address}/v2"), server)
}

fn provider_configs(
    base_url: String,
    media_sip_port: u16,
    webhook_public_key: String,
) -> ProviderConfigs {
    ProviderConfigs {
        twilio: None,
        telnyx: Some(TelnyxConfig {
            account_profile: PROFILE.into(),
            api_key: SecretRef::new(API_KEY),
            connection_id: CONNECTION_ID.into(),
            webhook_public_key: SecretRef::new(webhook_public_key),
            from: "+12065550100".into(),
            media_sip_authority: format!("127.0.0.1:{media_sip_port}"),
            media_sip_username: DIGEST_USER.into(),
            media_sip_password: SecretRef::new(DIGEST_PASSWORD),
            media_sip_realm: DIGEST_REALM.into(),
            // The Vapi ingress remains SIPS/TLS from the host's routable
            // address. The local Telnyx peer uses 127.0.0.1 over UDP
            // so the listener proves Digest identity instead of matching
            // Vapi's trusted CIDR. SRTP remains mandatory on this media leg.
            media_sip_transport: "UDP".into(),
            webhook_url: Some("https://bridgefu.invalid/v1/providers/telnyx/webhooks".into()),
            base_url,
            request_timeout_ms: 2_000,
            max_retries: 1,
        }),
        vonage: None,
    }
}

async fn call_runtime(configs: &ProviderConfigs) -> Arc<CallServiceRuntime> {
    let worker = WorkerId::new();
    let mut coordination = CallServiceCoordinationConfig::new(
        DeploymentId::parse("telnyx-destination-qualification").unwrap(),
    );
    coordination.worker_lease_ttl = Duration::from_secs(300);
    coordination.worker_renew_interval = Duration::from_secs(100);
    Arc::new(
        build_call_service_runtime(
            CallServiceRuntimeConfig {
                backend: CallRepositoryBackendConfig::Memory,
                worker_id: worker,
                max_calls: 4,
                worker_capabilities: BTreeSet::from([
                    "sip".into(),
                    "sip_egress".into(),
                    "webrtc".into(),
                    "telnyx".into(),
                ]),
                control_key: vec![0x74; 32],
                timeouts: CallTimeoutPolicy {
                    setup: Duration::from_secs(20),
                    media_idle: Duration::from_secs(20),
                    transfer: Duration::from_secs(20),
                    ending: Duration::from_secs(10),
                },
                coordination,
            },
            Arc::new(
                configs
                    .attachment_principal_resolver(&[TENANT.into()])
                    .with_vapi_ingress(
                        VAPI_INGRESS_PROFILE,
                        VAPI_INGRESS_PROFILE_REVISION,
                        vapi_ingress_principal(),
                    ),
            ),
            Arc::new(SystemCallServiceClock),
        )
        .await
        .unwrap(),
    )
}

fn route_binding(route: &str) -> NamedRouteBinding {
    NamedRouteBinding::new_with_profiles(
        route,
        None,
        vec![NamedProfileBinding::new(
            NamedProfileRole::Destination,
            NamedProfileKind::Telnyx,
            PROFILE,
            PROFILE_REVISION,
        )
        .unwrap()],
    )
    .unwrap()
}

fn managed_route_binding(route: &str, correlation_id: &str) -> NamedRouteBinding {
    NamedRouteBinding::new_with_profiles(
        route,
        Some(NamedRouteCallContext {
            correlation_id: correlation_id.into(),
            metadata: BTreeMap::from([
                ("account_tier".into(), "gold".into()),
                ("must_not_forward".into(), "private".into()),
            ]),
        }),
        vec![
            NamedProfileBinding::new(
                NamedProfileRole::Ingress,
                NamedProfileKind::VapiIngress,
                VAPI_INGRESS_PROFILE,
                VAPI_INGRESS_PROFILE_REVISION,
            )
            .unwrap(),
            NamedProfileBinding::new(
                NamedProfileRole::Destination,
                NamedProfileKind::Telnyx,
                PROFILE,
                PROFILE_REVISION,
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

fn route_input(webrtc_ingress: bool) -> CreateCallInput {
    let ingress = if webrtc_ingress {
        LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
            signaling_uri: None,
        })
    } else {
        LegEndpointConfig::Sip(SipEndpointConfig {
            uri: None,
            initial_context: SipInitialContextMode::None,
        })
    };
    CreateCallInput {
        tenant_id: None,
        legs: [
            RequestedLeg {
                direction: LegDirection::Inbound,
                signaling_initiator: Some(SignalingInitiator::Remote),
                media_flow: MediaFlow::SendReceive,
                endpoint: ingress,
                amazon_connect_start: None,
            },
            RequestedLeg {
                direction: LegDirection::Outbound,
                signaling_initiator: Some(SignalingInitiator::Bridgefu),
                media_flow: MediaFlow::SendReceive,
                endpoint: LegEndpointConfig::Provider(ProviderEndpointConfig {
                    provider: ProviderKind::Telnyx,
                    account_profile: PROFILE.into(),
                    destination: Some(DESTINATION.into()),
                }),
                amazon_connect_start: None,
            },
        ],
    }
}

async fn wait_for_call(
    runtime: &CallServiceRuntime,
    call_id: CallId,
    predicate: impl Fn(&bridgefu::call_service::StoredServiceCall) -> bool,
) -> bridgefu::call_service::StoredServiceCall {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let stored = runtime
                .service_repository()
                .load_service_call(&TenantId::parse(TENANT).unwrap(), call_id)
                .await
                .unwrap();
            if predicate(&stored) {
                return stored;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("call {call_id} state deadline"))
}

async fn wait_for_orchestrator_idle(orchestrator: &Orchestrator) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                orchestrator.capacity_report(),
                Event::CapacityReport {
                    active_connections: 0,
                    active_bridges: 0,
                    admission_in_use: 0,
                    ..
                }
            ) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("orchestrator retained connections, bridges, or admission");
}

async fn audio_stream(
    adapter: &dyn ConnectionAdapter,
    connection_id: &ConnectionId,
) -> Arc<dyn MediaStream> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(Some(stream)) = adapter.streams(connection_id.clone()).await.map(|streams| {
                streams
                    .into_iter()
                    .find(|stream| stream.kind() == StreamKind::Audio)
            }) {
                return stream;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("audio stream deadline")
}

async fn send_encoded(
    stream: &Arc<dyn MediaStream>,
    payload: bytes::Bytes,
    payload_type: u8,
    timestamp: u32,
    timestamp_step: u32,
) {
    for offset in 0..8 {
        stream
            .frames_out()
            .send(MediaFrame {
                stream_id: stream.id(),
                kind: StreamKind::Audio,
                payload: payload.clone(),
                timestamp_rtp: timestamp + offset * timestamp_step,
                captured_at: Utc::now(),
                payload_type: Some(payload_type),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn next_dtmf(
    events: &mut mpsc::Receiver<AdapterEvent>,
    connection_id: &ConnectionId,
) -> (String, u32) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await {
                Some(AdapterEvent::Dtmf {
                    connection_id: observed,
                    digits,
                    duration_ms,
                }) if &observed == connection_id => return (digits, duration_ms),
                Some(_) => {}
                None => panic!("adapter events closed before DTMF"),
            }
        }
    })
    .await
    .expect("DTMF deadline")
}

struct BrowserCall {
    call_id: CallId,
    provider_leg: bridgefu::call_engine::LegId,
    browser: Arc<WebRtcAdapter>,
    browser_events: mpsc::Receiver<AdapterEvent>,
    browser_connection: ConnectionId,
}

async fn start_browser_call(
    runtime: &CallServiceRuntime,
    bridge_address: SocketAddr,
    trust: Arc<WebRtcTlsClientTrust>,
) -> BrowserCall {
    let created = runtime
        .service()
        .create_named_route_call(
            &owner(),
            &IdempotencyKey::parse("telnyx-direct-browser").unwrap(),
            route_input(true),
            route_binding("telnyx-direct"),
        )
        .await
        .unwrap();
    let source = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Inbound)
        .unwrap();
    let provider_leg = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Outbound)
        .unwrap()
        .leg_id;
    let token = source.attachment.as_ref().unwrap().token.clone();
    let browser = WebRtcAdapter::new(WebRtcConfig::loopback());
    let browser_events = browser.subscribe_events();
    let endpoint = format!("wss://localhost:{}/signal", bridge_address.port());
    let context = WebRtcOriginateContext::websocket(
        &endpoint,
        WebRtcTargetPolicy::default()
            .allow_port(bridge_address.port())
            .allow_loopback(true)
            .with_timeouts(Duration::from_secs(3), Duration::from_secs(15))
            .unwrap(),
    )
    .unwrap()
    .with_bearer_provider(Arc::new(StaticWebRtcBearerCredentialProvider::new(
        WebRtcBearerCredential::new(token).unwrap(),
    )))
    .with_preopened_data_channel(CONTEXT_LABEL, DataReliability::ReliableOrdered)
    .unwrap()
    .require_remote_admission_ready()
    .unwrap()
    .with_tls_trust(trust);
    let connection = browser
        .originate(
            OriginateRequest::new(
                SessionId::new(),
                ParticipantId::new(),
                endpoint,
                Direction::Outbound,
                browser.capabilities(),
            )
            .with_context(context),
        )
        .await
        .unwrap()
        .connection
        .id;
    let activation = {
        let browser = Arc::clone(&browser);
        let connection = connection.clone();
        tokio::spawn(async move { browser.activate_outbound(connection).await })
    };
    let mut initial = ContextEnvelope::new(
        "direct-browser-to-telnyx-correlation",
        TENANT,
        created.value.call.call_id.to_string(),
        source.leg_id.to_string(),
    );
    initial
        .metadata
        .insert("account_tier".into(), "gold".into());
    initial
        .metadata
        .insert("must_not_forward".into(), "private".into());
    browser
        .send_data_message(connection.clone(), initial.to_data_message().unwrap())
        .await
        .unwrap();
    let activation = bounded("direct browser attachment activation", activation)
        .await
        .expect("direct browser activation task");
    if let Err(error) = activation {
        let stored = runtime
            .service_repository()
            .load_service_call(
                &TenantId::parse(TENANT).unwrap(),
                created.value.call.call_id,
            )
            .await
            .unwrap();
        panic!(
            "direct browser attachment failed after initial context admission: {}; call={:?}; bindings={:?}",
            rvoip_error_detail(&error),
            stored.call.aggregate,
            stored.call.bindings,
        );
    }
    BrowserCall {
        call_id: created.value.call.call_id,
        provider_leg,
        browser,
        browser_events,
        browser_connection: connection,
    }
}

struct SipSourceCall {
    call_id: CallId,
    provider_leg: LegId,
    source_connection: ConnectionId,
    activation: tokio::task::JoinHandle<rvoip_core::Result<()>>,
}

async fn start_vapi_call(
    runtime: &CallServiceRuntime,
    bridge_udp: SocketAddr,
    bridge_tls: SocketAddr,
    source: &Arc<SipAdapter>,
    untrusted_source: &Arc<SipAdapter>,
    http: &TelnyxMock,
) -> SipSourceCall {
    let created = runtime
        .service()
        .create_named_route_call(
            &owner(),
            &IdempotencyKey::parse("telnyx-vapi-sips").unwrap(),
            route_input(false),
            managed_route_binding("telnyx-vapi", "vapi-to-telnyx-correlation"),
        )
        .await
        .unwrap();
    let inbound = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Inbound)
        .unwrap();
    let provider_leg = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Outbound)
        .unwrap()
        .leg_id;
    let token = inbound.attachment.as_ref().unwrap().token.clone();
    let dial_count_before_probe = http
        .snapshot()
        .iter()
        .filter(|request| request.path == "calls")
        .count();
    let untrusted_target = format!("sip:{token}@{}:{}", bridge_udp.ip(), bridge_udp.port());
    let untrusted_context = SipOriginateContext::new()
        .with_from_uri("sip:untrusted-vapi-probe@127.0.0.1")
        .unwrap();
    let untrusted_connection = untrusted_source
        .originate(
            OriginateRequest::new(
                SessionId::new(),
                ParticipantId::new(),
                untrusted_target,
                Direction::Outbound,
                untrusted_source.capabilities(),
            )
            .with_transport(Transport::Sip)
            .with_context(untrusted_context),
        )
        .await
        .unwrap()
        .connection
        .id;
    let untrusted_activation = bounded(
        "outside-CIDR Vapi attachment rejection",
        untrusted_source.activate_outbound(untrusted_connection.clone()),
    )
    .await;
    assert!(
        untrusted_activation.is_err(),
        "an unauthenticated peer outside the Vapi CIDR consumed the attachment"
    );
    let _ = untrusted_source
        .end(untrusted_connection, EndReason::Cancelled)
        .await;
    assert_eq!(
        http.snapshot()
            .iter()
            .filter(|request| request.path == "calls")
            .count(),
        dial_count_before_probe,
        "an outside-CIDR probe triggered Telnyx destination I/O"
    );
    let target = format!(
        "sips:{token}@{}:{};transport=tls",
        bridge_tls.ip(),
        bridge_tls.port()
    );
    let context = SipOriginateContext::new()
        .with_from_uri("sips:vapi-widget@localhost;transport=tls")
        .unwrap()
        // Deliberately conflict with the durable route context. Provider
        // client_state must retain the server-owned correlation and tier.
        .with_initial_headers(
            SipInitialHeaders::new([
                ("X-Correlation-Id", "untrusted-vapi-correlation"),
                ("X-Account-Tier", "untrusted-tier"),
            ])
            .unwrap(),
        );
    let connection = source
        .originate(
            OriginateRequest::new(
                SessionId::new(),
                ParticipantId::new(),
                target,
                Direction::Outbound,
                source.capabilities(),
            )
            .with_transport(Transport::Sip)
            .with_context(context),
        )
        .await
        .unwrap()
        .connection
        .id;
    let activation = {
        let source = Arc::clone(source);
        let connection = connection.clone();
        tokio::spawn(async move { source.activate_outbound(connection).await })
    };
    SipSourceCall {
        call_id: created.value.call.call_id,
        provider_leg,
        source_connection: connection,
        activation,
    }
}

async fn originate_telnyx_media(
    adapter: &Arc<SipAdapter>,
    target: &str,
) -> rvoip_core::Result<ConnectionId> {
    let context = SipOriginateContext::new()
        .with_from_uri("sip:telnyx-media@127.0.0.1")
        .unwrap()
        .with_auth(SipClientAuth::digest(DIGEST_USER, DIGEST_PASSWORD))
        .unwrap();
    let connection = adapter
        .originate(
            OriginateRequest::new(
                SessionId::new(),
                ParticipantId::new(),
                target,
                Direction::Outbound,
                adapter.capabilities(),
            )
            .with_transport(Transport::Sip)
            .with_context(context),
        )
        .await?
        .connection
        .id;
    adapter.activate_outbound(connection.clone()).await?;
    Ok(connection)
}

fn rvoip_error_detail(error: &rvoip_core::RvoipError) -> String {
    match error {
        rvoip_core::RvoipError::Adapter(detail) => format!("adapter:{detail}"),
        rvoip_core::RvoipError::NotImplemented(detail) => {
            format!("not-implemented:{detail}")
        }
        rvoip_core::RvoipError::AdmissionRejected(detail) => {
            format!("admission-rejected:{detail}")
        }
        rvoip_core::RvoipError::InvalidState(detail) => format!("invalid-state:{detail}"),
        rvoip_core::RvoipError::UnsupportedCodec(codec) => format!("unsupported-codec:{codec}"),
        other => other.diagnostic_class().to_owned(),
    }
}

fn decoded_dial_state(request: &CapturedRequest) -> ProviderDialClientState {
    telnyx::calls::client_state::decode_json(
        request.body["client_state"]
            .as_str()
            .expect("Telnyx dial carries client_state"),
    )
    .expect("Telnyx dial client_state is valid")
}

fn captured_dial_client_state(
    requests: &[CapturedRequest],
    call: usize,
    role: ProviderDialRole,
) -> String {
    let dials: Vec<_> = requests
        .iter()
        .filter(|request| request.path == "calls")
        .collect();
    let offset = match role {
        ProviderDialRole::Media => 0,
        ProviderDialRole::Destination => 1,
    };
    dials[(call - 1) * 2 + offset].body["client_state"]
        .as_str()
        .expect("Telnyx dial carries client_state")
        .to_owned()
}

fn assert_two_dials(
    requests: &[CapturedRequest],
    call: usize,
    expected_correlation: &str,
) -> String {
    let dials: Vec<_> = requests
        .iter()
        .filter(|request| request.path == "calls")
        .collect();
    assert!(dials.len() >= call * 2);
    let media = dials[(call - 1) * 2];
    let destination = dials[(call - 1) * 2 + 1];
    assert_eq!(
        media.authorization.as_deref(),
        Some("Bearer KEY-hermetic-telnyx")
    );
    assert_eq!(media.body["from"], "+12065550100");
    assert_eq!(media.body["connection_id"], CONNECTION_ID);
    assert_eq!(media.body["sip_auth_username"], DIGEST_USER);
    assert_eq!(media.body["sip_auth_password"], DIGEST_PASSWORD);
    assert_eq!(media.body["sip_transport_protocol"], "UDP");
    assert!(media.body.get("link_to").is_none());
    assert!(media.body.get("bridge_on_answer").is_none());
    let media_state = decoded_dial_state(media);
    assert_eq!(media_state.role(), ProviderDialRole::Media);
    assert_eq!(media_state.correlation_id(), Some(expected_correlation));
    assert_eq!(
        media_state
            .metadata()
            .get("account_tier")
            .map(String::as_str),
        Some("gold")
    );
    assert!(!media_state.metadata().contains_key("must_not_forward"));
    assert_eq!(
        destination.authorization.as_deref(),
        Some("Bearer KEY-hermetic-telnyx")
    );
    assert_eq!(destination.body["to"], DESTINATION);
    assert_eq!(destination.body["from"], "+12065550100");
    assert_eq!(destination.body["connection_id"], CONNECTION_ID);
    assert_eq!(destination.body["link_to"], format!("telnyx-media-{call}"));
    assert_eq!(destination.body["bridge_on_answer"], true);
    assert_ne!(media.body["command_id"], destination.body["command_id"]);
    let destination_state = decoded_dial_state(destination);
    assert_eq!(destination_state.role(), ProviderDialRole::Destination);
    assert_eq!(
        destination_state.correlation_id(),
        Some(expected_correlation)
    );
    assert_eq!(destination_state.metadata(), media_state.metadata());
    assert!(!destination_state
        .metadata()
        .contains_key("must_not_forward"));
    media.body["to"].as_str().unwrap().to_owned()
}

fn signed_webhook(
    key: &ring::signature::Ed25519KeyPair,
    event_id: &str,
    event_type: &str,
    provider_call_id: &str,
    client_state: &str,
) -> WebhookRequest {
    let body = serde_json::to_vec(&json!({
        "data": {
            "id": event_id,
            "event_type": event_type,
            "occurred_at": Utc::now().to_rfc3339(),
            "payload": {
                "call_control_id": provider_call_id,
                "connection_id": CONNECTION_ID,
                "client_state": client_state,
                "hangup_cause": "normal_clearing"
            }
        }
    }))
    .unwrap();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    let mut signed = timestamp.as_bytes().to_vec();
    signed.push(b'|');
    signed.extend_from_slice(&body);
    WebhookRequest {
        url: "https://bridgefu.invalid/v1/providers/telnyx/webhooks".into(),
        headers: BTreeMap::from([
            (
                telnyx::webhooks::SIGNATURE_HEADER.into(),
                base64::engine::general_purpose::STANDARD.encode(key.sign(&signed)),
            ),
            (telnyx::webhooks::TIMESTAMP_HEADER.into(), timestamp),
        ]),
        content_type: "application/json".into(),
        body,
    }
}

async fn wait_for_destination_reference(
    runtime: &CallServiceRuntime,
    call_id: CallId,
    provider_leg: LegId,
) -> ProviderCallId {
    let tenant = TenantId::parse(TENANT).unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let reference = runtime
                .service_repository()
                .load_external_reference_by_role(
                    &tenant,
                    call_id,
                    provider_leg,
                    ProviderReferenceRole::Destination,
                )
                .await
                .unwrap();
            if let Some(reference) = reference {
                match reference.value {
                    ExternalReferenceValue::ProviderCall {
                        provider_call_id, ..
                    } => return provider_call_id,
                    ExternalReferenceValue::Signaling { .. } => {
                        panic!("Telnyx destination retained a signaling reference")
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Telnyx destination reference deadline")
}

async fn wait_for_destination_reference_for_binding(
    runtime: &CallServiceRuntime,
    call_id: CallId,
    provider_leg: LegId,
    binding_generation: BindingGeneration,
) -> ProviderCallId {
    let tenant = TenantId::parse(TENANT).unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let reference = runtime
                .service_repository()
                .load_external_reference_for_binding(
                    &tenant,
                    call_id,
                    provider_leg,
                    binding_generation,
                    ProviderReferenceRole::Destination,
                )
                .await
                .unwrap();
            if let Some(reference) = reference {
                match reference.value {
                    ExternalReferenceValue::ProviderCall {
                        provider_call_id, ..
                    } => return provider_call_id,
                    ExternalReferenceValue::Signaling { .. } => {
                        panic!("Telnyx destination retained a signaling reference")
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Telnyx binding-generation destination reference deadline")
}

async fn accept_signed_provider_event(
    runtime: &CallServiceRuntime,
    provider: &dyn bridgefu::providers::ProviderControl,
    webhook_key: &ring::signature::Ed25519KeyPair,
    event_id: &str,
    event_type: &str,
    provider_call_id: &ProviderCallId,
    client_state: &str,
) {
    let webhook = signed_webhook(
        webhook_key,
        event_id,
        event_type,
        provider_call_id.expose_secret(),
        client_state,
    );
    let normalized = provider.verify_webhook(&webhook).unwrap();
    assert_eq!(normalized.event_type, event_type);
    assert!(matches!(
        runtime
            .repository()
            .ingest_provider_event(provider_event_input(provider, normalized))
            .await
            .unwrap(),
        ProviderEventOutcome::Accepted(_)
    ));
}

fn provider_event_input(
    provider: &dyn bridgefu::providers::ProviderControl,
    event: bridgefu::providers::NormalizedProviderEvent,
) -> ProviderEventInput {
    let event_digest: [u8; 32] = Sha256::digest(event.event_id.as_bytes()).into();
    let payload = serde_json::to_vec(&event.raw).unwrap();
    let payload_digest: [u8; 32] = Sha256::digest(&payload).into();
    ProviderEventInput {
        account: provider.account_key(),
        event_digest: ProviderEventDigest::new(event_digest),
        payload_digest: ProviderPayloadDigest::new(payload_digest),
        provider_call_id: ProviderCallId::parse(event.provider_call_id.unwrap()).unwrap(),
        kind: event.event_type,
        payload: event.raw,
        occurred_at: event.occurred_at.map(|value| {
            DateTime::parse_from_rfc3339(&value)
                .unwrap()
                .with_timezone(&Utc)
        }),
        received_at: Utc::now(),
    }
}

#[test]
fn both_ingress_modes_reach_telnyx_full_duplex_with_control_callbacks_and_exact_cleanup() {
    let _serial = TELNYX_QUALIFICATION_TEST_LOCK.lock().unwrap();
    std::thread::Builder::new()
        .name("telnyx-network-qualification".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(6)
                .thread_stack_size(8 * 1024 * 1024)
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(run_telnyx_qualification()));
        })
        .unwrap()
        .join()
        .expect("Telnyx network qualification panicked");
}

async fn run_telnyx_qualification() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (http, base_url, http_server) = spawn_telnyx_mock().await;
    let random = ring::rand::SystemRandom::new();
    let encoded = ring::signature::Ed25519KeyPair::generate_pkcs8(&random).unwrap();
    let webhook_key = ring::signature::Ed25519KeyPair::from_pkcs8(encoded.as_ref()).unwrap();

    let vapi_ip = routable_local_ipv4();
    let sip_tls = sip_tls_files_for(vapi_ip);
    let bridge_udp = reserve_udp();
    let bridge_tls = reserve_tcp_on(vapi_ip);
    let configs = provider_configs(
        base_url,
        bridge_udp.port(),
        base64::engine::general_purpose::STANDARD.encode(webhook_key.public_key().as_ref()),
    );
    let registry = ProviderRegistry::from_config(&configs).unwrap();
    let runtime = call_runtime(&configs).await;
    let orchestrator = Orchestrator::new(CoreConfig::default());

    let bridge_web = WebRtcAdapter::new_with_inbound_admission_confirmation(
        WebRtcConfig::loopback(),
        Duration::from_secs(10),
    )
    .unwrap();
    let mut bridge_sip_config = tls_sip_config(
        "bridgefu-telnyx-edge",
        bridge_udp,
        bridge_tls,
        &sip_tls,
        vec![0, 101],
    );
    bridge_sip_config.local_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    bridge_sip_config.sip_advertised_addr = Some(bridge_udp);
    bridge_sip_config.tls_advertised_addr = Some(bridge_tls);
    // Let rvoip generate a transport-correct Contact. A single static SIPS
    // Contact would make the UDP Telnyx dialog send its 2xx ACK to the TLS
    // listener, while the Vapi leg still requires the TLS Contact.
    bridge_sip_config.contact_uri = None;
    let sip_auth =
        SipAuthService::digest(DIGEST_REALM).with_digest_user(DIGEST_USER, DIGEST_PASSWORD);
    let bridge_sip_policy = SipListenerAuthPolicy::authenticated_for_tenant(TENANT, sip_auth)
        .unwrap()
        .with_trusted_cidr(
            format!("{vapi_ip}/32").parse().unwrap(),
            vapi_ingress_principal(),
        );
    let bridge_sip_coordinator =
        rvoip_sip::UnifiedCoordinator::new_with_listener_auth(bridge_sip_config, bridge_sip_policy)
            .await
            .unwrap_or_else(|error| panic!("Bridgefu SIP edge config: {error}"));
    let bridge_sip = SipAdapter::new_with_inbound_context_policy(
        Arc::clone(&bridge_sip_coordinator),
        SipInboundContextPolicy::new(["X-Correlation-Id", "X-Account-Tier"]).unwrap(),
    )
    .await
    .unwrap();
    let authenticated_sip_principals = Arc::new(Mutex::new(Vec::new()));
    let sip_principal_observer = {
        let principals = Arc::clone(&authenticated_sip_principals);
        let mut events = bridge_sip_coordinator.events().await.unwrap();
        tokio::spawn(async move {
            while let Some(event) = events.next().await {
                if let SipEvent::IncomingCallAuthenticated { principal, .. } = event {
                    principals.lock().unwrap().push(principal);
                }
            }
        })
    };

    let supervisor = CallExecutionSupervisor::install_with_leg_executors_and_context_policy(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        Arc::new(registry.clone()),
        None,
        Arc::new(ContextPolicy {
            allow_headers: BTreeMap::from([
                ("X-Correlation-Id".into(), "correlation_id".into()),
                ("X-Account-Tier".into(), "account_tier".into()),
            ]),
            ..ContextPolicy::default()
        }),
        8,
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    orchestrator
        .register(Arc::clone(&bridge_web) as Arc<dyn ConnectionAdapter>)
        .unwrap();
    orchestrator
        .register(Arc::clone(&bridge_sip) as Arc<dyn ConnectionAdapter>)
        .unwrap();

    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let web_certificate = generated.cert.pem().into_bytes();
    let web_key = generated.signing_key.serialize_pem().into_bytes();
    let web_tls = TlsConfig::from_pem_bytes(&web_certificate, &web_key)
        .await
        .unwrap();
    let web_trust = Arc::new(WebRtcTlsClientTrust::from_pem(&web_certificate).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_web_address = listener.local_addr().unwrap();
    let (web_shutdown_tx, web_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let web_listener = {
        let adapter = Arc::clone(&bridge_web);
        let auth: Arc<dyn WsAuthHook> = Arc::new(AttachmentAuth {
            principal: owner().authenticated().clone(),
        });
        tokio::spawn(async move {
            serve_tls_listener_with_auth_and_shutdown(listener, web_tls, adapter, auth, async {
                let _ = web_shutdown_rx.await;
            })
            .await
        })
    };

    // The test Telnyx media UA signals over IPv4 loopback, so it cannot
    // inherit the Vapi host-IPv4 trusted-CIDR identity and must answer the Digest
    // challenge. RTP remains IPv4 to exercise the ordinary media path.
    let telnyx_media_udp = reserve_udp();
    let mut media_config = SipConfig::local("telnyx-media-peer", telnyx_media_udp.port());
    media_config.local_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    media_config.bind_addr = telnyx_media_udp;
    media_config.sip_advertised_addr = Some(telnyx_media_udp);
    media_config.local_uri = format!("sip:telnyx-media@127.0.0.1:{}", telnyx_media_udp.port());
    media_config.contact_uri = Some(media_config.local_uri.clone());
    media_config.offered_codecs = vec![0, 101];
    media_config.offer_srtp = true;
    media_config.srtp_required = true;
    let telnyx_media_coordinator = rvoip_sip::UnifiedCoordinator::new(media_config)
        .await
        .unwrap();
    let telnyx_media = SipAdapter::new(Arc::clone(&telnyx_media_coordinator))
        .await
        .unwrap();
    let mut telnyx_media_events = telnyx_media.subscribe_events();

    assert!(http.snapshot().is_empty());
    let mut browser =
        start_browser_call(&runtime, bridge_web_address, Arc::clone(&web_trust)).await;
    let requests = http.wait_for(1).await;
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.path == "calls")
            .count(),
        1,
        "destination dial started before the provider SIP attachment"
    );
    let first_target = requests[0].body["to"].as_str().unwrap().to_owned();
    let first_media_connection = match originate_telnyx_media(&telnyx_media, &first_target).await {
        Ok(connection) => connection,
        Err(error) => {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let stored = runtime
                .service_repository()
                .load_service_call(&TenantId::parse(TENANT).unwrap(), browser.call_id)
                .await
                .unwrap();
            panic!(
                "authenticated Telnyx media attachment failed: {}; call={:?}; bindings={:?}; principals={:?}",
                rvoip_error_detail(&error),
                stored.call.aggregate,
                stored.call.bindings,
                authenticated_sip_principals.lock().unwrap()
            );
        }
    };
    let requests = http.wait_for(2).await;
    let first_destination_state =
        captured_dial_client_state(&requests, 1, ProviderDialRole::Destination);
    assert_eq!(
        assert_two_dials(&requests, 1, "direct-browser-to-telnyx-correlation"),
        first_target
    );
    let provider = registry.get("telnyx").unwrap();
    let first_destination =
        wait_for_destination_reference(&runtime, browser.call_id, browser.provider_leg).await;
    assert_eq!(first_destination.expose_secret(), "telnyx-destination-1");
    accept_signed_provider_event(
        &runtime,
        provider.as_ref(),
        &webhook_key,
        "telnyx-event-bridged-1",
        "call.bridged",
        &first_destination,
        &first_destination_state,
    )
    .await;
    wait_for_call(&runtime, browser.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;

    let browser_stream = audio_stream(browser.browser.as_ref(), &browser.browser_connection).await;
    let provider_stream = audio_stream(telnyx_media.as_ref(), &first_media_connection).await;
    assert_eq!(browser_stream.codec().name.to_ascii_lowercase(), "opus");
    assert_eq!(
        provider_stream.codec().name.to_ascii_lowercase(),
        "g.711-mu"
    );
    let mut browser_audio = browser_stream.try_frames_in().unwrap();
    let mut provider_audio = provider_stream.try_frames_in().unwrap();
    send_encoded(
        &browser_stream,
        rvoip_webrtc::media::silent_opus_payload(),
        111,
        9_600,
        960,
    )
    .await;
    let at_provider = bounded("browser Opus to Telnyx PCMU", provider_audio.recv())
        .await
        .unwrap();
    assert_eq!(at_provider.payload_type, Some(0));
    assert_eq!(at_provider.payload.len(), 160);
    send_encoded(
        &provider_stream,
        bytes::Bytes::from(vec![0xff; 160]),
        0,
        16_000,
        160,
    )
    .await;
    let at_browser = bounded("Telnyx PCMU to browser Opus", browser_audio.recv())
        .await
        .unwrap();
    assert_eq!(at_browser.payload_type, Some(111));
    assert!(!at_browser.payload.is_empty());

    browser
        .browser
        .send_dtmf(browser.browser_connection.clone(), "6", 120)
        .await
        .unwrap();
    assert_eq!(
        next_dtmf(&mut telnyx_media_events, &first_media_connection)
            .await
            .0,
        "6"
    );
    telnyx_media
        .send_dtmf(first_media_connection.clone(), "3", 140)
        .await
        .unwrap();
    assert_eq!(
        next_dtmf(&mut browser.browser_events, &browser.browser_connection)
            .await
            .0,
        "3"
    );

    runtime
        .service()
        .send_dtmf(
            &owner(),
            browser.call_id,
            &IdempotencyKey::parse("telnyx-provider-dtmf-retry").unwrap(),
            DtmfCallInput {
                tenant_id: None,
                leg_id: browser.provider_leg,
                digits: "12#".into(),
                duration_ms: 120,
                gap_ms: 70,
            },
        )
        .await
        .unwrap();
    let requests = http.wait_for(4).await;
    let dtmf: Vec<_> = requests
        .iter()
        .filter(|request| request.path == "telnyx-media-1/send_dtmf")
        .collect();
    assert_eq!(dtmf.len(), 2, "429 must produce one bounded SDK retry");
    assert_eq!(dtmf[0].body, dtmf[1].body, "retry changed the command body");
    assert_eq!(dtmf[0].body["digits"], "12#");

    browser
        .browser
        .end(browser.browser_connection.clone(), EndReason::Normal)
        .await
        .unwrap();
    wait_for_call(&runtime, browser.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    let requests = http.wait_for(5).await;
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.path == "telnyx-media-1/hangup")
            .count(),
        1
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        while telnyx_media.is_connection_live(&first_media_connection) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("source hangup retained Telnyx SIP media");
    wait_for_orchestrator_idle(&orchestrator).await;

    // The exact already-consumed media attachment cannot be rebound to a new
    // SIP dialog and cannot create a third Telnyx dial.
    let replay_context = SipOriginateContext::new()
        .with_from_uri("sip:telnyx-media@127.0.0.1")
        .unwrap()
        .with_auth(SipClientAuth::digest(DIGEST_USER, DIGEST_PASSWORD))
        .unwrap();
    let replay = telnyx_media
        .originate(
            OriginateRequest::new(
                SessionId::new(),
                ParticipantId::new(),
                first_target,
                Direction::Outbound,
                telnyx_media.capabilities(),
            )
            .with_transport(Transport::Sip)
            .with_context(replay_context),
        )
        .await
        .unwrap()
        .connection
        .id;
    let replay_activation = telnyx_media.activate_outbound(replay.clone()).await;
    if replay_activation.is_ok() {
        tokio::time::timeout(Duration::from_secs(5), async {
            while telnyx_media.is_connection_live(&replay) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("consumed Telnyx attachment replay remained live");
    }
    assert_eq!(
        http.snapshot()
            .iter()
            .filter(|request| request.path == "calls")
            .count(),
        2
    );
    assert!(runtime
        .service_repository()
        .load_service_call(&TenantId::parse(TENANT).unwrap(), browser.call_id)
        .await
        .unwrap()
        .call
        .aggregate
        .state()
        .is_terminal());
    let _ = telnyx_media.end(replay, EndReason::Cancelled).await;

    let source_sip_udp = reserve_udp_on(vapi_ip);
    let source_sip_tls = reserve_tcp_on(vapi_ip);
    let mut source_config = tls_sip_config(
        "vapi-telnyx-source",
        source_sip_udp,
        source_sip_tls,
        &sip_tls,
        vec![0, 101],
    );
    source_config.local_ip = IpAddr::V4(vapi_ip);
    source_config.sip_advertised_addr = Some(source_sip_udp);
    source_config.tls_advertised_addr = Some(source_sip_tls);
    source_config.contact_uri = Some(format!(
        "sips:vapi-telnyx-source@{}:{};transport=tls",
        vapi_ip,
        source_sip_tls.port(),
    ));
    let source_coordinator = rvoip_sip::UnifiedCoordinator::new(source_config)
        .await
        .unwrap();
    let source_sip = SipAdapter::new(Arc::clone(&source_coordinator))
        .await
        .unwrap();
    let mut source_events = source_sip.subscribe_events();

    let mut vapi = start_vapi_call(
        &runtime,
        bridge_udp,
        bridge_tls,
        &source_sip,
        &telnyx_media,
        &http,
    )
    .await;
    let mut vapi_activation_completed = false;
    let requests = tokio::select! {
        requests = http.wait_for(6) => requests,
        activation = &mut vapi.activation => {
            let activation = activation.expect("Vapi SIPS activation task panicked");
            if let Err(error) = activation {
                panic!(
                    "Vapi SIPS activation failed before the Telnyx media dial: {}",
                    rvoip_error_detail(&error)
                );
            }
            // The SIP adapter may report that its outbound activation command
            // was accepted before Bridgefu sends the final answer. Preserve
            // that completed result and continue to the peer-visible dial
            // and aggregate-state assertions below.
            vapi_activation_completed = true;
            http.wait_for(6).await
        }
    };
    let dials: Vec<_> = requests
        .iter()
        .filter(|request| request.path == "calls")
        .collect();
    assert_eq!(dials.len(), 3);
    let second_target = dials[2].body["to"].as_str().unwrap().to_owned();
    assert_ne!(second_target, dials[0].body["to"].as_str().unwrap());
    let second_media_connection = match originate_telnyx_media(&telnyx_media, &second_target).await
    {
        Ok(connection) => connection,
        Err(error) => {
            let stored = runtime
                .service_repository()
                .load_service_call(&TenantId::parse(TENANT).unwrap(), vapi.call_id)
                .await
                .unwrap();
            panic!(
                "second authenticated Telnyx media attachment failed: {}; call={:?}",
                rvoip_error_detail(&error),
                stored.call.aggregate
            );
        }
    };
    let requests = http.wait_for(7).await;
    let second_destination_state =
        captured_dial_client_state(&requests, 2, ProviderDialRole::Destination);
    assert_eq!(
        assert_two_dials(&requests, 2, "vapi-to-telnyx-correlation"),
        second_target
    );
    let second_destination =
        wait_for_destination_reference(&runtime, vapi.call_id, vapi.provider_leg).await;
    assert_eq!(second_destination.expose_secret(), "telnyx-destination-2");
    accept_signed_provider_event(
        &runtime,
        provider.as_ref(),
        &webhook_key,
        "telnyx-event-bridged-2",
        "call.bridged",
        &second_destination,
        &second_destination_state,
    )
    .await;
    if !vapi_activation_completed {
        bounded("Vapi SIPS activation", vapi.activation)
            .await
            .unwrap()
            .unwrap();
    }
    wait_for_call(&runtime, vapi.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let observed = authenticated_sip_principals.lock().unwrap().clone();
            let saw_telnyx_digest = observed.iter().any(|principal| {
                principal.method == AuthenticationMethod::SipDigest
                    && principal.tenant.as_deref() == Some(TENANT)
            });
            let saw_vapi_trusted_cidr = observed.iter().any(|principal| {
                principal.method == AuthenticationMethod::ApiKey
                    && principal.subject == VAPI_INGRESS_SUBJECT
                    && principal.tenant.as_deref() == Some(TENANT)
                    && principal.issuer.as_deref() == Some("telnyx-vapi-ingress-profile")
                    && principal.scopes.len() == 1
                    && principal.scopes[0] == VAPI_INGRESS_SCOPE
            });
            let leaked_control_owner = observed.iter().any(|principal| {
                principal.method == AuthenticationMethod::Jwt
                    && principal.subject == "telnyx-route-owner"
            });
            assert!(
                !leaked_control_owner,
                "the API control principal leaked into SIP transport authentication"
            );
            if saw_telnyx_digest && saw_vapi_trusted_cidr {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("SIP Digest and trusted-CIDR principals were not both observed");

    let vapi_stream = audio_stream(source_sip.as_ref(), &vapi.source_connection).await;
    let second_provider_stream =
        audio_stream(telnyx_media.as_ref(), &second_media_connection).await;
    assert_eq!(vapi_stream.codec().name.to_ascii_lowercase(), "g.711-mu");
    assert_eq!(
        second_provider_stream.codec().name.to_ascii_lowercase(),
        "g.711-mu"
    );
    let mut vapi_audio = vapi_stream.try_frames_in().unwrap();
    let mut second_provider_audio = second_provider_stream.try_frames_in().unwrap();
    send_encoded(
        &vapi_stream,
        bytes::Bytes::from(vec![0xff; 160]),
        0,
        32_000,
        160,
    )
    .await;
    assert_eq!(
        bounded("Vapi PCMU to Telnyx PCMU", second_provider_audio.recv())
            .await
            .unwrap()
            .payload_type,
        Some(0)
    );
    send_encoded(
        &second_provider_stream,
        bytes::Bytes::from(vec![0xff; 160]),
        0,
        48_000,
        160,
    )
    .await;
    assert_eq!(
        bounded("Telnyx PCMU to Vapi PCMU", vapi_audio.recv())
            .await
            .unwrap()
            .payload_type,
        Some(0)
    );
    source_sip
        .send_dtmf(vapi.source_connection.clone(), "7", 120)
        .await
        .unwrap();
    assert_eq!(
        next_dtmf(&mut telnyx_media_events, &second_media_connection)
            .await
            .0,
        "7"
    );
    telnyx_media
        .send_dtmf(second_media_connection.clone(), "9", 140)
        .await
        .unwrap();
    assert_eq!(
        next_dtmf(&mut source_events, &vapi.source_connection)
            .await
            .0,
        "9"
    );

    // A real Ed25519-verified terminal event is ingested twice. The durable
    // repository accepts it once, returns Duplicate for the replay, and the
    // provider-event worker tears down the exact call and both media routes.
    let webhook = signed_webhook(
        &webhook_key,
        "telnyx-event-hangup-2",
        "call.hangup",
        "telnyx-media-2",
        &captured_dial_client_state(&requests, 2, ProviderDialRole::Media),
    );
    let normalized = provider.verify_webhook(&webhook).unwrap();
    assert_eq!(normalized.event_type, "call.hangup");
    let mut invalid = webhook.clone();
    invalid.body.push(b' ');
    assert!(matches!(
        provider.verify_webhook(&invalid),
        Err(ProviderError::InvalidSignature)
    ));
    let input = provider_event_input(provider.as_ref(), normalized);
    assert!(matches!(
        runtime
            .repository()
            .ingest_provider_event(input.clone())
            .await
            .unwrap(),
        ProviderEventOutcome::Accepted(_)
    ));
    assert!(matches!(
        runtime
            .repository()
            .ingest_provider_event(input)
            .await
            .unwrap(),
        ProviderEventOutcome::Duplicate(_)
    ));
    wait_for_call(&runtime, vapi.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while source_sip.is_connection_live(&vapi.source_connection)
            || telnyx_media.is_connection_live(&second_media_connection)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("provider terminal event retained source or media route");
    let requests = http.snapshot();
    assert_eq!(requests.len(), 7);
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.path == "telnyx-media-2/hangup")
            .count(),
        0,
        "a provider-originated terminal callback must not echo a redundant hangup command"
    );
    wait_for_orchestrator_idle(&orchestrator).await;
    assert!(bridge_web.routes().is_empty());
    assert!(browser.browser.routes().is_empty());
    assert!(!bridge_sip.is_connection_live(&first_media_connection));
    assert!(!bridge_sip.is_connection_live(&second_media_connection));
    assert!(!source_sip.is_connection_live(&vapi.source_connection));
    assert!(!telnyx_media.is_connection_live(&first_media_connection));
    assert!(!telnyx_media.is_connection_live(&second_media_connection));

    let _ = web_shutdown_tx.send(());
    bounded("WebRTC listener shutdown", web_listener)
        .await
        .unwrap()
        .unwrap();
    bounded(
        "Telnyx supervisor shutdown",
        supervisor.shutdown(Duration::from_secs(5)),
    )
    .await;
    bridge_sip_coordinator.shutdown();
    source_coordinator.shutdown();
    telnyx_media_coordinator.shutdown();
    sip_principal_observer.abort();
    let _ = sip_principal_observer.await;
    http_server.abort();
    let _ = http_server.await;
}

mod direct_assistant_handoff {
    use super::*;

    struct AssistantFixture {
        coordinator: Arc<rvoip_sip::UnifiedCoordinator>,
        adapter: Arc<SipAdapter>,
        events: mpsc::Receiver<AdapterEvent>,
        sip_events: SipEventReceiver,
        tls_address: SocketAddr,
    }

    async fn assistant_fixture(tls: &TestTlsFiles) -> AssistantFixture {
        let udp_address = reserve_udp();
        let tls_address = reserve_tcp();
        let policy = SipListenerAuthPolicy::authenticated_for_tenant(
            ASSISTANT_PROFILE,
            SipAuthService::digest(ASSISTANT_REALM)
                .with_digest_user(ASSISTANT_USER, ASSISTANT_PASSWORD),
        )
        .unwrap();
        let config = tls_sip_config(
            "telnyx-vapi-like-assistant",
            udp_address,
            tls_address,
            tls,
            vec![0, 101],
        );
        assert!(config.srtp_required);
        let coordinator = rvoip_sip::UnifiedCoordinator::new_with_listener_auth(config, policy)
            .await
            .unwrap();
        let sip_events = coordinator.events().await.unwrap();
        let adapter = SipAdapter::new_with_inbound_context_policy(
            Arc::clone(&coordinator),
            SipInboundContextPolicy::new([
                "X-Correlation-Id",
                "X-Account-Tier",
                "X-Unmapped-Private",
            ])
            .unwrap(),
        )
        .await
        .unwrap();
        let events = adapter.subscribe_events();
        AssistantFixture {
            coordinator,
            adapter,
            events,
            sip_events,
            tls_address,
        }
    }

    struct HandoffHarness {
        http: TelnyxMock,
        http_server: tokio::task::JoinHandle<()>,
        webhook_key: ring::signature::Ed25519KeyPair,
        registry: ProviderRegistry,
        runtime: Arc<CallServiceRuntime>,
        orchestrator: Arc<Orchestrator>,
        bridge_web: Arc<WebRtcAdapter>,
        bridge_sip_coordinator: Arc<rvoip_sip::UnifiedCoordinator>,
        bridge_sip: Arc<SipAdapter>,
        assistant: AssistantFixture,
        telnyx_media_coordinator: Arc<rvoip_sip::UnifiedCoordinator>,
        telnyx_media: Arc<SipAdapter>,
        telnyx_media_events: mpsc::Receiver<AdapterEvent>,
        authenticated_sip_principals: Arc<Mutex<Vec<AuthenticatedPrincipal>>>,
        sip_principal_observer: tokio::task::JoinHandle<()>,
        supervisor: CallExecutionSupervisor,
        web_address: SocketAddr,
        web_trust: Arc<WebRtcTlsClientTrust>,
        web_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
        web_listener: tokio::task::JoinHandle<std::result::Result<(), rvoip_webrtc::WebRtcError>>,
    }

    impl HandoffHarness {
        async fn shutdown(mut self) {
            let _ = self.web_shutdown.take().unwrap().send(());
            bounded("Telnyx handoff WebRTC listener shutdown", self.web_listener)
                .await
                .unwrap()
                .unwrap();
            bounded(
                "Telnyx handoff supervisor shutdown",
                self.supervisor.shutdown(Duration::from_secs(5)),
            )
            .await;
            bounded(
                "Telnyx handoff prepared outbound drain",
                self.orchestrator.drain_prepared_outbound_connections(),
            )
            .await;
            bounded(
                "Telnyx handoff lifecycle drain",
                self.orchestrator.drain_connection_lifecycle_tasks(),
            )
            .await;
            bounded("Telnyx handoff Bridgefu SIP drain", self.bridge_sip.drain())
                .await
                .unwrap();
            bounded(
                "Telnyx handoff assistant SIP drain",
                self.assistant.adapter.drain(),
            )
            .await
            .unwrap();
            bounded("Telnyx handoff media SIP drain", self.telnyx_media.drain())
                .await
                .unwrap();
            bounded(
                "Telnyx handoff Bridgefu SIP coordinator shutdown",
                self.bridge_sip_coordinator
                    .shutdown_gracefully(Some(Duration::from_secs(5))),
            )
            .await
            .unwrap();
            bounded(
                "Telnyx handoff assistant coordinator shutdown",
                self.assistant
                    .coordinator
                    .shutdown_gracefully(Some(Duration::from_secs(5))),
            )
            .await
            .unwrap();
            bounded(
                "Telnyx handoff media coordinator shutdown",
                self.telnyx_media_coordinator
                    .shutdown_gracefully(Some(Duration::from_secs(5))),
            )
            .await
            .unwrap();
            self.sip_principal_observer.abort();
            let _ = self.sip_principal_observer.await;
            self.http_server.abort();
            let _ = self.http_server.await;
            assert_eq!(self.bridge_sip.retained_task_count(), 0);
            assert_eq!(self.assistant.adapter.retained_task_count(), 0);
            assert_eq!(self.telnyx_media.retained_task_count(), 0);
            assert_eq!(self.orchestrator.connection_lifecycle_task_count(), 0);
            assert!(matches!(
                self.orchestrator.capacity_report(),
                Event::CapacityReport {
                    active_connections: 0,
                    active_bridges: 0,
                    admission_in_use: 0,
                    ..
                }
            ));
            assert!(self.bridge_web.routes().is_empty());
            drop(self.bridge_web);
            bounded(
                "Telnyx handoff runtime shutdown",
                Arc::try_unwrap(self.runtime)
                    .expect("Telnyx handoff runtime owner released")
                    .shutdown(Duration::from_secs(5)),
            )
            .await
            .unwrap();
        }
    }

    async fn setup_harness() -> HandoffHarness {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (http, base_url, http_server) = spawn_telnyx_mock().await;
        let random = ring::rand::SystemRandom::new();
        let encoded = ring::signature::Ed25519KeyPair::generate_pkcs8(&random).unwrap();
        let webhook_key = ring::signature::Ed25519KeyPair::from_pkcs8(encoded.as_ref()).unwrap();

        let sip_tls = TestTlsFiles::create();
        let bridge_udp = reserve_udp();
        let bridge_tls = reserve_tcp();
        let configs = provider_configs(
            base_url,
            bridge_udp.port(),
            base64::engine::general_purpose::STANDARD.encode(webhook_key.public_key().as_ref()),
        );
        let registry = ProviderRegistry::from_config(&configs).unwrap();
        let runtime = call_runtime(&configs).await;
        let orchestrator = Orchestrator::new(CoreConfig::default());
        let bridge_web = WebRtcAdapter::new_with_inbound_admission_confirmation(
            WebRtcConfig::loopback(),
            Duration::from_secs(10),
        )
        .unwrap();

        let mut bridge_sip_config = tls_sip_config(
            "bridgefu-telnyx-handoff-edge",
            bridge_udp,
            bridge_tls,
            &sip_tls,
            vec![0, 101],
        );
        bridge_sip_config.contact_uri = None;
        let bridge_sip_policy = SipListenerAuthPolicy::authenticated_for_tenant(
            TENANT,
            SipAuthService::digest(DIGEST_REALM).with_digest_user(DIGEST_USER, DIGEST_PASSWORD),
        )
        .unwrap();
        let bridge_sip_coordinator = rvoip_sip::UnifiedCoordinator::new_with_listener_auth(
            bridge_sip_config,
            bridge_sip_policy,
        )
        .await
        .unwrap();
        let bridge_sip = SipAdapter::new_with_inbound_context_policy(
            Arc::clone(&bridge_sip_coordinator),
            SipInboundContextPolicy::new(["X-Correlation-Id", "X-Account-Tier"]).unwrap(),
        )
        .await
        .unwrap();
        let authenticated_sip_principals = Arc::new(Mutex::new(Vec::new()));
        let sip_principal_observer = {
            let principals = Arc::clone(&authenticated_sip_principals);
            let mut events = bridge_sip_coordinator.events().await.unwrap();
            tokio::spawn(async move {
                while let Some(event) = events.next().await {
                    if let SipEvent::IncomingCallAuthenticated { principal, .. } = event {
                        principals.lock().unwrap().push(principal);
                    }
                }
            })
        };
        let assistant = assistant_fixture(&sip_tls).await;

        let mut outbound_profiles = StaticOutboundProfileResolver::default();
        outbound_profiles.insert_sip(
            ASSISTANT_PROFILE.into(),
            ASSISTANT_PROFILE_REVISION.into(),
            ConfiguredSipOutboundProfile {
                from_uri: format!(
                    "sips:bridgefu-browser@localhost:{};transport=tls",
                    bridge_tls.port()
                ),
                outbound_proxy: None,
                auth: Some(ConfiguredSipProfileAuth::Digest {
                    realm: Some(ASSISTANT_REALM.into()),
                    username: ASSISTANT_USER.into(),
                    password: SecretRef::new(ASSISTANT_PASSWORD),
                }),
            },
        );
        let supervisor = CallExecutionSupervisor::install_with_leg_executors_context_canary_broadcast_and_outbound_profiles(
            Arc::clone(&orchestrator),
            Arc::clone(&runtime),
            Arc::new(registry.clone()),
            None,
            Arc::new(ContextPolicy {
                allow_headers: BTreeMap::from([
                    ("X-Correlation-Id".into(), "correlation_id".into()),
                    ("X-Account-Tier".into(), "account_tier".into()),
                ]),
                ..ContextPolicy::default()
            }),
            None,
            None,
            Arc::new(outbound_profiles),
            8,
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        orchestrator
            .register(Arc::clone(&bridge_web) as Arc<dyn ConnectionAdapter>)
            .unwrap();
        orchestrator
            .register(Arc::clone(&bridge_sip) as Arc<dyn ConnectionAdapter>)
            .unwrap();

        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let web_certificate = generated.cert.pem().into_bytes();
        let web_key = generated.signing_key.serialize_pem().into_bytes();
        let web_tls = TlsConfig::from_pem_bytes(&web_certificate, &web_key)
            .await
            .unwrap();
        let web_trust = Arc::new(WebRtcTlsClientTrust::from_pem(&web_certificate).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let web_address = listener.local_addr().unwrap();
        let (web_shutdown, web_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let web_listener = {
            let adapter = Arc::clone(&bridge_web);
            let auth: Arc<dyn WsAuthHook> = Arc::new(AttachmentAuth {
                principal: owner().authenticated().clone(),
            });
            tokio::spawn(async move {
                serve_tls_listener_with_auth_and_shutdown(listener, web_tls, adapter, auth, async {
                    let _ = web_shutdown_rx.await;
                })
                .await
            })
        };

        let telnyx_media_udp = reserve_udp();
        let mut media_config = SipConfig::local("telnyx-handoff-media", telnyx_media_udp.port());
        media_config.local_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        media_config.bind_addr = telnyx_media_udp;
        media_config.sip_advertised_addr = Some(telnyx_media_udp);
        media_config.local_uri = format!(
            "sip:telnyx-handoff-media@127.0.0.1:{}",
            telnyx_media_udp.port()
        );
        media_config.contact_uri = Some(media_config.local_uri.clone());
        media_config.offered_codecs = vec![0, 101];
        media_config.offer_srtp = true;
        media_config.srtp_required = true;
        let telnyx_media_coordinator = rvoip_sip::UnifiedCoordinator::new(media_config)
            .await
            .unwrap();
        let telnyx_media = SipAdapter::new(Arc::clone(&telnyx_media_coordinator))
            .await
            .unwrap();
        let telnyx_media_events = telnyx_media.subscribe_events();

        HandoffHarness {
            http,
            http_server,
            webhook_key,
            registry,
            runtime,
            orchestrator,
            bridge_web,
            bridge_sip_coordinator,
            bridge_sip,
            assistant,
            telnyx_media_coordinator,
            telnyx_media,
            telnyx_media_events,
            authenticated_sip_principals,
            sip_principal_observer,
            supervisor,
            web_address,
            web_trust,
            web_shutdown: Some(web_shutdown),
            web_listener,
        }
    }

    fn assistant_route_input(endpoint: String) -> CreateCallInput {
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
                    endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                        uri: Some(endpoint),
                        initial_context: SipInitialContextMode::Required,
                    }),
                    amazon_connect_start: None,
                },
            ],
        }
    }

    fn assistant_route_binding() -> NamedRouteBinding {
        NamedRouteBinding::new_with_profiles(
            "direct-telnyx-vapi-assistant",
            None,
            vec![NamedProfileBinding::new(
                NamedProfileRole::Destination,
                NamedProfileKind::Sip,
                ASSISTANT_PROFILE,
                ASSISTANT_PROFILE_REVISION,
            )
            .unwrap()],
        )
        .unwrap()
    }

    struct LiveAssistantCall {
        call_id: CallId,
        source_leg_id: LegId,
        destination_leg_id: LegId,
        browser: Arc<WebRtcAdapter>,
        browser_events: mpsc::Receiver<AdapterEvent>,
        browser_connection: ConnectionId,
        assistant_connection: ConnectionId,
    }

    async fn next_inbound(events: &mut mpsc::Receiver<AdapterEvent>) -> ConnectionId {
        bounded("Telnyx handoff assistant INVITE", async {
            loop {
                match events.recv().await {
                    Some(AdapterEvent::InboundConnection { connection }) => return connection.id,
                    Some(_) => {}
                    None => panic!("assistant events ended before INVITE"),
                }
            }
        })
        .await
    }

    async fn next_authenticated_assistant_session(
        coordinator: &Arc<rvoip_sip::UnifiedCoordinator>,
        events: &mut SipEventReceiver,
    ) -> (String, SessionHandle) {
        bounded("Telnyx handoff authenticated assistant INVITE", async {
            let mut incoming = None;
            let mut authenticated = None;
            loop {
                match events.next().await {
                    Some(SipEvent::IncomingCall { call_id, from, .. }) => {
                        incoming = Some((call_id, from));
                    }
                    Some(SipEvent::IncomingCallAuthenticated { call_id, principal }) => {
                        assert_eq!(principal.tenant.as_deref(), Some(ASSISTANT_PROFILE));
                        authenticated = Some(call_id);
                    }
                    Some(_) => {}
                    None => panic!("assistant SIP events ended before authentication"),
                }
                if let (Some((incoming_id, from)), Some(authenticated_id)) =
                    (incoming.as_ref(), authenticated.as_ref())
                {
                    if incoming_id == authenticated_id {
                        return (from.clone(), coordinator.session(incoming_id));
                    }
                }
            }
        })
        .await
    }

    async fn establish_assistant_call(
        harness: &mut HandoffHarness,
        idempotency: &str,
        correlation_id: &str,
    ) -> LiveAssistantCall {
        let created = harness
            .runtime
            .service()
            .create_named_route_call(
                &owner(),
                &IdempotencyKey::parse(idempotency).unwrap(),
                assistant_route_input(format!(
                    "sips:vapi-assistant@localhost:{};transport=tls",
                    harness.assistant.tls_address.port()
                )),
                assistant_route_binding(),
            )
            .await
            .unwrap();
        let source = created
            .value
            .call
            .legs
            .iter()
            .find(|leg| leg.direction == LegDirection::Inbound)
            .unwrap();
        let source_leg_id = source.leg_id;
        let destination_leg_id = created
            .value
            .call
            .legs
            .iter()
            .find(|leg| leg.direction == LegDirection::Outbound)
            .unwrap()
            .leg_id;
        let attachment = source.attachment.as_ref().unwrap();
        let call_id = created.value.call.call_id;
        let browser = WebRtcAdapter::new(WebRtcConfig::loopback());
        let browser_events = browser.subscribe_events();
        let endpoint = format!("wss://localhost:{}/signal", harness.web_address.port());
        let context = WebRtcOriginateContext::websocket(
            &endpoint,
            WebRtcTargetPolicy::default()
                .allow_port(harness.web_address.port())
                .allow_loopback(true)
                .with_timeouts(Duration::from_secs(3), Duration::from_secs(15))
                .unwrap(),
        )
        .unwrap()
        .with_bearer_provider(Arc::new(StaticWebRtcBearerCredentialProvider::new(
            WebRtcBearerCredential::new(attachment.token.clone()).unwrap(),
        )))
        .with_tls_trust(Arc::clone(&harness.web_trust));
        let browser_connection = browser
            .originate(
                OriginateRequest::new(
                    SessionId::new(),
                    ParticipantId::new(),
                    endpoint,
                    Direction::Outbound,
                    browser.capabilities(),
                )
                .with_context(context),
            )
            .await
            .unwrap()
            .connection
            .id;
        browser
            .activate_outbound(browser_connection.clone())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), async {
                loop {
                    match harness.assistant.events.recv().await {
                        Some(AdapterEvent::InboundConnection { .. }) => return,
                        Some(_) => {}
                        None => panic!("assistant events ended before browser context"),
                    }
                }
            })
            .await
            .is_err(),
            "required context did not gate the Vapi-like assistant INVITE"
        );
        let mut initial = ContextEnvelope::new(
            correlation_id,
            TENANT,
            call_id.to_string(),
            source_leg_id.to_string(),
        );
        initial
            .metadata
            .insert("account_tier".into(), "gold".into());
        initial
            .metadata
            .insert("must_not_forward".into(), "private".into());
        browser
            .send_data_message(
                browser_connection.clone(),
                initial.to_data_message().unwrap(),
            )
            .await
            .unwrap();
        let assistant_connection = next_inbound(&mut harness.assistant.events).await;
        let inbound = harness
            .assistant
            .adapter
            .take_inbound_context(&assistant_connection)
            .unwrap();
        assert_eq!(
            inbound
                .metadata()
                .values("X-Correlation-Id")
                .collect::<Vec<_>>(),
            [correlation_id]
        );
        assert_eq!(
            inbound
                .metadata()
                .values("X-Account-Tier")
                .collect::<Vec<_>>(),
            ["gold"]
        );
        assert!(inbound
            .metadata()
            .values("X-Unmapped-Private")
            .next()
            .is_none());
        let (from, session) = next_authenticated_assistant_session(
            &harness.assistant.coordinator,
            &mut harness.assistant.sip_events,
        )
        .await;
        assert!(from.contains("sips:bridgefu-browser@localhost"));
        harness
            .assistant
            .adapter
            .accept(assistant_connection.clone())
            .await
            .unwrap();
        wait_for_call(&harness.runtime, call_id, |stored| {
            stored.call.aggregate.state() == CallState::Active
        })
        .await;
        let security = session
            .wait_for_media_security(Some(Duration::from_secs(5)))
            .await
            .expect("assistant installed mandatory SRTP contexts");
        assert!(security.contexts_installed);
        assert_eq!(security.profile, MediaSecurityProfile::RtpSavp);
        LiveAssistantCall {
            call_id,
            source_leg_id,
            destination_leg_id,
            browser,
            browser_events,
            browser_connection,
            assistant_connection,
        }
    }

    async fn current_binding(
        runtime: &CallServiceRuntime,
        call_id: CallId,
        direction: LegDirection,
    ) -> (LegId, BindingGeneration, ConnectionId) {
        let stored = runtime
            .service_repository()
            .load_service_call(&TenantId::parse(TENANT).unwrap(), call_id)
            .await
            .unwrap();
        let leg = stored
            .call
            .aggregate
            .legs()
            .iter()
            .find(|leg| leg.direction() == direction)
            .unwrap();
        let binding = &stored.call.bindings[&leg.id()];
        (
            leg.id(),
            binding.binding_generation,
            binding.connection_id.clone(),
        )
    }

    async fn wait_for_active_bridges(orchestrator: &Orchestrator, expected: u64) {
        bounded("Telnyx handoff bridge count", async {
            loop {
                if matches!(
                    orchestrator.capacity_report(),
                    Event::CapacityReport { active_bridges, .. } if active_bridges == expected
                ) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
    }

    async fn wait_connection_dead(adapter: &dyn ConnectionAdapter, connection_id: &ConnectionId) {
        bounded("Telnyx handoff route cleanup", async {
            while adapter.is_connection_live(connection_id) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
    }

    async fn drain_until_quiet(receiver: &mut mpsc::Receiver<MediaFrame>) {
        while tokio::time::timeout(Duration::from_millis(100), receiver.recv())
            .await
            .is_ok_and(|frame| frame.is_some())
        {}
    }

    async fn assert_no_audio(receiver: &mut mpsc::Receiver<MediaFrame>, reason: &'static str) {
        match tokio::time::timeout(Duration::from_millis(350), receiver.recv()).await {
            Err(_) => {}
            Ok(Some(frame)) => panic!("{reason}: unexpected payload type {:?}", frame.payload_type),
            Ok(None) => panic!("{reason}: retained media receiver closed"),
        }
    }

    async fn baseline_assistant_media(
        call: &LiveAssistantCall,
        assistant: &SipAdapter,
        timestamp: u32,
    ) -> (
        Arc<dyn MediaStream>,
        mpsc::Receiver<MediaFrame>,
        Arc<dyn MediaStream>,
        mpsc::Receiver<MediaFrame>,
    ) {
        let browser_stream = audio_stream(call.browser.as_ref(), &call.browser_connection).await;
        let assistant_stream = audio_stream(assistant, &call.assistant_connection).await;
        assert_eq!(browser_stream.codec().name.to_ascii_lowercase(), "opus");
        assert_eq!(
            assistant_stream.codec().name.to_ascii_lowercase(),
            "g.711-mu"
        );
        let mut browser_audio = browser_stream.try_frames_in().unwrap();
        let mut assistant_audio = assistant_stream.try_frames_in().unwrap();
        send_encoded(
            &browser_stream,
            rvoip_webrtc::media::silent_opus_payload(),
            111,
            timestamp,
            960,
        )
        .await;
        let at_assistant = bounded(
            "browser-to-assistant baseline media",
            assistant_audio.recv(),
        )
        .await
        .expect("assistant route remained live");
        assert_eq!(at_assistant.payload_type, Some(0));
        send_encoded(
            &assistant_stream,
            bytes::Bytes::from(vec![0xff; 160]),
            0,
            timestamp / 6,
            160,
        )
        .await;
        let at_browser = bounded("assistant-to-browser baseline media", browser_audio.recv())
            .await
            .expect("browser route remained live");
        assert_eq!(at_browser.payload_type, Some(111));
        drain_until_quiet(&mut browser_audio).await;
        drain_until_quiet(&mut assistant_audio).await;
        (
            browser_stream,
            browser_audio,
            assistant_stream,
            assistant_audio,
        )
    }

    async fn handoff_statuses_until(
        events: &mut mpsc::Receiver<AdapterEvent>,
        connection_id: &ConnectionId,
        terminal: HandoffStatusKind,
    ) -> Vec<HandoffStatusEnvelope> {
        bounded("authenticated Telnyx handoff status", async {
            let mut statuses = Vec::new();
            loop {
                match events.recv().await {
                    Some(AdapterEvent::DataMessage {
                        connection_id: observed,
                        message,
                    }) if &observed == connection_id && message.label == HANDOFF_STATUS_LABEL => {
                        let status = HandoffStatusEnvelope::from_data_message(&message)
                            .expect("reserved handoff status wire contract");
                        let complete = status.status == terminal;
                        statuses.push(status);
                        if complete {
                            return statuses;
                        }
                    }
                    Some(_) => {}
                    None => panic!("browser events ended before handoff status"),
                }
            }
        })
        .await
    }

    fn assert_statuses(
        statuses: &[HandoffStatusEnvelope],
        call_id: CallId,
        leg_id: LegId,
        generation: BindingGeneration,
        expected: &[HandoffStatusKind],
    ) {
        assert_eq!(
            statuses
                .iter()
                .map(|status| status.status)
                .collect::<Vec<_>>(),
            expected
        );
        for status in statuses {
            assert_eq!(status.call_id, call_id);
            assert_eq!(status.replacement_leg_id, leg_id);
            assert_eq!(status.binding_generation, generation);
        }
    }

    async fn start_telnyx_replacement(
        runtime: &CallServiceRuntime,
        call_id: CallId,
        leg_id: LegId,
        idempotency: &str,
    ) {
        let route = route_binding("direct-telnyx-handoff");
        runtime
            .service()
            .replace_leg(
                &owner(),
                call_id,
                leg_id,
                &IdempotencyKey::parse(idempotency).unwrap(),
                ReplaceLegInput {
                    tenant_id: None,
                    route_id: route.route_id().to_owned(),
                },
                RequestedLeg {
                    direction: LegDirection::Outbound,
                    signaling_initiator: Some(SignalingInitiator::Bridgefu),
                    media_flow: MediaFlow::SendReceive,
                    endpoint: LegEndpointConfig::Provider(ProviderEndpointConfig {
                        provider: ProviderKind::Telnyx,
                        account_profile: PROFILE.into(),
                        destination: Some(DESTINATION.into()),
                    }),
                    amazon_connect_start: None,
                },
                route,
            )
            .await
            .expect("server-owned Telnyx replacement was accepted");
    }

    async fn wait_for_dials(http: &TelnyxMock, expected: usize) -> Vec<CapturedRequest> {
        bounded("Telnyx handoff dial count", async {
            loop {
                let snapshot = http.snapshot();
                if snapshot
                    .iter()
                    .filter(|request| request.path == "calls")
                    .count()
                    >= expected
                {
                    return snapshot;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
    }

    async fn wait_for_action(http: &TelnyxMock, path: &str, expected: usize) {
        bounded("Telnyx handoff provider cleanup", async {
            loop {
                if http
                    .snapshot()
                    .iter()
                    .filter(|request| request.path == path)
                    .count()
                    >= expected
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
    }

    async fn assert_telnyx_media_principal(harness: &HandoffHarness) {
        bounded("Telnyx Digest media principal", async {
            loop {
                if harness
                    .authenticated_sip_principals
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|principal| {
                        principal.method == AuthenticationMethod::SipDigest
                            && principal.tenant.as_deref() == Some(TENANT)
                    })
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
    }

    struct ChromiumAssistantCall {
        call_id: CallId,
        source_leg_id: LegId,
        destination_leg_id: LegId,
        source_generation: BindingGeneration,
        source_connection: ConnectionId,
        assistant_generation: BindingGeneration,
        assistant_server_connection: ConnectionId,
        assistant_connection: ConnectionId,
        browser: crate::browser_sdk::BrowserSdkController,
    }

    async fn establish_chromium_assistant_call(
        harness: &mut HandoffHarness,
        idempotency: &str,
        correlation_id: &str,
        terminal_side: crate::browser_sdk::BrowserTerminalSide,
    ) -> ChromiumAssistantCall {
        let created = harness
            .runtime
            .service()
            .create_named_route_call(
                &owner(),
                &IdempotencyKey::parse(idempotency).unwrap(),
                assistant_route_input(format!(
                    "sips:vapi-assistant@localhost:{};transport=tls",
                    harness.assistant.tls_address.port()
                )),
                assistant_route_binding(),
            )
            .await
            .unwrap();
        let call_id = created.value.call.call_id;
        let source = created
            .value
            .call
            .legs
            .iter()
            .find(|leg| leg.direction == LegDirection::Inbound)
            .unwrap();
        let source_leg_id = source.leg_id;
        let destination_leg_id = created
            .value
            .call
            .legs
            .iter()
            .find(|leg| leg.direction == LegDirection::Outbound)
            .unwrap()
            .leg_id;
        let attachment = source.attachment.as_ref().unwrap();
        let mut scenario = crate::browser_sdk::BrowserScenario::handoff(
            "telnyx",
            correlation_id,
            crate::browser_sdk::BrowserDestinationBoundary::TelnyxMockAccountSeam,
            crate::browser_sdk::BrowserContextSemantics::NoLiveDataChannel,
            crate::browser_sdk::BrowserDtmfSemantics::SourceToDestination,
        )
        .with_terminal_side(terminal_side);
        scenario
            .initial_metadata
            .insert("account_tier".into(), "gold".into());
        let browser = crate::browser_sdk::BrowserSdkController::launch(
            crate::browser_sdk::attachment_fixture(
                format!("wss://localhost:{}/signal", harness.web_address.port()),
                attachment.token.clone(),
                attachment.expires_at.to_rfc3339(),
                TENANT,
                call_id.to_string(),
                source_leg_id.to_string(),
                scenario,
            ),
        )
        .await;

        let assistant_connection = next_inbound(&mut harness.assistant.events).await;
        let inbound = harness
            .assistant
            .adapter
            .take_inbound_context(&assistant_connection)
            .expect("Chromium initial context released the Telnyx Vapi-like assistant");
        assert_eq!(
            inbound
                .metadata()
                .values("X-Correlation-Id")
                .collect::<Vec<_>>(),
            [correlation_id]
        );
        assert_eq!(
            inbound
                .metadata()
                .values("X-Account-Tier")
                .collect::<Vec<_>>(),
            ["gold"]
        );
        assert!(inbound
            .metadata()
            .values("X-Unmapped-Private")
            .next()
            .is_none());
        let (_, session) = next_authenticated_assistant_session(
            &harness.assistant.coordinator,
            &mut harness.assistant.sip_events,
        )
        .await;
        harness
            .assistant
            .adapter
            .accept(assistant_connection.clone())
            .await
            .unwrap();
        wait_for_call(&harness.runtime, call_id, |stored| {
            stored.call.aggregate.state() == CallState::Active
        })
        .await;
        let security = session
            .wait_for_media_security(Some(Duration::from_secs(5)))
            .await
            .unwrap();
        assert!(security.contexts_installed);
        assert_eq!(security.profile, MediaSecurityProfile::RtpSavp);
        let (_, source_generation, source_connection) =
            current_binding(&harness.runtime, call_id, LegDirection::Inbound).await;
        let (_, assistant_generation, assistant_server_connection) =
            current_binding(&harness.runtime, call_id, LegDirection::Outbound).await;
        wait_for_active_bridges(&harness.orchestrator, 1).await;
        browser.mark_initial_destination_ready();

        ChromiumAssistantCall {
            call_id,
            source_leg_id,
            destination_leg_id,
            source_generation,
            source_connection,
            assistant_generation,
            assistant_server_connection,
            assistant_connection,
            browser,
        }
    }

    async fn wait_for_chromium_assistant_controls(
        events: &mut mpsc::Receiver<AdapterEvent>,
        connection_id: &ConnectionId,
        browser: &crate::browser_sdk::BrowserSdkController,
    ) {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                match events
                    .recv()
                    .await
                    .expect("assistant events ended before Chromium controls")
                {
                    AdapterEvent::Dtmf {
                        connection_id: observed,
                        digits,
                        ..
                    } if &observed == connection_id && digits == "6" => return,
                    _ => {}
                }
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "Chromium Telnyx assistant DTMF deadline; diagnostics={:?}; phases={:?}",
                browser.diagnostics(),
                browser.phases()
            )
        });
    }

    async fn run_actual_chromium_telnyx_matrix() {
        run_actual_chromium_telnyx_case(crate::browser_sdk::BrowserTerminalSide::Browser).await;
        run_actual_chromium_telnyx_case(crate::browser_sdk::BrowserTerminalSide::Destination).await;
    }

    async fn run_actual_chromium_telnyx_case(
        terminal_side: crate::browser_sdk::BrowserTerminalSide,
    ) {
        let mut harness = setup_harness().await;
        let provider = harness.registry.get("telnyx").unwrap();
        let correlation_id = "chromium-telnyx-controlled-context";
        let call = establish_chromium_assistant_call(
            &mut harness,
            "chromium-telnyx-assistant-call",
            correlation_id,
            terminal_side,
        )
        .await;
        let assistant_stream = audio_stream(
            harness.assistant.adapter.as_ref(),
            &call.assistant_connection,
        )
        .await;
        let mut assistant_audio = assistant_stream.try_frames_in().unwrap();
        let initial_media = tokio::spawn({
            let stream = Arc::clone(&assistant_stream);
            async move {
                send_encoded(&stream, bytes::Bytes::from(vec![0xff; 160]), 0, 96_000, 160).await;
            }
        });
        assert_eq!(
            bounded(
                "Chromium-to-Telnyx-assistant baseline audio",
                assistant_audio.recv(),
            )
            .await
            .expect("assistant microphone route remained live")
            .payload_type,
            Some(0)
        );
        call.browser.wait_for_phase("assistant-ready").await;
        initial_media.await.unwrap();
        wait_for_chromium_assistant_controls(
            &mut harness.assistant.events,
            &call.assistant_connection,
            &call.browser,
        )
        .await;

        let rejected_generation = call.assistant_generation.next().unwrap();
        harness.http.gate_next_destination();
        harness.http.reject_next_destination();
        start_telnyx_replacement(
            &harness.runtime,
            call.call_id,
            call.destination_leg_id,
            "chromium-telnyx-rejected-replacement",
        )
        .await;
        let requests = wait_for_dials(&harness.http, 1).await;
        let rejected_target = requests
            .iter()
            .find(|request| request.path == "calls")
            .unwrap()
            .body["to"]
            .as_str()
            .unwrap()
            .to_owned();
        let rejected_media = originate_telnyx_media(&harness.telnyx_media, &rejected_target)
            .await
            .unwrap();
        harness.http.wait_for_destination_gate().await;
        assert_two_dials(&wait_for_dials(&harness.http, 2).await, 1, correlation_id);
        assert_telnyx_media_principal(&harness).await;
        wait_for_active_bridges(&harness.orchestrator, 0).await;
        call.browser.wait_for_phase("reject-hold-ready").await;
        drain_until_quiet(&mut assistant_audio).await;
        send_encoded(
            &assistant_stream,
            bytes::Bytes::from(vec![0xff; 160]),
            0,
            112_000,
            160,
        )
        .await;
        assert_no_audio(
            &mut assistant_audio,
            "Chromium audio leaked into held assistant during rejected Telnyx handoff",
        )
        .await;
        harness.http.release_destination();
        call.browser.wait_for_phase("reject-resumed").await;
        wait_for_active_bridges(&harness.orchestrator, 1).await;
        wait_for_action(&harness.http, "telnyx-media-1/hangup", 1).await;
        wait_connection_dead(harness.telnyx_media.as_ref(), &rejected_media).await;
        send_encoded(
            &assistant_stream,
            bytes::Bytes::from(vec![0xff; 160]),
            0,
            128_000,
            160,
        )
        .await;
        call.browser.wait_for_phase("reject-resume-audio").await;

        let successful_generation = rejected_generation.next().unwrap();
        harness.http.gate_next_destination();
        start_telnyx_replacement(
            &harness.runtime,
            call.call_id,
            call.destination_leg_id,
            "chromium-telnyx-successful-replacement",
        )
        .await;
        let requests = wait_for_dials(&harness.http, 3).await;
        let successful_target = requests
            .iter()
            .filter(|request| request.path == "calls")
            .nth(2)
            .unwrap()
            .body["to"]
            .as_str()
            .unwrap()
            .to_owned();
        let successful_media = originate_telnyx_media(&harness.telnyx_media, &successful_target)
            .await
            .unwrap();
        harness.http.wait_for_destination_gate().await;
        let successful_requests = wait_for_dials(&harness.http, 4).await;
        assert_two_dials(&successful_requests, 2, correlation_id);
        let successful_destination_state =
            captured_dial_client_state(&successful_requests, 2, ProviderDialRole::Destination);
        wait_for_active_bridges(&harness.orchestrator, 0).await;
        call.browser.wait_for_phase("success-hold-ready").await;
        drain_until_quiet(&mut assistant_audio).await;
        send_encoded(
            &assistant_stream,
            bytes::Bytes::from(vec![0xff; 160]),
            0,
            144_000,
            160,
        )
        .await;
        assert_no_audio(
            &mut assistant_audio,
            "Chromium audio leaked into held assistant during successful Telnyx handoff",
        )
        .await;
        harness.http.release_destination();
        let destination_reference = wait_for_destination_reference_for_binding(
            &harness.runtime,
            call.call_id,
            call.destination_leg_id,
            successful_generation,
        )
        .await;
        assert_eq!(
            destination_reference.expose_secret(),
            "telnyx-destination-2"
        );
        accept_signed_provider_event(
            &harness.runtime,
            provider.as_ref(),
            &harness.webhook_key,
            "chromium-telnyx-ready",
            "call.bridged",
            &destination_reference,
            &successful_destination_state,
        )
        .await;
        let active = wait_for_call(&harness.runtime, call.call_id, |stored| {
            stored.call.aggregate.state() == CallState::Active
                && stored.call.aggregate.replacement().is_none()
                && stored
                    .call
                    .bindings
                    .get(&call.destination_leg_id)
                    .is_some_and(|binding| binding.binding_generation == successful_generation)
        })
        .await;
        call.browser.wait_for_phase("success-connected").await;
        assert_eq!(
            active.call.bindings[&call.source_leg_id].binding_generation,
            call.source_generation
        );
        assert_eq!(
            active.call.bindings[&call.source_leg_id].connection_id,
            call.source_connection
        );
        assert_ne!(
            active.call.bindings[&call.destination_leg_id].connection_id,
            call.assistant_server_connection
        );
        wait_connection_dead(
            harness.assistant.adapter.as_ref(),
            &call.assistant_connection,
        )
        .await;

        let provider_stream = audio_stream(harness.telnyx_media.as_ref(), &successful_media).await;
        let mut provider_audio = provider_stream.try_frames_in().unwrap();
        assert_eq!(
            bounded("Chromium-to-Telnyx promoted audio", provider_audio.recv())
                .await
                .expect("Telnyx media route remained live")
                .payload_type,
            Some(0)
        );
        send_encoded(
            &provider_stream,
            bytes::Bytes::from(vec![0xff; 160]),
            0,
            160_000,
            160,
        )
        .await;
        call.browser.wait_for_phase("agent-audio").await;
        call.browser
            .wait_for_phase("destination-actions-sent")
            .await;
        let (digits, duration_ms) =
            next_dtmf(&mut harness.telnyx_media_events, &successful_media).await;
        assert_eq!(digits, "5");
        assert!((40..=500).contains(&duration_ms));
        let requests_before_verification = harness.http.snapshot().len();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            harness.http.snapshot().len(),
            requests_before_verification,
            "browser DataChannels must not invent Telnyx control commands"
        );

        let call_id = call.call_id;
        let call_id_string = call_id.to_string();
        let destination_leg_id_string = call.destination_leg_id.to_string();
        call.browser.mark_destination_verified();
        if terminal_side == crate::browser_sdk::BrowserTerminalSide::Destination {
            call.browser
                .wait_for_phase("destination-hangup-ready")
                .await;
            accept_signed_provider_event(
                &harness.runtime,
                provider.as_ref(),
                &harness.webhook_key,
                "chromium-telnyx-destination-terminal",
                "call.hangup",
                &destination_reference,
                &successful_destination_state,
            )
            .await;
        }
        let result = call.browser.complete().await;
        crate::browser_sdk::assert_common_handoff_result(
            &result,
            &call_id_string,
            &destination_leg_id_string,
            rejected_generation.value(),
            successful_generation.value(),
            terminal_side,
            crate::browser_sdk::BrowserDestinationBoundary::TelnyxMockAccountSeam,
            crate::browser_sdk::BrowserContextSemantics::NoLiveDataChannel,
            crate::browser_sdk::BrowserDtmfSemantics::SourceToDestination,
        );
        assert!(result["remoteContext"].is_null());
        assert!(result["remoteMessage"].is_null());

        wait_for_call(&harness.runtime, call_id, |stored| {
            stored.call.aggregate.state().is_terminal()
        })
        .await;
        if terminal_side == crate::browser_sdk::BrowserTerminalSide::Browser {
            wait_for_action(&harness.http, "telnyx-media-2/hangup", 1).await;
        }
        wait_connection_dead(harness.telnyx_media.as_ref(), &successful_media).await;
        assert_eq!(
            harness
                .http
                .snapshot()
                .iter()
                .filter(|request| request.path == "telnyx-media-1/hangup")
                .count(),
            1
        );
        assert_eq!(
            harness
                .http
                .snapshot()
                .iter()
                .filter(|request| request.path == "telnyx-media-2/hangup")
                .count(),
            match terminal_side {
                crate::browser_sdk::BrowserTerminalSide::Browser => 1,
                crate::browser_sdk::BrowserTerminalSide::Destination => 0,
            },
            "a provider-originated terminal callback must not echo a Telnyx hangup command"
        );
        wait_for_orchestrator_idle(&harness.orchestrator).await;
        assert!(harness.bridge_web.routes().is_empty());
        harness.shutdown().await;
    }

    #[test]
    #[ignore = "requires BridgeFu's pinned Playwright Chromium; run explicitly with --ignored"]
    fn built_typescript_sdk_hands_off_to_telnyx_and_cleans_both_terminal_directions() {
        let _serial = TELNYX_QUALIFICATION_TEST_LOCK.lock().unwrap();
        std::thread::Builder::new()
            .name("chromium-vapi-assistant-telnyx-handoff".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(6)
                    .thread_stack_size(8 * 1024 * 1024)
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(run_actual_chromium_telnyx_matrix());
            })
            .unwrap()
            .join()
            .expect("actual Chromium Telnyx qualification panicked");
    }

    async fn run_handoff_qualification() {
        let mut harness = setup_harness().await;
        let provider = harness.registry.get("telnyx").unwrap();

        let mut success = establish_assistant_call(
            &mut harness,
            "telnyx-assistant-handoff-success-call",
            "telnyx-assistant-handoff-success-correlation",
        )
        .await;
        let source_binding =
            current_binding(&harness.runtime, success.call_id, LegDirection::Inbound).await;
        assert_eq!(source_binding.0, success.source_leg_id);
        let (_, assistant_generation, assistant_server_connection) =
            current_binding(&harness.runtime, success.call_id, LegDirection::Outbound).await;
        let pending_generation = assistant_generation.next().unwrap();
        let (browser_stream, mut browser_audio, assistant_stream, mut assistant_audio) =
            baseline_assistant_media(&success, &harness.assistant.adapter, 48_000).await;

        harness.http.gate_next_destination();
        start_telnyx_replacement(
            &harness.runtime,
            success.call_id,
            success.destination_leg_id,
            "telnyx-assistant-handoff-success-replacement",
        )
        .await;
        let first_requests = wait_for_dials(&harness.http, 1).await;
        assert_eq!(
            first_requests
                .iter()
                .filter(|request| request.path == "calls")
                .count(),
            1,
            "Telnyx destination dial started before its authenticated media attachment"
        );
        let first_target = first_requests
            .iter()
            .find(|request| request.path == "calls")
            .unwrap()
            .body["to"]
            .as_str()
            .unwrap()
            .to_owned();
        let transferring = wait_for_call(&harness.runtime, success.call_id, |stored| {
            stored.call.aggregate.state() == CallState::Transferring
                && stored
                    .call
                    .aggregate
                    .replacement()
                    .is_some_and(|replacement| {
                        replacement.pending_binding_generation() == pending_generation
                    })
        })
        .await;
        assert_eq!(
            transferring.call.bindings[&success.destination_leg_id].connection_id,
            assistant_server_connection
        );
        wait_for_active_bridges(&harness.orchestrator, 0).await;
        assert!(success
            .browser
            .is_connection_live(&success.browser_connection));
        assert!(harness
            .assistant
            .adapter
            .is_connection_live(&success.assistant_connection));

        let first_media_connection = originate_telnyx_media(&harness.telnyx_media, &first_target)
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "authenticated Telnyx replacement attachment failed: {}",
                    rvoip_error_detail(&error)
                )
            });
        harness.http.wait_for_destination_gate().await;
        let first_requests = wait_for_dials(&harness.http, 2).await;
        assert_eq!(
            assert_two_dials(
                &first_requests,
                1,
                "telnyx-assistant-handoff-success-correlation",
            ),
            first_target
        );
        let first_destination_state =
            captured_dial_client_state(&first_requests, 1, ProviderDialRole::Destination);
        let first_media_state =
            captured_dial_client_state(&first_requests, 1, ProviderDialRole::Media);
        assert_telnyx_media_principal(&harness).await;
        assert!(harness
            .telnyx_media
            .is_connection_live(&first_media_connection));
        let still_transferring = wait_for_call(&harness.runtime, success.call_id, |stored| {
            stored.call.aggregate.state() == CallState::Transferring
        })
        .await;
        assert_eq!(
            still_transferring.call.bindings[&success.destination_leg_id].connection_id,
            assistant_server_connection,
            "the held assistant binding changed before provider-ready evidence"
        );
        assert_eq!(
            current_binding(&harness.runtime, success.call_id, LegDirection::Inbound,).await,
            source_binding,
            "browser source binding changed while Telnyx was attaching"
        );
        wait_for_active_bridges(&harness.orchestrator, 0).await;

        send_encoded(
            &assistant_stream,
            bytes::Bytes::from(vec![0xff; 160]),
            0,
            16_000,
            160,
        )
        .await;
        assert_no_audio(
            &mut browser_audio,
            "held assistant leaked into browser while Telnyx was attaching",
        )
        .await;
        send_encoded(
            &browser_stream,
            rvoip_webrtc::media::silent_opus_payload(),
            111,
            96_000,
            960,
        )
        .await;
        assert_no_audio(
            &mut assistant_audio,
            "browser audio leaked into the held assistant while Telnyx was attaching",
        )
        .await;

        harness.http.release_destination();
        let _ = wait_for_dials(&harness.http, 2).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let before_ready = harness
            .runtime
            .service_repository()
            .load_service_call(&TenantId::parse(TENANT).unwrap(), success.call_id)
            .await
            .unwrap();
        assert_eq!(
            before_ready.call.aggregate.state(),
            CallState::Transferring,
            "a Telnyx HTTP dial/reference must not promote before signed call.bridged"
        );
        assert!(harness
            .assistant
            .adapter
            .is_connection_live(&success.assistant_connection));
        wait_for_active_bridges(&harness.orchestrator, 0).await;

        let stale = signed_webhook(
            &harness.webhook_key,
            "telnyx-handoff-stale-ready",
            "call.bridged",
            "telnyx-destination-stale",
            &first_destination_state,
        );
        let stale_normalized = provider.verify_webhook(&stale).unwrap();
        assert!(matches!(
            harness
                .runtime
                .repository()
                .ingest_provider_event(provider_event_input(provider.as_ref(), stale_normalized))
                .await
                .unwrap(),
            ProviderEventOutcome::Accepted(_)
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            harness
                .runtime
                .service_repository()
                .load_service_call(&TenantId::parse(TENANT).unwrap(), success.call_id)
                .await
                .unwrap()
                .call
                .aggregate
                .state(),
            CallState::Transferring,
            "a validly signed callback for another provider reference promoted this call"
        );

        for (event_id, invalid_state) in [
            ("telnyx-handoff-wrong-role", first_media_state.as_str()),
            ("telnyx-handoff-malformed-state", "!!!"),
        ] {
            let invalid_state_webhook = signed_webhook(
                &harness.webhook_key,
                event_id,
                "call.bridged",
                "telnyx-destination-1",
                invalid_state,
            );
            let normalized = provider.verify_webhook(&invalid_state_webhook).unwrap();
            assert!(matches!(
                harness
                    .runtime
                    .repository()
                    .ingest_provider_event(provider_event_input(provider.as_ref(), normalized))
                    .await
                    .unwrap(),
                ProviderEventOutcome::Accepted(_)
            ));
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(
                harness
                    .runtime
                    .service_repository()
                    .load_service_call(&TenantId::parse(TENANT).unwrap(), success.call_id)
                    .await
                    .unwrap()
                    .call
                    .aggregate
                    .state(),
                CallState::Transferring,
                "invalid Telnyx client_state promoted a replacement"
            );
        }

        let ready_webhook = signed_webhook(
            &harness.webhook_key,
            "telnyx-handoff-ready-1",
            "call.bridged",
            "telnyx-destination-1",
            &first_destination_state,
        );
        let mut invalid_ready = ready_webhook.clone();
        invalid_ready.body.push(b' ');
        assert!(matches!(
            provider.verify_webhook(&invalid_ready),
            Err(ProviderError::InvalidSignature)
        ));
        let normalized = provider.verify_webhook(&ready_webhook).unwrap();
        let ready_input = provider_event_input(provider.as_ref(), normalized);
        assert!(matches!(
            harness
                .runtime
                .repository()
                .ingest_provider_event(ready_input.clone())
                .await
                .unwrap(),
            ProviderEventOutcome::Accepted(_)
        ));
        assert!(matches!(
            harness
                .runtime
                .repository()
                .ingest_provider_event(ready_input)
                .await
                .unwrap(),
            ProviderEventOutcome::Duplicate(_)
        ));

        let active = wait_for_call(&harness.runtime, success.call_id, |stored| {
            stored.call.aggregate.state() == CallState::Active
                && stored.call.aggregate.replacement().is_none()
                && stored
                    .call
                    .bindings
                    .get(&success.destination_leg_id)
                    .is_some_and(|binding| {
                        binding.binding_generation == pending_generation
                            && binding.connection_id != assistant_server_connection
                    })
        })
        .await;
        let destination_reference = wait_for_destination_reference(
            &harness.runtime,
            success.call_id,
            success.destination_leg_id,
        )
        .await;
        assert_eq!(
            destination_reference.expose_secret(),
            "telnyx-destination-1"
        );
        let statuses = handoff_statuses_until(
            &mut success.browser_events,
            &success.browser_connection,
            HandoffStatusKind::Connected,
        )
        .await;
        assert_statuses(
            &statuses,
            success.call_id,
            success.destination_leg_id,
            pending_generation,
            &[
                HandoffStatusKind::Preparing,
                HandoffStatusKind::Ringing,
                HandoffStatusKind::Attaching,
                HandoffStatusKind::Connected,
            ],
        );
        wait_for_active_bridges(&harness.orchestrator, 1).await;
        wait_connection_dead(
            harness.assistant.adapter.as_ref(),
            &success.assistant_connection,
        )
        .await;
        assert!(success
            .browser
            .is_connection_live(&success.browser_connection));
        assert_eq!(
            current_binding(&harness.runtime, success.call_id, LegDirection::Inbound,).await,
            source_binding
        );
        assert_ne!(
            active.call.bindings[&success.destination_leg_id].connection_id,
            assistant_server_connection
        );

        drain_until_quiet(&mut browser_audio).await;
        let provider_stream =
            audio_stream(harness.telnyx_media.as_ref(), &first_media_connection).await;
        let mut provider_audio = provider_stream.try_frames_in().unwrap();
        send_encoded(
            &browser_stream,
            rvoip_webrtc::media::silent_opus_payload(),
            111,
            192_000,
            960,
        )
        .await;
        let at_provider = bounded("browser-to-Telnyx promoted media", provider_audio.recv())
            .await
            .expect("Telnyx media route remained live");
        assert_eq!(at_provider.payload_type, Some(0));
        send_encoded(
            &provider_stream,
            bytes::Bytes::from(vec![0xff; 160]),
            0,
            48_000,
            160,
        )
        .await;
        let at_browser = bounded("Telnyx-to-browser promoted media", browser_audio.recv())
            .await
            .expect("stable browser route remained live");
        assert_eq!(at_browser.payload_type, Some(111));

        success
            .browser
            .send_dtmf(success.browser_connection.clone(), "6", 120)
            .await
            .unwrap();
        let (digit, duration_ms) =
            next_dtmf(&mut harness.telnyx_media_events, &first_media_connection).await;
        assert_eq!(digit, "6");
        assert!((40..=500).contains(&duration_ms));
        harness
            .telnyx_media
            .send_dtmf(first_media_connection.clone(), "3", 140)
            .await
            .unwrap();
        let (digit, duration_ms) =
            next_dtmf(&mut success.browser_events, &success.browser_connection).await;
        assert_eq!(digit, "3");
        assert!((40..=500).contains(&duration_ms));

        success
            .browser
            .end(success.browser_connection.clone(), EndReason::Normal)
            .await
            .unwrap();
        wait_for_call(&harness.runtime, success.call_id, |stored| {
            stored.call.aggregate.state().is_terminal()
        })
        .await;
        wait_for_action(&harness.http, "telnyx-media-1/hangup", 1).await;
        wait_connection_dead(harness.telnyx_media.as_ref(), &first_media_connection).await;
        wait_for_orchestrator_idle(&harness.orchestrator).await;
        assert!(success.browser.routes().is_empty());
        drop(success);

        let mut rejected = establish_assistant_call(
            &mut harness,
            "telnyx-assistant-handoff-rejected-call",
            "telnyx-assistant-handoff-rejected-correlation",
        )
        .await;
        let rejected_source_binding =
            current_binding(&harness.runtime, rejected.call_id, LegDirection::Inbound).await;
        let (_, rejected_assistant_generation, rejected_assistant_server_connection) =
            current_binding(&harness.runtime, rejected.call_id, LegDirection::Outbound).await;
        let rejected_pending_generation = rejected_assistant_generation.next().unwrap();
        let (
            rejected_browser_stream,
            mut rejected_browser_audio,
            rejected_assistant_stream,
            mut rejected_assistant_audio,
        ) = baseline_assistant_media(&rejected, &harness.assistant.adapter, 384_000).await;

        harness.http.reject_next_destination();
        start_telnyx_replacement(
            &harness.runtime,
            rejected.call_id,
            rejected.destination_leg_id,
            "telnyx-assistant-handoff-rejected-replacement",
        )
        .await;
        let second_requests = wait_for_dials(&harness.http, 3).await;
        let second_target = second_requests
            .iter()
            .filter(|request| request.path == "calls")
            .nth(2)
            .unwrap()
            .body["to"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_ne!(second_target, first_target);
        let second_media_connection = originate_telnyx_media(&harness.telnyx_media, &second_target)
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "second authenticated Telnyx replacement attachment failed: {}",
                    rvoip_error_detail(&error)
                )
            });
        let second_requests = wait_for_dials(&harness.http, 4).await;
        assert_eq!(
            assert_two_dials(
                &second_requests,
                2,
                "telnyx-assistant-handoff-rejected-correlation",
            ),
            second_target
        );
        let statuses = handoff_statuses_until(
            &mut rejected.browser_events,
            &rejected.browser_connection,
            HandoffStatusKind::Resumed,
        )
        .await;
        assert_statuses(
            &statuses,
            rejected.call_id,
            rejected.destination_leg_id,
            rejected_pending_generation,
            &[
                HandoffStatusKind::Preparing,
                HandoffStatusKind::Ringing,
                HandoffStatusKind::Attaching,
                HandoffStatusKind::Resumed,
            ],
        );
        let resumed = wait_for_call(&harness.runtime, rejected.call_id, |stored| {
            stored.call.aggregate.state() == CallState::Active
                && stored.call.aggregate.replacement().is_none()
                && stored
                    .call
                    .bindings
                    .get(&rejected.destination_leg_id)
                    .is_some_and(|binding| {
                        binding.binding_generation == rejected_assistant_generation
                            && binding.connection_id == rejected_assistant_server_connection
                    })
        })
        .await;
        assert_eq!(
            resumed.call.bindings[&rejected.destination_leg_id].connection_id,
            rejected_assistant_server_connection
        );
        assert_eq!(
            current_binding(&harness.runtime, rejected.call_id, LegDirection::Inbound,).await,
            rejected_source_binding
        );
        assert!(rejected
            .browser
            .is_connection_live(&rejected.browser_connection));
        assert!(harness
            .assistant
            .adapter
            .is_connection_live(&rejected.assistant_connection));
        wait_for_active_bridges(&harness.orchestrator, 1).await;
        wait_for_action(&harness.http, "telnyx-media-2/hangup", 1).await;
        wait_connection_dead(harness.telnyx_media.as_ref(), &second_media_connection).await;

        send_encoded(
            &rejected_browser_stream,
            rvoip_webrtc::media::silent_opus_payload(),
            111,
            480_000,
            960,
        )
        .await;
        let at_assistant = bounded(
            "resumed browser-to-assistant media",
            rejected_assistant_audio.recv(),
        )
        .await
        .expect("assistant media resumed");
        assert_eq!(at_assistant.payload_type, Some(0));
        send_encoded(
            &rejected_assistant_stream,
            bytes::Bytes::from(vec![0xff; 160]),
            0,
            80_000,
            160,
        )
        .await;
        let at_browser = bounded(
            "resumed assistant-to-browser media",
            rejected_browser_audio.recv(),
        )
        .await
        .expect("stable browser media resumed");
        assert_eq!(at_browser.payload_type, Some(111));

        rejected
            .browser
            .end(rejected.browser_connection.clone(), EndReason::Normal)
            .await
            .unwrap();
        wait_for_call(&harness.runtime, rejected.call_id, |stored| {
            stored.call.aggregate.state().is_terminal()
        })
        .await;
        wait_connection_dead(
            harness.assistant.adapter.as_ref(),
            &rejected.assistant_connection,
        )
        .await;
        wait_for_orchestrator_idle(&harness.orchestrator).await;
        assert!(rejected.browser.routes().is_empty());
        drop(rejected);

        assert_eq!(
            harness
                .http
                .snapshot()
                .iter()
                .filter(|request| request.path == "telnyx-media-1/hangup")
                .count(),
            1
        );
        assert_eq!(
            harness
                .http
                .snapshot()
                .iter()
                .filter(|request| request.path == "telnyx-media-2/hangup")
                .count(),
            1
        );
        harness.shutdown().await;
    }

    #[test]
    fn direct_browser_vapi_assistant_to_telnyx_waits_for_signed_ready_and_compensates() {
        let _serial = TELNYX_QUALIFICATION_TEST_LOCK.lock().unwrap();
        std::thread::Builder::new()
            .name("direct-browser-vapi-assistant-telnyx-handoff".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(6)
                    .thread_stack_size(8 * 1024 * 1024)
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(Box::pin(run_handoff_qualification()));
            })
            .unwrap()
            .join()
            .expect("direct browser assistant-to-Telnyx qualification panicked");
    }
}
