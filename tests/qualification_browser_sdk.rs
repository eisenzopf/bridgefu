//! Opt-in Chromium qualification for the actual built Bridgefu browser SDK.
//!
//! The browser uses a fake microphone but otherwise traverses the production
//! SDK, authenticated one-use WSS attachment, named call engine, MediaGraph,
//! and a hermetic Digest-authenticated SIPS/SRTP destination.
//!
//! ```text
//! cargo test -p bridgefu --test qualification_browser_sdk \
//!   -- --ignored --nocapture
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path as AxumPath, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bridgefu::api_principal::ApiPrincipal;
use bridgefu::call_engine::{
    BindingGeneration, CallId, CallState, LegDirection, LegId, MediaFlow, SignalingInitiator,
    TenantId, WorkerId,
};
use bridgefu::call_service::{
    build_call_service_runtime, CallExecutionSupervisor, CallRepositoryBackendConfig,
    CallServiceCoordinationConfig, CallServiceRuntime, CallServiceRuntimeConfig, CallTimeoutPolicy,
    ConfiguredSipOutboundProfile, ConfiguredSipProfileAuth, CreateCallInput,
    DisabledProviderLegExecutor, IdempotencyKey, LegEndpointConfig, NamedProfileBinding,
    NamedProfileKind, NamedProfileRole, NamedRouteBinding, ReplaceLegInput, RequestedLeg,
    SamePrincipalAttachmentResolver, SipEndpointConfig, SipInitialContextMode,
    StaticOutboundProfileResolver, SystemCallServiceClock, WebRtcEndpointConfig,
};
use bridgefu::context::{ContextEnvelope, ContextPolicy, CONTEXT_LABEL};
use bridgefu::coordination::DeploymentId;
use bridgefu::secret_ref::SecretRef;
use chrono::Utc;
use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod};
use rvoip_core::adapter::{
    AdapterEvent, ConnectionAdapter, InboundConnectionContext, RejectReason,
};
use rvoip_core::config::Config as CoreConfig;
use rvoip_core::stream::{MediaFrame, MediaStream, StreamKind};
use rvoip_core::{DataMessage, DataReliability, Event, IdentityAssurance, Jwk, Orchestrator};
use rvoip_sip::{SipAdapter, SipAuthService, SipInboundContextPolicy, SipListenerAuthPolicy};
use rvoip_webrtc::signaling::auth::{AuthContext, AuthRejection, WsAuthHook};
use rvoip_webrtc::signaling::websocket::serve_tls_listener_with_auth_and_shutdown;
use rvoip_webrtc::tls::TlsConfig;
use rvoip_webrtc::{WebRtcAdapter, WebRtcConfig};
use serde_json::{json, Value};
use tokio::sync::mpsc;

#[path = "support/sip_fixture.rs"]
mod sip_fixture;
use sip_fixture::{reserve_tcp, reserve_udp, tls_sip_config, TestTlsFiles};

const TENANT: &str = "browser-sdk-tenant";
const SIP_PROFILE_ID: &str = "browser-sdk-sip-agent";
const SIP_PROFILE_REVISION: &str =
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const SIP_DIGEST_REALM: &str = "bridgefu-browser-sdk-destination";
const SIP_DIGEST_USER: &str = "bridgefu-chromium";
const SIP_DIGEST_PASSWORD: &str = "hermetic-chromium-sip-password";
const CALL_CENTER_PROFILE_ID: &str = "browser-sdk-call-center";
const CALL_CENTER_PROFILE_REVISION: &str =
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const CALL_CENTER_DIGEST_REALM: &str = "bridgefu-browser-sdk-call-center";
const CALL_CENTER_DIGEST_USER: &str = "bridgefu-chromium-call-center";
const CALL_CENTER_DIGEST_PASSWORD: &str = "hermetic-chromium-call-center-password";
const BROWSER_MESSAGE_LABEL: &str = "browser.arbitrary.v1";

#[derive(Clone)]
struct BrowserHttpState {
    attachment: Arc<Value>,
    destination_ready: Arc<AtomicBool>,
    destination_verified: Arc<AtomicBool>,
    diagnostics: Arc<Mutex<Option<Value>>>,
    phases: Arc<Mutex<Vec<Value>>>,
    sdk_dist: Arc<PathBuf>,
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
        _peer_addr: std::net::SocketAddr,
    ) -> Result<AuthContext, AuthRejection> {
        let token = subprotocols
            .iter()
            .find_map(|value| value.strip_prefix("token."))
            .filter(|value| !value.is_empty() && value.len() <= 512)
            .ok_or(AuthRejection::Unauthorized {
                www_authenticate: "Bearer realm=\"bridgefu-browser-sdk\"".into(),
            })?;
        Ok(AuthContext {
            subject: self.principal.subject.clone(),
            scopes: vec!["webrtc:connect".into()],
            session_hint: Some(token.to_owned()),
            principal: Some(self.principal.clone()),
        })
    }
}

fn principal() -> ApiPrincipal {
    ApiPrincipal::new(
        AuthenticatedPrincipal {
            subject: "chromium-browser-owner".into(),
            tenant: Some(TENANT.into()),
            scopes: vec![
                "*".into(),
                bridgefu::api_principal::CallScope::ArbitraryDestination
                    .as_str()
                    .into(),
            ],
            issuer: Some("browser-sdk-qualification".into()),
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

async fn call_runtime() -> Arc<CallServiceRuntime> {
    let mut coordination = CallServiceCoordinationConfig::new(
        DeploymentId::parse("browser-sdk-qualification").unwrap(),
    );
    coordination.worker_lease_ttl = Duration::from_secs(300);
    coordination.worker_renew_interval = Duration::from_secs(100);
    Arc::new(
        build_call_service_runtime(
            CallServiceRuntimeConfig {
                backend: CallRepositoryBackendConfig::Memory,
                worker_id: WorkerId::new(),
                max_calls: 2,
                worker_capabilities: BTreeSet::from([
                    "sip".into(),
                    "sip_egress".into(),
                    "webrtc".into(),
                ]),
                control_key: vec![0x5c; 32],
                timeouts: CallTimeoutPolicy {
                    setup: Duration::from_secs(30),
                    media_idle: Duration::from_secs(30),
                    transfer: Duration::from_secs(20),
                    ending: Duration::from_secs(10),
                },
                coordination,
            },
            Arc::new(SamePrincipalAttachmentResolver),
            Arc::new(SystemCallServiceClock),
        )
        .await
        .unwrap(),
    )
}

fn route_input(destination: String) -> CreateCallInput {
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
                    uri: Some(destination),
                    initial_context: SipInitialContextMode::Required,
                }),
                amazon_connect_start: None,
            },
        ],
    }
}

fn route_binding() -> NamedRouteBinding {
    NamedRouteBinding::new_with_profiles(
        "browser-sdk-generic-sip",
        None,
        vec![NamedProfileBinding::new(
            NamedProfileRole::Destination,
            NamedProfileKind::Sip,
            SIP_PROFILE_ID,
            SIP_PROFILE_REVISION,
        )
        .unwrap()],
    )
    .unwrap()
}

fn replacement_destination(endpoint: String) -> RequestedLeg {
    RequestedLeg {
        direction: LegDirection::Outbound,
        signaling_initiator: Some(SignalingInitiator::Bridgefu),
        media_flow: MediaFlow::SendReceive,
        endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
            uri: Some(endpoint),
            initial_context: SipInitialContextMode::None,
        }),
        amazon_connect_start: None,
    }
}

fn replacement_route_binding(route_id: &str) -> NamedRouteBinding {
    NamedRouteBinding::new_with_profiles(
        route_id,
        None,
        vec![NamedProfileBinding::new(
            NamedProfileRole::Destination,
            NamedProfileKind::Sip,
            CALL_CENTER_PROFILE_ID,
            CALL_CENTER_PROFILE_REVISION,
        )
        .unwrap()],
    )
    .unwrap()
}

async fn start_replacement(
    runtime: &CallServiceRuntime,
    call_id: CallId,
    leg_id: LegId,
    endpoint: String,
    route_id: &str,
    idempotency: &str,
) {
    runtime
        .service()
        .replace_leg(
            &principal(),
            call_id,
            leg_id,
            &IdempotencyKey::parse(idempotency).unwrap(),
            ReplaceLegInput {
                tenant_id: None,
                route_id: route_id.into(),
            },
            replacement_destination(endpoint),
            replacement_route_binding(route_id),
        )
        .await
        .expect("server-owned SIP replacement is accepted");
}

async fn index() -> Html<&'static str> {
    Html(include_str!(
        "../sdk/typescript/test/browser-qualification.html"
    ))
}

async fn attachment(State(state): State<BrowserHttpState>) -> Json<Value> {
    Json((*state.attachment).clone())
}

async fn destination_ready(State(state): State<BrowserHttpState>) -> Json<Value> {
    Json(json!({
        "ready": state.destination_ready.load(Ordering::Acquire),
    }))
}

async fn destination_verified(State(state): State<BrowserHttpState>) -> Json<Value> {
    Json(json!({
        "verified": state.destination_verified.load(Ordering::Acquire),
    }))
}

async fn browser_diagnostics(
    State(state): State<BrowserHttpState>,
    Json(diagnostics): Json<Value>,
) -> StatusCode {
    *state
        .diagnostics
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(diagnostics);
    StatusCode::NO_CONTENT
}

async fn browser_phase(
    State(state): State<BrowserHttpState>,
    Json(observation): Json<Value>,
) -> StatusCode {
    let Some(phase) = observation.get("phase").and_then(Value::as_str) else {
        return StatusCode::BAD_REQUEST;
    };
    if phase.is_empty()
        || phase.len() > 64
        || !phase
            .bytes()
            .all(|value| value.is_ascii_lowercase() || value == b'-')
    {
        return StatusCode::BAD_REQUEST;
    }
    state
        .phases
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(observation);
    StatusCode::NO_CONTENT
}

async fn sdk_file(
    State(state): State<BrowserHttpState>,
    AxumPath(file): AxumPath<String>,
) -> Response {
    if file.is_empty()
        || !file
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, '.' | '-' | '_'))
    {
        return (StatusCode::BAD_REQUEST, "invalid SDK filename").into_response();
    }
    let path = state.sdk_dist.join(&file);
    match tokio::fs::read(path).await {
        Ok(bytes) => (
            [(
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            )],
            bytes,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "SDK module not found").into_response(),
    }
}

async fn wait_for_call(
    runtime: &CallServiceRuntime,
    call_id: CallId,
    predicate: impl Fn(&bridgefu::call_service::StoredServiceCall) -> bool,
) -> bridgefu::call_service::StoredServiceCall {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let stored = runtime
                .service_repository()
                .load_service_call(&TenantId::parse(TENANT).unwrap(), call_id)
                .await
                .unwrap();
            if predicate(&stored) {
                return stored;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("durable call-state deadline")
}

async fn current_binding(
    runtime: &CallServiceRuntime,
    call_id: CallId,
    direction: LegDirection,
) -> (LegId, BindingGeneration, rvoip_core::ConnectionId) {
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
        .expect("call retains its logical leg");
    let binding = &stored.call.bindings[&leg.id()];
    (
        leg.id(),
        binding.binding_generation,
        binding.connection_id.clone(),
    )
}

async fn wait_for_active_bridge_count(orchestrator: &Orchestrator, expected: u64) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                orchestrator.capacity_report(),
                Event::CapacityReport { active_bridges, .. } if active_bridges == expected
            ) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("active bridge count did not become {expected}"));
}

async fn wait_for_browser_phase(phases: &Arc<Mutex<Vec<Value>>>, expected: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(observation) = phases
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .find(|observation| observation["phase"].as_str() == Some(expected))
                .cloned()
            {
                return observation;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("Chromium did not report {expected}"))
}

async fn wait_connection_dead(
    label: &'static str,
    orchestrator: &Orchestrator,
    adapter: &dyn ConnectionAdapter,
    connection_id: &rvoip_core::ConnectionId,
) {
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        while adapter.is_connection_live(connection_id) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        result.is_ok(),
        "{label}: terminal signaling route was retained; connection={connection_id}; adapter_kind={:?}; transport={:?}; live={}; capacity={:?}; lifecycle_tasks={}",
        adapter.kind(),
        adapter.transport(),
        adapter.is_connection_live(connection_id),
        orchestrator.capacity_report(),
        orchestrator.connection_lifecycle_task_count(),
    );
}

async fn wait_promoted_sip_route_dead(
    runtime: &CallServiceRuntime,
    call_id: CallId,
    outbound_leg: LegId,
    orchestrator: &Orchestrator,
    local_adapter: &SipAdapter,
    local_connection: &rvoip_core::ConnectionId,
    remote_adapter: &SipAdapter,
    remote_connection: &rvoip_core::ConnectionId,
    core_events: &mut tokio::sync::broadcast::Receiver<Event>,
    remote_events: &mut mpsc::Receiver<AdapterEvent>,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut local_terminal_events = Vec::new();
    let mut remote_terminal_events = Vec::new();
    loop {
        loop {
            match core_events.try_recv() {
                Ok(Event::ConnectionEnded { connection_id, .. })
                    if connection_id == *local_connection =>
                {
                    local_terminal_events.push("ended")
                }
                Ok(Event::ConnectionFailed { connection_id, .. })
                    if connection_id == *local_connection =>
                {
                    local_terminal_events.push("failed")
                }
                Ok(_) | Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                    local_terminal_events.push("event_stream_closed");
                    break;
                }
            }
        }
        loop {
            match remote_events.try_recv() {
                Ok(AdapterEvent::Ended { connection_id, .. })
                    if connection_id == *remote_connection =>
                {
                    remote_terminal_events.push("ended")
                }
                Ok(AdapterEvent::Failed { connection_id, .. })
                    if connection_id == *remote_connection =>
                {
                    remote_terminal_events.push("failed")
                }
                Ok(_) => {}
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    remote_terminal_events.push("event_stream_closed");
                    break;
                }
            }
        }

        if !remote_adapter.is_connection_live(remote_connection) {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let tenant_id = TenantId::parse(TENANT).unwrap();
    let stored = runtime
        .service_repository()
        .load_service_call(&tenant_id, call_id)
        .await
        .expect("load durable call for terminal cleanup diagnostics");
    let legs = stored
        .call
        .aggregate
        .legs()
        .iter()
        .map(|leg| {
            json!({
                "direction": format!("{:?}", leg.direction()),
                "kind": format!("{:?}", leg.kind()),
                "state": format!("{:?}", leg.state()),
                "binding_generation": leg.binding_generation().value(),
                "failure_code": leg.failure().map(|failure| failure.code()),
            })
        })
        .collect::<Vec<_>>();
    let current_binding = stored.call.bindings.get(&outbound_leg);
    let local_live = local_adapter.is_connection_live(local_connection);
    let stop_leg_inference = if local_live {
        "local_transport_cleanup_not_observed"
    } else if local_terminal_events.is_empty() {
        "local_route_retired_without_buffered_core_terminal"
    } else {
        "local_transport_cleanup_completed"
    };
    let diagnostics = json!({
        "durable_call_state": format!("{:?}", stored.call.aggregate.state()),
        "durable_legs": legs,
        "durable_outbound_binding_generation": current_binding
            .map(|binding| binding.binding_generation.value()),
        "durable_outbound_binding_matches_local": current_binding
            .is_some_and(|binding| binding.connection_id == *local_connection),
        "stop_leg_inference": stop_leg_inference,
        "local_route_live": local_live,
        "local_core_terminal_events": local_terminal_events,
        "local_adapter_retained_tasks": local_adapter.retained_task_count(),
        "remote_route_live": remote_adapter.is_connection_live(remote_connection),
        "remote_terminal_events": remote_terminal_events,
        "remote_adapter_retained_tasks": remote_adapter.retained_task_count(),
        "orchestrator_lifecycle_tasks": orchestrator.connection_lifecycle_task_count(),
        "orchestrator_capacity": format!("{:?}", orchestrator.capacity_report()),
    });
    panic!(
        "terminal generation-3 promoted call-center route was retained; redacted diagnostics={diagnostics}"
    );
}

async fn drain_audio_until_quiet(receiver: &mut mpsc::Receiver<MediaFrame>) {
    while tokio::time::timeout(Duration::from_millis(100), receiver.recv())
        .await
        .is_ok_and(|frame| frame.is_some())
    {}
}

async fn assert_no_audio(receiver: &mut mpsc::Receiver<MediaFrame>, reason: &'static str) {
    match tokio::time::timeout(Duration::from_millis(350), receiver.recv()).await {
        Err(_) => {}
        Ok(Some(frame)) => panic!(
            "{reason}: received unexpected media payload type {:?}",
            frame.payload_type
        ),
        Ok(None) => panic!("{reason}: media receiver closed"),
    }
}

async fn next_inbound(events: &mut mpsc::Receiver<AdapterEvent>) -> rvoip_core::ConnectionId {
    loop {
        match events.recv().await {
            Some(AdapterEvent::InboundConnection { connection }) => return connection.id,
            Some(_) => {}
            None => panic!("SIP destination event stream closed"),
        }
    }
}

async fn audio_stream(
    adapter: &dyn ConnectionAdapter,
    connection_id: &rvoip_core::ConnectionId,
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
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("destination audio stream deadline")
}

async fn next_labeled_data(
    events: &mut mpsc::Receiver<AdapterEvent>,
    connection_id: &rvoip_core::ConnectionId,
    label: &str,
) -> DataMessage {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await {
                Some(AdapterEvent::DataMessage {
                    connection_id: observed,
                    message,
                }) if &observed == connection_id && message.label == label => return message,
                Some(_) => {}
                None => panic!("SIP destination event stream closed before DataMessage"),
            }
        }
    })
    .await
    .expect("SIP destination DataMessage deadline")
}

async fn send_pcmu(stream: Arc<dyn MediaStream>) -> usize {
    let mut sent = 0;
    for sequence in 0..30 {
        if stream
            .frames_out()
            .send(MediaFrame {
                stream_id: stream.id(),
                kind: StreamKind::Audio,
                payload: bytes::Bytes::from(vec![0xff; 160]),
                timestamp_rtp: 32_000 + sequence * 160,
                captured_at: Utc::now(),
                payload_type: Some(0),
            })
            .await
            .is_err()
        {
            break;
        }
        sent += 1;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    sent
}

fn assert_initial_context(context: InboundConnectionContext) {
    assert_eq!(
        context
            .metadata()
            .values("X-Correlation-Id")
            .collect::<Vec<_>>(),
        ["chromium-browser-correlation"]
    );
    assert_eq!(
        context
            .metadata()
            .values("X-Account-Tier")
            .collect::<Vec<_>>(),
        ["chromium"]
    );
    assert!(
        context
            .metadata()
            .values("X-Unmapped-Private")
            .next()
            .is_none(),
        "unallowlisted browser context became a SIP header"
    );
}

fn find_playwright(standardcharter_web: &Path) {
    assert!(
        standardcharter_web.join("node_modules/playwright").is_dir(),
        "Playwright is absent; run the pinned StandardCharter web install before this ignored test"
    );
}

#[test]
#[ignore = "requires the pinned StandardCharter Playwright Chromium; run explicitly with --ignored"]
fn built_typescript_sdk_reaches_named_sips_destination_in_real_chromium() {
    std::thread::Builder::new()
        .name("browser-sdk-chromium-qualification".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(6)
                .thread_stack_size(8 * 1024 * 1024)
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(run_browser_qualification()));
        })
        .unwrap()
        .join()
        .expect("browser SDK Chromium qualification panicked");
}

async fn run_browser_qualification() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let sdk = repository.join("sdk/typescript");
    let standardcharter_web = repository.join("../standardcharter/web");
    find_playwright(&standardcharter_web);
    let build = tokio::process::Command::new("npm")
        .args(["run", "build"])
        .current_dir(&sdk)
        .output()
        .await
        .expect("execute the SDK build");
    assert!(
        build.status.success(),
        "SDK build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr),
    );

    let web_certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let web_certificate_pem = web_certificate.cert.pem().into_bytes();
    let web_private_key = web_certificate.signing_key.serialize_pem().into_bytes();
    let web_tls = TlsConfig::from_pem_bytes(&web_certificate_pem, &web_private_key)
        .await
        .unwrap();
    let sip_tls = TestTlsFiles::create();

    let runtime = call_runtime().await;
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let mut bridge_web_config = WebRtcConfig::loopback();
    bridge_web_config.max_concurrent_sessions = 2;
    bridge_web_config.trickle_ice = true;
    bridge_web_config
        .capabilities
        .audio_codecs
        .retain(|codec| codec.name.eq_ignore_ascii_case("opus"));
    let bridge_web_adapter = WebRtcAdapter::new_with_inbound_admission_confirmation(
        bridge_web_config,
        Duration::from_secs(15),
    )
    .unwrap();

    let bridge_sip_udp = reserve_udp();
    let bridge_sip_tls = reserve_tcp();
    let bridge_sip_config = tls_sip_config(
        "bridgefu-browser-sdk-egress",
        bridge_sip_udp,
        bridge_sip_tls,
        &sip_tls,
        vec![0, 101],
    );
    let bridge_sip_policy = SipListenerAuthPolicy::enabled_for_tenant(TENANT)
        .unwrap()
        .with_trusted_cidr(
            "127.0.0.1/32".parse().unwrap(),
            principal().authenticated().clone(),
        );
    let bridge_sip_coordinator =
        rvoip_sip::UnifiedCoordinator::new_with_listener_auth(bridge_sip_config, bridge_sip_policy)
            .await
            .unwrap();
    let bridge_sip_adapter = SipAdapter::new(Arc::clone(&bridge_sip_coordinator))
        .await
        .unwrap();

    let mut resolver = StaticOutboundProfileResolver::default();
    resolver.insert_sip(
        SIP_PROFILE_ID.into(),
        SIP_PROFILE_REVISION.into(),
        ConfiguredSipOutboundProfile {
            from_uri: format!(
                "sips:bridgefu-browser@localhost:{};transport=tls",
                bridge_sip_tls.port()
            ),
            outbound_proxy: None,
            auth: Some(ConfiguredSipProfileAuth::Digest {
                realm: Some(SIP_DIGEST_REALM.into()),
                username: SIP_DIGEST_USER.into(),
                password: SecretRef::new(SIP_DIGEST_PASSWORD),
            }),
        },
    );
    resolver.insert_sip(
        CALL_CENTER_PROFILE_ID.into(),
        CALL_CENTER_PROFILE_REVISION.into(),
        ConfiguredSipOutboundProfile {
            from_uri: format!(
                "sips:bridgefu-call-center@localhost:{};transport=tls",
                bridge_sip_tls.port()
            ),
            outbound_proxy: None,
            auth: Some(ConfiguredSipProfileAuth::Digest {
                realm: Some(CALL_CENTER_DIGEST_REALM.into()),
                username: CALL_CENTER_DIGEST_USER.into(),
                password: SecretRef::new(CALL_CENTER_DIGEST_PASSWORD),
            }),
        },
    );
    let supervisor = CallExecutionSupervisor::install_with_leg_executors_context_canary_broadcast_and_outbound_profiles(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        Arc::new(DisabledProviderLegExecutor),
        None,
        Arc::new(ContextPolicy {
            allow_headers: BTreeMap::from([
                ("X-Correlation-Id".into(), "correlation_id".into()),
                ("X-Account-Tier".into(), "account_tier".into()),
            ]),
        }),
        None,
        None,
        Arc::new(resolver),
        2,
        Duration::from_secs(20),
    )
    .await
    .unwrap();
    orchestrator
        .register(Arc::clone(&bridge_web_adapter) as Arc<dyn ConnectionAdapter>)
        .unwrap();
    orchestrator
        .register(Arc::clone(&bridge_sip_adapter) as Arc<dyn ConnectionAdapter>)
        .unwrap();

    let destination_udp = reserve_udp();
    let destination_tls = reserve_tcp();
    let destination_config = tls_sip_config(
        "browser-sdk-sip-destination",
        destination_udp,
        destination_tls,
        &sip_tls,
        vec![0, 101],
    );
    let destination_policy = SipListenerAuthPolicy::authenticated_for_tenant(
        SIP_PROFILE_ID,
        SipAuthService::digest(SIP_DIGEST_REALM)
            .with_digest_user(SIP_DIGEST_USER, SIP_DIGEST_PASSWORD),
    )
    .unwrap();
    let destination_coordinator = rvoip_sip::UnifiedCoordinator::new_with_listener_auth(
        destination_config,
        destination_policy,
    )
    .await
    .unwrap();
    let destination_adapter = SipAdapter::new_with_inbound_context_policy(
        Arc::clone(&destination_coordinator),
        SipInboundContextPolicy::new(["X-Correlation-Id", "X-Account-Tier", "X-Unmapped-Private"])
            .unwrap(),
    )
    .await
    .unwrap();
    let mut destination_events = destination_adapter.subscribe_events();

    let call_center_udp = reserve_udp();
    let call_center_tls = reserve_tcp();
    let call_center_config = tls_sip_config(
        "browser-sdk-call-center",
        call_center_udp,
        call_center_tls,
        &sip_tls,
        vec![0, 101],
    );
    let call_center_policy = SipListenerAuthPolicy::authenticated_for_tenant(
        CALL_CENTER_PROFILE_ID,
        SipAuthService::digest(CALL_CENTER_DIGEST_REALM)
            .with_digest_user(CALL_CENTER_DIGEST_USER, CALL_CENTER_DIGEST_PASSWORD),
    )
    .unwrap();
    let call_center_coordinator = rvoip_sip::UnifiedCoordinator::new_with_listener_auth(
        call_center_config,
        call_center_policy,
    )
    .await
    .unwrap();
    let call_center_adapter = SipAdapter::new_with_inbound_context_policy(
        Arc::clone(&call_center_coordinator),
        SipInboundContextPolicy::new(["X-Correlation-Id", "X-Account-Tier"]).unwrap(),
    )
    .await
    .unwrap();
    let mut call_center_events = call_center_adapter.subscribe_events();

    let wss_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let wss_address = wss_listener.local_addr().unwrap();
    let (wss_shutdown_tx, wss_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let wss_server = {
        let adapter = Arc::clone(&bridge_web_adapter);
        let auth: Arc<dyn WsAuthHook> = Arc::new(AttachmentAuth {
            principal: principal().authenticated().clone(),
        });
        tokio::spawn(async move {
            serve_tls_listener_with_auth_and_shutdown(wss_listener, web_tls, adapter, auth, async {
                let _ = wss_shutdown_rx.await;
            })
            .await
        })
    };

    let created = runtime
        .service()
        .create_named_route_call(
            &principal(),
            &IdempotencyKey::parse("browser-sdk-chromium-call").unwrap(),
            route_input(format!(
                "sips:agent@localhost:{};transport=tls",
                destination_tls.port()
            )),
            route_binding(),
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
    let source_attachment = source.attachment.as_ref().unwrap();
    let token = source_attachment.token.clone();
    let expires_at = source_attachment.expires_at.to_rfc3339();
    let signaling_uri = format!("wss://localhost:{}/signal", wss_address.port());
    let fixture_attachment = json!({
        "route_attachment": {
            "type": "webrtc",
            "signaling_uri": signaling_uri,
            "token": token,
            "signaling_credential": {
                "usage": "bridgefu-webrtc-signaling",
                "token": token,
                "expires_at": expires_at,
            },
            "subprotocols": [
                "rvoip.webrtc.v1",
                format!("token.{token}"),
                format!("bridgefu.attach.{token}"),
            ],
            "ice_servers": [],
            "expires_at": expires_at,
        },
        "binding": {
            "tenantId": TENANT,
            "callId": call_id.to_string(),
            "legId": source_leg_id.to_string(),
        },
        "scenario": {
            "name": "generic-sip",
            "expectedRemoteContextCorrelationId": "sip-to-browser-later-context",
        },
        "qualification": {
            "liveProviderQualified": false,
            "turnQualified": false,
            "browserPublicTlsQualified": false,
        },
    });
    let destination_ready_flag = Arc::new(AtomicBool::new(false));
    let destination_verified_flag = Arc::new(AtomicBool::new(false));
    let browser_diagnostics_state = Arc::new(Mutex::new(None));
    let browser_phases = Arc::new(Mutex::new(Vec::new()));
    let http_state = BrowserHttpState {
        attachment: Arc::new(fixture_attachment),
        destination_ready: Arc::clone(&destination_ready_flag),
        destination_verified: Arc::clone(&destination_verified_flag),
        diagnostics: Arc::clone(&browser_diagnostics_state),
        phases: Arc::clone(&browser_phases),
        sdk_dist: Arc::new(sdk.join("dist")),
    };
    let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_address = http_listener.local_addr().unwrap();
    let (http_shutdown_tx, http_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let http_server = tokio::spawn(async move {
        axum::serve(
            http_listener,
            Router::new()
                .route("/", get(index))
                .route("/attachment", get(attachment))
                .route("/destination-ready", get(destination_ready))
                .route("/destination-verified", get(destination_verified))
                .route("/browser-diagnostics", post(browser_diagnostics))
                .route("/browser-phase", post(browser_phase))
                .route("/sdk/:file", get(sdk_file))
                .with_state(http_state),
        )
        .with_graceful_shutdown(async {
            let _ = http_shutdown_rx.await;
        })
        .await
    });

    let driver = sdk.join("test/browser-qualification-driver.mjs");
    let mut browser_child = tokio::process::Command::new("node");
    browser_child
        .arg(driver)
        .env(
            "BRIDGEFU_BROWSER_QUALIFICATION_URL",
            format!("http://localhost:{}/", http_address.port()),
        )
        .env("BRIDGEFU_STANDARDCHARTER_WEB", &standardcharter_web)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let browser_child = browser_child.spawn().expect("launch Playwright driver");
    let mut browser_output = tokio::spawn(browser_child.wait_with_output());
    let mut core_events = orchestrator.subscribe_events();

    let destination_connection = {
        let destination_inbound = next_inbound(&mut destination_events);
        tokio::pin!(destination_inbound);
        tokio::time::timeout(Duration::from_secs(25), async {
            tokio::select! {
                connection = &mut destination_inbound => connection,
                output = &mut browser_output => {
                    let output = output
                        .expect("Chromium wait task")
                        .expect("Chromium process wait");
                    panic!(
                        "Chromium exited before SIPS destination with {}:\nstdout:\n{}\nstderr:\n{}",
                        output.status,
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr),
                    );
                }
            }
        })
        .await
        .expect("browser context did not release the SIPS destination")
    };
    assert_initial_context(
        destination_adapter
            .take_inbound_context(&destination_connection)
            .expect("destination retained sanitized initial context"),
    );
    destination_adapter
        .accept(destination_connection.clone())
        .await
        .expect("Digest-authenticated SIPS destination accepts");
    let active_call = wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;
    let outbound_leg = active_call
        .call
        .aggregate
        .legs()
        .iter()
        .find(|leg| leg.direction() == LegDirection::Outbound)
        .unwrap()
        .id();
    let source_leg = active_call
        .call
        .aggregate
        .legs()
        .iter()
        .find(|leg| leg.direction() == LegDirection::Inbound)
        .unwrap()
        .id();
    let bridgefu_source_connection = active_call.call.bindings[&source_leg].connection_id.clone();
    let bridgefu_sip_connection = active_call.call.bindings[&outbound_leg]
        .connection_id
        .clone();
    let source_generation = active_call.call.bindings[&source_leg].binding_generation;
    let assistant_generation = active_call.call.bindings[&outbound_leg].binding_generation;
    let readiness_probe = DataMessage::reliable(
        "bridgefu.browser-sdk.readiness.v1",
        "application/octet-stream",
        bytes::Bytes::from_static(b"ready"),
    );
    orchestrator
        .send_data_message(bridgefu_sip_connection.clone(), readiness_probe.clone())
        .await
        .expect("active outbound SIP dialog accepts readiness probe");
    assert_eq!(
        next_labeled_data(
            &mut destination_events,
            &destination_connection,
            "bridgefu.browser-sdk.readiness.v1",
        )
        .await,
        readiness_probe
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                orchestrator.capacity_report(),
                Event::CapacityReport {
                    active_bridges: 1,
                    ..
                }
            ) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("named route did not commit its media/data/DTMF bridge");
    destination_ready_flag.store(true, Ordering::Release);

    let destination_stream =
        audio_stream(destination_adapter.as_ref(), &destination_connection).await;
    assert_eq!(
        destination_stream.codec().name.to_ascii_lowercase(),
        "g.711-mu"
    );
    let mut microphone_audio = destination_stream.try_frames_in().unwrap();
    let remote_media = tokio::spawn(send_pcmu(Arc::clone(&destination_stream)));
    let mut saw_microphone_audio = false;
    let mut saw_core_arbitrary_message = false;
    let mut saw_core_later_context = false;
    let mut captured_core_later_context = None;
    let mut saw_later_context = false;
    let mut saw_arbitrary_sip_message = false;
    let mut saw_core_browser_dtmf = false;
    let mut saw_browser_dtmf = false;
    let evidence = tokio::time::timeout(Duration::from_secs(20), async {
        while !saw_microphone_audio
            || !saw_core_arbitrary_message
            || !saw_core_later_context
            || !saw_later_context
            || !saw_arbitrary_sip_message
            || !saw_core_browser_dtmf
            || !saw_browser_dtmf
        {
            tokio::select! {
                frame = microphone_audio.recv(), if !saw_microphone_audio => {
                    let frame = match frame {
                        Some(frame) => frame,
                        None => {
                            let output = tokio::time::timeout(Duration::from_secs(10), &mut browser_output)
                                .await
                                .expect("Chromium failure output deadline")
                                .expect("Chromium wait task")
                                .expect("Chromium process wait");
                            panic!(
                                "fake microphone stream closed after Chromium exited with {}:\nstdout:\n{}\nstderr:\n{}",
                                output.status,
                                String::from_utf8_lossy(&output.stdout),
                                String::from_utf8_lossy(&output.stderr),
                            );
                        }
                    };
                    assert_eq!(frame.payload_type, Some(0));
                    assert!(
                        matches!(frame.payload.len(), 80 | 160),
                        "browser Opus transcoded to an unexpected PCMU packet size: {}",
                        frame.payload.len()
                    );
                    saw_microphone_audio = true;
                }
                event = destination_events.recv() => {
                    match event.expect("SIP destination event stream closed") {
                        AdapterEvent::DataMessage { connection_id, message }
                            if connection_id == destination_connection && message.label == CONTEXT_LABEL =>
                        {
                            let envelope = ContextEnvelope::from_data_message(&message)
                                .expect("later browser context stays well formed");
                            assert_eq!(envelope.correlation_id, "chromium-browser-later-context");
                            assert_eq!(envelope.tenant_id, TENANT);
                            assert_eq!(envelope.call_id, call_id.to_string());
                            assert_eq!(envelope.source_leg_id, source_leg.to_string());
                            assert_eq!(
                                envelope.metadata.get("account_tier").map(String::as_str),
                                Some("chromium-updated")
                            );
                            saw_later_context = true;
                        }
                        AdapterEvent::DataMessage { connection_id, message }
                            if connection_id == destination_connection && message.label == BROWSER_MESSAGE_LABEL =>
                        {
                            saw_arbitrary_sip_message = true;
                        }
                        AdapterEvent::Dtmf { connection_id, digits, .. }
                            if connection_id == destination_connection =>
                        {
                            assert_eq!(digits, "6");
                            saw_browser_dtmf = true;
                        }
                        _ => {}
                    }
                }
                event = core_events.recv() => {
                    match event {
                        Ok(Event::DataMessageReceived { connection_id, message, .. })
                            if message.label == BROWSER_MESSAGE_LABEL =>
                        {
                            assert_eq!(connection_id, bridgefu_source_connection);
                            assert_eq!(message.content_type, "application/octet-stream");
                            assert_eq!(message.bytes.as_ref(), [0, 255, 66]);
                            assert_eq!(message.reliability, DataReliability::ReliableOrdered);
                            saw_core_arbitrary_message = true;
                        }
                        Ok(Event::DataMessageReceived { connection_id, message, .. })
                            if connection_id == bridgefu_source_connection && message.label == CONTEXT_LABEL =>
                        {
                            if let Ok(envelope) = ContextEnvelope::from_data_message(&message) {
                                if envelope.correlation_id == "chromium-browser-later-context" {
                                    assert_eq!(message.reliability, DataReliability::ReliableOrdered);
                                    captured_core_later_context = Some(message);
                                    saw_core_later_context = true;
                                }
                            }
                        }
                        Ok(Event::DtmfReceived { connection_id, digits, .. })
                            if connection_id == bridgefu_source_connection =>
                        {
                            assert_eq!(digits, "6");
                            saw_core_browser_dtmf = true;
                        }
                        Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            panic!("orchestrator event stream closed")
                        }
                    }
                }
            }
        }
    })
    .await;
    let captured_diagnostics = browser_diagnostics_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    if evidence.is_err() {
        let direct_sip_dispatch = match captured_core_later_context.as_ref() {
            Some(message) => bridge_sip_adapter
                .send_data_message(bridgefu_sip_connection, message.clone())
                .await
                .map(|_| "accepted")
                .map_err(|error| error.to_string()),
            None => Err("no later context reached rvoip core".to_string()),
        };
        panic!(
            "browser microphone/context/DataChannel evidence deadline: microphone={saw_microphone_audio}, core_arbitrary={saw_core_arbitrary_message}, core_later_context={saw_core_later_context}, sip_later_context={saw_later_context}, arbitrary_sip={saw_arbitrary_sip_message}, core_dtmf={saw_core_browser_dtmf}, sip_dtmf={saw_browser_dtmf}, direct_sip_dispatch={direct_sip_dispatch:?}, browser_diagnostics={captured_diagnostics:?}"
        );
    }

    let observed_browser_payload_type = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(payload_type) = bridge_web_adapter
                .last_inbound_audio_payload_type(&bridgefu_source_connection)
                .expect("browser WebRTC route remains available")
            {
                break payload_type;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("browser WebRTC wire payload-type observation deadline");
    assert_eq!(
        observed_browser_payload_type, 111,
        "Chromium must send Opus/PT111 on the deterministic browser profile"
    );
    let browser_graph = orchestrator
        .media_graph_snapshot(&bridgefu_source_connection)
        .await
        .expect("browser source MediaGraph remains active");
    assert_eq!(browser_graph.source_codec.name, "opus");
    assert_eq!(browser_graph.source_payload_type, 111);
    assert!(
        browser_graph.transcode_operations > 0,
        "wire PT evidence must include a real Opus-to-PCMU transcode"
    );
    assert_eq!(
        browser_graph.transcode_errors, 0,
        "the qualified browser flow cannot hide InvalidPacket transcodes"
    );

    assert!(
        remote_media.await.expect("initial assistant PCMU task") > 0,
        "no Vapi-like assistant PCMU frame reached the browser route"
    );

    let rejected_generation = assistant_generation.next().unwrap();
    start_replacement(
        &runtime,
        call_id,
        outbound_leg,
        format!(
            "sips:busy-agent@localhost:{};transport=tls",
            call_center_tls.port()
        ),
        "browser-sdk-busy-call-center",
        "browser-sdk-rejected-handoff",
    )
    .await;
    wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state() == CallState::Transferring
            && stored
                .call
                .aggregate
                .replacement()
                .is_some_and(|replacement| {
                    replacement.pending_binding_generation() == rejected_generation
                })
    })
    .await;
    let rejected_connection = tokio::time::timeout(
        Duration::from_secs(10),
        next_inbound(&mut call_center_events),
    )
    .await
    .expect("rejecting call center INVITE deadline");
    wait_for_active_bridge_count(&orchestrator, 0).await;
    assert!(destination_adapter.is_connection_live(&destination_connection));
    let reject_hold = wait_for_browser_phase(&browser_phases, "reject-hold-ready").await;
    assert_eq!(reject_hold["peerConnectionState"], "connected");
    assert_eq!(
        reject_hold["serverConnectionId"],
        bridgefu_source_connection.to_string()
    );
    drain_audio_until_quiet(&mut microphone_audio).await;
    let rejected_hold_media = tokio::spawn(send_pcmu(Arc::clone(&destination_stream)));
    assert_no_audio(
        &mut microphone_audio,
        "browser microphone leaked to the held assistant during rejected handoff",
    )
    .await;
    assert!(
        rejected_hold_media
            .await
            .expect("held assistant media task")
            > 0,
        "held assistant media source closed before rejection"
    );
    call_center_adapter
        .reject(rejected_connection.clone(), RejectReason::Decline)
        .await
        .expect("call-center replacement rejection");
    let resumed = wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
            && stored.call.aggregate.replacement().is_none()
            && stored
                .call
                .bindings
                .get(&outbound_leg)
                .is_some_and(|binding| {
                    binding.binding_generation == assistant_generation
                        && binding.connection_id == bridgefu_sip_connection
                })
    })
    .await;
    wait_for_active_bridge_count(&orchestrator, 1).await;
    let reject_resumed = wait_for_browser_phase(&browser_phases, "reject-resumed").await;
    assert_eq!(reject_resumed["peerConnectionState"], "connected");
    assert_eq!(
        reject_resumed["serverConnectionId"],
        bridgefu_source_connection.to_string()
    );
    assert_eq!(
        (
            source_leg,
            source_generation,
            bridgefu_source_connection.clone()
        ),
        current_binding(&runtime, call_id, LegDirection::Inbound).await,
        "browser source binding changed during rejected handoff"
    );
    assert_eq!(
        resumed.call.bindings[&outbound_leg].connection_id,
        bridgefu_sip_connection
    );
    wait_connection_dead(
        "rejected generation-2 call-center route",
        &orchestrator,
        call_center_adapter.as_ref(),
        &rejected_connection,
    )
    .await;
    let resumed_microphone = tokio::time::timeout(Duration::from_secs(10), microphone_audio.recv())
        .await
        .expect("resumed browser-to-assistant media deadline")
        .expect("resumed assistant media route remained live");
    assert_eq!(resumed_microphone.payload_type, Some(0));
    let resumed_assistant_media = tokio::spawn(send_pcmu(Arc::clone(&destination_stream)));
    wait_for_browser_phase(&browser_phases, "reject-resume-audio").await;
    assert!(
        resumed_assistant_media
            .await
            .expect("resumed assistant media task")
            > 0
    );

    let successful_generation = rejected_generation.next().unwrap();
    start_replacement(
        &runtime,
        call_id,
        outbound_leg,
        format!(
            "sips:agent@localhost:{};transport=tls",
            call_center_tls.port()
        ),
        "browser-sdk-call-center",
        "browser-sdk-successful-handoff",
    )
    .await;
    wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state() == CallState::Transferring
            && stored
                .call
                .aggregate
                .replacement()
                .is_some_and(|replacement| {
                    replacement.pending_binding_generation() == successful_generation
                })
    })
    .await;
    let call_center_connection = tokio::time::timeout(
        Duration::from_secs(10),
        next_inbound(&mut call_center_events),
    )
    .await
    .expect("successful call-center INVITE deadline");
    wait_for_active_bridge_count(&orchestrator, 0).await;
    assert!(destination_adapter.is_connection_live(&destination_connection));
    let success_hold = wait_for_browser_phase(&browser_phases, "success-hold-ready").await;
    assert_eq!(success_hold["peerConnectionState"], "connected");
    assert_eq!(
        success_hold["serverConnectionId"],
        bridgefu_source_connection.to_string()
    );
    drain_audio_until_quiet(&mut microphone_audio).await;
    let successful_hold_media = tokio::spawn(send_pcmu(Arc::clone(&destination_stream)));
    assert_no_audio(
        &mut microphone_audio,
        "browser microphone leaked to the held assistant during successful handoff",
    )
    .await;
    assert!(
        successful_hold_media
            .await
            .expect("successful held assistant media task")
            > 0,
        "held assistant media source closed before promotion"
    );
    call_center_adapter
        .accept(call_center_connection.clone())
        .await
        .expect("call-center replacement accepts");
    let promoted = wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
            && stored.call.aggregate.replacement().is_none()
            && stored
                .call
                .bindings
                .get(&outbound_leg)
                .is_some_and(|binding| {
                    binding.binding_generation == successful_generation
                        && binding.connection_id != bridgefu_sip_connection
                })
    })
    .await;
    wait_for_active_bridge_count(&orchestrator, 1).await;
    let success_connected = wait_for_browser_phase(&browser_phases, "success-connected").await;
    assert_eq!(success_connected["peerConnectionState"], "connected");
    assert_eq!(
        success_connected["serverConnectionId"],
        bridgefu_source_connection.to_string()
    );
    assert_eq!(
        (
            source_leg,
            source_generation,
            bridgefu_source_connection.clone()
        ),
        current_binding(&runtime, call_id, LegDirection::Inbound).await,
        "browser source binding changed during successful handoff"
    );
    assert_ne!(
        promoted.call.bindings[&outbound_leg].connection_id, bridgefu_sip_connection,
        "promoted binding must replace the assistant"
    );
    let bridgefu_call_center_connection =
        promoted.call.bindings[&outbound_leg].connection_id.clone();
    wait_connection_dead(
        "retired generation-1 Vapi-like assistant route",
        &orchestrator,
        destination_adapter.as_ref(),
        &destination_connection,
    )
    .await;

    let call_center_stream =
        audio_stream(call_center_adapter.as_ref(), &call_center_connection).await;
    assert_eq!(
        call_center_stream.codec().name.to_ascii_lowercase(),
        "g.711-mu"
    );
    let mut call_center_audio = call_center_stream.try_frames_in().unwrap();
    let agent_microphone = tokio::time::timeout(Duration::from_secs(10), call_center_audio.recv())
        .await
        .expect("browser-to-agent media deadline")
        .expect("promoted call-center route remained live");
    assert_eq!(agent_microphone.payload_type, Some(0));
    let agent_media = tokio::spawn(send_pcmu(Arc::clone(&call_center_stream)));
    wait_for_browser_phase(&browser_phases, "agent-audio").await;
    assert!(
        agent_media.await.expect("call-center media task") > 0,
        "promoted call center sent no media"
    );

    let mut remote_context = ContextEnvelope::new(
        "sip-to-browser-later-context",
        TENANT,
        call_id.to_string(),
        outbound_leg.to_string(),
    );
    remote_context
        .metadata
        .insert("agent_state".into(), "ready".into());
    call_center_adapter
        .send_data_message(
            call_center_connection.clone(),
            remote_context.to_data_message().unwrap(),
        )
        .await
        .expect("call-center SIP MESSAGE reaches the browser context DataChannel");

    let final_actions = wait_for_browser_phase(&browser_phases, "destination-actions-sent").await;
    assert_eq!(final_actions["peerConnectionState"], "connected");
    assert_eq!(
        final_actions["serverConnectionId"],
        bridgefu_source_connection.to_string()
    );
    let mut saw_final_context = false;
    let mut saw_final_arbitrary = false;
    let mut saw_final_dtmf = false;
    tokio::time::timeout(Duration::from_secs(10), async {
        while !saw_final_context || !saw_final_arbitrary || !saw_final_dtmf {
            match call_center_events
                .recv()
                .await
                .expect("call-center events ended before final browser actions")
            {
                AdapterEvent::DataMessage {
                    connection_id,
                    message,
                } if connection_id == call_center_connection && message.label == CONTEXT_LABEL => {
                    let envelope = ContextEnvelope::from_data_message(&message).unwrap();
                    if envelope.correlation_id == "chromium-browser-final-context" {
                        assert_eq!(
                            envelope.metadata.get("handoff_state").map(String::as_str),
                            Some("connected")
                        );
                        saw_final_context = true;
                    }
                }
                AdapterEvent::DataMessage {
                    connection_id,
                    message,
                } if connection_id == call_center_connection
                    && message.label == BROWSER_MESSAGE_LABEL =>
                {
                    assert_eq!(message.content_type, "application/octet-stream");
                    assert_eq!(message.bytes.as_ref(), [7, 0, 255, 42]);
                    saw_final_arbitrary = true;
                }
                AdapterEvent::Dtmf {
                    connection_id,
                    digits,
                    ..
                } if connection_id == call_center_connection && digits == "5" => {
                    saw_final_dtmf = true;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("promoted SIP destination did not receive final context, data, and RFC 4733 DTMF");
    destination_verified_flag.store(true, Ordering::Release);

    let output = tokio::time::timeout(Duration::from_secs(30), &mut browser_output)
        .await
        .expect("Chromium driver deadline")
        .expect("Chromium wait task")
        .expect("Chromium process wait");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "Chromium qualification failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let result_line = stdout
        .lines()
        .find_map(|line| line.strip_prefix("BRIDGEFU_BROWSER_RESULT="))
        .expect("Chromium driver omitted its result marker");
    let result: Value = serde_json::from_str(result_line).unwrap();
    assert_eq!(result["connected"], true);
    assert_eq!(result["finalState"], "closed");
    assert_eq!(result["replayRejected"], true);
    assert!(result["remoteTrackCount"].as_u64().unwrap_or_default() > 0);
    assert!(result["outboundAudioBytes"].as_u64().unwrap_or_default() > 0);
    assert!(result["inboundAudioBytes"].as_u64().unwrap_or_default() > 0);
    assert_eq!(
        result["remoteContext"]["correlation_id"],
        "sip-to-browser-later-context"
    );
    assert_eq!(result["remoteContext"]["tenant_id"], TENANT);
    assert_eq!(result["remoteContext"]["call_id"], call_id.to_string());
    assert_eq!(result["peerStable"], true);
    assert_eq!(result["serverConnectionStable"], true);
    assert_eq!(result["rejectedHoldByteDelta"], 0);
    assert_eq!(result["successfulHoldByteDelta"], 0);
    assert_eq!(result["ringbackStarts"], 3);
    assert_eq!(
        result["ringbackStops"],
        json!(["connected", "resumed", "connected"])
    );
    assert!(
        result["resumedInboundAudioBytes"]
            .as_u64()
            .unwrap_or_default()
            > result["initialInboundAudioBytes"]
                .as_u64()
                .unwrap_or_default()
    );
    assert!(
        result["agentInboundAudioBytes"]
            .as_u64()
            .unwrap_or_default()
            > result["resumedInboundAudioBytes"]
                .as_u64()
                .unwrap_or_default()
    );
    let handoff_messages = result["handoffMessages"]
        .as_array()
        .expect("SDK returned parsed handoff messages");
    assert_eq!(
        handoff_messages
            .iter()
            .map(|message| message["status"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "preparing",
            "ringing",
            "attaching",
            "resumed",
            "preparing",
            "ringing",
            "attaching",
            "connected",
        ]
    );
    for (index, message) in handoff_messages.iter().enumerate() {
        let expected_generation = if index < 4 {
            rejected_generation
        } else {
            successful_generation
        };
        assert_eq!(message["call_id"], call_id.to_string());
        assert_eq!(message["replacement_leg_id"], outbound_leg.to_string());
        assert_eq!(message["binding_generation"], expected_generation.value());
        assert_eq!(message["peerConnectionState"], "connected");
        assert_eq!(
            message["serverConnectionId"],
            bridgefu_source_connection.to_string()
        );
    }
    assert_eq!(
        result["dtmfSupported"], true,
        "qualified Chromium must expose RTCDTMFSender: {}",
        result["dtmfDiagnostics"]
    );
    assert!(
        saw_core_browser_dtmf,
        "Chromium DTMF never reached rvoip core: {}",
        result["dtmfDiagnostics"]
    );
    assert!(
        saw_browser_dtmf,
        "Chromium DTMF reached rvoip core but not the assistant SIP RFC 4733 destination"
    );

    wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    wait_promoted_sip_route_dead(
        runtime.as_ref(),
        call_id,
        outbound_leg,
        &orchestrator,
        bridge_sip_adapter.as_ref(),
        &bridgefu_call_center_connection,
        call_center_adapter.as_ref(),
        &call_center_connection,
        &mut core_events,
        &mut call_center_events,
    )
    .await;
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
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("browser cleanup retained orchestrator capacity");
    assert!(bridge_web_adapter.routes().is_empty());

    let _ = http_shutdown_tx.send(());
    http_server.await.unwrap().unwrap();
    let _ = wss_shutdown_tx.send(());
    wss_server.await.unwrap().unwrap();
    supervisor.shutdown(Duration::from_secs(5)).await;
    orchestrator.drain_prepared_outbound_connections().await;
    orchestrator.drain_connection_lifecycle_tasks().await;
    bridge_sip_adapter.drain().await.unwrap();
    destination_adapter.drain().await.unwrap();
    call_center_adapter.drain().await.unwrap();
    bridge_sip_coordinator
        .shutdown_gracefully(Some(Duration::from_secs(5)))
        .await
        .unwrap();
    destination_coordinator
        .shutdown_gracefully(Some(Duration::from_secs(5)))
        .await
        .unwrap();
    call_center_coordinator
        .shutdown_gracefully(Some(Duration::from_secs(5)))
        .await
        .unwrap();
    assert_eq!(bridge_sip_adapter.retained_task_count(), 0);
    assert_eq!(destination_adapter.retained_task_count(), 0);
    assert_eq!(call_center_adapter.retained_task_count(), 0);
    drop(bridge_web_adapter);
    Arc::try_unwrap(runtime)
        .expect("browser SDK qualification runtime owner released")
        .shutdown(Duration::from_secs(5))
        .await
        .unwrap();
    eprintln!("Chromium qualification result: {result}");
}
