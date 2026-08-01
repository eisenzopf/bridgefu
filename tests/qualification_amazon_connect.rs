//! Hermetic all-in-one qualification for direct authenticated browser WebRTC
//! to Amazon Connect's StartWebRTCContact + Chime media adapter.
//!
//! Browser signaling, WSS/TLS, ICE/DTLS, Opus RTP, DataChannels, DTMF, the
//! Bridgefu call actor, MediaGraph, and Amazon adapter lifecycle are real. AWS
//! control and Chime network I/O are replaced only at rvoip's public test
//! seams.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bridgefu::api_principal::ApiPrincipal;
use bridgefu::call_engine::{
    AttachmentTransport, CallId, CallState, LegDirection, MediaFlow, SignalingInitiator, TenantId,
    WorkerId,
};
use bridgefu::call_service::{
    build_call_service_runtime, AmazonConnectEndpointConfig, AmazonConnectStartSpec,
    CallExecutionSupervisor, CallRepositoryBackendConfig, CallServiceCoordinationConfig,
    CallServiceRuntime, CallServiceRuntimeConfig, CallTimeoutPolicy, CreateCallInput,
    DisabledOutboundProfileResolver, DisabledProviderLegExecutor, IdempotencyKey,
    LegEndpointConfig, NamedProfileBinding, NamedProfileKind, NamedProfileRole, NamedRouteBinding,
    RequestedLeg, SamePrincipalAttachmentResolver, SystemCallServiceClock, WebRtcEndpointConfig,
};
use bridgefu::context::{ContextEnvelope, ContextPolicy};
use bridgefu::coordination::DeploymentId;
use chrono::Utc;
use rvoip_amazon_connect::{
    AmazonConnectAdapter, ConnectConfig, ConnectContactStarter, ConnectMediaCloseOutcome,
    ConnectMediaConnectOptions, ConnectMediaConnector, ConnectMediaDtmfEvent, ConnectMediaHealth,
    ConnectMediaSession, ConnectMediaTerminalCause, ConnectionData, MediaPlacement,
    StartContactRequest, StopContactRequest,
};
use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod};
use rvoip_core::adapter::{AdapterEvent, ConnectionAdapter, EndReason, OriginateRequest};
use rvoip_core::capability::{CodecInfo, NegotiatedCodecs};
use rvoip_core::config::Config as CoreConfig;
use rvoip_core::connection::Direction;
use rvoip_core::ids::{ConnectionId, ParticipantId, SessionId, StreamId};
use rvoip_core::stream::{MediaFrame, MediaStream, QualitySnapshot, StreamKind};
use rvoip_core::{
    Event, IdentityAssurance, Jwk, MediaReceiverReservation, Orchestrator, Result as RvoipResult,
    RvoipError,
};
use rvoip_webrtc::signaling::auth::{AuthContext, AuthRejection, WsAuthHook};
use rvoip_webrtc::signaling::websocket::serve_tls_listener_with_auth_and_shutdown;
use rvoip_webrtc::tls::TlsConfig;
use rvoip_webrtc::{
    StaticWebRtcBearerCredentialProvider, WebRtcAdapter, WebRtcBearerCredential, WebRtcConfig,
    WebRtcOriginateContext, WebRtcTargetPolicy, WebRtcTlsClientTrust,
};
use tokio::sync::{mpsc, watch, Notify};

#[path = "support/browser_sdk.rs"]
mod browser_sdk;
#[path = "support/sip_fixture.rs"]
mod sip_fixture;

const TENANT: &str = "amazon-qualification-tenant";
const INSTANCE_ID: &str = "amazon-qualification-instance";
const FLOW_ID: &str = "amazon-qualification-flow";
const PROFILE_REVISION: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
static AMAZON_QUALIFICATION_TEST_LOCK: Mutex<()> = Mutex::new(());

async fn bounded<T>(label: &'static str, future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(20), future)
        .await
        .unwrap_or_else(|_| panic!("{label} deadline"))
}

fn principal() -> ApiPrincipal {
    ApiPrincipal::new(
        AuthenticatedPrincipal {
            subject: "amazon-qualification-browser".into(),
            tenant: Some(TENANT.into()),
            scopes: vec![
                "*".into(),
                bridgefu::api_principal::CallScope::ArbitraryDestination
                    .as_str()
                    .into(),
            ],
            issuer: Some("amazon-qualification-test".into()),
            expires_at: None,
            method: AuthenticationMethod::Jwt,
            assurance: IdentityAssurance::Pseudonymous {
                ephemeral_key: Jwk(serde_json::json!({"kty":"test"})),
            },
        },
        Utc::now(),
    )
    .unwrap()
}

async fn call_runtime() -> Arc<CallServiceRuntime> {
    let mut coordination = CallServiceCoordinationConfig::new(
        DeploymentId::parse("amazon-connect-qualification").unwrap(),
    );
    coordination.worker_lease_ttl = Duration::from_secs(300);
    coordination.worker_renew_interval = Duration::from_secs(100);
    Arc::new(
        build_call_service_runtime(
            CallServiceRuntimeConfig {
                backend: CallRepositoryBackendConfig::Memory,
                worker_id: WorkerId::new(),
                max_calls: 2,
                worker_capabilities: BTreeSet::from(["webrtc".into(), "amazon_connect".into()]),
                control_key: vec![0x6a; 32],
                timeouts: CallTimeoutPolicy {
                    setup: Duration::from_secs(15),
                    media_idle: Duration::from_secs(20),
                    transfer: Duration::from_secs(15),
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
                www_authenticate: "Bearer realm=\"bridgefu-amazon-test\"".into(),
            })?;
        Ok(AuthContext {
            subject: self.principal.subject.clone(),
            scopes: vec!["webrtc:connect".into()],
            session_hint: Some(token.to_owned()),
            principal: Some(self.principal.clone()),
        })
    }
}

struct HermeticConnectStream {
    id: StreamId,
    codec: CodecInfo,
    inbound: Arc<Mutex<Option<mpsc::Receiver<MediaFrame>>>>,
    source: mpsc::Sender<MediaFrame>,
    outbound: mpsc::Sender<MediaFrame>,
    sink: Mutex<Option<mpsc::Receiver<MediaFrame>>>,
    receiver_acquisitions: Arc<AtomicUsize>,
}

impl HermeticConnectStream {
    fn new() -> Arc<Self> {
        let (source, inbound) = mpsc::channel(32);
        let (outbound, sink) = mpsc::channel(32);
        Arc::new(Self {
            id: StreamId::new(),
            codec: CodecInfo {
                name: "opus".into(),
                clock_rate_hz: 48_000,
                channels: 1,
                fmtp: None,
            },
            inbound: Arc::new(Mutex::new(Some(inbound))),
            source,
            outbound,
            sink: Mutex::new(Some(sink)),
            receiver_acquisitions: Arc::new(AtomicUsize::new(0)),
        })
    }

    async fn inject(&self, timestamp: u32) {
        self.source
            .send(MediaFrame {
                stream_id: self.id.clone(),
                kind: StreamKind::Audio,
                payload: rvoip_webrtc::media::silent_opus_payload(),
                timestamp_rtp: timestamp,
                captured_at: Utc::now(),
                payload_type: Some(111),
            })
            .await
            .unwrap();
    }

    fn take_output(&self) -> mpsc::Receiver<MediaFrame> {
        self.sink
            .lock()
            .unwrap()
            .take()
            .expect("Connect output receiver is taken once")
    }
}

#[async_trait::async_trait]
impl MediaStream for HermeticConnectStream {
    fn id(&self) -> StreamId {
        self.id.clone()
    }

    fn kind(&self) -> StreamKind {
        StreamKind::Audio
    }

    fn codec(&self) -> CodecInfo {
        self.codec.clone()
    }

    fn direction(&self) -> Direction {
        Direction::Inbound
    }

    fn frames_in(&self) -> mpsc::Receiver<MediaFrame> {
        self.inbound
            .lock()
            .unwrap()
            .take()
            .unwrap_or_else(|| mpsc::channel(1).1)
    }

    fn try_frames_in(&self) -> RvoipResult<mpsc::Receiver<MediaFrame>> {
        let receiver = self
            .inbound
            .lock()
            .unwrap()
            .take()
            .ok_or(RvoipError::InvalidState(
                "Connect media receiver was already acquired",
            ))?;
        self.receiver_acquisitions.fetch_add(1, Ordering::SeqCst);
        Ok(receiver)
    }

    fn reserve_frames_in(&self) -> RvoipResult<MediaReceiverReservation> {
        let receiver = self
            .inbound
            .lock()
            .unwrap()
            .take()
            .ok_or(RvoipError::InvalidState(
                "Connect media receiver was already reserved",
            ))?;
        let inbound = Arc::clone(&self.inbound);
        let acquisitions = Arc::clone(&self.receiver_acquisitions);
        Ok(MediaReceiverReservation::new(receiver, move |receiver| {
            let replaced = inbound.lock().unwrap().replace(receiver);
            debug_assert!(replaced.is_none());
        })
        .with_commit_hook(move || {
            acquisitions.fetch_add(1, Ordering::SeqCst);
        }))
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

#[derive(Default)]
struct CapturingStarter {
    starts: Mutex<Vec<StartContactRequest>>,
    stops: Mutex<Vec<StopContactRequest>>,
}

#[async_trait::async_trait]
impl ConnectContactStarter for CapturingStarter {
    async fn start_webrtc_contact(
        &self,
        request: StartContactRequest,
    ) -> rvoip_amazon_connect::Result<ConnectionData> {
        self.starts.lock().unwrap().push(request);
        Ok(ConnectionData {
            contact_id: "amazon-qualification-contact".into(),
            participant_id: "amazon-qualification-participant".into(),
            participant_token: "amazon-qualification-participant-token".into(),
            meeting_id: "amazon-qualification-meeting".into(),
            media_region: "us-west-2".into(),
            attendee_id: "amazon-qualification-attendee".into(),
            join_token: "amazon-qualification-join-token".into(),
            media_placement: MediaPlacement {
                signaling_url: "wss://localhost.invalid/amazon-qualification".into(),
                audio_host_url: "https://localhost.invalid/amazon-qualification-audio".into(),
                ..MediaPlacement::default()
            },
        })
    }

    async fn stop_contact(&self, request: StopContactRequest) -> rvoip_amazon_connect::Result<()> {
        self.stops.lock().unwrap().push(request);
        Ok(())
    }
}

struct HermeticConnectSession {
    stream: Arc<HermeticConnectStream>,
    terminal_tx: watch::Sender<Option<ConnectMediaTerminalCause>>,
    terminal_rx: watch::Receiver<Option<ConnectMediaTerminalCause>>,
    dtmf_tx: mpsc::Sender<ConnectMediaDtmfEvent>,
    dtmf_rx: Mutex<Option<mpsc::Receiver<ConnectMediaDtmfEvent>>>,
    sent_dtmf: Mutex<Vec<(String, u32)>>,
    closes: AtomicUsize,
    aborts: AtomicUsize,
    close_notify: Notify,
}

impl HermeticConnectSession {
    fn new() -> Arc<Self> {
        let (terminal_tx, terminal_rx) = watch::channel(None);
        let (dtmf_tx, dtmf_rx) = mpsc::channel(8);
        Arc::new(Self {
            stream: HermeticConnectStream::new(),
            terminal_tx,
            terminal_rx,
            dtmf_tx,
            dtmf_rx: Mutex::new(Some(dtmf_rx)),
            sent_dtmf: Mutex::new(Vec::new()),
            closes: AtomicUsize::new(0),
            aborts: AtomicUsize::new(0),
            close_notify: Notify::new(),
        })
    }

    fn end_remotely(&self) {
        self.terminal_tx
            .send_replace(Some(ConnectMediaTerminalCause::RemoteEnded));
    }

    async fn emit_dtmf(&self, digit: char, duration_ms: u32) {
        self.dtmf_tx
            .send(ConnectMediaDtmfEvent { digit, duration_ms })
            .await
            .unwrap();
    }

    async fn wait_closed(&self) {
        bounded("Amazon media close", async {
            loop {
                let notified = self.close_notify.notified();
                if self.closes.load(Ordering::Acquire) > 0 {
                    return;
                }
                notified.await;
            }
        })
        .await;
    }
}

#[async_trait::async_trait]
impl ConnectMediaSession for HermeticConnectSession {
    fn negotiated_codecs(&self) -> NegotiatedCodecs {
        NegotiatedCodecs {
            audio: Some(self.stream.codec()),
            video: None,
        }
    }

    fn streams(&self) -> Vec<Arc<dyn MediaStream>> {
        vec![Arc::clone(&self.stream) as Arc<dyn MediaStream>]
    }

    fn take_dtmf_events(&self) -> Option<mpsc::Receiver<ConnectMediaDtmfEvent>> {
        self.dtmf_rx.lock().unwrap().take()
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

    async fn send_dtmf(&self, digits: &str, duration_ms: u32) -> rvoip_amazon_connect::Result<()> {
        self.sent_dtmf
            .lock()
            .unwrap()
            .push((digits.to_owned(), duration_ms));
        Ok(())
    }

    async fn close_until(
        &self,
        _deadline: Instant,
    ) -> rvoip_amazon_connect::Result<ConnectMediaCloseOutcome> {
        self.closes.fetch_add(1, Ordering::AcqRel);
        self.close_notify.notify_waiters();
        Ok(ConnectMediaCloseOutcome::Graceful)
    }

    fn abort(&self) {
        self.aborts.fetch_add(1, Ordering::AcqRel);
    }
}

struct HermeticConnector {
    session: Arc<HermeticConnectSession>,
}

#[async_trait::async_trait]
impl ConnectMediaConnector for HermeticConnector {
    async fn connect(
        &self,
        _connection: &ConnectionData,
        _options: ConnectMediaConnectOptions,
    ) -> rvoip_amazon_connect::Result<Arc<dyn ConnectMediaSession>> {
        Ok(Arc::clone(&self.session) as Arc<dyn ConnectMediaSession>)
    }
}

fn route_input() -> CreateCallInput {
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
                endpoint: LegEndpointConfig::AmazonConnect(AmazonConnectEndpointConfig {
                    instance_id: INSTANCE_ID.into(),
                    contact_flow_id: FLOW_ID.into(),
                }),
                amazon_connect_start: Some(
                    AmazonConnectStartSpec::new(
                        "default",
                        INSTANCE_ID,
                        FLOW_ID,
                        BTreeMap::from([("server_route".into(), "support".into())]),
                        "Bridgefu browser caller",
                        Some("Direct browser qualification".into()),
                    )
                    .unwrap(),
                ),
            },
        ],
    }
}

fn route_binding() -> NamedRouteBinding {
    NamedRouteBinding::new_with_profiles(
        "amazon-support",
        None,
        vec![NamedProfileBinding::new(
            NamedProfileRole::Destination,
            NamedProfileKind::AmazonConnect,
            "default",
            PROFILE_REVISION,
        )
        .unwrap()],
    )
    .unwrap()
}

async fn wait_for_call(
    runtime: &CallServiceRuntime,
    call_id: CallId,
    predicate: impl Fn(&bridgefu::call_service::StoredServiceCall) -> bool,
) -> bridgefu::call_service::StoredServiceCall {
    bounded("durable Amazon call state", async {
        loop {
            let stored = runtime
                .service_repository()
                .load_service_call(&TenantId::parse(TENANT).unwrap(), call_id)
                .await
                .unwrap();
            if predicate(&stored) {
                return stored;
            }
            if stored.call.aggregate.state().is_terminal() {
                panic!("Amazon qualification call terminated before predicate: {stored:#?}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
}

async fn wait_for_orchestrator_idle(orchestrator: &Orchestrator) {
    bounded("Amazon qualification orchestrator idle", async {
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
    .await;
}

async fn browser_audio_stream(
    browser: &WebRtcAdapter,
    connection_id: &ConnectionId,
) -> Arc<dyn MediaStream> {
    bounded("browser Opus stream", async {
        loop {
            if let Ok(Some(stream)) = browser.streams(connection_id.clone()).await.map(|streams| {
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
}

async fn send_browser_opus(stream: &Arc<dyn MediaStream>, timestamp: u32) {
    for offset in 0..8 {
        stream
            .frames_out()
            .send(MediaFrame {
                stream_id: stream.id(),
                kind: StreamKind::Audio,
                payload: rvoip_webrtc::media::silent_opus_payload(),
                timestamp_rtp: timestamp + offset * 960,
                captured_at: Utc::now(),
                payload_type: Some(111),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn next_browser_dtmf(
    events: &mut mpsc::Receiver<AdapterEvent>,
    connection_id: &ConnectionId,
) -> (String, u32) {
    bounded("Amazon-to-browser DTMF", async {
        loop {
            match events.recv().await {
                Some(AdapterEvent::Dtmf {
                    connection_id: observed,
                    digits,
                    duration_ms,
                }) if &observed == connection_id => return (digits, duration_ms),
                Some(_) => {}
                None => panic!("browser event stream closed before DTMF"),
            }
        }
    })
    .await
}

#[derive(Clone, Copy)]
enum TerminalSide {
    Browser,
    Amazon,
}

async fn run_direct_browser_amazon_case(terminal: TerminalSide) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = generated.cert.pem().into_bytes();
    let private_key = generated.signing_key.serialize_pem().into_bytes();
    let tls = TlsConfig::from_pem_bytes(&certificate, &private_key)
        .await
        .unwrap();
    let trust = Arc::new(WebRtcTlsClientTrust::from_pem(&certificate).unwrap());

    let runtime = call_runtime().await;
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let starter = Arc::new(CapturingStarter::default());
    let session = HermeticConnectSession::new();
    let starter_trait: Arc<dyn ConnectContactStarter> = starter.clone();
    let connector: Arc<dyn ConnectMediaConnector> = Arc::new(HermeticConnector {
        session: Arc::clone(&session),
    });
    let amazon =
        AmazonConnectAdapter::builder(ConnectConfig::new(INSTANCE_ID, FLOW_ID), starter_trait)
            .with_media_connector(connector)
            .build();

    let mut bridge_config = WebRtcConfig::loopback();
    bridge_config.max_concurrent_sessions = 4;
    bridge_config.trickle_ice = true;
    let bridge_adapter = WebRtcAdapter::new_with_inbound_admission_confirmation(
        bridge_config,
        Duration::from_secs(10),
    )
    .unwrap();
    let supervisor = CallExecutionSupervisor::install_with_leg_executors_context_canary_broadcast_and_outbound_profiles(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        Arc::new(DisabledProviderLegExecutor),
        Some(Arc::clone(&amazon)),
        Arc::new(ContextPolicy {
            allow_headers: BTreeMap::from([
                ("X-Correlation-Id".into(), "correlation_id".into()),
                ("X-Account-Tier".into(), "account_tier".into()),
            ]),
        }),
        None,
        None,
        Arc::new(DisabledOutboundProfileResolver),
        4,
        Duration::from_secs(15),
    )
    .await
    .unwrap();
    orchestrator
        .register(Arc::clone(&bridge_adapter) as Arc<dyn ConnectionAdapter>)
        .unwrap();
    orchestrator
        .register(Arc::clone(&amazon) as Arc<dyn ConnectionAdapter>)
        .expect("all-in-one worker registers the Amazon adapter");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let bridge_listener = {
        let adapter = Arc::clone(&bridge_adapter);
        let auth: Arc<dyn WsAuthHook> = Arc::new(AttachmentAuth {
            principal: principal().authenticated().clone(),
        });
        tokio::spawn(async move {
            serve_tls_listener_with_auth_and_shutdown(listener, tls, adapter, auth, async {
                let _ = shutdown_rx.await;
            })
            .await
        })
    };

    let idempotency = match terminal {
        TerminalSide::Browser => "amazon-browser-terminal-call",
        TerminalSide::Amazon => "amazon-remote-terminal-call",
    };
    let created = runtime
        .service()
        .create_named_route_call(
            &principal(),
            &IdempotencyKey::parse(idempotency).unwrap(),
            route_input(),
            route_binding(),
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
    let attachment = source.attachment.as_ref().unwrap();
    assert_eq!(attachment.transport, AttachmentTransport::WebRtc);
    let call_id = created.value.call.call_id;

    let browser = WebRtcAdapter::new(WebRtcConfig::loopback());
    let mut browser_events = browser.subscribe_events();
    let ingress_endpoint = format!("wss://localhost:{}/signal", bridge_address.port());
    let bearer = Arc::new(StaticWebRtcBearerCredentialProvider::new(
        WebRtcBearerCredential::new(attachment.token.clone()).unwrap(),
    ));
    let browser_context = WebRtcOriginateContext::websocket(
        &ingress_endpoint,
        WebRtcTargetPolicy::default()
            .allow_port(bridge_address.port())
            .allow_loopback(true)
            .with_timeouts(Duration::from_secs(3), Duration::from_secs(15))
            .unwrap(),
    )
    .unwrap()
    .with_bearer_provider(bearer)
    .with_tls_trust(trust);
    let browser_connection = bounded(
        "authenticated browser WSS originate",
        browser.originate(
            OriginateRequest::new(
                SessionId::new(),
                ParticipantId::new(),
                ingress_endpoint,
                Direction::Outbound,
                browser.capabilities(),
            )
            .with_context(browser_context),
        ),
    )
    .await
    .unwrap()
    .connection
    .id;
    bounded(
        "browser WSS/ICE/DTLS activation",
        browser.activate_outbound(browser_connection.clone()),
    )
    .await
    .unwrap();
    assert!(browser.is_connection_live(&browser_connection));
    wait_for_call(&runtime, call_id, |stored| {
        stored
            .call
            .aggregate
            .leg(source_leg_id)
            .is_some_and(|leg| leg.state() == bridgefu::call_engine::LegState::Connected)
            && stored.call.bindings.contains_key(&source_leg_id)
    })
    .await;
    assert!(
        starter.starts.lock().unwrap().is_empty(),
        "Amazon contact started before authenticated browser context"
    );

    let mut context = ContextEnvelope::new(
        "browser-amazon-correlation",
        TENANT,
        call_id.to_string(),
        source_leg_id.to_string(),
    );
    context
        .metadata
        .insert("account_tier".into(), "gold".into());
    context
        .metadata
        .insert("must_not_reach_amazon".into(), "private".into());
    context
        .metadata
        .insert("server_route".into(), "browser-override".into());
    bounded(
        "browser initial context DataChannel",
        browser.send_data_message(
            browser_connection.clone(),
            context.to_data_message().unwrap(),
        ),
    )
    .await
    .unwrap();

    wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;
    assert!(browser.is_connection_live(&browser_connection));
    let starts = starter.starts.lock().unwrap().clone();
    assert_eq!(starts.len(), 1);
    assert_eq!(
        starts[0].attributes,
        BTreeMap::from([
            ("account_tier".into(), "gold".into()),
            ("correlation_id".into(), "browser-amazon-correlation".into(),),
            ("server_route".into(), "support".into()),
        ]),
        "only allowlisted initial context drives the Connect screen pop"
    );

    let browser_stream = browser_audio_stream(&browser, &browser_connection).await;
    assert_eq!(browser_stream.codec().name.to_ascii_lowercase(), "opus");
    assert_eq!(session.stream.codec().name.to_ascii_lowercase(), "opus");
    let mut browser_audio = browser_stream.try_frames_in().unwrap();
    let mut connect_audio = session.stream.take_output();
    send_browser_opus(&browser_stream, 48_000).await;
    let at_connect = bounded("browser-to-Connect Opus", connect_audio.recv())
        .await
        .expect("Connect media stream stayed live");
    assert_eq!(at_connect.payload_type, Some(111));
    assert!(!at_connect.payload.is_empty());
    session.stream.inject(96_000).await;
    let at_browser = bounded("Connect-to-browser Opus", browser_audio.recv())
        .await
        .expect("browser media stream stayed live");
    assert_eq!(at_browser.payload_type, Some(111));
    assert!(!at_browser.payload.is_empty());

    bounded(
        "browser-to-Amazon DTMF",
        browser.send_dtmf(browser_connection.clone(), "5", 120),
    )
    .await
    .unwrap();
    bounded("Amazon DTMF delivery", async {
        loop {
            if session.sent_dtmf.lock().unwrap().as_slice() == [("5".into(), 120)] {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    session.emit_dtmf('8', 140).await;
    assert_eq!(
        next_browser_dtmf(&mut browser_events, &browser_connection).await,
        ("8".into(), 140)
    );

    let mut later = context;
    later.correlation_id = "must-not-restart-screen-pop".into();
    later
        .metadata
        .insert("account_tier".into(), "changed".into());
    bounded(
        "post-start browser context",
        browser.send_data_message(browser_connection.clone(), later.to_data_message().unwrap()),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let after_later_context = starter.starts.lock().unwrap().clone();
    assert_eq!(
        after_later_context.len(),
        1,
        "Amazon exposes initial screen-pop context only, not a live DataChannel"
    );
    assert_eq!(
        after_later_context[0].attributes, starts[0].attributes,
        "later DataChannel context cannot mutate the initial Connect screen pop"
    );

    match terminal {
        TerminalSide::Browser => {
            bounded(
                "browser terminal",
                browser.end(browser_connection.clone(), EndReason::Normal),
            )
            .await
            .unwrap();
        }
        TerminalSide::Amazon => session.end_remotely(),
    }
    wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    session.wait_closed().await;
    bounded("exact StopContact", async {
        loop {
            if starter.stops.lock().unwrap().len() == 1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert_eq!(starter.stops.lock().unwrap().len(), 1);
    assert_eq!(session.closes.load(Ordering::Acquire), 1);
    assert_eq!(amazon.metrics().active_sessions, 0);
    bounded("terminal browser route", async {
        while browser.is_connection_live(&browser_connection) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    wait_for_orchestrator_idle(&orchestrator).await;
    assert!(bridge_adapter.routes().is_empty());
    assert!(browser.routes().is_empty());

    let _ = shutdown_tx.send(());
    bounded(
        "Amazon qualification WSS listener shutdown",
        bridge_listener,
    )
    .await
    .unwrap()
    .unwrap();
    bounded(
        "Amazon qualification supervisor shutdown",
        supervisor.shutdown(Duration::from_secs(5)),
    )
    .await;
    amazon.begin_drain();
    let report = amazon
        .drain_until(Instant::now() + Duration::from_secs(5))
        .await;
    assert_eq!(report.remaining_routes, 0);
    bounded(
        "Amazon qualification prepared outbound drain",
        orchestrator.drain_prepared_outbound_connections(),
    )
    .await;
    bounded(
        "Amazon qualification lifecycle drain",
        orchestrator.drain_connection_lifecycle_tasks(),
    )
    .await;
    assert_eq!(orchestrator.connection_lifecycle_task_count(), 0);
    assert!(matches!(
        orchestrator.capacity_report(),
        Event::CapacityReport {
            active_connections: 0,
            active_bridges: 0,
            admission_in_use: 0,
            ..
        }
    ));
    drop(bridge_adapter);
    bounded(
        "Amazon qualification call runtime shutdown",
        Arc::try_unwrap(runtime)
            .expect("Amazon qualification runtime owner released")
            .shutdown(Duration::from_secs(5)),
    )
    .await
    .unwrap();
}

#[test]
fn direct_browser_to_amazon_connect_is_full_duplex_context_bound_and_leak_free() {
    let _serial = AMAZON_QUALIFICATION_TEST_LOCK.lock().unwrap();
    std::thread::Builder::new()
        .name("browser-to-amazon-connect-qualification".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(6)
                .thread_stack_size(8 * 1024 * 1024)
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    run_direct_browser_amazon_case(TerminalSide::Browser).await;
                    run_direct_browser_amazon_case(TerminalSide::Amazon).await;
                });
        })
        .unwrap()
        .join()
        .expect("browser-to-Amazon qualification panicked");
}

mod direct_assistant_handoff {
    use super::*;

    use std::sync::atomic::AtomicBool;

    use bridgefu::call_engine::{BindingGeneration, LegId};
    use bridgefu::call_service::{
        ConfiguredSipOutboundProfile, ConfiguredSipProfileAuth, ReplaceLegInput, SipEndpointConfig,
        SipInitialContextMode, StaticOutboundProfileResolver,
    };
    use bridgefu::handoff_status::{
        HandoffStatusEnvelope, HandoffStatusKind, HANDOFF_STATUS_LABEL,
    };
    use bridgefu::secret_ref::SecretRef;
    use rvoip_amazon_connect::{ConnectError, ConnectProfileId};
    use rvoip_sip::{
        Event as SipEvent, EventReceiver as SipEventReceiver, MediaSecurityProfile, SessionHandle,
        SipAdapter, SipAuthService, SipInboundContextPolicy, SipListenerAuthPolicy,
    };

    use super::sip_fixture::{reserve_tcp, reserve_udp, tls_sip_config, TestTlsFiles};

    const ASSISTANT_PROFILE: &str = "vapi-like-assistant";
    const ASSISTANT_PROFILE_REVISION: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ASSISTANT_REALM: &str = "bridgefu-vapi-like-assistant";
    const ASSISTANT_USER: &str = "bridgefu-direct-browser";
    const ASSISTANT_PASSWORD: &str = "hermetic-vapi-assistant-password";
    const AMAZON_PROFILE: &str = "direct-handoff-amazon";
    const AMAZON_REJECT_PROFILE: &str = "direct-handoff-amazon-reject";

    struct GatedConnector {
        session: Arc<HermeticConnectSession>,
        entered: AtomicBool,
        entered_notify: Notify,
        release: Notify,
    }

    impl GatedConnector {
        fn new(session: Arc<HermeticConnectSession>) -> Arc<Self> {
            Arc::new(Self {
                session,
                entered: AtomicBool::new(false),
                entered_notify: Notify::new(),
                release: Notify::new(),
            })
        }

        async fn wait_until_media_connecting(&self) {
            bounded("Amazon replacement media connector entry", async {
                loop {
                    let notified = self.entered_notify.notified();
                    if self.entered.load(Ordering::Acquire) {
                        return;
                    }
                    notified.await;
                }
            })
            .await;
        }

        fn make_media_ready(&self) {
            // `notify_one` retains a permit if the connector has set `entered`
            // but has not quite polled `notified()` yet.
            self.release.notify_one();
        }
    }

    #[async_trait::async_trait]
    impl ConnectMediaConnector for GatedConnector {
        async fn connect(
            &self,
            _connection: &ConnectionData,
            _options: ConnectMediaConnectOptions,
        ) -> rvoip_amazon_connect::Result<Arc<dyn ConnectMediaSession>> {
            self.entered.store(true, Ordering::Release);
            self.entered_notify.notify_waiters();
            self.release.notified().await;
            Ok(Arc::clone(&self.session) as Arc<dyn ConnectMediaSession>)
        }
    }

    #[derive(Default)]
    struct RejectingStarter {
        starts: Mutex<Vec<StartContactRequest>>,
        stops: Mutex<Vec<StopContactRequest>>,
    }

    #[async_trait::async_trait]
    impl ConnectContactStarter for RejectingStarter {
        async fn start_webrtc_contact(
            &self,
            request: StartContactRequest,
        ) -> rvoip_amazon_connect::Result<ConnectionData> {
            self.starts.lock().unwrap().push(request);
            Err(ConnectError::Control(
                "hermetic permanent Connect rejection".into(),
            ))
        }

        async fn stop_contact(
            &self,
            request: StopContactRequest,
        ) -> rvoip_amazon_connect::Result<()> {
            self.stops.lock().unwrap().push(request);
            Ok(())
        }
    }

    #[derive(Default)]
    struct BrowserGatedRejectingStarter {
        starts: Mutex<Vec<StartContactRequest>>,
        entered: AtomicBool,
        entered_notify: Notify,
        release: Notify,
    }

    impl BrowserGatedRejectingStarter {
        async fn wait_until_started(&self) {
            bounded("Chromium Amazon rejection starter entry", async {
                loop {
                    let notified = self.entered_notify.notified();
                    if self.entered.load(Ordering::Acquire) {
                        return;
                    }
                    notified.await;
                }
            })
            .await;
        }

        fn reject(&self) {
            self.release.notify_one();
        }
    }

    #[async_trait::async_trait]
    impl ConnectContactStarter for BrowserGatedRejectingStarter {
        async fn start_webrtc_contact(
            &self,
            request: StartContactRequest,
        ) -> rvoip_amazon_connect::Result<ConnectionData> {
            self.starts.lock().unwrap().push(request);
            self.entered.store(true, Ordering::Release);
            self.entered_notify.notify_waiters();
            self.release.notified().await;
            Err(ConnectError::Control(
                "hermetic gated Connect rejection".into(),
            ))
        }

        async fn stop_contact(
            &self,
            _request: StopContactRequest,
        ) -> rvoip_amazon_connect::Result<()> {
            panic!("a rejected Amazon contact cannot be stopped")
        }
    }

    struct AssistantFixture {
        coordinator: Arc<rvoip_sip::UnifiedCoordinator>,
        adapter: Arc<SipAdapter>,
        events: mpsc::Receiver<AdapterEvent>,
        sip_events: SipEventReceiver,
        tls_address: std::net::SocketAddr,
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
            "amazon-handoff-vapi-assistant",
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

    async fn handoff_runtime() -> Arc<CallServiceRuntime> {
        let mut coordination = CallServiceCoordinationConfig::new(
            DeploymentId::parse("amazon-handoff-qualification").unwrap(),
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
                        "webrtc".into(),
                        "sip".into(),
                        "sip_egress".into(),
                        "amazon_connect".into(),
                    ]),
                    control_key: vec![0x6b; 32],
                    timeouts: CallTimeoutPolicy {
                        setup: Duration::from_secs(15),
                        media_idle: Duration::from_secs(20),
                        transfer: Duration::from_secs(15),
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

    struct HandoffHarness {
        runtime: Arc<CallServiceRuntime>,
        orchestrator: Arc<Orchestrator>,
        web_adapter: Arc<WebRtcAdapter>,
        sip_coordinator: Arc<rvoip_sip::UnifiedCoordinator>,
        sip_adapter: Arc<SipAdapter>,
        assistant: AssistantFixture,
        amazon: Arc<AmazonConnectAdapter>,
        default_starter: Arc<CapturingStarter>,
        supervisor: CallExecutionSupervisor,
        web_address: std::net::SocketAddr,
        web_trust: Arc<WebRtcTlsClientTrust>,
        web_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
        web_listener: tokio::task::JoinHandle<std::result::Result<(), rvoip_webrtc::WebRtcError>>,
    }

    impl HandoffHarness {
        async fn shutdown(mut self) {
            let _ = self.web_shutdown.take().unwrap().send(());
            bounded("Amazon handoff WSS listener shutdown", self.web_listener)
                .await
                .unwrap()
                .unwrap();
            bounded(
                "Amazon handoff supervisor shutdown",
                self.supervisor.shutdown(Duration::from_secs(5)),
            )
            .await;
            self.amazon.begin_drain();
            let report = self
                .amazon
                .drain_until(Instant::now() + Duration::from_secs(5))
                .await;
            assert_eq!(report.remaining_routes, 0);
            bounded(
                "Amazon handoff prepared outbound drain",
                self.orchestrator.drain_prepared_outbound_connections(),
            )
            .await;
            bounded(
                "Amazon handoff lifecycle drain",
                self.orchestrator.drain_connection_lifecycle_tasks(),
            )
            .await;
            bounded(
                "Amazon handoff Bridgefu SIP drain",
                self.sip_adapter.drain(),
            )
            .await
            .unwrap();
            bounded(
                "Amazon handoff assistant SIP drain",
                self.assistant.adapter.drain(),
            )
            .await
            .unwrap();
            bounded(
                "Amazon handoff Bridgefu SIP coordinator shutdown",
                self.sip_coordinator
                    .shutdown_gracefully(Some(Duration::from_secs(5))),
            )
            .await
            .unwrap();
            bounded(
                "Amazon handoff assistant coordinator shutdown",
                self.assistant
                    .coordinator
                    .shutdown_gracefully(Some(Duration::from_secs(5))),
            )
            .await
            .unwrap();
            assert_eq!(self.sip_adapter.retained_task_count(), 0);
            assert_eq!(self.assistant.adapter.retained_task_count(), 0);
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
            assert!(self.web_adapter.routes().is_empty());
            drop(self.web_adapter);
            bounded(
                "Amazon handoff call runtime shutdown",
                Arc::try_unwrap(self.runtime)
                    .expect("Amazon handoff runtime owner released")
                    .shutdown(Duration::from_secs(5)),
            )
            .await
            .unwrap();
        }
    }

    async fn setup_handoff_harness(
        selected_profile: &str,
        selected_starter: Arc<dyn ConnectContactStarter>,
        connector: Arc<dyn ConnectMediaConnector>,
    ) -> HandoffHarness {
        setup_handoff_harness_with_profiles(
            vec![(selected_profile.to_owned(), selected_starter)],
            connector,
        )
        .await
    }

    async fn setup_handoff_harness_with_profiles(
        selected_profiles: Vec<(String, Arc<dyn ConnectContactStarter>)>,
        connector: Arc<dyn ConnectMediaConnector>,
    ) -> HandoffHarness {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let web_certificate = generated.cert.pem().into_bytes();
        let web_private_key = generated.signing_key.serialize_pem().into_bytes();
        let web_tls = TlsConfig::from_pem_bytes(&web_certificate, &web_private_key)
            .await
            .unwrap();
        let web_trust = Arc::new(WebRtcTlsClientTrust::from_pem(&web_certificate).unwrap());
        let sip_tls = TestTlsFiles::create();

        let runtime = handoff_runtime().await;
        let orchestrator = Orchestrator::new(CoreConfig::default());
        let mut web_config = WebRtcConfig::loopback();
        web_config.max_concurrent_sessions = 4;
        web_config.trickle_ice = true;
        let web_adapter = WebRtcAdapter::new_with_inbound_admission_confirmation(
            web_config,
            Duration::from_secs(10),
        )
        .unwrap();

        let bridge_sip_udp = reserve_udp();
        let bridge_sip_tls = reserve_tcp();
        let bridge_sip_config = tls_sip_config(
            "bridgefu-amazon-handoff-egress",
            bridge_sip_udp,
            bridge_sip_tls,
            &sip_tls,
            vec![0, 101],
        );
        assert!(bridge_sip_config.srtp_required);
        let bridge_sip_policy = SipListenerAuthPolicy::enabled_for_tenant(TENANT)
            .unwrap()
            .with_trusted_cidr(
                "127.0.0.1/32".parse().unwrap(),
                principal().authenticated().clone(),
            );
        let sip_coordinator = rvoip_sip::UnifiedCoordinator::new_with_listener_auth(
            bridge_sip_config,
            bridge_sip_policy,
        )
        .await
        .unwrap();
        let sip_adapter = SipAdapter::new(Arc::clone(&sip_coordinator)).await.unwrap();
        let assistant = assistant_fixture(&sip_tls).await;

        let default_starter = Arc::new(CapturingStarter::default());
        let default_trait: Arc<dyn ConnectContactStarter> = default_starter.clone();
        let mut amazon_builder =
            AmazonConnectAdapter::builder(ConnectConfig::new(INSTANCE_ID, FLOW_ID), default_trait)
                .with_media_connector(connector);
        for (profile, starter) in selected_profiles {
            amazon_builder
                .register_profile(ConnectProfileId::new(profile).unwrap(), starter)
                .unwrap();
        }
        let amazon = amazon_builder.build();

        let mut outbound_profiles = StaticOutboundProfileResolver::default();
        outbound_profiles.insert_sip(
            ASSISTANT_PROFILE.into(),
            ASSISTANT_PROFILE_REVISION.into(),
            ConfiguredSipOutboundProfile {
                from_uri: format!(
                    "sips:bridgefu-browser@localhost:{};transport=tls",
                    bridge_sip_tls.port()
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
            Arc::new(DisabledProviderLegExecutor),
            Some(Arc::clone(&amazon)),
            Arc::new(ContextPolicy {
                allow_headers: BTreeMap::from([
                    ("X-Correlation-Id".into(), "correlation_id".into()),
                    ("X-Account-Tier".into(), "account_tier".into()),
                ]),
            }),
            None,
            None,
            Arc::new(outbound_profiles),
            4,
            Duration::from_secs(15),
        )
        .await
        .unwrap();
        orchestrator
            .register(Arc::clone(&web_adapter) as Arc<dyn ConnectionAdapter>)
            .unwrap();
        orchestrator
            .register(Arc::clone(&sip_adapter) as Arc<dyn ConnectionAdapter>)
            .unwrap();
        orchestrator
            .register(Arc::clone(&amazon) as Arc<dyn ConnectionAdapter>)
            .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let web_address = listener.local_addr().unwrap();
        let (web_shutdown, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let web_listener = {
            let adapter = Arc::clone(&web_adapter);
            let auth: Arc<dyn WsAuthHook> = Arc::new(AttachmentAuth {
                principal: principal().authenticated().clone(),
            });
            tokio::spawn(async move {
                serve_tls_listener_with_auth_and_shutdown(listener, web_tls, adapter, auth, async {
                    let _ = shutdown_rx.await;
                })
                .await
            })
        };

        HandoffHarness {
            runtime,
            orchestrator,
            web_adapter,
            sip_coordinator,
            sip_adapter,
            assistant,
            amazon,
            default_starter,
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
            "direct-vapi-assistant",
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
        browser: Arc<WebRtcAdapter>,
        browser_events: mpsc::Receiver<AdapterEvent>,
        browser_connection: ConnectionId,
        assistant_connection: ConnectionId,
    }

    async fn next_inbound(events: &mut mpsc::Receiver<AdapterEvent>) -> ConnectionId {
        bounded("Vapi-like assistant inbound connection", async {
            loop {
                match events.recv().await {
                    Some(AdapterEvent::InboundConnection { connection }) => return connection.id,
                    Some(_) => {}
                    None => panic!("assistant adapter event stream closed before INVITE"),
                }
            }
        })
        .await
    }

    async fn next_authenticated_session(
        coordinator: &Arc<rvoip_sip::UnifiedCoordinator>,
        events: &mut SipEventReceiver,
    ) -> (String, SessionHandle) {
        bounded("authenticated Vapi-like assistant INVITE", async {
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
                    None => panic!("assistant SIP events closed before authentication"),
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
        let endpoint = format!(
            "sips:vapi-assistant@localhost:{};transport=tls",
            harness.assistant.tls_address.port()
        );
        let created = harness
            .runtime
            .service()
            .create_named_route_call(
                &principal(),
                &IdempotencyKey::parse(idempotency).unwrap(),
                assistant_route_input(endpoint),
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
        let attachment = source.attachment.as_ref().unwrap();
        assert_eq!(attachment.transport, AttachmentTransport::WebRtc);
        let call_id = created.value.call.call_id;

        let browser = WebRtcAdapter::new(WebRtcConfig::loopback());
        let browser_events = browser.subscribe_events();
        let ingress_endpoint = format!("wss://localhost:{}/signal", harness.web_address.port());
        let bearer = Arc::new(StaticWebRtcBearerCredentialProvider::new(
            WebRtcBearerCredential::new(attachment.token.clone()).unwrap(),
        ));
        let browser_context = WebRtcOriginateContext::websocket(
            &ingress_endpoint,
            WebRtcTargetPolicy::default()
                .allow_port(harness.web_address.port())
                .allow_loopback(true)
                .with_timeouts(Duration::from_secs(3), Duration::from_secs(15))
                .unwrap(),
        )
        .unwrap()
        .with_bearer_provider(bearer)
        .with_tls_trust(Arc::clone(&harness.web_trust));
        let browser_connection = bounded(
            "Amazon handoff browser WSS originate",
            browser.originate(
                OriginateRequest::new(
                    SessionId::new(),
                    ParticipantId::new(),
                    ingress_endpoint,
                    Direction::Outbound,
                    browser.capabilities(),
                )
                .with_context(browser_context),
            ),
        )
        .await
        .unwrap()
        .connection
        .id;
        bounded(
            "Amazon handoff browser WSS activation",
            browser.activate_outbound(browser_connection.clone()),
        )
        .await
        .unwrap();
        assert!(browser.is_connection_live(&browser_connection));
        assert!(
            tokio::time::timeout(Duration::from_millis(200), async {
                loop {
                    match harness.assistant.events.recv().await {
                        Some(AdapterEvent::InboundConnection { .. }) => return,
                        Some(_) => {}
                        None => panic!("assistant events ended before initial context"),
                    }
                }
            })
            .await
            .is_err(),
            "required browser context did not gate the assistant INVITE"
        );

        let mut context = ContextEnvelope::new(
            correlation_id,
            TENANT,
            call_id.to_string(),
            source_leg_id.to_string(),
        );
        context
            .metadata
            .insert("account_tier".into(), "gold".into());
        context
            .metadata
            .insert("must_not_forward".into(), "private-browser-value".into());
        bounded(
            "Amazon handoff initial browser context",
            browser.send_data_message(
                browser_connection.clone(),
                context.to_data_message().unwrap(),
            ),
        )
        .await
        .unwrap();

        let assistant_connection = next_inbound(&mut harness.assistant.events).await;
        let inbound = harness
            .assistant
            .adapter
            .take_inbound_context(&assistant_connection)
            .expect("assistant retained sanitized initial INVITE context");
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
        let (from, session) = next_authenticated_session(
            &harness.assistant.coordinator,
            &mut harness.assistant.sip_events,
        )
        .await;
        assert!(from.contains("sips:bridgefu-browser@localhost"));
        bounded(
            "Vapi-like assistant accepts SIPS/SRTP",
            harness
                .assistant
                .adapter
                .accept(assistant_connection.clone()),
        )
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
            browser,
            browser_events,
            browser_connection,
            assistant_connection,
        }
    }

    async fn current_outbound_binding(
        runtime: &CallServiceRuntime,
        call_id: CallId,
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
            .find(|leg| leg.direction() == LegDirection::Outbound)
            .unwrap();
        let binding = &stored.call.bindings[&leg.id()];
        (
            leg.id(),
            binding.binding_generation,
            binding.connection_id.clone(),
        )
    }

    async fn current_inbound_binding(
        runtime: &CallServiceRuntime,
        call_id: CallId,
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
            .find(|leg| leg.direction() == LegDirection::Inbound)
            .unwrap();
        let binding = &stored.call.bindings[&leg.id()];
        (
            leg.id(),
            binding.binding_generation,
            binding.connection_id.clone(),
        )
    }

    async fn audio_stream(
        adapter: &dyn ConnectionAdapter,
        connection_id: &ConnectionId,
    ) -> Arc<dyn MediaStream> {
        bounded("Amazon handoff audio stream", async {
            loop {
                if let Ok(Some(stream)) =
                    adapter.streams(connection_id.clone()).await.map(|streams| {
                        streams
                            .into_iter()
                            .find(|stream| stream.kind() == StreamKind::Audio)
                    })
                {
                    return stream;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
    }

    async fn send_assistant_pcmu(stream: &Arc<dyn MediaStream>, timestamp: u32) {
        for offset in 0..8 {
            stream
                .frames_out()
                .send(MediaFrame {
                    stream_id: stream.id(),
                    kind: StreamKind::Audio,
                    payload: bytes::Bytes::from(vec![0xff; 160]),
                    timestamp_rtp: timestamp + offset * 160,
                    captured_at: Utc::now(),
                    payload_type: Some(0),
                })
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
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
    ) -> (
        Arc<dyn MediaStream>,
        mpsc::Receiver<MediaFrame>,
        Arc<dyn MediaStream>,
        mpsc::Receiver<MediaFrame>,
    ) {
        let browser_stream = browser_audio_stream(&call.browser, &call.browser_connection).await;
        let assistant_stream = audio_stream(assistant, &call.assistant_connection).await;
        assert_eq!(
            assistant_stream.codec().name.to_ascii_lowercase(),
            "g.711-mu"
        );
        let mut browser_audio = browser_stream.try_frames_in().unwrap();
        let mut assistant_audio = assistant_stream.try_frames_in().unwrap();
        send_browser_opus(&browser_stream, 48_000).await;
        let to_assistant = bounded(
            "browser-to-assistant baseline media",
            assistant_audio.recv(),
        )
        .await
        .expect("assistant media route remained live");
        assert_eq!(to_assistant.payload_type, Some(0));
        send_assistant_pcmu(&assistant_stream, 16_000).await;
        let to_browser = bounded("assistant-to-browser baseline media", browser_audio.recv())
            .await
            .expect("browser media route remained live");
        assert_eq!(to_browser.payload_type, Some(111));
        drain_until_quiet(&mut browser_audio).await;
        drain_until_quiet(&mut assistant_audio).await;
        (
            browser_stream,
            browser_audio,
            assistant_stream,
            assistant_audio,
        )
    }

    async fn wait_for_active_bridges(orchestrator: &Orchestrator, expected: u64) {
        bounded("Amazon handoff bridge count", async {
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
        bounded("Amazon handoff connection cleanup", async {
            while adapter.is_connection_live(connection_id) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
    }

    async fn handoff_statuses_until(
        events: &mut mpsc::Receiver<AdapterEvent>,
        connection_id: &ConnectionId,
        terminal: HandoffStatusKind,
    ) -> Vec<HandoffStatusEnvelope> {
        bounded("Amazon handoff browser status", async {
            let mut statuses = Vec::new();
            loop {
                match events.recv().await {
                    Some(AdapterEvent::DataMessage {
                        connection_id: observed,
                        message,
                    }) if &observed == connection_id && message.label == HANDOFF_STATUS_LABEL => {
                        let status = HandoffStatusEnvelope::from_data_message(&message).unwrap();
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

    fn amazon_replacement(profile: &str) -> (RequestedLeg, NamedRouteBinding) {
        let start = AmazonConnectStartSpec::new(
            profile,
            INSTANCE_ID,
            FLOW_ID,
            BTreeMap::from([("server_route".into(), "support".into())]),
            "Bridgefu direct caller",
            Some("Direct assistant handoff qualification".into()),
        )
        .unwrap();
        let destination = RequestedLeg {
            direction: LegDirection::Outbound,
            signaling_initiator: Some(SignalingInitiator::Bridgefu),
            media_flow: MediaFlow::SendReceive,
            endpoint: LegEndpointConfig::AmazonConnect(AmazonConnectEndpointConfig {
                instance_id: INSTANCE_ID.into(),
                contact_flow_id: FLOW_ID.into(),
            }),
            amazon_connect_start: Some(start),
        };
        let route = NamedRouteBinding::new_with_profiles(
            "amazon-support-handoff",
            None,
            vec![NamedProfileBinding::new(
                NamedProfileRole::Destination,
                NamedProfileKind::AmazonConnect,
                profile,
                PROFILE_REVISION,
            )
            .unwrap()],
        )
        .unwrap();
        (destination, route)
    }

    async fn start_amazon_replacement(
        runtime: &CallServiceRuntime,
        call_id: CallId,
        leg_id: LegId,
        profile: &str,
        idempotency: &str,
    ) {
        let (destination, route) = amazon_replacement(profile);
        runtime
            .service()
            .replace_leg(
                &principal(),
                call_id,
                leg_id,
                &IdempotencyKey::parse(idempotency).unwrap(),
                ReplaceLegInput {
                    tenant_id: None,
                    route_id: route.route_id().to_owned(),
                },
                destination,
                route,
            )
            .await
            .expect("server-owned Amazon replacement was accepted");
    }

    async fn run_successful_handoff(terminal: TerminalSide) {
        let starter = Arc::new(CapturingStarter::default());
        let selected_starter: Arc<dyn ConnectContactStarter> = starter.clone();
        let session = HermeticConnectSession::new();
        let gate = GatedConnector::new(Arc::clone(&session));
        let connector: Arc<dyn ConnectMediaConnector> = gate.clone();
        let mut harness = setup_handoff_harness(AMAZON_PROFILE, selected_starter, connector).await;
        let suffix = match terminal {
            TerminalSide::Browser => "browser-terminal",
            TerminalSide::Amazon => "amazon-terminal",
        };
        let correlation_id = format!("direct-handoff-amazon-{suffix}");
        let mut call = establish_assistant_call(
            &mut harness,
            &format!("amazon-handoff-{suffix}-call"),
            &correlation_id,
        )
        .await;
        let source_binding = current_inbound_binding(&harness.runtime, call.call_id).await;
        assert_eq!(source_binding.0, call.source_leg_id);
        let (destination_leg_id, assistant_generation, assistant_server_connection) =
            current_outbound_binding(&harness.runtime, call.call_id).await;
        let pending_generation = assistant_generation.next().unwrap();
        let (browser_stream, mut browser_audio, assistant_stream, mut assistant_audio) =
            baseline_assistant_media(&call, &harness.assistant.adapter).await;

        start_amazon_replacement(
            &harness.runtime,
            call.call_id,
            destination_leg_id,
            AMAZON_PROFILE,
            &format!("amazon-handoff-{suffix}-replacement"),
        )
        .await;
        gate.wait_until_media_connecting().await;
        let transferring = wait_for_call(&harness.runtime, call.call_id, |stored| {
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
            transferring.call.bindings[&destination_leg_id].connection_id,
            assistant_server_connection
        );
        wait_for_active_bridges(&harness.orchestrator, 0).await;
        assert!(call.browser.is_connection_live(&call.browser_connection));
        assert!(harness
            .assistant
            .adapter
            .is_connection_live(&call.assistant_connection));
        assert_eq!(
            current_inbound_binding(&harness.runtime, call.call_id).await,
            source_binding,
            "browser source binding changed while Amazon media was pending"
        );
        assert_eq!(
            session.stream.receiver_acquisitions.load(Ordering::Acquire),
            0
        );

        send_assistant_pcmu(&assistant_stream, 32_000).await;
        assert_no_audio(
            &mut browser_audio,
            "held assistant leaked into the browser while Amazon media was pending",
        )
        .await;
        send_browser_opus(&browser_stream, 96_000).await;
        assert_no_audio(
            &mut assistant_audio,
            "browser audio leaked into the held assistant during replacement",
        )
        .await;

        let starts = starter.starts.lock().unwrap().clone();
        assert_eq!(starts.len(), 1);
        assert!(harness.default_starter.starts.lock().unwrap().is_empty());
        assert_eq!(starts[0].instance_id, INSTANCE_ID);
        assert_eq!(starts[0].contact_flow_id, FLOW_ID);
        assert_eq!(
            starts[0].attributes,
            BTreeMap::from([
                ("account_tier".into(), "gold".into()),
                ("correlation_id".into(), correlation_id.clone()),
                ("server_route".into(), "support".into()),
            ])
        );
        assert!(starts[0]
            .client_token
            .as_deref()
            .is_some_and(|value| !value.is_empty()));

        gate.make_media_ready();
        let active = wait_for_call(&harness.runtime, call.call_id, |stored| {
            stored.call.aggregate.state() == CallState::Active
                && stored.call.aggregate.replacement().is_none()
                && stored
                    .call
                    .bindings
                    .get(&destination_leg_id)
                    .is_some_and(|binding| {
                        binding.binding_generation == pending_generation
                            && binding.connection_id != assistant_server_connection
                    })
        })
        .await;
        wait_for_active_bridges(&harness.orchestrator, 1).await;
        let statuses = handoff_statuses_until(
            &mut call.browser_events,
            &call.browser_connection,
            HandoffStatusKind::Connected,
        )
        .await;
        assert_statuses(
            &statuses,
            call.call_id,
            destination_leg_id,
            pending_generation,
            &[
                HandoffStatusKind::Preparing,
                HandoffStatusKind::Ringing,
                HandoffStatusKind::Attaching,
                HandoffStatusKind::Connected,
            ],
        );
        wait_connection_dead(
            harness.assistant.adapter.as_ref(),
            &call.assistant_connection,
        )
        .await;
        assert!(call.browser.is_connection_live(&call.browser_connection));
        assert_eq!(
            current_inbound_binding(&harness.runtime, call.call_id).await,
            source_binding
        );
        assert_ne!(
            active.call.bindings[&destination_leg_id].connection_id,
            assistant_server_connection
        );
        assert_eq!(
            session.stream.receiver_acquisitions.load(Ordering::Acquire),
            1
        );

        drain_until_quiet(&mut browser_audio).await;
        let mut amazon_audio = session.stream.take_output();
        send_browser_opus(&browser_stream, 192_000).await;
        let at_amazon = bounded("browser-to-Amazon handoff media", amazon_audio.recv())
            .await
            .expect("Amazon media route remained live");
        assert_eq!(at_amazon.payload_type, Some(111));
        session.stream.inject(288_000).await;
        let at_browser = bounded("Amazon-to-browser handoff media", browser_audio.recv())
            .await
            .expect("stable browser media route remained live");
        assert_eq!(at_browser.payload_type, Some(111));

        bounded(
            "browser-to-Amazon handoff DTMF",
            call.browser
                .send_dtmf(call.browser_connection.clone(), "5", 120),
        )
        .await
        .unwrap();
        bounded("Amazon handoff DTMF delivery", async {
            loop {
                if session.sent_dtmf.lock().unwrap().as_slice() == [("5".into(), 120)] {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        session.emit_dtmf('8', 140).await;
        assert_eq!(
            next_browser_dtmf(&mut call.browser_events, &call.browser_connection).await,
            ("8".into(), 140)
        );

        let later = ContextEnvelope::new(
            "must-not-restart-screen-pop",
            TENANT,
            call.call_id.to_string(),
            call.source_leg_id.to_string(),
        );
        bounded(
            "post-handoff browser context",
            call.browser.send_data_message(
                call.browser_connection.clone(),
                later.to_data_message().unwrap(),
            ),
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(starter.starts.lock().unwrap().len(), 1);
        assert_eq!(
            starter.starts.lock().unwrap()[0].attributes,
            starts[0].attributes
        );

        match terminal {
            TerminalSide::Browser => {
                bounded(
                    "post-handoff browser terminal",
                    call.browser
                        .end(call.browser_connection.clone(), EndReason::Normal),
                )
                .await
                .unwrap();
            }
            TerminalSide::Amazon => session.end_remotely(),
        }
        wait_for_call(&harness.runtime, call.call_id, |stored| {
            stored.call.aggregate.state().is_terminal()
        })
        .await;
        session.wait_closed().await;
        bounded("post-handoff exact StopContact", async {
            loop {
                if starter.stops.lock().unwrap().len() == 1 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert_eq!(starter.stops.lock().unwrap().len(), 1);
        assert!(harness.default_starter.stops.lock().unwrap().is_empty());
        assert_eq!(session.closes.load(Ordering::Acquire), 1);
        assert_eq!(harness.amazon.metrics().active_sessions, 0);
        wait_connection_dead(call.browser.as_ref(), &call.browser_connection).await;
        wait_for_orchestrator_idle(&harness.orchestrator).await;
        assert!(call.browser.routes().is_empty());
        drop(call);
        harness.shutdown().await;
    }

    async fn run_rejected_handoff_resumes_assistant() {
        let rejecting = Arc::new(RejectingStarter::default());
        let selected_starter: Arc<dyn ConnectContactStarter> = rejecting.clone();
        let unused_session = HermeticConnectSession::new();
        let connector: Arc<dyn ConnectMediaConnector> = Arc::new(HermeticConnector {
            session: Arc::clone(&unused_session),
        });
        let mut harness =
            setup_handoff_harness(AMAZON_REJECT_PROFILE, selected_starter, connector).await;
        let correlation_id = "direct-handoff-amazon-rejected";
        let mut call =
            establish_assistant_call(&mut harness, "amazon-handoff-rejected-call", correlation_id)
                .await;
        let source_binding = current_inbound_binding(&harness.runtime, call.call_id).await;
        let (destination_leg_id, assistant_generation, assistant_server_connection) =
            current_outbound_binding(&harness.runtime, call.call_id).await;
        let pending_generation = assistant_generation.next().unwrap();
        let (browser_stream, mut browser_audio, assistant_stream, mut assistant_audio) =
            baseline_assistant_media(&call, &harness.assistant.adapter).await;

        start_amazon_replacement(
            &harness.runtime,
            call.call_id,
            destination_leg_id,
            AMAZON_REJECT_PROFILE,
            "amazon-handoff-rejected-replacement",
        )
        .await;
        let statuses = handoff_statuses_until(
            &mut call.browser_events,
            &call.browser_connection,
            HandoffStatusKind::Resumed,
        )
        .await;
        assert_statuses(
            &statuses,
            call.call_id,
            destination_leg_id,
            pending_generation,
            &[
                HandoffStatusKind::Preparing,
                HandoffStatusKind::Ringing,
                HandoffStatusKind::Attaching,
                HandoffStatusKind::Resumed,
            ],
        );
        let resumed = wait_for_call(&harness.runtime, call.call_id, |stored| {
            stored.call.aggregate.state() == CallState::Active
                && stored.call.aggregate.replacement().is_none()
                && stored
                    .call
                    .bindings
                    .get(&destination_leg_id)
                    .is_some_and(|binding| {
                        binding.binding_generation == assistant_generation
                            && binding.connection_id == assistant_server_connection
                    })
        })
        .await;
        assert_eq!(
            resumed.call.bindings[&destination_leg_id].connection_id,
            assistant_server_connection
        );
        assert_eq!(
            current_inbound_binding(&harness.runtime, call.call_id).await,
            source_binding
        );
        assert!(call.browser.is_connection_live(&call.browser_connection));
        assert!(harness
            .assistant
            .adapter
            .is_connection_live(&call.assistant_connection));
        wait_for_active_bridges(&harness.orchestrator, 1).await;
        assert_eq!(rejecting.starts.lock().unwrap().len(), 1);
        assert!(rejecting.stops.lock().unwrap().is_empty());
        assert!(harness.default_starter.stops.lock().unwrap().is_empty());
        assert!(harness.default_starter.starts.lock().unwrap().is_empty());
        assert_eq!(
            unused_session
                .stream
                .receiver_acquisitions
                .load(Ordering::Acquire),
            0,
            "a rejected StartWebRTCContact must not acquire Chime media"
        );

        send_browser_opus(&browser_stream, 384_000).await;
        let at_assistant = bounded("resumed browser-to-assistant media", assistant_audio.recv())
            .await
            .expect("assistant route resumed");
        assert_eq!(at_assistant.payload_type, Some(0));
        send_assistant_pcmu(&assistant_stream, 64_000).await;
        let at_browser = bounded("resumed assistant-to-browser media", browser_audio.recv())
            .await
            .expect("stable browser route resumed");
        assert_eq!(at_browser.payload_type, Some(111));

        bounded(
            "rejected Amazon handoff browser terminal",
            call.browser
                .end(call.browser_connection.clone(), EndReason::Normal),
        )
        .await
        .unwrap();
        wait_for_call(&harness.runtime, call.call_id, |stored| {
            stored.call.aggregate.state().is_terminal()
        })
        .await;
        wait_connection_dead(
            harness.assistant.adapter.as_ref(),
            &call.assistant_connection,
        )
        .await;
        wait_for_orchestrator_idle(&harness.orchestrator).await;
        assert!(call.browser.routes().is_empty());
        assert!(rejecting.stops.lock().unwrap().is_empty());
        drop(call);
        harness.shutdown().await;
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
                &principal(),
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
        assert_eq!(attachment.transport, AttachmentTransport::WebRtc);
        let mut scenario = crate::browser_sdk::BrowserScenario::handoff(
            "amazon-connect",
            correlation_id,
            crate::browser_sdk::BrowserDestinationBoundary::AmazonConnectTestSeam,
            crate::browser_sdk::BrowserContextSemantics::InitialOnly,
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
            .expect("Chromium initial context released the Vapi-like assistant");
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
        let (_, session) = next_authenticated_session(
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
        let (observed_source_leg, source_generation, source_connection) =
            current_inbound_binding(&harness.runtime, call_id).await;
        assert_eq!(observed_source_leg, source_leg_id);
        let (_, assistant_generation, assistant_server_connection) =
            current_outbound_binding(&harness.runtime, call_id).await;
        // `CallState::Active` records logical leg connectivity before the
        // durable bridge outbox effect is necessarily installed. Do not
        // release browser controls until DTMF/media have an exact peer route.
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

    async fn wait_for_chromium_assistant_dtmf(
        events: &mut mpsc::Receiver<AdapterEvent>,
        connection_id: &ConnectionId,
        browser: &crate::browser_sdk::BrowserSdkController,
    ) {
        let mut saw_dtmf = false;
        let mut observed = Vec::new();
        tokio::time::timeout(Duration::from_secs(20), async {
            while !saw_dtmf {
                let event = events
                    .recv()
                    .await
                    .expect("assistant events ended before Chromium controls");
                observed.push(format!("{event:?}"));
                match event {
                    AdapterEvent::Dtmf {
                        connection_id: observed,
                        digits,
                        ..
                    } if &observed == connection_id && digits == "6" => saw_dtmf = true,
                    _ => {}
                }
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "Chromium assistant DTMF deadline: dtmf={saw_dtmf}, browser_diagnostics={:?}, observed={observed:?}",
                browser.diagnostics()
            )
        });
    }

    async fn run_actual_chromium_amazon_matrix() {
        run_actual_chromium_amazon_case(crate::browser_sdk::BrowserTerminalSide::Browser).await;
        run_actual_chromium_amazon_case(crate::browser_sdk::BrowserTerminalSide::Destination).await;
    }

    async fn run_actual_chromium_amazon_case(
        terminal_side: crate::browser_sdk::BrowserTerminalSide,
    ) {
        let success_starter = Arc::new(CapturingStarter::default());
        let reject_starter = Arc::new(BrowserGatedRejectingStarter::default());
        let session = HermeticConnectSession::new();
        let gate = GatedConnector::new(Arc::clone(&session));
        let connector: Arc<dyn ConnectMediaConnector> = gate.clone();
        let mut harness = setup_handoff_harness_with_profiles(
            vec![
                (
                    AMAZON_PROFILE.into(),
                    success_starter.clone() as Arc<dyn ConnectContactStarter>,
                ),
                (
                    AMAZON_REJECT_PROFILE.into(),
                    reject_starter.clone() as Arc<dyn ConnectContactStarter>,
                ),
            ],
            connector,
        )
        .await;
        let correlation_id = "chromium-amazon-initial-context";
        let call = establish_chromium_assistant_call(
            &mut harness,
            "chromium-amazon-assistant-call",
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
        let initial_assistant_media = tokio::spawn({
            let stream = Arc::clone(&assistant_stream);
            async move { send_assistant_pcmu(&stream, 80_000).await }
        });
        let browser_audio = bounded(
            "Chromium-to-assistant baseline audio",
            assistant_audio.recv(),
        )
        .await
        .expect("browser microphone route remained live");
        assert_eq!(browser_audio.payload_type, Some(0));
        call.browser.wait_for_phase("assistant-ready").await;
        initial_assistant_media.await.unwrap();
        wait_for_chromium_assistant_dtmf(
            &mut harness.assistant.events,
            &call.assistant_connection,
            &call.browser,
        )
        .await;

        let rejected_generation = call.assistant_generation.next().unwrap();
        start_amazon_replacement(
            &harness.runtime,
            call.call_id,
            call.destination_leg_id,
            AMAZON_REJECT_PROFILE,
            "chromium-amazon-rejected-replacement",
        )
        .await;
        reject_starter.wait_until_started().await;
        wait_for_active_bridges(&harness.orchestrator, 0).await;
        call.browser.wait_for_phase("reject-hold-ready").await;
        drain_until_quiet(&mut assistant_audio).await;
        send_assistant_pcmu(&assistant_stream, 96_000).await;
        assert_no_audio(
            &mut assistant_audio,
            "Chromium audio leaked into held assistant during rejected Amazon handoff",
        )
        .await;
        reject_starter.reject();
        call.browser.wait_for_phase("reject-resumed").await;
        wait_for_active_bridges(&harness.orchestrator, 1).await;
        send_assistant_pcmu(&assistant_stream, 112_000).await;
        call.browser.wait_for_phase("reject-resume-audio").await;
        assert_eq!(reject_starter.starts.lock().unwrap().len(), 1);

        let successful_generation = rejected_generation.next().unwrap();
        start_amazon_replacement(
            &harness.runtime,
            call.call_id,
            call.destination_leg_id,
            AMAZON_PROFILE,
            "chromium-amazon-successful-replacement",
        )
        .await;
        gate.wait_until_media_connecting().await;
        wait_for_active_bridges(&harness.orchestrator, 0).await;
        call.browser.wait_for_phase("success-hold-ready").await;
        drain_until_quiet(&mut assistant_audio).await;
        send_assistant_pcmu(&assistant_stream, 128_000).await;
        assert_no_audio(
            &mut assistant_audio,
            "Chromium audio leaked into held assistant during successful Amazon handoff",
        )
        .await;
        gate.make_media_ready();
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

        let source_live = call.browser.wait_for_phase("success-source-live").await;
        let mut amazon_audio = session.stream.take_output();
        let at_amazon = match tokio::time::timeout(Duration::from_secs(20), amazon_audio.recv())
            .await
        {
            Ok(Some(frame)) => frame,
            Ok(None) => panic!("Amazon media route ended before Chromium audio arrived"),
            Err(_) => {
                let amazon_connection = active.call.bindings[&call.destination_leg_id]
                    .connection_id
                    .clone();
                let source_graph = harness
                    .orchestrator
                    .media_graph_snapshot(&call.source_connection)
                    .await;
                let destination_graph = harness
                    .orchestrator
                    .media_graph_snapshot(&amazon_connection)
                    .await;
                panic!(
                    "Chromium-to-Amazon audio deadline: source_live={source_live:?}, receiver_acquisitions={}, source_graph={source_graph:?}, destination_graph={destination_graph:?}, browser_diagnostics={:?}, browser_phases={:?}",
                    session.stream.receiver_acquisitions.load(Ordering::Acquire),
                    call.browser.diagnostics(),
                    call.browser.phases(),
                );
            }
        };
        assert_eq!(at_amazon.payload_type, Some(111));
        for timestamp in [144_000, 144_960, 145_920, 146_880] {
            session.stream.inject(timestamp).await;
        }
        call.browser.wait_for_phase("agent-audio").await;
        call.browser
            .wait_for_phase("destination-actions-sent")
            .await;
        bounded("Chromium-to-Amazon DTMF", async {
            loop {
                if session.sent_dtmf.lock().unwrap().as_slice() == [("5".into(), 120)] {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;

        let starts = success_starter.starts.lock().unwrap().clone();
        assert_eq!(starts.len(), 1);
        assert_eq!(
            starts[0].attributes,
            BTreeMap::from([
                ("account_tier".into(), "gold".into()),
                ("correlation_id".into(), correlation_id.into()),
                ("server_route".into(), "support".into()),
            ])
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            success_starter.starts.lock().unwrap()[0].attributes,
            starts[0].attributes,
            "post-handoff browser context mutated Amazon's initial-only attributes"
        );
        let call_id = call.call_id;
        let call_id_string = call_id.to_string();
        let destination_leg_id_string = call.destination_leg_id.to_string();
        call.browser.mark_destination_verified();
        if terminal_side == crate::browser_sdk::BrowserTerminalSide::Destination {
            call.browser
                .wait_for_phase("destination-hangup-ready")
                .await;
            session.end_remotely();
        }
        let result = call.browser.complete().await;
        crate::browser_sdk::assert_common_handoff_result(
            &result,
            &call_id_string,
            &destination_leg_id_string,
            rejected_generation.value(),
            successful_generation.value(),
            terminal_side,
            crate::browser_sdk::BrowserDestinationBoundary::AmazonConnectTestSeam,
            crate::browser_sdk::BrowserContextSemantics::InitialOnly,
            crate::browser_sdk::BrowserDtmfSemantics::SourceToDestination,
        );
        assert!(result["remoteContext"].is_null());
        assert!(result["remoteMessage"].is_null());

        wait_for_call(&harness.runtime, call_id, |stored| {
            stored.call.aggregate.state().is_terminal()
        })
        .await;
        session.wait_closed().await;
        bounded("Chromium Amazon exact StopContact", async {
            while success_starter.stops.lock().unwrap().len() != 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert_eq!(success_starter.stops.lock().unwrap().len(), 1);
        assert_eq!(session.closes.load(Ordering::Acquire), 1);
        wait_for_orchestrator_idle(&harness.orchestrator).await;
        assert!(harness.web_adapter.routes().is_empty());
        harness.shutdown().await;
    }

    #[test]
    #[ignore = "requires BridgeFu's pinned Playwright Chromium; run explicitly with --ignored"]
    fn built_typescript_sdk_hands_off_to_amazon_and_cleans_both_terminal_directions() {
        let _serial = AMAZON_QUALIFICATION_TEST_LOCK.lock().unwrap();
        std::thread::Builder::new()
            .name("chromium-vapi-assistant-amazon-handoff".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(6)
                    .thread_stack_size(8 * 1024 * 1024)
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(run_actual_chromium_amazon_matrix());
            })
            .unwrap()
            .join()
            .expect("actual Chromium Amazon qualification panicked");
    }

    #[test]
    fn direct_browser_vapi_assistant_to_amazon_is_make_before_break_and_compensating() {
        let _serial = AMAZON_QUALIFICATION_TEST_LOCK.lock().unwrap();
        std::thread::Builder::new()
            .name("direct-browser-vapi-assistant-amazon-handoff".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(6)
                    .thread_stack_size(8 * 1024 * 1024)
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        run_successful_handoff(TerminalSide::Browser).await;
                        run_successful_handoff(TerminalSide::Amazon).await;
                        run_rejected_handoff_resumes_assistant().await;
                    });
            })
            .unwrap()
            .join()
            .expect("direct browser assistant-to-Amazon qualification panicked");
    }
}
