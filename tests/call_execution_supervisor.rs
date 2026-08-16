use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bridgefu::api_principal::{ApiPrincipal, PrincipalFingerprintKey};
use bridgefu::call_engine::{
    AttachmentTransport, BindingGeneration, CallId, CallState, DeadlineKind, LegDirection, LegId,
    LegState, MediaFlow, ProviderAccountKey, ProviderCallId, ProviderEventDigest,
    ProviderEventInput, ProviderEventOutcome, ProviderEventState, ProviderPayloadDigest,
    ProviderReferenceRole, SignalingInitiator, TenantId, WorkerId,
};
use bridgefu::call_service::{
    build_call_service_runtime, parse_presented_attachment_token, AmazonConnectEndpointConfig,
    AmazonConnectStartSpec, CallExecutionSupervisor, CallMutationInput,
    CallRepositoryBackendConfig, CallServiceCoordinationConfig, CallServiceRuntime,
    CallServiceRuntimeConfig, CallTimeoutPolicy, ConfiguredAttachmentPrincipalResolver,
    CreateCallInput, DisabledOutboundProfileResolver, DisabledProviderLegExecutor,
    ExternalReferenceValue, IdempotencyKey, InboundAttachmentRequest, LegEndpointConfig,
    NamedProfileBinding, NamedProfileKind, NamedProfileRole, NamedRouteBinding,
    NamedRouteCallContext, ProviderConnectDestinationRequest, ProviderDialClientState,
    ProviderDialRole, ProviderDtmfRequest, ProviderEndpointConfig, ProviderExecutionContext,
    ProviderExecutionError, ProviderExecutionReference, ProviderHangupRequest, ProviderKind,
    ProviderLegExecutor, ProviderStartMediaRequest, ProviderTransferRequest, ReplaceLegInput,
    RequestedLeg, SamePrincipalAttachmentResolver, SipEndpointConfig, SipInitialContextMode,
    SystemCallServiceClock, TransferCallInput, TransferTarget as ServiceTransferTarget,
    WebRtcEndpointConfig, WhepEndpointConfig, WhipEndpointConfig,
};
use bridgefu::context::{ContextEnvelope, ContextPolicy};
use bridgefu::coordination::DeploymentId;
use bridgefu::coordination::{
    AttachmentRouteHint, CoordinationEvent, CoordinationPayload, CoordinationProjection,
    ManualCoordinationClock, MemoryCoordinator, ProjectionSequence, WorkerCoordinationSnapshot,
};
use bridgefu::gateway_attachment::{GatewayAttachmentResolver, WorkerAttachmentAdmissionResponse};
use bridgefu::gateway_forwarding::PRIVATE_FORWARD_SCOPE;
use bridgefu::handoff_status::{HandoffStatusEnvelope, HandoffStatusKind, HANDOFF_STATUS_LABEL};
use bridgefu::recipe_admission::{
    RecipeSipAdmissionCatalog, RecipeSipAdmissionDecision, RecipeSipAdmissionRoute,
};
use bridgefu::reference_tenant_canary::{
    ReferenceTenantCanaryConfig, ReferenceTenantCanaryDecision, ReferenceTenantCanaryPolicy,
};
use chrono::Utc;
use rvoip_amazon_connect::{
    AmazonConnectAdapter, AttributeMapping, ConnectConfig, ConnectContactStarter,
    ConnectMediaCloseOutcome, ConnectMediaConnectOptions, ConnectMediaConnector,
    ConnectMediaHealth, ConnectMediaSession, ConnectMediaTerminalCause, ConnectProfileId,
    ConnectionData, MediaPlacement, StartContactRequest, StopContactRequest, UnmappedPolicy,
};
use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod};
use rvoip_core::{
    adapter::{
        AdapterEvent, AdapterKind, AdapterLifecycleCapabilities, AdapterLifecycleSink,
        AdapterLifecycleSinkSlot, ConnectionAdapter, ConnectionHandle, EndReason,
        ExternalConnectionReference, InboundConnectionContext, InboundRoutingHint,
        InboundSignalingMetadata, OrchestratorAdapterEvent, OriginateContext, OriginateRequest,
        OutboundActivation, RejectReason, SignatureHeaders, TransferStatus, TransferTarget,
    },
    capability::{CapabilityDescriptor, CodecInfo, NegotiatedCodecs},
    config::Config as CoreConfig,
    connection::{Connection, ConnectionState, Direction, Transport, TransportHandle},
    ids::{ConnectionId, ParticipantId, SessionId, StreamId, TransferAttemptId},
    message::Message,
    stream::{MediaFrame, MediaStream, QualitySnapshot, StreamKind},
    DataMessage, Event, IdentityAssurance, Jwk, MediaReceiverReservation,
    OperationalEventStreamHealth, Orchestrator, Result as RvoipResult, RvoipError,
};
use rvoip_sip::{
    AudioFrame, Config as SipConfig, HeaderName, SipAdapter, SipInboundContextPolicy,
    SipListenerAuthPolicy, SipOriginateContext, SipRequestOptions, UnifiedCoordinator,
};
use rvoip_uctp::state::UCTP_SESSION_SCOPE;
use rvoip_webrtc::peer::{PeerRole, RvoipPeerConnection};
use rvoip_webrtc::signaling::auth::{AuthContext, AuthRejection, WhipAuthHook};
use rvoip_webrtc::{
    WebRtcConfig, WebRtcOriginateContext, WebRtcServerBuilder, WebRtcSignalingMode,
};
use tokio::sync::{mpsc, watch, Barrier, Notify};

fn runtime_config(
    backend: CallRepositoryBackendConfig,
    worker_id: WorkerId,
) -> CallServiceRuntimeConfig {
    let mut coordination = CallServiceCoordinationConfig::new(
        DeploymentId::parse("execution-supervisor-test").unwrap(),
    );
    coordination.worker_lease_ttl = Duration::from_secs(300);
    coordination.worker_renew_interval = Duration::from_secs(100);
    CallServiceRuntimeConfig {
        backend,
        worker_id,
        max_calls: 8,
        worker_capabilities: BTreeSet::from([
            "sip".into(),
            "webrtc".into(),
            "sip_egress".into(),
            "webrtc_egress".into(),
        ]),
        control_key: vec![0x41; 32],
        timeouts: CallTimeoutPolicy {
            setup: Duration::from_secs(30),
            media_idle: Duration::from_secs(30),
            transfer: Duration::from_secs(30),
            ending: Duration::from_secs(30),
        },
        coordination,
    }
}

async fn runtime(
    backend: CallRepositoryBackendConfig,
    worker_id: WorkerId,
) -> Arc<CallServiceRuntime> {
    Arc::new(
        build_call_service_runtime(
            runtime_config(backend, worker_id),
            Arc::new(SamePrincipalAttachmentResolver),
            Arc::new(SystemCallServiceClock),
        )
        .await
        .unwrap(),
    )
}

fn principal() -> ApiPrincipal {
    ApiPrincipal::new(
        AuthenticatedPrincipal {
            subject: "execution-owner".into(),
            tenant: Some("execution-tenant".into()),
            scopes: vec![
                "*".into(),
                bridgefu::api_principal::CallScope::ArbitraryDestination
                    .as_str()
                    .into(),
            ],
            issuer: Some("execution-test".into()),
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

fn reference_tenant_canary_policy() -> Arc<ReferenceTenantCanaryPolicy> {
    Arc::new(
        ReferenceTenantCanaryPolicy::new(ReferenceTenantCanaryConfig {
            tenant: "execution-tenant".into(),
            trusted_subject: "execution-owner".into(),
            trusted_issuer: "execution-test".into(),
            correlation_header: "X-Correlation-Id".into(),
            profile: "default".into(),
            instance_id: "reference-tenant-canary-instance".into(),
            contact_flow_id: "reference-tenant-canary-flow".into(),
            default_display_name: "ReferenceTenant canary caller".into(),
            attribute_mapping: AttributeMapping::default()
                .with_unmapped(UnmappedPolicy::Drop)
                .rename("X-Correlation-Id", "correlation_id")
                .rename("X-Vapi-Call-Id", "HostedWidget-vapiCallId"),
        })
        .unwrap(),
    )
}

fn reference_tenant_canary_metadata(correlation: &str) -> Vec<(String, String)> {
    vec![
        ("X-Correlation-Id".into(), correlation.into()),
        ("X-Vapi-Call-Id".into(), "vapi-call-canary-77".into()),
        (
            "X-Untrusted-Must-Not-Reach-Connect".into(),
            "private-unallowlisted-value".into(),
        ),
    ]
}

fn stable_recipe_principal() -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        subject: "stable-recipe-sbc".into(),
        tenant: Some("execution-tenant".into()),
        scopes: vec!["calls:create".into(), "sip:connect".into()],
        issuer: Some("bridgefu:recipe-catalog".into()),
        expires_at: None,
        method: AuthenticationMethod::ApiKey,
        assurance: IdentityAssurance::Pseudonymous {
            ephemeral_key: Jwk(serde_json::json!({
                "kty": "bridgefu-sip-ingress-profile",
                "profile_id": "recipe-execution-tenant-sip-ingress"
            })),
        },
    }
}

fn stable_recipe_catalog(principal: AuthenticatedPrincipal) -> Arc<RecipeSipAdmissionCatalog> {
    let ingress = NamedProfileBinding::new(
        NamedProfileRole::Ingress,
        NamedProfileKind::SipIngress,
        "recipe-execution-tenant-sip-ingress",
        "a".repeat(64),
    )
    .unwrap();
    let destination = NamedProfileBinding::new(
        NamedProfileRole::Destination,
        NamedProfileKind::AmazonConnect,
        "recipe-execution-tenant-amazon",
        "b".repeat(64),
    )
    .unwrap();
    let start = AmazonConnectStartSpec::new(
        "recipe-execution-tenant-amazon",
        "stable-recipe-instance",
        "stable-recipe-flow",
        BTreeMap::from([("bridgefu_recipe".into(), "stable-test".into())]),
        "Stable recipe caller",
        None,
    )
    .unwrap();
    Arc::new(
        RecipeSipAdmissionCatalog::new([RecipeSipAdmissionRoute {
            uri_user: "stable-support".into(),
            recipe_instance: "execution-tenant".into(),
            route_id: "stable-support".into(),
            expected_principal: principal,
            profiles: vec![ingress, destination],
            required_correlation_header: Some("X-Correlation-Id".into()),
            destination: RequestedLeg {
                direction: LegDirection::Outbound,
                signaling_initiator: Some(SignalingInitiator::Bridgefu),
                media_flow: MediaFlow::SendReceive,
                endpoint: LegEndpointConfig::AmazonConnect(AmazonConnectEndpointConfig {
                    instance_id: "stable-recipe-instance".into(),
                    contact_flow_id: "stable-recipe-flow".into(),
                }),
                amazon_connect_start: Some(start),
            },
        }])
        .unwrap(),
    )
}

async fn build_stable_recipe_runtime(principal: AuthenticatedPrincipal) -> Arc<CallServiceRuntime> {
    let mut config = runtime_config(CallRepositoryBackendConfig::Memory, WorkerId::new());
    config.max_calls = 2;
    config.worker_capabilities = BTreeSet::from(["sip".into(), "amazon_connect".into()]);
    let resolver = ConfiguredAttachmentPrincipalResolver::new().with_sip_ingress(
        NamedProfileKind::SipIngress,
        "recipe-execution-tenant-sip-ingress",
        "a".repeat(64),
        principal,
    );
    Arc::new(
        build_call_service_runtime(config, Arc::new(resolver), Arc::new(SystemCallServiceClock))
            .await
            .unwrap(),
    )
}

async fn assert_reference_tenant_wire_invite_rejected(
    caller: &Arc<UnifiedCoordinator>,
    caller_address: SocketAddr,
    listener: SocketAddr,
    routing_hint: &str,
    correlation: &str,
    vapi_call_id: &str,
) {
    let request = caller
        .invite(
            Some(format!("sip:trusted-vapi@{caller_address}")),
            format!("sip:{routing_hint}@{listener}"),
        )
        .with_raw_header(HeaderName::Other("X-Correlation-Id".into()), correlation)
        .expect("stage canary correlation header")
        .with_raw_header(HeaderName::Other("X-Vapi-Call-Id".into()), vapi_call_id)
        .expect("stage canary Vapi call header");
    let session_id = request
        .send()
        .await
        .expect("dispatch rejected-canary SIP transaction");
    let error = match caller
        .session(&session_id)
        .wait_for_answered(Some(Duration::from_secs(5)))
        .await
    {
        Ok(_) => panic!("replayed or cross-tenant canary INVITE must fail closed"),
        Err(error) => error,
    };
    let diagnostic = format!("{error:?}");
    assert!(!diagnostic.contains(correlation));
    assert!(!diagnostic.contains(vapi_call_id));
}

struct BridgefuWhepAuth {
    principal: AuthenticatedPrincipal,
}

#[async_trait::async_trait]
impl WhipAuthHook for BridgefuWhepAuth {
    async fn authenticate(
        &self,
        _method: &str,
        _path: &str,
        _bearer: Option<&str>,
        _peer_addr: SocketAddr,
    ) -> Result<AuthContext, AuthRejection> {
        Ok(AuthContext {
            subject: self.principal.subject.clone(),
            scopes: vec!["whep:subscribe".into()],
            session_hint: None,
            principal: Some(self.principal.clone()),
        })
    }
}

async fn canonical_whep_offer() -> String {
    let player = RvoipPeerConnection::new(&WebRtcConfig::loopback(), PeerRole::Offerer)
        .await
        .unwrap();
    player.prepare_receive_only_offer().await.unwrap();
    player.create_offer_and_gather().await.unwrap()
}

fn two_inbound_legs() -> CreateCallInput {
    two_inbound_legs_with_media(MediaFlow::SendReceive, MediaFlow::SendReceive)
}

fn two_inbound_sip_whep_legs() -> CreateCallInput {
    CreateCallInput {
        tenant_id: None,
        legs: [
            RequestedLeg {
                direction: LegDirection::Inbound,
                signaling_initiator: Some(SignalingInitiator::Remote),
                media_flow: MediaFlow::SendReceive,
                endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                    uri: None,
                    initial_context: Default::default(),
                }),
                amazon_connect_start: None,
            },
            RequestedLeg {
                direction: LegDirection::Inbound,
                signaling_initiator: Some(SignalingInitiator::Remote),
                media_flow: MediaFlow::SendReceive,
                endpoint: LegEndpointConfig::Whep(WhepEndpointConfig { endpoint_uri: None }),
                amazon_connect_start: None,
            },
        ],
    }
}

fn two_inbound_legs_with_media(
    sip_media_flow: MediaFlow,
    webrtc_media_flow: MediaFlow,
) -> CreateCallInput {
    CreateCallInput {
        tenant_id: None,
        legs: [
            RequestedLeg {
                direction: LegDirection::Inbound,
                signaling_initiator: None,
                media_flow: sip_media_flow,
                endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                    uri: None,
                    initial_context: Default::default(),
                }),
                amazon_connect_start: None,
            },
            RequestedLeg {
                direction: LegDirection::Inbound,
                signaling_initiator: None,
                media_flow: webrtc_media_flow,
                endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                    signaling_uri: None,
                }),
                amazon_connect_start: None,
            },
        ],
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcceptEvents {
    Connected,
    ConnectedThenEnded,
}

#[derive(Debug, Default)]
struct AdapterCounts {
    accept: AtomicUsize,
    reject: AtomicUsize,
    end: AtomicUsize,
    originate: AtomicUsize,
    activate: AtomicUsize,
    transfer: AtomicUsize,
    ended_connections: Mutex<Vec<ConnectionId>>,
    admission_outcomes: Mutex<Vec<(ConnectionId, u64, bool)>>,
}

struct TestMediaStream {
    id: StreamId,
    codec: CodecInfo,
    inbound: Arc<Mutex<Option<mpsc::Receiver<MediaFrame>>>>,
    source: mpsc::Sender<MediaFrame>,
    source_receiver_acquisitions: Arc<AtomicUsize>,
    outbound: mpsc::Sender<MediaFrame>,
    sink: Mutex<Option<mpsc::Receiver<MediaFrame>>>,
}

impl TestMediaStream {
    fn new(codec: CodecInfo) -> Arc<Self> {
        let (source, inbound) = mpsc::channel(32);
        let (outbound, sink) = mpsc::channel(32);
        Arc::new(Self {
            id: StreamId::new(),
            codec,
            inbound: Arc::new(Mutex::new(Some(inbound))),
            source,
            source_receiver_acquisitions: Arc::new(AtomicUsize::new(0)),
            outbound,
            sink: Mutex::new(Some(sink)),
        })
    }

    async fn inject(&self, frame: MediaFrame) -> Result<(), mpsc::error::SendError<MediaFrame>> {
        self.source.send(frame).await
    }

    fn take_output(&self) -> mpsc::Receiver<MediaFrame> {
        self.sink
            .lock()
            .unwrap()
            .take()
            .expect("test media output is acquired exactly once")
    }

    fn source_receiver_acquisitions(&self) -> usize {
        self.source_receiver_acquisitions.load(Ordering::SeqCst)
    }

    fn frame(&self, payload: Vec<u8>, timestamp_rtp: u32, payload_type: u8) -> MediaFrame {
        MediaFrame {
            stream_id: self.id.clone(),
            kind: StreamKind::Audio,
            payload: payload.into(),
            timestamp_rtp,
            captured_at: Utc::now(),
            payload_type: Some(payload_type),
        }
    }
}

fn codec(name: &str, clock_rate_hz: u32, channels: u8) -> CodecInfo {
    let payload_type = match name.to_ascii_lowercase().as_str() {
        "pcmu" | "g.711-mu" => Some(0),
        "pcma" | "g.711-a" => Some(8),
        "opus" => Some(111),
        _ => None,
    };
    CodecInfo {
        name: name.into(),
        clock_rate_hz,
        channels,
        fmtp: None,
        payload_type,
    }
}

#[async_trait::async_trait]
impl MediaStream for TestMediaStream {
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
                "test media receiver was already acquired",
            ))?;
        self.source_receiver_acquisitions
            .fetch_add(1, Ordering::SeqCst);
        Ok(receiver)
    }

    fn reserve_frames_in(&self) -> RvoipResult<MediaReceiverReservation> {
        let receiver = self
            .inbound
            .lock()
            .unwrap()
            .take()
            .ok_or(RvoipError::InvalidState(
                "test media receiver was already reserved",
            ))?;
        let inbound = Arc::clone(&self.inbound);
        let acquisitions = Arc::clone(&self.source_receiver_acquisitions);
        Ok(MediaReceiverReservation::new(receiver, move |receiver| {
            let replaced = inbound.lock().unwrap().replace(receiver);
            debug_assert!(replaced.is_none(), "rolled-back receiver slot was occupied");
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
struct CanaryConnectStarter {
    starts: Mutex<Vec<StartContactRequest>>,
    stops: Mutex<Vec<StopContactRequest>>,
}

#[async_trait::async_trait]
impl ConnectContactStarter for CanaryConnectStarter {
    async fn start_webrtc_contact(
        &self,
        request: StartContactRequest,
    ) -> rvoip_amazon_connect::Result<ConnectionData> {
        self.starts.lock().unwrap().push(request);
        Ok(ConnectionData {
            contact_id: "reference-tenant-canary-contact".into(),
            participant_id: "reference-tenant-canary-participant".into(),
            participant_token: "reference-tenant-canary-participant-token".into(),
            meeting_id: "reference-tenant-canary-meeting".into(),
            media_region: "us-west-2".into(),
            attendee_id: "reference-tenant-canary-attendee".into(),
            join_token: "reference-tenant-canary-join-token".into(),
            media_placement: MediaPlacement {
                signaling_url: "wss://localhost.invalid/reference-tenant-canary".into(),
                audio_host_url: "https://localhost.invalid/reference-tenant-canary-audio".into(),
                ..MediaPlacement::default()
            },
        })
    }

    async fn stop_contact(&self, request: StopContactRequest) -> rvoip_amazon_connect::Result<()> {
        self.stops.lock().unwrap().push(request);
        Ok(())
    }
}

struct CanaryConnectMediaSession {
    stream: Arc<TestMediaStream>,
    _terminal_tx: watch::Sender<Option<ConnectMediaTerminalCause>>,
    terminal_rx: watch::Receiver<Option<ConnectMediaTerminalCause>>,
    closes: AtomicUsize,
    aborts: AtomicUsize,
    close_notify: Notify,
}

impl CanaryConnectMediaSession {
    fn new() -> Arc<Self> {
        let (terminal_tx, terminal_rx) = watch::channel(None);
        Arc::new(Self {
            stream: TestMediaStream::new(codec("opus", 48_000, 1)),
            _terminal_tx: terminal_tx,
            terminal_rx,
            closes: AtomicUsize::new(0),
            aborts: AtomicUsize::new(0),
            close_notify: Notify::new(),
        })
    }

    async fn wait_closed(&self) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let notified = self.close_notify.notified();
                if self.closes.load(Ordering::Acquire) > 0 {
                    return;
                }
                notified.await;
            }
        })
        .await
        .expect("canary Connect media session was closed");
    }
}

#[async_trait::async_trait]
impl ConnectMediaSession for CanaryConnectMediaSession {
    fn negotiated_codecs(&self) -> NegotiatedCodecs {
        NegotiatedCodecs {
            audio: Some(self.stream.codec()),
            video: None,
        }
    }

    fn streams(&self) -> Vec<Arc<dyn MediaStream>> {
        vec![Arc::clone(&self.stream) as Arc<dyn MediaStream>]
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
        self.closes.fetch_add(1, Ordering::AcqRel);
        self.close_notify.notify_waiters();
        Ok(ConnectMediaCloseOutcome::Graceful)
    }

    fn abort(&self) {
        self.aborts.fetch_add(1, Ordering::AcqRel);
    }
}

struct CanaryConnectMediaConnector {
    session: Arc<CanaryConnectMediaSession>,
}

#[async_trait::async_trait]
impl ConnectMediaConnector for CanaryConnectMediaConnector {
    async fn connect(
        &self,
        _connection: &ConnectionData,
        _options: ConnectMediaConnectOptions,
    ) -> rvoip_amazon_connect::Result<Arc<dyn ConnectMediaSession>> {
        Ok(Arc::clone(&self.session) as Arc<dyn ConnectMediaSession>)
    }
}

type AcceptGate = (Arc<Barrier>, Arc<Barrier>);

struct LifecycleTestAdapter {
    transport: Transport,
    events: mpsc::Sender<OrchestratorAdapterEvent>,
    receiver: Mutex<Option<mpsc::Receiver<OrchestratorAdapterEvent>>>,
    live: Mutex<HashSet<ConnectionId>>,
    contexts: Mutex<HashMap<ConnectionId, InboundConnectionContext>>,
    sent_data: Mutex<Vec<(ConnectionId, DataMessage)>>,
    streams: Mutex<HashMap<ConnectionId, Arc<dyn MediaStream>>>,
    accept_events: Mutex<HashMap<ConnectionId, AcceptEvents>>,
    accept_gates: Mutex<HashMap<ConnectionId, AcceptGate>>,
    activation_gate: Mutex<Option<AcceptGate>>,
    originate_contexts: Mutex<Vec<OriginateContext>>,
    fail_activation: AtomicBool,
    fail_transfer: AtomicBool,
    transfers: Mutex<Vec<(ConnectionId, Option<TransferAttemptId>, TransferTarget)>>,
    transfer_status_on_submit: Mutex<Vec<TransferStatus>>,
    lifecycle: AdapterLifecycleSinkSlot,
    counts: Arc<AdapterCounts>,
}

impl LifecycleTestAdapter {
    fn new(transport: Transport) -> Arc<Self> {
        let (events, receiver) = mpsc::channel(64);
        Arc::new(Self {
            transport,
            events,
            receiver: Mutex::new(Some(receiver)),
            live: Mutex::new(HashSet::new()),
            contexts: Mutex::new(HashMap::new()),
            sent_data: Mutex::new(Vec::new()),
            streams: Mutex::new(HashMap::new()),
            accept_events: Mutex::new(HashMap::new()),
            accept_gates: Mutex::new(HashMap::new()),
            activation_gate: Mutex::new(None),
            originate_contexts: Mutex::new(Vec::new()),
            fail_activation: AtomicBool::new(false),
            fail_transfer: AtomicBool::new(false),
            transfers: Mutex::new(Vec::new()),
            transfer_status_on_submit: Mutex::new(Vec::new()),
            lifecycle: AdapterLifecycleSinkSlot::default(),
            counts: Arc::new(AdapterCounts::default()),
        })
    }

    fn prepare_inbound(
        &self,
        connection_id: ConnectionId,
        owner: &AuthenticatedPrincipal,
        token: String,
        events: AcceptEvents,
    ) -> Arc<TestMediaStream> {
        self.prepare_inbound_with_codec(
            connection_id,
            owner,
            token,
            events,
            codec("pcmu", 8_000, 1),
        )
    }

    fn prepare_inbound_with_codec(
        &self,
        connection_id: ConnectionId,
        owner: &AuthenticatedPrincipal,
        token: String,
        events: AcceptEvents,
        codec: CodecInfo,
    ) -> Arc<TestMediaStream> {
        self.prepare_inbound_with_codec_and_metadata(
            connection_id,
            owner,
            token,
            events,
            codec,
            InboundSignalingMetadata::default(),
        )
    }

    fn prepare_inbound_with_codec_and_metadata(
        &self,
        connection_id: ConnectionId,
        owner: &AuthenticatedPrincipal,
        token: String,
        events: AcceptEvents,
        codec: CodecInfo,
        metadata: InboundSignalingMetadata,
    ) -> Arc<TestMediaStream> {
        self.live.lock().unwrap().insert(connection_id.clone());
        let stream = TestMediaStream::new(codec);
        self.streams.lock().unwrap().insert(
            connection_id.clone(),
            Arc::clone(&stream) as Arc<dyn MediaStream>,
        );
        self.contexts.lock().unwrap().insert(
            connection_id.clone(),
            InboundConnectionContext::new(
                connection_id.clone(),
                self.transport,
                owner,
                Some(InboundRoutingHint::new(token).unwrap()),
                metadata,
            )
            .unwrap(),
        );
        self.accept_events
            .lock()
            .unwrap()
            .insert(connection_id, events);
        stream
    }

    fn gate_accept(&self, connection_id: &ConnectionId) -> AcceptGate {
        let gate = (Arc::new(Barrier::new(2)), Arc::new(Barrier::new(2)));
        self.accept_gates
            .lock()
            .unwrap()
            .insert(connection_id.clone(), gate.clone());
        gate
    }

    fn gate_activation(&self) -> AcceptGate {
        let gate = (Arc::new(Barrier::new(2)), Arc::new(Barrier::new(2)));
        *self.activation_gate.lock().unwrap() = Some(gate.clone());
        gate
    }

    fn last_web_rtc_originate_context(&self) -> Arc<WebRtcOriginateContext> {
        self.originate_contexts
            .lock()
            .unwrap()
            .last()
            .and_then(|context| context.downcast_arc::<WebRtcOriginateContext>())
            .expect("outbound WebRTC context was retained")
    }

    fn last_sip_originate_context(&self) -> Arc<SipOriginateContext> {
        self.originate_contexts
            .lock()
            .unwrap()
            .last()
            .and_then(|context| context.downcast_arc::<SipOriginateContext>())
            .expect("outbound SIP context was retained")
    }

    fn route_is_live(&self, connection_id: &ConnectionId) -> bool {
        self.live.lock().unwrap().contains(connection_id)
    }

    async fn announce_inbound(&self, connection_id: ConnectionId, owner: AuthenticatedPrincipal) {
        self.events
            .send(OrchestratorAdapterEvent::AuthenticatedInboundConnection {
                connection: inbound_connection(connection_id, self.transport),
                participant_id: format!("{}-participant", transport_label(self.transport)),
                principal: owner,
            })
            .await
            .unwrap();
    }

    async fn remote_end(&self, connection_id: ConnectionId) {
        self.live.lock().unwrap().remove(&connection_id);
        self.events
            .send(
                AdapterEvent::Ended {
                    connection_id,
                    reason: EndReason::Normal,
                }
                .into(),
            )
            .await
            .unwrap();
    }

    async fn emit_data_message(&self, connection_id: ConnectionId, message: DataMessage) {
        self.events
            .send(
                AdapterEvent::DataMessage {
                    connection_id,
                    message,
                }
                .into(),
            )
            .await
            .unwrap();
    }

    async fn emit_transfer_status(
        &self,
        connection_id: ConnectionId,
        attempt_id: Option<TransferAttemptId>,
        status: TransferStatus,
    ) {
        self.events
            .send(
                AdapterEvent::TransferStatus {
                    connection_id,
                    attempt_id,
                    status,
                }
                .into(),
            )
            .await
            .unwrap();
    }

    fn transfer_status_during_submission(&self, statuses: Vec<TransferStatus>) {
        *self.transfer_status_on_submit.lock().unwrap() = statuses;
    }

    fn last_transfer(&self) -> Option<(ConnectionId, Option<TransferAttemptId>, TransferTarget)> {
        self.transfers.lock().unwrap().last().cloned()
    }

    async fn submit_transfer(
        &self,
        connection_id: ConnectionId,
        attempt_id: Option<TransferAttemptId>,
        target: TransferTarget,
    ) -> RvoipResult<()> {
        self.counts.transfer.fetch_add(1, Ordering::SeqCst);
        self.transfers
            .lock()
            .unwrap()
            .push((connection_id.clone(), attempt_id.clone(), target));
        let statuses = std::mem::take(&mut *self.transfer_status_on_submit.lock().unwrap());
        for status in statuses {
            self.emit_transfer_status(connection_id.clone(), attempt_id.clone(), status)
                .await;
        }
        if self.fail_transfer.load(Ordering::SeqCst) {
            Err(RvoipError::NotImplemented(
                "test adapter transfer is unsupported",
            ))
        } else {
            Ok(())
        }
    }

    fn admission_was_accepted(&self, connection_id: &ConnectionId) -> bool {
        self.counts
            .admission_outcomes
            .lock()
            .unwrap()
            .iter()
            .any(|(observed, _, accepted)| observed == connection_id && *accepted)
    }

    fn take_sent_data(&self, connection_id: &ConnectionId) -> Option<DataMessage> {
        let mut messages = self.sent_data.lock().unwrap();
        messages
            .iter()
            .position(|(candidate, _)| candidate == connection_id)
            .map(|index| messages.remove(index).1)
    }
}

struct TelnyxReplacementExecutor {
    sip: Arc<LifecycleTestAdapter>,
    principal: AuthenticatedPrincipal,
    auto_attach: AtomicBool,
    start_calls: Mutex<Vec<ProviderExecutionContext>>,
    destination_calls: Mutex<Vec<ProviderExecutionContext>>,
    hangups: Mutex<Vec<(ProviderExecutionContext, ProviderExecutionReference)>>,
    attachment_connections: Mutex<HashMap<BindingGeneration, ConnectionId>>,
    connect_failures: Mutex<VecDeque<ProviderExecutionError>>,
    start_gate: Mutex<Option<AcceptGate>>,
    destination_gate: Mutex<Option<AcceptGate>>,
    start_notify: Notify,
}

impl TelnyxReplacementExecutor {
    fn new(sip: Arc<LifecycleTestAdapter>, principal: AuthenticatedPrincipal) -> Arc<Self> {
        Arc::new(Self {
            sip,
            principal,
            auto_attach: AtomicBool::new(true),
            start_calls: Mutex::new(Vec::new()),
            destination_calls: Mutex::new(Vec::new()),
            hangups: Mutex::new(Vec::new()),
            attachment_connections: Mutex::new(HashMap::new()),
            connect_failures: Mutex::new(VecDeque::new()),
            start_gate: Mutex::new(None),
            destination_gate: Mutex::new(None),
            start_notify: Notify::new(),
        })
    }

    fn set_auto_attach(&self, enabled: bool) {
        self.auto_attach.store(enabled, Ordering::SeqCst);
    }

    fn fail_next_destination(&self, error: ProviderExecutionError) {
        self.connect_failures.lock().unwrap().push_back(error);
    }

    fn gate_next_start(&self) -> AcceptGate {
        let gate = (Arc::new(Barrier::new(2)), Arc::new(Barrier::new(2)));
        *self.start_gate.lock().unwrap() = Some(gate.clone());
        gate
    }

    fn gate_next_destination(&self) -> AcceptGate {
        let gate = (Arc::new(Barrier::new(2)), Arc::new(Barrier::new(2)));
        *self.destination_gate.lock().unwrap() = Some(gate.clone());
        gate
    }

    fn start_count(&self) -> usize {
        self.start_calls.lock().unwrap().len()
    }

    fn destination_count(&self) -> usize {
        self.destination_calls.lock().unwrap().len()
    }

    fn hangup_snapshot(&self) -> Vec<(ProviderExecutionContext, ProviderExecutionReference)> {
        self.hangups.lock().unwrap().clone()
    }

    fn attachment_connection(&self, generation: BindingGeneration) -> Option<ConnectionId> {
        self.attachment_connections
            .lock()
            .unwrap()
            .get(&generation)
            .cloned()
    }

    async fn wait_for_start_count(&self, expected: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let notified = self.start_notify.notified();
                if self.start_count() >= expected {
                    return;
                }
                notified.await;
            }
        })
        .await
        .expect("Telnyx replacement media start did not execute");
    }

    fn reference(context: &ProviderExecutionContext, role: &str) -> ProviderExecutionReference {
        ProviderExecutionReference {
            account: ProviderAccountKey::parse("telnyx-test").unwrap(),
            provider_call_id: ProviderCallId::parse(format!(
                "{role}-generation-{}-{}",
                context.binding_generation.value(),
                context.effect_id
            ))
            .unwrap(),
        }
    }
}

#[async_trait::async_trait]
impl ProviderLegExecutor for TelnyxReplacementExecutor {
    async fn start_media(
        &self,
        request: ProviderStartMediaRequest,
    ) -> Result<ProviderExecutionReference, ProviderExecutionError> {
        let context = request.context.clone();
        self.start_calls.lock().unwrap().push(context.clone());
        self.start_notify.notify_waiters();
        let gate = self.start_gate.lock().unwrap().take();
        if let Some((entered, release)) = gate {
            entered.wait().await;
            release.wait().await;
        }
        if self.auto_attach.load(Ordering::SeqCst) {
            let connection_id = ConnectionId::new();
            self.sip.prepare_inbound(
                connection_id.clone(),
                &self.principal,
                request.attachment_token.expose_secret().to_owned(),
                AcceptEvents::Connected,
            );
            self.attachment_connections
                .lock()
                .unwrap()
                .insert(context.binding_generation, connection_id.clone());
            self.sip
                .announce_inbound(connection_id, self.principal.clone())
                .await;
        }
        Ok(Self::reference(&context, "media"))
    }

    async fn connect_destination(
        &self,
        request: ProviderConnectDestinationRequest,
    ) -> Result<ProviderExecutionReference, ProviderExecutionError> {
        let context = request.context.clone();
        self.destination_calls.lock().unwrap().push(context.clone());
        let gate = self.destination_gate.lock().unwrap().take();
        if let Some((entered, release)) = gate {
            entered.wait().await;
            release.wait().await;
        }
        if let Some(error) = self.connect_failures.lock().unwrap().pop_front() {
            return Err(error);
        }
        Ok(Self::reference(&context, "destination"))
    }

    async fn transfer(
        &self,
        _request: ProviderTransferRequest,
    ) -> Result<(), ProviderExecutionError> {
        Err(ProviderExecutionError::Unsupported)
    }

    async fn hangup(&self, request: ProviderHangupRequest) -> Result<(), ProviderExecutionError> {
        self.hangups
            .lock()
            .unwrap()
            .push((request.context, request.media_call));
        Ok(())
    }

    async fn send_dtmf(&self, _request: ProviderDtmfRequest) -> Result<(), ProviderExecutionError> {
        Err(ProviderExecutionError::Unsupported)
    }
}

#[async_trait::async_trait]
impl ConnectionAdapter for LifecycleTestAdapter {
    fn transport(&self) -> Transport {
        self.transport
    }

    fn kind(&self) -> AdapterKind {
        AdapterKind::Interop
    }

    fn lifecycle_capabilities(&self) -> AdapterLifecycleCapabilities {
        AdapterLifecycleCapabilities {
            staged_outbound_activation: true,
            ..AdapterLifecycleCapabilities::FAIL_CLOSED_INBOUND
        }
    }

    fn supports_inbound_admission_confirmation(&self) -> bool {
        true
    }

    fn notify_inbound_admission_outcome(
        &self,
        connection_id: &ConnectionId,
        generation: u64,
        accepted: bool,
    ) {
        self.counts.admission_outcomes.lock().unwrap().push((
            connection_id.clone(),
            generation,
            accepted,
        ));
    }

    fn install_lifecycle_sink(&self, sink: Arc<dyn AdapterLifecycleSink>) -> RvoipResult<()> {
        self.lifecycle
            .install(sink)
            .map_err(|_| RvoipError::InvalidState("test lifecycle sink already installed"))
    }

    fn is_connection_live(&self, connection_id: &ConnectionId) -> bool {
        self.live.lock().unwrap().contains(connection_id)
    }

    fn take_inbound_context(
        &self,
        connection_id: &ConnectionId,
    ) -> Option<InboundConnectionContext> {
        self.contexts.lock().unwrap().remove(connection_id)
    }

    async fn originate(&self, request: OriginateRequest) -> RvoipResult<ConnectionHandle> {
        self.counts.originate.fetch_add(1, Ordering::SeqCst);
        self.originate_contexts
            .lock()
            .unwrap()
            .push(request.context.clone());
        let connection = Connection {
            id: ConnectionId::new(),
            session_id: request.session_id,
            participant_id: request.participant_id,
            transport: self.transport,
            direction: Direction::Outbound,
            state: ConnectionState::Connecting,
            capabilities: request.capabilities,
            negotiated_codecs: NegotiatedCodecs::default(),
            streams: Vec::new(),
            messaging_enabled: true,
            transport_handle: TransportHandle(Arc::new(())),
            opened_at: Utc::now(),
            closed_at: None,
        };
        self.streams.lock().unwrap().insert(
            connection.id.clone(),
            TestMediaStream::new(codec("opus", 48_000, 1)) as Arc<dyn MediaStream>,
        );
        self.live.lock().unwrap().insert(connection.id.clone());
        Ok(ConnectionHandle::new(connection))
    }

    async fn activate_outbound(&self, connection_id: ConnectionId) -> RvoipResult<()> {
        self.counts.activate.fetch_add(1, Ordering::SeqCst);
        let gate = self.activation_gate.lock().unwrap().take();
        if let Some((entered, release)) = gate {
            entered.wait().await;
            release.wait().await;
        }
        if self.fail_activation.load(Ordering::SeqCst) {
            return Err(RvoipError::InvalidState("test outbound activation failed"));
        }
        self.events
            .send(AdapterEvent::Connected { connection_id }.into())
            .await
            .map_err(|_| RvoipError::InvalidState("test event receiver closed"))
    }

    async fn activate_outbound_with_receipt(
        &self,
        connection_id: ConnectionId,
    ) -> RvoipResult<OutboundActivation> {
        self.activate_outbound(connection_id.clone()).await?;
        if self.transport == Transport::Sip {
            let reference = ExternalConnectionReference::new(
                "sip.call-id",
                format!("{}@capture.example.test", connection_id.as_str()),
            )
            .map_err(|_| RvoipError::InvalidState("test SIP Call-ID is invalid"))?;
            Ok(OutboundActivation::with_external_reference(reference))
        } else {
            Ok(OutboundActivation::default())
        }
    }

    async fn accept(&self, connection_id: ConnectionId) -> RvoipResult<()> {
        self.counts.accept.fetch_add(1, Ordering::SeqCst);
        let gate = self.accept_gates.lock().unwrap().remove(&connection_id);
        if let Some((entered, release)) = gate {
            entered.wait().await;
            release.wait().await;
        }
        if !self.live.lock().unwrap().contains(&connection_id) {
            return Err(RvoipError::ConnectionNotFound(connection_id));
        }
        let events = self
            .accept_events
            .lock()
            .unwrap()
            .get(&connection_id)
            .copied()
            .unwrap_or(AcceptEvents::Connected);
        self.events
            .send(
                AdapterEvent::Connected {
                    connection_id: connection_id.clone(),
                }
                .into(),
            )
            .await
            .map_err(|_| RvoipError::InvalidState("test event receiver closed"))?;
        if events == AcceptEvents::ConnectedThenEnded {
            self.live.lock().unwrap().remove(&connection_id);
            self.events
                .send(
                    AdapterEvent::Ended {
                        connection_id,
                        reason: EndReason::Normal,
                    }
                    .into(),
                )
                .await
                .map_err(|_| RvoipError::InvalidState("test event receiver closed"))?;
        }
        Ok(())
    }

    async fn reject(&self, connection_id: ConnectionId, _: RejectReason) -> RvoipResult<()> {
        self.counts.reject.fetch_add(1, Ordering::SeqCst);
        self.live.lock().unwrap().remove(&connection_id);
        Ok(())
    }

    async fn end(&self, connection_id: ConnectionId, _: EndReason) -> RvoipResult<()> {
        self.counts.end.fetch_add(1, Ordering::SeqCst);
        self.counts
            .ended_connections
            .lock()
            .unwrap()
            .push(connection_id.clone());
        let was_live = self.live.lock().unwrap().remove(&connection_id);
        if was_live {
            self.events
                .send(
                    AdapterEvent::Ended {
                        connection_id,
                        reason: EndReason::Normal,
                    }
                    .into(),
                )
                .await
                .map_err(|_| RvoipError::InvalidState("test event receiver closed"))?;
        }
        Ok(())
    }

    async fn hold(&self, _: ConnectionId) -> RvoipResult<()> {
        Ok(())
    }

    async fn resume(&self, _: ConnectionId) -> RvoipResult<()> {
        Ok(())
    }

    async fn transfer(
        &self,
        connection_id: ConnectionId,
        target: TransferTarget,
    ) -> RvoipResult<()> {
        self.submit_transfer(connection_id, None, target).await
    }

    async fn transfer_with_attempt(
        &self,
        connection_id: ConnectionId,
        attempt_id: TransferAttemptId,
        target: TransferTarget,
    ) -> RvoipResult<()> {
        self.submit_transfer(connection_id, Some(attempt_id), target)
            .await
    }

    async fn streams(&self, connection_id: ConnectionId) -> RvoipResult<Vec<Arc<dyn MediaStream>>> {
        Ok(self
            .streams
            .lock()
            .unwrap()
            .get(&connection_id)
            .cloned()
            .into_iter()
            .collect())
    }

    async fn send_message(&self, _: ConnectionId, _: Message) -> RvoipResult<()> {
        Ok(())
    }

    async fn send_data_message(
        &self,
        connection_id: ConnectionId,
        message: DataMessage,
    ) -> RvoipResult<()> {
        self.sent_data
            .lock()
            .unwrap()
            .push((connection_id, message));
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
        mpsc::channel(1).1
    }

    fn subscribe_orchestrator_events(&self) -> mpsc::Receiver<OrchestratorAdapterEvent> {
        self.receiver
            .lock()
            .unwrap()
            .take()
            .expect("orchestrator subscribes exactly once")
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

fn inbound_connection(connection_id: ConnectionId, transport: Transport) -> Connection {
    Connection {
        id: connection_id,
        session_id: SessionId::new(),
        participant_id: ParticipantId::new(),
        transport,
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

fn transport_label(transport: Transport) -> &'static str {
    match transport {
        Transport::Sip => "sip",
        Transport::WebRtc => "webrtc",
        _ => "other",
    }
}

struct CreatedInboundCall {
    call_id: CallId,
    sip_leg: LegId,
    sip_token: String,
    webrtc_leg: LegId,
    webrtc_token: String,
}

struct CreatedOutboundWebRtcCall {
    call_id: CallId,
    leg_id: LegId,
}

struct CreatedRequiredSipContextCall {
    call_id: CallId,
    source_leg_id: LegId,
    source_token: String,
    target_leg_id: LegId,
}

fn inbound_sip_outbound_web_rtc(endpoint: LegEndpointConfig) -> CreateCallInput {
    CreateCallInput {
        tenant_id: None,
        legs: [
            RequestedLeg {
                direction: LegDirection::Inbound,
                signaling_initiator: Some(SignalingInitiator::Remote),
                media_flow: MediaFlow::SendReceive,
                endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                    uri: None,
                    initial_context: Default::default(),
                }),
                amazon_connect_start: None,
            },
            RequestedLeg {
                direction: LegDirection::Outbound,
                signaling_initiator: Some(SignalingInitiator::Bridgefu),
                media_flow: MediaFlow::SendReceive,
                endpoint,
                amazon_connect_start: None,
            },
        ],
    }
}

fn inbound_web_rtc_outbound_web_rtc(endpoint: LegEndpointConfig) -> CreateCallInput {
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
                endpoint,
                amazon_connect_start: None,
            },
        ],
    }
}

async fn create_outbound_web_rtc_call(
    runtime: &CallServiceRuntime,
    idempotency: &str,
    endpoint: LegEndpointConfig,
) -> CreatedOutboundWebRtcCall {
    let expected_kind = endpoint.kind();
    let created = runtime
        .service()
        .create_call(
            &principal(),
            &IdempotencyKey::parse(idempotency).unwrap(),
            inbound_sip_outbound_web_rtc(endpoint),
        )
        .await
        .unwrap();
    let leg = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.kind == expected_kind && leg.direction == LegDirection::Outbound)
        .unwrap();
    CreatedOutboundWebRtcCall {
        call_id: created.value.call.call_id,
        leg_id: leg.leg_id,
    }
}

async fn create_required_sip_context_call(
    runtime: &CallServiceRuntime,
    idempotency: &str,
) -> CreatedRequiredSipContextCall {
    let created = runtime
        .service()
        .create_call(
            &principal(),
            &IdempotencyKey::parse(idempotency).unwrap(),
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
                            uri: Some("sips:callee@voice.example.test;transport=tls".into()),
                            initial_context: SipInitialContextMode::Required,
                        }),
                        amazon_connect_start: None,
                    },
                ],
            },
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
    let target = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Outbound)
        .unwrap();
    CreatedRequiredSipContextCall {
        call_id: created.value.call.call_id,
        source_leg_id: source.leg_id,
        source_token: source.attachment.as_ref().unwrap().token.clone(),
        target_leg_id: target.leg_id,
    }
}

async fn create_inbound_call(
    runtime: &CallServiceRuntime,
    idempotency: &str,
) -> CreatedInboundCall {
    create_inbound_call_with_media(
        runtime,
        idempotency,
        MediaFlow::SendReceive,
        MediaFlow::SendReceive,
    )
    .await
}

async fn create_inbound_call_with_media(
    runtime: &CallServiceRuntime,
    idempotency: &str,
    sip_media_flow: MediaFlow,
    webrtc_media_flow: MediaFlow,
) -> CreatedInboundCall {
    let created = runtime
        .service()
        .create_call(
            &principal(),
            &IdempotencyKey::parse(idempotency).unwrap(),
            two_inbound_legs_with_media(sip_media_flow, webrtc_media_flow),
        )
        .await
        .unwrap();
    let sip = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.kind == bridgefu::call_engine::LegKind::Sip)
        .unwrap();
    let webrtc = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.kind == bridgefu::call_engine::LegKind::InteractiveWebRtc)
        .unwrap();
    CreatedInboundCall {
        call_id: created.value.call.call_id,
        sip_leg: sip.leg_id,
        sip_token: sip.attachment.as_ref().unwrap().token.clone(),
        webrtc_leg: webrtc.leg_id,
        webrtc_token: webrtc.attachment.as_ref().unwrap().token.clone(),
    }
}

async fn execution_harness(
    max_calls: usize,
) -> (
    Arc<CallServiceRuntime>,
    Arc<Orchestrator>,
    CallExecutionSupervisor,
    Arc<LifecycleTestAdapter>,
    Arc<LifecycleTestAdapter>,
) {
    execution_harness_with_context(max_calls, ContextPolicy::default(), Duration::from_secs(30))
        .await
}

async fn execution_harness_with_context(
    max_calls: usize,
    context_policy: ContextPolicy,
    setup_timeout: Duration,
) -> (
    Arc<CallServiceRuntime>,
    Arc<Orchestrator>,
    CallExecutionSupervisor,
    Arc<LifecycleTestAdapter>,
    Arc<LifecycleTestAdapter>,
) {
    let worker_id = WorkerId::new();
    let mut config = runtime_config(CallRepositoryBackendConfig::Memory, worker_id);
    config.max_calls = max_calls;
    config.timeouts.setup = setup_timeout;
    let runtime = Arc::new(
        build_call_service_runtime(
            config,
            Arc::new(SamePrincipalAttachmentResolver),
            Arc::new(SystemCallServiceClock),
        )
        .await
        .unwrap(),
    );
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let supervisor = CallExecutionSupervisor::install_with_leg_executors_and_context_policy(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        Arc::new(DisabledProviderLegExecutor),
        None,
        Arc::new(context_policy),
        max_calls * 2,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let sip = LifecycleTestAdapter::new(Transport::Sip);
    let webrtc = LifecycleTestAdapter::new(Transport::WebRtc);
    orchestrator
        .register(Arc::clone(&sip) as Arc<dyn ConnectionAdapter>)
        .unwrap();
    orchestrator
        .register(Arc::clone(&webrtc) as Arc<dyn ConnectionAdapter>)
        .unwrap();
    (runtime, orchestrator, supervisor, sip, webrtc)
}

fn telnyx_media_principal() -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        subject: "telnyx-media".into(),
        tenant: Some("execution-tenant".into()),
        scopes: Vec::new(),
        issuer: Some("sip-digest:bridgefu".into()),
        expires_at: None,
        method: AuthenticationMethod::SipDigest,
        assurance: IdentityAssurance::Identified {
            credential_kind: rvoip_core::CredentialKind::SipDigest,
        },
    }
}

async fn telnyx_replacement_harness(
    transfer_timeout: Duration,
) -> (
    Arc<CallServiceRuntime>,
    Arc<Orchestrator>,
    CallExecutionSupervisor,
    Arc<LifecycleTestAdapter>,
    Arc<LifecycleTestAdapter>,
    Arc<TelnyxReplacementExecutor>,
) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
    let worker_id = WorkerId::new();
    let mut config = runtime_config(CallRepositoryBackendConfig::Memory, worker_id);
    config.timeouts.transfer = transfer_timeout;
    config.worker_capabilities.insert("telnyx".into());
    let media_principal = telnyx_media_principal();
    let runtime = Arc::new(
        build_call_service_runtime(
            config,
            Arc::new(ConfiguredAttachmentPrincipalResolver::new().with_provider(
                ProviderKind::Telnyx,
                "telnyx-test",
                media_principal.clone(),
            )),
            Arc::new(SystemCallServiceClock),
        )
        .await
        .unwrap(),
    );
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let sip = LifecycleTestAdapter::new(Transport::Sip);
    let webrtc = LifecycleTestAdapter::new(Transport::WebRtc);
    let provider = TelnyxReplacementExecutor::new(Arc::clone(&sip), media_principal);
    let supervisor = CallExecutionSupervisor::install_with_leg_executors_and_context_policy(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        Arc::clone(&provider) as Arc<dyn ProviderLegExecutor>,
        None,
        Arc::new(ContextPolicy::default()),
        8,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    orchestrator
        .register(Arc::clone(&sip) as Arc<dyn ConnectionAdapter>)
        .unwrap();
    orchestrator
        .register(Arc::clone(&webrtc) as Arc<dyn ConnectionAdapter>)
        .unwrap();
    (runtime, orchestrator, supervisor, sip, webrtc, provider)
}

struct ActiveReplaceableCall {
    call_id: CallId,
    source_connection_id: ConnectionId,
    destination_leg_id: LegId,
    destination_connection_id: ConnectionId,
    destination_generation: BindingGeneration,
}

async fn activate_replaceable_call(
    runtime: &CallServiceRuntime,
    orchestrator: &Orchestrator,
    sip: &LifecycleTestAdapter,
    idempotency: &str,
) -> ActiveReplaceableCall {
    let created = runtime
        .service()
        .create_call(
            &principal(),
            &IdempotencyKey::parse(idempotency).unwrap(),
            inbound_sip_outbound_web_rtc(LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                signaling_uri: Some("wss://original-agent.example.test/session".into()),
            })),
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
    let source_connection_id = attach(
        sip,
        principal().authenticated(),
        source.attachment.as_ref().unwrap().token.clone(),
        AcceptEvents::Connected,
    )
    .await;
    let destination_leg_id = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Outbound)
        .unwrap()
        .leg_id;
    let active = wait_for_call(runtime, created.value.call.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;
    wait_for_active_bridge_count(orchestrator, 1).await;
    let destination = active.call.bindings.get(&destination_leg_id).unwrap();
    ActiveReplaceableCall {
        call_id: created.value.call.call_id,
        source_connection_id,
        destination_leg_id,
        destination_connection_id: destination.connection_id.clone(),
        destination_generation: destination.binding_generation,
    }
}

async fn activate_direct_browser_call(
    runtime: &CallServiceRuntime,
    orchestrator: &Orchestrator,
    webrtc: &LifecycleTestAdapter,
    idempotency: &str,
) -> ActiveReplaceableCall {
    let created = runtime
        .service()
        .create_call(
            &principal(),
            &IdempotencyKey::parse(idempotency).unwrap(),
            inbound_web_rtc_outbound_web_rtc(LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                signaling_uri: Some("wss://vapi-assistant.example.test/session".into()),
            })),
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
    let source_connection_id = attach(
        webrtc,
        principal().authenticated(),
        source.attachment.as_ref().unwrap().token.clone(),
        AcceptEvents::Connected,
    )
    .await;
    let destination_leg_id = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Outbound)
        .unwrap()
        .leg_id;
    let active = wait_for_call(runtime, created.value.call.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;
    wait_for_active_bridge_count(orchestrator, 1).await;
    let destination = active.call.bindings.get(&destination_leg_id).unwrap();
    ActiveReplaceableCall {
        call_id: created.value.call.call_id,
        source_connection_id,
        destination_leg_id,
        destination_connection_id: destination.connection_id.clone(),
        destination_generation: destination.binding_generation,
    }
}

async fn wait_for_handoff_status(
    adapter: &LifecycleTestAdapter,
    browser_connection_id: &ConnectionId,
    terminal: HandoffStatusKind,
) -> Vec<HandoffStatusEnvelope> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut statuses = Vec::new();
        loop {
            while let Some(message) = adapter.take_sent_data(browser_connection_id) {
                if message.label != HANDOFF_STATUS_LABEL {
                    continue;
                }
                let status = HandoffStatusEnvelope::from_data_message(&message)
                    .expect("server handoff status must match the public wire contract");
                let done = status.status == terminal;
                statuses.push(status);
                if done {
                    return statuses;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("terminal browser handoff status was not delivered")
}

fn assert_handoff_sequence(
    statuses: &[HandoffStatusEnvelope],
    call: &ActiveReplaceableCall,
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
        assert_eq!(status.version, 1);
        assert_eq!(status.call_id, call.call_id);
        assert_eq!(status.replacement_leg_id, call.destination_leg_id);
        assert_eq!(status.binding_generation, generation);
        assert_eq!(status.detail_code, None);
    }
}

fn telnyx_replacement_destination(destination: &str) -> RequestedLeg {
    RequestedLeg {
        direction: LegDirection::Outbound,
        signaling_initiator: Some(SignalingInitiator::Bridgefu),
        media_flow: MediaFlow::SendReceive,
        endpoint: LegEndpointConfig::Provider(ProviderEndpointConfig {
            provider: ProviderKind::Telnyx,
            account_profile: "telnyx-test".into(),
            destination: Some(destination.into()),
        }),
        amazon_connect_start: None,
    }
}

async fn start_telnyx_replacement(
    runtime: &CallServiceRuntime,
    call: &ActiveReplaceableCall,
    idempotency: &str,
) -> bridgefu::call_service::CallOperationResult<bridgefu::call_service::CallView> {
    runtime
        .service()
        .replace_leg(
            &principal(),
            call.call_id,
            call.destination_leg_id,
            &IdempotencyKey::parse(idempotency).unwrap(),
            ReplaceLegInput {
                tenant_id: None,
                route_id: "telnyx-support".into(),
            },
            telnyx_replacement_destination("+12065550100"),
            NamedRouteBinding::new_with_profiles(
                "telnyx-support",
                None,
                vec![NamedProfileBinding::new(
                    NamedProfileRole::Destination,
                    NamedProfileKind::Telnyx,
                    "telnyx-test",
                    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                )
                .unwrap()],
            )
            .unwrap(),
        )
        .await
        .unwrap()
}

async fn accept_telnyx_replacement_ready(
    runtime: &CallServiceRuntime,
    call_id: CallId,
    leg_id: LegId,
    binding_generation: BindingGeneration,
    digest_seed: u8,
) {
    ingest_telnyx_replacement_destination_event(
        runtime,
        call_id,
        leg_id,
        binding_generation,
        "call.bridged",
        digest_seed,
    )
    .await;
}

fn telnyx_event_payload(
    kind: &str,
    context: &ProviderExecutionContext,
    role: ProviderDialRole,
) -> serde_json::Value {
    let client_state = telnyx::calls::client_state::encode_json(
        &ProviderDialClientState::new(context, role, None, &ContextPolicy::default())
            .expect("construct exact Telnyx callback client state"),
    )
    .expect("encode exact Telnyx callback client state");
    serde_json::json!({
        "data": {
            "event_type": kind,
            "payload": {"client_state": client_state}
        }
    })
}

async fn ingest_telnyx_replacement_destination_event(
    runtime: &CallServiceRuntime,
    call_id: CallId,
    leg_id: LegId,
    binding_generation: BindingGeneration,
    kind: &str,
    digest_seed: u8,
) {
    let tenant = TenantId::parse("execution-tenant").unwrap();
    let reference = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(reference) = runtime
                .service_repository()
                .load_external_reference_for_binding(
                    &tenant,
                    call_id,
                    leg_id,
                    binding_generation,
                    ProviderReferenceRole::Destination,
                )
                .await
                .unwrap()
            {
                return reference;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Telnyx destination reference was not retained");
    let effect_id = reference.effect_id;
    let (account, provider_call_id) = match reference.value {
        ExternalReferenceValue::ProviderCall {
            account,
            provider_call_id,
        } => (account, provider_call_id),
        ExternalReferenceValue::Signaling { .. } => {
            panic!("Telnyx destination reference must be provider-owned")
        }
    };
    let context = ProviderExecutionContext {
        tenant_id: tenant.clone(),
        call_id,
        leg_id,
        binding_generation,
        effect_id,
    };
    let received_at = Utc::now();
    assert!(matches!(
        runtime
            .repository()
            .ingest_provider_event(ProviderEventInput {
                account,
                event_digest: ProviderEventDigest::new([digest_seed; 32]),
                payload_digest: ProviderPayloadDigest::new([digest_seed.wrapping_add(1); 32]),
                provider_call_id,
                kind: kind.into(),
                payload: telnyx_event_payload(kind, &context, ProviderDialRole::Destination),
                occurred_at: Some(received_at),
                received_at,
            })
            .await
            .unwrap(),
        ProviderEventOutcome::Accepted(_)
    ));
}

async fn attach(
    adapter: &LifecycleTestAdapter,
    owner: &AuthenticatedPrincipal,
    token: String,
    events: AcceptEvents,
) -> ConnectionId {
    let connection_id = ConnectionId::new();
    adapter.prepare_inbound(connection_id.clone(), owner, token, events);
    adapter
        .announce_inbound(connection_id.clone(), owner.clone())
        .await;
    connection_id
}

async fn activate_inbound_call(
    runtime: &CallServiceRuntime,
    sip: &LifecycleTestAdapter,
    webrtc: &LifecycleTestAdapter,
    idempotency: &str,
) -> (CreatedInboundCall, ConnectionId, ConnectionId) {
    let created = create_inbound_call(runtime, idempotency).await;
    let owner = principal().authenticated().clone();
    let sip_id = attach(
        sip,
        &owner,
        created.sip_token.clone(),
        AcceptEvents::Connected,
    )
    .await;
    let webrtc_id = attach(
        webrtc,
        &owner,
        created.webrtc_token.clone(),
        AcceptEvents::Connected,
    )
    .await;
    wait_for_call(runtime, created.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;
    (created, sip_id, webrtc_id)
}

async fn wait_for_transfer_submission(
    adapter: &LifecycleTestAdapter,
) -> (ConnectionId, TransferAttemptId, TransferTarget) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some((connection_id, Some(attempt_id), target)) = adapter.last_transfer() {
                return (connection_id, attempt_id, target);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("correlated transfer was submitted")
}

async fn wait_for_call<F>(
    runtime: &CallServiceRuntime,
    call_id: CallId,
    predicate: F,
) -> bridgefu::call_service::StoredServiceCall
where
    F: Fn(&bridgefu::call_service::StoredServiceCall) -> bool,
{
    let tenant = TenantId::parse("execution-tenant").unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let stored = runtime
                .service_repository()
                .load_service_call(&tenant, call_id)
                .await
                .unwrap();
            if predicate(&stored) {
                return stored;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    match result {
        Ok(stored) => stored,
        Err(_) => {
            let stored = runtime
                .service_repository()
                .load_service_call(&tenant, call_id)
                .await
                .unwrap();
            panic!(
                "call did not reach the expected durable state: aggregate={:?}, bindings={:?}",
                stored.call.aggregate, stored.call.bindings,
            );
        }
    }
}

async fn wait_for_accepted(adapter: &LifecycleTestAdapter, connection_id: &ConnectionId) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !adapter.admission_was_accepted(connection_id) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("inbound connection was durably accepted");
}

fn active_bridge_count(orchestrator: &Orchestrator) -> u64 {
    match orchestrator.capacity_report() {
        Event::CapacityReport { active_bridges, .. } => active_bridges,
        _ => unreachable!("capacity_report always returns a capacity event"),
    }
}

async fn wait_for_active_bridge_count(orchestrator: &Orchestrator, expected: u64) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while active_bridge_count(orchestrator) != expected {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "active bridge count did not converge: expected {expected}, observed {}",
            active_bridge_count(orchestrator)
        )
    });
}

async fn receive_media(output: &mut mpsc::Receiver<MediaFrame>) -> MediaFrame {
    tokio::time::timeout(Duration::from_secs(5), output.recv())
        .await
        .expect("bridged media was not delivered before the deadline")
        .expect("bridged media output closed before delivery")
}

async fn wait_for_source_shutdown(stream: &TestMediaStream, frame: MediaFrame) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if stream.inject(frame.clone()).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("connection teardown retained the MediaGraph source receiver");
}

async fn stop_harness(supervisor: CallExecutionSupervisor, orchestrator: Arc<Orchestrator>) {
    supervisor.shutdown(Duration::from_secs(2)).await;
    orchestrator.drain_prepared_outbound_connections().await;
    orchestrator.drain_connection_lifecycle_tasks().await;
}

async fn wait_for_rejection_count(adapter: &LifecycleTestAdapter, expected: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while adapter.counts.reject.load(Ordering::SeqCst) < expected {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("canary admission rejection was not delivered");
}

async fn build_reference_tenant_canary_runtime(
    backend: CallRepositoryBackendConfig,
    worker_id: WorkerId,
) -> Arc<CallServiceRuntime> {
    let mut config = runtime_config(backend, worker_id);
    config.max_calls = 2;
    config.worker_capabilities = BTreeSet::from(["sip".into(), "amazon_connect".into()]);
    Arc::new(
        build_call_service_runtime(
            config,
            Arc::new(SamePrincipalAttachmentResolver),
            Arc::new(SystemCallServiceClock),
        )
        .await
        .unwrap(),
    )
}

fn build_reference_tenant_canary_amazon() -> (
    Arc<CanaryConnectStarter>,
    Arc<CanaryConnectMediaSession>,
    Arc<AmazonConnectAdapter>,
) {
    let starter = Arc::new(CanaryConnectStarter::default());
    let media = CanaryConnectMediaSession::new();
    let starter_trait: Arc<dyn ConnectContactStarter> = starter.clone();
    let connector: Arc<dyn ConnectMediaConnector> = Arc::new(CanaryConnectMediaConnector {
        session: Arc::clone(&media),
    });
    let mut builder = AmazonConnectAdapter::builder(
        ConnectConfig::new(
            "unused-legacy-reference-tenant-instance",
            "unused-legacy-reference-tenant-flow",
        ),
        Arc::clone(&starter_trait),
    )
    .with_media_connector(connector);
    builder
        .register_profile(
            ConnectProfileId::new("recipe-execution-tenant-amazon").unwrap(),
            starter_trait,
        )
        .unwrap();
    let adapter = builder.build();
    (starter, media, adapter)
}

#[tokio::test]
async fn stable_recipe_uri_uses_named_route_context_media_and_exact_cleanup() {
    let owner = stable_recipe_principal();
    let runtime = build_stable_recipe_runtime(owner.clone()).await;
    let catalog = stable_recipe_catalog(owner.clone());
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let (starter, media, amazon) = build_reference_tenant_canary_amazon();
    let context_policy = ContextPolicy {
        allow_headers: BTreeMap::from([("X-Correlation-Id".into(), "correlation_id".into())]),
        allow_metadata_keys: BTreeSet::new(),
    };
    let supervisor = CallExecutionSupervisor::install_with_leg_executors_context_canary_recipe_broadcast_profiles_and_private_egress(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        Arc::new(DisabledProviderLegExecutor),
        Some(Arc::clone(&amazon)),
        Arc::new(context_policy),
        None,
        Some(Arc::clone(&catalog)),
        None,
        Arc::new(DisabledOutboundProfileResolver),
        None,
        8,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let sip = LifecycleTestAdapter::new(Transport::Sip);
    orchestrator
        .register(Arc::clone(&sip) as Arc<dyn ConnectionAdapter>)
        .unwrap();
    orchestrator
        .register(Arc::clone(&amazon) as Arc<dyn ConnectionAdapter>)
        .unwrap();

    let connection_id = ConnectionId::new();
    let metadata = vec![("X-Correlation-Id".into(), "bf1_stable-context-77".into())];
    // Observe the deterministic durable call ID without exposing the bearer
    // to the signaling fixture. The supervisor replays this exact operation
    // from the fixed URI and consumes the internal proof itself.
    let observed = catalog
        .admit(
            &owner,
            "stable-support",
            &metadata,
            &connection_id,
            runtime.as_ref(),
        )
        .await
        .unwrap();
    let RecipeSipAdmissionDecision::Attachment(observed) = observed else {
        panic!("configured stable URI must create a durable named-route call")
    };
    let call_id = observed.call_id();
    drop(observed);

    let sip_stream = sip.prepare_inbound_with_codec_and_metadata(
        connection_id.clone(),
        &owner,
        "stable-support".into(),
        AcceptEvents::Connected,
        codec("pcmu", 8_000, 1),
        InboundSignalingMetadata::new(metadata.clone()).unwrap(),
    );
    let mut sip_output = sip_stream.take_output();
    let mut amazon_output = media.stream.take_output();
    sip.announce_inbound(connection_id.clone(), owner.clone())
        .await;
    wait_for_accepted(&sip, &connection_id).await;
    let active = wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;
    let route = active.plan.named_route().expect("durable recipe route");
    assert_eq!(route.route_id(), "stable-support");
    assert_eq!(route.profiles().len(), 2);
    assert_eq!(
        route
            .context()
            .map(|context| context.correlation_id.as_str()),
        Some("bf1_stable-context-77")
    );
    assert_eq!(
        route.required_sip_correlation_header(),
        Some("X-Correlation-Id")
    );
    wait_for_active_bridge_count(&orchestrator, 1).await;

    {
        let starts = starter.starts.lock().unwrap();
        assert_eq!(starts.len(), 1);
        assert_eq!(starts[0].instance_id, "stable-recipe-instance");
        assert_eq!(starts[0].contact_flow_id, "stable-recipe-flow");
        assert_eq!(
            starts[0]
                .attributes
                .get("correlation_id")
                .map(String::as_str),
            Some("bf1_stable-context-77")
        );
        assert_eq!(
            starts[0]
                .attributes
                .get("bridgefu_recipe")
                .map(String::as_str),
            Some("stable-test")
        );
    }

    let pcmu = vec![0xff; 160];
    sip_stream
        .inject(sip_stream.frame(pcmu.clone(), 80_000, 0))
        .await
        .unwrap();
    let opus = receive_media(&mut amazon_output).await;
    assert_eq!(opus.payload_type, Some(111));
    media.stream.inject(opus).await.unwrap();
    assert_eq!(receive_media(&mut sip_output).await.payload_type, Some(0));

    // Duplicate correlation headers fail before a second route call can be
    // reserved or an Amazon contact can be started.
    let duplicate_connection = ConnectionId::new();
    let duplicate_metadata: Vec<(String, String)> = vec![
        ("X-Correlation-Id".into(), "bf1_stable-context-78".into()),
        ("x-correlation-id".into(), "bf1_stable-context-78".into()),
    ];
    sip.prepare_inbound_with_codec_and_metadata(
        duplicate_connection.clone(),
        &owner,
        "stable-support".into(),
        AcceptEvents::Connected,
        codec("pcmu", 8_000, 1),
        InboundSignalingMetadata::new(duplicate_metadata).unwrap(),
    );
    sip.announce_inbound(duplicate_connection.clone(), owner)
        .await;
    wait_for_rejection_count(&sip, 1).await;
    assert!(!sip.route_is_live(&duplicate_connection));
    assert_eq!(starter.starts.lock().unwrap().len(), 1);

    sip.remote_end(connection_id).await;
    wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    media.wait_closed().await;
    wait_for_active_bridge_count(&orchestrator, 0).await;
    wait_for_source_shutdown(&sip_stream, sip_stream.frame(pcmu, 80_160, 0)).await;
    assert_eq!(starter.stops.lock().unwrap().len(), 1);
    assert_eq!(media.closes.load(Ordering::Acquire), 1);
    assert_eq!(amazon.metrics().active_sessions, 0);
    assert_eq!(amazon.pending_cleanup_count(), 0);

    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn reference_tenant_canary_replays_into_generic_engine_bridges_media_and_drains() {
    let runtime =
        build_reference_tenant_canary_runtime(CallRepositoryBackendConfig::Memory, WorkerId::new())
            .await;
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let policy = reference_tenant_canary_policy();
    let (starter, media, amazon) = build_reference_tenant_canary_amazon();
    let supervisor = CallExecutionSupervisor::install_with_leg_executors_context_and_canary_policy(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        Arc::new(DisabledProviderLegExecutor),
        Some(Arc::clone(&amazon)),
        Arc::new(ContextPolicy::default()),
        Some(Arc::clone(&policy)),
        8,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let sip = LifecycleTestAdapter::new(Transport::Sip);
    orchestrator
        .register(Arc::clone(&sip) as Arc<dyn ConnectionAdapter>)
        .unwrap();
    orchestrator
        .register(Arc::clone(&amazon) as Arc<dyn ConnectionAdapter>)
        .unwrap();

    let owner = principal().authenticated().clone();
    let metadata = reference_tenant_canary_metadata("+14155550199");
    // Observe the durable authority without handing its bearer to the SIP
    // fixture. The actual inbound route below supplies only `sip:<tenant>` and
    // the allowlisted Vapi headers, forcing the listener path to replay the
    // exact decision and derive/consume the bearer internally.
    let observed = policy
        .admit(&owner, "execution-tenant", &metadata, runtime.as_ref())
        .await
        .unwrap();
    let ReferenceTenantCanaryDecision::Attachment(observed) = observed else {
        panic!("configured canary route must create a durable call")
    };
    let call_id = observed.call_id();
    drop(observed);

    let sip_connection = ConnectionId::new();
    let sip_stream = sip.prepare_inbound_with_codec_and_metadata(
        sip_connection.clone(),
        &owner,
        "execution-tenant".into(),
        AcceptEvents::Connected,
        codec("pcmu", 8_000, 1),
        InboundSignalingMetadata::new(metadata.clone()).unwrap(),
    );
    let mut sip_output = sip_stream.take_output();
    let mut amazon_output = media.stream.take_output();
    sip.announce_inbound(sip_connection.clone(), owner.clone())
        .await;
    wait_for_accepted(&sip, &sip_connection).await;
    let active = wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;
    assert_eq!(active.plan.legs.len(), 2);
    wait_for_active_bridge_count(&orchestrator, 1).await;
    assert_eq!(sip_stream.source_receiver_acquisitions(), 1);
    assert_eq!(media.stream.source_receiver_acquisitions(), 1);

    {
        let starts = starter.starts.lock().unwrap();
        assert_eq!(starts.len(), 1, "exact replay starts one Connect contact");
        let request = &starts[0];
        assert_eq!(request.instance_id, "reference-tenant-canary-instance");
        assert_eq!(request.contact_flow_id, "reference-tenant-canary-flow");
        assert_eq!(
            request.attributes.get("correlation_id").map(String::as_str),
            Some("+14155550199")
        );
        assert_eq!(
            request
                .attributes
                .get("HostedWidget-vapiCallId")
                .map(String::as_str),
            Some("vapi-call-canary-77")
        );
        assert_eq!(request.attributes.len(), 2);
        assert!(request
            .attributes
            .values()
            .all(|value| value != "private-unallowlisted-value"));
        assert!(request.client_token.is_some());
    }

    let pcmu = vec![0xff; 160];
    sip_stream
        .inject(sip_stream.frame(pcmu.clone(), 80_000, 0))
        .await
        .unwrap();
    sip_stream
        .inject(sip_stream.frame(pcmu.clone(), 80_160, 0))
        .await
        .unwrap();
    let opus_first = receive_media(&mut amazon_output).await;
    let opus_second = receive_media(&mut amazon_output).await;
    assert_eq!(opus_first.payload_type, Some(111));
    assert_eq!(
        opus_second
            .timestamp_rtp
            .wrapping_sub(opus_first.timestamp_rtp),
        960
    );
    assert!(!opus_first.payload.is_empty());

    media.stream.inject(opus_first).await.unwrap();
    media.stream.inject(opus_second).await.unwrap();
    let pcmu_first = receive_media(&mut sip_output).await;
    let pcmu_second = receive_media(&mut sip_output).await;
    assert_eq!(pcmu_first.payload_type, Some(0));
    assert_eq!(
        pcmu_second
            .timestamp_rtp
            .wrapping_sub(pcmu_first.timestamp_rtp),
        160
    );
    assert_eq!(pcmu_first.payload.len(), 160);

    // An exact replay cannot reuse the already-consumed attachment, changed
    // mapped metadata conflicts with the durable idempotency transcript, and
    // a foreign tenant cannot enter the canary at all.
    let replay_connection = ConnectionId::new();
    sip.prepare_inbound_with_codec_and_metadata(
        replay_connection.clone(),
        &owner,
        "execution-tenant".into(),
        AcceptEvents::Connected,
        codec("pcmu", 8_000, 1),
        InboundSignalingMetadata::new(metadata.clone()).unwrap(),
    );
    sip.announce_inbound(replay_connection.clone(), owner.clone())
        .await;
    wait_for_rejection_count(&sip, 1).await;
    assert!(!sip.route_is_live(&replay_connection));

    let mut changed_metadata = metadata.clone();
    changed_metadata[1].1 = "different-vapi-call".into();
    let changed_connection = ConnectionId::new();
    sip.prepare_inbound_with_codec_and_metadata(
        changed_connection.clone(),
        &owner,
        "execution-tenant".into(),
        AcceptEvents::Connected,
        codec("pcmu", 8_000, 1),
        InboundSignalingMetadata::new(changed_metadata).unwrap(),
    );
    sip.announce_inbound(changed_connection.clone(), owner.clone())
        .await;
    wait_for_rejection_count(&sip, 2).await;
    assert!(!sip.route_is_live(&changed_connection));

    let mut foreign = owner;
    foreign.tenant = Some("foreign-tenant".into());
    let foreign_connection = ConnectionId::new();
    sip.prepare_inbound_with_codec_and_metadata(
        foreign_connection.clone(),
        &foreign,
        "execution-tenant".into(),
        AcceptEvents::Connected,
        codec("pcmu", 8_000, 1),
        InboundSignalingMetadata::new(metadata).unwrap(),
    );
    sip.announce_inbound(foreign_connection.clone(), foreign)
        .await;
    wait_for_rejection_count(&sip, 3).await;
    assert!(!sip.route_is_live(&foreign_connection));
    assert_eq!(starter.starts.lock().unwrap().len(), 1);

    sip.remote_end(sip_connection).await;
    wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    media.wait_closed().await;
    wait_for_active_bridge_count(&orchestrator, 0).await;
    wait_for_source_shutdown(&sip_stream, sip_stream.frame(pcmu, 80_320, 0)).await;
    assert_eq!(starter.stops.lock().unwrap().len(), 1);
    assert_eq!(media.closes.load(Ordering::Acquire), 1);
    assert_eq!(media.aborts.load(Ordering::Acquire), 0);
    assert_eq!(amazon.metrics().active_sessions, 0);
    assert_eq!(amazon.pending_cleanup_count(), 0);

    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_reference_tenant_canary_crosses_real_sip_rtp_and_drains_exactly() {
    let runtime =
        build_reference_tenant_canary_runtime(CallRepositoryBackendConfig::Memory, WorkerId::new())
            .await;
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let policy = reference_tenant_canary_policy();
    let (starter, media, amazon) = build_reference_tenant_canary_amazon();
    let supervisor = CallExecutionSupervisor::install_with_leg_executors_context_and_canary_policy(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        Arc::new(DisabledProviderLegExecutor),
        Some(Arc::clone(&amazon)),
        Arc::new(ContextPolicy::default()),
        Some(Arc::clone(&policy)),
        8,
        Duration::from_secs(5),
    )
    .await
    .unwrap();

    let reservation =
        std::net::UdpSocket::bind("127.0.0.1:0").expect("reserve canary SIP listener");
    let sip_address = reservation.local_addr().expect("reserved listener address");
    drop(reservation);
    let owner = principal().authenticated().clone();
    let listener_policy = SipListenerAuthPolicy::enabled_for_tenant("execution-tenant")
        .expect("tenant-bound authenticated listener")
        .with_trusted_cidr(
            "127.0.0.1/32".parse().expect("loopback Vapi source CIDR"),
            owner.clone(),
        );
    let mut listener_config =
        SipConfig::local("bridgefu-reference-tenant-canary-wire", sip_address.port());
    listener_config.offered_codecs = vec![0, 101];
    let sip_coordinator =
        UnifiedCoordinator::new_with_listener_auth(listener_config, listener_policy)
            .await
            .expect("start authenticated production SIP listener");
    let sip_adapter = SipAdapter::new_with_inbound_context_policy(
        Arc::clone(&sip_coordinator),
        SipInboundContextPolicy::new(["X-Correlation-Id", "X-Vapi-Call-Id"])
            .expect("safe Vapi inbound header allowlist"),
    )
    .await
    .expect("production SIP adapter");
    orchestrator
        .register(Arc::clone(&sip_adapter) as Arc<dyn ConnectionAdapter>)
        .expect("register production SIP adapter");
    orchestrator
        .register(Arc::clone(&amazon) as Arc<dyn ConnectionAdapter>)
        .expect("register fake-backed Amazon adapter");

    let caller_reservation =
        std::net::UdpSocket::bind("127.0.0.1:0").expect("reserve canary Vapi caller");
    let caller_address = caller_reservation
        .local_addr()
        .expect("reserved Vapi caller address");
    drop(caller_reservation);
    let mut caller_config = SipConfig::local(
        "bridgefu-reference-tenant-canary-vapi",
        caller_address.port(),
    );
    caller_config.offered_codecs = vec![0, 101];
    let caller = UnifiedCoordinator::new(caller_config)
        .await
        .expect("start production Vapi SIP peer");
    let correlation = "+14155550199-wire";
    let vapi_call_id = "vapi-call-canary-77";
    let caller_session = caller
        .invite(
            Some(format!("sip:trusted-vapi@{caller_address}")),
            format!("sip:execution-tenant@{sip_address}"),
        )
        .with_raw_header(HeaderName::Other("X-Correlation-Id".into()), correlation)
        .expect("stage canary correlation header")
        .with_raw_header(HeaderName::Other("X-Vapi-Call-Id".into()), vapi_call_id)
        .expect("stage canary Vapi call header")
        .with_raw_header(
            HeaderName::Other("X-Untrusted-Must-Not-Reach-Connect".into()),
            "private-unallowlisted-value",
        )
        .expect("stage intentionally untrusted application header")
        .send()
        .await
        .expect("authenticated canary INVITE accepted over real SIP");
    let caller_handle = caller.session(&caller_session);
    caller_handle
        .wait_for_answered(Some(Duration::from_secs(5)))
        .await
        .expect("authenticated canary SIP transaction answered");

    // The packet-path admission creates and consumes the durable attachment.
    // A policy replay is inspection-only here: it recovers the deterministic
    // call identifier while retaining the same already-consumed bearer.
    let observed = policy
        .admit(
            &owner,
            "execution-tenant",
            &reference_tenant_canary_metadata(correlation),
            runtime.as_ref(),
        )
        .await
        .expect("byte-equivalent canary decision replays durably");
    let ReferenceTenantCanaryDecision::Attachment(observed) = observed else {
        panic!("configured wire canary must resolve its durable call")
    };
    let call_id = observed.call_id();
    drop(observed);
    let active = wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;
    let sip_leg = active
        .call
        .aggregate
        .legs()
        .iter()
        .find(|leg| leg.kind() == bridgefu::call_engine::LegKind::Sip)
        .expect("durable SIP leg");
    let sip_connection = active
        .call
        .bindings
        .get(&sip_leg.id())
        .expect("exact production SIP binding")
        .connection_id
        .clone();
    wait_for_active_bridge_count(&orchestrator, 1).await;

    let sip_streams = sip_adapter
        .streams(sip_connection.clone())
        .await
        .expect("production SIP streams");
    let sip_audio = sip_streams
        .iter()
        .find(|stream| stream.kind() == StreamKind::Audio)
        .expect("negotiated SIP audio stream");
    assert_eq!(sip_audio.codec().name.to_ascii_lowercase(), "g.711-mu");
    assert_eq!(sip_audio.codec().clock_rate_hz, 8_000);

    {
        let starts = starter.starts.lock().unwrap();
        assert_eq!(starts.len(), 1, "one durable admission starts one contact");
        let request = &starts[0];
        assert_eq!(request.instance_id, "reference-tenant-canary-instance");
        assert_eq!(request.contact_flow_id, "reference-tenant-canary-flow");
        assert_eq!(
            request.attributes.get("correlation_id").map(String::as_str),
            Some(correlation)
        );
        assert_eq!(
            request
                .attributes
                .get("HostedWidget-vapiCallId")
                .map(String::as_str),
            Some(vapi_call_id)
        );
        assert_eq!(
            request.attributes.len(),
            2,
            "screen-pop metadata is allowlisted"
        );
        assert!(request.client_token.is_some());
    }

    let (caller_audio_tx, mut caller_audio_rx) = caller_handle
        .audio()
        .await
        .expect("Vapi-side real RTP audio stream")
        .split();
    let mut amazon_output = media.stream.take_output();
    for sequence in 0..12_u32 {
        caller_audio_tx
            .send(AudioFrame::new(vec![0_i16; 160], 8_000, 1, sequence * 160))
            .await
            .expect("send decoded audio through real PCMU RTP");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let opus_first = receive_media(&mut amazon_output).await;
    let opus_second = receive_media(&mut amazon_output).await;
    assert_eq!(opus_first.payload_type, Some(111));
    assert_eq!(media.stream.codec().name.to_ascii_lowercase(), "opus");
    assert_eq!(media.stream.codec().clock_rate_hz, 48_000);
    assert_eq!(
        opus_second
            .timestamp_rtp
            .wrapping_sub(opus_first.timestamp_rtp),
        960
    );

    media.stream.inject(opus_first).await.unwrap();
    media.stream.inject(opus_second).await.unwrap();
    let returned_pcmu = tokio::time::timeout(Duration::from_secs(5), caller_audio_rx.recv())
        .await
        .expect("Opus-to-PCMU RTP return deadline")
        .expect("Vapi-side audio remained live");
    assert_eq!(returned_pcmu.sample_rate, 8_000);
    assert_eq!(returned_pcmu.channels, 1);
    assert_eq!(returned_pcmu.samples.len(), 160);

    // A second INVITE with the exact correlation cannot reuse the consumed
    // bearer. Metadata drift and a route for another tenant fail before any
    // additional Connect or media I/O.
    assert_reference_tenant_wire_invite_rejected(
        &caller,
        caller_address,
        sip_address,
        "execution-tenant",
        correlation,
        vapi_call_id,
    )
    .await;
    assert_reference_tenant_wire_invite_rejected(
        &caller,
        caller_address,
        sip_address,
        "execution-tenant",
        correlation,
        "metadata-drift-must-fail",
    )
    .await;
    assert_reference_tenant_wire_invite_rejected(
        &caller,
        caller_address,
        sip_address,
        "foreign-tenant",
        "foreign-correlation",
        "foreign-vapi-call",
    )
    .await;
    assert_eq!(starter.starts.lock().unwrap().len(), 1);

    tokio::time::timeout(Duration::from_secs(5), caller.hangup(&caller_session))
        .await
        .expect("real SIP BYE deadline")
        .expect("real SIP BYE");
    wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    media.wait_closed().await;
    wait_for_active_bridge_count(&orchestrator, 0).await;
    assert_eq!(starter.stops.lock().unwrap().len(), 1);
    assert_eq!(media.closes.load(Ordering::Acquire), 1);
    assert_eq!(media.aborts.load(Ordering::Acquire), 0);
    assert_eq!(amazon.metrics().active_sessions, 0);
    assert_eq!(amazon.pending_cleanup_count(), 0);

    stop_harness(supervisor, Arc::clone(&orchestrator)).await;
    caller
        .shutdown_gracefully(Some(Duration::from_secs(2)))
        .await
        .expect("shutdown Vapi SIP peer");
    sip_adapter
        .drain()
        .await
        .expect("drain production SIP adapter");
    sip_coordinator
        .shutdown_gracefully(Some(Duration::from_secs(2)))
        .await
        .expect("shutdown authenticated production SIP listener");
    assert_eq!(sip_adapter.retained_task_count(), 0);
    assert_eq!(orchestrator.connection_lifecycle_task_count(), 0);
}

#[tokio::test]
async fn reference_tenant_canary_sqlite_restart_fails_closed_without_connect_io() {
    let path = std::env::temp_dir().join(format!(
        "bridgefu-reference-tenant-canary-crash-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let url = format!("sqlite://{}", path.display());
    let worker_id = WorkerId::from_str("00000000-0000-4000-8000-0000000000c7").unwrap();
    let policy = reference_tenant_canary_policy();
    let owner = principal().authenticated().clone();
    let metadata = reference_tenant_canary_metadata("crash-before-attachment");

    let first = build_reference_tenant_canary_runtime(
        CallRepositoryBackendConfig::Sqlite {
            database_url: url.clone(),
        },
        worker_id,
    )
    .await;
    let first_fence = first.worker().lease.fence;
    let created = policy
        .admit(&owner, "execution-tenant", &metadata, first.as_ref())
        .await
        .unwrap();
    let ReferenceTenantCanaryDecision::Attachment(created) = created else {
        panic!("configured canary route must persist before the crash barrier")
    };
    let call_id = created.call_id();
    drop(created);
    let first = Arc::into_inner(first).expect("first runtime has no external owners");
    first.shutdown(Duration::from_secs(2)).await.unwrap();

    let second = build_reference_tenant_canary_runtime(
        CallRepositoryBackendConfig::Sqlite {
            database_url: url.clone(),
        },
        worker_id,
    )
    .await;
    assert!(second.worker().lease.fence > first_fence);
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let (starter, _media, amazon) = build_reference_tenant_canary_amazon();
    let supervisor = CallExecutionSupervisor::install_with_leg_executors_context_and_canary_policy(
        Arc::clone(&orchestrator),
        Arc::clone(&second),
        Arc::new(DisabledProviderLegExecutor),
        Some(Arc::clone(&amazon)),
        Arc::new(ContextPolicy::default()),
        Some(Arc::clone(&policy)),
        8,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let sip = LifecycleTestAdapter::new(Transport::Sip);
    orchestrator
        .register(Arc::clone(&sip) as Arc<dyn ConnectionAdapter>)
        .unwrap();
    orchestrator
        .register(Arc::clone(&amazon) as Arc<dyn ConnectionAdapter>)
        .unwrap();

    let recovered = second
        .service_repository()
        .load_service_call(&TenantId::parse("execution-tenant").unwrap(), call_id)
        .await
        .unwrap();
    assert!(recovered.call.aggregate.state().is_terminal());
    assert!(recovered.call.aggregate.legs().iter().all(|leg| {
        leg.state().is_terminal()
            && leg.failure().map(|failure| failure.code()) == Some("worker_restarted")
    }));
    assert!(starter.starts.lock().unwrap().is_empty());
    assert!(starter.stops.lock().unwrap().is_empty());

    let replay_connection = ConnectionId::new();
    sip.prepare_inbound_with_codec_and_metadata(
        replay_connection.clone(),
        &owner,
        "execution-tenant".into(),
        AcceptEvents::Connected,
        codec("pcmu", 8_000, 1),
        InboundSignalingMetadata::new(metadata).unwrap(),
    );
    sip.announce_inbound(replay_connection.clone(), owner).await;
    wait_for_rejection_count(&sip, 1).await;
    assert!(!sip.route_is_live(&replay_connection));
    assert!(starter.starts.lock().unwrap().is_empty());
    assert!(starter.stops.lock().unwrap().is_empty());
    assert_eq!(amazon.metrics().active_sessions, 0);

    stop_harness(supervisor, orchestrator).await;
    drop(second);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn sip_transfer_waits_for_authoritative_progress_and_completion() {
    let (runtime, orchestrator, supervisor, sip, webrtc) = execution_harness(1).await;
    let (created, sip_id, _webrtc_id) = activate_inbound_call(
        &runtime,
        &sip,
        &webrtc,
        "execution-transfer-authoritative-completion",
    )
    .await;
    wait_for_active_bridge_count(&orchestrator, 1).await;

    let accepted = runtime
        .service()
        .transfer_call(
            &principal(),
            created.call_id,
            &IdempotencyKey::parse("execution-transfer-authoritative-completion-command").unwrap(),
            TransferCallInput {
                tenant_id: None,
                target_leg_id: created.sip_leg,
                target: ServiceTransferTarget::Sip {
                    uri: "sip:replacement@example.invalid".into(),
                },
            },
        )
        .await
        .unwrap();
    assert_eq!(accepted.value.state, CallState::Transferring);

    let (submitted_connection, attempt_id, target) = wait_for_transfer_submission(&sip).await;
    assert_eq!(submitted_connection, sip_id);
    assert!(matches!(
        target,
        TransferTarget::Uri(uri) if uri == "sip:replacement@example.invalid"
    ));
    let submitted = wait_for_call(&runtime, created.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Transferring
            && stored
                .call
                .aggregate
                .deadlines()
                .get(DeadlineKind::Transfer)
                .due_at()
                .is_some()
    })
    .await;
    assert_eq!(sip.counts.transfer.load(Ordering::SeqCst), 1);
    assert_eq!(
        submitted.call.bindings[&created.sip_leg].connection_id,
        sip_id
    );

    sip.emit_transfer_status(
        submitted_connection.clone(),
        Some(attempt_id.clone()),
        TransferStatus::Accepted,
    )
    .await;
    sip.emit_transfer_status(
        submitted_connection.clone(),
        Some(attempt_id.clone()),
        TransferStatus::Progress {
            status_code: 180,
            reason: "Ringing".into(),
        },
    )
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let progressing = runtime
        .service_repository()
        .load_service_call(
            &TenantId::parse("execution-tenant").unwrap(),
            created.call_id,
        )
        .await
        .unwrap();
    assert_eq!(progressing.call.aggregate.state(), CallState::Transferring);
    assert!(progressing
        .call
        .aggregate
        .deadlines()
        .get(DeadlineKind::Transfer)
        .due_at()
        .is_some());
    assert_eq!(active_bridge_count(&orchestrator), 1);

    sip.emit_transfer_status(
        submitted_connection,
        Some(attempt_id.clone()),
        TransferStatus::Completed {
            status_code: 200,
            reason: "OK".into(),
        },
    )
    .await;
    let completed = wait_for_call(&runtime, created.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
            && stored
                .call
                .aggregate
                .deadlines()
                .get(DeadlineKind::Transfer)
                .due_at()
                .is_none()
    })
    .await;
    assert_eq!(completed.call.aggregate.state(), CallState::Active);
    assert_eq!(active_bridge_count(&orchestrator), 1);

    sip.emit_transfer_status(
        sip_id.clone(),
        Some(attempt_id),
        TransferStatus::Completed {
            status_code: 200,
            reason: "duplicate".into(),
        },
    )
    .await;
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(
        runtime
            .service_repository()
            .load_service_call(
                &TenantId::parse("execution-tenant").unwrap(),
                created.call_id,
            )
            .await
            .unwrap()
            .call
            .aggregate
            .state(),
        CallState::Active
    );

    sip.remote_end(sip_id).await;
    wait_for_call(&runtime, created.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    wait_for_active_bridge_count(&orchestrator, 0).await;
    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn sip_transfer_terminal_status_can_arrive_before_submission_ack() {
    let (runtime, orchestrator, supervisor, sip, webrtc) = execution_harness(1).await;
    let (created, sip_id, _webrtc_id) = activate_inbound_call(
        &runtime,
        &sip,
        &webrtc,
        "execution-transfer-terminal-before-ack",
    )
    .await;
    sip.transfer_status_during_submission(vec![TransferStatus::Completed {
        status_code: 200,
        reason: "OK".into(),
    }]);

    let accepted = runtime
        .service()
        .transfer_call(
            &principal(),
            created.call_id,
            &IdempotencyKey::parse("execution-transfer-terminal-before-ack-command").unwrap(),
            TransferCallInput {
                tenant_id: None,
                target_leg_id: created.sip_leg,
                target: ServiceTransferTarget::Sip {
                    uri: "sip:early-result@example.invalid".into(),
                },
            },
        )
        .await
        .unwrap();
    assert_eq!(accepted.value.state, CallState::Transferring);
    let (submitted_connection, attempt_id, _) = wait_for_transfer_submission(&sip).await;
    assert_eq!(submitted_connection, sip_id);
    assert!(!attempt_id.as_str().is_empty());

    let completed = wait_for_call(&runtime, created.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
            && stored
                .call
                .aggregate
                .deadlines()
                .get(DeadlineKind::Transfer)
                .due_at()
                .is_none()
    })
    .await;
    assert_eq!(completed.call.aggregate.state(), CallState::Active);
    assert_eq!(sip.counts.transfer.load(Ordering::SeqCst), 1);

    sip.remote_end(sip_id).await;
    wait_for_call(&runtime, created.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    wait_for_active_bridge_count(&orchestrator, 0).await;
    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn sip_transfer_rejects_stale_missing_and_cross_leg_status_before_exact_failure() {
    let (runtime, orchestrator, supervisor, sip, webrtc) = execution_harness(1).await;
    let (created, sip_id, webrtc_id) =
        activate_inbound_call(&runtime, &sip, &webrtc, "execution-transfer-stale-status").await;
    runtime
        .service()
        .transfer_call(
            &principal(),
            created.call_id,
            &IdempotencyKey::parse("execution-transfer-stale-status-command").unwrap(),
            TransferCallInput {
                tenant_id: None,
                target_leg_id: created.sip_leg,
                target: ServiceTransferTarget::Sip {
                    uri: "sip:failure@example.invalid".into(),
                },
            },
        )
        .await
        .unwrap();
    let (_, attempt_id, _) = wait_for_transfer_submission(&sip).await;

    sip.emit_transfer_status(
        sip_id.clone(),
        None,
        TransferStatus::Completed {
            status_code: 200,
            reason: "missing correlation".into(),
        },
    )
    .await;
    sip.emit_transfer_status(
        sip_id.clone(),
        Some(TransferAttemptId::new()),
        TransferStatus::Completed {
            status_code: 200,
            reason: "stale generation".into(),
        },
    )
    .await;
    webrtc
        .emit_transfer_status(
            webrtc_id,
            Some(attempt_id.clone()),
            TransferStatus::Completed {
                status_code: 200,
                reason: "wrong leg".into(),
            },
        )
        .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let still_transferring = runtime
        .service_repository()
        .load_service_call(
            &TenantId::parse("execution-tenant").unwrap(),
            created.call_id,
        )
        .await
        .unwrap();
    assert_eq!(
        still_transferring.call.aggregate.state(),
        CallState::Transferring
    );
    assert!(still_transferring
        .call
        .aggregate
        .deadlines()
        .get(DeadlineKind::Transfer)
        .due_at()
        .is_some());

    sip.emit_transfer_status(
        sip_id.clone(),
        Some(attempt_id.clone()),
        TransferStatus::Failed {
            status_code: 503,
            reason: "Service Unavailable".into(),
        },
    )
    .await;
    let rejected = wait_for_call(&runtime, created.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
            && stored
                .call
                .aggregate
                .deadlines()
                .get(DeadlineKind::Transfer)
                .due_at()
                .is_none()
    })
    .await;
    assert_eq!(rejected.call.aggregate.state(), CallState::Active);
    assert_eq!(active_bridge_count(&orchestrator), 1);

    sip.emit_transfer_status(
        sip_id.clone(),
        Some(attempt_id),
        TransferStatus::Completed {
            status_code: 200,
            reason: "late success".into(),
        },
    )
    .await;
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(
        runtime
            .service_repository()
            .load_service_call(
                &TenantId::parse("execution-tenant").unwrap(),
                created.call_id,
            )
            .await
            .unwrap()
            .call
            .aggregate
            .state(),
        CallState::Active
    );

    sip.remote_end(sip_id).await;
    wait_for_call(&runtime, created.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    wait_for_active_bridge_count(&orchestrator, 0).await;
    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn begin_drain_retains_authoritative_operational_receiver() {
    let worker_id = WorkerId::new();
    let runtime = runtime(CallRepositoryBackendConfig::Memory, worker_id).await;
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let supervisor = CallExecutionSupervisor::install(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        8,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(
        orchestrator.operational_event_stream_health(),
        OperationalEventStreamHealth::Healthy
    );

    supervisor.begin_drain();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        orchestrator.operational_event_stream_health(),
        OperationalEventStreamHealth::Healthy,
        "draining admission must not drop the correctness receiver"
    );

    supervisor.shutdown(Duration::from_secs(2)).await;
    drop(orchestrator);
    drop(runtime);
}

#[tokio::test]
async fn startup_recovery_finishes_old_fence_and_cleanup_before_returning() {
    let path = std::env::temp_dir().join(format!(
        "bridgefu-execution-supervisor-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let url = format!("sqlite://{}", path.display());
    let worker_id = WorkerId::from_str("00000000-0000-4000-8000-0000000000e6").unwrap();
    let first = runtime(
        CallRepositoryBackendConfig::Sqlite {
            database_url: url.clone(),
        },
        worker_id,
    )
    .await;
    let created = first
        .service()
        .create_call(
            &principal(),
            &IdempotencyKey::parse("execution-startup-recovery").unwrap(),
            two_inbound_legs(),
        )
        .await
        .unwrap();
    let call_id = created.value.call.call_id;
    let bound_leg_id = created.value.call.legs[0].leg_id;
    let attachment = created.value.call.legs[0].attachment.as_ref().unwrap();
    let bound_connection_id = ConnectionId::new();
    first
        .service()
        .consume_inbound_attachment(InboundAttachmentRequest::new(
            principal().authenticated().clone(),
            Some(attachment.token.clone()),
            attachment.transport,
            first.worker().lease,
            bound_connection_id.clone(),
        ))
        .await
        .unwrap();
    let tenant = TenantId::parse("execution-tenant").unwrap();
    let before_restart = first
        .service_repository()
        .load_service_call(&tenant, call_id)
        .await
        .unwrap();
    assert_eq!(
        before_restart
            .call
            .bindings
            .get(&bound_leg_id)
            .unwrap()
            .connection_id,
        bound_connection_id
    );
    assert_eq!(
        before_restart
            .call
            .aggregate
            .leg(bound_leg_id)
            .unwrap()
            .state(),
        LegState::Signaling
    );
    let first_fence = first.worker().lease.fence;
    drop(first);

    let second = runtime(
        CallRepositoryBackendConfig::Sqlite { database_url: url },
        worker_id,
    )
    .await;
    assert!(second.worker().lease.fence > first_fence);
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let supervisor = CallExecutionSupervisor::install(
        Arc::clone(&orchestrator),
        Arc::clone(&second),
        8,
        Duration::from_secs(5),
    )
    .await
    .unwrap();

    let recovered = second
        .service_repository()
        .load_service_call(&tenant, call_id)
        .await
        .unwrap();
    assert!(matches!(
        recovered.call.aggregate.state(),
        CallState::Ended | CallState::Failed
    ));
    let recovered_bound_leg = recovered.call.aggregate.leg(bound_leg_id).unwrap();
    assert_eq!(recovered_bound_leg.state(), LegState::Failed);
    assert_eq!(
        recovered_bound_leg.failure().map(|failure| failure.code()),
        Some("worker_restarted")
    );
    assert!(second
        .repository()
        .claim_outbox(
            second.worker().lease,
            Utc::now(),
            Duration::from_secs(60),
            64,
        )
        .await
        .unwrap()
        .is_empty());

    supervisor.shutdown(Duration::from_secs(2)).await;
    drop(orchestrator);
    drop(second);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn outbound_sip_binds_registers_and_persists_call_id_before_activation_completes() {
    let (runtime, orchestrator, supervisor, sip, _webrtc) = execution_harness(1).await;
    let activation_count = sip.counts.activate.load(Ordering::SeqCst);
    let gate = sip.gate_activation();
    let created = create_outbound_web_rtc_call(
        &runtime,
        "execution-outbound-sip",
        LegEndpointConfig::Sip(SipEndpointConfig {
            uri: Some("sips:callee@voice.example.test;transport=tls".into()),
            initial_context: SipInitialContextMode::None,
        }),
    )
    .await;

    tokio::time::timeout(Duration::from_secs(5), gate.0.wait())
        .await
        .expect("outbound SIP activation did not reach its peer-visible boundary");
    let bound = wait_for_call(&runtime, created.call_id, |stored| {
        stored.call.bindings.contains_key(&created.leg_id)
            && stored
                .call
                .aggregate
                .leg(created.leg_id)
                .is_some_and(|leg| leg.state() == LegState::Signaling)
    })
    .await;
    let binding = bound.call.bindings.get(&created.leg_id).unwrap();
    assert_eq!(binding.transport, AttachmentTransport::Sip);
    assert_eq!(binding.binding_generation.value(), 1);
    assert!(sip.route_is_live(&binding.connection_id));
    assert_eq!(
        sip.counts.activate.load(Ordering::SeqCst),
        activation_count + 1,
        "durable bind and actor registration must precede SIP INVITE activation"
    );
    let originate_context = sip.last_sip_originate_context();
    assert!(originate_context.initial_headers().is_empty());
    originate_context.validate().unwrap();

    gate.1.wait().await;
    let connected = wait_for_call(&runtime, created.call_id, |stored| {
        stored
            .call
            .aggregate
            .leg(created.leg_id)
            .is_some_and(|leg| leg.state() == LegState::Connected)
    })
    .await;
    assert_eq!(
        connected.call.bindings[&created.leg_id].connection_id,
        binding.connection_id
    );
    let reference = runtime
        .service_repository()
        .load_external_reference_by_role(
            &TenantId::parse("execution-tenant").unwrap(),
            created.call_id,
            created.leg_id,
            ProviderReferenceRole::Media,
        )
        .await
        .unwrap()
        .expect("SIP Call-ID reference was not retained");
    assert_eq!(reference.binding_generation.value(), 1);
    assert!(matches!(
        reference.value,
        ExternalReferenceValue::Signaling { ref namespace, .. }
            if namespace == "sip.call-id"
    ));

    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn named_route_consumes_ingress_before_dial_and_answers_only_after_destination_connects() {
    let (runtime, orchestrator, supervisor, sip, webrtc) = execution_harness(1).await;
    let originated_before = webrtc.counts.originate.load(Ordering::SeqCst);
    let activated_before = webrtc.counts.activate.load(Ordering::SeqCst);
    let accepted_before = sip.counts.accept.load(Ordering::SeqCst);
    let created = runtime
        .service()
        .create_named_route_call(
            &principal(),
            &IdempotencyKey::parse("execution-named-route-attach-then-dial").unwrap(),
            inbound_sip_outbound_web_rtc(LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                signaling_uri: Some("wss://agent.example.test/session".into()),
            })),
            NamedRouteBinding::new("agent-wss", None).unwrap(),
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
    let source_token = source.attachment.as_ref().unwrap().token.clone();
    let destination_leg_id = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Outbound)
        .unwrap()
        .leg_id;

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        webrtc.counts.originate.load(Ordering::SeqCst),
        originated_before,
        "a named route must not allocate its destination before ingress attachment"
    );
    assert_eq!(
        webrtc.counts.activate.load(Ordering::SeqCst),
        activated_before,
        "a named route must not expose destination signaling before ingress attachment"
    );

    let destination_gate = webrtc.gate_activation();
    let source_connection_id = ConnectionId::new();
    let owner = principal().authenticated().clone();
    sip.prepare_inbound(
        source_connection_id.clone(),
        &owner,
        source_token,
        AcceptEvents::Connected,
    );
    let source_accept_gate = sip.gate_accept(&source_connection_id);
    sip.announce_inbound(source_connection_id.clone(), owner)
        .await;

    tokio::time::timeout(Duration::from_secs(5), destination_gate.0.wait())
        .await
        .expect("consumed named-route ingress did not release destination setup");
    assert_eq!(
        sip.counts.accept.load(Ordering::SeqCst),
        accepted_before,
        "the source must remain provisionally unanswered while destination setup is pending"
    );
    assert!(!sip.admission_was_accepted(&source_connection_id));
    let during_setup = wait_for_call(&runtime, call_id, |stored| {
        stored
            .call
            .aggregate
            .leg(destination_leg_id)
            .is_some_and(|leg| leg.state() == LegState::Signaling)
    })
    .await;
    assert_eq!(
        during_setup
            .call
            .aggregate
            .leg(source_leg_id)
            .unwrap()
            .state(),
        LegState::Signaling
    );

    destination_gate.1.wait().await;
    tokio::time::timeout(Duration::from_secs(5), source_accept_gate.0.wait())
        .await
        .expect("connected destination did not release the inbound final answer");
    assert!(sip.admission_was_accepted(&source_connection_id));
    assert_eq!(
        webrtc.counts.activate.load(Ordering::SeqCst),
        activated_before + 1
    );
    source_accept_gate.1.wait().await;

    let active = wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;
    assert_eq!(
        active.call.aggregate.leg(source_leg_id).unwrap().state(),
        LegState::Connected
    );
    assert_eq!(
        active
            .call
            .aggregate
            .leg(destination_leg_id)
            .unwrap()
            .state(),
        LegState::Connected
    );

    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn named_route_destination_failure_rejects_ingress_without_final_answer() {
    let (runtime, orchestrator, supervisor, sip, webrtc) = execution_harness(1).await;
    webrtc.fail_activation.store(true, Ordering::SeqCst);
    let rejected_before = sip.counts.reject.load(Ordering::SeqCst);
    let created = runtime
        .service()
        .create_named_route_call(
            &principal(),
            &IdempotencyKey::parse("execution-named-route-destination-failure").unwrap(),
            inbound_sip_outbound_web_rtc(LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                signaling_uri: Some("wss://failure.example.test/session".into()),
            })),
            NamedRouteBinding::new("failure-wss", None).unwrap(),
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
    let source_connection_id = ConnectionId::new();
    let owner = principal().authenticated().clone();
    sip.prepare_inbound(
        source_connection_id.clone(),
        &owner,
        source.attachment.as_ref().unwrap().token.clone(),
        AcceptEvents::Connected,
    );
    sip.announce_inbound(source_connection_id.clone(), owner)
        .await;

    let failed = wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    wait_for_rejection_count(&sip, rejected_before + 1).await;
    assert!(!sip.admission_was_accepted(&source_connection_id));
    assert!(failed
        .call
        .aggregate
        .legs()
        .iter()
        .any(|leg| leg.failure().is_some_and(|failure| {
            matches!(
                failure.code(),
                "webrtc_start_failed" | "webrtc_start_timeout"
            )
        })));

    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn named_route_source_hangup_cancels_destination_while_dialing() {
    let (runtime, orchestrator, supervisor, sip, webrtc) = execution_harness(1).await;
    let destination_gate = webrtc.gate_activation();
    let created = runtime
        .service()
        .create_named_route_call(
            &principal(),
            &IdempotencyKey::parse("execution-named-route-source-cancel").unwrap(),
            inbound_sip_outbound_web_rtc(LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                signaling_uri: Some("wss://slow-agent.example.test/session".into()),
            })),
            NamedRouteBinding::new("slow-agent-wss", None).unwrap(),
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
    let destination_leg_id = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Outbound)
        .unwrap()
        .leg_id;
    let source_connection_id = ConnectionId::new();
    let owner = principal().authenticated().clone();
    sip.prepare_inbound(
        source_connection_id.clone(),
        &owner,
        source.attachment.as_ref().unwrap().token.clone(),
        AcceptEvents::Connected,
    );
    sip.announce_inbound(source_connection_id.clone(), owner)
        .await;

    tokio::time::timeout(Duration::from_secs(5), destination_gate.0.wait())
        .await
        .expect("destination activation did not start");
    let dialing = wait_for_call(&runtime, call_id, |stored| {
        stored.call.bindings.contains_key(&destination_leg_id)
    })
    .await;
    let destination_connection_id = dialing.call.bindings[&destination_leg_id]
        .connection_id
        .clone();
    sip.remote_end(source_connection_id.clone()).await;
    wait_for_call(&runtime, call_id, |stored| {
        matches!(stored.call.aggregate.state(), CallState::Ending)
            || stored.call.aggregate.state().is_terminal()
    })
    .await;
    destination_gate.1.wait().await;
    wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while webrtc.route_is_live(&destination_connection_id) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("source hangup left the dialing destination route live");
    assert!(!sip.admission_was_accepted(&source_connection_id));

    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn named_route_source_hangup_during_initial_telnyx_start_retires_late_provider_call() {
    run_bounded_telnyx_replacement_test(async {
        let (runtime, orchestrator, supervisor, _sip, webrtc, provider) =
            telnyx_replacement_harness(Duration::from_secs(10)).await;
        provider.set_auto_attach(false);
        let start_gate = provider.gate_next_start();
        let created = runtime
            .service()
            .create_named_route_call(
                &principal(),
                &IdempotencyKey::parse("execution-initial-telnyx-source-cancel").unwrap(),
                inbound_web_rtc_outbound_web_rtc(LegEndpointConfig::Provider(
                    ProviderEndpointConfig {
                        provider: ProviderKind::Telnyx,
                        account_profile: "telnyx-test".into(),
                        destination: Some("+12065550100".into()),
                    },
                )),
                NamedRouteBinding::new_with_profiles(
                    "initial-telnyx-source-cancel",
                    Some(NamedRouteCallContext {
                        correlation_id: "initial-telnyx-source-cancel".into(),
                        metadata: BTreeMap::new(),
                    }),
                    vec![NamedProfileBinding::new(
                        NamedProfileRole::Destination,
                        NamedProfileKind::Telnyx,
                        "telnyx-test",
                        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    )
                    .unwrap()],
                )
                .unwrap(),
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
        let destination_leg_id = created
            .value
            .call
            .legs
            .iter()
            .find(|leg| leg.direction == LegDirection::Outbound)
            .unwrap()
            .leg_id;
        let source_connection_id = attach(
            &webrtc,
            principal().authenticated(),
            source.attachment.as_ref().unwrap().token.clone(),
            AcceptEvents::Connected,
        )
        .await;

        start_gate.0.wait().await;
        webrtc.remote_end(source_connection_id.clone()).await;
        wait_for_call(&runtime, call_id, |stored| {
            matches!(stored.call.aggregate.state(), CallState::Ending)
                || stored.call.aggregate.state().is_terminal()
        })
        .await;
        start_gate.1.wait().await;

        tokio::time::timeout(Duration::from_secs(5), async {
            while provider.hangup_snapshot().is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("late initial Telnyx media call was not durably retired");
        let hangups = provider.hangup_snapshot();
        assert_eq!(hangups.len(), 1);
        assert_eq!(hangups[0].0.call_id, call_id);
        assert_eq!(hangups[0].0.leg_id, destination_leg_id);
        assert_eq!(hangups[0].0.binding_generation, BindingGeneration::INITIAL);
        assert_eq!(provider.start_count(), 1);
        assert_eq!(provider.destination_count(), 0);
        assert!(!webrtc.admission_was_accepted(&source_connection_id));

        let retained = runtime
            .service_repository()
            .load_external_reference_for_binding(
                &TenantId::parse("execution-tenant").unwrap(),
                call_id,
                destination_leg_id,
                BindingGeneration::INITIAL,
                ProviderReferenceRole::Media,
            )
            .await
            .unwrap()
            .expect("late provider media reference was not retained for StopLeg");
        assert!(matches!(
            retained.value,
            ExternalReferenceValue::ProviderCall { provider_call_id, .. }
                if provider_call_id == hangups[0].1.provider_call_id
        ));

        stop_harness(supervisor, orchestrator).await;
    })
    .await;
}

#[tokio::test]
async fn named_route_source_hangup_during_final_answer_stops_connected_destination() {
    let (runtime, orchestrator, supervisor, sip, webrtc) = execution_harness(1).await;
    let created = runtime
        .service()
        .create_named_route_call(
            &principal(),
            &IdempotencyKey::parse("execution-named-route-source-final-answer-race").unwrap(),
            inbound_sip_outbound_web_rtc(LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                signaling_uri: Some("wss://connected-agent.example.test/session".into()),
            })),
            NamedRouteBinding::new("connected-agent-wss", None).unwrap(),
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
    let source_connection_id = ConnectionId::new();
    let source_accept_gate = sip.gate_accept(&source_connection_id);
    let owner = principal().authenticated().clone();
    sip.prepare_inbound(
        source_connection_id.clone(),
        &owner,
        source.attachment.as_ref().unwrap().token.clone(),
        AcceptEvents::Connected,
    );
    sip.announce_inbound(source_connection_id.clone(), owner)
        .await;

    tokio::time::timeout(Duration::from_secs(5), source_accept_gate.0.wait())
        .await
        .expect("destination readiness did not begin the source final answer");
    let connecting = wait_for_call(&runtime, call_id, |stored| {
        stored
            .call
            .aggregate
            .leg(destination_leg_id)
            .is_some_and(|leg| leg.state() == LegState::Connected)
    })
    .await;
    let destination_connection_id = connecting.call.bindings[&destination_leg_id]
        .connection_id
        .clone();

    sip.remote_end(source_connection_id.clone()).await;
    tokio::time::sleep(Duration::from_millis(25)).await;
    source_accept_gate.1.wait().await;

    let final_call = tokio::time::timeout(Duration::from_secs(1), async {
        let final_call = wait_for_call(&runtime, call_id, |stored| {
            stored.call.aggregate.state().is_terminal()
        })
        .await;
        while webrtc.route_is_live(&destination_connection_id) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        final_call
    })
    .await
    .expect("source loss during final answer did not stop the connected destination promptly");
    assert_eq!(
        final_call
            .call
            .aggregate
            .leg(source_leg_id)
            .unwrap()
            .state(),
        LegState::Ended,
        "the final-answer race must use the durable source-termination transition"
    );
    assert!(!sip.route_is_live(&source_connection_id));

    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn named_route_setup_deadline_interrupts_blocked_destination_activation() {
    let (runtime, orchestrator, supervisor, sip, webrtc) =
        execution_harness_with_context(1, ContextPolicy::default(), Duration::from_millis(250))
            .await;
    let destination_gate = webrtc.gate_activation();
    let rejected_before = sip.counts.reject.load(Ordering::SeqCst);
    let created = runtime
        .service()
        .create_named_route_call(
            &principal(),
            &IdempotencyKey::parse("execution-named-route-setup-timeout").unwrap(),
            inbound_sip_outbound_web_rtc(LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                signaling_uri: Some("wss://blocked-agent.example.test/session".into()),
            })),
            NamedRouteBinding::new("blocked-agent-wss", None).unwrap(),
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
    let destination_leg_id = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Outbound)
        .unwrap()
        .leg_id;
    let source_connection_id = ConnectionId::new();
    let owner = principal().authenticated().clone();
    sip.prepare_inbound(
        source_connection_id.clone(),
        &owner,
        source.attachment.as_ref().unwrap().token.clone(),
        AcceptEvents::Connected,
    );
    sip.announce_inbound(source_connection_id.clone(), owner)
        .await;

    tokio::time::timeout(Duration::from_secs(5), destination_gate.0.wait())
        .await
        .expect("destination activation did not reach the blocked boundary");
    let dialing = wait_for_call(&runtime, call_id, |stored| {
        stored.call.bindings.contains_key(&destination_leg_id)
    })
    .await;
    let destination_connection_id = dialing.call.bindings[&destination_leg_id]
        .connection_id
        .clone();
    let failed = wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    wait_for_rejection_count(&sip, rejected_before + 1).await;
    assert!(!sip.admission_was_accepted(&source_connection_id));
    assert!(failed
        .call
        .aggregate
        .legs()
        .iter()
        .any(|leg| leg.failure().is_some_and(|failure| {
            matches!(failure.code(), "webrtc_start_timeout" | "setup_timeout")
        })));
    assert!(!webrtc.route_is_live(&destination_connection_id));

    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn outbound_sip_activation_failure_is_not_replayed_and_cleans_the_exact_route() {
    let (runtime, orchestrator, supervisor, sip, _webrtc) = execution_harness(1).await;
    sip.fail_activation.store(true, Ordering::SeqCst);
    let created = create_outbound_web_rtc_call(
        &runtime,
        "execution-outbound-sip-activation-failure",
        LegEndpointConfig::Sip(SipEndpointConfig {
            uri: Some("sip:callee@voice.example.test".into()),
            initial_context: SipInitialContextMode::None,
        }),
    )
    .await;

    let failed = wait_for_call(&runtime, created.call_id, |stored| {
        stored
            .call
            .aggregate
            .leg(created.leg_id)
            .is_some_and(|leg| leg.state() == LegState::Failed)
    })
    .await;
    assert_eq!(
        failed
            .call
            .aggregate
            .leg(created.leg_id)
            .and_then(|leg| leg.failure())
            .map(|failure| failure.code()),
        Some("sip_start_failed")
    );
    assert_eq!(sip.counts.originate.load(Ordering::SeqCst), 1);
    assert_eq!(sip.counts.activate.load(Ordering::SeqCst), 1);
    let connection_id = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(connection_id) =
                sip.counts.ended_connections.lock().unwrap().last().cloned()
            {
                break connection_id;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("failed outbound SIP route did not reach exact teardown");
    assert!(!sip.route_is_live(&connection_id));
    assert!(failed
        .call
        .bindings
        .get(&created.leg_id)
        .is_none_or(|binding| binding.connection_id == connection_id));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        sip.counts.originate.load(Ordering::SeqCst),
        1,
        "the claimed StartLeg must not retransmit after activation failure"
    );
    assert!(runtime
        .service_repository()
        .load_external_reference_by_role(
            &TenantId::parse("execution-tenant").unwrap(),
            created.call_id,
            created.leg_id,
            ProviderReferenceRole::Media,
        )
        .await
        .unwrap()
        .is_none());

    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn required_context_is_owned_persisted_and_applied_before_the_first_sip_invite() {
    let policy = ContextPolicy {
        allow_headers: BTreeMap::from([
            ("X-Account-Tier".into(), "account_tier".into()),
            ("X-Correlation-Id".into(), "correlation_id".into()),
        ]),
        ..ContextPolicy::default()
    };
    let (runtime, orchestrator, supervisor, sip, webrtc) =
        execution_harness_with_context(1, policy, Duration::from_secs(5)).await;
    let originated_before = sip.counts.originate.load(Ordering::SeqCst);
    let activation_gate = sip.gate_activation();
    let created =
        create_required_sip_context_call(&runtime, "execution-required-sip-context").await;
    let owner = principal().authenticated().clone();
    let source_connection_id = attach(
        &webrtc,
        &owner,
        created.source_token.clone(),
        AcceptEvents::Connected,
    )
    .await;
    wait_for_accepted(&webrtc, &source_connection_id).await;

    let wrong_owner = ContextEnvelope::new(
        "wrong-owner",
        "other-tenant",
        created.call_id.to_string(),
        created.source_leg_id.to_string(),
    )
    .to_data_message()
    .unwrap();
    webrtc
        .emit_data_message(source_connection_id.clone(), wrong_owner)
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        sip.counts.originate.load(Ordering::SeqCst),
        originated_before,
        "an ownership-mismatched context must not prepare or send an INVITE"
    );

    let mut envelope = ContextEnvelope::new(
        "correlation-private",
        "execution-tenant",
        created.call_id.to_string(),
        created.source_leg_id.to_string(),
    );
    envelope
        .metadata
        .insert("account_tier".into(), "gold".into());
    webrtc
        .emit_data_message(
            source_connection_id.clone(),
            envelope.to_data_message().unwrap(),
        )
        .await;

    tokio::time::timeout(Duration::from_secs(5), activation_gate.0.wait())
        .await
        .expect("valid durable context did not release outbound SIP activation");
    let context = sip.last_sip_originate_context();
    let headers = context
        .initial_headers()
        .iter()
        .map(|(name, value)| (name.as_str(), value))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(headers.get("X-Account-Tier"), Some(&"gold"));
    assert_eq!(
        headers.get("X-Correlation-Id"),
        Some(&"correlation-private")
    );
    let retained = runtime
        .service_repository()
        .load_initial_context(
            &TenantId::parse("execution-tenant").unwrap(),
            created.call_id,
            created.target_leg_id,
            BindingGeneration::INITIAL,
        )
        .await
        .unwrap()
        .expect("first-INVITE context was not durable before SIP activation");
    assert_eq!(retained.source_connection_id, source_connection_id);
    assert_eq!(retained.source_leg_id, created.source_leg_id);
    assert_eq!(retained.target_leg_id, created.target_leg_id);
    assert_eq!(
        sip.counts.originate.load(Ordering::SeqCst),
        originated_before + 1
    );

    activation_gate.1.wait().await;
    wait_for_call(&runtime, created.call_id, |stored| {
        stored
            .call
            .aggregate
            .leg(created.target_leg_id)
            .is_some_and(|leg| leg.state() == LegState::Connected)
    })
    .await;
    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn named_route_server_context_is_applied_after_attach_without_browser_data_message() {
    let policy = ContextPolicy {
        allow_headers: BTreeMap::from([
            ("X-Bridgefu_Handoff_Token".into(), "handoff_token".into()),
            ("X-Correlation-Id".into(), "correlation_id".into()),
        ]),
        ..ContextPolicy::default()
    };
    let (runtime, orchestrator, supervisor, sip, webrtc) =
        execution_harness_with_context(1, policy, Duration::from_secs(5)).await;
    let originated_before = sip.counts.originate.load(Ordering::SeqCst);
    let created = runtime
        .service()
        .create_named_route_call(
            &principal(),
            &IdempotencyKey::parse("execution-named-server-context").unwrap(),
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
                            uri: Some("sips:vapi-assistant@sip.vapi.ai;transport=tls".into()),
                            initial_context: SipInitialContextMode::Required,
                        }),
                        amazon_connect_start: None,
                    },
                ],
            },
            NamedRouteBinding::new(
                "vapi-direct-assistant",
                Some(NamedRouteCallContext {
                    correlation_id: "direct-server-correlation".into(),
                    metadata: BTreeMap::from([(
                        "handoff_token".into(),
                        "signed-opaque-token".into(),
                    )]),
                }),
            )
            .unwrap(),
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
    let destination_leg_id = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Outbound)
        .unwrap()
        .leg_id;

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        sip.counts.originate.load(Ordering::SeqCst),
        originated_before
    );
    let owner = principal().authenticated().clone();
    let source_connection_id = attach(
        &webrtc,
        &owner,
        source.attachment.as_ref().unwrap().token.clone(),
        AcceptEvents::Connected,
    )
    .await;
    wait_for_accepted(&webrtc, &source_connection_id).await;
    wait_for_call(&runtime, created.value.call.call_id, |stored| {
        stored
            .call
            .aggregate
            .leg(destination_leg_id)
            .is_some_and(|leg| leg.state() == LegState::Connected)
    })
    .await;

    let context = sip.last_sip_originate_context();
    let headers = context
        .initial_headers()
        .iter()
        .map(|(name, value)| (name.as_str(), value))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        headers.get("X-Bridgefu_Handoff_Token"),
        Some(&"signed-opaque-token")
    );
    assert_eq!(
        headers.get("X-Correlation-Id"),
        Some(&"direct-server-correlation")
    );
    assert_eq!(
        sip.counts.originate.load(Ordering::SeqCst),
        originated_before + 1
    );
    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn required_context_timeout_sends_no_sip_invite() {
    let (runtime, orchestrator, supervisor, sip, _webrtc) =
        execution_harness_with_context(1, ContextPolicy::default(), Duration::from_millis(200))
            .await;
    let created =
        create_required_sip_context_call(&runtime, "execution-required-context-timeout").await;
    let failed = wait_for_call(&runtime, created.call_id, |stored| {
        stored
            .call
            .aggregate
            .leg(created.target_leg_id)
            .is_some_and(|leg| leg.state() == LegState::Failed)
    })
    .await;
    assert_eq!(sip.counts.originate.load(Ordering::SeqCst), 0);
    assert_eq!(sip.counts.activate.load(Ordering::SeqCst), 0);
    assert_eq!(
        failed
            .call
            .aggregate
            .leg(created.target_leg_id)
            .and_then(|leg| leg.failure())
            .map(|failure| failure.code()),
        Some("initial_context_timeout")
    );
    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn inbound_sip_context_reaches_the_peer_data_channel_and_later_messages_bridge() {
    let policy = ContextPolicy {
        allow_headers: BTreeMap::from([
            ("X-Account-Tier".into(), "account_tier".into()),
            ("X-Correlation-Id".into(), "correlation_id".into()),
        ]),
        ..ContextPolicy::default()
    };
    let (runtime, orchestrator, supervisor, sip, webrtc) =
        execution_harness_with_context(1, policy, Duration::from_secs(5)).await;
    let created = create_inbound_call(&runtime, "execution-sip-context-to-data").await;
    let owner = principal().authenticated().clone();
    let sip_connection_id = ConnectionId::new();
    sip.prepare_inbound_with_codec_and_metadata(
        sip_connection_id.clone(),
        &owner,
        created.sip_token.clone(),
        AcceptEvents::Connected,
        codec("pcmu", 8_000, 1),
        InboundSignalingMetadata::new([
            ("X-Correlation-Id", "sip-correlation-private"),
            ("X-Account-Tier", "platinum"),
        ])
        .unwrap(),
    );
    sip.announce_inbound(sip_connection_id.clone(), owner.clone())
        .await;
    wait_for_accepted(&sip, &sip_connection_id).await;
    let webrtc_connection_id = attach(
        &webrtc,
        &owner,
        created.webrtc_token.clone(),
        AcceptEvents::Connected,
    )
    .await;
    wait_for_accepted(&webrtc, &webrtc_connection_id).await;

    let initial_message = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(message) = webrtc.take_sent_data(&webrtc_connection_id) {
                break message;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("SIP initial context was not delivered to the peer DataChannel");
    let initial = ContextEnvelope::from_data_message_for(
        &initial_message,
        "execution-tenant",
        &created.call_id.to_string(),
        &created.sip_leg.to_string(),
    )
    .unwrap();
    assert_eq!(initial.correlation_id, "sip-correlation-private");
    assert_eq!(
        initial.metadata.get("account_tier").map(String::as_str),
        Some("platinum")
    );

    wait_for_active_bridge_count(&orchestrator, 1).await;
    let arbitrary = DataMessage::reliable(
        "customer.binary.v7",
        "application/octet-stream",
        vec![0_u8, 0xff, 7],
    );
    webrtc
        .emit_data_message(webrtc_connection_id.clone(), arbitrary.clone())
        .await;
    let forwarded = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(message) = sip.take_sent_data(&sip_connection_id) {
                break message;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("arbitrary DataChannel message did not cross the media graph");
    assert_eq!(forwarded, arbitrary);

    let later_context = ContextEnvelope::new(
        "later-correlation",
        "execution-tenant",
        created.call_id.to_string(),
        created.webrtc_leg.to_string(),
    )
    .to_data_message()
    .unwrap();
    webrtc
        .emit_data_message(webrtc_connection_id, later_context.clone())
        .await;
    let forwarded_context = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(message) = sip.take_sent_data(&sip_connection_id) {
                break message;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("later context did not reach the SIP MESSAGE transport boundary");
    assert_eq!(forwarded_context, later_context);

    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn outbound_web_rtc_modes_bind_and_register_before_peer_visible_activation() {
    let (runtime, orchestrator, supervisor, _sip, webrtc) = execution_harness(3).await;
    let cases = [
        (
            "execution-outbound-websocket",
            LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                signaling_uri: Some("wss://signal.example.test:8443/session".into()),
            }),
            WebRtcSignalingMode::WebSocket,
        ),
        (
            "execution-outbound-whip",
            LegEndpointConfig::Whip(WhipEndpointConfig {
                endpoint_uri: Some("https://media.example.test/whip/publish".into()),
            }),
            WebRtcSignalingMode::Whip,
        ),
        (
            "execution-outbound-whep",
            LegEndpointConfig::Whep(WhepEndpointConfig {
                endpoint_uri: Some("https://media.example.test/whep/play".into()),
            }),
            WebRtcSignalingMode::Whep,
        ),
    ];

    for (idempotency, endpoint, expected_mode) in cases {
        let activation_count = webrtc.counts.activate.load(Ordering::SeqCst);
        let gate = webrtc.gate_activation();
        let created = create_outbound_web_rtc_call(&runtime, idempotency, endpoint).await;
        if tokio::time::timeout(Duration::from_secs(5), gate.0.wait())
            .await
            .is_err()
        {
            let observed = runtime
                .service_repository()
                .load_service_call(
                    &TenantId::parse("execution-tenant").unwrap(),
                    created.call_id,
                )
                .await
                .unwrap();
            panic!(
                "outbound activation did not start: originate={}, activate={}, end={}, bindings={:?}, call={:?}",
                webrtc.counts.originate.load(Ordering::SeqCst),
                webrtc.counts.activate.load(Ordering::SeqCst),
                webrtc.counts.end.load(Ordering::SeqCst),
                observed.call.bindings,
                observed.call.aggregate
            );
        }

        let bound = wait_for_call(&runtime, created.call_id, |stored| {
            stored.call.bindings.contains_key(&created.leg_id)
                && stored
                    .call
                    .aggregate
                    .leg(created.leg_id)
                    .is_some_and(|leg| leg.state() == LegState::Signaling)
        })
        .await;
        let binding = bound.call.bindings.get(&created.leg_id).unwrap();
        assert_eq!(binding.transport, AttachmentTransport::WebRtc);
        assert_eq!(binding.binding_generation.value(), 1);
        assert!(webrtc.route_is_live(&binding.connection_id));
        assert_eq!(
            webrtc.counts.activate.load(Ordering::SeqCst),
            activation_count + 1,
            "the activation hook is the first peer-visible signaling boundary"
        );
        assert_eq!(
            webrtc.last_web_rtc_originate_context().signaling_mode(),
            expected_mode
        );

        gate.1.wait().await;
        let connected = wait_for_call(&runtime, created.call_id, |stored| {
            stored
                .call
                .aggregate
                .leg(created.leg_id)
                .is_some_and(|leg| leg.state() == LegState::Connected)
        })
        .await;
        assert_eq!(
            connected.call.bindings[&created.leg_id].connection_id,
            binding.connection_id
        );
    }

    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn recovery_without_process_owner_fails_web_rtc_before_prepare_or_bind() {
    let worker_id = WorkerId::new();
    let runtime = runtime(CallRepositoryBackendConfig::Memory, worker_id).await;
    let created = create_outbound_web_rtc_call(
        &runtime,
        "execution-outbound-owner-missing",
        LegEndpointConfig::Whep(WhepEndpointConfig {
            endpoint_uri: Some("https://media.example.test/whep/play".into()),
        }),
    )
    .await;
    let orchestrator = Orchestrator::new(CoreConfig::default());

    let supervisor = CallExecutionSupervisor::install(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        2,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let failed = wait_for_call(&runtime, created.call_id, |stored| {
        stored
            .call
            .aggregate
            .leg(created.leg_id)
            .is_some_and(|leg| leg.state() == LegState::Failed)
    })
    .await;
    assert!(failed.call.bindings.is_empty());
    assert_eq!(
        failed
            .call
            .aggregate
            .leg(created.leg_id)
            .unwrap()
            .failure()
            .map(|failure| failure.code()),
        Some("outbound_owner_unavailable")
    );

    supervisor.shutdown(Duration::from_secs(2)).await;
    orchestrator.drain_prepared_outbound_connections().await;
    orchestrator.drain_connection_lifecycle_tasks().await;
}

#[tokio::test]
async fn canonical_whep_uses_the_durable_single_use_attachment_token() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let worker_id = WorkerId::new();
    let runtime = runtime(CallRepositoryBackendConfig::Memory, worker_id).await;
    let created = runtime
        .service()
        .create_call(
            &principal(),
            &IdempotencyKey::parse("execution-canonical-whep-replay").unwrap(),
            two_inbound_sip_whep_legs(),
        )
        .await
        .unwrap();
    let call_id = created.value.call.call_id;
    let whep_leg = created
        .value
        .call
        .legs
        .iter()
        .find(|leg| leg.kind == bridgefu::call_engine::LegKind::Whep)
        .unwrap();
    let whep_leg_id = whep_leg.leg_id;
    let token = whep_leg.attachment.as_ref().unwrap().token.clone();

    let orchestrator = Orchestrator::new(CoreConfig::default());
    let supervisor = CallExecutionSupervisor::install(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        4,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let mut config = WebRtcConfig::loopback();
    config.max_concurrent_sessions = 2;
    let server = WebRtcServerBuilder::new(config)
        .with_inbound_admission_confirmation(Duration::from_secs(5))
        .with_whip_auth(Arc::new(BridgefuWhepAuth {
            principal: principal().authenticated().clone(),
        }))
        .with_whip("127.0.0.1:0")
        .build()
        .await
        .unwrap();
    orchestrator
        .register(server.adapter() as Arc<dyn ConnectionAdapter>)
        .unwrap();

    let endpoint = format!("http://{}/whep/{token}", server.whip_addr().unwrap());
    let offer = canonical_whep_offer().await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let post = |offer: String| {
        client
            .post(endpoint.clone())
            .header("authorization", "Bearer bridgefu-test")
            .header("content-type", "application/sdp")
            .body(offer)
            .send()
    };
    let first = tokio::spawn(post(offer.clone()));
    let second = tokio::spawn(post(offer));
    let first = first.await.unwrap().unwrap();
    let second = second.await.unwrap().unwrap();
    let statuses = [first.status(), second.status()];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == reqwest::StatusCode::CREATED)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == reqwest::StatusCode::FORBIDDEN)
            .count(),
        1
    );

    let bound = wait_for_call(&runtime, call_id, |stored| {
        stored.call.bindings.contains_key(&whep_leg_id)
    })
    .await;
    let connection_id = bound.call.bindings[&whep_leg_id].connection_id.clone();
    assert_eq!(bound.call.bindings.len(), 1);
    assert_eq!(server.adapter().metrics().active_sessions, 1);
    assert_eq!(server.adapter().metrics().active_http_resources, 1);

    server
        .adapter()
        .end(connection_id, EndReason::Cancelled)
        .await
        .unwrap();
    assert_eq!(server.adapter().metrics().active_sessions, 0);
    assert_eq!(server.adapter().metrics().active_http_resources, 0);
    supervisor.shutdown(Duration::from_secs(2)).await;
    orchestrator.drain_prepared_outbound_connections().await;
    orchestrator.drain_connection_lifecycle_tasks().await;
    server.shutdown().await;
}

#[tokio::test]
async fn outbound_web_rtc_terminal_cleanup_ends_the_exact_bound_generation() {
    let (runtime, orchestrator, supervisor, _sip, webrtc) = execution_harness(1).await;
    let created = create_outbound_web_rtc_call(
        &runtime,
        "execution-outbound-terminal-cleanup",
        LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
            signaling_uri: Some("wss://signal.example.test/session".into()),
        }),
    )
    .await;
    let connected = wait_for_call(&runtime, created.call_id, |stored| {
        stored
            .call
            .aggregate
            .leg(created.leg_id)
            .is_some_and(|leg| leg.state() == LegState::Connected)
    })
    .await;
    let connection_id = connected.call.bindings[&created.leg_id]
        .connection_id
        .clone();

    runtime
        .service()
        .hangup_call(
            &principal(),
            created.call_id,
            &IdempotencyKey::parse("execution-outbound-terminal-hangup").unwrap(),
            CallMutationInput::default(),
        )
        .await
        .unwrap();
    wait_for_call(&runtime, created.call_id, |stored| {
        stored
            .call
            .aggregate
            .leg(created.leg_id)
            .is_some_and(|leg| leg.state().is_terminal())
    })
    .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while webrtc.route_is_live(&connection_id) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("generation-bound WebRTC route was not torn down");
    assert!(webrtc
        .counts
        .ended_connections
        .lock()
        .unwrap()
        .contains(&connection_id));

    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn simultaneous_authenticated_legs_are_bound_before_accept_and_cannot_outrun_ownership() {
    let (runtime, orchestrator, supervisor, sip, webrtc) = execution_harness(2).await;
    let created = create_inbound_call(&runtime, "execution-simultaneous-legs").await;
    let owner = principal().authenticated().clone();
    let sip_id = ConnectionId::new();
    let webrtc_id = ConnectionId::new();
    sip.prepare_inbound(
        sip_id.clone(),
        &owner,
        created.sip_token,
        AcceptEvents::Connected,
    );
    webrtc.prepare_inbound(
        webrtc_id.clone(),
        &owner,
        created.webrtc_token,
        AcceptEvents::Connected,
    );
    let sip_gate = sip.gate_accept(&sip_id);

    let ((), ()) = tokio::join!(
        sip.announce_inbound(sip_id.clone(), owner.clone()),
        webrtc.announce_inbound(webrtc_id.clone(), owner.clone()),
    );
    tokio::time::timeout(Duration::from_secs(5), sip_gate.0.wait())
        .await
        .expect("the gated same-call leg reached adapter accept");

    let bound = wait_for_call(&runtime, created.call_id, |stored| {
        stored.call.bindings.len() == 2
    })
    .await;
    assert_eq!(
        bound
            .call
            .bindings
            .get(&created.sip_leg)
            .unwrap()
            .connection_id,
        sip_id
    );
    assert_eq!(
        bound
            .call
            .bindings
            .get(&created.webrtc_leg)
            .unwrap()
            .connection_id,
        webrtc_id
    );
    assert_eq!(
        bound.call.aggregate.leg(created.sip_leg).unwrap().state(),
        LegState::Signaling
    );
    assert_eq!(
        bound
            .call
            .aggregate
            .leg(created.webrtc_leg)
            .unwrap()
            .state(),
        LegState::Signaling
    );
    assert!(sip.admission_was_accepted(&sip_id));
    // The actor serializes external admission operations. The other proof is
    // already durably bound and queued even though its adapter accept cannot
    // begin until the gated first operation is released.

    sip_gate.1.wait().await;
    wait_for_accepted(&webrtc, &webrtc_id).await;
    let active = wait_for_call(&runtime, created.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;
    assert_eq!(
        active.call.aggregate.leg(created.sip_leg).unwrap().state(),
        LegState::Connected
    );
    assert_eq!(
        active
            .call
            .aggregate
            .leg(created.webrtc_leg)
            .unwrap()
            .state(),
        LegState::Connected
    );
    assert_eq!(sip.counts.reject.load(Ordering::SeqCst), 0);
    assert_eq!(webrtc.counts.reject.load(Ordering::SeqCst), 0);

    stop_harness(supervisor, orchestrator).await;
}

#[allow(clippy::too_many_arguments)]
async fn assert_bidirectional_media_case(
    idempotency: &str,
    sip_codec: CodecInfo,
    sip_payload_type: u8,
    sip_payload: Vec<u8>,
    webrtc_codec: CodecInfo,
    webrtc_payload_type: u8,
    webrtc_payload: Vec<u8>,
) {
    let (runtime, orchestrator, supervisor, sip, webrtc) = execution_harness(1).await;
    let created = create_inbound_call(&runtime, idempotency).await;
    let owner = principal().authenticated().clone();
    let sip_id = ConnectionId::new();
    let webrtc_id = ConnectionId::new();
    let sip_stream = sip.prepare_inbound_with_codec(
        sip_id.clone(),
        &owner,
        created.sip_token,
        AcceptEvents::Connected,
        sip_codec.clone(),
    );
    let webrtc_stream = webrtc.prepare_inbound_with_codec(
        webrtc_id.clone(),
        &owner,
        created.webrtc_token,
        AcceptEvents::Connected,
        webrtc_codec.clone(),
    );
    let mut sip_output = sip_stream.take_output();
    let mut webrtc_output = webrtc_stream.take_output();

    let ((), ()) = tokio::join!(
        sip.announce_inbound(sip_id.clone(), owner.clone()),
        webrtc.announce_inbound(webrtc_id.clone(), owner),
    );
    wait_for_call(&runtime, created.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;
    wait_for_active_bridge_count(&orchestrator, 1).await;
    assert_eq!(
        sip_stream.source_receiver_acquisitions(),
        1,
        "SIP source must have exactly one MediaGraph consumer"
    );
    assert_eq!(
        webrtc_stream.source_receiver_acquisitions(),
        1,
        "WebRTC source must have exactly one MediaGraph consumer"
    );

    let sip_delta = sip_codec.clock_rate_hz / 50;
    let webrtc_delta = webrtc_codec.clock_rate_hz / 50;
    let sip_first_timestamp = 80_000;
    sip_stream
        .inject(sip_stream.frame(sip_payload.clone(), sip_first_timestamp, sip_payload_type))
        .await
        .unwrap();
    sip_stream
        .inject(sip_stream.frame(
            sip_payload.clone(),
            sip_first_timestamp.wrapping_add(sip_delta),
            sip_payload_type,
        ))
        .await
        .unwrap();
    let toward_webrtc_first = receive_media(&mut webrtc_output).await;
    let toward_webrtc_second = receive_media(&mut webrtc_output).await;
    assert_eq!(toward_webrtc_first.payload_type, Some(webrtc_payload_type));
    assert_eq!(
        toward_webrtc_second
            .timestamp_rtp
            .wrapping_sub(toward_webrtc_first.timestamp_rtp),
        webrtc_delta,
        "SIP-to-WebRTC RTP clock must follow the negotiated target codec"
    );
    if sip_codec == webrtc_codec {
        assert_eq!(toward_webrtc_first.payload.as_ref(), sip_payload.as_slice());
        assert_eq!(
            toward_webrtc_second.payload.as_ref(),
            sip_payload.as_slice()
        );
    } else {
        assert!(!toward_webrtc_first.payload.is_empty());
        assert!(!toward_webrtc_second.payload.is_empty());
    }

    let webrtc_first_timestamp = 480_000;
    webrtc_stream
        .inject(webrtc_stream.frame(
            webrtc_payload.clone(),
            webrtc_first_timestamp,
            webrtc_payload_type,
        ))
        .await
        .unwrap();
    webrtc_stream
        .inject(webrtc_stream.frame(
            webrtc_payload.clone(),
            webrtc_first_timestamp.wrapping_add(webrtc_delta),
            webrtc_payload_type,
        ))
        .await
        .unwrap();
    let toward_sip_first = receive_media(&mut sip_output).await;
    let toward_sip_second = receive_media(&mut sip_output).await;
    assert_eq!(toward_sip_first.payload_type, Some(sip_payload_type));
    assert_eq!(
        toward_sip_second
            .timestamp_rtp
            .wrapping_sub(toward_sip_first.timestamp_rtp),
        sip_delta,
        "WebRTC-to-SIP RTP clock must follow the negotiated target codec"
    );
    if sip_codec == webrtc_codec {
        assert_eq!(toward_sip_first.payload.as_ref(), webrtc_payload.as_slice());
        assert_eq!(
            toward_sip_second.payload.as_ref(),
            webrtc_payload.as_slice()
        );
    } else {
        assert!(!toward_sip_first.payload.is_empty());
        assert!(!toward_sip_second.payload.is_empty());
    }

    sip.remote_end(sip_id).await;
    wait_for_call(&runtime, created.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    wait_for_active_bridge_count(&orchestrator, 0).await;
    wait_for_source_shutdown(
        &sip_stream,
        sip_stream.frame(sip_payload, 81_000, sip_payload_type),
    )
    .await;
    wait_for_source_shutdown(
        &webrtc_stream,
        webrtc_stream.frame(webrtc_payload, 481_000, webrtc_payload_type),
    )
    .await;
    assert!(sip_output.try_recv().is_err());
    assert!(webrtc_output.try_recv().is_err());

    stop_harness(supervisor, orchestrator).await;
}

async fn assert_one_way_media_case(idempotency: &str, sip_to_webrtc: bool) {
    let (sip_media_flow, webrtc_media_flow) = if sip_to_webrtc {
        (MediaFlow::ReceiveOnly, MediaFlow::SendOnly)
    } else {
        (MediaFlow::SendOnly, MediaFlow::ReceiveOnly)
    };
    let (runtime, orchestrator, supervisor, sip, webrtc) = execution_harness(1).await;
    let created =
        create_inbound_call_with_media(&runtime, idempotency, sip_media_flow, webrtc_media_flow)
            .await;
    let owner = principal().authenticated().clone();
    let sip_id = ConnectionId::new();
    let webrtc_id = ConnectionId::new();
    let media_codec = codec("pcmu", 8_000, 1);
    let sip_stream = sip.prepare_inbound_with_codec(
        sip_id.clone(),
        &owner,
        created.sip_token,
        AcceptEvents::Connected,
        media_codec.clone(),
    );
    let webrtc_stream = webrtc.prepare_inbound_with_codec(
        webrtc_id.clone(),
        &owner,
        created.webrtc_token,
        AcceptEvents::Connected,
        media_codec,
    );
    let mut sip_output = sip_stream.take_output();
    let mut webrtc_output = webrtc_stream.take_output();

    let ((), ()) = tokio::join!(
        sip.announce_inbound(sip_id.clone(), owner.clone()),
        webrtc.announce_inbound(webrtc_id.clone(), owner),
    );
    wait_for_call(&runtime, created.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;
    wait_for_active_bridge_count(&orchestrator, 1).await;

    let (
        enabled_stream,
        disabled_stream,
        target_output,
        forbidden_output,
        ending_adapter,
        ending_connection,
    ) = if sip_to_webrtc {
        (
            &sip_stream,
            &webrtc_stream,
            &mut webrtc_output,
            &mut sip_output,
            &sip,
            sip_id,
        )
    } else {
        (
            &webrtc_stream,
            &sip_stream,
            &mut sip_output,
            &mut webrtc_output,
            &webrtc,
            webrtc_id,
        )
    };
    assert_eq!(
        enabled_stream.source_receiver_acquisitions(),
        1,
        "the persisted ReceiveOnly leg must have exactly one MediaGraph consumer"
    );
    assert_eq!(
        disabled_stream.source_receiver_acquisitions(),
        0,
        "the persisted SendOnly leg must never surrender its source receiver"
    );

    let enabled_payload = vec![0x55; 160];
    enabled_stream
        .inject(enabled_stream.frame(enabled_payload.clone(), 80_000, 0))
        .await
        .unwrap();
    let delivered = receive_media(target_output).await;
    assert_eq!(delivered.payload_type, Some(0));
    assert_eq!(delivered.payload.as_ref(), enabled_payload.as_slice());

    disabled_stream
        .inject(disabled_stream.frame(vec![0xaa; 160], 88_000, 0))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(150), forbidden_output.recv())
            .await
            .is_err(),
        "the persisted SendOnly leg unexpectedly acted as a media source"
    );

    ending_adapter.remote_end(ending_connection).await;
    wait_for_call(&runtime, created.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    wait_for_active_bridge_count(&orchestrator, 0).await;
    wait_for_source_shutdown(
        enabled_stream,
        enabled_stream.frame(enabled_payload, 80_160, 0),
    )
    .await;
    assert_eq!(disabled_stream.source_receiver_acquisitions(), 0);

    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn sip_webrtc_media_graph_is_directional_codec_exact_and_cleanup_owned() {
    assert_bidirectional_media_case(
        "execution-media-pcmu-opus",
        codec("pcmu", 8_000, 1),
        0,
        vec![0xff; 160],
        codec("opus", 48_000, 2),
        111,
        vec![0xf8, 0xff, 0xfe],
    )
    .await;

    assert_bidirectional_media_case(
        "execution-media-pcma-opus",
        codec("pcma", 8_000, 1),
        8,
        vec![0xd5; 160],
        codec("opus", 48_000, 2),
        111,
        vec![0xf8, 0xff, 0xfe],
    )
    .await;

    // These codec bytes deliberately begin with a syntactically plausible
    // RTP v2 header. Same-codec routing must keep the payload opaque rather
    // than stripping twelve bytes based on content heuristics.
    let mut rtp_looking_codec_payload = vec![0xff; 160];
    rtp_looking_codec_payload[..12].copy_from_slice(&[
        0x80, 0x00, 0x12, 0x34, 0x00, 0x01, 0x38, 0x80, 0x12, 0x34, 0x56, 0x78,
    ]);
    assert_bidirectional_media_case(
        "execution-media-opaque-pcmu",
        codec("pcmu", 8_000, 1),
        0,
        rtp_looking_codec_payload.clone(),
        codec("pcmu", 8_000, 1),
        0,
        rtp_looking_codec_payload,
    )
    .await;
}

#[tokio::test]
async fn durable_one_way_media_flows_route_both_orientations_without_acquiring_disabled_sources() {
    assert_one_way_media_case("execution-media-sip-to-webrtc", true).await;
    assert_one_way_media_case("execution-media-webrtc-to-sip", false).await;
}

#[tokio::test]
async fn immediate_connected_then_ended_is_reconciled_after_exact_durable_binding() {
    let (runtime, orchestrator, supervisor, sip, webrtc) = execution_harness(2).await;
    let created = create_inbound_call(&runtime, "execution-immediate-terminal").await;
    let owner = principal().authenticated().clone();
    let webrtc_id = attach(
        &webrtc,
        &owner,
        created.webrtc_token,
        AcceptEvents::Connected,
    )
    .await;
    wait_for_accepted(&webrtc, &webrtc_id).await;
    let sip_id = ConnectionId::new();
    sip.prepare_inbound(
        sip_id.clone(),
        &owner,
        created.sip_token,
        AcceptEvents::ConnectedThenEnded,
    );
    let sip_gate = sip.gate_accept(&sip_id);
    sip.announce_inbound(sip_id.clone(), owner.clone()).await;
    tokio::time::timeout(Duration::from_secs(5), sip_gate.0.wait())
        .await
        .expect("immediate-terminal leg reached adapter accept");
    let bound = wait_for_call(&runtime, created.call_id, |stored| {
        stored
            .call
            .bindings
            .get(&created.sip_leg)
            .is_some_and(|binding| binding.connection_id == sip_id)
    })
    .await;
    assert_eq!(
        bound.call.aggregate.leg(created.sip_leg).unwrap().state(),
        LegState::Signaling
    );
    sip_gate.1.wait().await;
    wait_for_accepted(&sip, &sip_id).await;

    let terminal = wait_for_call(&runtime, created.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    for leg in terminal.call.aggregate.legs() {
        assert!(leg.state().is_terminal());
        assert_ne!(
            leg.failure().map(|failure| failure.code()),
            Some("execution_unavailable")
        );
    }
    assert!(
        webrtc
            .counts
            .ended_connections
            .lock()
            .unwrap()
            .contains(&webrtc_id),
        "the immediate terminal event must durably tear down its peer"
    );

    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn interleaved_unrelated_calls_never_cross_connection_ownership() {
    let (runtime, orchestrator, supervisor, sip, webrtc) = execution_harness(2).await;
    let first = create_inbound_call(&runtime, "execution-interleaved-first").await;
    let second = create_inbound_call(&runtime, "execution-interleaved-second").await;
    let owner = principal().authenticated().clone();

    let first_sip = attach(&sip, &owner, first.sip_token, AcceptEvents::Connected).await;
    let second_sip = attach(&sip, &owner, second.sip_token, AcceptEvents::Connected).await;
    let second_webrtc = attach(
        &webrtc,
        &owner,
        second.webrtc_token,
        AcceptEvents::Connected,
    )
    .await;
    let first_webrtc = attach(&webrtc, &owner, first.webrtc_token, AcceptEvents::Connected).await;

    let (first_stored, second_stored) = tokio::join!(
        wait_for_call(&runtime, first.call_id, |stored| {
            stored.call.aggregate.state() == CallState::Active
        }),
        wait_for_call(&runtime, second.call_id, |stored| {
            stored.call.aggregate.state() == CallState::Active
        }),
    );
    assert_eq!(
        first_stored
            .call
            .bindings
            .get(&first.sip_leg)
            .unwrap()
            .connection_id,
        first_sip
    );
    assert_eq!(
        first_stored
            .call
            .bindings
            .get(&first.webrtc_leg)
            .unwrap()
            .connection_id,
        first_webrtc
    );
    assert_eq!(
        second_stored
            .call
            .bindings
            .get(&second.sip_leg)
            .unwrap()
            .connection_id,
        second_sip
    );
    assert_eq!(
        second_stored
            .call
            .bindings
            .get(&second.webrtc_leg)
            .unwrap()
            .connection_id,
        second_webrtc
    );
    assert_ne!(first_sip, second_sip);
    assert_ne!(first_webrtc, second_webrtc);

    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn authenticated_real_sip_request_uri_attachment_reaches_the_durable_call_actor() {
    let worker_id = WorkerId::new();
    let runtime = runtime(CallRepositoryBackendConfig::Memory, worker_id).await;
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let supervisor = CallExecutionSupervisor::install(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        4,
        Duration::from_secs(5),
    )
    .await
    .unwrap();

    let reservation =
        std::net::UdpSocket::bind("127.0.0.1:0").expect("reserve real SIP attachment listener");
    let sip_address = reservation
        .local_addr()
        .expect("reserved SIP attachment address");
    drop(reservation);
    let owner = principal().authenticated().clone();
    let listener_policy = SipListenerAuthPolicy::enabled_for_tenant("execution-tenant")
        .expect("tenant-bound SIP listener")
        .with_trusted_cidr(
            "127.0.0.1/32".parse().expect("loopback CIDR"),
            owner.clone(),
        );
    let sip_adapter = SipAdapter::from_config_with_listener_auth(
        SipConfig::local("bridgefu-real-attachment", sip_address.port()),
        listener_policy,
    )
    .await
    .expect("production SIP attachment adapter");
    let coordinator = Arc::clone(sip_adapter.coordinator());
    let webrtc = LifecycleTestAdapter::new(Transport::WebRtc);
    orchestrator
        .register(Arc::clone(&sip_adapter) as Arc<dyn ConnectionAdapter>)
        .expect("register production SIP attachment adapter");
    orchestrator
        .register(Arc::clone(&webrtc) as Arc<dyn ConnectionAdapter>)
        .expect("register test WebRTC peer adapter");

    let created = create_inbound_call(&runtime, "execution-real-sip-attachment").await;

    let caller_reservation =
        std::net::UdpSocket::bind("127.0.0.1:0").expect("reserve real SIP attachment caller");
    let caller_address = caller_reservation
        .local_addr()
        .expect("reserved SIP caller address");
    drop(caller_reservation);
    let caller = UnifiedCoordinator::new(SipConfig::local(
        "bridgefu-real-attachment-caller",
        caller_address.port(),
    ))
    .await
    .expect("production SIP attachment caller");
    let caller_session = caller
        .invite(
            Some(format!("sip:bridgefu-caller@{caller_address}")),
            format!("sip:{}@{sip_address}", created.sip_token),
        )
        .send()
        .await
        .expect("send production SIP attachment INVITE");
    let attached = wait_for_call(&runtime, created.call_id, |stored| {
        stored
            .call
            .aggregate
            .leg(created.sip_leg)
            .is_some_and(|leg| leg.state() == LegState::Connected)
    })
    .await;
    let sip_connection = attached
        .call
        .bindings
        .get(&created.sip_leg)
        .expect("durable production SIP binding")
        .connection_id
        .clone();
    assert!(
        !attached.call.bindings.contains_key(&created.webrtc_leg),
        "an unattached peer leg must not be globally or FIFO paired"
    );
    assert_eq!(attached.call.aggregate.state(), CallState::Connecting);
    wait_for_active_bridge_count(&orchestrator, 0).await;

    let webrtc_connection = attach(
        &webrtc,
        &owner,
        created.webrtc_token,
        AcceptEvents::Connected,
    )
    .await;
    let active = wait_for_call(&runtime, created.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;
    assert_eq!(
        active
            .call
            .bindings
            .get(&created.sip_leg)
            .expect("production SIP binding remains exact")
            .connection_id,
        sip_connection
    );
    assert_eq!(
        active
            .call
            .bindings
            .get(&created.webrtc_leg)
            .expect("explicit WebRTC peer binding")
            .connection_id,
        webrtc_connection
    );
    wait_for_active_bridge_count(&orchestrator, 1).await;

    tokio::time::timeout(Duration::from_secs(5), caller.hangup(&caller_session))
        .await
        .expect("production SIP remote BYE deadline")
        .expect("production SIP remote BYE");
    let terminal = wait_for_call(&runtime, created.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    assert!(terminal
        .call
        .aggregate
        .legs()
        .iter()
        .all(|leg| leg.state().is_terminal()));
    wait_for_active_bridge_count(&orchestrator, 0).await;

    stop_harness(supervisor, Arc::clone(&orchestrator)).await;
    caller
        .shutdown_gracefully(Some(Duration::from_secs(2)))
        .await
        .expect("shutdown production SIP attachment caller");
    sip_adapter
        .drain()
        .await
        .expect("drain production SIP adapter");
    coordinator
        .shutdown_gracefully(Some(Duration::from_secs(2)))
        .await
        .expect("shutdown production SIP attachment coordinator");
    assert_eq!(sip_adapter.retained_task_count(), 0);
    assert_eq!(orchestrator.connection_lifecycle_task_count(), 0);
}

#[tokio::test]
async fn private_quic_attachment_is_fence_bound_activated_before_receipt_and_single_use() {
    let worker_id = WorkerId::new();
    let runtime = runtime(CallRepositoryBackendConfig::Memory, worker_id).await;
    let created = create_inbound_call(&runtime, "execution-private-quic-admission").await;
    let owner = principal();
    let now = Utc::now();
    let deployment = DeploymentId::parse("execution-private-quic").unwrap();
    let coordinator = Arc::new(
        MemoryCoordinator::new(
            deployment.clone(),
            Arc::new(ManualCoordinationClock::new(now)),
            16,
        )
        .unwrap(),
    );
    let worker = runtime.worker().lease;
    coordinator
        .apply(&CoordinationEvent {
            deployment: deployment.clone(),
            sequence: ProjectionSequence::from_i64(1).unwrap(),
            payload: CoordinationPayload::Worker(WorkerCoordinationSnapshot {
                lease: worker,
                max_calls: runtime.worker().max_calls,
                reserved_calls: 1,
                draining: false,
                capabilities: BTreeSet::from(["sip".into(), "webrtc".into()]),
                lease_expires_at: now + chrono::TimeDelta::minutes(2),
            }),
            recorded_at: now,
        })
        .await
        .unwrap();
    let fingerprint_key = vec![0x41; 32];
    let tenant_binding = PrincipalFingerprintKey::new(fingerprint_key.clone())
        .unwrap()
        .derive(&owner);
    coordinator
        .apply(&CoordinationEvent {
            deployment,
            sequence: ProjectionSequence::from_i64(2).unwrap(),
            payload: CoordinationPayload::AttachmentRoute(AttachmentRouteHint {
                token_digest: parse_presented_attachment_token(created.sip_token.clone())
                    .unwrap()
                    .digest(),
                worker,
                route_catalog_fingerprint: None,
                transport: AttachmentTransport::Sip,
                tenant_binding,
                expires_at: now + chrono::TimeDelta::minutes(1),
            }),
            recorded_at: now,
        })
        .await
        .unwrap();
    let resolver = GatewayAttachmentResolver::new(coordinator, fingerprint_key).unwrap();
    let authorization = resolver
        .resolve(
            owner.authenticated().clone(),
            created.sip_token,
            AttachmentTransport::Sip,
            now,
        )
        .await
        .unwrap();
    let request_id = uuid::Uuid::new_v4();
    let request = authorization.into_request(request_id);

    let orchestrator = Orchestrator::new(CoreConfig::default());
    let supervisor = CallExecutionSupervisor::install(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        8,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let quic = LifecycleTestAdapter::new(Transport::Quic);
    orchestrator
        .register(Arc::clone(&quic) as Arc<dyn ConnectionAdapter>)
        .unwrap();
    let gateway_principal = AuthenticatedPrincipal {
        subject: "private-gateway".into(),
        tenant: Some("execution-tenant".into()),
        scopes: vec![PRIVATE_FORWARD_SCOPE.into(), UCTP_SESSION_SCOPE.into()],
        issuer: Some("bridgefu-private-forwarding".into()),
        expires_at: None,
        method: AuthenticationMethod::MutualTls,
        assurance: IdentityAssurance::Anonymous,
    };

    let connection_id = ConnectionId::new();
    quic.prepare_inbound(
        connection_id.clone(),
        &gateway_principal,
        request.to_routing_hint().unwrap(),
        AcceptEvents::Connected,
    );
    quic.announce_inbound(connection_id.clone(), gateway_principal.clone())
        .await;
    wait_for_accepted(&quic, &connection_id).await;
    let stored = wait_for_call(&runtime, created.call_id, |stored| {
        stored
            .call
            .bindings
            .get(&created.sip_leg)
            .is_some_and(|binding| binding.connection_id == connection_id)
    })
    .await;
    let response = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(message) = quic.take_sent_data(&connection_id) {
                break message;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("post-activation private receipt");
    let receipt = WorkerAttachmentAdmissionResponse::from_data_message(response)
        .unwrap()
        .into_receipt(request_id, worker)
        .unwrap();
    assert_eq!(receipt.call_id, created.call_id);
    assert_eq!(receipt.leg_id, created.sip_leg);
    assert_eq!(
        receipt.binding_generation,
        stored.call.bindings[&created.sip_leg].binding_generation
    );

    let replay_id = ConnectionId::new();
    quic.prepare_inbound(
        replay_id.clone(),
        &gateway_principal,
        request.to_routing_hint().unwrap(),
        AcceptEvents::Connected,
    );
    quic.announce_inbound(replay_id.clone(), gateway_principal)
        .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while quic.counts.reject.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("replayed private attachment rejected");
    assert!(!quic.route_is_live(&replay_id));
    assert!(quic.take_sent_data(&replay_id).is_none());

    stop_harness(supervisor, orchestrator).await;
}

#[tokio::test]
async fn remote_terminal_tears_down_peer_and_retiring_actor_does_not_consume_capacity() {
    let (runtime, orchestrator, supervisor, sip, webrtc) = execution_harness(1).await;
    let first = create_inbound_call(&runtime, "execution-capacity-first").await;
    let owner = principal().authenticated().clone();
    let first_sip = attach(&sip, &owner, first.sip_token, AcceptEvents::Connected).await;
    let first_webrtc = attach(&webrtc, &owner, first.webrtc_token, AcceptEvents::Connected).await;
    wait_for_call(&runtime, first.call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;

    sip.remote_end(first_sip).await;
    wait_for_call(&runtime, first.call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    assert!(webrtc
        .counts
        .ended_connections
        .lock()
        .unwrap()
        .contains(&first_webrtc));

    // The first actor intentionally remains for a one-second late-event
    // quiet window. Durable worker capacity is already free, so a replacement
    // call must not be rejected by that retiring actor's slot.
    let second = create_inbound_call(&runtime, "execution-capacity-second").await;
    let second_sip = attach(&sip, &owner, second.sip_token, AcceptEvents::Connected).await;
    wait_for_accepted(&sip, &second_sip).await;
    let second_bound = wait_for_call(&runtime, second.call_id, |stored| {
        stored
            .call
            .aggregate
            .leg(second.sip_leg)
            .is_some_and(|leg| leg.state() == LegState::Connected)
    })
    .await;
    assert_eq!(
        second_bound
            .call
            .bindings
            .get(&second.sip_leg)
            .unwrap()
            .connection_id,
        second_sip
    );
    assert_ne!(
        second_bound
            .call
            .aggregate
            .leg(second.sip_leg)
            .unwrap()
            .failure()
            .map(|failure| failure.code()),
        Some("execution_unavailable")
    );

    stop_harness(supervisor, orchestrator).await;
}

async fn run_bounded_telnyx_replacement_test(future: impl std::future::Future<Output = ()>) {
    tokio::time::timeout(Duration::from_secs(20), future)
        .await
        .expect("Telnyx replacement scenario exceeded its hard test timeout");
}

#[tokio::test]
async fn direct_browser_handoff_status_is_monotonic_and_destination_cannot_spoof_it() {
    run_bounded_telnyx_replacement_test(async {
        let (runtime, orchestrator, supervisor, _sip, webrtc, provider) =
            telnyx_replacement_harness(Duration::from_secs(10)).await;
        let call = activate_direct_browser_call(
            &runtime,
            &orchestrator,
            &webrtc,
            "execution-handoff-status-success-call",
        )
        .await;
        let pending_generation = call.destination_generation.next().unwrap();

        let forged = HandoffStatusEnvelope::new(
            call.call_id,
            call.destination_leg_id,
            pending_generation,
            HandoffStatusKind::Connected,
            None,
        )
        .to_data_message()
        .unwrap();
        webrtc
            .emit_data_message(call.destination_connection_id.clone(), forged)
            .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        while let Some(message) = webrtc.take_sent_data(&call.source_connection_id) {
            assert_ne!(
                message.label, HANDOFF_STATUS_LABEL,
                "the held assistant must not spoof the server-owned handoff channel"
            );
        }

        start_telnyx_replacement(&runtime, &call, "execution-handoff-status-success-command").await;
        provider.wait_for_start_count(1).await;
        accept_telnyx_replacement_ready(
            &runtime,
            call.call_id,
            call.destination_leg_id,
            pending_generation,
            0xc1,
        )
        .await;
        let active = wait_for_call(&runtime, call.call_id, |stored| {
            let state = stored.call.aggregate.state();
            let replacement_present = stored.call.aggregate.replacement().is_some();
            let observed_generation = stored
                .call
                .bindings
                .get(&call.destination_leg_id)
                .map(|binding| binding.binding_generation);
            tracing::debug!(
                ?state,
                replacement_present,
                ?observed_generation,
                ?pending_generation,
                "observed Telnyx replacement qualification state"
            );
            state == CallState::Active
                && !replacement_present
                && observed_generation == Some(pending_generation)
        })
        .await;
        wait_for_active_bridge_count(&orchestrator, 1).await;
        let statuses = wait_for_handoff_status(
            &webrtc,
            &call.source_connection_id,
            HandoffStatusKind::Connected,
        )
        .await;
        assert_handoff_sequence(
            &statuses,
            &call,
            pending_generation,
            &[
                HandoffStatusKind::Preparing,
                HandoffStatusKind::Ringing,
                HandoffStatusKind::Attaching,
                HandoffStatusKind::Connected,
            ],
        );
        assert_eq!(
            active.call.bindings[&call.destination_leg_id].binding_generation, pending_generation,
            "connected must be emitted only for the promoted generation"
        );

        stop_harness(supervisor, orchestrator).await;
    })
    .await;
}

#[tokio::test]
async fn failed_direct_browser_handoff_reports_resumed_only_after_old_graph_is_restored() {
    run_bounded_telnyx_replacement_test(async {
        let (runtime, orchestrator, supervisor, _sip, webrtc, provider) =
            telnyx_replacement_harness(Duration::from_secs(10)).await;
        let call = activate_direct_browser_call(
            &runtime,
            &orchestrator,
            &webrtc,
            "execution-handoff-status-resume-call",
        )
        .await;
        let pending_generation = call.destination_generation.next().unwrap();
        provider.fail_next_destination(ProviderExecutionError::Remote { retryable: false });

        start_telnyx_replacement(&runtime, &call, "execution-handoff-status-resume-command").await;
        provider.wait_for_start_count(1).await;
        let resumed = wait_for_call(&runtime, call.call_id, |stored| {
            stored.call.aggregate.state() == CallState::Active
                && stored.call.aggregate.replacement().is_none()
                && stored
                    .call
                    .bindings
                    .get(&call.destination_leg_id)
                    .is_some_and(|binding| {
                        binding.binding_generation == call.destination_generation
                            && binding.connection_id == call.destination_connection_id
                    })
        })
        .await;
        wait_for_active_bridge_count(&orchestrator, 1).await;
        let statuses = wait_for_handoff_status(
            &webrtc,
            &call.source_connection_id,
            HandoffStatusKind::Resumed,
        )
        .await;
        assert_handoff_sequence(
            &statuses,
            &call,
            pending_generation,
            &[
                HandoffStatusKind::Preparing,
                HandoffStatusKind::Ringing,
                HandoffStatusKind::Attaching,
                HandoffStatusKind::Resumed,
            ],
        );
        assert_eq!(
            resumed.call.bindings[&call.destination_leg_id].connection_id,
            call.destination_connection_id,
            "resumed must be emitted only after the old durable binding is restored"
        );

        stop_harness(supervisor, orchestrator).await;
    })
    .await;
}

#[tokio::test]
async fn signed_telnyx_destination_failure_before_ready_resumes_held_assistant() {
    run_bounded_telnyx_replacement_test(async {
        let (runtime, orchestrator, supervisor, _sip, webrtc, provider) =
            telnyx_replacement_harness(Duration::from_secs(10)).await;
        let call = activate_direct_browser_call(
            &runtime,
            &orchestrator,
            &webrtc,
            "execution-handoff-signed-failure-call",
        )
        .await;
        let pending_generation = call.destination_generation.next().unwrap();

        start_telnyx_replacement(&runtime, &call, "execution-handoff-signed-failure-command").await;
        provider.wait_for_start_count(1).await;
        ingest_telnyx_replacement_destination_event(
            &runtime,
            call.call_id,
            call.destination_leg_id,
            pending_generation,
            "call.failed",
            0xcd,
        )
        .await;

        let resumed = wait_for_call(&runtime, call.call_id, |stored| {
            stored.call.aggregate.state() == CallState::Active
                && stored.call.aggregate.replacement().is_none()
                && stored
                    .call
                    .bindings
                    .get(&call.destination_leg_id)
                    .is_some_and(|binding| {
                        binding.binding_generation == call.destination_generation
                            && binding.connection_id == call.destination_connection_id
                    })
        })
        .await;
        wait_for_active_bridge_count(&orchestrator, 1).await;
        let statuses = wait_for_handoff_status(
            &webrtc,
            &call.source_connection_id,
            HandoffStatusKind::Resumed,
        )
        .await;
        assert_handoff_sequence(
            &statuses,
            &call,
            pending_generation,
            &[
                HandoffStatusKind::Preparing,
                HandoffStatusKind::Ringing,
                HandoffStatusKind::Attaching,
                HandoffStatusKind::Resumed,
            ],
        );
        assert_eq!(
            resumed.call.bindings[&call.destination_leg_id].connection_id,
            call.destination_connection_id
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while provider.hangup_snapshot().is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("failed pending Telnyx media call was not cleaned up");
        assert_eq!(provider.hangup_snapshot().len(), 1);
        assert_eq!(
            provider.hangup_snapshot()[0].0.binding_generation,
            pending_generation
        );
        assert!(webrtc.route_is_live(&call.destination_connection_id));

        stop_harness(supervisor, orchestrator).await;
    })
    .await;
}

#[tokio::test]
async fn rejected_telnyx_sip_attachment_retires_owner_and_same_profile_retry_succeeds() {
    run_bounded_telnyx_replacement_test(async {
        let (runtime, orchestrator, supervisor, sip, _webrtc, provider) =
            telnyx_replacement_harness(Duration::from_secs(10)).await;
        let call = activate_replaceable_call(
            &runtime,
            &orchestrator,
            &sip,
            "execution-replacement-reject-then-retry-call",
        )
        .await;
        let first_pending_generation = call.destination_generation.next().unwrap();
        let retry_generation = first_pending_generation.next().unwrap();
        let first_destination = provider.gate_next_destination();
        provider.fail_next_destination(ProviderExecutionError::Remote { retryable: false });

        start_telnyx_replacement(
            &runtime,
            &call,
            "execution-replacement-reject-first-command",
        )
        .await;
        provider.wait_for_start_count(1).await;
        first_destination.0.wait().await;
        let first_pending_connection = provider
            .attachment_connection(first_pending_generation)
            .expect("first replacement SIP attachment was registered");
        sip.remote_end(first_pending_connection.clone()).await;

        let resumed = wait_for_call(&runtime, call.call_id, |stored| {
            stored.call.aggregate.state() == CallState::Active
                && stored.call.aggregate.replacement().is_none()
                && stored
                    .call
                    .bindings
                    .get(&call.destination_leg_id)
                    .is_some_and(|binding| {
                        binding.connection_id == call.destination_connection_id
                            && binding.binding_generation == call.destination_generation
                    })
        })
        .await;
        assert_eq!(
            resumed.call.bindings[&call.destination_leg_id].connection_id,
            call.destination_connection_id
        );
        first_destination.1.wait().await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while provider.hangup_snapshot().is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("rejected replacement provider call was not cleaned up");

        start_telnyx_replacement(
            &runtime,
            &call,
            "execution-replacement-retry-second-command",
        )
        .await;
        provider.wait_for_start_count(2).await;
        accept_telnyx_replacement_ready(
            &runtime,
            call.call_id,
            call.destination_leg_id,
            retry_generation,
            0xc3,
        )
        .await;
        let retried = wait_for_call(&runtime, call.call_id, |stored| {
            stored.call.aggregate.state() == CallState::Active
                && stored.call.aggregate.replacement().is_none()
                && stored
                    .call
                    .bindings
                    .get(&call.destination_leg_id)
                    .is_some_and(|binding| {
                        binding.binding_generation == retry_generation
                            && binding.connection_id != call.destination_connection_id
                    })
        })
        .await;
        let retried_connection = retried.call.bindings[&call.destination_leg_id]
            .connection_id
            .clone();
        assert_ne!(retried_connection, first_pending_connection);
        assert_eq!(provider.destination_count(), 2);
        tokio::time::timeout(Duration::from_secs(5), async {
            while !sip.route_is_live(&retried_connection) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("retried replacement route did not become live");
        assert!(sip.route_is_live(&retried_connection));

        stop_harness(supervisor, orchestrator).await;
    })
    .await;
}

#[tokio::test]
async fn stale_provider_generation_cannot_regress_direct_browser_handoff_status() {
    run_bounded_telnyx_replacement_test(async {
        let (runtime, orchestrator, supervisor, _sip, webrtc, provider) =
            telnyx_replacement_harness(Duration::from_secs(10)).await;
        let call = activate_direct_browser_call(
            &runtime,
            &orchestrator,
            &webrtc,
            "execution-handoff-status-stale-call",
        )
        .await;
        let first_generation = call.destination_generation.next().unwrap();
        start_telnyx_replacement(
            &runtime,
            &call,
            "execution-handoff-status-stale-first-command",
        )
        .await;
        accept_telnyx_replacement_ready(
            &runtime,
            call.call_id,
            call.destination_leg_id,
            first_generation,
            0xc5,
        )
        .await;
        wait_for_call(&runtime, call.call_id, |stored| {
            stored.call.aggregate.state() == CallState::Active
                && stored.call.aggregate.replacement().is_none()
                && stored
                    .call
                    .bindings
                    .get(&call.destination_leg_id)
                    .is_some_and(|binding| binding.binding_generation == first_generation)
        })
        .await;
        let first_statuses = wait_for_handoff_status(
            &webrtc,
            &call.source_connection_id,
            HandoffStatusKind::Connected,
        )
        .await;
        assert_handoff_sequence(
            &first_statuses,
            &call,
            first_generation,
            &[
                HandoffStatusKind::Preparing,
                HandoffStatusKind::Ringing,
                HandoffStatusKind::Attaching,
                HandoffStatusKind::Connected,
            ],
        );

        let tenant = TenantId::parse("execution-tenant").unwrap();
        let old_media = runtime
            .service_repository()
            .load_external_reference_for_binding(
                &tenant,
                call.call_id,
                call.destination_leg_id,
                first_generation,
                ProviderReferenceRole::Media,
            )
            .await
            .unwrap()
            .expect("first replacement media reference");
        let old_media_effect_id = old_media.effect_id;
        let (account, provider_call_id) = match old_media.value {
            ExternalReferenceValue::ProviderCall {
                account,
                provider_call_id,
            } => (account, provider_call_id),
            ExternalReferenceValue::Signaling { .. } => {
                panic!("Telnyx media reference must be provider-owned")
            }
        };

        let gate = provider.gate_next_destination();
        let next_generation = first_generation.next().unwrap();
        start_telnyx_replacement(
            &runtime,
            &call,
            "execution-handoff-status-stale-second-command",
        )
        .await;
        provider.wait_for_start_count(2).await;
        gate.0.wait().await;

        let received_at = Utc::now();
        let stale_context = ProviderExecutionContext {
            tenant_id: tenant.clone(),
            call_id: call.call_id,
            leg_id: call.destination_leg_id,
            binding_generation: first_generation,
            effect_id: old_media_effect_id,
        };
        let stale_ringing = ProviderEventInput {
            account,
            event_digest: ProviderEventDigest::new([0xb1; 32]),
            payload_digest: ProviderPayloadDigest::new([0xb2; 32]),
            provider_call_id,
            kind: "call.ringing".into(),
            payload: telnyx_event_payload("call.ringing", &stale_context, ProviderDialRole::Media),
            occurred_at: Some(received_at),
            received_at,
        };
        runtime
            .repository()
            .ingest_provider_event(stale_ringing.clone())
            .await
            .unwrap();
        gate.1.wait().await;
        accept_telnyx_replacement_ready(
            &runtime,
            call.call_id,
            call.destination_leg_id,
            next_generation,
            0xc7,
        )
        .await;

        wait_for_call(&runtime, call.call_id, |stored| {
            stored.call.aggregate.state() == CallState::Active
                && stored.call.aggregate.replacement().is_none()
                && stored
                    .call
                    .bindings
                    .get(&call.destination_leg_id)
                    .is_some_and(|binding| binding.binding_generation == next_generation)
        })
        .await;
        wait_for_active_bridge_count(&orchestrator, 1).await;
        let next_statuses = wait_for_handoff_status(
            &webrtc,
            &call.source_connection_id,
            HandoffStatusKind::Connected,
        )
        .await;
        assert_handoff_sequence(
            &next_statuses,
            &call,
            next_generation,
            &[
                HandoffStatusKind::Preparing,
                HandoffStatusKind::Ringing,
                HandoffStatusKind::Attaching,
                HandoffStatusKind::Connected,
            ],
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if matches!(
                    runtime
                        .repository()
                        .ingest_provider_event(stale_ringing.clone())
                        .await
                        .unwrap(),
                    ProviderEventOutcome::Duplicate(event)
                        if event.state == ProviderEventState::Applied
                ) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("stale provider callback was not durably acknowledged");

        stop_harness(supervisor, orchestrator).await;
    })
    .await;
}

#[tokio::test]
async fn telnyx_leg_replacement_promotes_authenticated_media_and_persists_both_references_once() {
    run_bounded_telnyx_replacement_test(async {
        let (runtime, orchestrator, supervisor, sip, webrtc, provider) =
            telnyx_replacement_harness(Duration::from_secs(10)).await;
        let call = activate_replaceable_call(
            &runtime,
            &orchestrator,
            &sip,
            "execution-telnyx-replacement-success-call",
        )
        .await;
        let pending_generation = call.destination_generation.next().unwrap();

        let accepted = start_telnyx_replacement(
            &runtime,
            &call,
            "execution-telnyx-replacement-success-command",
        )
        .await;
        assert!(!accepted.replayed);
        let replayed = start_telnyx_replacement(
            &runtime,
            &call,
            "execution-telnyx-replacement-success-command",
        )
        .await;
        assert!(replayed.replayed);
        provider.wait_for_start_count(1).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if provider.destination_count() == 1 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
            "Telnyx destination did not execute after media attachment: starts={}, attachment={:?}",
            provider.start_count(),
            provider.attachment_connection(pending_generation)
        )
        });
        accept_telnyx_replacement_ready(
            &runtime,
            call.call_id,
            call.destination_leg_id,
            pending_generation,
            0xc9,
        )
        .await;

        let active = wait_for_call(&runtime, call.call_id, |stored| {
            let state = stored.call.aggregate.state();
            let replacement_present = stored.call.aggregate.replacement().is_some();
            let observed_generation = stored
                .call
                .bindings
                .get(&call.destination_leg_id)
                .map(|binding| binding.binding_generation);
            tracing::debug!(
                ?state,
                replacement_present,
                ?observed_generation,
                ?pending_generation,
                "observed Telnyx replacement promotion state"
            );
            state == CallState::Active
                && !replacement_present
                && observed_generation == Some(pending_generation)
        })
        .await;
        assert_eq!(provider.start_count(), 1);
        assert_eq!(provider.destination_count(), 1);
        let provider_connection = provider
            .attachment_connection(pending_generation)
            .expect("provider attachment connection");
        assert_eq!(
            active.call.bindings[&call.destination_leg_id].connection_id,
            provider_connection
        );
        assert!(sip.admission_was_accepted(&provider_connection));
        tokio::time::timeout(Duration::from_secs(5), async {
            while webrtc.route_is_live(&call.destination_connection_id) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("promoted replacement did not retire the exact old WebRTC route");
        assert!(!webrtc.route_is_live(&call.destination_connection_id));
        assert!(sip.route_is_live(&call.source_connection_id));

        let tenant = TenantId::parse("execution-tenant").unwrap();
        let media = runtime
            .service_repository()
            .load_external_reference_for_binding(
                &tenant,
                call.call_id,
                call.destination_leg_id,
                pending_generation,
                ProviderReferenceRole::Media,
            )
            .await
            .unwrap()
            .expect("replacement media reference");
        let destination = runtime
            .service_repository()
            .load_external_reference_for_binding(
                &tenant,
                call.call_id,
                call.destination_leg_id,
                pending_generation,
                ProviderReferenceRole::Destination,
            )
            .await
            .unwrap()
            .expect("replacement destination reference");
        assert_eq!(media.binding_generation, pending_generation);
        assert_eq!(destination.binding_generation, pending_generation);
        assert_ne!(media.value, destination.value);
        assert!(provider.hangup_snapshot().is_empty());

        let media_effect_id = media.effect_id;
        let (account, provider_call_id) = match media.value {
            ExternalReferenceValue::ProviderCall {
                account,
                provider_call_id,
            } => (account, provider_call_id),
            ExternalReferenceValue::Signaling { .. } => {
                panic!("Telnyx replacement media reference was not provider-owned")
            }
        };
        let media_context = ProviderExecutionContext {
            tenant_id: tenant.clone(),
            call_id: call.call_id,
            leg_id: call.destination_leg_id,
            binding_generation: pending_generation,
            effect_id: media_effect_id,
        };
        let received_at = Utc::now();
        runtime
            .repository()
            .ingest_provider_event(ProviderEventInput {
                account,
                event_digest: ProviderEventDigest::new([0x91; 32]),
                payload_digest: ProviderPayloadDigest::new([0x92; 32]),
                provider_call_id,
                kind: "call.hangup".into(),
                payload: telnyx_event_payload(
                    "call.hangup",
                    &media_context,
                    ProviderDialRole::Media,
                ),
                occurred_at: Some(received_at),
                received_at,
            })
            .await
            .unwrap();
        wait_for_call(&runtime, call.call_id, |stored| {
            stored.call.aggregate.state().is_terminal()
        })
        .await;

        stop_harness(supervisor, orchestrator).await;
    })
    .await;
}

#[tokio::test]
async fn failed_second_telnyx_replacement_resumes_current_leg_and_cleans_only_pending_generation() {
    run_bounded_telnyx_replacement_test(async {
        let (runtime, orchestrator, supervisor, sip, _webrtc, provider) =
            telnyx_replacement_harness(Duration::from_secs(10)).await;
        let call = activate_replaceable_call(
            &runtime,
            &orchestrator,
            &sip,
            "execution-telnyx-replacement-cross-generation-call",
        )
        .await;
        let current_generation = call.destination_generation.next().unwrap();
        start_telnyx_replacement(
            &runtime,
            &call,
            "execution-telnyx-replacement-cross-generation-first",
        )
        .await;
        accept_telnyx_replacement_ready(
            &runtime,
            call.call_id,
            call.destination_leg_id,
            current_generation,
            0xcb,
        )
        .await;
        let first = wait_for_call(&runtime, call.call_id, |stored| {
            stored.call.aggregate.state() == CallState::Active
                && stored.call.aggregate.replacement().is_none()
                && stored
                    .call
                    .bindings
                    .get(&call.destination_leg_id)
                    .is_some_and(|binding| binding.binding_generation == current_generation)
        })
        .await;
        let current_connection = first.call.bindings[&call.destination_leg_id]
            .connection_id
            .clone();
        assert!(provider.hangup_snapshot().is_empty());

        provider.fail_next_destination(ProviderExecutionError::Remote { retryable: false });
        let pending_generation = current_generation.next().unwrap();
        start_telnyx_replacement(
            &runtime,
            &call,
            "execution-telnyx-replacement-cross-generation-second",
        )
        .await;
        provider.wait_for_start_count(2).await;
        let resumed = wait_for_call(&runtime, call.call_id, |stored| {
            stored.call.aggregate.state() == CallState::Active
                && stored.call.aggregate.replacement().is_none()
                && stored
                    .call
                    .bindings
                    .get(&call.destination_leg_id)
                    .is_some_and(|binding| {
                        binding.binding_generation == current_generation
                            && binding.connection_id == current_connection
                    })
        })
        .await;
        assert_eq!(
            resumed.call.bindings[&call.destination_leg_id].binding_generation,
            current_generation
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if !provider.hangup_snapshot().is_empty() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("failed pending provider call was not cleaned up");
        let hangups = provider.hangup_snapshot();
        assert_eq!(hangups.len(), 1);
        assert_eq!(hangups[0].0.binding_generation, pending_generation);
        assert_ne!(hangups[0].0.binding_generation, current_generation);
        assert!(sip.route_is_live(&current_connection));
        assert_eq!(provider.destination_count(), 2);

        let received_at = Utc::now();
        let stale_event = ProviderEventInput {
            account: hangups[0].1.account.clone(),
            event_digest: ProviderEventDigest::new([0xa1; 32]),
            payload_digest: ProviderPayloadDigest::new([0xa2; 32]),
            provider_call_id: hangups[0].1.provider_call_id.clone(),
            kind: "call.hangup".into(),
            payload: telnyx_event_payload("call.hangup", &hangups[0].0, ProviderDialRole::Media),
            occurred_at: Some(received_at),
            received_at,
        };
        runtime
            .repository()
            .ingest_provider_event(stale_event.clone())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if matches!(
                    runtime
                        .repository()
                        .ingest_provider_event(stale_event.clone())
                        .await
                        .unwrap(),
                    ProviderEventOutcome::Duplicate(event)
                        if event.state == ProviderEventState::Applied
                ) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("stale replacement callback was not durably acknowledged");
        let after_stale_callback = runtime
            .service_repository()
            .load_service_call(&TenantId::parse("execution-tenant").unwrap(), call.call_id)
            .await
            .unwrap();
        assert_eq!(
            after_stale_callback.call.aggregate.state(),
            CallState::Active
        );
        assert_eq!(
            after_stale_callback.call.bindings[&call.destination_leg_id].binding_generation,
            current_generation
        );

        let replayed = start_telnyx_replacement(
            &runtime,
            &call,
            "execution-telnyx-replacement-cross-generation-second",
        )
        .await;
        assert!(replayed.replayed);
        assert_eq!(provider.start_count(), 2);

        stop_harness(supervisor, orchestrator).await;
    })
    .await;
}

#[tokio::test]
async fn telnyx_replacement_attachment_timeout_resumes_old_leg_without_destination_dial() {
    run_bounded_telnyx_replacement_test(async {
        let (runtime, orchestrator, supervisor, sip, webrtc, provider) =
            telnyx_replacement_harness(Duration::from_secs(2)).await;
        provider.set_auto_attach(false);
        let call = activate_replaceable_call(
            &runtime,
            &orchestrator,
            &sip,
            "execution-telnyx-replacement-attachment-timeout-call",
        )
        .await;
        start_telnyx_replacement(
            &runtime,
            &call,
            "execution-telnyx-replacement-attachment-timeout-command",
        )
        .await;
        provider.wait_for_start_count(1).await;
        let resumed = wait_for_call(&runtime, call.call_id, |stored| {
            stored.call.aggregate.state() == CallState::Active
                && stored.call.aggregate.replacement().is_none()
                && stored
                    .call
                    .bindings
                    .get(&call.destination_leg_id)
                    .is_some_and(|binding| {
                        binding.connection_id == call.destination_connection_id
                            && binding.binding_generation == call.destination_generation
                    })
        })
        .await;
        assert_eq!(
            resumed.call.bindings[&call.destination_leg_id].connection_id,
            call.destination_connection_id
        );
        assert_eq!(provider.destination_count(), 0);
        tokio::time::timeout(Duration::from_secs(5), async {
            while provider.hangup_snapshot().is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("timed-out provider media call was not cleaned up");
        assert_eq!(
            provider.hangup_snapshot()[0].0.binding_generation,
            call.destination_generation.next().unwrap()
        );
        assert!(webrtc.route_is_live(&call.destination_connection_id));

        stop_harness(supervisor, orchestrator).await;
    })
    .await;
}

#[tokio::test]
async fn source_hangup_while_telnyx_media_attaches_cancels_replacement_and_exact_provider_call() {
    run_bounded_telnyx_replacement_test(async {
        let (runtime, orchestrator, supervisor, sip, _webrtc, provider) =
            telnyx_replacement_harness(Duration::from_secs(10)).await;
        provider.set_auto_attach(false);
        let call = activate_replaceable_call(
            &runtime,
            &orchestrator,
            &sip,
            "execution-telnyx-replacement-source-hangup-call",
        )
        .await;
        let pending_generation = call.destination_generation.next().unwrap();
        start_telnyx_replacement(
            &runtime,
            &call,
            "execution-telnyx-replacement-source-hangup-command",
        )
        .await;
        provider.wait_for_start_count(1).await;
        sip.remote_end(call.source_connection_id.clone()).await;

        wait_for_call(&runtime, call.call_id, |stored| {
            stored.call.aggregate.state().is_terminal()
        })
        .await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while provider.hangup_snapshot().is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("source cancellation did not hang up pending Telnyx media");
        let hangups = provider.hangup_snapshot();
        assert_eq!(hangups.len(), 1);
        assert_eq!(hangups[0].0.binding_generation, pending_generation);
        assert_eq!(provider.destination_count(), 0);

        stop_harness(supervisor, orchestrator).await;
    })
    .await;
}
