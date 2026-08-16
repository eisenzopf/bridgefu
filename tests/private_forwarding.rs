use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bridgefu::api_principal::{ApiPrincipal, ConfiguredApiKeyValidator, PrincipalFingerprintKey};
use bridgefu::call_engine::{
    AttachmentTransport, BindingGeneration, CallId, CallState, LegDirection, LegId, LegState,
    MediaFlow, SignalingInitiator, TenantId, WorkerFence, WorkerId, WorkerLease,
};
use bridgefu::call_service::{
    build_call_service_runtime, parse_presented_attachment_token, CallExecutionSupervisor,
    CallRepositoryBackendConfig, CallServiceCoordinationConfig, CallServiceRuntime,
    CallServiceRuntimeConfig, CallTimeoutPolicy, CreateCallInput, DisabledOutboundProfileResolver,
    DisabledProviderLegExecutor, IdempotencyKey, LegEndpointConfig, NamedProfileBinding,
    NamedProfileKind, NamedProfileRole, NamedRouteBinding, ReplaceLegInput, RequestedLeg,
    SamePrincipalAttachmentResolver, SipEndpointConfig, SipInitialContextMode,
    SystemCallServiceClock, WebRtcEndpointConfig,
};
use bridgefu::context::{ContextEnvelope, ContextPolicy, CONTEXT_LABEL};
use bridgefu::coordination::{
    AttachmentRouteHint, CoordinationEvent, CoordinationPayload, CoordinationProjection,
    DeploymentId, ManualCoordinationClock, MemoryCoordinator, ProjectionSequence,
    WorkerCoordinationSnapshot,
};
use bridgefu::gateway_attachment::GatewayAttachmentResolver;
use bridgefu::gateway_forwarding::{
    admit_private_egress_worker_connection, ForwardedPacket, ForwardingHealth, GatewayForwarder,
    GatewayForwardingConfig, GatewayForwardingError, GatewayRouteKey, MutualTlsFiles,
    PrivateForwardingLimits, PrivateForwardingTimeouts, PrivateTokenKey, PrivateWorkerTarget,
    WorkerForwardingConfig, WorkerForwardingRuntime, PRIVATE_RTCP_CONTENT_TYPE, PRIVATE_RTCP_LABEL,
};
use bridgefu::gateway_native_ingress::{
    GatewayNativeIngress, GatewayNativeIngressConfig, GatewayNativeSipConfig,
    GatewayNativeWebRtcConfig,
};
use bridgefu::gateway_uctp_ingress::{GatewayIngressAdmission, GatewayUctpIngressError};
use bridgefu::private_egress::{
    PrivateEgressCommand, PrivateEgressCommandService, PrivateEgressControlClient,
    PrivateEgressEndReason, PrivateEgressLifecycleKind, PrivateEgressLifecycleState,
    PrivateEgressOperation, PrivateEgressProfile, PrivateEgressRouteAuthority,
    PrivateEgressServiceConfig, PrivateEgressSource, PrivateEgressTarget, PrivateEgressTransport,
};
use bridgefu::private_egress_stream::{
    PrivateEgressGatewayAdapters, PrivateEgressGatewayLifecycleSource,
    PrivateEgressGatewayProfileResolver, PrivateEgressGatewayProxyConfig,
    PrivateEgressGatewayProxyHandler, PrivateEgressResolvedOriginate, PrivateEgressStreamAdmission,
    PrivateEgressStreamAdmissionRegistry, PrivateEgressWorkerRouteCatalog,
    PrivateEgressWorkerRouteDescriptor, PrivateEgressWorkerRuntime,
};
use bytes::Bytes;
use chrono::Utc;
use rvoip_auth_core::BearerValidator;
use rvoip_core::adapter::{
    AdapterEvent, AdapterKind, AdapterLifecycleCapabilities, ConnectionAdapter, ConnectionHandle,
    EndReason, OriginateRequest, RejectReason, SignatureHeaders, TransferTarget,
};
use rvoip_core::capability::{
    default_audio_codec, CapabilityDescriptor, CodecInfo, NegotiatedCodecs,
};
use rvoip_core::config::Config as CoreConfig;
use rvoip_core::connection::{Connection, ConnectionState, Direction, Transport, TransportHandle};
use rvoip_core::conversation::ConversationPolicy;
use rvoip_core::error::{Result as RvoipResult, RvoipError};
use rvoip_core::events::Event;
use rvoip_core::identity::IdentityAssurance;
use rvoip_core::ids::{ConnectionId, StreamId, TenantId as RvoipTenantId};
use rvoip_core::message::Message;
use rvoip_core::operational_events::OperationalEvent;
use rvoip_core::session::SessionMedium;
use rvoip_core::stream::{MediaFrame, MediaStream, QualitySnapshot, StreamKind};
use rvoip_core::{DataMessage, DataReliability, Orchestrator};
use rvoip_media_core::codec::audio::{AudioCodec, G711Codec, OpusCodec, OpusConfig};
use rvoip_media_core::types::{AudioFrame as DecodedAudioFrame, SampleRate};
use rvoip_sip::{
    Config as SipConfig, SipInboundContextPolicy, SipListenerAuthPolicy, SipNatConfig,
};
use rvoip_webrtc::data_message::{
    decode_data_message, encode_data_message, options_for_reliability, EncodedDataMessage,
    DATA_MESSAGE_SUBPROTOCOL,
};
use rvoip_webrtc::media::dtmf::send_dtmf;
use rvoip_webrtc::media::{
    from_tracks, from_tracks_with_dtmf_codecs, from_tracks_with_dtmf_events,
};
use rvoip_webrtc::peer::{PeerRole, RvoipPeerConnection};
use rvoip_webrtc::WebRtcConfig;
use webrtc::data_channel::{DataChannel, DataChannelEvent};

struct TlsFixture {
    root: PathBuf,
    worker: MutualTlsFiles,
    gateway: MutualTlsFiles,
}

impl Drop for TlsFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn write_pem(path: &Path, label: &str, der: &[u8]) {
    let encoded = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    std::fs::write(path, pem).unwrap();
}

fn tls_fixture() -> TlsFixture {
    let root = std::env::temp_dir().join(format!("bridgefu-private-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let (worker_cert, worker_key) =
        rvoip_uctp::substrate::self_signed_for_dev(&["localhost".into()]).unwrap();
    let (gateway_cert, gateway_key) =
        rvoip_uctp::substrate::self_signed_for_dev(&["gateway.local".into()]).unwrap();
    let worker_cert_path = root.join("worker.pem");
    let worker_key_path = root.join("worker.key");
    let gateway_cert_path = root.join("gateway.pem");
    let gateway_key_path = root.join("gateway.key");
    write_pem(&worker_cert_path, "CERTIFICATE", worker_cert.as_ref());
    write_pem(&worker_key_path, "PRIVATE KEY", worker_key.secret_der());
    write_pem(&gateway_cert_path, "CERTIFICATE", gateway_cert.as_ref());
    write_pem(&gateway_key_path, "PRIVATE KEY", gateway_key.secret_der());
    TlsFixture {
        root,
        worker: MutualTlsFiles {
            certificate_chain: vec![worker_cert_path.clone()],
            private_key: worker_key_path,
            peer_ca_certificates: vec![gateway_cert_path.clone()],
        },
        gateway: MutualTlsFiles {
            certificate_chain: vec![gateway_cert_path],
            private_key: gateway_key_path,
            peer_ca_certificates: vec![worker_cert_path],
        },
    }
}

fn limits() -> PrivateForwardingLimits {
    PrivateForwardingLimits {
        max_active_routes: 8,
        max_peer_connections: 4,
        max_routes_per_peer: 1,
        media_queue_capacity: 1,
        reliable_queue_capacity: 1,
        inbound_queue_capacity: 8,
    }
}

fn timeouts() -> PrivateForwardingTimeouts {
    PrivateForwardingTimeouts {
        connect: Duration::from_secs(3),
        signaling: Duration::from_secs(3),
        token_ttl: Duration::from_secs(60),
        health_interval: Duration::from_secs(60),
    }
}

fn durable_split_timeouts() -> PrivateForwardingTimeouts {
    PrivateForwardingTimeouts {
        connect: Duration::from_secs(10),
        signaling: Duration::from_secs(15),
        token_ttl: Duration::from_secs(60),
        health_interval: Duration::from_secs(60),
    }
}

fn composite_limits() -> PrivateForwardingLimits {
    PrivateForwardingLimits {
        max_active_routes: 8,
        max_peer_connections: 2,
        max_routes_per_peer: 4,
        media_queue_capacity: 64,
        reliable_queue_capacity: 32,
        inbound_queue_capacity: 64,
    }
}

fn reserve_udp() -> SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn reserve_tcp() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn composite_runtime_config(worker_id: WorkerId) -> CallServiceRuntimeConfig {
    let mut coordination =
        CallServiceCoordinationConfig::new(DeploymentId::parse("private-composite").unwrap());
    coordination.worker_lease_ttl = Duration::from_secs(300);
    coordination.worker_renew_interval = Duration::from_secs(100);
    CallServiceRuntimeConfig {
        backend: CallRepositoryBackendConfig::Memory,
        worker_id,
        max_calls: 8,
        worker_capabilities: BTreeSet::from(["sip".into(), "webrtc".into()]),
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

fn two_inbound_webrtc_legs() -> CreateCallInput {
    let leg = || RequestedLeg {
        direction: LegDirection::Inbound,
        signaling_initiator: Some(SignalingInitiator::Remote),
        media_flow: MediaFlow::SendReceive,
        endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
            signaling_uri: None,
        }),
        amazon_connect_start: None,
    };
    CreateCallInput {
        tenant_id: None,
        legs: [leg(), leg()],
    }
}

struct CompositeGatewayAdmission;

impl GatewayIngressAdmission for CompositeGatewayAdmission {
    fn try_admit(
        &self,
    ) -> Result<
        Box<dyn bridgefu::gateway_uctp_ingress::GatewayIngressAdmissionLease>,
        GatewayUctpIngressError,
    > {
        Ok(Box::new(()))
    }
}

struct WhipClient {
    peer: Arc<RvoipPeerConnection>,
    context_channel: Arc<dyn DataChannel>,
    location: String,
    etag: String,
}

async fn attach_whip_client(
    client: &reqwest::Client,
    endpoint: SocketAddr,
    api_key: &str,
    attachment_token: &str,
) -> WhipClient {
    let peer = RvoipPeerConnection::new(&WebRtcConfig::loopback(), PeerRole::Offerer)
        .await
        .expect("construct WHIP client peer");
    let context_channel = peer
        .create_data_channel(
            CONTEXT_LABEL,
            options_for_reliability(&DataReliability::ReliableOrdered)
                .expect("context DataChannel options"),
        )
        .await
        .expect("create context DataChannel before offer");
    // create_offer_and_gather installs both the Opus and RFC 4733 tracks when
    // no local audio track was pre-created.
    let offer = peer
        .create_offer_and_gather()
        .await
        .expect("create full-gather WHIP offer");
    let response = client
        .post(format!("http://{endpoint}/whip/{attachment_token}"))
        .bearer_auth(api_key)
        .header(reqwest::header::CONTENT_TYPE, "application/sdp")
        .body(offer)
        .send()
        .await
        .expect("submit WHIP attachment");
    if response.status() != reqwest::StatusCode::CREATED {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        panic!("WHIP attachment failed with {status}: {body}");
    }
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .expect("WHIP Location")
        .to_str()
        .expect("valid WHIP Location")
        .to_owned();
    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .expect("WHIP ETag")
        .to_str()
        .expect("valid WHIP ETag")
        .to_owned();
    let answer = response.text().await.expect("WHIP answer SDP");
    peer.set_remote_answer(&answer)
        .await
        .expect("apply WHIP answer");
    peer.wait_connected(Duration::from_secs(10))
        .await
        .expect("WHIP client connected");
    RvoipPeerConnection::wait_data_channel_open(&context_channel, Duration::from_secs(10))
        .await
        .expect("context DataChannel open");
    WhipClient {
        peer,
        context_channel,
        location,
        etag,
    }
}

async fn send_data_message(channel: &Arc<dyn DataChannel>, message: &DataMessage) {
    match encode_data_message(message).expect("encode DataMessage") {
        EncodedDataMessage::Text(frame) => channel
            .send_text(&frame)
            .await
            .expect("send text DataMessage"),
        EncodedDataMessage::Binary(frame) => {
            channel.send(frame).await.expect("send binary DataMessage")
        }
    }
}

async fn receive_data_message(channel: &Arc<dyn DataChannel>) -> DataMessage {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(DataChannelEvent::OnMessage(frame)) = channel.poll().await {
                return decode_data_message(
                    CONTEXT_LABEL,
                    DATA_MESSAGE_SUBPROTOCOL,
                    DataReliability::ReliableOrdered,
                    &frame.data,
                    frame.is_string,
                )
                .expect("decode bridged DataMessage");
            }
        }
    })
    .await
    .expect("bridged DataMessage timeout")
}

async fn receive_audible_opus(
    receiver: &mut tokio::sync::mpsc::Receiver<MediaFrame>,
) -> MediaFrame {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut decoder = OpusCodec::new(SampleRate::Rate48000, 1, OpusConfig::default()).unwrap();
        loop {
            let frame = receiver.recv().await.expect("client media stream closed");
            if let Ok(decoded) = decoder.decode(&frame.payload) {
                if decoded.samples.iter().any(|sample| sample.abs() > 100) {
                    return frame;
                }
            }
        }
    })
    .await
    .expect("audible bridged Opus timeout")
}

fn active_bridge_count(orchestrator: &Orchestrator) -> u64 {
    match orchestrator.capacity_report() {
        Event::CapacityReport { active_bridges, .. } => active_bridges,
        _ => unreachable!("capacity_report always returns a capacity event"),
    }
}

async fn wait_for_bridge_count(orchestrator: &Orchestrator, expected: u64) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while active_bridge_count(orchestrator) != expected {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "bridge count did not converge: expected {expected}, observed {}",
            active_bridge_count(orchestrator)
        )
    });
}

async fn wait_for_call_state(
    runtime: &CallServiceRuntime,
    tenant: &TenantId,
    call_id: CallId,
    predicate: impl Fn(CallState) -> bool,
) -> CallState {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let stored = runtime
                .service_repository()
                .load_service_call(tenant, call_id)
                .await
                .expect("load composite call");
            let state = stored.call.aggregate.state();
            if predicate(state) {
                return state;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("durable call state timeout")
}

async fn wait_for_zero_routes(native: &GatewayNativeIngress, gateway: &GatewayForwarder) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while native.active_routes() != 0 || gateway.active_routes() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "routes did not drain: native={}, private={}",
            native.active_routes(),
            gateway.active_routes()
        )
    });
}

fn rtp(payload: &[u8], sequence: u16, timestamp: u32, ssrc: u32) -> Bytes {
    rtp_with_pt(payload, 111, sequence, timestamp, ssrc)
}

fn rtp_with_pt(
    payload: &[u8],
    payload_type: u8,
    sequence: u16,
    timestamp: u32,
    ssrc: u32,
) -> Bytes {
    let mut packet = Vec::with_capacity(12 + payload.len());
    packet.extend_from_slice(&[0x80, payload_type & 0x7f]);
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(payload);
    Bytes::from(packet)
}

async fn next_connection(events: &mut tokio::sync::broadcast::Receiver<Event>) -> ConnectionId {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(Event::ConnectionInbound { connection_id, .. }) = events.recv().await {
                return connection_id;
            }
        }
    })
    .await
    .expect("inbound private connection")
}

async fn next_data(
    events: &mut tokio::sync::broadcast::Receiver<Event>,
    connection_id: &ConnectionId,
) -> DataMessage {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(Event::DataMessageReceived {
                connection_id: incoming,
                message,
                ..
            }) = events.recv().await
            {
                if &incoming == connection_id {
                    return message;
                }
            }
        }
    })
    .await
    .expect("private DataMessage")
}

async fn next_dtmf(
    events: &mut tokio::sync::broadcast::Receiver<Event>,
    connection_id: &ConnectionId,
) -> String {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(Event::DtmfReceived {
                connection_id: incoming,
                digits,
                ..
            }) = events.recv().await
            {
                if &incoming == connection_id {
                    return digits;
                }
            }
        }
    })
    .await
    .expect("private DTMF")
}

async fn first_stream(
    worker: &WorkerForwardingRuntime,
    connection_id: ConnectionId,
) -> Arc<dyn MediaStream> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(mut streams) = worker.adapter().streams(connection_id.clone()).await {
                if let Some(stream) = streams.pop() {
                    return stream;
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("private media stream")
}

struct ProxyTestMediaStream {
    id: StreamId,
    codec: CodecInfo,
    inbound: std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<MediaFrame>>>,
    outbound: tokio::sync::mpsc::Sender<MediaFrame>,
}

#[async_trait::async_trait]
impl MediaStream for ProxyTestMediaStream {
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
        Direction::Outbound
    }

    fn frames_in(&self) -> tokio::sync::mpsc::Receiver<MediaFrame> {
        self.inbound
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .expect("proxy test receiver is single-consumer")
    }

    fn frames_out(&self) -> tokio::sync::mpsc::Sender<MediaFrame> {
        self.outbound.clone()
    }

    fn quality_snapshot(&self) -> QualitySnapshot {
        QualitySnapshot::default()
    }

    async fn close(self: Arc<Self>) -> RvoipResult<()> {
        Ok(())
    }
}

struct ProxyTestAdapter {
    transport: Transport,
    stream: std::sync::Mutex<Option<Arc<dyn MediaStream>>>,
    connection_id: std::sync::Mutex<Option<ConnectionId>>,
    events_tx: tokio::sync::mpsc::Sender<AdapterEvent>,
    events:
        std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<rvoip_core::adapter::AdapterEvent>>>,
    live: std::sync::atomic::AtomicBool,
    activated: std::sync::atomic::AtomicBool,
    ended: std::sync::atomic::AtomicBool,
    gate_activation: bool,
    activation_entries: std::sync::atomic::AtomicUsize,
    activation_completions: std::sync::atomic::AtomicUsize,
    activation_release_calls: std::sync::atomic::AtomicUsize,
    activation_started: tokio::sync::Notify,
    activation_release: tokio::sync::Semaphore,
    fail_next_activation: std::sync::atomic::AtomicBool,
    dtmf: std::sync::Mutex<Vec<(String, u32)>>,
    data: std::sync::Mutex<Vec<DataMessage>>,
    agent_to_gateway: std::sync::Mutex<Option<tokio::sync::mpsc::Sender<MediaFrame>>>,
    gateway_to_agent: tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<MediaFrame>>>,
}

impl ProxyTestAdapter {
    fn new_gated(transport: Transport) -> Arc<Self> {
        Self::new_inner(transport, true)
    }

    fn new_inner(transport: Transport, gate_activation: bool) -> Arc<Self> {
        let (events_tx, events) = tokio::sync::mpsc::channel(16);
        Arc::new(Self {
            transport,
            stream: std::sync::Mutex::new(None),
            connection_id: std::sync::Mutex::new(None),
            events_tx,
            events: std::sync::Mutex::new(Some(events)),
            live: std::sync::atomic::AtomicBool::new(false),
            activated: std::sync::atomic::AtomicBool::new(false),
            ended: std::sync::atomic::AtomicBool::new(false),
            gate_activation,
            activation_entries: std::sync::atomic::AtomicUsize::new(0),
            activation_completions: std::sync::atomic::AtomicUsize::new(0),
            activation_release_calls: std::sync::atomic::AtomicUsize::new(0),
            activation_started: tokio::sync::Notify::new(),
            activation_release: tokio::sync::Semaphore::new(0),
            fail_next_activation: std::sync::atomic::AtomicBool::new(false),
            dtmf: std::sync::Mutex::new(Vec::new()),
            data: std::sync::Mutex::new(Vec::new()),
            agent_to_gateway: std::sync::Mutex::new(None),
            gateway_to_agent: tokio::sync::Mutex::new(None),
        })
    }

    async fn receive_agent_audio(&self) -> MediaFrame {
        let mut receiver = self.gateway_to_agent.lock().await;
        tokio::time::timeout(
            Duration::from_secs(5),
            receiver
                .as_mut()
                .expect("gateway adapter has current agent media")
                .recv(),
        )
        .await
        .expect("agent audio timeout")
        .expect("agent audio channel closed")
    }

    async fn wait_for_activation(&self) {
        if self.activated.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        tokio::time::timeout(Duration::from_secs(15), self.activation_started.notified())
            .await
            .expect("gateway adapter activation did not start");
    }

    async fn wait_for_activation_after(&self, previous_entries: usize) {
        tokio::time::timeout(Duration::from_secs(15), async {
            while self
                .activation_entries
                .load(std::sync::atomic::Ordering::Acquire)
                <= previous_entries
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("gateway adapter activation did not advance");
    }

    fn release_activation(&self) {
        self.activation_release_calls
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.activation_release.add_permits(1);
    }

    fn fail_next_activation(&self) {
        self.fail_next_activation
            .store(true, std::sync::atomic::Ordering::Release);
    }

    async fn send_agent_audio(&self, frame: MediaFrame) {
        let sender = self
            .agent_to_gateway
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .expect("gateway adapter has current agent media");
        sender
            .send(frame)
            .await
            .expect("gateway adapter media receiver remains live");
    }

    fn connection_id(&self) -> ConnectionId {
        self.connection_id
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .expect("gateway adapter has an outbound Connection")
    }

    async fn emit_remote_data(&self, message: DataMessage) {
        self.events_tx
            .send(AdapterEvent::DataMessage {
                connection_id: self.connection_id(),
                message,
            })
            .await
            .expect("gateway adapter event receiver remains live");
    }

    async fn emit_remote_dtmf(&self, digits: &str, duration_ms: u32) {
        self.events_tx
            .send(AdapterEvent::Dtmf {
                connection_id: self.connection_id(),
                digits: digits.to_owned(),
                duration_ms,
            })
            .await
            .expect("gateway adapter event receiver remains live");
    }

    async fn emit_remote_progress(&self, status_code: u16, early_media: bool) {
        self.events_tx
            .send(AdapterEvent::Progress {
                connection_id: self.connection_id(),
                status_code,
                reason: "provisional".into(),
                early_media,
            })
            .await
            .expect("gateway adapter event receiver remains live");
    }

    async fn emit_remote_end(&self) {
        self.live.store(false, std::sync::atomic::Ordering::Release);
        self.events_tx
            .send(AdapterEvent::Ended {
                connection_id: self.connection_id(),
                reason: EndReason::Normal,
            })
            .await
            .expect("gateway adapter event receiver remains live");
    }
}

#[async_trait::async_trait]
impl ConnectionAdapter for ProxyTestAdapter {
    fn transport(&self) -> Transport {
        self.transport
    }

    fn kind(&self) -> AdapterKind {
        AdapterKind::Interop
    }

    fn lifecycle_capabilities(&self) -> AdapterLifecycleCapabilities {
        AdapterLifecycleCapabilities {
            staged_outbound_activation: true,
            ..AdapterLifecycleCapabilities::default()
        }
    }

    async fn originate(&self, request: OriginateRequest) -> RvoipResult<ConnectionHandle> {
        let id = ConnectionId::new();
        let codec = CodecInfo::from_name_with_defaults("opus");
        let (agent_to_gateway, inbound) = tokio::sync::mpsc::channel(16);
        let (outbound, gateway_to_agent) = tokio::sync::mpsc::channel(16);
        let stream: Arc<dyn MediaStream> = Arc::new(ProxyTestMediaStream {
            id: StreamId::new(),
            codec,
            inbound: std::sync::Mutex::new(Some(inbound)),
            outbound,
        });
        *self
            .stream
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(stream);
        *self
            .agent_to_gateway
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(agent_to_gateway);
        *self.gateway_to_agent.lock().await = Some(gateway_to_agent);
        *self
            .connection_id
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(id.clone());
        self.live.store(true, std::sync::atomic::Ordering::Release);
        self.activated
            .store(false, std::sync::atomic::Ordering::Release);
        self.ended
            .store(false, std::sync::atomic::Ordering::Release);
        Ok(ConnectionHandle::new(Connection {
            id,
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
        }))
    }

    async fn activate_outbound(&self, connection_id: ConnectionId) -> RvoipResult<()> {
        self.activation_entries
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.activation_started.notify_one();
        if self.gate_activation {
            self.activation_release
                .acquire()
                .await
                .expect("the test activation gate remains open")
                .forget();
        }
        if self
            .fail_next_activation
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            return Err(RvoipError::Adapter(
                "injected staged activation failure".into(),
            ));
        }
        self.activation_completions
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.activated
            .store(true, std::sync::atomic::Ordering::Release);
        self.events_tx
            .send(AdapterEvent::Connected { connection_id })
            .await
            .map_err(|_| RvoipError::Adapter("gateway adapter event receiver closed".into()))?;
        Ok(())
    }

    async fn accept(&self, _: ConnectionId) -> RvoipResult<()> {
        Ok(())
    }

    async fn reject(&self, _: ConnectionId, _: RejectReason) -> RvoipResult<()> {
        Ok(())
    }

    async fn end(&self, connection_id: ConnectionId, reason: EndReason) -> RvoipResult<()> {
        self.live.store(false, std::sync::atomic::Ordering::Release);
        self.ended.store(true, std::sync::atomic::Ordering::Release);
        self.events_tx
            .send(AdapterEvent::Ended {
                connection_id,
                reason,
            })
            .await
            .map_err(|_| RvoipError::Adapter("gateway adapter event receiver closed".into()))?;
        Ok(())
    }

    async fn hold(&self, _: ConnectionId) -> RvoipResult<()> {
        Ok(())
    }

    async fn resume(&self, _: ConnectionId) -> RvoipResult<()> {
        Ok(())
    }

    async fn transfer(&self, _: ConnectionId, _: TransferTarget) -> RvoipResult<()> {
        Ok(())
    }

    async fn streams(&self, connection_id: ConnectionId) -> RvoipResult<Vec<Arc<dyn MediaStream>>> {
        if self
            .connection_id
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            != Some(&connection_id)
        {
            return Err(RvoipError::ConnectionNotFound(connection_id));
        }
        self.stream
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .map(|stream| vec![stream])
            .ok_or(RvoipError::ConnectionNotFound(connection_id))
    }

    async fn send_message(&self, _: ConnectionId, _: Message) -> RvoipResult<()> {
        Ok(())
    }

    async fn send_data_message(&self, _: ConnectionId, message: DataMessage) -> RvoipResult<()> {
        self.data
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(message);
        Ok(())
    }

    async fn send_dtmf(&self, _: ConnectionId, digits: &str, duration_ms: u32) -> RvoipResult<()> {
        self.dtmf
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((digits.to_owned(), duration_ms));
        Ok(())
    }

    async fn renegotiate_media(
        &self,
        _: ConnectionId,
        _: CapabilityDescriptor,
    ) -> RvoipResult<NegotiatedCodecs> {
        Ok(NegotiatedCodecs::default())
    }

    fn subscribe_events(&self) -> tokio::sync::mpsc::Receiver<rvoip_core::adapter::AdapterEvent> {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .expect("proxy test adapter subscribed once")
    }

    fn is_connection_live(&self, connection_id: &ConnectionId) -> bool {
        self.live.load(std::sync::atomic::Ordering::Acquire)
            && self
                .connection_id
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_ref()
                == Some(connection_id)
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

/// Test equivalent of the production gateway's bounded authoritative egress
/// event branch. It deliberately consumes the Orchestrator stream rather than
/// raw adapter events, so a handler that bypasses core outbound ownership
/// cannot make remote lifecycle or application controls visible here.
struct ProxyOperationalRouter {
    routes: std::sync::Mutex<HashMap<ConnectionId, tokio::sync::mpsc::Sender<OperationalEvent>>>,
}

impl ProxyOperationalRouter {
    fn start(mut operational: tokio::sync::mpsc::Receiver<OperationalEvent>) -> Arc<Self> {
        let router = Arc::new(Self {
            routes: std::sync::Mutex::new(HashMap::new()),
        });
        let weak = Arc::downgrade(&router);
        tokio::spawn(async move {
            while let Some(event) = operational.recv().await {
                let Some(router) = weak.upgrade() else {
                    break;
                };
                let sender = router
                    .routes
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get(&event.connection_id)
                    .cloned();
                if let Some(sender) = sender {
                    let connection_id = event.connection_id.clone();
                    if sender.send(event).await.is_err() {
                        router
                            .routes
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .remove(&connection_id);
                    }
                }
            }
        });
        router
    }

    fn active_routes(&self) -> usize {
        self.routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

impl PrivateEgressGatewayLifecycleSource for ProxyOperationalRouter {
    fn subscribe(
        &self,
        connection_id: ConnectionId,
    ) -> Result<
        tokio::sync::mpsc::Receiver<OperationalEvent>,
        bridgefu::private_egress::PrivateEgressError,
    > {
        let (sender, receiver) = tokio::sync::mpsc::channel(32);
        if self
            .routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(connection_id, sender)
            .is_some()
        {
            return Err(bridgefu::private_egress::PrivateEgressError::InvalidTransition);
        }
        Ok(receiver)
    }

    fn unsubscribe(&self, connection_id: &ConnectionId) {
        self.routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(connection_id);
    }
}

struct ProxyTestProfiles;

#[async_trait::async_trait]
impl PrivateEgressGatewayProfileResolver for ProxyTestProfiles {
    async fn resolve(
        &self,
        tenant_id: &TenantId,
        transport: PrivateEgressTransport,
        profile: &PrivateEgressProfile,
        codec: &CodecInfo,
        target: &str,
        initial_context: &[(String, String)],
    ) -> Result<PrivateEgressResolvedOriginate, bridgefu::private_egress::PrivateEgressError> {
        let exact_route = match transport {
            PrivateEgressTransport::Sip => {
                profile.profile_id == "primary"
                    && profile.revision == "revision-1"
                    && target == "sips:queue@example.test"
                    && initial_context
                        == [("X-Correlation-Id".into(), "corr-egress".into())].as_slice()
            }
            PrivateEgressTransport::WebRtc => {
                profile.profile_id == "web-primary"
                    && profile.revision == "revision-2"
                    && target == "wss://agent.example.test/signaling"
                    && initial_context.is_empty()
            }
        };
        if tenant_id.as_str() != "tenant-egress"
            || !exact_route
            || codec != &CodecInfo::from_name_with_defaults("opus")
        {
            return Err(bridgefu::private_egress::PrivateEgressError::HandlerRejected);
        }
        Ok(PrivateEgressResolvedOriginate {
            capabilities: CapabilityDescriptor {
                audio_codecs: vec![CodecInfo::from_name_with_defaults("opus")],
                ..CapabilityDescriptor::default()
            },
            context: rvoip_core::adapter::OriginateContext::default(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum DurableSplitDestination {
    Sip,
    WebRtc,
}

impl DurableSplitDestination {
    fn core_transport(self) -> Transport {
        match self {
            Self::Sip => Transport::Sip,
            Self::WebRtc => Transport::WebRtc,
        }
    }

    fn route_id(self) -> &'static str {
        match self {
            Self::Sip => "split-sip",
            Self::WebRtc => "split-wss",
        }
    }

    fn profile_id(self) -> &'static str {
        match self {
            Self::Sip => "split-sip-primary",
            Self::WebRtc => "split-wss-primary",
        }
    }

    fn revision(self) -> String {
        match self {
            Self::Sip => "a".repeat(64),
            Self::WebRtc => "b".repeat(64),
        }
    }

    fn target(self) -> &'static str {
        match self {
            Self::Sip => "sips:queue@split.example.test",
            Self::WebRtc => "wss://agent.split.example.test/signaling",
        }
    }

    fn profile_kind(self) -> NamedProfileKind {
        match self {
            Self::Sip => NamedProfileKind::Sip,
            Self::WebRtc => NamedProfileKind::WebRtc,
        }
    }
}

struct DurableSplitProfiles;

#[async_trait::async_trait]
impl PrivateEgressGatewayProfileResolver for DurableSplitProfiles {
    async fn resolve(
        &self,
        tenant_id: &TenantId,
        transport: PrivateEgressTransport,
        profile: &PrivateEgressProfile,
        codec: &CodecInfo,
        target: &str,
        initial_context: &[(String, String)],
    ) -> Result<PrivateEgressResolvedOriginate, bridgefu::private_egress::PrivateEgressError> {
        let destination = match transport {
            PrivateEgressTransport::Sip => DurableSplitDestination::Sip,
            PrivateEgressTransport::WebRtc => DurableSplitDestination::WebRtc,
        };
        if tenant_id.as_str() != "private-composite-tenant"
            || profile.profile_id != destination.profile_id()
            || profile.revision != destination.revision()
            || target != destination.target()
            || !initial_context.is_empty()
            || codec != &CodecInfo::from_name_with_defaults("opus")
        {
            return Err(bridgefu::private_egress::PrivateEgressError::HandlerRejected);
        }
        Ok(PrivateEgressResolvedOriginate {
            capabilities: CapabilityDescriptor {
                audio_codecs: vec![CodecInfo::from_name_with_defaults("opus")],
                ..CapabilityDescriptor::default()
            },
            context: rvoip_core::adapter::OriginateContext::default(),
        })
    }
}

fn durable_split_destination(destination: DurableSplitDestination) -> RequestedLeg {
    let endpoint = match destination {
        DurableSplitDestination::Sip => LegEndpointConfig::Sip(SipEndpointConfig {
            uri: Some(destination.target().into()),
            initial_context: SipInitialContextMode::None,
        }),
        DurableSplitDestination::WebRtc => LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
            signaling_uri: Some(destination.target().into()),
        }),
    };
    RequestedLeg {
        direction: LegDirection::Outbound,
        signaling_initiator: Some(SignalingInitiator::Bridgefu),
        media_flow: MediaFlow::SendReceive,
        endpoint,
        amazon_connect_start: None,
    }
}

fn durable_split_call_input(destination: DurableSplitDestination) -> CreateCallInput {
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
            durable_split_destination(destination),
        ],
    }
}

fn durable_split_route(destination: DurableSplitDestination) -> NamedRouteBinding {
    NamedRouteBinding::new_with_profiles(
        destination.route_id(),
        None,
        vec![NamedProfileBinding::new(
            NamedProfileRole::Destination,
            destination.profile_kind(),
            destination.profile_id(),
            destination.revision(),
        )
        .expect("valid split destination profile")],
    )
    .expect("valid split named route")
}

fn durable_split_worker_route(
    tenant_id: &TenantId,
    destination: DurableSplitDestination,
) -> PrivateEgressWorkerRouteDescriptor {
    PrivateEgressWorkerRouteDescriptor {
        tenant_id: tenant_id.clone(),
        route_id: destination.route_id().to_owned(),
        transport: match destination {
            DurableSplitDestination::Sip => PrivateEgressTransport::Sip,
            DurableSplitDestination::WebRtc => PrivateEgressTransport::WebRtc,
        },
        profile: PrivateEgressProfile {
            profile_id: destination.profile_id().to_owned(),
            revision: destination.revision().to_owned(),
        },
        target: destination.target().to_owned(),
        codecs: vec![CodecInfo::from_name_with_defaults("opus")],
    }
}

fn private_egress_command(
    authority: &PrivateEgressRouteAuthority,
    target: PrivateEgressTarget,
    operation: PrivateEgressOperation,
) -> PrivateEgressCommand {
    let now_ms = Utc::now().timestamp_millis();
    PrivateEgressCommand::new(
        uuid::Uuid::new_v4(),
        now_ms,
        Duration::from_secs(10),
        authority.worker,
        authority.source.clone(),
        target,
        operation,
    )
    .unwrap()
}

struct DurableSplitHarness {
    runtime: Arc<CallServiceRuntime>,
    owner: ApiPrincipal,
    coordinator: Arc<MemoryCoordinator>,
    deployment: DeploymentId,
    projection_sequence: std::sync::atomic::AtomicI64,
    fingerprint_key: Vec<u8>,
    native: Arc<GatewayNativeIngress>,
    gateway: Arc<GatewayForwarder>,
    worker_orchestrator: Arc<Orchestrator>,
    proxy: Arc<PrivateEgressGatewayProxyHandler>,
    private_egress: Arc<PrivateEgressWorkerRuntime>,
}

impl DurableSplitHarness {
    async fn run_route(
        &self,
        destination: DurableSplitDestination,
        adapter: Arc<ProxyTestAdapter>,
        replacement_adapter: Option<Arc<ProxyTestAdapter>>,
    ) {
        let route_activation_baseline = adapter
            .activation_entries
            .load(std::sync::atomic::Ordering::Acquire);
        let mut private_lifecycle = self.private_egress.control().subscribe_lifecycle();
        let idempotency = format!("durable-{}-route", destination.route_id());
        let created = self
            .runtime
            .service()
            .create_named_route_call(
                &self.owner,
                &IdempotencyKey::parse(idempotency).unwrap(),
                durable_split_call_input(destination),
                durable_split_route(destination),
            )
            .await
            .expect("create exact durable split route");
        let call_id = created.value.call.call_id;
        let tenant = created.value.call.tenant_id.clone();
        let source_leg = created.value.call.legs[0].leg_id;
        let destination_leg = created.value.call.legs[1].leg_id;
        let attachment = created.value.call.legs[0]
            .attachment
            .as_ref()
            .expect("split browser attachment")
            .clone();
        assert_eq!(attachment.transport, AttachmentTransport::WebRtc);

        let sequence = self
            .projection_sequence
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let tenant_binding = PrincipalFingerprintKey::new(self.fingerprint_key.clone())
            .unwrap()
            .derive(&self.owner);
        self.coordinator
            .apply(&CoordinationEvent {
                deployment: self.deployment.clone(),
                sequence: ProjectionSequence::from_i64(sequence).unwrap(),
                payload: CoordinationPayload::AttachmentRoute(AttachmentRouteHint {
                    token_digest: parse_presented_attachment_token(attachment.token.clone())
                        .unwrap()
                        .digest(),
                    worker: self.runtime.worker().lease,
                    route_catalog_fingerprint: None,
                    transport: attachment.transport,
                    tenant_binding,
                    expires_at: attachment.expires_at,
                }),
                recorded_at: Utc::now(),
            })
            .await
            .expect("project exact split attachment");
        let projection: Arc<dyn CoordinationProjection> = self.coordinator.clone();
        GatewayAttachmentResolver::new(projection, self.fingerprint_key.clone())
            .expect("construct split projection preflight")
            .resolve(
                self.owner.authenticated().clone(),
                attachment.token.clone(),
                AttachmentTransport::WebRtc,
                Utc::now(),
            )
            .await
            .expect("split attachment projection and principal fingerprint must match");

        let http = reqwest::Client::new();
        let endpoint = self.native.whip_whep_addr();
        let attachment_token = attachment.token.clone();
        let mut attach = tokio::spawn(async move {
            attach_whip_client(
                &http,
                endpoint,
                "private-composite-api-key",
                &attachment_token,
            )
            .await
        });

        let mut attached = None;
        tokio::select! {
            _ = adapter.wait_for_activation_after(route_activation_baseline) => {}
            result = &mut attach => match result {
                Ok(client) => attached = Some(client),
                Err(error) => {
                    let stored = self
                        .runtime
                        .service_repository()
                        .load_service_call(&tenant, call_id)
                        .await
                        .expect("load split call after source attachment failure");
                    panic!(
                        "source attachment ended before destination activation: {error}; call_state={:?}; source_state={:?}; source_failure={:?}; destination_state={:?}; destination_failure={:?}; bindings={}; native_routes={}; gateway_routes={}; private_admissions={}",
                        stored.call.aggregate.state(),
                        stored.call.aggregate.leg(source_leg).map(|leg| leg.state()),
                        stored.call.aggregate.leg(source_leg).and_then(|leg| leg.failure()).map(|failure| (failure.code(), failure.message(), failure.retryable())),
                        stored.call.aggregate.leg(destination_leg).map(|leg| leg.state()),
                        stored.call.aggregate.leg(destination_leg).and_then(|leg| leg.failure()).map(|failure| (failure.code(), failure.message(), failure.retryable())),
                        stored.call.bindings.len(),
                        self.native.active_routes(),
                        self.gateway.active_routes(),
                        self.private_egress.admissions().active_admissions(),
                    );
                }
            }
        }
        assert!(
            attached.is_none(),
            "the public WHIP final answer must remain gated after the staged receipt until the destination is media-ready"
        );
        let signing = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let stored = self
                    .runtime
                    .service_repository()
                    .load_service_call(&tenant, call_id)
                    .await
                    .expect("load split call before activation");
                if stored.call.bindings.contains_key(&destination_leg)
                    && stored
                        .call
                        .aggregate
                        .leg(destination_leg)
                        .is_some_and(|leg| leg.state() == LegState::Signaling)
                {
                    break stored;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        let signing = match signing {
            Ok(signing) => signing,
            Err(_) => {
                let stored = self
                    .runtime
                    .service_repository()
                    .load_service_call(&tenant, call_id)
                    .await
                    .expect("load split call after destination binding timeout");
                panic!(
                    "destination was not durably bound before activation; destination={destination:?}; call_state={:?}; source_state={:?}; source_failure={:?}; destination_state={:?}; destination_failure={:?}; source_bound={}; destination_bound={}; bindings={}; native_routes={}; gateway_routes={}; proxy_routes={}; private_admissions={}; activation_entries={}; activation_completions={}; activation_release_calls={}; activation_permits={}",
                    stored.call.aggregate.state(),
                    stored.call.aggregate.leg(source_leg).map(|leg| leg.state()),
                    stored.call.aggregate.leg(source_leg).and_then(|leg| leg.failure()).map(|failure| (failure.code(), failure.message(), failure.retryable())),
                    stored.call.aggregate.leg(destination_leg).map(|leg| leg.state()),
                    stored.call.aggregate.leg(destination_leg).and_then(|leg| leg.failure()).map(|failure| (failure.code(), failure.message(), failure.retryable())),
                    stored.call.bindings.contains_key(&source_leg),
                    stored.call.bindings.contains_key(&destination_leg),
                    stored.call.bindings.len(),
                    self.native.active_routes(),
                    self.gateway.active_routes(),
                    self.proxy.active_routes(),
                    self.private_egress.admissions().active_admissions(),
                    adapter.activation_entries.load(std::sync::atomic::Ordering::Acquire),
                    adapter.activation_completions.load(std::sync::atomic::Ordering::Acquire),
                    adapter.activation_release_calls.load(std::sync::atomic::Ordering::Acquire),
                    adapter.activation_release.available_permits(),
                );
            }
        };
        let destination_binding = signing.call.bindings.get(&destination_leg).unwrap();
        let source_binding = signing.call.bindings.get(&source_leg).unwrap();
        let previous_destination_connection = destination_binding.connection_id.clone();
        assert_eq!(
            destination_binding.binding_generation,
            BindingGeneration::INITIAL
        );
        assert_eq!(
            destination_binding.transport,
            match destination {
                DurableSplitDestination::Sip => AttachmentTransport::Sip,
                DurableSplitDestination::WebRtc => AttachmentTransport::WebRtc,
            }
        );
        assert_eq!(active_bridge_count(&self.worker_orchestrator), 0);

        adapter.emit_remote_progress(183, true).await;
        match destination {
            DurableSplitDestination::Sip => {
                let progress =
                    tokio::time::timeout(Duration::from_secs(10), private_lifecycle.recv())
                        .await
                        .expect("SIP Progress must reach the worker before final activation")
                        .expect("private SIP lifecycle channel remains live");
                assert_eq!(progress.source_connection, source_binding.connection_id);
                assert_eq!(progress.event.worker, self.runtime.worker().lease);
                assert_eq!(progress.event.source.tenant_id, tenant);
                assert_eq!(progress.event.source.call_id, call_id);
                assert_eq!(progress.event.source.leg_id, source_leg);
                assert_eq!(
                    progress.event.source.binding_generation,
                    source_binding.binding_generation
                );
                assert_eq!(progress.event.target.leg_id, destination_leg);
                assert_eq!(
                    progress.event.target.binding_generation,
                    destination_binding.binding_generation
                );
                assert_eq!(
                    progress.event.kind,
                    PrivateEgressLifecycleKind::Progress {
                        status_code: 183,
                        early_media: true,
                    }
                );
                assert!(progress.event.sequence > 0);
                assert!(
                    !attach.is_finished(),
                    "SIP Progress must not release the final WHIP answer"
                );
            }
            DurableSplitDestination::WebRtc => {
                assert!(
                    tokio::time::timeout(Duration::from_millis(200), private_lifecycle.recv(),)
                        .await
                        .is_err(),
                    "WebRTC egress must not manufacture a SIP Progress lifecycle"
                );
            }
        }
        adapter.release_activation();

        let client = attach.await.expect("split WHIP attachment task");
        // The Activate response, not the adapter's initial Connected event, is
        // authoritative. Receiving SIP Progress above while `attach` was still
        // pending and observing Active only after releasing the adapter proves
        // the required Progress -> Active order without two state writers.
        assert_eq!(
            wait_for_call_state(&self.runtime, &tenant, call_id, |state| state
                == CallState::Active)
            .await,
            CallState::Active
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), private_lifecycle.recv())
                .await
                .is_err(),
            "the initial adapter Connected event must not duplicate Activate promotion"
        );
        wait_for_bridge_count(&self.worker_orchestrator, 1).await;
        assert_eq!(self.proxy.active_routes(), 1);
        assert_eq!(self.private_egress.admissions().active_admissions(), 1);

        let codec = CodecInfo::from_name_with_defaults("opus");
        let mut encoder = OpusCodec::new(SampleRate::Rate48000, 1, OpusConfig::default()).unwrap();
        let browser_payload = Bytes::from(
            encoder
                .encode(&DecodedAudioFrame::new(
                    (0..960)
                        .map(|index| if index % 96 < 48 { 1_900 } else { -1_900 })
                        .collect(),
                    48_000,
                    1,
                    48_000,
                ))
                .unwrap(),
        );
        let mut agent_encoder =
            OpusCodec::new(SampleRate::Rate48000, 1, OpusConfig::default()).unwrap();
        let agent_payload = Bytes::from(
            agent_encoder
                .encode(&DecodedAudioFrame::new(
                    (0..960)
                        .map(|index| if index % 120 < 60 { 2_700 } else { -2_700 })
                        .collect(),
                    48_000,
                    1,
                    57_600,
                ))
                .unwrap(),
        );
        for offset in 0..4_u32 {
            adapter
                .send_agent_audio(MediaFrame {
                    stream_id: StreamId::new(),
                    kind: StreamKind::Audio,
                    payload: agent_payload.clone(),
                    timestamp_rtp: 57_600 + offset * 960,
                    captured_at: Utc::now(),
                    payload_type: Some(111),
                })
                .await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let remote = client
            .peer
            .wait_remote_track(Duration::from_secs(10))
            .await
            .expect("browser receives split destination Opus track");
        let (browser_dtmf_tx, mut browser_dtmf_rx) = tokio::sync::mpsc::channel(4);
        let browser_stream = from_tracks_with_dtmf_events(
            StreamId::new(),
            codec,
            client
                .peer
                .local_audio_track()
                .expect("browser local audio"),
            client
                .peer
                .local_audio_ssrc()
                .expect("browser local audio SSRC"),
            111,
            Some(remote),
            Some(browser_dtmf_tx),
        );
        let mut browser_media = browser_stream.frames_in();
        for offset in 4..8_u32 {
            adapter
                .send_agent_audio(MediaFrame {
                    stream_id: StreamId::new(),
                    kind: StreamKind::Audio,
                    payload: agent_payload.clone(),
                    timestamp_rtp: 57_600 + offset * 960,
                    captured_at: Utc::now(),
                    payload_type: Some(111),
                })
                .await;
            browser_stream
                .frames_out()
                .send(MediaFrame {
                    stream_id: browser_stream.id(),
                    kind: StreamKind::Audio,
                    payload: browser_payload.clone(),
                    timestamp_rtp: 48_000 + offset * 960,
                    captured_at: Utc::now(),
                    payload_type: Some(111),
                })
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            adapter.receive_agent_audio().await.payload,
            browser_payload,
            "caller media crosses the durable actor and destination UCTP route"
        );
        let received_agent = receive_audible_opus(&mut browser_media).await;
        assert_eq!(received_agent.payload_type, Some(111));

        let browser_context = ContextEnvelope::new(
            format!("{}-browser", destination.route_id()),
            tenant.as_str(),
            call_id.to_string(),
            source_leg.to_string(),
        )
        .to_data_message()
        .unwrap();
        send_data_message(&client.context_channel, &browser_context).await;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if adapter
                    .data
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .contains(&browser_context)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("browser DataMessage did not reach split destination");

        let remote_context = ContextEnvelope::new(
            format!("{}-remote", destination.route_id()),
            tenant.as_str(),
            call_id.to_string(),
            destination_leg.to_string(),
        )
        .to_data_message()
        .unwrap();
        adapter.emit_remote_data(remote_context.clone()).await;
        assert_eq!(
            receive_data_message(&client.context_channel).await,
            remote_context
        );

        send_dtmf(&client.peer, "5", 120)
            .await
            .expect("send browser RFC 4733 to split destination");
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if adapter
                    .dtmf
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .iter()
                    .any(|(digits, duration)| digits == "5" && *duration >= 120)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("browser DTMF did not reach split destination");
        adapter.emit_remote_dtmf("8", 140).await;
        let remote_dtmf = tokio::time::timeout(Duration::from_secs(10), browser_dtmf_rx.recv())
            .await
            .expect("split destination DTMF receive timeout")
            .expect("split destination DTMF receiver remains live");
        assert_eq!(remote_dtmf.digit, '8');
        assert!(remote_dtmf.duration_ms >= 140);

        let replacement_requested = replacement_adapter.is_some();
        let terminal_adapter = match replacement_adapter {
            Some(replacement_adapter) => {
                self.exercise_split_replacement(
                    &tenant,
                    call_id,
                    destination_leg,
                    previous_destination_connection,
                    destination,
                    Arc::clone(&adapter),
                    Arc::clone(&replacement_adapter),
                )
                .await;
                replacement_adapter
            }
            None => adapter,
        };
        terminal_adapter.emit_remote_end().await;
        assert_eq!(
            wait_for_call_state(&self.runtime, &tenant, call_id, CallState::is_terminal).await,
            CallState::Ended
        );
        wait_for_bridge_count(&self.worker_orchestrator, 0).await;
        wait_for_zero_routes(&self.native, &self.gateway).await;
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.proxy.active_routes() != 0
                || self.private_egress.admissions().active_admissions() != 0
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("split destination ownership did not retire exactly");
        if tokio::time::timeout(Duration::from_secs(10), async {
            while self.gateway.shutdown_task_snapshot().total() != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .is_err()
        {
            panic!(
                "split destination left supervised gateway cleanup tasks: {:?}; destination={destination:?}; replacement_requested={replacement_requested}",
                self.gateway.shutdown_task_snapshot()
            );
        }
        client.peer.close().await.unwrap();
    }

    // Replacement qualification keeps both old and new route identities explicit; grouping
    // them would obscure which durable binding a failed assertion is diagnosing.
    #[allow(clippy::too_many_arguments)]
    async fn exercise_split_replacement(
        &self,
        tenant: &TenantId,
        call_id: CallId,
        destination_leg: LegId,
        previous_connection: ConnectionId,
        previous_destination: DurableSplitDestination,
        previous_adapter: Arc<ProxyTestAdapter>,
        replacement_adapter: Arc<ProxyTestAdapter>,
    ) {
        let previous = self
            .runtime
            .service_repository()
            .load_service_call(tenant, call_id)
            .await
            .expect("load active split call before replacement");
        let previous_binding = previous
            .call
            .bindings
            .get(&destination_leg)
            .expect("active split destination binding");
        assert_eq!(previous_binding.connection_id, previous_connection);
        let previous_generation = previous_binding.binding_generation;
        let failed_generation = previous_generation.next().unwrap();
        let successful_generation = failed_generation.next().unwrap();
        let activation_baseline = replacement_adapter
            .activation_entries
            .load(std::sync::atomic::Ordering::Acquire);

        // First drive the complete private Prepare/admission/Activate path into
        // a deterministic final-activation failure. The held generation must
        // be resumed and every pending gateway/worker resource must retire.
        replacement_adapter.fail_next_activation();
        self.runtime
            .service()
            .replace_leg(
                &self.owner,
                call_id,
                destination_leg,
                &IdempotencyKey::parse("durable-split-replacement-rejected").unwrap(),
                ReplaceLegInput {
                    tenant_id: None,
                    route_id: DurableSplitDestination::WebRtc.route_id().into(),
                },
                durable_split_destination(DurableSplitDestination::WebRtc),
                durable_split_route(DurableSplitDestination::WebRtc),
            )
            .await
            .expect("commit rejected split replacement attempt");
        replacement_adapter
            .wait_for_activation_after(activation_baseline)
            .await;
        let pending = self
            .runtime
            .service_repository()
            .load_service_call(tenant, call_id)
            .await
            .expect("load pending rejected split replacement");
        assert_eq!(pending.call.aggregate.state(), CallState::Transferring);
        assert!(pending
            .call
            .aggregate
            .replacement()
            .is_some_and(|replacement| {
                replacement.leg_id() == destination_leg
                    && replacement.previous_binding_generation() == previous_generation
                    && replacement.pending_binding_generation() == failed_generation
            }));
        assert!(pending
            .call
            .bindings
            .get(&destination_leg)
            .is_some_and(|binding| {
                binding.connection_id == previous_connection
                    && binding.binding_generation == previous_generation
            }));
        assert_eq!(active_bridge_count(&self.worker_orchestrator), 0);
        assert_eq!(self.proxy.active_routes(), 2);
        assert_eq!(self.private_egress.admissions().active_admissions(), 2);
        replacement_adapter.release_activation();

        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let stored = self
                    .runtime
                    .service_repository()
                    .load_service_call(tenant, call_id)
                    .await
                    .expect("load compensated split replacement");
                let resumed = stored.call.aggregate.state() == CallState::Active
                    && stored.call.aggregate.replacement().is_none()
                    && stored
                        .call
                        .bindings
                        .get(&destination_leg)
                        .is_some_and(|binding| {
                            binding.connection_id == previous_connection
                                && binding.binding_generation == previous_generation
                        });
                if resumed
                    && active_bridge_count(&self.worker_orchestrator) == 1
                    && self.proxy.active_routes() == 1
                    && self.private_egress.admissions().active_admissions() == 1
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("failed split replacement did not resume and clean exact resources");
        assert!(previous_adapter
            .live
            .load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(
            self.worker_orchestrator
                .connection_transport(&previous_connection)
                .unwrap(),
            Transport::Quic
        );
        assert_eq!(
            replacement_adapter
                .activation_entries
                .load(std::sync::atomic::Ordering::Acquire),
            activation_baseline + 1
        );

        // Retry with the same logical route. Attempt generations are
        // append-only, so a new one-use admission and generation-bound QUIC
        // connection are staged without reusing the failed generation, while
        // the old durable binding remains authoritative until Activate succeeds.
        self.runtime
            .service()
            .replace_leg(
                &self.owner,
                call_id,
                destination_leg,
                &IdempotencyKey::parse("durable-split-replacement-connected").unwrap(),
                ReplaceLegInput {
                    tenant_id: None,
                    route_id: DurableSplitDestination::WebRtc.route_id().into(),
                },
                durable_split_destination(DurableSplitDestination::WebRtc),
                durable_split_route(DurableSplitDestination::WebRtc),
            )
            .await
            .expect("commit successful split replacement attempt");
        replacement_adapter
            .wait_for_activation_after(activation_baseline + 1)
            .await;
        let pending = self
            .runtime
            .service_repository()
            .load_service_call(tenant, call_id)
            .await
            .expect("load pending successful split replacement");
        assert_eq!(pending.call.aggregate.state(), CallState::Transferring);
        assert!(pending
            .call
            .aggregate
            .replacement()
            .is_some_and(|replacement| {
                replacement.leg_id() == destination_leg
                    && replacement.previous_binding_generation() == previous_generation
                    && replacement.pending_binding_generation() == successful_generation
            }));
        assert!(pending
            .call
            .bindings
            .get(&destination_leg)
            .is_some_and(|binding| {
                binding.connection_id == previous_connection
                    && binding.binding_generation == previous_generation
            }));
        assert_eq!(active_bridge_count(&self.worker_orchestrator), 0);
        assert_eq!(self.proxy.active_routes(), 2);
        assert_eq!(self.private_egress.admissions().active_admissions(), 2);
        replacement_adapter.release_activation();

        let promoted = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let stored = self
                    .runtime
                    .service_repository()
                    .load_service_call(tenant, call_id)
                    .await
                    .expect("load promoted split replacement");
                let promoted = stored.call.aggregate.state() == CallState::Active
                    && stored.call.aggregate.replacement().is_none()
                    && stored
                        .call
                        .bindings
                        .get(&destination_leg)
                        .is_some_and(|binding| {
                            binding.connection_id != previous_connection
                                && binding.binding_generation == successful_generation
                                && binding.transport == AttachmentTransport::WebRtc
                        });
                if promoted
                    && active_bridge_count(&self.worker_orchestrator) == 1
                    && self.proxy.active_routes() == 1
                    && self.private_egress.admissions().active_admissions() == 1
                {
                    break stored;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        let promoted = match promoted {
            Ok(promoted) => promoted,
            Err(_) => {
                let stored = self
                    .runtime
                    .service_repository()
                    .load_service_call(tenant, call_id)
                    .await
                    .expect("load timed-out split replacement");
                let replacement = stored.call.aggregate.replacement().map(|replacement| {
                    (
                        replacement.leg_id(),
                        replacement.previous_binding_generation(),
                        replacement.pending_binding_generation(),
                    )
                });
                let binding = stored.call.bindings.get(&destination_leg).map(|binding| {
                    (
                        binding.connection_id.clone(),
                        binding.binding_generation,
                        binding.transport,
                    )
                });
                panic!(
                    "split replacement promotion/cleanup timed out: initial_destination={previous_destination:?}; replacement_destination={:?}; call_state={:?}; replacement={replacement:?}; binding={binding:?}; expected_previous_generation={:?}; expected_successful_generation={:?}; active_bridges={}; proxy_routes={}; private_admissions={}; previous_live={}; previous_ended={}; replacement_activation_entries={}; replacement_activation_completions={}",
                    DurableSplitDestination::WebRtc,
                    stored.call.aggregate.state(),
                    previous_generation,
                    successful_generation,
                    active_bridge_count(&self.worker_orchestrator),
                    self.proxy.active_routes(),
                    self.private_egress.admissions().active_admissions(),
                    previous_adapter.live.load(std::sync::atomic::Ordering::Acquire),
                    previous_adapter.ended.load(std::sync::atomic::Ordering::Acquire),
                    replacement_adapter.activation_entries.load(std::sync::atomic::Ordering::Acquire),
                    replacement_adapter.activation_completions.load(std::sync::atomic::Ordering::Acquire),
                );
            }
        };
        let current = promoted.call.bindings.get(&destination_leg).unwrap();
        assert_eq!(
            self.worker_orchestrator
                .connection_transport(&current.connection_id)
                .unwrap(),
            Transport::Quic
        );
        assert!(previous_adapter
            .ended
            .load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(
            replacement_adapter
                .activation_entries
                .load(std::sync::atomic::Ordering::Acquire),
            activation_baseline + 2
        );
    }
}

#[tokio::test]
async fn durable_actor_routes_whip_to_split_sip_and_wss_egress_with_authoritative_lifecycle() {
    const API_KEY: &str = "private-composite-api-key";
    const TENANT: &str = "private-composite-tenant";

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls = tls_fixture();
    let private_key = PrivateTokenKey::new(b"durable-split-private-key-32bytes".to_vec()).unwrap();
    let worker_id = WorkerId::new();
    let validator = Arc::new(
        ConfiguredApiKeyValidator::new(API_KEY.into(), [TENANT])
            .expect("configure exact split public bearer"),
    );
    let authenticated = validator
        .validate_principal(API_KEY)
        .await
        .expect("resolve exact split principal");
    let owner =
        ApiPrincipal::new(authenticated.clone(), Utc::now()).expect("construct split call owner");
    let tenant = TenantId::parse(TENANT).unwrap();

    let mut runtime_config = composite_runtime_config(worker_id);
    runtime_config.worker_capabilities = BTreeSet::from([
        "sip".to_owned(),
        "webrtc".to_owned(),
        "sip_egress".to_owned(),
        "webrtc_egress".to_owned(),
    ]);
    let runtime = Arc::new(
        build_call_service_runtime(
            runtime_config,
            Arc::new(SamePrincipalAttachmentResolver),
            Arc::new(SystemCallServiceClock),
        )
        .await
        .expect("start exact durable split runtime"),
    );
    assert_eq!(runtime.worker().capabilities.len(), 4);
    assert!(runtime.worker().capabilities.contains("sip_egress"));
    assert!(runtime.worker().capabilities.contains("webrtc_egress"));
    assert!(!runtime.worker().capabilities.contains("amazon_connect"));
    assert!(!runtime.worker().capabilities.contains("telnyx"));

    let worker_orchestrator = Orchestrator::new(CoreConfig::default());
    let private_control = PrivateEgressControlClient::start_authoritative(
        Arc::clone(&worker_orchestrator),
        runtime.worker().lease,
        16,
        Duration::from_secs(15),
    )
    .unwrap();
    let stream_admissions =
        PrivateEgressStreamAdmissionRegistry::new(runtime.worker().lease, 8).unwrap();
    let route_catalog = PrivateEgressWorkerRouteCatalog::new(vec![
        durable_split_worker_route(&tenant, DurableSplitDestination::Sip),
        durable_split_worker_route(&tenant, DurableSplitDestination::WebRtc),
    ])
    .unwrap();
    let private_egress = PrivateEgressWorkerRuntime::new_with_routes(
        private_control,
        Arc::clone(&stream_admissions),
        route_catalog,
        false,
    )
    .unwrap();
    let supervisor =
        CallExecutionSupervisor::install_with_leg_executors_context_canary_broadcast_profiles_and_private_egress(
            Arc::clone(&worker_orchestrator),
            Arc::clone(&runtime),
            Arc::new(DisabledProviderLegExecutor),
            None,
            Arc::new(ContextPolicy::default()),
            None,
            None,
            Arc::new(DisabledOutboundProfileResolver),
            Some(Arc::clone(&private_egress)),
            16,
            Duration::from_secs(15),
        )
        .await
        .expect("install exact split durable actor");
    let worker_forwarding = WorkerForwardingRuntime::start_with_private_egress_admissions(
        WorkerForwardingConfig {
            worker_id,
            bind: "127.0.0.1:0".parse().unwrap(),
            tls: tls.worker.clone(),
            token_key: private_key.clone(),
            limits: composite_limits(),
            timeouts: durable_split_timeouts(),
        },
        Arc::clone(&worker_orchestrator),
        Arc::clone(&stream_admissions),
    )
    .await
    .expect("start destination-capable split worker listener");
    let gateway = GatewayForwarder::start(
        GatewayForwardingConfig {
            gateway_id: "durable-split-gateway".into(),
            bind: "127.0.0.1:0".parse().unwrap(),
            tls: tls.gateway.clone(),
            token_key: private_key,
            workers: vec![PrivateWorkerTarget {
                worker_id,
                endpoint: worker_forwarding.local_addr().unwrap().to_string(),
                server_name: "localhost".into(),
            }],
            limits: composite_limits(),
            timeouts: durable_split_timeouts(),
        },
        vec![tenant.clone()],
    )
    .await
    .expect("start exact split gateway forwarder");

    // Deterministic staged destinations exercise the same Orchestrator-owned
    // lifecycle seam as the native SIP and WebRTC adapters without requiring
    // an external PBX or WSS service in this hermetic test.
    let gateway_orchestrator = Orchestrator::new(CoreConfig::default());
    let operational = gateway_orchestrator
        .install_operational_event_stream(128)
        .unwrap();
    let sip_adapter = ProxyTestAdapter::new_gated(DurableSplitDestination::Sip.core_transport());
    let wss_adapter = ProxyTestAdapter::new_gated(DurableSplitDestination::WebRtc.core_transport());
    gateway_orchestrator
        .register(Arc::clone(&sip_adapter) as Arc<dyn ConnectionAdapter>)
        .unwrap();
    gateway_orchestrator
        .register(Arc::clone(&wss_adapter) as Arc<dyn ConnectionAdapter>)
        .unwrap();
    let lifecycle = ProxyOperationalRouter::start(operational);
    let gateway_adapters = PrivateEgressGatewayAdapters::new(
        Some(Arc::clone(&sip_adapter) as Arc<dyn ConnectionAdapter>),
        Some(Arc::clone(&wss_adapter) as Arc<dyn ConnectionAdapter>),
    )
    .unwrap();
    let proxy = PrivateEgressGatewayProxyHandler::new_with_lifecycle(
        Arc::clone(&gateway),
        Arc::clone(&gateway_orchestrator),
        gateway_adapters,
        Arc::new(DurableSplitProfiles),
        Arc::clone(&lifecycle) as Arc<dyn PrivateEgressGatewayLifecycleSource>,
        PrivateEgressGatewayProxyConfig {
            media_setup_timeout: Duration::from_secs(15),
            operation_timeout: Duration::from_secs(15),
        },
    )
    .unwrap();
    let proxy_service = PrivateEgressCommandService::new(
        Arc::clone(&proxy) as Arc<dyn bridgefu::private_egress::PrivateEgressHandler>,
        PrivateEgressServiceConfig {
            max_active_routes: 8,
            max_replay_entries: 64,
            replay_ttl: Duration::from_secs(60),
            operation_timeout: Duration::from_secs(15),
        },
    )
    .unwrap();
    gateway
        .install_private_egress_service(proxy_service)
        .unwrap();

    let now = Utc::now();
    let deployment = DeploymentId::parse("durable-split-gateway").unwrap();
    let coordinator = Arc::new(
        MemoryCoordinator::new(
            deployment.clone(),
            Arc::new(ManualCoordinationClock::new(now)),
            32,
        )
        .unwrap(),
    );
    let worker = runtime.worker().clone();
    coordinator
        .apply(&CoordinationEvent {
            deployment: deployment.clone(),
            sequence: ProjectionSequence::from_i64(1).unwrap(),
            payload: CoordinationPayload::Worker(WorkerCoordinationSnapshot {
                lease: worker.lease,
                max_calls: worker.max_calls,
                reserved_calls: 0,
                draining: false,
                capabilities: worker.capabilities.clone(),
                lease_expires_at: worker.lease_expires_at,
            }),
            recorded_at: now,
        })
        .await
        .unwrap();
    let fingerprint_key = vec![0x41; 32];
    let projection: Arc<dyn CoordinationProjection> = coordinator.clone();
    let resolver = Arc::new(
        GatewayAttachmentResolver::new(projection, fingerprint_key.clone())
            .expect("construct exact split attachment resolver"),
    );
    let native = GatewayNativeIngress::start(
        GatewayNativeIngressConfig {
            sip: GatewayNativeSipConfig {
                stack: SipConfig::local("durable-split-edge", reserve_udp().port()),
                nat: SipNatConfig::default(),
                authentication: SipListenerAuthPolicy::enabled_for_tenant(TENANT)
                    .unwrap()
                    .with_trusted_cidr("127.0.0.1/32".parse().unwrap(), authenticated),
                inbound_context: SipInboundContextPolicy::default(),
                egress_profiles: Vec::new(),
            },
            webrtc: GatewayNativeWebRtcConfig {
                stack: WebRtcConfig::loopback(),
                websocket_bind: reserve_tcp().to_string(),
                whip_whep_bind: reserve_tcp().to_string(),
                tls: None,
            },
            admission_capacity: 16,
            setup_timeout: Duration::from_secs(15),
        },
        validator as Arc<dyn BearerValidator>,
        resolver,
        Arc::clone(&gateway),
        Arc::new(CompositeGatewayAdmission),
    )
    .await
    .expect("start real WHIP split source edge");

    let harness = DurableSplitHarness {
        runtime: Arc::clone(&runtime),
        owner,
        coordinator,
        deployment,
        projection_sequence: std::sync::atomic::AtomicI64::new(2),
        fingerprint_key,
        native: Arc::clone(&native),
        gateway: Arc::clone(&gateway),
        worker_orchestrator: Arc::clone(&worker_orchestrator),
        proxy: Arc::clone(&proxy),
        private_egress: Arc::clone(&private_egress),
    };
    harness
        .run_route(
            DurableSplitDestination::Sip,
            Arc::clone(&sip_adapter),
            Some(Arc::clone(&wss_adapter)),
        )
        .await;
    harness
        .run_route(
            DurableSplitDestination::WebRtc,
            Arc::clone(&wss_adapter),
            None,
        )
        .await;
    assert_eq!(lifecycle.active_routes(), 0);
    assert_eq!(proxy.active_routes(), 0);
    assert_eq!(stream_admissions.active_admissions(), 0);

    private_egress.begin_drain();
    supervisor.begin_drain();
    worker_forwarding.begin_drain();
    gateway.begin_drain();
    native.begin_drain();
    assert_eq!(
        *worker_forwarding.subscribe_health().borrow(),
        ForwardingHealth::Draining
    );
    assert_eq!(
        *gateway.subscribe_health().borrow(),
        ForwardingHealth::Draining
    );

    drop(harness);
    native.shutdown(Duration::from_secs(5)).await.unwrap();
    supervisor.shutdown(Duration::from_secs(5)).await;
    // Keep the worker's authoritative control receiver alive until the gateway
    // has drained every supervised lifecycle delivery and its durable ACK.
    gateway.shutdown(Duration::from_secs(5)).await.unwrap();
    private_egress.shutdown().await;
    worker_forwarding
        .shutdown(Duration::from_secs(5))
        .await
        .unwrap();
    gateway_orchestrator
        .drain_connection_lifecycle_tasks()
        .await;
}

#[tokio::test]
async fn split_egress_uses_a_second_generation_bound_connection_full_duplex() {
    let tls = tls_fixture();
    let token_key = PrivateTokenKey::new(b"abcdef0123456789abcdef0123456789".to_vec()).unwrap();
    let worker_id = WorkerId::new();
    let worker_lease = WorkerLease {
        worker_id,
        fence: WorkerFence::INITIAL,
    };
    let tenant = TenantId::parse("tenant-egress").unwrap();
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let mut admissions = orchestrator
        .install_inbound_admission_gate(8, Duration::from_secs(5))
        .unwrap();
    let stream_admissions = PrivateEgressStreamAdmissionRegistry::new(worker_lease, 4).unwrap();
    let worker = WorkerForwardingRuntime::start_with_private_egress_admissions(
        WorkerForwardingConfig {
            worker_id,
            bind: "127.0.0.1:0".parse().unwrap(),
            tls: tls.worker.clone(),
            token_key: token_key.clone(),
            limits: composite_limits(),
            timeouts: timeouts(),
        },
        Arc::clone(&orchestrator),
        Arc::clone(&stream_admissions),
    )
    .await
    .unwrap();
    let gateway = GatewayForwarder::start(
        GatewayForwardingConfig {
            gateway_id: "gateway-egress".into(),
            bind: "127.0.0.1:0".parse().unwrap(),
            tls: tls.gateway.clone(),
            token_key,
            workers: vec![PrivateWorkerTarget {
                worker_id,
                endpoint: worker.local_addr().unwrap().to_string(),
                server_name: "localhost".into(),
            }],
            limits: composite_limits(),
            timeouts: timeouts(),
        },
        vec![tenant.clone()],
    )
    .await
    .unwrap();

    let native = ProxyTestAdapter::new_gated(Transport::Sip);
    let web_native = ProxyTestAdapter::new_gated(Transport::WebRtc);
    let gateway_orchestrator = Orchestrator::new(CoreConfig::default());
    let operational = gateway_orchestrator
        .install_operational_event_stream(64)
        .unwrap();
    gateway_orchestrator
        .register(Arc::clone(&native) as Arc<dyn ConnectionAdapter>)
        .unwrap();
    gateway_orchestrator
        .register(Arc::clone(&web_native) as Arc<dyn ConnectionAdapter>)
        .unwrap();
    let lifecycle = ProxyOperationalRouter::start(operational);
    let adapters = PrivateEgressGatewayAdapters::new(
        Some(Arc::clone(&native) as Arc<dyn ConnectionAdapter>),
        Some(Arc::clone(&web_native) as Arc<dyn ConnectionAdapter>),
    )
    .unwrap();
    let handler = PrivateEgressGatewayProxyHandler::new_with_lifecycle(
        Arc::clone(&gateway),
        Arc::clone(&gateway_orchestrator),
        adapters,
        Arc::new(ProxyTestProfiles),
        Arc::clone(&lifecycle) as Arc<dyn PrivateEgressGatewayLifecycleSource>,
        PrivateEgressGatewayProxyConfig {
            media_setup_timeout: Duration::from_secs(5),
            operation_timeout: Duration::from_secs(5),
        },
    )
    .unwrap();
    let service = PrivateEgressCommandService::new(
        Arc::clone(&handler) as Arc<dyn bridgefu::private_egress::PrivateEgressHandler>,
        PrivateEgressServiceConfig {
            max_active_routes: 4,
            max_replay_entries: 32,
            replay_ttl: Duration::from_secs(60),
            operation_timeout: Duration::from_secs(10),
        },
    )
    .unwrap();
    let authority = PrivateEgressRouteAuthority {
        worker: worker_lease,
        source: PrivateEgressSource {
            tenant_id: tenant.clone(),
            call_id: CallId::new(),
            leg_id: LegId::new(),
            binding_generation: BindingGeneration::INITIAL,
        },
    };
    let target = PrivateEgressTarget {
        leg_id: LegId::new(),
        binding_generation: BindingGeneration::INITIAL,
    };
    let prepare = private_egress_command(
        &authority,
        target,
        PrivateEgressOperation::Prepare {
            transport: PrivateEgressTransport::Sip,
            profile: PrivateEgressProfile {
                profile_id: "primary".into(),
                revision: "revision-1".into(),
            },
            codec: CodecInfo::from_name_with_defaults("opus"),
            target: "sips:queue@example.test".into(),
            initial_context: vec![("X-Correlation-Id".into(), "corr-egress".into())],
        },
    );
    let descriptor = PrivateEgressStreamAdmission::from_prepare(&prepare).unwrap();
    let reservation = stream_admissions.reserve(descriptor).unwrap();

    let execute_prepare = {
        let service = Arc::clone(&service);
        let authority = authority.clone();
        let prepare = prepare.clone();
        tokio::spawn(async move {
            service
                .execute(authority, prepare, Utc::now().timestamp_millis())
                .await
        })
    };
    let ticket = tokio::time::timeout(Duration::from_secs(5), admissions.recv())
        .await
        .expect("private egress admission ticket timeout")
        .expect("private egress admission receiver closed");
    let conversation = orchestrator
        .open_conversation(
            RvoipTenantId::from_string(tenant.as_str()),
            ConversationPolicy::default(),
            std::collections::HashMap::new(),
        )
        .await
        .unwrap();
    let session = orchestrator
        .start_session(conversation, SessionMedium::Voice, Vec::new())
        .await
        .unwrap();
    let admitted = admit_private_egress_worker_connection(
        ticket,
        Arc::clone(&orchestrator),
        Arc::clone(&worker),
        Arc::clone(&stream_admissions),
        session.clone(),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let reserved = reservation.wait(Duration::from_secs(5)).await.unwrap();
    assert_eq!(admitted.connection_id(), reserved.connection_id());
    assert_ne!(
        admitted.connection_id().as_str(),
        authority.source.leg_id.to_string()
    );
    assert_eq!(admitted.admission().target, target);
    assert_eq!(admitted.admission().source, authority.source);
    assert!(execute_prepare.await.unwrap().unwrap().accepted);

    let activate = private_egress_command(&authority, target, PrivateEgressOperation::Activate);
    let activation = {
        let service = Arc::clone(&service);
        let authority = authority.clone();
        tokio::spawn(async move {
            service
                .execute(authority, activate, Utc::now().timestamp_millis())
                .await
        })
    };
    native.wait_for_activation().await;
    assert!(
        !activation.is_finished(),
        "the command must remain pending until the staged adapter reaches final activation"
    );

    native.emit_remote_progress(183, true).await;

    // The proxy pump is installed before commit, so real destination audio
    // traverses the generation-bound private stream while final activation is
    // still gated. This is early media, not a fabricated lifecycle claim.
    let private_stream = admitted.stream();
    let mut from_gateway = private_stream.try_frames_in().unwrap();
    native
        .send_agent_audio(MediaFrame {
            stream_id: StreamId::new(),
            kind: StreamKind::Audio,
            payload: Bytes::from_static(b"agent-early-media"),
            timestamp_rtp: 480,
            captured_at: Utc::now(),
            payload_type: Some(111),
        })
        .await;
    let early_media = tokio::time::timeout(Duration::from_secs(5), from_gateway.recv())
        .await
        .expect("pre-answer private media timeout")
        .expect("pre-answer private media stream closed");
    assert_eq!(
        early_media.payload,
        Bytes::from_static(b"agent-early-media")
    );
    assert!(!activation.is_finished());
    assert!(!native.activated.load(std::sync::atomic::Ordering::Acquire));

    native.release_activation();
    let activation = activation.await.unwrap().unwrap();
    assert!(activation.accepted);
    assert_eq!(activation.state, Some(PrivateEgressLifecycleState::Active));
    assert!(native.activated.load(std::sync::atomic::Ordering::Acquire));
    private_stream
        .frames_out()
        .send(MediaFrame {
            stream_id: private_stream.id(),
            kind: StreamKind::Audio,
            payload: Bytes::from_static(b"caller-to-agent"),
            timestamp_rtp: 960,
            captured_at: Utc::now(),
            payload_type: Some(111),
        })
        .await
        .unwrap();
    assert_eq!(
        native.receive_agent_audio().await.payload,
        Bytes::from_static(b"caller-to-agent")
    );
    native
        .send_agent_audio(MediaFrame {
            stream_id: StreamId::new(),
            kind: StreamKind::Audio,
            payload: Bytes::from_static(b"agent-to-caller"),
            timestamp_rtp: 1_920,
            captured_at: Utc::now(),
            payload_type: Some(111),
        })
        .await;
    let reverse = tokio::time::timeout(Duration::from_secs(5), from_gateway.recv())
        .await
        .expect("reverse private media timeout")
        .expect("reverse private media stream closed");
    assert_eq!(reverse.payload, Bytes::from_static(b"agent-to-caller"));

    service
        .execute(
            authority.clone(),
            private_egress_command(
                &authority,
                target,
                PrivateEgressOperation::Dtmf {
                    digits: "12#".into(),
                    duration_ms: 120,
                },
            ),
            Utc::now().timestamp_millis(),
        )
        .await
        .unwrap();
    service
        .execute(
            authority.clone(),
            private_egress_command(
                &authority,
                target,
                PrivateEgressOperation::DataMessage {
                    message: DataMessage::reliable(
                        "bridgefu.context.v1",
                        "application/json",
                        Bytes::from_static(br#"{"correlation_id":"corr-egress"}"#),
                    ),
                },
            ),
            Utc::now().timestamp_millis(),
        )
        .await
        .unwrap();
    assert_eq!(
        native
            .dtmf
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_slice(),
        &[("12#".into(), 120)]
    );
    assert_eq!(
        native
            .data
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .first()
            .map(|message| message.label.as_str()),
        Some("bridgefu.context.v1")
    );

    let ended = service
        .execute(
            authority.clone(),
            private_egress_command(
                &authority,
                target,
                PrivateEgressOperation::End {
                    reason: PrivateEgressEndReason::Normal,
                },
            ),
            Utc::now().timestamp_millis(),
        )
        .await
        .unwrap();
    assert!(ended.accepted);
    assert!(native.ended.load(std::sync::atomic::Ordering::Acquire));
    assert_eq!(handler.active_routes(), 0);
    assert_eq!(service.active_routes(), 0);
    drop(admitted);
    drop(reserved);
    assert_eq!(stream_admissions.active_admissions(), 0);

    let web_target = PrivateEgressTarget {
        leg_id: LegId::new(),
        binding_generation: BindingGeneration::INITIAL,
    };
    let web_prepare = private_egress_command(
        &authority,
        web_target,
        PrivateEgressOperation::Prepare {
            transport: PrivateEgressTransport::WebRtc,
            profile: PrivateEgressProfile {
                profile_id: "web-primary".into(),
                revision: "revision-2".into(),
            },
            codec: CodecInfo::from_name_with_defaults("opus"),
            target: "wss://agent.example.test/signaling".into(),
            initial_context: Vec::new(),
        },
    );
    let web_descriptor = PrivateEgressStreamAdmission::from_prepare(&web_prepare).unwrap();
    let web_reservation = stream_admissions.reserve(web_descriptor).unwrap();
    let execute_web_prepare = {
        let service = Arc::clone(&service);
        let authority = authority.clone();
        tokio::spawn(async move {
            service
                .execute(authority, web_prepare, Utc::now().timestamp_millis())
                .await
        })
    };
    let web_ticket = tokio::time::timeout(Duration::from_secs(5), admissions.recv())
        .await
        .expect("private WebRTC egress admission ticket timeout")
        .expect("private egress admission receiver closed");
    let web_admitted = admit_private_egress_worker_connection(
        web_ticket,
        Arc::clone(&orchestrator),
        Arc::clone(&worker),
        Arc::clone(&stream_admissions),
        session,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let web_reserved = web_reservation.wait(Duration::from_secs(5)).await.unwrap();
    assert_eq!(web_admitted.connection_id(), web_reserved.connection_id());
    assert!(execute_web_prepare.await.unwrap().unwrap().accepted);

    let web_activate =
        private_egress_command(&authority, web_target, PrivateEgressOperation::Activate);
    let web_activation = {
        let service = Arc::clone(&service);
        let authority = authority.clone();
        tokio::spawn(async move {
            service
                .execute(authority, web_activate, Utc::now().timestamp_millis())
                .await
        })
    };
    web_native.wait_for_activation().await;
    let web_private_stream = web_admitted.stream();
    let mut web_from_gateway = web_private_stream.try_frames_in().unwrap();
    web_native
        .send_agent_audio(MediaFrame {
            stream_id: StreamId::new(),
            kind: StreamKind::Audio,
            payload: Bytes::from_static(b"not-webrtc-early-media"),
            timestamp_rtp: 2_880,
            captured_at: Utc::now(),
            payload_type: Some(111),
        })
        .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(200), web_from_gateway.recv())
            .await
            .is_err(),
        "WebRTC media forwarding must not start before final commit"
    );
    web_native.emit_remote_progress(183, true).await;
    assert!(!web_activation.is_finished());
    web_native.release_activation();
    let web_activation = web_activation.await.unwrap().unwrap();
    assert!(web_activation.accepted);
    assert!(web_native
        .activated
        .load(std::sync::atomic::Ordering::Acquire));
    let post_commit_media = tokio::time::timeout(Duration::from_secs(5), web_from_gateway.recv())
        .await
        .expect("post-commit WebRTC media timeout")
        .expect("post-commit WebRTC media stream closed");
    assert_eq!(
        post_commit_media.payload,
        Bytes::from_static(b"not-webrtc-early-media")
    );
    service
        .execute(
            authority.clone(),
            private_egress_command(
                &authority,
                web_target,
                PrivateEgressOperation::DataMessage {
                    message: DataMessage::reliable(
                        "bridgefu.context.v1",
                        "application/json",
                        Bytes::from_static(br#"{"correlation_id":"corr-web-egress"}"#),
                    ),
                },
            ),
            Utc::now().timestamp_millis(),
        )
        .await
        .unwrap();
    assert_eq!(
        web_native
            .data
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .first()
            .map(|message| message.label.as_str()),
        Some("bridgefu.context.v1")
    );
    let web_ended = service
        .execute(
            authority.clone(),
            private_egress_command(
                &authority,
                web_target,
                PrivateEgressOperation::End {
                    reason: PrivateEgressEndReason::Normal,
                },
            ),
            Utc::now().timestamp_millis(),
        )
        .await
        .unwrap();
    assert!(web_ended.accepted);
    assert!(web_native.ended.load(std::sync::atomic::Ordering::Acquire));
    assert_eq!(handler.active_routes(), 0);
    assert_eq!(service.active_routes(), 0);
    drop(web_admitted);
    drop(web_reserved);
    assert_eq!(stream_admissions.active_admissions(), 0);
    assert_eq!(lifecycle.active_routes(), 0);

    gateway.shutdown(Duration::from_secs(5)).await.unwrap();
    worker.shutdown(Duration::from_secs(5)).await.unwrap();
    gateway_orchestrator
        .drain_connection_lifecycle_tasks()
        .await;
}

#[tokio::test]
async fn mtls_uctp_routes_full_rtp_rtcp_and_data_with_pinning_backpressure_and_drain() {
    let tls = tls_fixture();
    let key = PrivateTokenKey::new(b"0123456789abcdef0123456789abcdef".to_vec()).unwrap();
    let worker_id: WorkerId = "00000000-0000-4000-8000-000000000011".parse().unwrap();
    let other_worker: WorkerId = "00000000-0000-4000-8000-000000000012".parse().unwrap();
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let mut events = orchestrator.subscribe_events();
    let worker = WorkerForwardingRuntime::start(
        WorkerForwardingConfig {
            worker_id,
            bind: "127.0.0.1:0".parse().unwrap(),
            tls: tls.worker.clone(),
            token_key: key.clone(),
            limits: limits(),
            timeouts: timeouts(),
        },
        Arc::clone(&orchestrator),
    )
    .await
    .unwrap();
    let endpoint = worker.local_addr().unwrap().to_string();
    let tenant = TenantId::parse("tenant-a").unwrap();
    let gateway = GatewayForwarder::start(
        GatewayForwardingConfig {
            gateway_id: "gateway-a".into(),
            bind: "127.0.0.1:0".parse().unwrap(),
            tls: tls.gateway.clone(),
            token_key: key,
            workers: vec![
                PrivateWorkerTarget {
                    worker_id,
                    endpoint: endpoint.clone(),
                    server_name: "localhost".into(),
                },
                // The same address with a different audience is deliberately
                // unavailable, but it is enough to prove pin rejection occurs
                // before a call can be rebound to another worker.
                PrivateWorkerTarget {
                    worker_id: other_worker,
                    endpoint,
                    server_name: "localhost".into(),
                },
            ],
            limits: limits(),
            timeouts: timeouts(),
        },
        vec![tenant.clone()],
    )
    .await
    .unwrap();
    assert_eq!(
        *gateway.subscribe_health().borrow(),
        ForwardingHealth::Degraded
    );

    let call_id = CallId::new();
    let route = gateway
        .open_route_with_codec(
            GatewayRouteKey::new(tenant.clone(), call_id, LegId::new()),
            worker_id,
            default_audio_codec(),
        )
        .await
        .unwrap();
    let connection_id = next_connection(&mut events).await;
    let stream = first_stream(&worker, connection_id.clone()).await;
    assert_eq!(stream.codec().name, "opus");
    assert_eq!(stream.codec().clock_rate_hz, 48_000);
    let mut inbound_media = stream.frames_in();

    assert_eq!(
        route.try_send_rtp(rtp_with_pt(b"wrong-codec", 0, 40, 8_640, 0x1020_3040,)),
        Err(GatewayForwardingError::UnsupportedCodec)
    );
    let opus_samples = (0..960)
        .map(|index| if index % 120 < 60 { 2_000 } else { -2_000 })
        .collect::<Vec<i16>>();
    let mut opus_encoder = OpusCodec::new(SampleRate::Rate48000, 1, OpusConfig::default()).unwrap();
    let opus_payload = opus_encoder
        .encode(&DecodedAudioFrame::new(opus_samples, 48_000, 1, 9_600))
        .expect("encode deterministic Opus");
    route
        .try_send_rtp(rtp(&opus_payload, 41, 9_600, 0x1020_3040))
        .unwrap();
    assert_eq!(
        route.try_send_rtp(rtp(b"queue-full", 42, 10_560, 0x1020_3040)),
        Err(GatewayForwardingError::Backpressure)
    );
    let frame = tokio::time::timeout(Duration::from_secs(5), inbound_media.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(frame.payload, Bytes::from(opus_payload));
    assert_eq!(frame.timestamp_rtp, 9_600);
    let mut opus_decoder = OpusCodec::new(SampleRate::Rate48000, 1, OpusConfig::default()).unwrap();
    let decoded_opus = opus_decoder
        .decode(&frame.payload)
        .expect("decode worker Opus frame");
    assert_eq!(decoded_opus.sample_rate, 48_000);
    assert_eq!(decoded_opus.channels, 1);
    assert!(decoded_opus.samples.iter().any(|sample| *sample != 0));

    stream
        .frames_out()
        .send(MediaFrame {
            stream_id: stream.id(),
            kind: StreamKind::Audio,
            payload: Bytes::from_static(b"worker-audio"),
            timestamp_rtp: 19_200,
            captured_at: Utc::now(),
            payload_type: Some(111),
        })
        .await
        .unwrap();
    let ForwardedPacket::Rtp(worker_rtp) =
        tokio::time::timeout(Duration::from_secs(5), route.recv())
            .await
            .unwrap()
            .unwrap()
    else {
        panic!("expected worker RTP")
    };
    assert_eq!(&worker_rtp[12..], b"worker-audio");

    let context = DataMessage::reliable(
        "bridgefu.context.v1",
        "application/json",
        Bytes::from_static(br#"{"correlation_id":"corr-1"}"#),
    );
    route.try_send_data(context.clone()).unwrap();
    assert_eq!(
        route.try_send_data(context),
        Err(GatewayForwardingError::Backpressure)
    );
    let received_context = next_data(&mut events, &connection_id).await;
    assert_eq!(received_context.label, "bridgefu.context.v1");

    let rtcp = Bytes::from_static(&[0x80, 200, 0, 1, 0x10, 0x20, 0x30, 0x40]);
    assert_eq!(
        route.try_send_rtcp(Bytes::from_static(&[
            0x80, 111, 0, 1, 0x10, 0x20, 0x30, 0x40
        ])),
        Err(GatewayForwardingError::InvalidRtcp)
    );
    assert_eq!(
        route.try_send_data(DataMessage::reliable(
            PRIVATE_RTCP_LABEL,
            PRIVATE_RTCP_CONTENT_TYPE,
            rtcp.clone(),
        )),
        Err(GatewayForwardingError::InvalidDataMessage)
    );
    route.try_send_rtcp(rtcp.clone()).unwrap();
    let received_rtcp = next_data(&mut events, &connection_id).await;
    assert_eq!(received_rtcp.label, PRIVATE_RTCP_LABEL);
    assert_eq!(received_rtcp.content_type, PRIVATE_RTCP_CONTENT_TYPE);
    assert_eq!(received_rtcp.bytes, rtcp);

    assert_eq!(
        route.try_send_dtmf("not-dtmf".into(), 120),
        Err(GatewayForwardingError::InvalidDataMessage)
    );
    route.try_send_dtmf("12#".into(), 120).unwrap();
    assert_eq!(next_dtmf(&mut events, &connection_id).await, "12#");

    orchestrator
        .send_dtmf(connection_id.clone(), "A*", 160)
        .await
        .unwrap();
    let ForwardedPacket::Dtmf {
        digits,
        duration_ms,
    } = tokio::time::timeout(Duration::from_secs(5), route.recv())
        .await
        .unwrap()
        .unwrap()
    else {
        panic!("expected worker DTMF")
    };
    assert_eq!(digits, "A*");
    assert_eq!(duration_ms, 160);

    orchestrator
        .send_data_message(
            connection_id.clone(),
            DataMessage::reliable(
                "worker.event.v1",
                "application/json",
                Bytes::from_static(b"{}"),
            ),
        )
        .await
        .unwrap();
    let ForwardedPacket::Data(worker_data) =
        tokio::time::timeout(Duration::from_secs(5), route.recv())
            .await
            .unwrap()
            .unwrap()
    else {
        panic!("expected worker DataMessage")
    };
    assert_eq!(worker_data.label, "worker.event.v1");

    // A private command sent over the real mTLS UCTP 0.2 connection is
    // intercepted at the gateway and never delivered to the public route.
    // This low-level test route has no consumed attachment generation, so the
    // gateway returns an ownership error instead of invoking egress.
    let worker_lease = serde_json::from_value(serde_json::json!({
        "worker_id": worker_id.to_string(),
        "fence": 1
    }))
    .unwrap();
    let now_ms = Utc::now().timestamp_millis();
    let private_command = PrivateEgressCommand::new(
        uuid::Uuid::new_v4(),
        now_ms,
        Duration::from_secs(5),
        worker_lease,
        PrivateEgressSource {
            tenant_id: route.key().tenant_id().clone(),
            call_id: route.key().call_id(),
            leg_id: route.key().leg_id(),
            binding_generation: bridgefu::call_engine::BindingGeneration::INITIAL,
        },
        PrivateEgressTarget {
            leg_id: LegId::new(),
            binding_generation: bridgefu::call_engine::BindingGeneration::INITIAL,
        },
        PrivateEgressOperation::Prepare {
            transport: PrivateEgressTransport::Sip,
            profile: PrivateEgressProfile {
                profile_id: "primary".into(),
                revision: "a".repeat(64),
            },
            codec: CodecInfo::from_name_with_defaults("opus"),
            target: "sips:queue@example.test".into(),
            initial_context: Vec::new(),
        },
    )
    .unwrap();
    assert_eq!(
        route.try_send_data(private_command.to_data_message().unwrap()),
        Err(GatewayForwardingError::InvalidDataMessage)
    );
    let control = PrivateEgressControlClient::start(
        Arc::clone(&orchestrator),
        worker_lease,
        4,
        Duration::from_secs(3),
    )
    .unwrap();
    let private_response = control
        .execute(connection_id.clone(), private_command)
        .await
        .unwrap();
    assert!(!private_response.accepted);
    assert_eq!(
        private_response.failure_code.as_deref(),
        Some("ownership_mismatch")
    );
    control.shutdown().await;

    let pinned = gateway
        .open_route(
            GatewayRouteKey::new(tenant.clone(), call_id, LegId::new()),
            other_worker,
        )
        .await;
    assert_eq!(
        pinned.unwrap_err(),
        GatewayForwardingError::WorkerPinMismatch
    );

    let peer_at_capacity = gateway
        .open_route(
            GatewayRouteKey::new(tenant.clone(), CallId::new(), LegId::new()),
            worker_id,
        )
        .await;
    assert_eq!(
        peer_at_capacity.unwrap_err(),
        GatewayForwardingError::CapacityExceeded
    );

    gateway.begin_drain();
    assert_eq!(
        gateway
            .open_route(
                GatewayRouteKey::new(tenant, CallId::new(), LegId::new()),
                worker_id,
            )
            .await
            .unwrap_err(),
        GatewayForwardingError::Draining
    );
    route.close().await;
    assert_eq!(gateway.active_routes(), 0);
    gateway.shutdown(Duration::from_secs(5)).await.unwrap();
    worker.begin_drain();
    worker.shutdown(Duration::from_secs(5)).await.unwrap();
}

#[tokio::test]
async fn exact_pcmu_private_route_negotiates_and_decodes_as_pcmu() {
    let tls = tls_fixture();
    let key = PrivateTokenKey::new(b"fedcba9876543210fedcba9876543210".to_vec()).unwrap();
    let worker_id: WorkerId = "00000000-0000-4000-8000-000000000021".parse().unwrap();
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let mut events = orchestrator.subscribe_events();
    let worker = WorkerForwardingRuntime::start(
        WorkerForwardingConfig {
            worker_id,
            bind: "127.0.0.1:0".parse().unwrap(),
            tls: tls.worker.clone(),
            token_key: key.clone(),
            limits: limits(),
            timeouts: timeouts(),
        },
        Arc::clone(&orchestrator),
    )
    .await
    .unwrap();
    let tenant = TenantId::parse("tenant-pcmu").unwrap();
    let gateway = GatewayForwarder::start(
        GatewayForwardingConfig {
            gateway_id: "gateway-pcmu".into(),
            bind: "127.0.0.1:0".parse().unwrap(),
            tls: tls.gateway.clone(),
            token_key: key,
            workers: vec![PrivateWorkerTarget {
                worker_id,
                endpoint: worker.local_addr().unwrap().to_string(),
                server_name: "localhost".into(),
            }],
            limits: limits(),
            timeouts: timeouts(),
        },
        vec![tenant.clone()],
    )
    .await
    .unwrap();
    let pcmu = CodecInfo {
        name: "PCMU".into(),
        clock_rate_hz: 8_000,
        channels: 1,
        fmtp: None,
        payload_type: Some(0),
    };
    let route = gateway
        .open_route_with_codec(
            GatewayRouteKey::new(tenant, CallId::new(), LegId::new()),
            worker_id,
            pcmu,
        )
        .await
        .unwrap();
    let connection_id = next_connection(&mut events).await;
    let stream = first_stream(&worker, connection_id).await;
    assert_eq!(stream.codec().name, "g.711-mu");
    assert_eq!(stream.codec().clock_rate_hz, 8_000);
    assert_eq!(stream.codec().channels, 1);
    let mut received = stream.frames_in();

    assert_eq!(
        route.try_send_rtp(rtp_with_pt(b"not-opus", 111, 1, 160, 0x0102_0304)),
        Err(GatewayForwardingError::UnsupportedCodec)
    );
    let samples = (0..160)
        .map(|index| if index % 20 < 10 { 4_000 } else { -4_000 })
        .collect::<Vec<i16>>();
    let mut encoder = G711Codec::mu_law(8_000, 1).unwrap();
    let mut encoded = vec![0_u8; samples.len()];
    let encoded_len = encoder
        .encode_to_buffer(&samples, &mut encoded)
        .expect("encode deterministic PCMU");
    encoded.truncate(encoded_len);
    route
        .try_send_rtp(rtp_with_pt(&encoded, 0, 2, 320, 0x0102_0304))
        .unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(5), received.recv())
        .await
        .expect("PCMU worker media timeout")
        .expect("PCMU worker stream closed");
    assert_eq!(frame.payload_type, Some(0));
    let mut decoder = G711Codec::mu_law(8_000, 1).unwrap();
    let mut decoded = vec![0_i16; samples.len()];
    let decoded_len = decoder
        .decode_to_buffer(&frame.payload, &mut decoded)
        .expect("decode worker PCMU frame");
    assert_eq!(decoded_len, samples.len());
    assert!(decoded.iter().any(|sample| *sample > 0));
    assert!(decoded.iter().any(|sample| *sample < 0));

    route.close().await;
    gateway.shutdown(Duration::from_secs(5)).await.unwrap();
    worker.shutdown(Duration::from_secs(5)).await.unwrap();
}

#[tokio::test]
async fn mtls_rejects_an_untrusted_gateway_certificate() {
    let trusted = tls_fixture();
    let untrusted = tls_fixture();
    let key = PrivateTokenKey::new(b"0123456789abcdef0123456789abcdef".to_vec()).unwrap();
    let worker_id: WorkerId = "00000000-0000-4000-8000-000000000021".parse().unwrap();
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let worker = WorkerForwardingRuntime::start(
        WorkerForwardingConfig {
            worker_id,
            bind: "127.0.0.1:0".parse().unwrap(),
            tls: trusted.worker.clone(),
            token_key: key.clone(),
            limits: limits(),
            timeouts: timeouts(),
        },
        Arc::clone(&orchestrator),
    )
    .await
    .unwrap();
    let tenant = TenantId::parse("tenant-b").unwrap();
    let gateway = GatewayForwarder::start(
        GatewayForwardingConfig {
            gateway_id: "untrusted-gateway".into(),
            bind: "127.0.0.1:0".parse().unwrap(),
            // This certificate is not signed by/trusted as the worker's
            // configured gateway trust anchor.
            tls: untrusted.gateway.clone(),
            token_key: key,
            workers: vec![PrivateWorkerTarget {
                worker_id,
                endpoint: worker.local_addr().unwrap().to_string(),
                server_name: "localhost".into(),
            }],
            limits: limits(),
            timeouts: timeouts(),
        },
        vec![tenant.clone()],
    )
    .await
    .unwrap();
    assert_eq!(
        *gateway.subscribe_health().borrow(),
        ForwardingHealth::Degraded
    );
    assert!(matches!(
        gateway
            .open_route(
                GatewayRouteKey::new(tenant, CallId::new(), LegId::new()),
                worker_id,
            )
            .await,
        Err(GatewayForwardingError::PeerUnavailable)
            | Err(GatewayForwardingError::AuthenticationFailed)
            | Err(GatewayForwardingError::Timeout)
    ));
    gateway.shutdown(Duration::from_secs(2)).await.unwrap();
    worker.shutdown(Duration::from_secs(2)).await.unwrap();
}

#[tokio::test]
async fn worker_disconnect_retires_the_exact_route_and_releases_capacity() {
    let tls = tls_fixture();
    let key = PrivateTokenKey::new(b"0123456789abcdef0123456789abcdef".to_vec()).unwrap();
    let worker_id: WorkerId = "00000000-0000-4000-8000-000000000031".parse().unwrap();
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let worker = WorkerForwardingRuntime::start(
        WorkerForwardingConfig {
            worker_id,
            bind: "127.0.0.1:0".parse().unwrap(),
            tls: tls.worker.clone(),
            token_key: key.clone(),
            limits: limits(),
            timeouts: timeouts(),
        },
        orchestrator,
    )
    .await
    .unwrap();
    let tenant = TenantId::parse("tenant-c").unwrap();
    let gateway = GatewayForwarder::start(
        GatewayForwardingConfig {
            gateway_id: "gateway-c".into(),
            bind: "127.0.0.1:0".parse().unwrap(),
            tls: tls.gateway.clone(),
            token_key: key,
            workers: vec![PrivateWorkerTarget {
                worker_id,
                endpoint: worker.local_addr().unwrap().to_string(),
                server_name: "localhost".into(),
            }],
            limits: limits(),
            timeouts: timeouts(),
        },
        vec![tenant.clone()],
    )
    .await
    .unwrap();
    let route = gateway
        .open_route(
            GatewayRouteKey::new(tenant, CallId::new(), LegId::new()),
            worker_id,
        )
        .await
        .unwrap();
    assert_eq!(gateway.active_routes(), 1);

    worker.shutdown(Duration::from_secs(2)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while gateway.active_routes() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("worker disconnect retired its route");
    assert!(route.recv().await.is_none());

    gateway.shutdown(Duration::from_secs(2)).await.unwrap();
}

#[tokio::test]
async fn native_whip_edge_reaches_call_pinned_worker_over_mtls_uctp_and_drains_cleanly() {
    const API_KEY: &str = "private-composite-api-key";
    const TENANT: &str = "private-composite-tenant";

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls = tls_fixture();
    let private_key = PrivateTokenKey::new(b"composite-private-token-key-32bb".to_vec()).unwrap();
    let worker_id = WorkerId::new();

    let validator = Arc::new(
        ConfiguredApiKeyValidator::new(API_KEY.into(), [TENANT])
            .expect("configure exact public bearer"),
    );
    let authenticated = validator
        .validate_principal(API_KEY)
        .await
        .expect("resolve exact public principal");
    let owner =
        ApiPrincipal::new(authenticated.clone(), Utc::now()).expect("construct durable call owner");

    let runtime = Arc::new(
        build_call_service_runtime(
            composite_runtime_config(worker_id),
            Arc::new(SamePrincipalAttachmentResolver),
            Arc::new(SystemCallServiceClock),
        )
        .await
        .expect("start in-memory durable worker runtime"),
    );
    let created = runtime
        .service()
        .create_call(
            &owner,
            &IdempotencyKey::parse("private-composite-call").unwrap(),
            two_inbound_webrtc_legs(),
        )
        .await
        .expect("create two-leg durable call");
    let call_id = created.value.call.call_id;
    let tenant = created.value.call.tenant_id.clone();
    let first_leg = created.value.call.legs[0].leg_id;
    let second_leg = created.value.call.legs[1].leg_id;
    let first_attachment = created.value.call.legs[0]
        .attachment
        .as_ref()
        .expect("first attachment")
        .clone();
    let second_attachment = created.value.call.legs[1]
        .attachment
        .as_ref()
        .expect("second attachment")
        .clone();
    assert_eq!(first_attachment.transport, AttachmentTransport::WebRtc);
    assert_eq!(second_attachment.transport, AttachmentTransport::WebRtc);

    // This projection is the gateway's independent, credential-free routing
    // view. The worker still atomically consumes the raw, single-use bearer
    // against the authoritative call repository before signaling succeeds.
    let now = Utc::now();
    let deployment = DeploymentId::parse("private-composite-gateway").unwrap();
    let coordinator = Arc::new(
        MemoryCoordinator::new(
            deployment.clone(),
            Arc::new(ManualCoordinationClock::new(now)),
            32,
        )
        .unwrap(),
    );
    let worker = runtime.worker().clone();
    coordinator
        .apply(&CoordinationEvent {
            deployment: deployment.clone(),
            sequence: ProjectionSequence::from_i64(1).unwrap(),
            payload: CoordinationPayload::Worker(WorkerCoordinationSnapshot {
                lease: worker.lease,
                max_calls: worker.max_calls,
                reserved_calls: 1,
                draining: false,
                capabilities: worker.capabilities.clone(),
                lease_expires_at: worker.lease_expires_at,
            }),
            recorded_at: now,
        })
        .await
        .unwrap();
    let fingerprint_key = vec![0x41; 32];
    let tenant_binding = PrincipalFingerprintKey::new(fingerprint_key.clone())
        .unwrap()
        .derive(&owner);
    for (sequence, attachment) in [(2_i64, &first_attachment), (3_i64, &second_attachment)] {
        coordinator
            .apply(&CoordinationEvent {
                deployment: deployment.clone(),
                sequence: ProjectionSequence::from_i64(sequence).unwrap(),
                payload: CoordinationPayload::AttachmentRoute(AttachmentRouteHint {
                    token_digest: parse_presented_attachment_token(attachment.token.clone())
                        .unwrap()
                        .digest(),
                    worker: worker.lease,
                    route_catalog_fingerprint: None,
                    transport: attachment.transport,
                    tenant_binding,
                    expires_at: attachment.expires_at,
                }),
                recorded_at: now,
            })
            .await
            .unwrap();
    }
    let projection: Arc<dyn CoordinationProjection> = coordinator;
    let resolver = Arc::new(
        GatewayAttachmentResolver::new(projection, fingerprint_key)
            .expect("construct exact gateway attachment resolver"),
    );

    let orchestrator = Orchestrator::new(CoreConfig::default());
    let supervisor = CallExecutionSupervisor::install(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        8,
        Duration::from_secs(5),
    )
    .await
    .expect("install durable worker call execution");
    let worker_forwarding = WorkerForwardingRuntime::start(
        WorkerForwardingConfig {
            worker_id,
            bind: "127.0.0.1:0".parse().unwrap(),
            tls: tls.worker.clone(),
            token_key: private_key.clone(),
            limits: composite_limits(),
            timeouts: timeouts(),
        },
        Arc::clone(&orchestrator),
    )
    .await
    .expect("start private worker listener");
    let gateway = GatewayForwarder::start(
        GatewayForwardingConfig {
            gateway_id: "private-composite-gateway".into(),
            bind: "127.0.0.1:0".parse().unwrap(),
            tls: tls.gateway.clone(),
            token_key: private_key,
            workers: vec![PrivateWorkerTarget {
                worker_id,
                endpoint: worker_forwarding.local_addr().unwrap().to_string(),
                server_name: "localhost".into(),
            }],
            limits: composite_limits(),
            timeouts: timeouts(),
        },
        vec![tenant.clone()],
    )
    .await
    .expect("start private gateway forwarder");

    let sip_addr = reserve_udp();
    let native = GatewayNativeIngress::start(
        GatewayNativeIngressConfig {
            sip: GatewayNativeSipConfig {
                stack: SipConfig::local("private-composite-edge", sip_addr.port()),
                nat: SipNatConfig::default(),
                authentication: SipListenerAuthPolicy::enabled_for_tenant(TENANT)
                    .unwrap()
                    .with_trusted_cidr("127.0.0.1/32".parse().unwrap(), authenticated.clone()),
                inbound_context: SipInboundContextPolicy::default(),
                egress_profiles: Vec::new(),
            },
            webrtc: GatewayNativeWebRtcConfig {
                stack: WebRtcConfig::loopback(),
                websocket_bind: reserve_tcp().to_string(),
                whip_whep_bind: reserve_tcp().to_string(),
                tls: None,
            },
            admission_capacity: 8,
            setup_timeout: Duration::from_secs(5),
        },
        validator as Arc<dyn BearerValidator>,
        resolver,
        Arc::clone(&gateway),
        Arc::new(CompositeGatewayAdmission),
    )
    .await
    .expect("start native public edge");

    let http = reqwest::Client::new();
    let first = attach_whip_client(
        &http,
        native.whip_whep_addr(),
        API_KEY,
        &first_attachment.token,
    )
    .await;
    let second = attach_whip_client(
        &http,
        native.whip_whep_addr(),
        API_KEY,
        &second_attachment.token,
    )
    .await;
    assert_eq!(
        wait_for_call_state(&runtime, &tenant, call_id, |state| state
            == CallState::Active)
        .await,
        CallState::Active
    );
    wait_for_bridge_count(&orchestrator, 1).await;
    assert_eq!(native.active_routes(), 2);
    assert_eq!(gateway.active_routes(), 2);

    // The clients observe the real SRTP path. Each packet traverses the
    // native WebRTC adapter, the gateway's mTLS UCTP 0.2 route, the worker
    // MediaGraph, and the peer route before arriving here.
    let first_remote =
        RvoipPeerConnection::prime_remote_track(&second.peer, &first.peer, Duration::from_secs(10))
            .await
            .expect("first client receives second client Opus track");
    let second_remote =
        RvoipPeerConnection::prime_remote_track(&first.peer, &second.peer, Duration::from_secs(10))
            .await
            .expect("second client receives first client Opus track");
    let client_codec = CodecInfo {
        name: "opus".into(),
        clock_rate_hz: 48_000,
        channels: 1,
        fmtp: None,
        payload_type: Some(111),
    };
    let first_stream = from_tracks(
        StreamId::new(),
        client_codec.clone(),
        first.peer.local_audio_track().expect("first local audio"),
        first.peer.local_audio_ssrc().expect("first audio SSRC"),
        111,
        Some(first_remote),
    );
    let second_dtmf_codec = second
        .peer
        .negotiated_outbound_dtmf_codec()
        .expect("second WHIP peer negotiated telephone-event");
    let (second_dtmf_tx, mut second_dtmf_rx) = tokio::sync::mpsc::channel(4);
    let second_stream = from_tracks_with_dtmf_codecs(
        StreamId::new(),
        client_codec,
        second.peer.local_audio_track().expect("second local audio"),
        second.peer.local_audio_ssrc().expect("second audio SSRC"),
        111,
        Some(second_remote),
        Some(second_dtmf_tx),
        [second_dtmf_codec],
    );
    let mut first_media = first_stream.frames_in();
    let mut second_media = second_stream.frames_in();
    let mut first_encoder =
        OpusCodec::new(SampleRate::Rate48000, 1, OpusConfig::default()).unwrap();
    let first_payload = Bytes::from(
        first_encoder
            .encode(&DecodedAudioFrame::new(
                (0..960)
                    .map(|index| if index % 96 < 48 { 1_750 } else { -1_750 })
                    .collect(),
                48_000,
                1,
                48_000,
            ))
            .unwrap(),
    );
    let mut second_encoder =
        OpusCodec::new(SampleRate::Rate48000, 1, OpusConfig::default()).unwrap();
    let second_payload = Bytes::from(
        second_encoder
            .encode(&DecodedAudioFrame::new(
                (0..960)
                    .map(|index| if index % 120 < 60 { 2_500 } else { -2_500 })
                    .collect(),
                48_000,
                1,
                57_600,
            ))
            .unwrap(),
    );
    for offset in 0..5_u32 {
        first_stream
            .frames_out()
            .send(MediaFrame {
                stream_id: first_stream.id(),
                kind: StreamKind::Audio,
                payload: first_payload.clone(),
                timestamp_rtp: 48_000 + offset * 960,
                captured_at: Utc::now(),
                payload_type: Some(111),
            })
            .await
            .unwrap();
        second_stream
            .frames_out()
            .send(MediaFrame {
                stream_id: second_stream.id(),
                kind: StreamKind::Audio,
                payload: second_payload.clone(),
                timestamp_rtp: 57_600 + offset * 960,
                captured_at: Utc::now(),
                payload_type: Some(111),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let received_from_first = receive_audible_opus(&mut second_media).await;
    let next_from_first = receive_audible_opus(&mut second_media).await;
    let received_from_second = receive_audible_opus(&mut first_media).await;
    let next_from_second = receive_audible_opus(&mut first_media).await;
    assert_eq!(received_from_first.payload_type, Some(111));
    assert_eq!(next_from_first.payload_type, Some(111));
    assert_eq!(received_from_second.payload_type, Some(111));
    assert_eq!(next_from_second.payload_type, Some(111));
    assert_eq!(received_from_first.payload, first_payload);
    assert_eq!(next_from_first.payload, first_payload);
    assert_eq!(received_from_second.payload, second_payload);
    assert_eq!(next_from_second.payload, second_payload);
    // The WebRTC transport owns one stable RTP timeline per outbound SSRC.
    // Track priming may precede these test frames, so the absolute source
    // timestamp is intentionally rebased on the wire. Consecutive 20 ms Opus
    // frames must still advance by exactly 960 ticks at the 48 kHz RTP clock.
    assert_eq!(
        next_from_first
            .timestamp_rtp
            .wrapping_sub(received_from_first.timestamp_rtp),
        960
    );
    assert_eq!(
        next_from_second
            .timestamp_rtp
            .wrapping_sub(received_from_second.timestamp_rtp),
        960
    );

    let first_context = ContextEnvelope::new(
        "private-composite-first",
        tenant.as_str(),
        call_id.to_string(),
        first_leg.to_string(),
    )
    .to_data_message()
    .unwrap();
    send_data_message(&first.context_channel, &first_context).await;
    assert_eq!(
        receive_data_message(&second.context_channel).await,
        first_context
    );
    let second_context = ContextEnvelope::new(
        "private-composite-second",
        tenant.as_str(),
        call_id.to_string(),
        second_leg.to_string(),
    )
    .to_data_message()
    .unwrap();
    send_data_message(&second.context_channel, &second_context).await;
    assert_eq!(
        receive_data_message(&first.context_channel).await,
        second_context
    );

    send_dtmf(&first.peer, "5", 100)
        .await
        .expect("send client RFC 4733 DTMF");
    let dtmf = tokio::time::timeout(Duration::from_secs(10), second_dtmf_rx.recv())
        .await
        .expect("bridged DTMF receive timeout")
        .expect("second client DTMF receiver remains live");
    assert_eq!(dtmf.digit, '5');
    assert!(dtmf.duration_ms >= 100);

    let deleted = http
        .delete(format!(
            "http://{}{}",
            native.whip_whep_addr(),
            first.location
        ))
        .bearer_auth(API_KEY)
        .header(reqwest::header::IF_MATCH, &first.etag)
        .send()
        .await
        .expect("delete first WHIP resource");
    assert_eq!(deleted.status(), reqwest::StatusCode::OK);
    assert_eq!(
        wait_for_call_state(&runtime, &tenant, call_id, CallState::is_terminal).await,
        CallState::Ended
    );
    wait_for_bridge_count(&orchestrator, 0).await;
    wait_for_zero_routes(&native, &gateway).await;

    first.peer.close().await.unwrap();
    second.peer.close().await.unwrap();
    native.shutdown(Duration::from_secs(5)).await.unwrap();
    gateway.shutdown(Duration::from_secs(5)).await.unwrap();
    supervisor.shutdown(Duration::from_secs(5)).await;
    orchestrator.drain_prepared_outbound_connections().await;
    orchestrator.drain_connection_lifecycle_tasks().await;
    worker_forwarding
        .shutdown(Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(gateway.active_routes(), 0);
    assert_eq!(orchestrator.connection_lifecycle_task_count(), 0);
    Arc::try_unwrap(runtime)
        .expect("call execution released runtime owner")
        .shutdown(Duration::from_secs(5))
        .await
        .unwrap();
}
