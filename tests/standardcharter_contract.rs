#![allow(dead_code)]

//! Hermetic regression for the production StandardCharter handoff contract.
//!
//! These tests enter through a real localhost SIP listener. Amazon's control
//! plane and Chime media session are replaced at rvoip's public injection
//! seams, while Bridgefu routing, SIP/RTP, header mapping, the production
//! MediaGraph/transcoder, lifecycle events, and teardown stay real.

#[path = "../src/config.rs"]
mod config;
mod handoff_status {
    pub use bridgefu::handoff_status::HANDOFF_STATUS_LABEL;
}
mod private_egress {
    pub use bridgefu::private_egress::is_private_egress_label;
}
#[path = "../src/context.rs"]
mod context;
#[path = "../src/imds.rs"]
mod imds;
#[path = "../src/providers.rs"]
mod providers;

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use rvoip_amazon_connect::{
    ConnectContactStarter, ConnectMediaCloseOutcome, ConnectMediaConnectOptions,
    ConnectMediaConnector, ConnectMediaHealth, ConnectMediaSession, ConnectMediaTerminalCause,
    ConnectScreenPopServer, ConnectionData, MediaPlacement, ScreenPopLifecycleEvent,
    ScreenPopLifecycleStage, StartContactRequest, StopContactRequest,
};
use rvoip_core::capability::{CodecInfo, NegotiatedCodecs};
use rvoip_core::connection::Direction;
use rvoip_core::ids::StreamId;
use rvoip_core::stream::{MediaFrame, MediaStream, QualitySnapshot, StreamKind};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc, oneshot, watch, Notify};
use tokio::task::JoinHandle;

const GOLDEN_CONFIG: &str = include_str!("fixtures/standardcharter-golden.yaml");
const VAPI_INVITE: &str = include_str!("fixtures/standardcharter-vapi-invite.sip");
const CALL_ID: &str = "standardcharter-golden@127.0.0.1";
const CONTACT_ID: &str = "contact-standardcharter-hermetic";

struct CapturingStarter {
    captured: Mutex<Option<oneshot::Sender<StartContactRequest>>>,
    stopped: mpsc::UnboundedSender<StopContactRequest>,
}

#[async_trait]
impl ConnectContactStarter for CapturingStarter {
    async fn start_webrtc_contact(
        &self,
        request: StartContactRequest,
    ) -> rvoip_amazon_connect::Result<ConnectionData> {
        if let Some(sender) = self.captured.lock().expect("capture lock").take() {
            let _ = sender.send(request);
        }
        Ok(ConnectionData {
            contact_id: CONTACT_ID.into(),
            participant_id: "participant-standardcharter".into(),
            participant_token: "participant-token-standardcharter".into(),
            meeting_id: "meeting-standardcharter".into(),
            media_region: "us-west-2".into(),
            attendee_id: "attendee-standardcharter".into(),
            join_token: "join-token-standardcharter".into(),
            media_placement: MediaPlacement {
                signaling_url: "wss://localhost.invalid/signaling".into(),
                audio_host_url: "https://localhost.invalid/audio".into(),
                ..MediaPlacement::default()
            },
        })
    }

    async fn stop_contact(&self, request: StopContactRequest) -> rvoip_amazon_connect::Result<()> {
        let _ = self.stopped.send(request);
        Ok(())
    }
}

struct HermeticConnectStream {
    id: StreamId,
    inbound_tx: mpsc::Sender<MediaFrame>,
    inbound_rx: Mutex<Option<mpsc::Receiver<MediaFrame>>>,
    outbound_tx: mpsc::Sender<MediaFrame>,
    outbound_rx: Mutex<Option<mpsc::Receiver<MediaFrame>>>,
}

impl HermeticConnectStream {
    fn new() -> Arc<Self> {
        let (inbound_tx, inbound_rx) = mpsc::channel(32);
        let (outbound_tx, outbound_rx) = mpsc::channel(32);
        Arc::new(Self {
            id: StreamId::new(),
            inbound_tx,
            inbound_rx: Mutex::new(Some(inbound_rx)),
            outbound_tx,
            outbound_rx: Mutex::new(Some(outbound_rx)),
        })
    }

    fn take_output(&self) -> mpsc::Receiver<MediaFrame> {
        self.outbound_rx
            .lock()
            .expect("Connect output lock")
            .take()
            .expect("Connect output is taken once")
    }

    async fn inject(&self, mut frame: MediaFrame) {
        frame.stream_id = self.id.clone();
        frame.kind = StreamKind::Audio;
        frame.captured_at = Utc::now();
        self.inbound_tx
            .send(frame)
            .await
            .expect("Connect source stays open while the bridge is active");
    }
}

#[async_trait]
impl MediaStream for HermeticConnectStream {
    fn id(&self) -> StreamId {
        self.id.clone()
    }

    fn kind(&self) -> StreamKind {
        StreamKind::Audio
    }

    fn codec(&self) -> CodecInfo {
        CodecInfo {
            name: "opus".into(),
            clock_rate_hz: 48_000,
            channels: 1,
            fmtp: None,
        }
    }

    fn direction(&self) -> Direction {
        Direction::Inbound
    }

    fn frames_in(&self) -> mpsc::Receiver<MediaFrame> {
        self.inbound_rx
            .lock()
            .expect("Connect input lock")
            .take()
            .unwrap_or_else(|| mpsc::channel(1).1)
    }

    fn frames_out(&self) -> mpsc::Sender<MediaFrame> {
        self.outbound_tx.clone()
    }

    fn quality_snapshot(&self) -> QualitySnapshot {
        QualitySnapshot::default()
    }

    async fn close(self: Arc<Self>) -> rvoip_core::error::Result<()> {
        Ok(())
    }
}

struct HermeticMediaSession {
    stream: Arc<HermeticConnectStream>,
    terminal_tx: watch::Sender<Option<ConnectMediaTerminalCause>>,
    terminal_rx: watch::Receiver<Option<ConnectMediaTerminalCause>>,
    closes: AtomicUsize,
    aborts: AtomicUsize,
    close_notify: Notify,
}

impl HermeticMediaSession {
    fn new() -> Arc<Self> {
        let (terminal_tx, terminal_rx) = watch::channel(None);
        Arc::new(Self {
            stream: HermeticConnectStream::new(),
            terminal_tx,
            terminal_rx,
            closes: AtomicUsize::new(0),
            aborts: AtomicUsize::new(0),
            close_notify: Notify::new(),
        })
    }

    fn end_remotely(&self) {
        self.terminal_tx
            .send_replace(Some(ConnectMediaTerminalCause::RemoteEnded));
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
        .expect("Amazon media session was closed");
    }
}

#[async_trait]
impl ConnectMediaSession for HermeticMediaSession {
    fn negotiated_codecs(&self) -> NegotiatedCodecs {
        NegotiatedCodecs {
            audio: Some(self.stream.codec()),
            video: None,
        }
    }

    fn streams(&self) -> Vec<Arc<dyn MediaStream>> {
        vec![self.stream.clone()]
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

struct HermeticMediaConnector {
    session: Arc<HermeticMediaSession>,
}

#[async_trait]
impl ConnectMediaConnector for HermeticMediaConnector {
    async fn connect(
        &self,
        _connection: &ConnectionData,
        _options: ConnectMediaConnectOptions,
    ) -> rvoip_amazon_connect::Result<Arc<dyn ConnectMediaSession>> {
        Ok(self.session.clone())
    }
}

struct EstablishedCall {
    server: Arc<ConnectScreenPopServer>,
    serve_task: JoinHandle<rvoip_amazon_connect::Result<()>>,
    sip_client: UdpSocket,
    media_client: UdpSocket,
    sip_server_port: u16,
    client_port: u16,
    remote_target: String,
    to_header: String,
    server_media_port: u16,
    session: Arc<HermeticMediaSession>,
    connect_output: mpsc::Receiver<MediaFrame>,
    stopped: mpsc::UnboundedReceiver<StopContactRequest>,
    lifecycle: broadcast::Receiver<ScreenPopLifecycleEvent>,
    stages: Vec<ScreenPopLifecycleStage>,
}

impl EstablishedCall {
    async fn wait_for_stop(&mut self) -> StopContactRequest {
        tokio::time::timeout(Duration::from_secs(5), self.stopped.recv())
            .await
            .expect("StopContact was invoked")
            .expect("StopContact capture stayed open")
    }

    async fn wait_for_terminal_lifecycle(&mut self) {
        collect_lifecycle_through(
            &mut self.lifecycle,
            &mut self.stages,
            ScreenPopLifecycleStage::Terminated,
        )
        .await;
        assert_eq!(
            self.stages,
            [
                ScreenPopLifecycleStage::SipInviteReceived,
                ScreenPopLifecycleStage::AttributesMapped,
                ScreenPopLifecycleStage::ContactStarted,
                ScreenPopLifecycleStage::MediaConnected,
                ScreenPopLifecycleStage::TeardownStarted,
                ScreenPopLifecycleStage::Terminated,
            ],
            "screen-pop lifecycle remains ordered and complete"
        );
    }

    async fn finish(mut self) {
        assert!(self.server.active_call_ids().is_empty());
        assert_eq!(self.session.closes.load(Ordering::Acquire), 1);
        assert_eq!(self.session.aborts.load(Ordering::Acquire), 0);
        assert!(
            matches!(
                self.stopped.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "StopContact is invoked exactly once"
        );
        self.serve_task.abort();
        let _ = self.serve_task.await;
    }
}

fn available_udp_port() -> u16 {
    std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("reserve UDP port")
        .local_addr()
        .expect("reserved address")
        .port()
}

fn run_on_two_mib_worker_stack<F>(scenario: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_stack_size(2 * 1024 * 1024)
        .enable_all()
        .build()
        .expect("two MiB StandardCharter regression runtime");
    let task = runtime.spawn(scenario);
    runtime
        .block_on(task)
        .expect("StandardCharter scenario completed on a two MiB worker stack");
}

fn render_invite(server_port: u16, client_port: u16, media_port: u16) -> Vec<u8> {
    let normalized = VAPI_INVITE.replace("\r\n", "\n");
    let (headers, body) = normalized
        .split_once("\n\n")
        .expect("golden INVITE has a header/body separator");
    let body = body
        .trim_end_matches('\n')
        .replace("__MEDIA_PORT__", &media_port.to_string())
        .replace('\n', "\r\n")
        + "\r\n";
    let headers = headers
        .replace("__SERVER_PORT__", &server_port.to_string())
        .replace("__CLIENT_PORT__", &client_port.to_string())
        .replace("__MEDIA_PORT__", &media_port.to_string())
        .replace("__CONTENT_LENGTH__", &body.len().to_string())
        .replace('\n', "\r\n");
    format!("{headers}\r\n\r\n{body}").into_bytes()
}

fn header_value<'a>(message: &'a str, wanted: &str) -> Option<&'a str> {
    message.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case(wanted)
            .then(|| value.trim())
    })
}

fn contact_uri(value: &str) -> String {
    value
        .split_once('<')
        .and_then(|(_, rest)| rest.split_once('>').map(|(uri, _)| uri))
        .unwrap_or_else(|| value.split(';').next().unwrap_or(value))
        .trim()
        .to_string()
}

fn media_port(answer: &str) -> u16 {
    answer
        .lines()
        .find_map(|line| {
            line.trim_end_matches('\r')
                .strip_prefix("m=audio ")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .expect("200 SDP advertises an audio port")
}

async fn receive_through_200(client: &UdpSocket) -> Vec<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut packet = vec![0_u8; 65_535];
    let mut responses = Vec::new();
    loop {
        let (len, _) = tokio::time::timeout_at(deadline, client.recv_from(&mut packet))
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for SIP 200; saw {responses:?}"))
            .expect("receive SIP response");
        let response = String::from_utf8_lossy(&packet[..len]).into_owned();
        let is_200 = response.starts_with("SIP/2.0 200 ");
        responses.push(response);
        if is_200 {
            return responses;
        }
    }
}

async fn send_ack(call: &EstablishedCall) {
    let ack = format!(
        "ACK {} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:{};branch=z9hG4bK-standardcharter-ack;rport\r\n\
         Max-Forwards: 70\r\n\
         From: \"Vapi caller\" <sip:vapi@127.0.0.1:{}>;tag=vapi-golden\r\n\
         To: {}\r\n\
         Call-ID: {}\r\n\
         CSeq: 1 ACK\r\n\
         Contact: <sip:vapi@127.0.0.1:{}>\r\n\
         Content-Length: 0\r\n\r\n",
        call.remote_target,
        call.client_port,
        call.client_port,
        call.to_header,
        CALL_ID,
        call.client_port,
    );
    call.sip_client
        .send_to(
            ack.as_bytes(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, call.sip_server_port)),
        )
        .await
        .expect("send ACK");
}

async fn collect_lifecycle_through(
    receiver: &mut broadcast::Receiver<ScreenPopLifecycleEvent>,
    stages: &mut Vec<ScreenPopLifecycleStage>,
    target: ScreenPopLifecycleStage,
) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let event = receiver.recv().await.expect("lifecycle feed stays open");
            assert_eq!(event.correlation_id.as_deref(), Some("+14155550199"));
            stages.push(event.stage);
            if event.stage == target {
                return;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {target:?}; saw {stages:?}"));
}

async fn establish_call() -> EstablishedCall {
    let sip_server_port = available_udp_port();
    let yaml = GOLDEN_CONFIG.replace("__SIP_PORT__", &sip_server_port.to_string());
    let cfg: config::Config = serde_yaml::from_str(&yaml).expect("golden config parses");
    cfg.validate().expect("golden config is valid");

    let sip_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind Vapi SIP client");
    let client_port = sip_client.local_addr().expect("SIP client address").port();
    let media_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind Vapi RTP client");
    let client_media_port = media_client
        .local_addr()
        .expect("RTP client address")
        .port();

    let (captured_tx, captured_rx) = oneshot::channel();
    let (stopped_tx, stopped) = mpsc::unbounded_channel();
    let starter: Arc<dyn ConnectContactStarter> = Arc::new(CapturingStarter {
        captured: Mutex::new(Some(captured_tx)),
        stopped: stopped_tx,
    });
    let session = HermeticMediaSession::new();
    let connect_output = session.stream.take_output();
    let connector: Arc<dyn ConnectMediaConnector> = Arc::new(HermeticMediaConnector {
        session: Arc::clone(&session),
    });
    let server_config = cfg
        .build_server_config_with_starter(starter)
        .await
        .expect("Bridgefu builds without AWS or IMDS");
    let server = ConnectScreenPopServer::build_with_media_connector(server_config, connector)
        .await
        .expect("localhost SIP server builds");
    let lifecycle = server.subscribe_lifecycle();
    let serve_task = tokio::spawn(server.clone().serve());
    tokio::time::sleep(Duration::from_millis(50)).await;

    let invite = render_invite(sip_server_port, client_port, client_media_port);
    sip_client
        .send_to(
            &invite,
            SocketAddr::from((Ipv4Addr::LOCALHOST, sip_server_port)),
        )
        .await
        .expect("send golden Vapi INVITE");

    let request = tokio::time::timeout(Duration::from_secs(5), captured_rx)
        .await
        .expect("StartWebRTCContact was invoked before the test deadline")
        .expect("capture sender stayed alive");
    assert_eq!(request.instance_id, "instance-standardcharter-test");
    assert_eq!(request.contact_flow_id, "flow-standardcharter-test");
    assert!(
        request.display_name.to_ascii_lowercase().contains("vapi"),
        "SIP From identity is preserved for the agent display name: {}",
        request.display_name
    );
    assert_eq!(
        request.attributes.get("correlation_id").map(String::as_str),
        Some("+14155550199")
    );
    assert_eq!(
        request
            .attributes
            .get("HostedWidget-customerId")
            .map(String::as_str),
        Some("customer-42")
    );
    assert_eq!(
        request
            .attributes
            .get("HostedWidget-vapiCallId")
            .map(String::as_str),
        Some("vapi-call-77")
    );
    assert_eq!(
        request
            .attributes
            .get("HostedWidget-accountTier")
            .map(String::as_str),
        Some("gold")
    );
    assert_eq!(request.attributes.len(), 4);
    assert!(
        request
            .attributes
            .values()
            .all(|value| value != "must-not-reach-connect"),
        "unallowlisted SIP headers must not cross the Connect boundary"
    );

    let responses = receive_through_200(&sip_client).await;
    assert!(
        responses
            .iter()
            .any(|response| response.starts_with("SIP/2.0 180 Ringing")),
        "the inbound Vapi call rings before acceptance: {responses:?}"
    );
    let accepted = responses.last().expect("response sequence is not empty");
    assert!(accepted.starts_with("SIP/2.0 200 OK"));
    assert!(accepted.contains("Content-Type: application/sdp"));
    let (_, answer_sdp) = accepted
        .split_once("\r\n\r\n")
        .expect("200 response carries an SDP body");
    assert!(answer_sdp.contains("m=audio "));
    assert!(answer_sdp.contains("a=rtpmap:0 PCMU/8000"));
    assert!(answer_sdp.contains("a=rtpmap:101 telephone-event/8000"));

    let remote_target = contact_uri(
        header_value(accepted, "Contact").expect("200 response carries a Contact target"),
    );
    let to_header = header_value(accepted, "To")
        .expect("200 response carries a tagged To")
        .to_string();
    assert!(to_header.contains(";tag="));
    let server_media_port = media_port(accepted);
    assert_ne!(
        server_media_port, 0,
        "the SIP answer must advertise a usable RTP port"
    );
    let mut stages = Vec::new();
    let mut call = EstablishedCall {
        server,
        serve_task,
        sip_client,
        media_client,
        sip_server_port,
        client_port,
        remote_target,
        to_header,
        server_media_port,
        session,
        connect_output,
        stopped,
        lifecycle,
        stages: Vec::new(),
    };
    send_ack(&call).await;
    // `MediaConnected` describes the bridge graph, while the SIP UAS becomes
    // RTP-active only after its 2xx ACK is consumed by the session machine.
    tokio::time::sleep(Duration::from_millis(100)).await;
    collect_lifecycle_through(
        &mut call.lifecycle,
        &mut stages,
        ScreenPopLifecycleStage::MediaConnected,
    )
    .await;
    call.stages = stages;
    call
}

fn pcmu_rtp_packet(sequence: u16, timestamp: u32, frame: u8) -> Vec<u8> {
    let mut packet = Vec::with_capacity(12 + 160);
    packet.extend_from_slice(&[0x80, if sequence == 1 { 0x80 } else { 0x00 }]);
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.extend_from_slice(&0x52_56_4f_49_u32.to_be_bytes());
    packet.extend((0..160).map(|sample| {
        if ((sample / 10) + usize::from(frame)) % 2 == 0 {
            0x10
        } else {
            0x90
        }
    }));
    packet
}

fn rtp_payload_type(packet: &[u8]) -> Option<u8> {
    (packet.len() >= 12 && packet[0] >> 6 == 2).then(|| packet[1] & 0x7f)
}

async fn assert_pcmu_opus_round_trip(call: &mut EstablishedCall) {
    let media_target = SocketAddr::from((Ipv4Addr::LOCALHOST, call.server_media_port));
    for index in 0..8_u16 {
        let packet = pcmu_rtp_packet(index + 1, 8_000 + u32::from(index) * 160, index as u8);
        call.media_client
            .send_to(&packet, media_target)
            .await
            .expect("send Vapi PCMU RTP");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let mut opus = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        while opus.len() < 4 {
            let frame = call
                .connect_output
                .recv()
                .await
                .expect("Connect media sink remains open");
            if frame.payload_type == Some(111) && !frame.payload.is_empty() {
                opus.push(frame);
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "PCMU sent to localhost:{} did not reach the fake Connect leg as Opus",
            call.server_media_port
        )
    });
    assert!(
        opus.windows(2)
            .all(|pair| pair[1].timestamp_rtp.wrapping_sub(pair[0].timestamp_rtp) == 960),
        "Opus output uses a 48 kHz, 20 ms RTP clock"
    );

    for frame in opus {
        call.session.stream.inject(frame).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let mut packet = vec![0_u8; 2_048];
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (bytes, _) = call
                .media_client
                .recv_from(&mut packet)
                .await
                .expect("receive bridged Vapi RTP");
            if rtp_payload_type(&packet[..bytes]) == Some(0) {
                assert!(bytes >= 12 + 160, "one PCMU frame is returned on RTP");
                return;
            }
        }
    })
    .await
    .expect("Opus reached the Vapi leg as PCMU RTP");
}

async fn send_vapi_bye(call: &EstablishedCall) {
    let bye = format!(
        "BYE {} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:{};branch=z9hG4bK-standardcharter-bye;rport\r\n\
         Max-Forwards: 70\r\n\
         From: \"Vapi caller\" <sip:vapi@127.0.0.1:{}>;tag=vapi-golden\r\n\
         To: {}\r\n\
         Call-ID: {}\r\n\
         CSeq: 2 BYE\r\n\
         Contact: <sip:vapi@127.0.0.1:{}>\r\n\
         Content-Length: 0\r\n\r\n",
        call.remote_target,
        call.client_port,
        call.client_port,
        call.to_header,
        CALL_ID,
        call.client_port,
    );
    call.sip_client
        .send_to(
            bye.as_bytes(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, call.sip_server_port)),
        )
        .await
        .expect("send Vapi BYE");

    let mut packet = vec![0_u8; 8_192];
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (bytes, _) = call
                .sip_client
                .recv_from(&mut packet)
                .await
                .expect("receive BYE response");
            let response = String::from_utf8_lossy(&packet[..bytes]);
            if response.starts_with("SIP/2.0 200 ")
                && header_value(&response, "CSeq").is_some_and(|cseq| cseq == "2 BYE")
            {
                return;
            }
        }
    })
    .await
    .expect("Vapi BYE received 200 OK");
}

async fn receive_server_bye_and_respond(call: &EstablishedCall) {
    let mut packet = vec![0_u8; 8_192];
    let (wire, peer) = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (bytes, peer) = call
                .sip_client
                .recv_from(&mut packet)
                .await
                .expect("receive server BYE");
            let wire = String::from_utf8_lossy(&packet[..bytes]).into_owned();
            if wire.starts_with("BYE ") {
                return (wire, peer);
            }
        }
    })
    .await
    .expect("Connect hangup generated a SIP BYE");

    let via = header_value(&wire, "Via").expect("BYE Via");
    let from = header_value(&wire, "From").expect("BYE From");
    let to = header_value(&wire, "To").expect("BYE To");
    let call_id = header_value(&wire, "Call-ID").expect("BYE Call-ID");
    let cseq = header_value(&wire, "CSeq").expect("BYE CSeq");
    assert_eq!(call_id, CALL_ID);
    assert!(cseq.ends_with(" BYE"));
    let response = format!(
        "SIP/2.0 200 OK\r\n\
         Via: {via}\r\n\
         From: {from}\r\n\
         To: {to}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq}\r\n\
         Content-Length: 0\r\n\r\n"
    );
    call.sip_client
        .send_to(response.as_bytes(), peer)
        .await
        .expect("answer server BYE");
}

fn assert_stop_request(request: &StopContactRequest) {
    assert_eq!(request.instance_id, "instance-standardcharter-test");
    assert_eq!(request.contact_id, CONTACT_ID);
}

#[test]
fn vapi_to_connect_contract_bridges_media_and_vapi_teardown() {
    run_on_two_mib_worker_stack(async move {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("rvoip_amazon_connect=debug,rvoip_sip=info")
            .with_test_writer()
            .try_init();
        let mut call = establish_call().await;

        assert_pcmu_opus_round_trip(&mut call).await;
        send_vapi_bye(&call).await;
        assert_stop_request(&call.wait_for_stop().await);
        call.session.wait_closed().await;
        call.wait_for_terminal_lifecycle().await;
        call.finish().await;
    });
}

#[test]
fn connect_teardown_sends_vapi_bye_and_stops_contact_once() {
    run_on_two_mib_worker_stack(async move {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("rvoip_amazon_connect=debug,rvoip_sip=debug")
            .with_test_writer()
            .try_init();
        let mut call = establish_call().await;

        call.session.end_remotely();
        receive_server_bye_and_respond(&call).await;
        assert_stop_request(&call.wait_for_stop().await);
        call.session.wait_closed().await;
        call.wait_for_terminal_lifecycle().await;
        call.finish().await;
    });
}
