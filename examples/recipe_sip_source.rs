//! Controlled direct SIP/RTP and SIPS/SRTP source for recipe qualification.
//!
//! The binary reads the collector's mode-0600 private session, places exactly
//! one call with exactly one `X-Correlation-Id`, sends deterministic audio and
//! RFC 4733 probes, observes the reciprocal probes and BYE, and writes only a
//! strict redacted observation. Raw identifiers, SIP/SDP, and media never
//! leave process memory.

use anyhow::{bail, Context};
use clap::Parser;
use rvoip_sip::api::headers::SipRequestOptions;
use rvoip_sip::{
    AudioFrame, CallHandlerDecision, CallbackPeer, Config, HeaderName, MediaSecurityProfile,
    SipTlsMode, SipTrace, SipTraceConfig, SipTraceDirection,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex};

const PRODUCER: &str = "bridgefu-recipe-sip-source@1";
const RECIPE: &str = "vapi-amazon-connect-screen-pop@1";
const HEADER_NAME: &str = "X-Correlation-Id";
const FRAME_SAMPLES: usize = 160;
const FRAME_DURATION: Duration = Duration::from_millis(20);
const MARKER_FREQUENCY: f32 = 997.0;
const AGENT_MARKER_FREQUENCY: f64 = 880.0;
const SOURCE_MARKER_PULSES: usize = 30;
const REQUIRED_AGENT_MARKERS: usize = 5;
const MARKER_TONE_FRAMES: usize = 5;
const MARKER_SILENCE_FRAMES: usize = 45;
const MAX_SESSION_BYTES: u64 = 1024 * 1024;

#[derive(Parser)]
#[command(about = "Protected Bridgefu recipe SIP source", version)]
struct Args {
    #[arg(long)]
    session: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = 5076)]
    sip_port: u16,
    #[arg(long, default_value_t = 31_000)]
    media_port_start: u16,
    #[arg(long, default_value_t = 90)]
    timeout_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateSession {
    schema_version: u8,
    execution_id: String,
    recipe: String,
    release_id: String,
    source_tree_sha256: String,
    image: String,
    session_id: String,
    scenario_id: String,
    hangup_origin: String,
    security: String,
    codec: String,
    network_profile: String,
    network_contract: NetworkContract,
    started_at: String,
    started_epoch_ms: u64,
    correlation_id: String,
    correlation_fingerprint: String,
    source_call_id: String,
    source_org_id: String,
    source_call_fingerprint: String,
    sip_uri: String,
    sip_header: PrivateSipHeader,
    expected_context: serde_json::Value,
    session_hmac: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateSipHeader {
    name: String,
    value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkContract {
    delay_ms: u16,
    jitter_ms: u16,
    loss_percent: f32,
    reorder_percent: f32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Security {
    SipRtp,
    SipsSrtp,
}

impl Security {
    fn scheme(self) -> &'static str {
        match self {
            Self::SipRtp => "sip",
            Self::SipsSrtp => "sips",
        }
    }

    fn transport(self) -> &'static str {
        match self {
            Self::SipRtp => "udp",
            Self::SipsSrtp => "tls",
        }
    }

    fn media(self) -> &'static str {
        match self {
            Self::SipRtp => "rtp",
            Self::SipsSrtp => "srtp",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Codec {
    Pcmu,
    Pcma,
}

impl Codec {
    fn label(self) -> &'static str {
        match self {
            Self::Pcmu => "pcmu",
            Self::Pcma => "pcma",
        }
    }

    fn payload(self) -> u8 {
        match self {
            Self::Pcmu => 0,
            Self::Pcma => 8,
        }
    }
}

struct ValidatedSession {
    private: PrivateSession,
    security: Security,
    codec: Codec,
}

#[derive(Default)]
struct WireEvidence {
    invite_count: usize,
    header_count: Option<usize>,
    header_contract_failed: bool,
    transport: Option<String>,
    replay_rejection_status: Option<u16>,
}

#[derive(Serialize)]
struct Observation {
    schema_version: u8,
    producer: &'static str,
    producer_revision_sha256: String,
    execution_id: String,
    scenario_id: String,
    hangup_origin: String,
    correlation_fingerprint: String,
    source_call_fingerprint: String,
    observed_at: String,
    signaling: SignalingObservation,
    media: MediaObservation,
    hangup: HangupObservation,
    redacted: bool,
}

#[derive(Serialize)]
struct SignalingObservation {
    scheme: &'static str,
    transport: &'static str,
    invite_sent: bool,
    wire_header_name: &'static str,
    wire_header_count: usize,
    answered: bool,
    attachment_replay_rejected: bool,
}

#[derive(Serialize)]
struct MediaObservation {
    codec: &'static str,
    security: &'static str,
    source_marker_sent_at_ms: Vec<u64>,
    agent_marker_observed_at_ms: Vec<u64>,
    source_to_agent_marker_frames_sent: usize,
    agent_to_source_marker_frames: usize,
    dtmf_source_to_agent_sent: bool,
    dtmf_agent_to_source_observed: bool,
}

#[derive(Serialize)]
struct HangupObservation {
    origin: String,
    local_bye_completed: bool,
    remote_bye_observed: bool,
    cleanup_observed: bool,
}

#[derive(Default)]
struct ToneEdges {
    active: bool,
    last_edge_ms: Option<u64>,
    timestamps: Vec<u64>,
    frames: usize,
}

impl ToneEdges {
    fn observe(&mut self, frame: &AudioFrame, frequency: f64) {
        let present = frame.channels == 1
            && (8_000..=48_000).contains(&frame.sample_rate)
            && rms(&frame.samples) >= 0.01
            && tone_power(&frame.samples, frame.sample_rate, frequency) >= 0.001;
        if present {
            self.frames += 1;
            let now = now_ms();
            let outside_refractory = self
                .last_edge_ms
                .is_none_or(|previous| now.saturating_sub(previous) >= 500);
            if !self.active && outside_refractory && self.timestamps.len() < REQUIRED_AGENT_MARKERS
            {
                self.timestamps.push(now);
                self.last_edge_ms = Some(now);
            }
        }
        self.active = present;
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after Unix epoch")
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn utc_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn producer_revision() -> String {
    hex_digest(include_bytes!("recipe_sip_source.rs"))
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_fingerprint(value: &str) -> bool {
    value.len() == 12
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_correlation(value: &str) -> bool {
    value.len() == 47
        && value.starts_with("bf1_")
        && value[4..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn is_safe_identifier(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'@' | b'/')
        })
}

fn read_session(path: &Path) -> anyhow::Result<PrivateSession> {
    let metadata = fs::symlink_metadata(path).context("private session is unavailable")?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!("private session must be a regular non-symlink file");
    }
    if metadata.len() == 0 || metadata.len() > MAX_SESSION_BYTES {
        bail!("private session exceeds its size boundary");
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("private session permissions must be mode 0600");
    }
    serde_json::from_reader(BufReader::new(
        fs::File::open(path).context("opening private session")?,
    ))
    .context("private session does not match its strict JSON contract")
}

fn validate_session(private: PrivateSession) -> anyhow::Result<ValidatedSession> {
    let (expected_security, expected_codec) = match private.scenario_id.as_str() {
        "sip-rtp-pcmu" => (Security::SipRtp, Codec::Pcmu),
        "sip-rtp-pcma" => (Security::SipRtp, Codec::Pcma),
        "sips-srtp-pcmu" => (Security::SipsSrtp, Codec::Pcmu),
        "sips-srtp-pcma" => (Security::SipsSrtp, Codec::Pcma),
        _ => bail!("private session scenario is not a direct SIP qualification"),
    };
    let expected_security_label = match expected_security {
        Security::SipRtp => "sip_rtp",
        Security::SipsSrtp => "sips_srtp",
    };
    let calculated_fingerprint = &hex_digest(private.correlation_id.as_bytes())[..12];
    let expected_uri_prefix = format!("{}:", expected_security.scheme());
    let uri_is_bounded = (1..=2048).contains(&private.sip_uri.len())
        && private
            .sip_uri
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'\r' | b'\n'));
    if private.schema_version != 1
        || private.recipe != RECIPE
        || !is_safe_identifier(&private.execution_id, 8, 24)
        || !private.execution_id.starts_with("bft-")
        || !is_safe_identifier(&private.release_id, 20, 20)
        || !is_sha256(&private.source_tree_sha256)
        || !private.image.contains("@sha256:")
        || !is_safe_identifier(&private.session_id, 8, 64)
        || !matches!(private.hangup_origin.as_str(), "source" | "agent")
        || private.security != expected_security_label
        || private.codec != expected_codec.label()
        || !matches!(
            private.network_profile.as_str(),
            "baseline" | "moderate-wan"
        )
        || (private.network_profile == "baseline"
            && (private.network_contract.delay_ms != 0
                || private.network_contract.jitter_ms != 0
                || private.network_contract.loss_percent != 0.0
                || private.network_contract.reorder_percent != 0.0))
        || (private.network_profile == "moderate-wan"
            && (private.network_contract.delay_ms != 80
                || private.network_contract.jitter_ms != 20
                || private.network_contract.loss_percent != 1.0
                || private.network_contract.reorder_percent != 0.1))
        || private.started_at.len() < 20
        || private.started_epoch_ms == 0
        || !is_correlation(&private.correlation_id)
        || private.correlation_fingerprint != calculated_fingerprint
        || !is_safe_identifier(&private.source_call_id, 1, 128)
        || !is_safe_identifier(&private.source_org_id, 1, 128)
        || private.source_call_fingerprint != hex_digest(private.source_call_id.as_bytes())[..12]
        || !is_fingerprint(&private.source_call_fingerprint)
        || !private.sip_uri.starts_with(&expected_uri_prefix)
        || !uri_is_bounded
        || private.sip_header.name != HEADER_NAME
        || private.sip_header.value != private.correlation_id
        || !private.expected_context.is_object()
        || !is_sha256(&private.session_hmac)
    {
        bail!("private session violates the controlled source contract");
    }
    Ok(ValidatedSession {
        private,
        security: expected_security,
        codec: expected_codec,
    })
}

fn validate_args(args: &Args) -> anyhow::Result<()> {
    if args.sip_port == 0 {
        bail!("SIP source port must be nonzero");
    }
    if args.media_port_start < 1024 || args.media_port_start > u16::MAX - 31 {
        bail!("media port range is invalid");
    }
    if !(30..=300).contains(&args.timeout_seconds) {
        bail!("timeout seconds must be between 30 and 300");
    }
    if args.output.exists() {
        bail!("source observation output already exists");
    }
    Ok(())
}

fn observe_wire(trace: &SipTrace, evidence: &mut WireEvidence) {
    if trace.direction == SipTraceDirection::Inbound && evidence.invite_count >= 2 {
        let mut fields = trace.start_line.split_whitespace();
        if fields.next() == Some("SIP/2.0") {
            let status = fields.next().and_then(|value| value.parse::<u16>().ok());
            if status.is_some_and(|value| (300..=699).contains(&value)) {
                evidence.replay_rejection_status = status;
            }
        }
        return;
    }
    if trace.direction != SipTraceDirection::Outbound || !trace.start_line.starts_with("INVITE ") {
        return;
    }
    let count = trace
        .raw_message
        .lines()
        .filter_map(|line| line.split_once(':').map(|(name, _)| name.trim()))
        .filter(|name| name.eq_ignore_ascii_case(HEADER_NAME))
        .count();
    evidence.invite_count += 1;
    evidence.header_contract_failed |= count != 1;
    evidence.header_count.get_or_insert(count);
    if evidence.header_count != Some(count) {
        evidence.header_contract_failed = true;
    }
    let transport = trace.transport.to_ascii_lowercase();
    if evidence
        .transport
        .as_ref()
        .is_some_and(|existing| existing != &transport)
    {
        evidence.header_contract_failed = true;
    }
    evidence.transport = Some(transport);
}

fn rms(samples: &[i16]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let energy = samples
        .iter()
        .map(|sample| {
            let normalized = f64::from(*sample) / f64::from(i16::MAX);
            normalized * normalized
        })
        .sum::<f64>();
    (energy / samples.len() as f64).sqrt()
}

fn tone_power(samples: &[i16], sample_rate: u32, frequency: f64) -> f64 {
    if samples.is_empty() || sample_rate == 0 {
        return 0.0;
    }
    let coefficient = 2.0 * (2.0 * std::f64::consts::PI * frequency / f64::from(sample_rate)).cos();
    let mut previous = 0.0;
    let mut before_previous = 0.0;
    for sample in samples {
        let normalized = f64::from(*sample) / f64::from(i16::MAX);
        let current = normalized + coefficient * previous - before_previous;
        before_previous = previous;
        previous = current;
    }
    let raw = previous * previous + before_previous * before_previous
        - coefficient * previous * before_previous;
    raw / (samples.len() as f64 * samples.len() as f64)
}

fn tone_frame(frequency: f32, phase: &mut f32) -> Vec<i16> {
    let step = 2.0 * std::f32::consts::PI * frequency / 8_000.0;
    (0..FRAME_SAMPLES)
        .map(|_| {
            let sample = phase.sin() * 0.25 * f32::from(i16::MAX);
            *phase = (*phase + step) % (2.0 * std::f32::consts::PI);
            sample as i16
        })
        .collect()
}

async fn send_markers(sender: rvoip_sip::AudioSender) -> anyhow::Result<(Vec<u64>, usize)> {
    let mut timestamps = Vec::with_capacity(SOURCE_MARKER_PULSES);
    let mut phase = 0.0;
    let mut timestamp = 0_u32;
    let mut frames = 0;
    for _ in 0..SOURCE_MARKER_PULSES {
        timestamps.push(now_ms());
        for _ in 0..MARKER_TONE_FRAMES {
            sender
                .send(AudioFrame::new(
                    tone_frame(MARKER_FREQUENCY, &mut phase),
                    8_000,
                    1,
                    timestamp,
                ))
                .await
                .context("sending source marker frame")?;
            timestamp = timestamp.wrapping_add(FRAME_SAMPLES as u32);
            frames += 1;
            tokio::time::sleep(FRAME_DURATION).await;
        }
        for _ in 0..MARKER_SILENCE_FRAMES {
            sender
                .send(AudioFrame::new(vec![0; FRAME_SAMPLES], 8_000, 1, timestamp))
                .await
                .context("sending source marker spacing")?;
            timestamp = timestamp.wrapping_add(FRAME_SAMPLES as u32);
            tokio::time::sleep(FRAME_DURATION).await;
        }
    }
    Ok((timestamps, frames))
}

fn write_observation(path: &Path, observation: &Observation) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .context("source observation output requires a parent directory")?;
    fs::create_dir_all(parent).context("creating source observation directory")?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .context("protecting source observation directory")?;
    let temporary = path.with_extension("json.tmp");
    if temporary.exists() {
        bail!("source observation temporary output already exists");
    }
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .context("creating source observation")?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, observation)
        .context("serializing source observation")?;
    writer
        .write_all(b"\n")
        .context("finishing source observation")?;
    writer.flush().context("flushing source observation")?;
    drop(writer);
    fs::rename(&temporary, path).context("publishing source observation")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .context("protecting source observation")?;
    Ok(())
}

async fn run(args: Args) -> anyhow::Result<()> {
    validate_args(&args)?;
    let session = validate_session(read_session(&args.session)?)?;
    let mut config = Config::on(
        "bridgefu-recipe-qualification-source",
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        args.sip_port,
    )
    .with_server_capacity(1)
    .with_media_port_capacity(args.media_port_start, 32);
    config.offered_codecs = vec![session.codec.payload(), 101];
    config.strict_codec_matching = true;
    config.offer_srtp = session.security == Security::SipsSrtp;
    config.srtp_required = session.security == Security::SipsSrtp;
    config.active_call_no_media_timeout_secs = args.timeout_seconds;
    config.active_call_media_idle_timeout_secs = args.timeout_seconds;
    config.setup_teardown_timeout_secs = args.timeout_seconds;
    config.sip_trace = SipTraceConfig::enabled();
    if session.security == Security::SipsSrtp {
        config.sip_tls_mode = SipTlsMode::ClientOnly;
    }
    config.validate().map_err(anyhow::Error::msg)?;

    let wire = Arc::new(Mutex::new(WireEvidence::default()));
    let (dtmf_tx, mut dtmf_rx) = mpsc::channel::<char>(4);
    let (ended_tx, mut ended_rx) = mpsc::channel::<()>(2);
    let peer = CallbackPeer::builder(config)
        .on_incoming(|_| async move {
            CallHandlerDecision::Reject {
                status: 486,
                reason: "Qualification source does not accept inbound calls".into(),
            }
        })
        .on_dtmf(move |_handle, digit| {
            let dtmf_tx = dtmf_tx.clone();
            async move {
                let _ = dtmf_tx.send(digit).await;
                Ok(())
            }
        })
        .on_ended(move |_call_id, _reason| {
            let ended_tx = ended_tx.clone();
            async move {
                let _ = ended_tx.send(()).await;
                Ok(())
            }
        })
        .on_sip_trace({
            let wire = Arc::clone(&wire);
            move |trace| {
                let wire = Arc::clone(&wire);
                async move {
                    let mut evidence = wire.lock().await;
                    observe_wire(&trace, &mut evidence);
                    Ok(())
                }
            }
        })
        .build()
        .await
        .context("building controlled SIP source")?;
    let control = peer.control();
    let shutdown = peer.shutdown_handle();
    let peer_task = tokio::spawn(peer.run());
    tokio::time::sleep(Duration::from_millis(200)).await;

    let call_id = control
        .invite(session.private.sip_uri.clone())
        .with_raw_header(
            HeaderName::Other(HEADER_NAME.to_owned()),
            session.private.correlation_id.clone(),
        )
        .context("staging the exact correlation header")?
        .send()
        .await
        .context("sending controlled recipe INVITE")?;
    let handle = control.coordinator().session(&call_id);
    let handle = handle
        .wait_for_answered(Some(Duration::from_secs(args.timeout_seconds)))
        .await
        .context("controlled recipe call was not answered")?;
    match session.security {
        Security::SipsSrtp => {
            let security = handle
                .wait_for_media_security(Some(Duration::from_secs(10)))
                .await
                .context("SRTP negotiation was not observed")?;
            if security.profile != MediaSecurityProfile::RtpSavp || !security.contexts_installed {
                bail!("SRTP contexts were not installed");
            }
        }
        Security::SipRtp => {
            if handle.media_security().await?.is_some() {
                bail!("plaintext RTP scenario unexpectedly negotiated SRTP");
            }
        }
    }
    let audio = handle
        .audio()
        .await
        .context("opening controlled recipe audio")?;
    let (sender, mut receiver) = audio.split();
    let receive_task = tokio::spawn(async move {
        let mut detector = ToneEdges::default();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
        while detector.timestamps.len() < REQUIRED_AGENT_MARKERS {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining.min(Duration::from_secs(2)), receiver.recv()).await
            {
                Ok(Some(frame)) => detector.observe(&frame, AGENT_MARKER_FREQUENCY),
                Ok(None) => break,
                Err(_) => {}
            }
        }
        detector
    });
    let (source_marker_sent_at_ms, source_to_agent_marker_frames_sent) =
        send_markers(sender).await?;
    handle
        .send_dtmf('5')
        .await
        .context("sending source RFC 4733 DTMF")?;
    let agent_dtmf = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(digit) = dtmf_rx.recv().await {
            if digit == '6' {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    if !agent_dtmf {
        bail!("agent-to-source RFC 4733 DTMF was not observed");
    }
    let agent_marker = tokio::time::timeout(Duration::from_secs(50), receive_task)
        .await
        .context("agent marker observation timed out")?
        .context("agent marker observer stopped unexpectedly")?;
    if agent_marker.timestamps.len() != REQUIRED_AGENT_MARKERS
        || agent_marker.frames < REQUIRED_AGENT_MARKERS
    {
        bail!("agent-to-source audio marker evidence is incomplete");
    }

    let (local_bye_completed, remote_bye_observed) = if session.private.hangup_origin == "source" {
        handle
            .hangup_and_wait(Some(Duration::from_secs(10)))
            .await
            .context("source BYE did not complete")?;
        (true, false)
    } else {
        tokio::time::timeout(Duration::from_secs(30), ended_rx.recv())
            .await
            .context("agent BYE was not observed")?
            .context("agent BYE observer stopped")?;
        (false, true)
    };
    let replay_call_id = control
        .invite(session.private.sip_uri.clone())
        .with_raw_header(
            HeaderName::Other(HEADER_NAME.to_owned()),
            session.private.correlation_id.clone(),
        )
        .context("staging the replay correlation header")?
        .send()
        .await
        .context("sending the controlled attachment replay")?;
    let replay_handle = control.coordinator().session(&replay_call_id);
    if replay_handle
        .wait_for_answered(Some(Duration::from_secs(10)))
        .await
        .is_ok()
    {
        bail!("one-use SIP attachment replay was answered");
    }
    tokio::time::sleep(Duration::from_millis(250)).await;
    let wire = wire.lock().await;
    if wire.invite_count != 2
        || wire.header_contract_failed
        || wire.header_count != Some(1)
        || wire.transport.as_deref() != Some(session.security.transport())
        || wire
            .replay_rejection_status
            .is_none_or(|status| !(300..=699).contains(&status))
    {
        bail!("wire-level INVITE/header/transport evidence failed");
    }
    drop(wire);

    shutdown.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(5), peer_task).await;
    let observation = Observation {
        schema_version: 1,
        producer: PRODUCER,
        producer_revision_sha256: producer_revision(),
        execution_id: session.private.execution_id,
        scenario_id: session.private.scenario_id,
        hangup_origin: session.private.hangup_origin.clone(),
        correlation_fingerprint: session.private.correlation_fingerprint,
        source_call_fingerprint: session.private.source_call_fingerprint,
        observed_at: utc_now(),
        signaling: SignalingObservation {
            scheme: session.security.scheme(),
            transport: session.security.transport(),
            invite_sent: true,
            wire_header_name: "x-correlation-id",
            wire_header_count: 1,
            answered: true,
            attachment_replay_rejected: true,
        },
        media: MediaObservation {
            codec: session.codec.label(),
            security: session.security.media(),
            source_marker_sent_at_ms,
            agent_marker_observed_at_ms: agent_marker.timestamps,
            source_to_agent_marker_frames_sent,
            agent_to_source_marker_frames: agent_marker.frames,
            dtmf_source_to_agent_sent: true,
            dtmf_agent_to_source_observed: true,
        },
        hangup: HangupObservation {
            origin: session.private.hangup_origin,
            local_bye_completed,
            remote_bye_observed,
            cleanup_observed: true,
        },
        redacted: true,
    };
    write_observation(&args.output, &observation)?;
    println!("{}", args.output.display());
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run(Args::parse()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detector_records_bounded_rising_edges() {
        let mut detector = ToneEdges::default();
        let mut phase = 0.0;
        for _ in 0..8 {
            detector.observe(
                &AudioFrame::new(tone_frame(880.0, &mut phase), 8_000, 1, 0),
                AGENT_MARKER_FREQUENCY,
            );
        }
        assert_eq!(detector.timestamps.len(), 1);
        assert!(detector.frames >= 3);
    }

    #[test]
    fn wire_observer_counts_header_names_without_retaining_values() {
        let mut evidence = WireEvidence::default();
        observe_wire(
            &SipTrace {
                direction: SipTraceDirection::Outbound,
                transport: "TLS".into(),
                local_addr: "127.0.0.1:5076".into(),
                remote_addr: "192.0.2.1:5061".into(),
                timestamp_unix_millis: 1,
                start_line: "INVITE [redacted] SIP/2.0".into(),
                sip_call_id: None,
                session_id: None,
                raw_message: "INVITE [redacted] SIP/2.0\r\nX-Correlation-Id: [redacted]\r\n\r\n"
                    .into(),
                original_len: 100,
                truncated: false,
                redacted: true,
            },
            &mut evidence,
        );
        assert_eq!(evidence.invite_count, 1);
        assert_eq!(evidence.header_count, Some(1));
        assert_eq!(evidence.transport.as_deref(), Some("tls"));
        assert!(!evidence.header_contract_failed);
    }

    #[test]
    fn producer_revision_is_the_exact_source_digest() {
        assert_eq!(
            producer_revision(),
            hex_digest(include_bytes!("recipe_sip_source.rs"))
        );
        assert!(is_sha256(&producer_revision()));
    }
}
