//! Redacted wire probe for the flagship recipe's SIP negative cases.
//!
//! This example accepts only a collector-authenticated mode-0600 session. It
//! deliberately changes one signaling property, proves the live listener's
//! rejection or cancellation outcome, and writes no URI, token, header value,
//! call identifier, SDP, or media.

use anyhow::{bail, Context};
use clap::{Parser, ValueEnum};
use rvoip_sip::api::headers::SipRequestOptions;
use rvoip_sip::{
    CallHandlerDecision, CallbackPeer, Config, HeaderName, SipTlsMode, SipTrace, SipTraceConfig,
    SipTraceDirection,
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

const PRODUCER: &str = "bridgefu-recipe-sip-negative@1";
const RECIPE: &str = "vapi-amazon-connect-screen-pop@1";
const HEADER_NAME: &str = "X-Correlation-Id";
const MAX_SESSION_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum NegativeCase {
    MissingCorrelationHeader,
    DuplicateCorrelationHeader,
    ExpiredAttachment,
    SourceCancellation,
}

impl NegativeCase {
    const fn label(self) -> &'static str {
        match self {
            Self::MissingCorrelationHeader => "missing_correlation_header_rejected",
            Self::DuplicateCorrelationHeader => "duplicate_correlation_header_rejected",
            Self::ExpiredAttachment => "expired_attachment_rejected",
            Self::SourceCancellation => "source_cancellation_cleanup",
        }
    }

    const fn expected_headers(self) -> usize {
        match self {
            Self::MissingCorrelationHeader => 0,
            Self::DuplicateCorrelationHeader => 2,
            Self::ExpiredAttachment | Self::SourceCancellation => 1,
        }
    }
}

#[derive(Parser)]
#[command(about = "Protected Bridgefu recipe SIP negative probe", version)]
struct Args {
    #[arg(long)]
    session: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, value_enum)]
    case: NegativeCase,
    #[arg(long)]
    not_before_epoch: Option<u64>,
    #[arg(long, default_value_t = 5086)]
    sip_port: u16,
    #[arg(long, default_value_t = 32_000)]
    media_port_start: u16,
    #[arg(long, default_value_t = 180)]
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
    const fn transport(self) -> &'static str {
        match self {
            Self::SipRtp => "udp",
            Self::SipsSrtp => "tls",
        }
    }
}

struct ValidatedSession {
    private: PrivateSession,
    security: Security,
}

#[derive(Default)]
struct WireEvidence {
    invite_count: usize,
    cancel_count: usize,
    header_counts: Vec<usize>,
    transport: Option<String>,
    rejection_status: Option<u16>,
}

#[derive(Serialize)]
struct Observation {
    schema_version: u8,
    producer: &'static str,
    producer_revision_sha256: String,
    execution_id: String,
    id: &'static str,
    correlation_fingerprint: String,
    source_call_fingerprint: String,
    started_at: String,
    ended_at: String,
    transport: &'static str,
    invite_count: usize,
    wire_header_count: usize,
    cancel_count: usize,
    rejection_status: Option<u16>,
    answered: bool,
    cancellation_completed: bool,
    redacted: bool,
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after Unix epoch")
        .as_secs()
}

fn utc_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn producer_revision() -> String {
    hex_digest(include_bytes!("recipe_sip_negative.rs"))
}

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn safe_identifier(value: &str, minimum: usize, maximum: usize) -> bool {
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
    let security = match private.scenario_id.as_str() {
        "sip-rtp-pcmu" | "sip-rtp-pcma" => Security::SipRtp,
        "sips-srtp-pcmu" | "sips-srtp-pcma" => Security::SipsSrtp,
        _ => bail!("private session scenario is not direct SIP"),
    };
    let expected_security = match security {
        Security::SipRtp => "sip_rtp",
        Security::SipsSrtp => "sips_srtp",
    };
    let expected_scheme = match security {
        Security::SipRtp => "sip:",
        Security::SipsSrtp => "sips:",
    };
    let correlation = &private.correlation_id;
    let valid_network = match private.network_profile.as_str() {
        "baseline" => {
            private.network_contract.delay_ms == 0
                && private.network_contract.jitter_ms == 0
                && private.network_contract.loss_percent == 0.0
                && private.network_contract.reorder_percent == 0.0
        }
        "moderate-wan" => {
            private.network_contract.delay_ms == 80
                && private.network_contract.jitter_ms == 20
                && private.network_contract.loss_percent == 1.0
                && private.network_contract.reorder_percent == 0.1
        }
        _ => false,
    };
    if private.schema_version != 1
        || private.recipe != RECIPE
        || !private.execution_id.starts_with("bft-")
        || !safe_identifier(&private.execution_id, 8, 24)
        || !lowercase_hex(&private.release_id, 20)
        || !lowercase_hex(&private.source_tree_sha256, 64)
        || !private.image.contains("@sha256:")
        || !safe_identifier(&private.session_id, 8, 64)
        || !matches!(private.hangup_origin.as_str(), "source" | "agent")
        || private.security != expected_security
        || !matches!(private.codec.as_str(), "pcmu" | "pcma")
        || !valid_network
        || private.started_at.len() < 20
        || private.started_epoch_ms == 0
        || correlation.len() != 47
        || !correlation.starts_with("bf1_")
        || !correlation[4..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        || private.correlation_fingerprint != hex_digest(correlation.as_bytes())[..12]
        || !lowercase_hex(&private.correlation_fingerprint, 12)
        || !safe_identifier(&private.source_call_id, 1, 128)
        || !safe_identifier(&private.source_org_id, 1, 128)
        || private.source_call_fingerprint != hex_digest(private.source_call_id.as_bytes())[..12]
        || !lowercase_hex(&private.source_call_fingerprint, 12)
        || !private.sip_uri.starts_with(expected_scheme)
        || !(1..=2048).contains(&private.sip_uri.len())
        || !private.sip_uri.bytes().all(|byte| byte.is_ascii_graphic())
        || private.sip_header.name != HEADER_NAME
        || private.sip_header.value != *correlation
        || !private.expected_context.is_object()
        || !lowercase_hex(&private.session_hmac, 64)
    {
        bail!("private session violates the controlled negative-source contract");
    }
    Ok(ValidatedSession { private, security })
}

fn validate_args(args: &Args) -> anyhow::Result<()> {
    if args.sip_port == 0 || !(1024..=u16::MAX - 31).contains(&args.media_port_start) {
        bail!("source port range is invalid");
    }
    if !(30..=300).contains(&args.timeout_seconds) || args.output.exists() {
        bail!("negative probe timeout or output is invalid");
    }
    if args.case == NegativeCase::ExpiredAttachment {
        let not_before = args
            .not_before_epoch
            .context("expired attachment probe requires not-before epoch")?;
        let now = now_epoch();
        if not_before < now || not_before > now.saturating_add(args.timeout_seconds) {
            bail!("expired attachment not-before epoch is outside the probe boundary");
        }
    } else if args.not_before_epoch.is_some() {
        bail!("not-before epoch is valid only for expired attachment");
    }
    Ok(())
}

fn observe_wire(trace: &SipTrace, evidence: &mut WireEvidence) {
    if trace.direction == SipTraceDirection::Outbound {
        if trace.start_line.starts_with("INVITE ") {
            evidence.invite_count += 1;
            evidence.header_counts.push(
                trace
                    .raw_message
                    .lines()
                    .filter_map(|line| line.split_once(':').map(|(name, _)| name.trim()))
                    .filter(|name| name.eq_ignore_ascii_case(HEADER_NAME))
                    .count(),
            );
            evidence.transport = Some(trace.transport.to_ascii_lowercase());
        } else if trace.start_line.starts_with("CANCEL ") {
            evidence.cancel_count += 1;
        }
        return;
    }
    let mut fields = trace.start_line.split_whitespace();
    if fields.next() == Some("SIP/2.0") {
        let status = fields.next().and_then(|value| value.parse::<u16>().ok());
        if status.is_some_and(|value| (300..=699).contains(&value)) {
            evidence.rejection_status = status;
        }
    }
}

fn write_observation(path: &Path, value: &Observation) -> anyhow::Result<()> {
    let parent = path.parent().context("observation requires a parent")?;
    fs::create_dir_all(parent).context("creating observation directory")?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .context("protecting observation directory")?;
    let temporary = path.with_extension("json.tmp");
    if temporary.exists() {
        bail!("negative observation temporary path already exists");
    }
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .context("creating negative observation")?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value).context("serializing observation")?;
    writer.write_all(b"\n").context("finishing observation")?;
    writer.flush().context("flushing observation")?;
    drop(writer);
    fs::rename(&temporary, path).context("publishing observation")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .context("protecting observation")?;
    Ok(())
}

async fn run(args: Args) -> anyhow::Result<()> {
    validate_args(&args)?;
    let session = validate_session(read_session(&args.session)?)?;
    if let Some(not_before) = args.not_before_epoch {
        tokio::time::sleep(Duration::from_secs(not_before.saturating_sub(now_epoch()))).await;
    }
    let started_at = utc_now();
    let mut config = Config::on(
        "bridgefu-recipe-negative-source",
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        args.sip_port,
    )
    .with_server_capacity(1)
    .with_media_port_capacity(args.media_port_start, 32);
    config.offered_codecs = vec![0, 8, 101];
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
    let (cancelled_tx, mut cancelled_rx) = mpsc::channel::<()>(1);
    let peer = CallbackPeer::builder(config)
        .on_incoming(|_| async move {
            CallHandlerDecision::Reject {
                status: 486,
                reason: "Qualification source does not accept inbound calls".into(),
            }
        })
        .on_cancelled(move |_| {
            let cancelled_tx = cancelled_tx.clone();
            async move {
                let _ = cancelled_tx.send(()).await;
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
        .context("building controlled negative SIP source")?;
    let control = peer.control();
    let shutdown = peer.shutdown_handle();
    let peer_task = tokio::spawn(peer.run());
    tokio::time::sleep(Duration::from_millis(200)).await;

    let invite = control.invite(session.private.sip_uri.clone());
    let invite = match args.case {
        NegativeCase::MissingCorrelationHeader => invite,
        NegativeCase::DuplicateCorrelationHeader => invite
            .with_raw_header(
                HeaderName::Other(HEADER_NAME.to_owned()),
                session.private.correlation_id.clone(),
            )
            .context("staging first duplicate header")?
            .with_raw_header(
                HeaderName::Other(HEADER_NAME.to_owned()),
                session.private.correlation_id.clone(),
            )
            .context("staging second duplicate header")?,
        NegativeCase::ExpiredAttachment | NegativeCase::SourceCancellation => invite
            .with_raw_header(
                HeaderName::Other(HEADER_NAME.to_owned()),
                session.private.correlation_id.clone(),
            )
            .context("staging exact correlation header")?,
    };
    let call_id = invite.send().await.context("sending negative SIP INVITE")?;
    let handle = control.coordinator().session(&call_id);
    let (answered, cancellation_completed) = if args.case == NegativeCase::SourceCancellation {
        handle
            .hangup_and_wait(Some(Duration::from_secs(15)))
            .await
            .context("source cancellation did not complete")?;
        let cancelled = tokio::time::timeout(Duration::from_secs(3), cancelled_rx.recv())
            .await
            .ok()
            .flatten()
            .is_some();
        (false, cancelled)
    } else {
        let answered = handle
            .wait_for_answered(Some(Duration::from_secs(20)))
            .await
            .is_ok();
        (answered, false)
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let evidence = wire.lock().await;
    let expected_headers = args.case.expected_headers();
    if answered
        || evidence.invite_count != 1
        || evidence.header_counts.as_slice() != [expected_headers]
        || evidence.transport.as_deref() != Some(session.security.transport())
        || (args.case == NegativeCase::SourceCancellation
            && (evidence.cancel_count != 1 || !cancellation_completed))
        || (args.case != NegativeCase::SourceCancellation
            && (evidence.cancel_count != 0
                || evidence
                    .rejection_status
                    .is_none_or(|status| !(300..=699).contains(&status))))
    {
        bail!("negative SIP wire outcome did not match the controlled case");
    }
    let observation = Observation {
        schema_version: 1,
        producer: PRODUCER,
        producer_revision_sha256: producer_revision(),
        execution_id: session.private.execution_id,
        id: args.case.label(),
        correlation_fingerprint: session.private.correlation_fingerprint,
        source_call_fingerprint: session.private.source_call_fingerprint,
        started_at,
        ended_at: utc_now(),
        transport: session.security.transport(),
        invite_count: evidence.invite_count,
        wire_header_count: expected_headers,
        cancel_count: evidence.cancel_count,
        rejection_status: evidence.rejection_status,
        answered,
        cancellation_completed,
        redacted: true,
    };
    drop(evidence);
    shutdown.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(5), peer_task).await;
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
    fn negative_cases_bind_exact_header_cardinality() {
        assert_eq!(NegativeCase::MissingCorrelationHeader.expected_headers(), 0);
        assert_eq!(
            NegativeCase::DuplicateCorrelationHeader.expected_headers(),
            2
        );
        assert_eq!(NegativeCase::ExpiredAttachment.expected_headers(), 1);
        assert_eq!(NegativeCase::SourceCancellation.expected_headers(), 1);
    }

    #[test]
    fn revision_is_exact_source_digest() {
        assert_eq!(
            producer_revision(),
            hex_digest(include_bytes!("recipe_sip_negative.rs"))
        );
        assert!(lowercase_hex(&producer_revision(), 64));
    }
}
