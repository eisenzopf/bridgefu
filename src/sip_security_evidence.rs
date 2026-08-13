//! Redacted, per-leg SIPS media-security runtime evidence.
//!
//! The observer joins independent transport-owned facts for both inbound Vapi
//! destination legs and outbound Bridgefu-to-Vapi source legs: a TLS-bound,
//! duplicate-preserving correlation header; a URI-scheme-only classification
//! of the `To` header; the peer's typed audio SDP profile; and rvoip's
//! media-security/established lifecycle. It emits one structured event only
//! after every required fact is present. Strict SDES-SRTP and the explicit
//! TLS-with-optional-SRTP compatibility posture are distinguished in the event
//! rather than inferred by release tooling.
//! Raw SIP targets, addresses, SDP, correlation values, and SDES keys are never
//! retained in the tracker or written to the event. The temporary trace join
//! hashes the SIP Call-ID before using it as an in-memory map key.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rvoip_sip::{
    BodyRedactionDecision, DefaultTraceRedactor, Event, MediaSecurityKeying, MediaSecurityProfile,
    RedactionDecision, SessionId, SipTrace, SipTraceConfig, SipTraceDirection, TraceRedactor,
    UnifiedCoordinator,
};
use rvoip_sip_core::types::address::Address;
use rvoip_sip_core::types::sdp::CryptoSuite;
use rvoip_sip_core::types::uri::{Scheme, Uri};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Stable structured-event name consumed by release qualification.
pub const VAPI_DESTINATION_SECURITY_EVENT: &str = "bridgefu_vapi_destination_security_evidence";
/// Stable structured-event name for Bridgefu-originated Vapi SIP legs.
pub const VAPI_SOURCE_SECURITY_EVENT: &str = "bridgefu_vapi_source_security_evidence";

const FINGERPRINT_PREFIX: &str = "bridgefu-fingerprint:";
const URI_SCHEME_PREFIX: &str = "bridgefu-uri-scheme:";
const CORRELATION_FINGERPRINT_HEX_BYTES: usize = 12;
const MAX_CORRELATION_BYTES: usize = 512;
const MAX_HEADER_NAME_BYTES: usize = 128;
const MAX_CALLED_URI_BYTES: usize = 2_048;
const MIN_EVIDENCE_CAPACITY: usize = 64;
const MAX_EVIDENCE_CAPACITY: usize = 16_384;

/// Invalid local construction input for the evidence observer.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SipSecurityEvidenceConfigError {
    /// Evidence cannot run without TLS signaling and SRTP negotiation support.
    #[error("SIP security evidence requires a TLS listener that offers SRTP")]
    UnsupportedStack,
    /// The correlation header name is not a bounded SIP token.
    #[error("invalid SIP security-evidence correlation header")]
    InvalidCorrelationHeader,
    /// A zero capacity cannot bound retained in-flight observations.
    #[error("SIP security-evidence capacity must be nonzero")]
    InvalidCapacity,
}

/// Immutable, secret-free policy shared by the trace redactor and observer.
#[derive(Clone)]
pub struct SipSecurityEvidencePolicy {
    correlation_header: Arc<str>,
    capacity: usize,
    allow_plain_rtp: bool,
}

impl fmt::Debug for SipSecurityEvidencePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SipSecurityEvidencePolicy")
            .field("correlation_header_configured", &true)
            .field("capacity", &self.capacity)
            .field("allow_plain_rtp", &self.allow_plain_rtp)
            .finish()
    }
}

impl SipSecurityEvidencePolicy {
    /// Enable the minimum production-safe SIP trace needed to prove the
    /// transport and media-security posture of an accepted SIPS leg.
    ///
    /// The installed redactor replaces the configured correlation value with
    /// its existing 12-hex SHA-256 fingerprint, redacts every other sensitive
    /// header through rvoip's default policy, and drops every message body.
    /// The wire message is never modified.
    pub fn install(
        stack: &mut rvoip_sip::Config,
        correlation_header: &str,
        capacity: usize,
    ) -> Result<Self, SipSecurityEvidenceConfigError> {
        if stack.tls_bind_addr.is_none() || !stack.offer_srtp {
            return Err(SipSecurityEvidenceConfigError::UnsupportedStack);
        }
        if !valid_header_name(correlation_header) {
            return Err(SipSecurityEvidenceConfigError::InvalidCorrelationHeader);
        }
        if capacity == 0 {
            return Err(SipSecurityEvidenceConfigError::InvalidCapacity);
        }
        let capacity = capacity.clamp(MIN_EVIDENCE_CAPACITY, MAX_EVIDENCE_CAPACITY);
        let policy = Self {
            correlation_header: Arc::from(correlation_header.to_ascii_lowercase()),
            capacity,
            allow_plain_rtp: !stack.srtp_required,
        };
        stack.trace_redaction = Some(Arc::new(SecurityEvidenceTraceRedactor {
            correlation_header: Arc::clone(&policy.correlation_header),
        }));
        stack.sip_trace = SipTraceConfig {
            enabled: true,
            capacity,
            redact_sensitive_headers: true,
            include_body: false,
        };
        Ok(policy)
    }
}

/// Owned observer task. Dropping it aborts observation but never affects SIP.
pub struct SipSecurityEvidenceMonitor {
    cancel: watch::Sender<bool>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl fmt::Debug for SipSecurityEvidenceMonitor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SipSecurityEvidenceMonitor")
            .field(
                "running",
                &self.task.lock().is_ok_and(|task| task.is_some()),
            )
            .finish()
    }
}

impl SipSecurityEvidenceMonitor {
    /// Subscribe to the coordinator's observational event stream and start a
    /// bounded, best-effort evidence join. The observer has no signaling or
    /// media control authority.
    pub async fn start(
        coordinator: &UnifiedCoordinator,
        policy: SipSecurityEvidencePolicy,
    ) -> rvoip_sip::Result<Self> {
        let mut events = coordinator.events().await?;
        let (cancel, mut cancelled) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut tracker = EvidenceTracker::new(policy);
            loop {
                tokio::select! {
                    changed = cancelled.changed() => {
                        if changed.is_err() || *cancelled.borrow() {
                            break;
                        }
                    }
                    event = events.next() => {
                        let Some(event) = event else {
                            break;
                        };
                        if let Some(evidence) = tracker.observe(event) {
                            evidence.emit();
                        }
                    }
                }
            }
        });
        Ok(Self {
            cancel,
            task: Mutex::new(Some(task)),
        })
    }

    /// Stop and join the observer without extending the caller's deadline.
    pub async fn shutdown(&self, timeout: Duration) {
        self.cancel.send_replace(true);
        let task = self
            .task
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        let Some(mut task) = task else {
            return;
        };
        if tokio::time::timeout(timeout, &mut task).await.is_err() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for SipSecurityEvidenceMonitor {
    fn drop(&mut self) {
        self.cancel.send_replace(true);
        if let Some(task) = self
            .task
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            task.abort();
        }
    }
}

#[derive(Clone)]
struct SecurityEvidenceTraceRedactor {
    correlation_header: Arc<str>,
}

impl fmt::Debug for SecurityEvidenceTraceRedactor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecurityEvidenceTraceRedactor")
            .field("correlation_header_configured", &true)
            .finish_non_exhaustive()
    }
}

impl TraceRedactor for SecurityEvidenceTraceRedactor {
    fn redact(&self, header: &rvoip_sip::HeaderName, value: &str) -> RedactionDecision {
        if header
            .as_str()
            .eq_ignore_ascii_case(self.correlation_header.as_ref())
        {
            return correlation_fingerprint(value).map_or_else(
                || RedactionDecision::Redact("<redacted>".to_owned()),
                |fingerprint| {
                    RedactionDecision::Redact(format!("{FINGERPRINT_PREFIX}{fingerprint}"))
                },
            );
        }
        if header.as_str().eq_ignore_ascii_case("to") {
            return called_uri_scheme(value).map_or_else(
                || RedactionDecision::Redact("<redacted>".to_owned()),
                |scheme| {
                    RedactionDecision::Redact(format!("{URI_SCHEME_PREFIX}{}", scheme.as_str()))
                },
            );
        }
        DefaultTraceRedactor.redact(header, value)
    }

    fn redact_body(&self, _content_type: Option<&str>) -> BodyRedactionDecision {
        BodyRedactionDecision::Drop
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransportEvidence {
    correlation_fingerprint: String,
    correlation_header_count: usize,
    called_uri_scheme: Option<EvidenceUriScheme>,
    leg: EvidenceLeg,
}

#[derive(Default)]
struct CallEvidence {
    transport: Option<TransportEvidence>,
    leg: Option<EvidenceLeg>,
    leg_conflict: bool,
    called_uri_scheme: Option<EvidenceUriScheme>,
    sdp_offer: Option<EvidenceMediaProfile>,
    media: Option<MediaEvidence>,
    answered: bool,
    emitted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvidenceUriScheme {
    Sip,
    Sips,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvidenceLeg {
    VapiToBridgefu,
    BridgefuToVapi,
}

impl EvidenceLeg {
    fn event(self) -> &'static str {
        match self {
            Self::VapiToBridgefu => VAPI_DESTINATION_SECURITY_EVENT,
            Self::BridgefuToVapi => VAPI_SOURCE_SECURITY_EVENT,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::VapiToBridgefu => "vapi-to-bridgefu",
            Self::BridgefuToVapi => "bridgefu-to-vapi",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::VapiToBridgefu => "accepted Vapi destination leg",
            Self::BridgefuToVapi => "established Bridgefu Vapi source leg",
        }
    }
}

impl EvidenceUriScheme {
    fn as_str(self) -> &'static str {
        match self {
            Self::Sip => "sip",
            Self::Sips => "sips",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MediaEvidence {
    suite: EvidenceMediaSuite,
    contexts_installed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvidenceMediaProfile {
    RtpAvp,
    RtpSavp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvidenceMediaSuite {
    AesCm128HmacSha1_80,
    AesCm128HmacSha1_32,
}

impl EvidenceMediaSuite {
    fn from_negotiated(suite: CryptoSuite) -> Option<Self> {
        match suite {
            CryptoSuite::AesCm128HmacSha1_80 => Some(Self::AesCm128HmacSha1_80),
            CryptoSuite::AesCm128HmacSha1_32 => Some(Self::AesCm128HmacSha1_32),
            CryptoSuite::AesCm256HmacSha1_80 | CryptoSuite::AesCm256HmacSha1_32 => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::AesCm128HmacSha1_80 => "AES_CM_128_HMAC_SHA1_80",
            Self::AesCm128HmacSha1_32 => "AES_CM_128_HMAC_SHA1_32",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CompletedEvidence {
    correlation_fingerprint: String,
    uri_scheme: &'static str,
    media_profile: &'static str,
    media_keying: &'static str,
    media_suite: &'static str,
    srtp_contexts_installed: bool,
    leg: EvidenceLeg,
}

impl CompletedEvidence {
    fn emit(&self) {
        tracing::info!(
            event = self.leg.event(),
            correlation_fingerprint = %self.correlation_fingerprint,
            leg = self.leg.as_str(),
            uri_scheme = self.uri_scheme,
            signaling_transport = "tls",
            media_profile = self.media_profile,
            media_keying = self.media_keying,
            media_suite = self.media_suite,
            inbound_srtp_context_installed = self.srtp_contexts_installed,
            outbound_srtp_context_installed = self.srtp_contexts_installed,
            answered = true,
            redacted = true,
            "{}",
            self.leg.message()
        );
    }
}

struct EvidenceTracker {
    policy: SipSecurityEvidencePolicy,
    pending_by_call_fingerprint: HashMap<String, TransportEvidence>,
    calls: HashMap<SessionId, CallEvidence>,
}

impl EvidenceTracker {
    fn new(policy: SipSecurityEvidencePolicy) -> Self {
        Self {
            policy,
            pending_by_call_fingerprint: HashMap::new(),
            calls: HashMap::new(),
        }
    }

    fn observe(&mut self, event: Event) -> Option<CompletedEvidence> {
        let call_id = event.call_id().cloned();
        match event {
            Event::SipTrace(trace) => self.observe_trace(trace),
            Event::IncomingCall {
                call_id, to, sdp, ..
            } => {
                let call = self.call_mut(call_id.clone());
                set_leg(call, EvidenceLeg::VapiToBridgefu);
                call.called_uri_scheme = called_uri_scheme(&to);
                call.sdp_offer = sdp.as_deref().and_then(sdp_audio_profile);
                self.complete(&call_id)
            }
            Event::CallAnswered { call_id, sdp } => {
                let call = self.call_mut(call_id.clone());
                set_leg(call, EvidenceLeg::BridgefuToVapi);
                call.sdp_offer = sdp.as_deref().and_then(sdp_audio_profile);
                self.complete(&call_id)
            }
            Event::MediaSecurityNegotiated {
                call_id,
                keying,
                suite,
                profile,
                contexts_installed,
            } => {
                if keying == MediaSecurityKeying::Sdes && profile == MediaSecurityProfile::RtpSavp {
                    self.call_mut(call_id.clone()).media =
                        EvidenceMediaSuite::from_negotiated(suite).map(|suite| MediaEvidence {
                            suite,
                            contexts_installed,
                        });
                }
                self.complete(&call_id)
            }
            Event::CallEstablished { call_id } => {
                self.call_mut(call_id.clone()).answered = true;
                self.complete(&call_id)
            }
            Event::CallEnded { .. } | Event::CallFailed { .. } | Event::CallCancelled { .. } => {
                if let Some(call_id) = call_id {
                    self.calls.remove(&call_id);
                }
                None
            }
            _ => None,
        }
    }

    fn observe_trace(&mut self, trace: SipTrace) -> Option<CompletedEvidence> {
        let initial_invite = matches!(
            trace.direction,
            SipTraceDirection::Inbound | SipTraceDirection::Outbound
        ) && trace
            .start_line
            .split_ascii_whitespace()
            .next()
            .is_some_and(|method| method.eq_ignore_ascii_case("INVITE"));
        let trace_evidence = if initial_invite
            && !trace.truncated
            && trace.redacted
            && trace.transport.eq_ignore_ascii_case("TLS")
        {
            extract_transport_evidence(
                &trace.raw_message,
                self.policy.correlation_header.as_ref(),
                match trace.direction {
                    SipTraceDirection::Inbound => EvidenceLeg::VapiToBridgefu,
                    SipTraceDirection::Outbound => EvidenceLeg::BridgefuToVapi,
                },
            )
        } else {
            None
        };

        let call_fingerprint = trace
            .sip_call_id
            .as_deref()
            .and_then(sip_call_binding_fingerprint);
        if let (Some(call_fingerprint), Some(evidence)) =
            (call_fingerprint.as_ref(), trace_evidence.clone())
        {
            insert_bounded(
                &mut self.pending_by_call_fingerprint,
                call_fingerprint.clone(),
                evidence,
                self.policy.capacity,
            );
        }

        let session_id = trace.session_id?;
        let pending = call_fingerprint
            .as_ref()
            .and_then(|fingerprint| self.pending_by_call_fingerprint.remove(fingerprint));
        let evidence = trace_evidence.or(pending);
        if let Some(evidence) = evidence {
            let call = self.call_mut(session_id.clone());
            set_leg(call, evidence.leg);
            if evidence.leg == EvidenceLeg::BridgefuToVapi {
                call.called_uri_scheme = evidence.called_uri_scheme;
            }
            call.transport = Some(evidence);
        }
        self.complete(&session_id)
    }

    fn call_mut(&mut self, call_id: SessionId) -> &mut CallEvidence {
        insert_default_bounded(&mut self.calls, call_id.clone(), self.policy.capacity);
        self.calls
            .get_mut(&call_id)
            .expect("bounded call insertion retains the requested key")
    }

    fn complete(&mut self, call_id: &SessionId) -> Option<CompletedEvidence> {
        let allow_plain_rtp = self.policy.allow_plain_rtp;
        let call = self.calls.get_mut(call_id)?;
        if call.emitted || !call.answered || call.leg_conflict {
            return None;
        }
        let uri_scheme = call.called_uri_scheme?;
        let leg = call.leg?;
        if uri_scheme == EvidenceUriScheme::Sip && !allow_plain_rtp {
            return None;
        }
        let transport = call.transport.as_ref()?;
        if transport.correlation_header_count != 1 {
            return None;
        }
        let (media_profile, media_keying, media_suite, srtp_contexts_installed) = match call
            .sdp_offer?
        {
            EvidenceMediaProfile::RtpSavp => {
                let media = call.media?;
                if !media.contexts_installed {
                    return None;
                }
                ("RTP/SAVP", "SDES-SRTP", media.suite.as_str(), true)
            }
            EvidenceMediaProfile::RtpAvp if allow_plain_rtp => ("RTP/AVP", "none", "none", false),
            EvidenceMediaProfile::RtpAvp => return None,
        };
        call.emitted = true;
        Some(CompletedEvidence {
            correlation_fingerprint: transport.correlation_fingerprint.clone(),
            uri_scheme: uri_scheme.as_str(),
            media_profile,
            media_keying,
            media_suite,
            srtp_contexts_installed,
            leg,
        })
    }
}

fn insert_bounded<K, V>(map: &mut HashMap<K, V>, key: K, value: V, capacity: usize)
where
    K: Clone + Eq + std::hash::Hash,
{
    if !map.contains_key(&key) && map.len() >= capacity {
        if let Some(evicted) = map.keys().next().cloned() {
            map.remove(&evicted);
        }
    }
    map.insert(key, value);
}

fn insert_default_bounded<K, V>(map: &mut HashMap<K, V>, key: K, capacity: usize)
where
    K: Clone + Eq + std::hash::Hash,
    V: Default,
{
    if map.contains_key(&key) {
        return;
    }
    if map.len() >= capacity {
        if let Some(evicted) = map.keys().next().cloned() {
            map.remove(&evicted);
        }
    }
    map.insert(key, V::default());
}

fn set_leg(call: &mut CallEvidence, leg: EvidenceLeg) {
    if call.leg.is_some_and(|existing| existing != leg) {
        call.leg_conflict = true;
    } else {
        call.leg = Some(leg);
    }
}

fn extract_transport_evidence(
    raw_message: &str,
    header_name: &str,
    leg: EvidenceLeg,
) -> Option<TransportEvidence> {
    let mut values = Vec::new();
    let mut correlation_continuation = false;
    let mut uri_schemes = Vec::new();
    for line in raw_message.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            if correlation_continuation {
                return None;
            }
            continue;
        }
        let (name, value) = line.split_once(':')?;
        correlation_continuation = name.trim().eq_ignore_ascii_case(header_name);
        if correlation_continuation {
            values.push(value.trim());
        }
        if name.trim().eq_ignore_ascii_case("to") {
            uri_schemes.push(
                value
                    .trim()
                    .strip_prefix(URI_SCHEME_PREFIX)
                    .and_then(classified_uri_scheme),
            );
        }
    }
    if values.len() != 1 {
        return None;
    }
    let fingerprint = values[0].strip_prefix(FINGERPRINT_PREFIX)?;
    if fingerprint.len() != CORRELATION_FINGERPRINT_HEX_BYTES
        || !fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    Some(TransportEvidence {
        correlation_fingerprint: fingerprint.to_owned(),
        correlation_header_count: values.len(),
        called_uri_scheme: if uri_schemes.len() == 1 {
            uri_schemes[0]
        } else {
            None
        },
        leg,
    })
}

fn classified_uri_scheme(value: &str) -> Option<EvidenceUriScheme> {
    match value {
        "sip" => Some(EvidenceUriScheme::Sip),
        "sips" => Some(EvidenceUriScheme::Sips),
        _ => None,
    }
}

/// Existing secret-safe correlation identifier shared with SIP admission
/// evidence. Keeping the implementation here prevents qualification and
/// durable admission logs from drifting to different hashes.
pub(crate) fn correlation_fingerprint(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > MAX_CORRELATION_BYTES || value.contains(['\r', '\n', '\0'])
    {
        return None;
    }
    let digest = Sha256::digest(value.as_bytes());
    Some(
        digest[..6]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )
}

fn valid_header_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_HEADER_NAME_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn sip_call_binding_fingerprint(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 512 || value.contains(['\r', '\n', '\0']) {
        return None;
    }
    let digest = Sha256::digest(value.as_bytes());
    Some(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn sdp_audio_profile(sdp: &str) -> Option<EvidenceMediaProfile> {
    sdp.lines().find_map(|line| {
        let mut fields = line.trim_end_matches('\r').split_ascii_whitespace();
        if !fields
            .next()
            .is_some_and(|media| media.eq_ignore_ascii_case("m=audio"))
            || fields.next().is_none()
        {
            return None;
        }
        match fields.next()? {
            profile if profile.eq_ignore_ascii_case("RTP/SAVP") => {
                Some(EvidenceMediaProfile::RtpSavp)
            }
            profile if profile.eq_ignore_ascii_case("RTP/AVP") => {
                Some(EvidenceMediaProfile::RtpAvp)
            }
            _ => None,
        }
    })
}

fn called_uri_scheme(value: &str) -> Option<EvidenceUriScheme> {
    if value.is_empty() || value.len() > MAX_CALLED_URI_BYTES || value.contains(['\r', '\n', '\0'])
    {
        return None;
    }
    if let Some(open) = value.rfind('<') {
        let tail = &value[open + 1..];
        let close = tail.find('>')?;
        if tail[close + 1..].contains(['<', '>']) {
            return None;
        }
        return tail[..close].parse::<Uri>().ok().and_then(uri_scheme);
    }
    value
        .parse::<Address>()
        .ok()
        .and_then(|address| uri_scheme(address.uri))
}

fn uri_scheme(uri: Uri) -> Option<EvidenceUriScheme> {
    match uri.scheme() {
        Scheme::Sip => Some(EvidenceUriScheme::Sip),
        Scheme::Sips => Some(EvidenceUriScheme::Sips),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::{BTreeMap, BTreeSet};
    use tracing::field::{Field, Visit};
    use tracing::{Event as TracingEvent, Subscriber};
    use tracing_subscriber::layer::{Context as LayerContext, SubscriberExt};
    use tracing_subscriber::{Layer, Registry};

    const SECRET_CORRELATION: &str = "bf1_do-not-log-this-correlation";

    fn policy() -> SipSecurityEvidencePolicy {
        SipSecurityEvidencePolicy {
            correlation_header: Arc::from("x-correlation-id"),
            capacity: MIN_EVIDENCE_CAPACITY,
            allow_plain_rtp: false,
        }
    }

    fn optional_policy() -> SipSecurityEvidencePolicy {
        SipSecurityEvidencePolicy {
            allow_plain_rtp: true,
            ..policy()
        }
    }

    fn session() -> SessionId {
        SessionId("security-evidence-session".to_owned())
    }

    fn trace(transport: &str, header_lines: &str, session_id: Option<SessionId>) -> Event {
        Event::SipTrace(SipTrace {
            direction: SipTraceDirection::Inbound,
            transport: transport.to_owned(),
            local_addr: "192.0.2.1:5061".to_owned(),
            remote_addr: "198.51.100.2:40000".to_owned(),
            timestamp_unix_millis: 1,
            start_line: "INVITE <redacted-request-uri> SIP/2.0".to_owned(),
            sip_call_id: Some("wire-call-id".to_owned()),
            session_id,
            raw_message: format!(
                "INVITE <redacted-request-uri> SIP/2.0\r\nCall-ID: wire-call-id\r\n{header_lines}\r\n"
            ),
            original_len: 1_024,
            truncated: false,
            redacted: true,
        })
    }

    fn outbound_trace(transport: &str, uri_scheme: &str, session_id: Option<SessionId>) -> Event {
        Event::SipTrace(SipTrace {
            direction: SipTraceDirection::Outbound,
            transport: transport.to_owned(),
            local_addr: "192.0.2.1:5061".to_owned(),
            remote_addr: "198.51.100.2:5061".to_owned(),
            timestamp_unix_millis: 1,
            start_line: "INVITE <redacted-request-uri> SIP/2.0".to_owned(),
            sip_call_id: Some("outbound-wire-call-id".to_owned()),
            session_id,
            raw_message: format!(
                "INVITE <redacted-request-uri> SIP/2.0\r\nCall-ID: outbound-wire-call-id\r\nTo: {URI_SCHEME_PREFIX}{uri_scheme}\r\n{}\r\n",
                fingerprint_header()
            ),
            original_len: 1_024,
            truncated: false,
            redacted: true,
        })
    }

    fn incoming(sdp_profile: &str) -> Event {
        incoming_with_scheme("sips", sdp_profile)
    }

    fn incoming_with_scheme(uri_scheme: &str, sdp_profile: &str) -> Event {
        Event::IncomingCall {
            call_id: session(),
            from: "[redacted]".to_owned(),
            to: format!("<{uri_scheme}:bridgefu@example.test>"),
            sdp: Some(format!(
                "v=0\r\nm=audio 49170 {sdp_profile} 0 101\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:never-retained\r\n"
            )),
        }
    }

    fn media(contexts_installed: bool) -> Event {
        media_with_suite(CryptoSuite::AesCm128HmacSha1_80, contexts_installed)
    }

    fn media_with_suite(suite: CryptoSuite, contexts_installed: bool) -> Event {
        Event::MediaSecurityNegotiated {
            call_id: session(),
            keying: MediaSecurityKeying::Sdes,
            suite,
            profile: MediaSecurityProfile::RtpSavp,
            contexts_installed,
        }
    }

    fn established() -> Event {
        Event::CallEstablished { call_id: session() }
    }

    fn answered(sdp_profile: &str) -> Event {
        Event::CallAnswered {
            call_id: session(),
            sdp: Some(format!(
                "v=0\r\nm=audio 49170 {sdp_profile} 0 101\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:never-retained\r\n"
            )),
        }
    }

    fn fingerprint_header() -> String {
        format!(
            "X-Correlation-Id: {FINGERPRINT_PREFIX}{}\r\n",
            correlation_fingerprint(SECRET_CORRELATION).unwrap()
        )
    }

    #[test]
    fn redactor_keeps_only_the_existing_fingerprint_and_drops_sdp() {
        let redactor = SecurityEvidenceTraceRedactor {
            correlation_header: Arc::from("x-correlation-id"),
        };
        let header =
            rvoip_sip::HeaderName::from_str("X-Correlation-Id").expect("valid extension header");
        let decision = redactor.redact(&header, SECRET_CORRELATION);
        let rendered = match decision {
            RedactionDecision::Redact(rendered) => rendered,
            _ => panic!("correlation header must be replaced"),
        };
        assert_eq!(
            rendered,
            format!(
                "{FINGERPRINT_PREFIX}{}",
                correlation_fingerprint(SECRET_CORRELATION).unwrap()
            )
        );
        assert!(!rendered.contains(SECRET_CORRELATION));
        assert_eq!(
            redactor.redact_body(Some("application/sdp")),
            BodyRedactionDecision::Drop
        );
        assert!(!redactor.allows_verbatim_trace());
        let to = rvoip_sip::HeaderName::from_str("To").expect("valid To header");
        assert_eq!(
            redactor.redact(&to, "\"Private user\" <sips:secret@example.test>"),
            RedactionDecision::Redact(format!("{URI_SCHEME_PREFIX}sips"))
        );
    }

    #[test]
    fn installation_requires_tls_with_srtp_support_and_records_optional_policy() {
        let mut stack = rvoip_sip::Config::local("security-evidence", 5060);
        assert!(matches!(
            SipSecurityEvidencePolicy::install(&mut stack, "X-Correlation-Id", 64),
            Err(SipSecurityEvidenceConfigError::UnsupportedStack)
        ));

        stack.tls_bind_addr = Some("127.0.0.1:5061".parse().unwrap());
        stack.offer_srtp = true;
        stack.srtp_required = false;
        stack.trace_redaction = Some(Arc::new(rvoip_sip::PassthroughRedactor));
        let optional = SipSecurityEvidencePolicy::install(&mut stack, "X-Correlation-Id", 64)
            .expect("SIPS optional-SRTP evidence policy");
        assert!(optional.allow_plain_rtp);

        stack.srtp_required = true;
        let strict = SipSecurityEvidencePolicy::install(&mut stack, "X-Correlation-Id", 64)
            .expect("strict SIPS/SRTP evidence policy");
        assert!(!strict.allow_plain_rtp);

        assert!(stack.sip_trace.enabled);
        assert!(stack.sip_trace.redact_sensitive_headers);
        assert!(!stack.sip_trace.include_body);
        let authorization = rvoip_sip::HeaderName::from_str("Authorization").unwrap();
        assert!(matches!(
            stack
                .trace_redaction
                .as_ref()
                .unwrap()
                .redact(&authorization, "secret"),
            RedactionDecision::Redact(_)
        ));
        assert!(!stack
            .trace_redaction
            .as_ref()
            .unwrap()
            .allows_verbatim_trace());
    }

    #[test]
    fn exact_secure_facts_emit_once_in_any_lifecycle_order() {
        let orders = [
            vec![
                trace("TLS", &fingerprint_header(), Some(session())),
                incoming("RTP/SAVP"),
                media(true),
                established(),
            ],
            vec![
                established(),
                media(true),
                incoming("RTP/SAVP"),
                trace("tls", &fingerprint_header(), Some(session())),
            ],
        ];
        for events in orders {
            let mut tracker = EvidenceTracker::new(policy());
            let completed = events
                .into_iter()
                .filter_map(|event| tracker.observe(event))
                .collect::<Vec<_>>();
            assert_eq!(completed.len(), 1);
            assert_eq!(
                completed[0],
                CompletedEvidence {
                    correlation_fingerprint: correlation_fingerprint(SECRET_CORRELATION).unwrap(),
                    uri_scheme: "sips",
                    media_profile: "RTP/SAVP",
                    media_keying: "SDES-SRTP",
                    media_suite: "AES_CM_128_HMAC_SHA1_80",
                    srtp_contexts_installed: true,
                    leg: EvidenceLeg::VapiToBridgefu,
                }
            );
            assert!(tracker.observe(established()).is_none());
        }
    }

    #[test]
    fn optional_policy_emits_exact_plain_rtp_posture_only_after_answer() {
        let mut tracker = EvidenceTracker::new(optional_policy());
        for event in [
            trace("TLS", &fingerprint_header(), Some(session())),
            incoming_with_scheme("sip", "RTP/AVP"),
        ] {
            assert!(tracker.observe(event).is_none());
        }
        assert_eq!(
            tracker.observe(established()),
            Some(CompletedEvidence {
                correlation_fingerprint: correlation_fingerprint(SECRET_CORRELATION).unwrap(),
                uri_scheme: "sip",
                media_profile: "RTP/AVP",
                media_keying: "none",
                media_suite: "none",
                srtp_contexts_installed: false,
                leg: EvidenceLeg::VapiToBridgefu,
            })
        );
        assert!(tracker.observe(established()).is_none());
    }

    #[test]
    fn outbound_optional_vapi_leg_requires_tls_scheme_answer_and_established() {
        let orders = [
            vec![
                outbound_trace("TLS", "sips", Some(session())),
                answered("RTP/AVP"),
                established(),
            ],
            vec![
                answered("RTP/AVP"),
                established(),
                outbound_trace("TLS", "sips", Some(session())),
            ],
        ];
        for events in orders {
            let mut tracker = EvidenceTracker::new(optional_policy());
            assert_eq!(
                events
                    .into_iter()
                    .filter_map(|event| tracker.observe(event))
                    .collect::<Vec<_>>(),
                vec![CompletedEvidence {
                    correlation_fingerprint: correlation_fingerprint(SECRET_CORRELATION).unwrap(),
                    uri_scheme: "sips",
                    media_profile: "RTP/AVP",
                    media_keying: "none",
                    media_suite: "none",
                    srtp_contexts_installed: false,
                    leg: EvidenceLeg::BridgefuToVapi,
                }]
            );
        }
    }

    #[test]
    fn outbound_strict_vapi_leg_requires_typed_sdes_contexts() {
        let mut tracker = EvidenceTracker::new(policy());
        for event in [
            outbound_trace("TLS", "sips", Some(session())),
            answered("RTP/SAVP"),
            media(true),
        ] {
            assert!(tracker.observe(event).is_none());
        }
        assert_eq!(
            tracker.observe(established()),
            Some(CompletedEvidence {
                correlation_fingerprint: correlation_fingerprint(SECRET_CORRELATION).unwrap(),
                uri_scheme: "sips",
                media_profile: "RTP/SAVP",
                media_keying: "SDES-SRTP",
                media_suite: "AES_CM_128_HMAC_SHA1_80",
                srtp_contexts_installed: true,
                leg: EvidenceLeg::BridgefuToVapi,
            })
        );
    }

    #[test]
    fn strict_policy_rejects_plain_sip_request_uri_even_with_secure_media() {
        let mut tracker = EvidenceTracker::new(policy());
        for event in [
            trace("TLS", &fingerprint_header(), Some(session())),
            incoming_with_scheme("sip", "RTP/SAVP"),
            media(true),
            established(),
        ] {
            assert!(tracker.observe(event).is_none());
        }
    }

    #[test]
    fn call_id_late_binding_joins_transport_trace_without_raw_values() {
        let mut tracker = EvidenceTracker::new(policy());
        assert!(tracker
            .observe(trace("TLS", &fingerprint_header(), None))
            .is_none());
        assert_eq!(tracker.pending_by_call_fingerprint.len(), 1);
        assert!(!tracker
            .pending_by_call_fingerprint
            .contains_key("wire-call-id"));
        assert!(tracker
            .observe(Event::SipTrace(SipTrace {
                direction: SipTraceDirection::Outbound,
                transport: "TLS".to_owned(),
                local_addr: "[not-retained]".to_owned(),
                remote_addr: "[not-retained]".to_owned(),
                timestamp_unix_millis: 2,
                start_line: "SIP/2.0 180 <redacted-reason>".to_owned(),
                sip_call_id: Some("wire-call-id".to_owned()),
                session_id: Some(session()),
                raw_message: "SIP/2.0 180 <redacted-reason>\r\nCall-ID: wire-call-id\r\n\r\n"
                    .to_owned(),
                original_len: 128,
                truncated: false,
                redacted: true,
            }))
            .is_none());
        assert!(tracker.observe(incoming("RTP/SAVP")).is_none());
        assert!(tracker.observe(media(true)).is_none());
        let completed = tracker.observe(established()).expect("complete evidence");
        assert_eq!(
            completed.correlation_fingerprint,
            correlation_fingerprint(SECRET_CORRELATION).unwrap()
        );
        assert!(!completed
            .correlation_fingerprint
            .contains(SECRET_CORRELATION));
        assert!(tracker.pending_by_call_fingerprint.is_empty());
    }

    #[test]
    fn clear_or_incomplete_security_never_emits() {
        let cases = [
            trace("UDP", &fingerprint_header(), Some(session())),
            trace(
                "TLS",
                &format!("{}{}", fingerprint_header(), fingerprint_header()),
                Some(session()),
            ),
        ];
        for rejected_trace in cases {
            let mut tracker = EvidenceTracker::new(policy());
            for event in [
                rejected_trace,
                incoming("RTP/SAVP"),
                media(true),
                established(),
            ] {
                assert!(tracker.observe(event).is_none());
            }
        }

        let folded_correlation = format!(
            "{} {FINGERPRINT_PREFIX}continuation\r\n",
            fingerprint_header()
        );
        let mut tracker = EvidenceTracker::new(policy());
        for event in [
            trace("TLS", &folded_correlation, Some(session())),
            incoming("RTP/SAVP"),
            media(true),
            established(),
        ] {
            assert!(tracker.observe(event).is_none());
        }

        for (profile, contexts) in [("RTP/AVP", true), ("RTP/SAVP", false)] {
            let mut tracker = EvidenceTracker::new(policy());
            for event in [
                trace("TLS", &fingerprint_header(), Some(session())),
                incoming(profile),
                media(contexts),
                established(),
            ] {
                assert!(tracker.observe(event).is_none());
            }
        }

        let mut tracker = EvidenceTracker::new(policy());
        for event in [
            trace("TLS", &fingerprint_header(), Some(session())),
            incoming_with_scheme("sip", "RTP/SAVP"),
            media(true),
            established(),
        ] {
            assert!(tracker.observe(event).is_none());
        }

        let mut tracker = EvidenceTracker::new(policy());
        for event in [
            trace("TLS", &fingerprint_header(), Some(session())),
            incoming("RTP/SAVP"),
            media_with_suite(CryptoSuite::AesCm256HmacSha1_80, true),
            established(),
        ] {
            assert!(tracker.observe(event).is_none());
        }
    }

    #[test]
    fn supported_media_suite_vocabulary_is_exact() {
        assert_eq!(
            EvidenceMediaSuite::from_negotiated(CryptoSuite::AesCm128HmacSha1_80)
                .unwrap()
                .as_str(),
            "AES_CM_128_HMAC_SHA1_80"
        );
        assert_eq!(
            EvidenceMediaSuite::from_negotiated(CryptoSuite::AesCm128HmacSha1_32)
                .unwrap()
                .as_str(),
            "AES_CM_128_HMAC_SHA1_32"
        );
        assert!(EvidenceMediaSuite::from_negotiated(CryptoSuite::AesCm256HmacSha1_80).is_none());
        assert!(EvidenceMediaSuite::from_negotiated(CryptoSuite::AesCm256HmacSha1_32).is_none());
    }

    #[test]
    fn called_uri_scheme_is_parsed_without_retaining_the_uri() {
        assert_eq!(
            called_uri_scheme("\"Bridgefu destination\" <SIPS:route@example.test>;tag=opaque"),
            Some(EvidenceUriScheme::Sips)
        );
        assert_eq!(
            called_uri_scheme("<sip:route@example.test>"),
            Some(EvidenceUriScheme::Sip)
        );
        assert_eq!(
            called_uri_scheme("\"sips:misleading-display-name\" <sip:route@example.test>"),
            Some(EvidenceUriScheme::Sip)
        );
        assert_eq!(
            called_uri_scheme("sips:not a valid address\r\nInjected: value"),
            None
        );
    }

    #[test]
    fn directional_context_fields_project_only_from_rvoip_send_receive_invariant() {
        let mut strict = EvidenceTracker::new(policy());
        let strict = [
            trace("TLS", &fingerprint_header(), Some(session())),
            incoming("RTP/SAVP"),
            media(true),
            established(),
        ]
        .into_iter()
        .find_map(|event| strict.observe(event))
        .expect("strict evidence");
        assert!(strict.srtp_contexts_installed);

        let mut optional = EvidenceTracker::new(optional_policy());
        let optional = [
            trace("TLS", &fingerprint_header(), Some(session())),
            incoming("RTP/AVP"),
            established(),
        ]
        .into_iter()
        .find_map(|event| optional.observe(event))
        .expect("plain compatibility evidence");
        assert!(!optional.srtp_contexts_installed);
    }

    #[test]
    fn structured_event_contract_is_exact_and_contains_no_private_input() {
        let capture = FieldCapture::default();
        let subscriber = Registry::default().with(capture.clone());
        let fingerprint = correlation_fingerprint(SECRET_CORRELATION).unwrap();
        tracing::subscriber::with_default(subscriber, || {
            CompletedEvidence {
                correlation_fingerprint: fingerprint.clone(),
                uri_scheme: "sips",
                media_profile: "RTP/SAVP",
                media_keying: "SDES-SRTP",
                media_suite: "AES_CM_128_HMAC_SHA1_80",
                srtp_contexts_installed: true,
                leg: EvidenceLeg::VapiToBridgefu,
            }
            .emit();
        });

        let events = capture.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        let fields = &events[0];
        assert_eq!(
            fields.keys().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "answered".to_owned(),
                "correlation_fingerprint".to_owned(),
                "event".to_owned(),
                "inbound_srtp_context_installed".to_owned(),
                "leg".to_owned(),
                "media_keying".to_owned(),
                "media_profile".to_owned(),
                "media_suite".to_owned(),
                "message".to_owned(),
                "outbound_srtp_context_installed".to_owned(),
                "redacted".to_owned(),
                "signaling_transport".to_owned(),
                "uri_scheme".to_owned(),
            ])
        );
        assert_eq!(fields["event"], VAPI_DESTINATION_SECURITY_EVENT);
        assert_eq!(fields["correlation_fingerprint"], fingerprint);
        assert_eq!(fields["leg"], "vapi-to-bridgefu");
        assert_eq!(fields["uri_scheme"], "sips");
        assert_eq!(fields["signaling_transport"], "tls");
        assert_eq!(fields["media_profile"], "RTP/SAVP");
        assert_eq!(fields["media_keying"], "SDES-SRTP");
        assert_eq!(fields["media_suite"], "AES_CM_128_HMAC_SHA1_80");
        assert_eq!(fields["inbound_srtp_context_installed"], true);
        assert_eq!(fields["outbound_srtp_context_installed"], true);
        assert_eq!(fields["answered"], true);
        assert_eq!(fields["redacted"], true);
        assert_eq!(fields["message"], "accepted Vapi destination leg");
        let serialized = serde_json::to_string(fields).unwrap();
        assert!(!serialized.contains(SECRET_CORRELATION));
        assert!(!serialized.contains("inline:"));
        assert!(!serialized.contains("192.0.2.1"));
        assert!(!serialized.contains("198.51.100.2"));
    }

    #[test]
    fn outbound_structured_event_contract_is_exact_and_contains_no_private_input() {
        let capture = FieldCapture::default();
        let subscriber = Registry::default().with(capture.clone());
        let fingerprint = correlation_fingerprint(SECRET_CORRELATION).unwrap();
        tracing::subscriber::with_default(subscriber, || {
            CompletedEvidence {
                correlation_fingerprint: fingerprint.clone(),
                uri_scheme: "sips",
                media_profile: "RTP/AVP",
                media_keying: "none",
                media_suite: "none",
                srtp_contexts_installed: false,
                leg: EvidenceLeg::BridgefuToVapi,
            }
            .emit();
        });

        let events = capture.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        let fields = &events[0];
        assert_eq!(fields["event"], VAPI_SOURCE_SECURITY_EVENT);
        assert_eq!(fields["correlation_fingerprint"], fingerprint);
        assert_eq!(fields["leg"], "bridgefu-to-vapi");
        assert_eq!(fields["uri_scheme"], "sips");
        assert_eq!(fields["signaling_transport"], "tls");
        assert_eq!(fields["media_profile"], "RTP/AVP");
        assert_eq!(fields["media_keying"], "none");
        assert_eq!(fields["media_suite"], "none");
        assert_eq!(fields["inbound_srtp_context_installed"], false);
        assert_eq!(fields["outbound_srtp_context_installed"], false);
        assert_eq!(fields["answered"], true);
        assert_eq!(fields["redacted"], true);
        assert_eq!(fields["message"], "established Bridgefu Vapi source leg");
        let serialized = serde_json::to_string(fields).unwrap();
        assert!(!serialized.contains(SECRET_CORRELATION));
        assert!(!serialized.contains("inline:"));
        assert!(!serialized.contains("192.0.2.1"));
        assert!(!serialized.contains("198.51.100.2"));
    }

    #[test]
    fn structured_plain_rtp_event_is_explicit_and_secret_safe() {
        let capture = FieldCapture::default();
        let subscriber = Registry::default().with(capture.clone());
        let fingerprint = correlation_fingerprint(SECRET_CORRELATION).unwrap();
        tracing::subscriber::with_default(subscriber, || {
            CompletedEvidence {
                correlation_fingerprint: fingerprint.clone(),
                uri_scheme: "sip",
                media_profile: "RTP/AVP",
                media_keying: "none",
                media_suite: "none",
                srtp_contexts_installed: false,
                leg: EvidenceLeg::VapiToBridgefu,
            }
            .emit();
        });

        let events = capture.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        let fields = &events[0];
        assert_eq!(fields["event"], VAPI_DESTINATION_SECURITY_EVENT);
        assert_eq!(fields["correlation_fingerprint"], fingerprint);
        assert_eq!(fields["uri_scheme"], "sip");
        assert_eq!(fields["signaling_transport"], "tls");
        assert_eq!(fields["media_profile"], "RTP/AVP");
        assert_eq!(fields["media_keying"], "none");
        assert_eq!(fields["media_suite"], "none");
        assert_eq!(fields["inbound_srtp_context_installed"], false);
        assert_eq!(fields["outbound_srtp_context_installed"], false);
        assert_eq!(fields["answered"], true);
        assert_eq!(fields["redacted"], true);
        assert_eq!(fields["message"], "accepted Vapi destination leg");
        let serialized = serde_json::to_string(fields).unwrap();
        assert!(!serialized.contains(SECRET_CORRELATION));
        assert!(!serialized.contains("inline:"));
    }

    #[test]
    fn tracker_state_is_bounded_and_terminal_calls_are_removed() {
        let mut policy = policy();
        policy.capacity = 2;
        let mut tracker = EvidenceTracker::new(policy);
        for id in ["a", "b", "c"] {
            tracker.observe(Event::IncomingCall {
                call_id: SessionId(id.to_owned()),
                from: String::new(),
                to: String::new(),
                sdp: None,
            });
        }
        assert_eq!(tracker.calls.len(), 2);
        tracker.observe(Event::CallFailed {
            call_id: SessionId("c".to_owned()),
            status_code: 488,
            reason: "[redacted]".to_owned(),
        });
        assert!(!tracker.calls.contains_key(&SessionId("c".to_owned())));
    }

    #[derive(Clone, Default)]
    struct FieldCapture(Arc<Mutex<Vec<BTreeMap<String, Value>>>>);

    impl<S> Layer<S> for FieldCapture
    where
        S: Subscriber,
    {
        fn on_event(&self, event: &TracingEvent<'_>, _context: LayerContext<'_, S>) {
            let mut fields = BTreeMap::new();
            event.record(&mut FieldVisitor(&mut fields));
            self.0.lock().unwrap().push(fields);
        }
    }

    struct FieldVisitor<'a>(&'a mut BTreeMap<String, Value>);

    impl Visit for FieldVisitor<'_> {
        fn record_bool(&mut self, field: &Field, value: bool) {
            self.0.insert(field.name().to_owned(), Value::Bool(value));
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.0
                .insert(field.name().to_owned(), Value::String(value.to_owned()));
        }

        fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
            self.0
                .insert(field.name().to_owned(), Value::String(format!("{value:?}")));
        }
    }

    use std::str::FromStr;
}
