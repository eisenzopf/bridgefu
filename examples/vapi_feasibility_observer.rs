//! Disposable Vapi `webCall` -> SIP feasibility observer and media peer.
//!
//! This is qualification infrastructure, not a Bridgefu administration API.
//! It composes rvoip's SIP/TLS/SRTP/media implementation with a deliberately
//! small, authenticated HTTP surface consumed by StandardCharter's owner-gated
//! Chromium harness. Run `--validate-config` before binding any socket.

use anyhow::{bail, Context};
use async_trait::async_trait;
#[cfg(test)]
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, State};
#[cfg(test)]
use axum::http::Request;
use axum::http::{header::AUTHORIZATION, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use reqwest::redirect::Policy;
use rvoip_sip::api::headers::SipHeaderView;
use rvoip_sip::{
    AudioFrame, AudioSender, CallHandler, CallHandlerDecision, CallId, CallbackPeer, Config,
    EndReason, HeaderName, IncomingCall, SessionHandle,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;

const QUERY_PATH: &str = "/v1/observations/query";
const CONTROL_PATH: &str = "/v1/observations/control";
const VAPI_EVENTS_PATH: &str = "/v1/observations/vapi-events";
const OBSERVATION_SCHEMA: &str = "standardcharter.vapi-webcall-sip-observation.v1";
const READINESS_SCHEMA: &str = "standardcharter.vapi-webcall-sip-fixture-readiness.v1";
const MAX_HTTP_BODY_BYTES: usize = 256 * 1024;
const MAX_CALLBACK_TYPES: usize = 16;
const MAX_HEADER_NAMES: usize = 32;
const MAX_AUDIO_SAMPLES: usize = 32_000;
const RETURN_AUDIO_FRAMES: usize = 75;
const FRAME_SAMPLES: usize = 160;
const FRAME_DURATION: Duration = Duration::from_millis(20);
#[cfg(test)]
const DEFAULT_ATTEMPT_TTL: Duration = Duration::from_secs(15 * 60);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const BRIDGEFU_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Local,
    Deployment,
}

impl Mode {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "local" => Ok(Self::Local),
            "deployment" => Ok(Self::Deployment),
            _ => bail!("VAPI_FIXTURE_MODE must be local or deployment"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Deployment => "deployment",
        }
    }
}

#[derive(Clone)]
struct FixtureConfig {
    mode: Mode,
    http_bind: SocketAddr,
    http_tls_cert: Option<PathBuf>,
    http_tls_key: Option<PathBuf>,
    sip_bind: SocketAddr,
    sip_tls_bind: Option<SocketAddr>,
    sip_advertised_addr: Option<SocketAddr>,
    media_public_ip: Option<IpAddr>,
    media_port_start: u16,
    media_port_end: u16,
    public_sip_uri: String,
    sip_tls_cert: Option<PathBuf>,
    sip_tls_key: Option<PathBuf>,
    observation_token: Arc<str>,
    webhook_token: Arc<str>,
    max_attempts: usize,
    attempt_ttl: Duration,
    allowed_header_names: Arc<BTreeSet<String>>,
    bridgefu: Option<BridgefuConfig>,
}

impl FixtureConfig {
    fn from_env() -> anyhow::Result<Self> {
        let mode = Mode::parse(&env_value("VAPI_FIXTURE_MODE", "local"))?;
        let http_bind = parse_socket(
            "VAPI_FIXTURE_HTTP_BIND",
            &env_value("VAPI_FIXTURE_HTTP_BIND", "127.0.0.1:9088"),
        )?;
        let sip_bind = parse_socket(
            "VAPI_FIXTURE_SIP_BIND",
            &env_value("VAPI_FIXTURE_SIP_BIND", "127.0.0.1:5060"),
        )?;
        let sip_tls_bind = optional_env("VAPI_FIXTURE_SIP_TLS_BIND")
            .map(|value| parse_socket("VAPI_FIXTURE_SIP_TLS_BIND", &value))
            .transpose()?;
        let sip_advertised_addr = optional_env("VAPI_FIXTURE_SIP_ADVERTISED_ADDR")
            .map(|value| parse_socket("VAPI_FIXTURE_SIP_ADVERTISED_ADDR", &value))
            .transpose()?;
        let media_public_ip = optional_env("VAPI_FIXTURE_MEDIA_PUBLIC_IP")
            .map(|value| {
                value
                    .parse::<IpAddr>()
                    .context("VAPI_FIXTURE_MEDIA_PUBLIC_IP is invalid")
            })
            .transpose()?;
        let media_port_start = parse_u16_env("VAPI_FIXTURE_MEDIA_PORT_START", 30_000)?;
        let media_port_end = parse_u16_env("VAPI_FIXTURE_MEDIA_PORT_END", 30_031)?;
        let max_attempts = parse_usize_env("VAPI_FIXTURE_MAX_ATTEMPTS", 8)?;
        let ttl_seconds = parse_u64_env("VAPI_FIXTURE_ATTEMPT_TTL_SECONDS", 900)?;
        let observation_token =
            Arc::<str>::from(required_secret("VAPI_FIXTURE_OBSERVATION_TOKEN")?);
        let webhook_token = Arc::<str>::from(required_secret("VAPI_FIXTURE_WEBHOOK_TOKEN")?);
        let allowed_header_names = optional_env("VAPI_FIXTURE_ALLOWED_HEADER_NAMES")
            .unwrap_or_else(|| "x-correlation-id".to_owned())
            .split(',')
            .map(|name| name.trim().to_ascii_lowercase())
            .filter(|name| !name.is_empty())
            .collect::<BTreeSet<_>>();

        let bridgefu = BridgefuConfig::from_env()?;
        let config = Self {
            mode,
            http_bind,
            http_tls_cert: optional_env("VAPI_FIXTURE_HTTP_TLS_CERT").map(PathBuf::from),
            http_tls_key: optional_env("VAPI_FIXTURE_HTTP_TLS_KEY").map(PathBuf::from),
            sip_bind,
            sip_tls_bind,
            sip_advertised_addr,
            media_public_ip,
            media_port_start,
            media_port_end,
            public_sip_uri: env_value("VAPI_FIXTURE_PUBLIC_SIP_URI", "sip:echo@127.0.0.1:5060"),
            sip_tls_cert: optional_env("VAPI_FIXTURE_SIP_TLS_CERT").map(PathBuf::from),
            sip_tls_key: optional_env("VAPI_FIXTURE_SIP_TLS_KEY").map(PathBuf::from),
            observation_token,
            webhook_token,
            max_attempts,
            attempt_ttl: Duration::from_secs(ttl_seconds),
            allowed_header_names: Arc::new(allowed_header_names),
            bridgefu,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.observation_token.len() < 32 || self.webhook_token.len() < 32 {
            bail!("fixture bearer tokens must each contain at least 32 bytes");
        }
        if constant_time_eq(
            self.observation_token.as_bytes(),
            self.webhook_token.as_bytes(),
        ) {
            bail!("observation and Vapi webhook tokens must be distinct");
        }
        if !(1..=32).contains(&self.max_attempts) {
            bail!("VAPI_FIXTURE_MAX_ATTEMPTS must be between 1 and 32");
        }
        if !(Duration::from_secs(60)..=Duration::from_secs(3600)).contains(&self.attempt_ttl) {
            bail!("VAPI_FIXTURE_ATTEMPT_TTL_SECONDS must be between 60 and 3600");
        }
        if self.media_port_start == 0
            || self.media_port_end < self.media_port_start
            || usize::from(self.media_port_end - self.media_port_start + 1)
                < self.max_attempts.saturating_mul(2)
        {
            bail!("fixture media range must provide two UDP ports per attempt");
        }
        if self.allowed_header_names.is_empty()
            || self.allowed_header_names.len() > MAX_HEADER_NAMES
            || !self.allowed_header_names.contains("x-correlation-id")
            || self
                .allowed_header_names
                .iter()
                .any(|name| !is_safe_header_name(name))
        {
            bail!("allowed SIP headers must be a bounded X-* set containing x-correlation-id");
        }
        validate_public_sip_uri(&self.public_sip_uri, self.mode)?;
        if self.mode == Mode::Deployment {
            if self.http_bind.ip().is_loopback() || self.sip_bind.ip().is_loopback() {
                bail!("deployment bind addresses must not be loopback");
            }
            let http_cert = required_path(&self.http_tls_cert, "VAPI_FIXTURE_HTTP_TLS_CERT")?;
            let http_key = required_path(&self.http_tls_key, "VAPI_FIXTURE_HTTP_TLS_KEY")?;
            let sip_cert = required_path(&self.sip_tls_cert, "VAPI_FIXTURE_SIP_TLS_CERT")?;
            let sip_key = required_path(&self.sip_tls_key, "VAPI_FIXTURE_SIP_TLS_KEY")?;
            validate_readable_file(http_cert, "HTTP TLS certificate")?;
            validate_readable_file(http_key, "HTTP TLS private key")?;
            validate_readable_file(sip_cert, "SIP TLS certificate")?;
            validate_readable_file(sip_key, "SIP TLS private key")?;
            let tls_bind = self
                .sip_tls_bind
                .context("deployment requires VAPI_FIXTURE_SIP_TLS_BIND")?;
            if tls_bind.ip().is_loopback() {
                bail!("deployment SIP TLS bind must not be loopback");
            }
            let advertised = self
                .sip_advertised_addr
                .context("deployment requires VAPI_FIXTURE_SIP_ADVERTISED_ADDR")?;
            if !is_publicly_advertisable(advertised.ip()) {
                bail!("deployment SIP advertised address must be public/routable");
            }
            let media_ip = self
                .media_public_ip
                .context("deployment requires VAPI_FIXTURE_MEDIA_PUBLIC_IP")?;
            if !is_publicly_advertisable(media_ip) {
                bail!("deployment media public IP must be public/routable");
            }
            if self.bridgefu.is_none() {
                bail!("deployment requires the Bridgefu route used by the attachment case");
            }
        } else if self.http_tls_cert.is_some() ^ self.http_tls_key.is_some() {
            bail!("local HTTP TLS certificate and key must be configured together");
        }
        Ok(())
    }

    fn safe_effective_config(&self) -> Value {
        json!({
            "schema": READINESS_SCHEMA,
            "mode": self.mode.as_str(),
            "http_bind": self.http_bind.to_string(),
            "http_tls": self.http_tls_cert.is_some(),
            "sip_bind": self.sip_bind.to_string(),
            "sip_tls": self.sip_tls_bind.is_some(),
            "srtp_required": true,
            "media_port_count": usize::from(self.media_port_end - self.media_port_start + 1),
            "media_public_address_configured": self.media_public_ip.is_some(),
            "max_attempts": self.max_attempts,
            "attempt_ttl_seconds": self.attempt_ttl.as_secs(),
            "allowed_header_names": self.allowed_header_names.as_ref(),
            "bridgefu_route_configured": self.bridgefu.is_some(),
            "observation_token": "[redacted]",
            "webhook_token": "[redacted]"
        })
    }

    fn sip_config(&self) -> anyhow::Result<Config> {
        let mut config = Config::on(
            "vapi-feasibility-observer",
            self.sip_bind.ip(),
            self.sip_bind.port(),
        )
        .with_server_capacity(self.max_attempts)
        .with_media_port_capacity(
            self.media_port_start,
            usize::from(self.media_port_end - self.media_port_start + 1),
        );
        config.offer_srtp = true;
        config.srtp_required = true;
        config.active_call_no_media_timeout_secs = 30;
        config.active_call_media_idle_timeout_secs = 30;
        config.setup_teardown_timeout_secs = 30;
        if let Some(advertised) = self.sip_advertised_addr {
            config.sip_advertised_addr = Some(advertised);
        }
        if let Some(media_ip) = self.media_public_ip {
            config.media_public_addr = Some(SocketAddr::new(media_ip, 0));
        }
        if let (Some(tls_bind), Some(cert), Some(key)) = (
            self.sip_tls_bind,
            self.sip_tls_cert.as_ref(),
            self.sip_tls_key.as_ref(),
        ) {
            config = config.tls_reachable_contact(tls_bind, cert, key);
            config.tls_advertised_addr = self.sip_advertised_addr;
        }
        config.validate().map_err(anyhow::Error::msg)?;
        Ok(config)
    }
}

#[derive(Clone)]
struct BridgefuConfig {
    client: reqwest::Client,
    base_url: Url,
    bearer: Arc<str>,
    route_id: Arc<str>,
}

impl BridgefuConfig {
    fn from_env() -> anyhow::Result<Option<Self>> {
        let base = optional_env("VAPI_FIXTURE_BRIDGEFU_API_BASE");
        let bearer = optional_env("VAPI_FIXTURE_BRIDGEFU_BEARER_TOKEN");
        let route_id = optional_env("VAPI_FIXTURE_BRIDGEFU_ROUTE_ID");
        if base.is_none() && bearer.is_none() && route_id.is_none() {
            return Ok(None);
        }
        let (Some(base), Some(bearer), Some(route_id)) = (base, bearer, route_id) else {
            bail!("Bridgefu fixture configuration is partial");
        };
        if bearer.len() < 32 || bearer.len() > 4096 {
            bail!("VAPI_FIXTURE_BRIDGEFU_BEARER_TOKEN has an invalid length");
        }
        if !is_safe_route_id(&route_id) {
            bail!("VAPI_FIXTURE_BRIDGEFU_ROUTE_ID is invalid");
        }
        let mut base_url =
            Url::parse(&base).context("VAPI_FIXTURE_BRIDGEFU_API_BASE is invalid")?;
        if base_url.scheme() != "https"
            || base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            bail!("Bridgefu API base must be a credential-free HTTPS origin");
        }
        if !base_url.path().ends_with('/') {
            base_url.set_path(&format!("{}/", base_url.path()));
        }
        let client = reqwest::Client::builder()
            .timeout(BRIDGEFU_TIMEOUT)
            .redirect(Policy::none())
            .build()
            .context("building Bridgefu fixture client")?;
        Ok(Some(Self {
            client,
            base_url,
            bearer: Arc::from(bearer),
            route_id: Arc::from(route_id),
        }))
    }

    async fn reserve_sip_attachment(&self, correlation: &str) -> anyhow::Result<Attachment> {
        let endpoint = self
            .base_url
            .join(&format!("v1/routes/{}/calls", self.route_id))
            .context("constructing Bridgefu route URL")?;
        let response = self
            .client
            .post(endpoint)
            .bearer_auth(self.bearer.as_ref())
            .header("Idempotency-Key", format!("vapi-feasibility-{correlation}"))
            .json(&json!({
                "ingress": "sip",
                "context": {"correlation_id": correlation, "metadata": {}}
            }))
            .send()
            .await
            .context("Bridgefu route request failed")?;
        if response.status() != reqwest::StatusCode::CREATED {
            bail!("Bridgefu route request returned a non-created status");
        }
        if response
            .content_length()
            .is_some_and(|length| length > 64 * 1024)
        {
            bail!("Bridgefu route response exceeded the fixture limit");
        }
        let body = response
            .bytes()
            .await
            .context("reading Bridgefu route response")?;
        if body.len() > 64 * 1024 {
            bail!("Bridgefu route response exceeded the fixture limit");
        }
        let value: Value =
            serde_json::from_slice(&body).context("invalid Bridgefu route response")?;
        if value.get("route_id").and_then(Value::as_str) != Some(self.route_id.as_ref()) {
            bail!("Bridgefu route response changed the route ID");
        }
        let attachment = value
            .get("attachment")
            .and_then(Value::as_object)
            .context("Bridgefu route response omitted attachment")?;
        if attachment.get("type").and_then(Value::as_str) != Some("sip") {
            bail!("Bridgefu route response did not contain a SIP attachment");
        }
        let uri = attachment
            .get("uri")
            .and_then(Value::as_str)
            .context("Bridgefu route response omitted the SIP URI")?;
        validate_sips_uri(uri)?;
        let expires_at = attachment
            .get("expires_at")
            .and_then(Value::as_str)
            .context("Bridgefu route response omitted attachment expiry")?;
        let expires = DateTime::parse_from_rfc3339(expires_at)
            .context("Bridgefu attachment expiry was invalid")?
            .with_timezone(&Utc);
        let ttl = (expires - Utc::now()).num_seconds();
        if !(1..=120).contains(&ttl) {
            bail!("Bridgefu attachment TTL was outside the qualification contract");
        }
        Ok(Attachment {
            uri: uri.to_owned(),
            ttl_seconds: ttl as u64,
        })
    }
}

struct Attachment {
    uri: String,
    ttl_seconds: u64,
}

#[derive(Default)]
struct Attempt {
    created_at: Option<Instant>,
    case_id: Option<String>,
    call_fingerprint: Option<String>,
    callback_types: BTreeSet<String>,
    final_reason: Option<String>,
    sip_invite_observed: bool,
    transfer_complete_observed: bool,
    browser_marker_observed: bool,
    return_audio_started: bool,
    return_audio_sent: bool,
    dtmf_verified: bool,
    dtmf_transport: Option<&'static str>,
    observed_header_names: BTreeSet<String>,
    handle: Option<SessionHandle>,
    sender: Option<AudioSender>,
    media_task: Option<JoinHandle<()>>,
    peer_hangup_requested: bool,
    bye_from_vapi_observed: bool,
    bye_from_peer_observed: bool,
    ended: bool,
    cleanup_verified: bool,
    attachment_ttl_seconds: Option<u64>,
    failure_class: Option<&'static str>,
}

impl Attempt {
    fn touch(&mut self) {
        if self.created_at.is_none() {
            self.created_at = Some(Instant::now());
        }
    }
}

struct Store {
    attempts: HashMap<String, Attempt>,
    sessions: HashMap<String, String>,
}

impl Store {
    fn new() -> Self {
        Self {
            attempts: HashMap::new(),
            sessions: HashMap::new(),
        }
    }
}

#[derive(Clone)]
struct AppState {
    config: Arc<FixtureConfig>,
    store: Arc<Mutex<Store>>,
    stopping: CancellationToken,
}

impl AppState {
    fn new(config: FixtureConfig) -> Self {
        Self {
            config: Arc::new(config),
            store: Arc::new(Mutex::new(Store::new())),
            stopping: CancellationToken::new(),
        }
    }

    async fn ensure_attempt<'a>(
        &'a self,
        store: &'a mut Store,
        correlation: &str,
    ) -> Result<&'a mut Attempt, ApiError> {
        reap_expired_locked(store, self.config.attempt_ttl);
        if !store.attempts.contains_key(correlation)
            && store.attempts.len() >= self.config.max_attempts
        {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "capacity_exhausted",
            ));
        }
        let attempt = store.attempts.entry(correlation.to_owned()).or_default();
        attempt.touch();
        Ok(attempt)
    }

    async fn cleanup_all(&self) {
        self.stopping.cancel();
        let handles = {
            let mut store = self.store.lock().await;
            store
                .attempts
                .values_mut()
                .filter_map(|attempt| {
                    if let Some(task) = attempt.media_task.take() {
                        task.abort();
                    }
                    attempt.sender = None;
                    attempt.handle.take()
                })
                .collect::<Vec<_>>()
        };
        for handle in handles {
            let _ = tokio::time::timeout(
                CLEANUP_TIMEOUT,
                handle.hangup_and_wait(Some(CLEANUP_TIMEOUT)),
            )
            .await;
        }
        let mut store = self.store.lock().await;
        store.sessions.clear();
        for attempt in store.attempts.values_mut() {
            attempt.ended = true;
            attempt.cleanup_verified = true;
        }
    }
}

#[derive(Clone)]
struct ObserverHandler {
    state: AppState,
}

#[async_trait]
impl CallHandler for ObserverHandler {
    async fn on_incoming_call(&self, call: IncomingCall) -> CallHandlerDecision {
        if self.state.stopping.is_cancelled() {
            return reject(503, "Fixture Draining");
        }
        if self.state.config.mode == Mode::Deployment
            && !call.transport_security_context().is_secure()
        {
            return reject(403, "SIPS Required");
        }
        let header = HeaderName::Other("X-Correlation-Id".to_owned());
        let Some(correlation) = call
            .header_str(&header)
            .and_then(|value| normalize_header_value(&value))
            .filter(|value| is_correlation(value))
        else {
            return reject(403, "Correlation Required");
        };
        let session_id = call.call_id.to_string();
        let observed_names = call
            .header_names()
            .into_iter()
            .map(|name| name.canonical_wire_name().as_str().to_ascii_lowercase())
            .filter(|name| self.state.config.allowed_header_names.contains(name))
            .take(MAX_HEADER_NAMES)
            .collect::<BTreeSet<_>>();
        let mut store = self.state.store.lock().await;
        let attempt = match self.state.ensure_attempt(&mut store, &correlation).await {
            Ok(attempt) => attempt,
            Err(_) => return reject(503, "Fixture Capacity"),
        };
        if attempt.sip_invite_observed || attempt.ended {
            return reject(409, "Duplicate Attempt");
        }
        attempt.sip_invite_observed = true;
        attempt.observed_header_names = observed_names;
        store.sessions.insert(session_id, correlation);
        CallHandlerDecision::Accept
    }

    async fn on_call_established(&self, handle: SessionHandle) {
        let session_id = handle.id().to_string();
        let correlation = {
            let store = self.state.store.lock().await;
            store.sessions.get(&session_id).cloned()
        };
        let Some(correlation) = correlation else {
            let _ = handle.hangup().await;
            return;
        };
        let audio = match handle.audio().await {
            Ok(audio) => audio,
            Err(_) => {
                mark_failure(&self.state, &correlation, "infrastructure").await;
                let _ = handle.hangup().await;
                return;
            }
        };
        let (sender, mut receiver) = audio.split();
        let state = self.state.clone();
        let correlation_for_task = correlation.clone();
        let cancel = self.state.stopping.child_token();
        let media_task = tokio::spawn(async move {
            let mut detector = MarkerDetector::default();
            loop {
                let frame = tokio::select! {
                    _ = cancel.cancelled() => break,
                    frame = receiver.recv() => frame,
                };
                let Some(frame) = frame else { break };
                let result = detector.observe(&frame);
                if result.marker || result.in_band_dtmf {
                    let mut store = state.store.lock().await;
                    if let Some(attempt) = store.attempts.get_mut(&correlation_for_task) {
                        attempt.browser_marker_observed |= result.marker;
                        if result.in_band_dtmf {
                            attempt.dtmf_verified = true;
                            attempt.dtmf_transport = Some("in_band");
                        }
                    }
                }
            }
        });
        let mut store = self.state.store.lock().await;
        if let Some(attempt) = store.attempts.get_mut(&correlation) {
            attempt.transfer_complete_observed = true;
            attempt.handle = Some(handle);
            attempt.sender = Some(sender);
            attempt.media_task = Some(media_task);
        } else {
            media_task.abort();
        }
    }

    async fn on_dtmf(&self, handle: SessionHandle, _digit: char) {
        let session_id = handle.id().to_string();
        let mut store = self.state.store.lock().await;
        let correlation = store.sessions.get(&session_id).cloned();
        if let Some(attempt) = correlation.and_then(|id| store.attempts.get_mut(&id)) {
            attempt.dtmf_verified = true;
            attempt.dtmf_transport = Some("rfc4733");
        }
    }

    async fn on_call_ended(&self, call_id: CallId, _reason: EndReason) {
        finish_session(&self.state, &call_id.to_string(), false).await;
    }

    async fn on_call_failed(&self, call_id: CallId, _status_code: u16, _reason: String) {
        finish_session(&self.state, &call_id.to_string(), true).await;
    }

    async fn on_call_cancelled(&self, call_id: CallId) {
        finish_session(&self.state, &call_id.to_string(), false).await;
    }
}

fn reject(status: u16, reason: &str) -> CallHandlerDecision {
    CallHandlerDecision::Reject {
        status,
        reason: reason.to_owned(),
    }
}

async fn finish_session(state: &AppState, session_id: &str, failed: bool) {
    let mut store = state.store.lock().await;
    let Some(correlation) = store.sessions.remove(session_id) else {
        return;
    };
    let Some(attempt) = store.attempts.get_mut(&correlation) else {
        return;
    };
    if let Some(task) = attempt.media_task.take() {
        task.abort();
    }
    attempt.sender = None;
    attempt.handle = None;
    attempt.ended = true;
    if attempt.peer_hangup_requested {
        attempt.bye_from_peer_observed = true;
    } else {
        attempt.bye_from_vapi_observed = true;
    }
    if failed {
        attempt.failure_class = Some("infrastructure");
    }
}

async fn mark_failure(state: &AppState, correlation: &str, class: &'static str) {
    let mut store = state.store.lock().await;
    if let Some(attempt) = store.attempts.get_mut(correlation) {
        attempt.failure_class = Some(class);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationRequest {
    run_nonce: String,
    case_id: String,
    hangup_origin: String,
    vapi_call_id: String,
}

impl ObservationRequest {
    fn validate(&self) -> Result<(), ApiError> {
        if !is_base64urlish(&self.run_nonce, 16, 96)
            || !matches!(
                self.case_id.as_str(),
                "static-sip-echo" | "dynamic-sip-echo" | "dynamic-bridgefu-sips"
            )
            || !matches!(self.hangup_origin.as_str(), "browser" | "sip_peer")
            || !is_opaque_id(&self.vapi_call_id, 1, 128)
        {
            return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_request"));
        }
        Ok(())
    }

    fn correlation(&self, token: &str) -> String {
        attempt_correlation(token, &self.run_nonce, &self.case_id, &self.hangup_origin)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlRequest {
    run_nonce: String,
    case_id: String,
    hangup_origin: String,
    vapi_call_id: String,
    action: ControlAction,
}

impl ControlRequest {
    fn observation(&self) -> ObservationRequest {
        ObservationRequest {
            run_nonce: self.run_nonce.clone(),
            case_id: self.case_id.clone(),
            hangup_origin: self.hangup_origin.clone(),
            vapi_call_id: self.vapi_call_id.clone(),
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ControlAction {
    RunDtmfProbe,
    SendReturnAudioProbe,
    HangupPeer,
    Cleanup,
}

#[derive(Serialize)]
struct Observation {
    schema: &'static str,
    transfer: TransferObservation,
    media: MediaObservation,
    dtmf: DtmfObservation,
    headers: HeaderObservation,
    signaling: SignalingObservation,
    callbacks: CallbackObservation,
    cleanup: CleanupObservation,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_class: Option<&'static str>,
}

#[derive(Serialize)]
struct TransferObservation {
    mechanism: &'static str,
    target: &'static str,
    sip_invite_observed: bool,
    transfer_complete_observed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    bridgefu_attachment: Option<AttachmentObservation>,
}

#[derive(Serialize)]
struct AttachmentObservation {
    generated: bool,
    scheme: &'static str,
    single_use: bool,
    ttl_seconds: u64,
}

#[derive(Serialize)]
struct MediaObservation {
    browser_to_sip_marker_observed: bool,
    sip_to_browser_marker_sent: bool,
}

#[derive(Serialize)]
struct DtmfObservation {
    verified: bool,
    transport: Option<&'static str>,
}

#[derive(Serialize)]
struct HeaderObservation {
    allowlisted_verified: bool,
    names: Vec<String>,
}

#[derive(Serialize)]
struct SignalingObservation {
    bye_from_vapi_observed: bool,
    bye_from_peer_observed: bool,
    final_reason_observed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    final_reason: Option<String>,
}

#[derive(Serialize)]
struct CallbackObservation {
    types: Vec<String>,
}

#[derive(Serialize)]
struct CleanupObservation {
    verified: bool,
}

async fn query_observation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ObservationRequest>,
) -> Result<Json<Observation>, ApiError> {
    authorize(&headers, state.config.observation_token.as_ref())?;
    request.validate()?;
    let correlation = request.correlation(state.config.observation_token.as_ref());
    let expected_call = fingerprint(&request.vapi_call_id);
    let mut store = state.store.lock().await;
    reap_expired_locked(&mut store, state.config.attempt_ttl);
    let attempt = store
        .attempts
        .get(&correlation)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_ready"))?;
    if attempt.case_id.as_deref() != Some(request.case_id.as_str())
        || attempt.call_fingerprint.as_deref() != Some(expected_call.as_str())
    {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "attempt_mismatch"));
    }
    let (mechanism, target) = topology(&request.case_id);
    let names = attempt
        .observed_header_names
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let allowlisted_verified = names.iter().any(|name| name == "x-correlation-id")
        && names
            .iter()
            .all(|name| state.config.allowed_header_names.contains(name));
    let bridgefu_attachment =
        attempt
            .attachment_ttl_seconds
            .map(|ttl_seconds| AttachmentObservation {
                generated: true,
                scheme: "sips",
                single_use: true,
                ttl_seconds,
            });
    Ok(Json(Observation {
        schema: OBSERVATION_SCHEMA,
        transfer: TransferObservation {
            mechanism,
            target,
            sip_invite_observed: attempt.sip_invite_observed,
            transfer_complete_observed: attempt.transfer_complete_observed,
            bridgefu_attachment,
        },
        media: MediaObservation {
            browser_to_sip_marker_observed: attempt.browser_marker_observed,
            sip_to_browser_marker_sent: attempt.return_audio_sent,
        },
        dtmf: DtmfObservation {
            verified: attempt.dtmf_verified,
            transport: attempt.dtmf_transport,
        },
        headers: HeaderObservation {
            allowlisted_verified,
            names,
        },
        signaling: SignalingObservation {
            bye_from_vapi_observed: attempt.bye_from_vapi_observed,
            bye_from_peer_observed: attempt.bye_from_peer_observed,
            final_reason_observed: attempt.final_reason.is_some(),
            final_reason: attempt.final_reason.clone(),
        },
        callbacks: CallbackObservation {
            types: attempt.callback_types.iter().cloned().collect(),
        },
        cleanup: CleanupObservation {
            verified: attempt.cleanup_verified,
        },
        failure_class: attempt.failure_class,
    }))
}

async fn control_observation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ControlRequest>,
) -> Result<StatusCode, ApiError> {
    authorize(&headers, state.config.observation_token.as_ref())?;
    let observation = request.observation();
    observation.validate()?;
    let correlation = observation.correlation(state.config.observation_token.as_ref());
    let call_fingerprint = fingerprint(&observation.vapi_call_id);
    {
        let store = state.store.lock().await;
        let attempt = store
            .attempts
            .get(&correlation)
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_ready"))?;
        if attempt.case_id.as_deref() != Some(observation.case_id.as_str())
            || attempt.call_fingerprint.as_deref() != Some(call_fingerprint.as_str())
        {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "attempt_mismatch"));
        }
    }
    match request.action {
        ControlAction::RunDtmfProbe => run_dtmf_probe(&state, &correlation).await?,
        ControlAction::SendReturnAudioProbe => {
            start_return_audio_probe(&state, &correlation).await?
        }
        ControlAction::HangupPeer => hangup_peer(&state, &correlation).await?,
        ControlAction::Cleanup => cleanup_attempt(&state, &correlation).await?,
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn run_dtmf_probe(state: &AppState, correlation: &str) -> Result<(), ApiError> {
    let handle = {
        let store = state.store.lock().await;
        store
            .attempts
            .get(correlation)
            .and_then(|attempt| attempt.handle.clone())
            .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "call_not_active"))?
    };
    tokio::time::timeout(Duration::from_secs(2), handle.send_dtmf('5'))
        .await
        .map_err(|_| ApiError::new(StatusCode::GATEWAY_TIMEOUT, "dtmf_timeout"))?
        .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "dtmf_failed"))?;
    Ok(())
}

async fn start_return_audio_probe(state: &AppState, correlation: &str) -> Result<(), ApiError> {
    let sender = {
        let mut store = state.store.lock().await;
        let attempt = store
            .attempts
            .get_mut(correlation)
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_ready"))?;
        if attempt.return_audio_started {
            return Ok(());
        }
        let sender = attempt
            .sender
            .clone()
            .filter(AudioSender::is_open)
            .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "media_not_active"))?;
        attempt.return_audio_started = true;
        sender
    };
    let state = state.clone();
    let correlation = correlation.to_owned();
    tokio::spawn(async move {
        let mut phase = 0.0_f32;
        let mut sent = true;
        for frame_index in 0..RETURN_AUDIO_FRAMES {
            let samples = tone_frame(880.0, &mut phase);
            let frame = AudioFrame::new(samples, 8_000, 1, (frame_index * FRAME_SAMPLES) as u32);
            if sender.send(frame).await.is_err() {
                sent = false;
                break;
            }
            tokio::time::sleep(FRAME_DURATION).await;
        }
        let mut store = state.store.lock().await;
        if let Some(attempt) = store.attempts.get_mut(&correlation) {
            attempt.return_audio_sent = sent;
            if !sent {
                attempt.failure_class = Some("infrastructure");
            }
        }
    });
    Ok(())
}

async fn hangup_peer(state: &AppState, correlation: &str) -> Result<(), ApiError> {
    let handle = {
        let mut store = state.store.lock().await;
        let attempt = store
            .attempts
            .get_mut(correlation)
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_ready"))?;
        if attempt.ended {
            attempt.bye_from_peer_observed = true;
            return Ok(());
        }
        attempt.peer_hangup_requested = true;
        attempt
            .handle
            .clone()
            .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "call_not_active"))?
    };
    tokio::time::timeout(
        CLEANUP_TIMEOUT,
        handle.hangup_and_wait(Some(CLEANUP_TIMEOUT)),
    )
    .await
    .map_err(|_| ApiError::new(StatusCode::GATEWAY_TIMEOUT, "hangup_timeout"))?
    .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "hangup_failed"))?;
    let mut store = state.store.lock().await;
    if let Some(attempt) = store.attempts.get_mut(correlation) {
        attempt.bye_from_peer_observed = true;
        attempt.ended = true;
    }
    Ok(())
}

async fn cleanup_attempt(state: &AppState, correlation: &str) -> Result<(), ApiError> {
    let handle = {
        let mut store = state.store.lock().await;
        let attempt = store
            .attempts
            .get_mut(correlation)
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_ready"))?;
        if let Some(task) = attempt.media_task.take() {
            task.abort();
        }
        attempt.sender = None;
        attempt.handle.take()
    };
    if let Some(handle) = handle {
        let _ = tokio::time::timeout(
            CLEANUP_TIMEOUT,
            handle.hangup_and_wait(Some(CLEANUP_TIMEOUT)),
        )
        .await;
    }
    let mut store = state.store.lock().await;
    store.sessions.retain(|_, value| value != correlation);
    if let Some(attempt) = store.attempts.get_mut(correlation) {
        attempt.ended = true;
        attempt.cleanup_verified = true;
    }
    Ok(())
}

async fn vapi_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    authorize(&headers, state.config.webhook_token.as_ref())?;
    let message = payload
        .get("message")
        .and_then(Value::as_object)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "invalid_vapi_event"))?;
    let event_type = message
        .get("type")
        .and_then(Value::as_str)
        .and_then(safe_label)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "invalid_vapi_event"))?;
    let call = message
        .get("call")
        .and_then(Value::as_object)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "invalid_vapi_event"))?;
    let call_id = call
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| is_opaque_id(value, 1, 128))
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "invalid_vapi_event"))?;
    let variables = find_variable_values(message, call)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "missing_attempt_binding"))?;
    let correlation = variables
        .get("bridgefu_feasibility_correlation_id")
        .and_then(Value::as_str)
        .filter(|value| is_correlation(value))
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "missing_attempt_binding"))?;
    let case_id = variables
        .get("bridgefu_feasibility_case_id")
        .and_then(Value::as_str)
        .filter(|value| {
            matches!(
                *value,
                "static-sip-echo" | "dynamic-sip-echo" | "dynamic-bridgefu-sips"
            )
        })
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "missing_attempt_binding"))?;
    let call_fingerprint = fingerprint(call_id);
    let final_reason = extract_final_reason(message, call);
    {
        let mut store = state.store.lock().await;
        let attempt = state.ensure_attempt(&mut store, correlation).await?;
        if attempt
            .case_id
            .as_deref()
            .is_some_and(|existing| existing != case_id)
            || attempt
                .call_fingerprint
                .as_deref()
                .is_some_and(|existing| existing != call_fingerprint)
        {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "attempt_mismatch"));
        }
        attempt.case_id = Some(case_id.to_owned());
        attempt.call_fingerprint = Some(call_fingerprint);
        if attempt.callback_types.len() < MAX_CALLBACK_TYPES {
            attempt.callback_types.insert(event_type.to_owned());
        }
        if let Some(reason) = final_reason {
            attempt.final_reason = Some(reason);
        }
    }

    if event_type != "transfer-destination-request" {
        return Ok(Json(json!({"received": true})));
    }
    let attachment = match case_id {
        "dynamic-sip-echo" => Attachment {
            uri: state.config.public_sip_uri.clone(),
            ttl_seconds: 0,
        },
        "dynamic-bridgefu-sips" => {
            let bridgefu = state.config.bridgefu.as_ref().ok_or_else(|| {
                ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "bridgefu_not_configured")
            })?;
            bridgefu
                .reserve_sip_attachment(correlation)
                .await
                .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "bridgefu_unavailable"))?
        }
        _ => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "unexpected_transfer_request",
            ))
        }
    };
    if case_id == "dynamic-bridgefu-sips" {
        let mut store = state.store.lock().await;
        if let Some(attempt) = store.attempts.get_mut(correlation) {
            attempt.attachment_ttl_seconds = Some(attachment.ttl_seconds);
        }
    }
    Ok(Json(json!({
        "destination": {
            "type": "sip",
            "sipUri": attachment.uri,
            "sipHeaders": {"x-correlation-id": correlation}
        },
        "message": {
            "type": "request-start",
            "message": "Connecting the controlled non-production qualification peer now."
        }
    })))
}

fn find_variable_values<'a>(
    message: &'a serde_json::Map<String, Value>,
    call: &'a serde_json::Map<String, Value>,
) -> Option<&'a serde_json::Map<String, Value>> {
    let candidates = [
        call.get("assistantOverrides")
            .and_then(|value| value.get("variableValues")),
        call.get("artifact")
            .and_then(|value| value.get("variableValues")),
        call.get("variableValues"),
        message.get("variableValues"),
    ];
    candidates.into_iter().flatten().find_map(Value::as_object)
}

fn extract_final_reason(
    message: &serde_json::Map<String, Value>,
    call: &serde_json::Map<String, Value>,
) -> Option<String> {
    [message.get("endedReason"), call.get("endedReason")]
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .find_map(safe_label)
        .map(str::to_owned)
}

async fn livez() -> Json<Value> {
    Json(json!({"status": "live"}))
}

async fn readyz(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    authorize(&headers, state.config.observation_token.as_ref())?;
    if state.stopping.is_cancelled() {
        return Err(ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "draining"));
    }
    Ok(Json(json!({
        "schema": READINESS_SCHEMA,
        "status": "ready",
        "mode": state.config.mode.as_str(),
        "capabilities": {
            "authenticated_query_control": true,
            "authenticated_vapi_callbacks": true,
            "dynamic_sip_transfer": true,
            "bridgefu_attachment": state.config.bridgefu.is_some(),
            "sips": state.config.sip_tls_bind.is_some(),
            "srtp_required": true,
            "bidirectional_audio_probe": true,
            "dtmf": true,
            "remote_hangup": true,
            "redacted_observations": true
        }
    })))
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        .route(QUERY_PATH, post(query_observation))
        .route(CONTROL_PATH, post(control_observation))
        .route(VAPI_EVENTS_PATH, post(vapi_events))
        .layer(DefaultBodyLimit::max(MAX_HTTP_BODY_BYTES))
        .with_state(state)
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str) -> Self {
        Self { status, code }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error": self.code}))).into_response()
    }
}

fn authorize(headers: &HeaderMap, expected: &str) -> Result<(), ApiError> {
    let presented = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

fn attempt_correlation(token: &str, run_nonce: &str, case_id: &str, hangup: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(token.as_bytes())
        .expect("HMAC accepts arbitrary bearer-token bytes");
    mac.update(run_nonce.as_bytes());
    mac.update(&[0]);
    mac.update(case_id.as_bytes());
    mac.update(&[0]);
    mac.update(hangup.as_bytes());
    hex_lower(&mac.finalize().into_bytes())
}

fn fingerprint(value: &str) -> String {
    hex_lower(&Sha256::digest(value.as_bytes()))[..12].to_owned()
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn topology(case_id: &str) -> (&'static str, &'static str) {
    match case_id {
        "static-sip-echo" => ("static_transfer_destination", "controlled_sip_echo"),
        "dynamic-sip-echo" => ("transfer_destination_request", "controlled_sip_echo"),
        "dynamic-bridgefu-sips" => ("transfer_destination_request", "bridgefu_generated_sips"),
        _ => unreachable!("validated case ID"),
    }
}

fn normalize_header_value(value: &str) -> Option<String> {
    let value = value.split_once(':').map_or(value, |(_, tail)| tail).trim();
    is_correlation(value).then(|| value.to_owned())
}

fn is_correlation(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_safe_header_name(value: &str) -> bool {
    value.len() <= 64
        && value.starts_with("x-")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_safe_route_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn is_base64urlish(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn is_opaque_id(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn safe_label(value: &str) -> Option<&str> {
    (!value.is_empty()
        && value.len() <= 80
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        }))
    .then_some(value)
}

fn validate_public_sip_uri(value: &str, mode: Mode) -> anyhow::Result<()> {
    if value.len() > 2048 || value.contains(['\r', '\n']) {
        bail!("VAPI_FIXTURE_PUBLIC_SIP_URI is invalid");
    }
    if mode == Mode::Deployment {
        validate_sips_uri(value)?;
        let host = sips_uri_host(value).context("SIPS URI omitted its host")?;
        let host = host.to_ascii_lowercase();
        let reserved_name = [
            "localhost",
            "local",
            "internal",
            "invalid",
            "test",
            "example",
        ]
        .iter()
        .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")));
        if reserved_name
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| !is_publicly_advertisable(address))
        {
            bail!("deployment SIPS URI must use a public/routable host");
        }
    } else if !value.starts_with("sip:") && !value.starts_with("sips:") {
        bail!("local fixture SIP URI must use sip: or sips:");
    }
    Ok(())
}

fn validate_sips_uri(value: &str) -> anyhow::Result<()> {
    let Some(remainder) = value.strip_prefix("sips:") else {
        bail!("SIP attachment must be a bounded SIPS URI");
    };
    if value.len() > 2_048
        || value.contains(['\r', '\n', '?', '#'])
        || remainder.contains(char::is_whitespace)
    {
        bail!("SIP attachment must be a bounded SIPS URI");
    }
    let Some((user, authority_and_params)) = remainder.split_once('@') else {
        bail!("SIP attachment must contain an opaque user and host");
    };
    if user.is_empty()
        || user.len() > 512
        || !user.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'+' | b'%')
        })
    {
        bail!("SIP attachment contains an invalid opaque user");
    }
    let authority = authority_and_params.split(';').next().unwrap_or_default();
    let valid_authority = if let Some(ipv6) = authority.strip_prefix('[') {
        ipv6.split_once(']').is_some_and(|(host, suffix)| {
            !host.is_empty()
                && host.parse::<std::net::Ipv6Addr>().is_ok()
                && (suffix.is_empty() || suffix.strip_prefix(':').is_some_and(valid_nonzero_port))
        })
    } else {
        let (host, port) = authority
            .rsplit_once(':')
            .filter(|(_, port)| port.bytes().all(|byte| byte.is_ascii_digit()))
            .map_or((authority, None), |(host, port)| (host, Some(port)));
        !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
            && port.is_none_or(valid_nonzero_port)
    };
    if !valid_authority {
        bail!("SIP attachment contains an invalid host or port");
    }
    Ok(())
}

fn valid_nonzero_port(value: &str) -> bool {
    !value.is_empty() && value.parse::<u16>().is_ok_and(|port| port != 0)
}

fn sips_uri_host(value: &str) -> Option<&str> {
    let authority = value
        .strip_prefix("sips:")?
        .split_once('@')?
        .1
        .split(';')
        .next()?;
    if let Some(ipv6) = authority.strip_prefix('[') {
        return ipv6.split_once(']').map(|(host, _)| host);
    }
    authority
        .rsplit_once(':')
        .filter(|(_, port)| port.bytes().all(|byte| byte.is_ascii_digit()))
        .map_or(Some(authority), |(host, _)| Some(host))
}

fn is_publicly_advertisable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [first, second, third, _] = address.octets();
            !(first == 0
                || first == 10
                || first == 127
                || first >= 224
                || (first == 100 && (64..=127).contains(&second))
                || (first == 169 && second == 254)
                || (first == 172 && (16..=31).contains(&second))
                || (first == 192 && second == 0 && third == 0)
                || (first == 192 && second == 0 && third == 2)
                || (first == 192 && second == 168)
                || (first == 198 && (second == 18 || second == 19))
                || (first == 198 && second == 51 && third == 100)
                || (first == 203 && second == 0 && third == 113))
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            !(address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || segments[0] & 0xfe00 == 0xfc00
                || segments[0] & 0xffc0 == 0xfe80
                || (segments[0] == 0x2001 && segments[1] == 0x0db8))
        }
    }
}

fn reap_expired_locked(store: &mut Store, ttl: Duration) {
    let expired = store
        .attempts
        .iter()
        .filter(|(_, attempt)| {
            attempt
                .created_at
                .is_some_and(|created| created.elapsed() >= ttl)
        })
        .map(|(correlation, _)| correlation.clone())
        .collect::<Vec<_>>();
    for correlation in expired {
        if let Some(mut attempt) = store.attempts.remove(&correlation) {
            if let Some(task) = attempt.media_task.take() {
                task.abort();
            }
            if let Some(handle) = attempt.handle.take() {
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(CLEANUP_TIMEOUT, handle.hangup()).await;
                });
            }
        }
        store.sessions.retain(|_, value| value != &correlation);
    }
}

#[derive(Default)]
struct MarkerDetector {
    samples: Vec<i16>,
    sample_rate: u32,
}

#[derive(Default)]
struct MarkerResult {
    marker: bool,
    in_band_dtmf: bool,
}

impl MarkerDetector {
    fn observe(&mut self, frame: &AudioFrame) -> MarkerResult {
        if frame.channels != 1 || !(8_000..=48_000).contains(&frame.sample_rate) {
            return MarkerResult::default();
        }
        if self.sample_rate != frame.sample_rate {
            self.samples.clear();
            self.sample_rate = frame.sample_rate;
        }
        self.samples.extend_from_slice(&frame.samples);
        if self.samples.len() > MAX_AUDIO_SAMPLES {
            let excess = self.samples.len() - MAX_AUDIO_SAMPLES;
            self.samples.drain(..excess);
        }
        let window_len = (self.sample_rate as usize / 4).min(self.samples.len());
        if window_len < self.sample_rate as usize / 10 {
            return MarkerResult::default();
        }
        let window = &self.samples[self.samples.len() - window_len..];
        let rms = rms(window);
        if rms < 0.015 {
            return MarkerResult::default();
        }
        let marker = tone_power(window, self.sample_rate, 997.0) > 0.002;
        let low = tone_power(window, self.sample_rate, 697.0);
        let high = tone_power(window, self.sample_rate, 1209.0);
        let in_band_dtmf = low > 0.001 && high > 0.001;
        MarkerResult {
            marker,
            in_band_dtmf,
        }
    }
}

fn rms(samples: &[i16]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let energy = samples
        .iter()
        .map(|sample| {
            let value = f64::from(*sample) / f64::from(i16::MAX);
            value * value
        })
        .sum::<f64>();
    (energy / samples.len() as f64).sqrt()
}

fn tone_power(samples: &[i16], sample_rate: u32, frequency: f64) -> f64 {
    let normalized_frequency = frequency / f64::from(sample_rate);
    let coefficient = 2.0 * (2.0 * std::f64::consts::PI * normalized_frequency).cos();
    let mut previous = 0.0;
    let mut before_previous = 0.0;
    for sample in samples {
        let value = f64::from(*sample) / f64::from(i16::MAX);
        let current = value + coefficient * previous - before_previous;
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
            let sample = (*phase).sin() * 0.25 * f32::from(i16::MAX);
            *phase = (*phase + step) % (2.0 * std::f32::consts::PI);
            sample as i16
        })
        .collect()
}

fn env_value(name: &str, default: &str) -> String {
    optional_env(name).unwrap_or_else(|| default.to_owned())
}

fn optional_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn required_secret(name: &str) -> anyhow::Result<String> {
    optional_env(name).with_context(|| format!("{name} is required"))
}

fn parse_socket(name: &str, value: &str) -> anyhow::Result<SocketAddr> {
    value.parse().with_context(|| format!("{name} is invalid"))
}

fn parse_u16_env(name: &str, default: u16) -> anyhow::Result<u16> {
    optional_env(name)
        .map(|value| {
            value
                .parse::<u16>()
                .with_context(|| format!("{name} is invalid"))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn parse_u64_env(name: &str, default: u64) -> anyhow::Result<u64> {
    optional_env(name)
        .map(|value| {
            value
                .parse::<u64>()
                .with_context(|| format!("{name} is invalid"))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn parse_usize_env(name: &str, default: usize) -> anyhow::Result<usize> {
    optional_env(name)
        .map(|value| {
            value
                .parse::<usize>()
                .with_context(|| format!("{name} is invalid"))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn required_path<'a>(value: &'a Option<PathBuf>, name: &str) -> anyhow::Result<&'a Path> {
    value
        .as_deref()
        .with_context(|| format!("deployment requires {name}"))
}

fn validate_readable_file(path: &Path, label: &str) -> anyhow::Result<()> {
    let metadata = std::fs::metadata(path).with_context(|| format!("{label} is not readable"))?;
    if !metadata.is_file() || metadata.len() == 0 {
        bail!("{label} must be a non-empty regular file");
    }
    Ok(())
}

async fn run_http(state: AppState) -> anyhow::Result<()> {
    let app = router(state.clone());
    if let (Some(cert), Some(key)) = (
        state.config.http_tls_cert.as_ref(),
        state.config.http_tls_key.as_ref(),
    ) {
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
            .await
            .context("loading fixture HTTP TLS identity")?;
        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();
        let cancel = state.stopping.clone();
        tokio::spawn(async move {
            cancel.cancelled().await;
            shutdown_handle.graceful_shutdown(Some(CLEANUP_TIMEOUT));
        });
        axum_server::bind_rustls(state.config.http_bind, tls)
            .handle(handle)
            .serve(app.into_make_service())
            .await
            .context("fixture HTTPS server failed")?;
    } else {
        let listener = tokio::net::TcpListener::bind(state.config.http_bind)
            .await
            .context("binding fixture HTTP listener")?;
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(state.stopping.clone().cancelled_owned())
            .await
            .context("fixture HTTP server failed")?;
    }
    Ok(())
}

async fn run_reaper(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
            _ = state.stopping.cancelled() => return,
            _ = interval.tick() => {
                let mut store = state.store.lock().await;
                reap_expired_locked(&mut store, state.config.attempt_ttl);
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = FixtureConfig::from_env()?;
    if env::args().any(|argument| argument == "--validate-config") {
        println!(
            "{}",
            serde_json::to_string_pretty(&config.safe_effective_config())?
        );
        return Ok(());
    }
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            env::var("RUST_LOG").unwrap_or_else(|_| "vapi_feasibility_observer=info".to_owned()),
        )
        .init();

    let sip_config = config.sip_config()?;
    let state = AppState::new(config);
    let peer = CallbackPeer::new(
        ObserverHandler {
            state: state.clone(),
        },
        sip_config,
    )
    .await
    .context("starting rvoip SIP observer")?;
    let sip_shutdown = peer.shutdown_handle();
    let sip_task = tokio::spawn(peer.run());
    let http_task = tokio::spawn(run_http(state.clone()));
    let reaper_task = tokio::spawn(run_reaper(state.clone()));

    tracing::info!(
        mode = state.config.mode.as_str(),
        http_tls = state.config.http_tls_cert.is_some(),
        sip_tls = state.config.sip_tls_bind.is_some(),
        srtp_required = true,
        max_attempts = state.config.max_attempts,
        "Vapi feasibility fixture ready"
    );

    tokio::select! {
        signal = tokio::signal::ctrl_c() => signal.context("installing shutdown signal")?,
        result = http_task => {
            result.context("HTTP task join")??;
        },
        result = sip_task => {
            result.context("SIP task join")?.context("SIP observer failed")?;
        },
    }
    state.cleanup_all().await;
    sip_shutdown.shutdown();
    reaper_task.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::CONTENT_TYPE;
    use rvoip_sip::api::headers::SipRequestOptions;
    use rvoip_sip::StreamPeer;
    use tower::ServiceExt;

    const OBSERVATION_TOKEN: &str = "observation-token-with-at-least-32-bytes";
    const WEBHOOK_TOKEN: &str = "webhook-token-that-is-separate-and-long";

    fn test_config() -> FixtureConfig {
        FixtureConfig {
            mode: Mode::Local,
            http_bind: "127.0.0.1:9088".parse().unwrap(),
            http_tls_cert: None,
            http_tls_key: None,
            sip_bind: "127.0.0.1:5060".parse().unwrap(),
            sip_tls_bind: None,
            sip_advertised_addr: None,
            media_public_ip: None,
            media_port_start: 30_000,
            media_port_end: 30_031,
            public_sip_uri: "sip:echo@127.0.0.1:5060".to_owned(),
            sip_tls_cert: None,
            sip_tls_key: None,
            observation_token: Arc::from(OBSERVATION_TOKEN),
            webhook_token: Arc::from(WEBHOOK_TOKEN),
            max_attempts: 8,
            attempt_ttl: DEFAULT_ATTEMPT_TTL,
            allowed_header_names: Arc::new(BTreeSet::from(["x-correlation-id".to_owned()])),
            bridgefu: None,
        }
    }

    #[test]
    fn correlation_is_stable_and_bound_to_every_attempt_dimension() {
        let value = attempt_correlation(
            OBSERVATION_TOKEN,
            "run_nonce_0123456789",
            "static-sip-echo",
            "browser",
        );
        assert_eq!(value.len(), 64);
        assert_eq!(
            value,
            "c28d46762e6d28e3984432d41fb86cdab1435598eada1e023b018485ca7ed005"
        );
        assert_ne!(
            value,
            attempt_correlation(
                OBSERVATION_TOKEN,
                "run_nonce_0123456789",
                "static-sip-echo",
                "sip_peer"
            )
        );
    }

    #[test]
    fn deployment_address_policy_rejects_local_private_and_documentation_ranges() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "192.0.2.10",
            "198.51.100.10",
            "203.0.113.10",
            "::1",
            "fd00::1",
            "fe80::1",
            "2001:db8::1",
        ] {
            assert!(!is_publicly_advertisable(address.parse().unwrap()));
        }
        assert!(is_publicly_advertisable("8.8.8.8".parse().unwrap()));
        assert!(is_publicly_advertisable(
            "2606:4700:4700::1111".parse().unwrap()
        ));
    }

    #[test]
    fn marker_detector_recognizes_fake_microphone_marker_and_dtmf() {
        let mut detector = MarkerDetector::default();
        let mut phase = 0.0;
        let mut result = MarkerResult::default();
        for _ in 0..20 {
            result = detector.observe(&AudioFrame::new(tone_frame(997.0, &mut phase), 8_000, 1, 0));
        }
        assert!(result.marker);

        let mut detector = MarkerDetector::default();
        let mut low_phase = 0.0_f32;
        let mut high_phase = 0.0_f32;
        for frame_index in 0..20 {
            let samples = (0..FRAME_SAMPLES)
                .map(|_| {
                    let low = low_phase.sin();
                    let high = high_phase.sin();
                    low_phase += 2.0 * std::f32::consts::PI * 697.0 / 8_000.0;
                    high_phase += 2.0 * std::f32::consts::PI * 1209.0 / 8_000.0;
                    ((low + high) * 0.12 * f32::from(i16::MAX)) as i16
                })
                .collect();
            result = detector.observe(&AudioFrame::new(
                samples,
                8_000,
                1,
                (frame_index * FRAME_SAMPLES) as u32,
            ));
        }
        assert!(result.in_band_dtmf);
    }

    #[tokio::test]
    async fn webhook_and_query_are_authenticated_bound_and_redacted() {
        let state = AppState::new(test_config());
        let app = router(state.clone());
        let run_nonce = "run_nonce_0123456789";
        let case_id = "dynamic-sip-echo";
        let hangup = "browser";
        let correlation = attempt_correlation(OBSERVATION_TOKEN, run_nonce, case_id, hangup);
        let call_id = "call_123456789";
        let webhook = json!({
            "message": {
                "type": "transfer-destination-request",
                "call": {
                    "id": call_id,
                    "assistantOverrides": {"variableValues": {
                        "bridgefu_feasibility_correlation_id": correlation,
                        "bridgefu_feasibility_case_id": case_id
                    }}
                }
            }
        });
        let response = app
            .clone()
            .oneshot(json_request(VAPI_EVENTS_PATH, WEBHOOK_TOKEN, webhook))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let destination: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(destination["destination"]["type"], "sip");
        assert_eq!(destination["message"]["type"], "request-start");
        assert_eq!(
            destination["destination"]["sipHeaders"]["x-correlation-id"],
            correlation
        );

        {
            let mut store = state.store.lock().await;
            let attempt = store.attempts.get_mut(&correlation).unwrap();
            attempt.sip_invite_observed = true;
            attempt.transfer_complete_observed = true;
            attempt.browser_marker_observed = true;
            attempt.return_audio_sent = true;
            attempt.dtmf_verified = true;
            attempt.dtmf_transport = Some("rfc4733");
            attempt
                .observed_header_names
                .insert("x-correlation-id".to_owned());
        }
        let query = json!({
            "run_nonce": run_nonce,
            "case_id": case_id,
            "hangup_origin": hangup,
            "vapi_call_id": call_id
        });
        let response = app
            .clone()
            .oneshot(json_request(QUERY_PATH, OBSERVATION_TOKEN, query.clone()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(!text.contains(call_id));
        assert!(!text.contains(&correlation));
        assert!(!text.contains("sip:echo@"));
        let observation: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(observation["schema"], OBSERVATION_SCHEMA);
        assert_eq!(observation["headers"]["names"][0], "x-correlation-id");

        let unauthorized = app
            .clone()
            .oneshot(json_request(QUERY_PATH, "wrong-token", query.clone()))
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let mismatched = json!({
            "run_nonce": run_nonce,
            "case_id": case_id,
            "hangup_origin": "sip_peer",
            "vapi_call_id": call_id
        });
        let response = app
            .oneshot(json_request(QUERY_PATH, OBSERVATION_TOKEN, mismatched))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn local_rvoip_peer_observes_srtp_audio_dtmf_and_bye() {
        let base = 41_000 + ((std::process::id() as u16) % 1_000) * 8;
        let fixture_sip = base;
        let caller_sip = base + 1;
        let mut config = test_config();
        config.sip_bind = SocketAddr::from(([127, 0, 0, 1], fixture_sip));
        config.public_sip_uri = format!("sip:echo@127.0.0.1:{fixture_sip}");
        config.media_port_start = base + 2;
        config.media_port_end = base + 5;
        config.max_attempts = 1;
        config.validate().unwrap();
        let state = AppState::new(config.clone());
        let peer = CallbackPeer::new(
            ObserverHandler {
                state: state.clone(),
            },
            config.sip_config().unwrap(),
        )
        .await
        .unwrap();
        let stop = peer.shutdown_handle();
        let peer_task = tokio::spawn(peer.run());
        tokio::time::sleep(Duration::from_millis(150)).await;

        let mut caller_config = Config::local("fixture-test-caller", caller_sip);
        caller_config.media_port_start = base + 6;
        caller_config.media_port_end = base + 9;
        caller_config.offer_srtp = true;
        caller_config.srtp_required = true;
        let mut caller = StreamPeer::with_config(caller_config).await.unwrap();
        let correlation = attempt_correlation(
            OBSERVATION_TOKEN,
            "run_nonce_0123456789",
            "static-sip-echo",
            "browser",
        );
        let call_id = caller
            .invite(format!("sip:echo@127.0.0.1:{fixture_sip}"))
            .with_raw_header(
                HeaderName::Other("X-Correlation-Id".to_owned()),
                correlation.clone(),
            )
            .unwrap()
            .send()
            .await
            .unwrap();
        caller
            .wait_for_answered(&call_id)
            .await
            .expect("fixture answers SRTP call");
        let handle = caller.coordinator().session(&call_id);
        handle
            .wait_for_media_security(Some(Duration::from_secs(3)))
            .await
            .expect("caller installs SRTP contexts");
        let audio = handle.audio().await.unwrap();
        let (sender, mut receiver) = audio.split();

        let mut phase = 0.0;
        for frame_index in 0..24 {
            sender
                .send(AudioFrame::new(
                    tone_frame(997.0, &mut phase),
                    8_000,
                    1,
                    (frame_index * FRAME_SAMPLES) as u32,
                ))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        handle.send_dtmf('7').await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let store = state.store.lock().await;
                let ready = store.attempts.get(&correlation).is_some_and(|attempt| {
                    attempt.browser_marker_observed && attempt.dtmf_verified
                });
                drop(store);
                if ready {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("fixture observes audio marker and RFC4733");

        start_return_audio_probe(&state, &correlation)
            .await
            .expect("start return probe");
        let mut returned = Vec::new();
        tokio::time::timeout(Duration::from_secs(4), async {
            while returned.len() < 4_000 {
                let frame = receiver.recv().await.expect("return audio channel open");
                returned.extend(frame.samples);
            }
        })
        .await
        .expect("caller receives return audio");
        assert!(tone_power(&returned, 8_000, 880.0) > 0.002);

        handle
            .hangup_and_wait(Some(Duration::from_secs(3)))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let store = state.store.lock().await;
                let ended = store
                    .attempts
                    .get(&correlation)
                    .is_some_and(|attempt| attempt.bye_from_vapi_observed && attempt.ended);
                drop(store);
                if ended {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("fixture observes remote BYE");
        cleanup_attempt(&state, &correlation).await.unwrap();
        caller.shutdown().await.unwrap();
        stop.shutdown();
        peer_task.await.unwrap().unwrap();
    }

    fn json_request(path: &str, token: &str, value: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&value).unwrap()))
            .unwrap()
    }
}
