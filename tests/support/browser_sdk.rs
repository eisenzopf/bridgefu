//! Reusable actual-Chromium controller for destination qualification tests.
//!
//! The controller deliberately owns only the browser edge: it serves the
//! built TypeScript SDK, launches BridgeFu's pinned Playwright Chromium, and
//! exposes explicit phase barriers. Destination simulators stay
//! in their existing qualification modules so this helper cannot accidentally
//! replace production-shaped Amazon, Telnyx, SIP, or WSS behavior.

// This support module is compiled independently into several destination-
// specific integration-test binaries. Each binary intentionally exercises
// only its own capability variants and helpers.
#![allow(dead_code)]

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
use serde::Serialize;
use serde_json::{json, Value};

static SDK_BUILD: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedBrowserMessage {
    pub label: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserDestinationBoundary {
    AmazonConnectTestSeam,
    TelnyxMockAccountSeam,
    AuthenticatedGenericWss,
}

impl BrowserDestinationBoundary {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AmazonConnectTestSeam => "amazon-connect-test-seam",
            Self::TelnyxMockAccountSeam => "telnyx-mock-account-seam",
            Self::AuthenticatedGenericWss => "authenticated-generic-wss",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserContextSemantics {
    InitialOnly,
    NoLiveDataChannel,
    LiveDataChannel,
}

impl BrowserContextSemantics {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InitialOnly => "initial-only",
            Self::NoLiveDataChannel => "no-live-data-channel",
            Self::LiveDataChannel => "live-data-channel",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserTerminalSide {
    Browser,
    Destination,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserDtmfSemantics {
    SourceToDestination,
    BidirectionalMediaPlane,
}

impl BrowserDtmfSemantics {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SourceToDestination => "source-to-destination",
            Self::BidirectionalMediaPlane => "bidirectional-media-plane",
        }
    }
}

impl BrowserTerminalSide {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::Destination => "destination",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserScenario {
    pub name: String,
    pub destination_boundary: BrowserDestinationBoundary,
    pub context_semantics: BrowserContextSemantics,
    pub dtmf_semantics: BrowserDtmfSemantics,
    pub terminal_side: BrowserTerminalSide,
    pub initial_correlation_id: String,
    pub initial_metadata: std::collections::BTreeMap<String, String>,
    pub assistant_context_correlation_id: String,
    pub final_context_correlation_id: String,
    pub assistant_dtmf_digits: String,
    pub destination_dtmf_digits: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_remote_context_correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_remote_message: Option<ExpectedBrowserMessage>,
}

impl BrowserScenario {
    pub fn handoff(
        name: impl Into<String>,
        correlation_id: impl Into<String>,
        destination_boundary: BrowserDestinationBoundary,
        context_semantics: BrowserContextSemantics,
        dtmf_semantics: BrowserDtmfSemantics,
    ) -> Self {
        Self {
            name: name.into(),
            destination_boundary,
            context_semantics,
            dtmf_semantics,
            terminal_side: BrowserTerminalSide::Browser,
            initial_correlation_id: correlation_id.into(),
            initial_metadata: std::collections::BTreeMap::from([
                ("account_tier".into(), "chromium".into()),
                ("must_not_forward".into(), "private-browser-value".into()),
            ]),
            assistant_context_correlation_id: "chromium-browser-later-context".into(),
            final_context_correlation_id: "chromium-browser-final-context".into(),
            assistant_dtmf_digits: "6".into(),
            destination_dtmf_digits: "5".into(),
            expected_remote_context_correlation_id: None,
            expected_remote_message: None,
        }
    }

    pub fn with_terminal_side(mut self, terminal_side: BrowserTerminalSide) -> Self {
        self.terminal_side = terminal_side;
        self
    }

    pub fn with_remote_context(mut self, correlation_id: impl Into<String>) -> Self {
        self.expected_remote_context_correlation_id = Some(correlation_id.into());
        self
    }

    pub fn with_remote_message(mut self, message: ExpectedBrowserMessage) -> Self {
        self.expected_remote_message = Some(message);
        self
    }
}

pub fn attachment_fixture(
    signaling_uri: impl Into<String>,
    token: impl Into<String>,
    expires_at: impl Into<String>,
    tenant_id: impl Into<String>,
    call_id: impl Into<String>,
    leg_id: impl Into<String>,
    scenario: BrowserScenario,
) -> Value {
    let token = token.into();
    let expires_at = expires_at.into();
    json!({
        "route_attachment": {
            "type": "webrtc",
            "signaling_uri": signaling_uri.into(),
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
            "tenantId": tenant_id.into(),
            "callId": call_id.into(),
            "legId": leg_id.into(),
        },
        "scenario": scenario,
        "qualification": {
            "liveProviderQualified": false,
            "turnQualified": false,
            "browserPublicTlsQualified": false,
        },
    })
}

// The destination-specific qualification tests intentionally pass every expected boundary
// independently so this shared assertion cannot silently apply destination defaults.
#[allow(clippy::too_many_arguments)]
pub fn assert_common_handoff_result(
    result: &Value,
    call_id: &str,
    replacement_leg_id: &str,
    rejected_generation: u64,
    successful_generation: u64,
    terminal_side: BrowserTerminalSide,
    destination_boundary: BrowserDestinationBoundary,
    context_semantics: BrowserContextSemantics,
    dtmf_semantics: BrowserDtmfSemantics,
) {
    assert_eq!(result["connected"], true);
    assert_eq!(result["finalState"], "closed");
    assert_eq!(result["terminalSide"], terminal_side.as_str());
    assert_eq!(
        result["terminalReason"],
        match terminal_side {
            BrowserTerminalSide::Browser => "browser-disconnect",
            BrowserTerminalSide::Destination => "remote-bye",
        }
    );
    assert_eq!(result["localAudioTrackState"], "ended");
    assert_eq!(result["finalPeerConnectionState"], "closed");
    assert_eq!(result["finalManagedContextChannelState"], "closed");
    assert_eq!(result["finalArbitraryChannelState"], "closed");
    assert!(result["finalServerConnectionId"].is_null());
    assert_eq!(result["expiredAttachmentErrorCode"], "invalid-attachment");
    assert_eq!(result["forgedAttachmentRejected"], true);
    assert_eq!(result["forgedAttachmentErrorCode"], "signaling-failed");
    assert_eq!(result["replayRejected"], true);
    assert_eq!(result["replayErrorCode"], "signaling-failed");
    assert_eq!(
        result["dtmfSupported"], true,
        "{}",
        result["dtmfDiagnostics"]
    );
    assert_eq!(result["peerStable"], true);
    assert_eq!(result["serverConnectionStable"], true);
    assert_eq!(
        result["qualification"]["destinationBoundary"],
        destination_boundary.as_str()
    );
    assert_eq!(
        result["qualification"]["contextSemantics"],
        context_semantics.as_str()
    );
    assert_eq!(
        result["qualification"]["dtmfSemantics"],
        dtmf_semantics.as_str()
    );
    assert_eq!(
        result["qualification"]["remoteDtmfObserved"],
        dtmf_semantics == BrowserDtmfSemantics::BidirectionalMediaPlane
    );
    assert_eq!(result["qualification"]["liveProviderQualified"], false);
    assert_eq!(result["qualification"]["turnQualified"], false);
    assert_eq!(result["qualification"]["browserPublicTlsQualified"], false);
    assert_eq!(result["qualification"]["configuredIceServerCount"], 0);
    assert_eq!(result["qualification"]["turnConfigured"], false);
    assert_eq!(result["qualification"]["relayCandidateSelected"], false);
    assert!(result["qualification"]["localCandidateType"]
        .as_str()
        .is_some_and(|candidate_type| candidate_type != "relay"));
    assert!(result["qualification"]["remoteCandidateType"]
        .as_str()
        .is_some_and(|candidate_type| candidate_type != "relay"));
    assert_eq!(result["rejectedHoldByteDelta"], 0);
    assert_eq!(result["successfulHoldByteDelta"], 0);
    assert!(result["outboundAudioBytes"].as_u64().unwrap_or_default() > 0);
    assert!(
        result["initialInboundAudioBytes"]
            .as_u64()
            .unwrap_or_default()
            > 0
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
    assert_eq!(result["ringbackStarts"], 3);
    assert_eq!(
        result["ringbackStops"],
        json!(["connected", "resumed", "connected"])
    );

    let messages = result["handoffMessages"]
        .as_array()
        .expect("SDK returned authenticated handoff messages");
    assert_eq!(
        messages
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
    for (index, message) in messages.iter().enumerate() {
        assert_eq!(message["call_id"], call_id);
        assert_eq!(message["replacement_leg_id"], replacement_leg_id);
        assert_eq!(
            message["binding_generation"],
            if index < 4 {
                rejected_generation
            } else {
                successful_generation
            }
        );
        assert_eq!(message["peerConnectionState"], "connected");
        assert_eq!(
            message["serverConnectionId"],
            result["connectedServerConnectionId"]
        );
    }
}

#[derive(Clone)]
struct BrowserHttpState {
    fixture: Arc<Value>,
    initial_destination_ready: Arc<AtomicBool>,
    destination_verified: Arc<AtomicBool>,
    diagnostics: Arc<Mutex<Option<Value>>>,
    phases: Arc<Mutex<Vec<Value>>>,
    sdk_dist: Arc<PathBuf>,
}

async fn index() -> Html<&'static str> {
    Html(include_str!(
        "../../sdk/typescript/test/browser-qualification.html"
    ))
}

async fn attachment(State(state): State<BrowserHttpState>) -> Json<Value> {
    Json((*state.fixture).clone())
}

async fn destination_ready(State(state): State<BrowserHttpState>) -> Json<Value> {
    Json(json!({
        "ready": state.initial_destination_ready.load(Ordering::Acquire),
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
    match tokio::fs::read(state.sdk_dist.join(file)).await {
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

fn find_playwright(sdk: &Path) {
    assert!(
        sdk.join("node_modules/playwright").is_dir(),
        "Playwright is absent; run npm ci and npm run browser:install in sdk/typescript"
    );
}

pub struct BrowserSdkController {
    initial_destination_ready: Arc<AtomicBool>,
    destination_verified: Arc<AtomicBool>,
    diagnostics: Arc<Mutex<Option<Value>>>,
    phases: Arc<Mutex<Vec<Value>>>,
    http_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    http_server: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    browser_output: Option<tokio::task::JoinHandle<Result<std::process::Output, std::io::Error>>>,
}

impl BrowserSdkController {
    pub async fn launch(fixture: Value) -> Self {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let sdk = repository.join("sdk/typescript");
        find_playwright(&sdk);

        SDK_BUILD
            .get_or_init(|| async {
                let build = tokio::process::Command::new("npm")
                    .args(["run", "build"])
                    .current_dir(&sdk)
                    .output()
                    .await
                    .expect("execute the browser SDK build");
                assert!(
                    build.status.success(),
                    "SDK build failed:\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&build.stdout),
                    String::from_utf8_lossy(&build.stderr),
                );
            })
            .await;

        let initial_destination_ready = Arc::new(AtomicBool::new(false));
        let destination_verified_flag = Arc::new(AtomicBool::new(false));
        let diagnostics = Arc::new(Mutex::new(None));
        let phases = Arc::new(Mutex::new(Vec::new()));
        let state = BrowserHttpState {
            fixture: Arc::new(fixture),
            initial_destination_ready: Arc::clone(&initial_destination_ready),
            destination_verified: Arc::clone(&destination_verified_flag),
            diagnostics: Arc::clone(&diagnostics),
            phases: Arc::clone(&phases),
            sdk_dist: Arc::new(sdk.join("dist")),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (http_shutdown, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let http_server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/", get(index))
                    .route("/attachment", get(attachment))
                    .route("/destination-ready", get(destination_ready))
                    .route("/destination-verified", get(destination_verified))
                    .route("/browser-diagnostics", post(browser_diagnostics))
                    .route("/browser-phase", post(browser_phase))
                    .route("/sdk/:file", get(sdk_file))
                    .with_state(state),
            )
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
        });

        let mut browser = tokio::process::Command::new("node");
        browser
            .arg(sdk.join("test/browser-qualification-driver.mjs"))
            .env(
                "BRIDGEFU_BROWSER_QUALIFICATION_URL",
                format!("http://localhost:{}/", address.port()),
            )
            .env("PLAYWRIGHT_BROWSERS_PATH", "0")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let child = browser.spawn().expect("launch pinned Playwright Chromium");
        let browser_output = tokio::spawn(child.wait_with_output());

        Self {
            initial_destination_ready,
            destination_verified: destination_verified_flag,
            diagnostics,
            phases,
            http_shutdown: Some(http_shutdown),
            http_server: Some(http_server),
            browser_output: Some(browser_output),
        }
    }

    pub fn mark_initial_destination_ready(&self) {
        self.initial_destination_ready
            .store(true, Ordering::Release);
    }

    pub fn mark_destination_verified(&self) {
        self.destination_verified.store(true, Ordering::Release);
    }

    pub fn diagnostics(&self) -> Option<Value> {
        self.diagnostics
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn phases(&self) -> Vec<Value> {
        self.phases
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub async fn wait_for_phase(&self, expected: &str) -> Value {
        tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                if let Some(observation) = self
                    .phases
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
        .unwrap_or_else(|_| {
            panic!(
                "Chromium did not report {expected}; diagnostics={:?}",
                self.diagnostics()
            )
        })
    }

    pub async fn complete(mut self) -> Value {
        let output =
            tokio::time::timeout(Duration::from_secs(35), self.browser_output.take().unwrap())
                .await
                .expect("Chromium driver deadline")
                .expect("Chromium wait task")
                .expect("Chromium process wait");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "Chromium qualification failed:\nstdout:\n{stdout}\nstderr:\n{stderr}\ndiagnostics={:?}",
            self.diagnostics()
        );
        let result_line = stdout
            .lines()
            .find_map(|line| line.strip_prefix("BRIDGEFU_BROWSER_RESULT="))
            .expect("Chromium driver omitted its result marker");
        let result = serde_json::from_str(result_line).unwrap();

        let _ = self.http_shutdown.take().unwrap().send(());
        self.http_server
            .take()
            .unwrap()
            .await
            .expect("browser HTTP server task")
            .expect("browser HTTP server");
        result
    }
}

impl Drop for BrowserSdkController {
    fn drop(&mut self) {
        if let Some(shutdown) = self.http_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(server) = self.http_server.take() {
            server.abort();
        }
        if let Some(browser) = self.browser_output.take() {
            browser.abort();
        }
    }
}
