//! Local real-protocol demonstrations; see examples/native-sip-webrtc/README.md.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridgefu::api_principal::ApiPrincipal;
use bridgefu::call_engine::{
    CallId, CallState, LegDirection, MediaFlow, SignalingInitiator, TenantId, WorkerId,
};
use bridgefu::call_service::{
    build_call_service_runtime, CallExecutionSupervisor, CallRepositoryBackendConfig,
    CallServiceCoordinationConfig, CallServiceRuntime, CallServiceRuntimeConfig, CallTimeoutPolicy,
    ConfiguredSipOutboundProfile, ConfiguredWebRtcOutboundProfile, CreateCallInput,
    DisabledProviderLegExecutor, IdempotencyKey, LegEndpointConfig, NamedProfileBinding,
    NamedProfileKind, NamedProfileRole, NamedRouteBinding, RequestedLeg,
    SamePrincipalAttachmentResolver, SipEndpointConfig, SipInitialContextMode,
    StaticOutboundProfileResolver, SystemCallServiceClock, WebRtcEndpointConfig,
};
use bridgefu::context::ContextPolicy;
use bridgefu::coordination::DeploymentId;
use bridgefu::secret_ref::SecretRef;
use chrono::Utc;
use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod};
use rvoip_core::adapter::{
    AdapterEvent, AdapterKind, AdapterLifecycleCapabilities, AdapterLifecycleSink,
    ConnectionAdapter, ConnectionHandle, EndReason, InboundConnectionContext,
    OrchestratorAdapterEvent, OriginateContext, OriginateRequest, OutboundActivation, RejectReason,
    SignatureHeaders, TransferTarget,
};
use rvoip_core::capability::{CapabilityDescriptor, NegotiatedCodecs};
use rvoip_core::config::Config as CoreConfig;
use rvoip_core::connection::{Direction, Transport};
use rvoip_core::ids::{ConnectionId, ParticipantId, SessionId};
use rvoip_core::message::Message;
use rvoip_core::stream::{MediaFrame, MediaStream, StreamKind};
use rvoip_core::{
    DataMessage, Event, IdentityAssurance, Jwk, Orchestrator, Result as RvoipResult, RvoipError,
};
use rvoip_sip::{Event as SipEvent, MediaSecurityProfile, SipAdapter, SipListenerAuthPolicy};
use rvoip_webrtc::signaling::auth::{AuthContext, AuthRejection, WsAuthHook};
use rvoip_webrtc::signaling::websocket::serve_tls_listener_with_auth_and_shutdown;
use rvoip_webrtc::tls::TlsConfig;
use rvoip_webrtc::{
    StaticWebRtcBearerCredentialProvider, WebRtcAdapter, WebRtcBearerCredential, WebRtcConfig,
    WebRtcOriginateContext, WebRtcServerBuilder, WebRtcTargetPolicy, WebRtcTlsClientTrust,
};
use tokio::sync::mpsc;

async fn bounded<T>(label: &'static str, future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(20), future)
        .await
        .unwrap_or_else(|_| panic!("{label} deadline"))
}

#[derive(Clone, Debug)]
struct ObservedOutboundContext {
    bearer_present: bool,
    tls_trust_present: bool,
    ice_urls: Vec<String>,
}

/// Delegates every operation to the real adapter, changing only the frozen
/// target policy for this loopback test. No production config or global state
/// can select this wrapper.
struct LoopbackFixtureWebRtcAdapter {
    inner: Arc<WebRtcAdapter>,
    observed: Mutex<Vec<ObservedOutboundContext>>,
}

impl LoopbackFixtureWebRtcAdapter {
    fn new(inner: Arc<WebRtcAdapter>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            observed: Mutex::new(Vec::new()),
        })
    }

    fn last_observed(&self) -> ObservedOutboundContext {
        self.observed
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("outbound WSS context reached the adapter boundary")
    }
}

#[async_trait::async_trait]
impl ConnectionAdapter for LoopbackFixtureWebRtcAdapter {
    fn transport(&self) -> Transport {
        self.inner.transport()
    }

    fn kind(&self) -> AdapterKind {
        self.inner.kind()
    }

    fn lifecycle_capabilities(&self) -> AdapterLifecycleCapabilities {
        self.inner.lifecycle_capabilities()
    }

    fn supports_inbound_admission_confirmation(&self) -> bool {
        self.inner.supports_inbound_admission_confirmation()
    }

    fn notify_inbound_admission_outcome(
        &self,
        connection_id: &ConnectionId,
        lifecycle_generation: u64,
        accepted: bool,
    ) {
        self.inner
            .notify_inbound_admission_outcome(connection_id, lifecycle_generation, accepted);
    }

    fn install_lifecycle_sink(&self, sink: Arc<dyn AdapterLifecycleSink>) -> RvoipResult<()> {
        self.inner.install_lifecycle_sink(sink)
    }

    fn is_connection_live(&self, connection_id: &ConnectionId) -> bool {
        self.inner.is_connection_live(connection_id)
    }

    fn take_inbound_context(
        &self,
        connection_id: &ConnectionId,
    ) -> Option<InboundConnectionContext> {
        self.inner.take_inbound_context(connection_id)
    }

    fn subscribe_orchestrator_events(&self) -> mpsc::Receiver<OrchestratorAdapterEvent> {
        self.inner.subscribe_orchestrator_events()
    }

    async fn originate(&self, mut request: OriginateRequest) -> RvoipResult<ConnectionHandle> {
        let context = request
            .context
            .downcast_arc::<WebRtcOriginateContext>()
            .ok_or(RvoipError::AdmissionRejected(
                "fixture expected a typed WebRTC context",
            ))?;
        let diagnostic = format!("{context:?}");
        self.observed.lock().unwrap().push(ObservedOutboundContext {
            bearer_present: diagnostic.contains("bearer_provider_present: true"),
            tls_trust_present: diagnostic.contains("tls_trust_present: true"),
            ice_urls: context
                .ice_servers_override()
                .unwrap_or_default()
                .iter()
                .flat_map(|server| server.urls.iter().cloned())
                .collect(),
        });
        let policy = context.target_policy().clone().allow_loopback(true);
        let context = context
            .as_ref()
            .clone()
            .with_target_policy(policy)
            .map_err(|_| RvoipError::AdmissionRejected("invalid fixture target policy"))?;
        request.context = OriginateContext::new(context);
        self.inner.originate(request).await
    }

    async fn activate_outbound(&self, connection_id: ConnectionId) -> RvoipResult<()> {
        self.inner.activate_outbound(connection_id).await
    }

    async fn activate_outbound_with_receipt(
        &self,
        connection_id: ConnectionId,
    ) -> RvoipResult<OutboundActivation> {
        self.inner
            .activate_outbound_with_receipt(connection_id)
            .await
    }

    async fn accept(&self, connection_id: ConnectionId) -> RvoipResult<()> {
        self.inner.accept(connection_id).await
    }

    async fn reject(&self, connection_id: ConnectionId, reason: RejectReason) -> RvoipResult<()> {
        self.inner.reject(connection_id, reason).await
    }

    async fn end(&self, connection_id: ConnectionId, reason: EndReason) -> RvoipResult<()> {
        self.inner.end(connection_id, reason).await
    }

    async fn hold(&self, connection_id: ConnectionId) -> RvoipResult<()> {
        self.inner.hold(connection_id).await
    }

    async fn resume(&self, connection_id: ConnectionId) -> RvoipResult<()> {
        self.inner.resume(connection_id).await
    }

    async fn transfer(
        &self,
        connection_id: ConnectionId,
        target: TransferTarget,
    ) -> RvoipResult<()> {
        self.inner.transfer(connection_id, target).await
    }

    async fn streams(&self, connection_id: ConnectionId) -> RvoipResult<Vec<Arc<dyn MediaStream>>> {
        self.inner.streams(connection_id).await
    }

    async fn send_message(&self, connection_id: ConnectionId, message: Message) -> RvoipResult<()> {
        self.inner.send_message(connection_id, message).await
    }

    async fn send_data_message(
        &self,
        connection_id: ConnectionId,
        message: DataMessage,
    ) -> RvoipResult<()> {
        self.inner.send_data_message(connection_id, message).await
    }

    async fn send_dtmf(
        &self,
        connection_id: ConnectionId,
        digits: &str,
        duration_ms: u32,
    ) -> RvoipResult<()> {
        self.inner
            .send_dtmf(connection_id, digits, duration_ms)
            .await
    }

    async fn renegotiate_media(
        &self,
        connection_id: ConnectionId,
        capabilities: CapabilityDescriptor,
    ) -> RvoipResult<NegotiatedCodecs> {
        self.inner
            .renegotiate_media(connection_id, capabilities)
            .await
    }

    fn subscribe_events(&self) -> mpsc::Receiver<AdapterEvent> {
        self.inner.subscribe_events()
    }

    fn capabilities(&self) -> CapabilityDescriptor {
        self.inner.capabilities()
    }

    async fn verify_request_signature(
        &self,
        connection_id: ConnectionId,
        signature: SignatureHeaders,
    ) -> RvoipResult<IdentityAssurance> {
        self.inner
            .verify_request_signature(connection_id, signature)
            .await
    }
}

async fn next_inbound(events: &mut mpsc::Receiver<AdapterEvent>) -> Option<ConnectionId> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await {
                Some(AdapterEvent::InboundConnection { connection }) => return connection.id,
                Some(_) => {}
                None => panic!("destination event stream closed"),
            }
        }
    })
    .await
    .ok()
}

async fn wait_for_orchestrator_idle(orchestrator: &Orchestrator) {
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
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("orchestrator retained a connection, bridge, or admission permit");
}

async fn audio_stream(
    adapter: &dyn ConnectionAdapter,
    connection_id: &ConnectionId,
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
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Opus stream deadline")
}

async fn send_encoded(
    stream: &Arc<dyn MediaStream>,
    payload: bytes::Bytes,
    payload_type: u8,
    timestamp: u32,
    timestamp_step: u32,
) {
    for offset in 0..8 {
        bounded(
            "encoded media frame send",
            stream.frames_out().send(MediaFrame {
                stream_id: stream.id(),
                kind: StreamKind::Audio,
                payload: payload.clone(),
                timestamp_rtp: timestamp + offset * timestamp_step,
                captured_at: Utc::now(),
                payload_type: Some(payload_type),
            }),
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

use anyhow::{bail, ensure, Context, Result};
use bridgefu::recipes::{RecipeCatalog, RecipeEndpointSpec};
use clap::Parser;
use rvoip_media_core::codec::audio::{AudioCodec, G711Codec, OpusCodec, OpusConfig};
use rvoip_media_core::types::{AudioFrame as DecodedAudioFrame, SampleRate};
use serde::{Deserialize, Serialize};

#[path = "../tests/support/sip_fixture.rs"]
mod sip_fixture;
use sip_fixture::{reserve_tcp, reserve_udp, tls_sip_config, TestTlsFiles};

#[derive(Parser)]
struct Args {
    /// Editable demo settings. All sockets are intentionally local and temporary.
    #[arg(long)]
    settings: std::path::PathBuf,
    /// Optional sanitized assertion report; no endpoints, IDs, or credentials.
    #[arg(long)]
    report: Option<std::path::PathBuf>,
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum DirectionChoice {
    SipToWebrtc,
    WebrtcToSip,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum SipCodec {
    Pcmu,
    Pcma,
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Hangup {
    Source,
    Destination,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    direction: DirectionChoice,
    recipe_directory: std::path::PathBuf,
    tenant: String,
    route_id: String,
    sip_user: String,
    sip_codec: SipCodec,
    hangup: Hangup,
}

impl Settings {
    fn owner(&self) -> ApiPrincipal {
        ApiPrincipal::new(
            AuthenticatedPrincipal {
                subject: self.sip_user.clone(),
                tenant: Some(self.tenant.clone()),
                scopes: vec![
                    "*".into(),
                    bridgefu::api_principal::CallScope::ArbitraryDestination
                        .as_str()
                        .into(),
                ],
                issuer: Some("local-native-example".into()),
                expires_at: None,
                method: AuthenticationMethod::MutualTls,
                assurance: IdentityAssurance::Pseudonymous {
                    ephemeral_key: Jwk(serde_json::json!({"kty":"test"})),
                },
            },
            Utc::now(),
        )
        .unwrap()
    }
    fn payload_type(&self) -> u8 {
        match self.sip_codec {
            SipCodec::Pcmu => 0,
            SipCodec::Pcma => 8,
        }
    }
    fn g711(&self) -> G711Codec {
        match self.sip_codec {
            SipCodec::Pcmu => G711Codec::mu_law(8_000, 1).unwrap(),
            SipCodec::Pcma => G711Codec::a_law(8_000, 1).unwrap(),
        }
    }
}

struct WebAuth {
    owner: AuthenticatedPrincipal,
    destination_token: Option<String>,
}
#[async_trait::async_trait]
impl WsAuthHook for WebAuth {
    async fn authenticate(
        &self,
        protocols: &[String],
        _: Option<&str>,
        _: std::net::SocketAddr,
    ) -> Result<AuthContext, AuthRejection> {
        let token = protocols
            .iter()
            .find_map(|p| p.strip_prefix("token."))
            .filter(|t| !t.is_empty() && t.len() <= 512)
            .ok_or_else(|| AuthRejection::Unauthorized {
                www_authenticate: "Bearer".into(),
            })?;
        if self
            .destination_token
            .as_ref()
            .is_some_and(|expected| expected != token)
        {
            return Err(AuthRejection::Unauthorized {
                www_authenticate: "Bearer".into(),
            });
        }
        Ok(AuthContext {
            subject: self.owner.subject.clone(),
            scopes: vec!["webrtc:connect".into(), "webrtc:answer".into()],
            session_hint: self.destination_token.is_none().then(|| token.to_owned()),
            principal: Some(self.owner.clone()),
        })
    }
}

async fn wait_state(runtime: &CallServiceRuntime, tenant: &str, id: CallId, terminal: bool) {
    bounded("call state", async {
        loop {
            let call = runtime
                .service_repository()
                .load_service_call(&TenantId::parse(tenant).unwrap(), id)
                .await
                .unwrap();
            if (terminal && call.call.aggregate.state().is_terminal())
                || (!terminal && call.call.aggregate.state() == CallState::Active)
            {
                break;
            }
            assert!(
                terminal || !call.call.aggregate.state().is_terminal(),
                "call ended before becoming active"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
}

fn samples(rate: u32, frequency: f64) -> Vec<i16> {
    (0..rate / 50)
        .map(|n| {
            (9000.0
                * (2.0 * std::f64::consts::PI * frequency * f64::from(n) / f64::from(rate)).sin())
                as i16
        })
        .collect()
}

fn tone_ratio(samples: &[i16], rate: f64, frequency: f64) -> f64 {
    let (mut real, mut imag, mut energy) = (0.0, 0.0, 0.0);
    for (i, &sample) in samples.iter().enumerate() {
        let angle = 2.0 * std::f64::consts::PI * frequency * i as f64 / rate;
        real += f64::from(sample) * angle.cos();
        imag += f64::from(sample) * angle.sin();
        energy += f64::from(sample).powi(2);
    }
    2.0 * (real * real + imag * imag) / (samples.len() as f64 * energy.max(1.0))
}

async fn media_check(
    settings: &Settings,
    sip: &Arc<dyn MediaStream>,
    web: &Arc<dyn MediaStream>,
) -> (usize, usize) {
    let mut sip_in = sip.try_frames_in().unwrap();
    let mut web_in = web.try_frames_in().unwrap();
    let mut g711 = settings.g711();
    let encoded = g711
        .encode(&DecodedAudioFrame::new(samples(8000, 1000.0), 8000, 1, 0))
        .unwrap();
    send_encoded(sip, encoded.into(), settings.payload_type(), 1600, 160).await;
    let received_web = bounded("SIP tone at WebRTC", async {
        let mut decoder = OpusCodec::new(SampleRate::Rate48000, 1, OpusConfig::default()).unwrap();
        let mut count = 0;
        loop {
            let frame = web_in.recv().await.unwrap();
            count += 1;
            let pcm = decoder.decode(&frame.payload).unwrap();
            if tone_ratio(&pcm.samples, 48000.0, 1000.0) > 0.45 {
                return count;
            }
        }
    })
    .await;
    let mut encoder = OpusCodec::new(SampleRate::Rate48000, 1, OpusConfig::default()).unwrap();
    let encoded = encoder
        .encode(&DecodedAudioFrame::new(samples(48000, 500.0), 48000, 1, 0))
        .unwrap();
    send_encoded(web, encoded.into(), 111, 48000, 960).await;
    let received_sip = bounded("WebRTC tone at SIP", async {
        let mut decoder = settings.g711();
        let mut count = 0;
        loop {
            let frame = sip_in.recv().await.unwrap();
            count += 1;
            let pcm = decoder.decode(&frame.payload).unwrap();
            if tone_ratio(&pcm.samples, 8000.0, 500.0) > 0.45 {
                return count;
            }
        }
    })
    .await;
    (received_sip, received_web)
}

async fn demo(settings: &Settings) -> Result<serde_json::Value> {
    let sip_to_web = settings.direction == DirectionChoice::SipToWebrtc;
    let owner = settings.owner();
    let tls_files = TestTlsFiles::create();
    let cert = std::fs::read(&tls_files.cert)?;
    let key = std::fs::read(&tls_files.key)?;
    let web_tls = TlsConfig::from_pem_bytes(&cert, &key).await?;
    let web_trust = Arc::new(WebRtcTlsClientTrust::from_pem(&cert)?);
    let destination_token = uuid::Uuid::new_v4().to_string();
    let bridge_tls = reserve_tcp();
    let peer_tls = reserve_tcp();
    let bridge_policy = SipListenerAuthPolicy::enabled_for_tenant(&settings.tenant)?
        .with_trusted_cidr("127.0.0.1/32".parse()?, owner.authenticated().clone());
    let bridge_sip = rvoip_sip::UnifiedCoordinator::new_with_listener_auth(
        tls_sip_config(
            "bridgefu",
            reserve_udp(),
            bridge_tls,
            &tls_files,
            vec![settings.payload_type(), 101],
        ),
        bridge_policy,
    )
    .await?;
    let bridge_sip_adapter = SipAdapter::new(Arc::clone(&bridge_sip)).await?;
    let peer_policy = SipListenerAuthPolicy::enabled_for_tenant(&settings.tenant)?
        .with_trusted_cidr("127.0.0.1/32".parse()?, owner.authenticated().clone());
    let sip_peer = rvoip_sip::UnifiedCoordinator::new_with_listener_auth(
        tls_sip_config(
            &settings.sip_user,
            reserve_udp(),
            peer_tls,
            &tls_files,
            vec![settings.payload_type(), 101],
        ),
        peer_policy,
    )
    .await?;
    let sip_peer_adapter = SipAdapter::new(Arc::clone(&sip_peer)).await?;
    let mut sip_peer_events = sip_peer_adapter.subscribe_events();
    let mut sip_security_events = sip_peer.events().await?;
    let mut web_config = WebRtcConfig::loopback();
    web_config.trickle_ice = true;
    let web_peer_server = WebRtcServerBuilder::new(web_config.clone())
        .with_wss("127.0.0.1:0", web_tls.clone())
        .with_ws_auth(Arc::new(WebAuth {
            owner: owner.authenticated().clone(),
            destination_token: Some(destination_token.clone()),
        }))
        .build()
        .await?;
    let web_peer_adapter = web_peer_server.adapter();
    let mut web_peer_events = web_peer_adapter.subscribe_events();
    let web_peer_uri = format!(
        "wss://localhost:{}/signal",
        web_peer_server.wss_addr().unwrap().port()
    );
    let bridge_web = WebRtcAdapter::new_with_inbound_admission_confirmation(
        web_config,
        Duration::from_secs(20),
    )?;
    let loopback_web = LoopbackFixtureWebRtcAdapter::new(Arc::clone(&bridge_web));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let bridge_web_uri = format!("wss://localhost:{}/signal", listener.local_addr()?.port());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let web_listener = {
        let adapter = Arc::clone(&bridge_web);
        let auth: Arc<dyn WsAuthHook> = Arc::new(WebAuth {
            owner: owner.authenticated().clone(),
            destination_token: None,
        });
        tokio::spawn(async move {
            serve_tls_listener_with_auth_and_shutdown(listener, web_tls, adapter, auth, async {
                let _ = stopped.await;
            })
            .await
        })
    };
    let recipe_name = if sip_to_web {
        "example-sip-to-webrtc"
    } else {
        "example-webrtc-to-sip"
    };
    let mut values = BTreeMap::new();
    values.insert("sip_security".into(), serde_yaml::Value::from("sips_srtp"));
    values.insert(
        "webrtc_signaling_uri".into(),
        serde_yaml::Value::from(if sip_to_web {
            web_peer_uri.clone()
        } else {
            bridge_web_uri.clone()
        }),
    );
    if sip_to_web {
        values.insert(
            "sip_signaling_cidrs".into(),
            serde_yaml::to_value(["127.0.0.1/32"])?,
        );
    } else {
        values.insert(
            "sip_target_uri".into(),
            serde_yaml::Value::from(format!(
                "sips:{}@localhost:{};transport=tls",
                settings.sip_user,
                peer_tls.port()
            )),
        );
        values.insert(
            "sip_from_uri".into(),
            serde_yaml::Value::from(format!(
                "sips:{}@localhost:{};transport=tls",
                settings.sip_user,
                bridge_tls.port()
            )),
        );
    }
    let compiled =
        RecipeCatalog::with_external_paths(std::slice::from_ref(&settings.recipe_directory))?
            .resolve(&format!("external:{recipe_name}@1"))?
            .compile(&values)?;
    let bridge = compiled
        .spec
        .bridges
        .values()
        .next()
        .context("recipe has no bridge")?;
    let destination = match &bridge.destination {
        RecipeEndpointSpec::Webrtc {
            signaling_uri: Some(uri),
            ..
        } => LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
            signaling_uri: Some(uri.clone()),
        }),
        RecipeEndpointSpec::Sip {
            target_uri: Some(uri),
            ..
        } => LegEndpointConfig::Sip(SipEndpointConfig {
            uri: Some(uri.clone()),
            initial_context: SipInitialContextMode::None,
        }),
        _ => bail!("unsupported demonstration destination"),
    };
    let source = if sip_to_web {
        LegEndpointConfig::Sip(SipEndpointConfig {
            uri: None,
            initial_context: SipInitialContextMode::None,
        })
    } else {
        LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
            signaling_uri: None,
        })
    };
    let runtime = Arc::new(
        build_call_service_runtime(
            CallServiceRuntimeConfig {
                backend: CallRepositoryBackendConfig::Memory,
                worker_id: WorkerId::new(),
                max_calls: 1,
                worker_capabilities: BTreeSet::from([
                    "sip".into(),
                    "sip_egress".into(),
                    "webrtc".into(),
                    "webrtc_egress".into(),
                ]),
                control_key: uuid::Uuid::new_v4().simple().to_string().into_bytes(),
                timeouts: CallTimeoutPolicy {
                    setup: Duration::from_secs(20),
                    media_idle: Duration::from_secs(30),
                    transfer: Duration::from_secs(20),
                    ending: Duration::from_secs(10),
                },
                coordination: CallServiceCoordinationConfig::new(DeploymentId::parse(
                    "native-example",
                )?),
            },
            Arc::new(SamePrincipalAttachmentResolver),
            Arc::new(SystemCallServiceClock),
        )
        .await?,
    );
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let mut profiles = StaticOutboundProfileResolver::default();
    let kind = if sip_to_web {
        profiles.insert_webrtc(
            settings.route_id.clone(),
            compiled.fingerprint.clone(),
            ConfiguredWebRtcOutboundProfile {
                bearer_token: Some(SecretRef::new(&destination_token)),
                tls_roots: vec![tls_files.cert.to_string_lossy().into_owned()],
                ice_servers: vec![],
                audio_codecs: vec![rvoip_webrtc::WebRtcAudioCodec::Opus],
                data_channels: true,
            },
        );
        NamedProfileKind::WebRtc
    } else {
        let RecipeEndpointSpec::Sip {
            from_uri: Some(from),
            ..
        } = &bridge.destination
        else {
            bail!("missing From URI")
        };
        profiles.insert_sip(
            settings.route_id.clone(),
            compiled.fingerprint.clone(),
            ConfiguredSipOutboundProfile {
                from_uri: from.clone(),
                outbound_proxy: None,
                auth: None,
            },
        );
        NamedProfileKind::Sip
    };
    let supervisor = CallExecutionSupervisor::install_with_leg_executors_context_canary_broadcast_and_outbound_profiles(
        Arc::clone(&orchestrator), Arc::clone(&runtime), Arc::new(DisabledProviderLegExecutor), None,
        Arc::new(ContextPolicy::default()), None, None, Arc::new(profiles), 1, Duration::from_secs(20)).await?;
    orchestrator.register(Arc::clone(&bridge_sip_adapter) as Arc<dyn ConnectionAdapter>)?;
    orchestrator.register(Arc::clone(&loopback_web) as Arc<dyn ConnectionAdapter>)?;
    println!("1/4 Starting encrypted local endpoints and compiling {recipe_name}.");
    let created = runtime
        .service()
        .create_named_route_call(
            &owner,
            &IdempotencyKey::parse(uuid::Uuid::new_v4().to_string())?,
            CreateCallInput {
                tenant_id: None,
                legs: [
                    RequestedLeg {
                        direction: LegDirection::Inbound,
                        signaling_initiator: Some(SignalingInitiator::Remote),
                        media_flow: MediaFlow::SendReceive,
                        endpoint: source,
                        amazon_connect_start: None,
                    },
                    RequestedLeg {
                        direction: LegDirection::Outbound,
                        signaling_initiator: Some(SignalingInitiator::Bridgefu),
                        media_flow: MediaFlow::SendReceive,
                        endpoint: destination,
                        amazon_connect_start: None,
                    },
                ],
            },
            NamedRouteBinding::new_with_profiles(
                &settings.route_id,
                None,
                vec![NamedProfileBinding::new(
                    NamedProfileRole::Destination,
                    kind,
                    &settings.route_id,
                    &compiled.fingerprint,
                )?],
            )?,
        )
        .await?;
    let call = &created.value.call;
    let token = call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Inbound)
        .unwrap()
        .attachment
        .as_ref()
        .unwrap()
        .token
        .clone();
    let source_adapter: Arc<dyn ConnectionAdapter> = if sip_to_web {
        Arc::clone(&sip_peer_adapter) as _
    } else {
        Arc::clone(&web_peer_adapter) as _
    };
    let destination_adapter: Arc<dyn ConnectionAdapter> = if sip_to_web {
        Arc::clone(&web_peer_adapter) as _
    } else {
        Arc::clone(&sip_peer_adapter) as _
    };
    let (target, transport, context) = if sip_to_web {
        (
            format!("sips:{token}@localhost:{};transport=tls", bridge_tls.port()),
            Transport::Sip,
            OriginateContext::new(rvoip_sip::SipOriginateContext::new().with_from_uri(format!(
                "sips:{}@localhost;transport=tls",
                settings.sip_user
            ))?),
        )
    } else {
        let policy = WebRtcTargetPolicy::default()
            .allow_loopback(true)
            .allow_port(url::Url::parse(&bridge_web_uri)?.port().unwrap());
        let context = WebRtcOriginateContext::websocket(&bridge_web_uri, policy)?
            .with_tls_trust(web_trust)
            .with_bearer_provider(Arc::new(StaticWebRtcBearerCredentialProvider::new(
                WebRtcBearerCredential::new(token)?,
            )));
        (
            bridge_web_uri,
            Transport::WebRtc,
            OriginateContext::new(context),
        )
    };
    let mut request = OriginateRequest::new(
        SessionId::new(),
        ParticipantId::new(),
        target,
        Direction::Outbound,
        source_adapter.capabilities(),
    )
    .with_transport(transport);
    request.context = context;
    let source_connection = source_adapter
        .originate(request)
        .await
        .context("source originate")?
        .connection
        .id;
    let activation = {
        let adapter = Arc::clone(&source_adapter);
        let id = source_connection.clone();
        tokio::spawn(async move { adapter.activate_outbound(id).await })
    };
    let events = if sip_to_web {
        &mut web_peer_events
    } else {
        &mut sip_peer_events
    };
    let destination_connection = next_inbound(events)
        .await
        .context("destination did not receive the call")?;
    destination_adapter
        .accept(destination_connection.clone())
        .await?;
    bounded("source activation", activation).await??;
    wait_state(&runtime, &settings.tenant, call.call_id, false).await;
    let sip_connection = if sip_to_web {
        &source_connection
    } else {
        &destination_connection
    };
    let web_connection = if sip_to_web {
        &destination_connection
    } else {
        &source_connection
    };
    let sip_session = bounded("SIP session", async {
        loop {
            match sip_security_events.next().await {
                Some(SipEvent::IncomingCall { call_id, .. })
                | Some(SipEvent::CallEstablished { call_id, .. }) => {
                    break sip_peer.session(&call_id)
                }
                Some(_) => {}
                None => panic!("SIP events closed"),
            }
        }
    })
    .await;
    let security = sip_session
        .wait_for_media_security(Some(Duration::from_secs(10)))
        .await?;
    ensure!(
        security.contexts_installed && security.profile == MediaSecurityProfile::RtpSavp,
        "SIP did not negotiate SRTP"
    );
    println!("2/4 Call active: SIPS/SRTP and WSS/DTLS-SRTP established.");
    let sip_stream = audio_stream(sip_peer_adapter.as_ref(), sip_connection).await;
    let web_stream = audio_stream(web_peer_adapter.as_ref(), web_connection).await;
    let (sip_frames, web_frames) = media_check(settings, &sip_stream, &web_stream).await;
    println!(
        "3/4 Verified distinct audio tones in both directions, including G.711/Opus transcoding."
    );
    let hangup_source = settings.hangup == Hangup::Source;
    let (ending_adapter, ending_id) = if hangup_source {
        (&source_adapter, &source_connection)
    } else {
        (&destination_adapter, &destination_connection)
    };
    ending_adapter
        .end(ending_id.clone(), EndReason::Normal)
        .await?;
    wait_state(&runtime, &settings.tenant, call.call_id, true).await;
    wait_for_orchestrator_idle(&orchestrator).await;
    bounded("peer cleanup", async {
        while source_adapter.is_connection_live(&source_connection)
            || destination_adapter.is_connection_live(&destination_connection)
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if sip_to_web {
        let observed = loopback_web.last_observed();
        ensure!(
            observed.bearer_present && observed.tls_trust_present && observed.ice_urls.is_empty(),
            "destination profile was not applied"
        );
    }
    let _ = stop.send(());
    bounded("WSS listener shutdown", web_listener).await??;
    bounded("WebRTC peer shutdown", web_peer_server.shutdown()).await;
    supervisor.shutdown(Duration::from_secs(5)).await;
    orchestrator.drain_prepared_outbound_connections().await;
    orchestrator.drain_connection_lifecycle_tasks().await;
    sip_peer_adapter.drain().await?;
    bridge_sip_adapter.drain().await?;
    sip_peer
        .shutdown_gracefully(Some(Duration::from_secs(5)))
        .await?;
    bridge_sip
        .shutdown_gracefully(Some(Duration::from_secs(5)))
        .await?;
    ensure!(
        sip_peer_adapter.retained_task_count() == 0
            && bridge_sip_adapter.retained_task_count() == 0,
        "SIP tasks were retained"
    );
    drop(orchestrator);
    Arc::try_unwrap(runtime)
        .map_err(|_| anyhow::anyhow!("runtime ownership was retained"))?
        .shutdown(Duration::from_secs(5))
        .await?;
    println!("4/4 Hangup propagated; no calls, bridges, admission permits, or peer connections remain. PASS");
    Ok(
        serde_json::json!({"schema_version":1, "bridgefu_version":env!("CARGO_PKG_VERSION"), "direction":settings.direction, "sip_codec":settings.sip_codec, "hangup":settings.hangup, "passed":true, "sip_srtp_verified":true, "web_rtc_peer":"rvoip automated peer", "sip_to_webrtc_tone_verified":true, "webrtc_to_sip_tone_verified":true, "sip_frames_observed":sip_frames, "webrtc_frames_observed":web_frames, "cleanup_verified":true, "scope":"local production call runtime and real protocol adapters; example-only loopback target permission; not the HTTP API, browser UI, public NAT/TURN, or carrier qualification"}),
    )
}

fn main() -> Result<()> {
    let args = Args::parse();
    let settings: Settings = serde_json::from_slice(&std::fs::read(&args.settings)?)?;
    TenantId::parse(&settings.tenant)?;
    ensure!(
        !settings.sip_user.is_empty()
            && settings
                .sip_user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "sip_user must contain only letters, digits, or hyphens"
    );
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .with_writer(std::io::stderr)
        .try_init();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    let result = runtime
        .block_on(async { tokio::time::timeout(Duration::from_secs(90), demo(&settings)).await });
    // A bounded runtime shutdown also closes every socket after an error or panic.
    runtime.shutdown_timeout(Duration::from_secs(5));
    let report = result.context("demo exceeded its 90-second deadline")??;
    if let Some(path) = args.report {
        std::fs::write(path, serde_json::to_vec_pretty(&report)?)?;
    }
    Ok(())
}
