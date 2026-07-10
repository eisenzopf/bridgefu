//! Generic SIP/RTP ↔ WebRTC/RTP runtime built from rvoip's first-party
//! server and adapter implementations.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rvoip_core::adapter::ConnectionAdapter;
use rvoip_core::commands::InboundAction;
use rvoip_core::config::Config as CoreConfig;
use rvoip_core::connection::Transport;
use rvoip_core::conversation::ConversationPolicy;
use rvoip_core::events::Event;
use rvoip_core::ids::{ConnectionId, ParticipantId, TenantId};
use rvoip_core::session::SessionMedium;
use rvoip_core::Orchestrator;
use rvoip_sip::{Config as SipConfig, SipAdapter, UnifiedCoordinator};
use rvoip_webrtc::signaling::auth::{AnonymousAuth, BearerStaticTokenAuth};
use rvoip_webrtc::{WebRtcConfig, WebRtcServer, WebRtcServerBuilder};
use tokio::sync::Mutex;
use tokio::task::AbortHandle;

use crate::config::{GenericBridgeCfg, RuntimeCfg};

pub struct GenericBridgeRuntime {
    orchestrator: Arc<Orchestrator>,
    _sip: Arc<UnifiedCoordinator>,
    webrtc: Mutex<Option<WebRtcServer>>,
    event_task: AbortHandle,
    pub sip_addr: SocketAddr,
    pub ws_addr: SocketAddr,
    pub whip_addr: SocketAddr,
}

impl GenericBridgeRuntime {
    pub async fn start(config: &GenericBridgeCfg, runtime: &RuntimeCfg) -> Result<Arc<Self>> {
        let sip_addr: SocketAddr = config.sip_bind.parse().context("generic_bridge.sip_bind")?;
        let coordinator = UnifiedCoordinator::new(SipConfig::on(
            "bridgefu-generic",
            sip_addr.ip(),
            sip_addr.port(),
        ))
        .await
        .context("starting generic SIP coordinator")?;
        let sip_adapter = SipAdapter::new(Arc::clone(&coordinator))
            .await
            .context("starting generic SIP adapter")?;

        let mut rtc_config = WebRtcConfig::default();
        rtc_config.trickle_ice = true;
        let mut builder = WebRtcServerBuilder::new(rtc_config)
            .with_ws(config.webrtc_ws_bind.clone())
            .with_whip(config.webrtc_whip_bind.clone());
        if let Some(secret) = &config.bearer_token {
            let token = secret.resolve()?;
            let auth = Arc::new(BearerStaticTokenAuth::new(token));
            builder = builder.with_ws_auth(auth.clone()).with_whip_auth(auth);
        } else {
            let auth = Arc::new(AnonymousAuth);
            builder = builder.with_ws_auth(auth.clone()).with_whip_auth(auth);
        }
        let webrtc = builder
            .build()
            .await
            .context("starting generic WebRTC server")?;
        let ws_addr = webrtc.ws_addr().context("WebRTC WS listener missing")?;
        let whip_addr = webrtc.whip_addr().context("WebRTC WHIP listener missing")?;

        let orchestrator = Orchestrator::new(CoreConfig::default());
        orchestrator.register(sip_adapter as Arc<dyn ConnectionAdapter>)?;
        orchestrator.register(webrtc.adapter() as Arc<dyn ConnectionAdapter>)?;

        let task_orchestrator = Arc::clone(&orchestrator);
        let setup_timeout = Duration::from_secs(runtime.setup_timeout_secs);
        let event_task = tokio::spawn(async move {
            run_pairing_loop(task_orchestrator, setup_timeout).await;
        });

        tracing::info!(%sip_addr, %ws_addr, %whip_addr, "generic SIP/WebRTC bridge runtime started");
        Ok(Arc::new(Self {
            orchestrator,
            _sip: coordinator,
            webrtc: Mutex::new(Some(webrtc)),
            event_task: event_task.abort_handle(),
            sip_addr,
            ws_addr,
            whip_addr,
        }))
    }

    pub fn orchestrator(&self) -> Arc<Orchestrator> {
        Arc::clone(&self.orchestrator)
    }

    pub async fn shutdown(&self, deadline: Duration) {
        self.event_task.abort();
        if let Some(server) = self.webrtc.lock().await.take() {
            server.shutdown_with_deadline(deadline).await;
        }
    }
}

async fn run_pairing_loop(orchestrator: Arc<Orchestrator>, setup_timeout: Duration) {
    let mut events = orchestrator.subscribe_events();
    let mut waiting: HashMap<Transport, VecDeque<(ConnectionId, Instant)>> = HashMap::new();
    loop {
        let event = match events.recv().await {
            Ok(event) => event,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                tracing::warn!(skipped, "generic bridge event receiver lagged");
                continue;
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
        };
        let Event::ConnectionInbound { connection_id, .. } = event else {
            continue;
        };
        let Ok(transport) = orchestrator.connection_transport(&connection_id) else {
            continue;
        };
        if !matches!(transport, Transport::Sip | Transport::WebRtc) {
            continue;
        }
        let queue = waiting.entry(transport).or_default();
        queue.retain(|(_, admitted)| admitted.elapsed() < setup_timeout);
        queue.push_back((connection_id, Instant::now()));

        let sip = waiting
            .get_mut(&Transport::Sip)
            .and_then(VecDeque::pop_front);
        let webrtc = waiting
            .get_mut(&Transport::WebRtc)
            .and_then(VecDeque::pop_front);
        match (sip, webrtc) {
            (Some((sip, _)), Some((webrtc, _))) => {
                let bridge_orchestrator = Arc::clone(&orchestrator);
                tokio::spawn(async move {
                    if let Err(error) = accept_and_bridge(bridge_orchestrator, sip, webrtc).await {
                        metrics::counter!("bridgefu_generic_bridge_total", "result" => "error")
                            .increment(1);
                        tracing::warn!(%error, "generic SIP/WebRTC bridge failed");
                    } else {
                        metrics::counter!("bridgefu_generic_bridge_total", "result" => "ok")
                            .increment(1);
                    }
                });
            }
            (Some(sip), None) => waiting.entry(Transport::Sip).or_default().push_front(sip),
            (None, Some(webrtc)) => waiting
                .entry(Transport::WebRtc)
                .or_default()
                .push_front(webrtc),
            (None, None) => {}
        }
    }
}

async fn accept_and_bridge(
    orchestrator: Arc<Orchestrator>,
    sip: ConnectionId,
    webrtc: ConnectionId,
) -> Result<()> {
    let conversation = orchestrator
        .open_conversation(
            TenantId::new(),
            ConversationPolicy::default(),
            HashMap::new(),
        )
        .await?;
    let session = orchestrator
        .start_session(conversation, SessionMedium::Voice, vec![])
        .await?;
    orchestrator
        .route_inbound_connection(
            sip.clone(),
            InboundAction::Accept {
                session_id: session.clone(),
                participant_id: ParticipantId::new(),
            },
        )
        .await?;
    orchestrator
        .route_inbound_connection(
            webrtc.clone(),
            InboundAction::Accept {
                session_id: session,
                participant_id: ParticipantId::new(),
            },
        )
        .await?;
    let bridge = orchestrator
        .bridge_connections(sip.clone(), webrtc.clone())
        .await?;
    tracing::info!(%bridge, sip = %sip, webrtc = %webrtc, "generic SIP ↔ WebRTC bridge established");
    Ok(())
}
