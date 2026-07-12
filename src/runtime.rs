//! Generic SIP/RTP ↔ WebRTC/RTP runtime built from rvoip's first-party
//! server and adapter implementations.
//!
//! The durable call execution supervisor is installed before public signaling
//! sockets or adapters. It owns both the admission boundary and the
//! authoritative operational stream; the lossy compatibility broadcast is
//! never used for authorization or call-state correctness.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bridgefu::call_service::{CallExecutionSupervisor, CallServiceRuntime};
use rvoip_auth_core::BearerValidator;
use rvoip_core::adapter::ConnectionAdapter;
use rvoip_core::config::Config as CoreConfig;
use rvoip_core::Orchestrator;
use rvoip_sip::{
    Config as SipConfig, SipAdapter, SipAuthService, SipListenerAuthPolicy, UnifiedCoordinator,
};
use rvoip_webrtc::signaling::auth::AuthCoreHook;
use rvoip_webrtc::{WebRtcConfig, WebRtcServer, WebRtcServerBuilder};
use tokio::sync::Mutex;

use crate::config::{GenericBridgeCfg, RuntimeCfg};

const WEBSOCKET_ATTACHMENT_PREFIX: &str = "bridgefu.attach.";
const SIP_BEARER_SCOPE: &str = "sip:connect";

pub struct GenericBridgeRuntime {
    orchestrator: Arc<Orchestrator>,
    sip: Arc<UnifiedCoordinator>,
    webrtc: Mutex<Option<WebRtcServer>>,
    execution: Mutex<Option<CallExecutionSupervisor>>,
    pub sip_addr: SocketAddr,
    pub ws_addr: SocketAddr,
    pub whip_addr: SocketAddr,
}

impl GenericBridgeRuntime {
    pub async fn start(
        config: &GenericBridgeCfg,
        runtime: &RuntimeCfg,
        call_runtime: Arc<CallServiceRuntime>,
        bearer_validator: Arc<dyn BearerValidator>,
    ) -> Result<Arc<Self>> {
        let sip_addr: SocketAddr = config.sip_bind.parse().context("generic_bridge.sip_bind")?;
        let setup_timeout = Duration::from_secs(runtime.setup_timeout_secs);
        let admission_capacity = runtime
            .max_concurrent_calls
            .checked_mul(2)
            .ok_or_else(|| anyhow!("generic bridge admission capacity overflow"))?;

        let orchestrator = Orchestrator::new(CoreConfig::default());
        // This install must remain before coordinator/server construction and
        // before adapter registration. It makes ownership visible before an
        // admission can produce an immediate lifecycle event.
        let execution = CallExecutionSupervisor::install(
            Arc::clone(&orchestrator),
            call_runtime,
            admission_capacity,
            setup_timeout,
        )
        .await
        .context("installing generic call execution supervisor")?;

        // The configured generic SIP listener is UDP today, so accepting a
        // Bearer header over cleartext is an explicit deployment choice. The
        // credential is validated by the same first-party validator as HTTP
        // and WebRTC.
        let sip_auth = SipAuthService::new()
            .with_bearer_validator("bridgefu", Arc::clone(&bearer_validator))
            .with_bearer_scope(SIP_BEARER_SCOPE)
            .with_required_bearer_scope(SIP_BEARER_SCOPE)
            .allow_bearer_over_cleartext(true);
        let coordinator = UnifiedCoordinator::new_with_listener_auth(
            SipConfig::on("bridgefu-generic", sip_addr.ip(), sip_addr.port()),
            SipListenerAuthPolicy::authenticated(sip_auth),
        )
        .await
        .context("starting authenticated generic SIP coordinator")?;
        let sip_adapter = SipAdapter::new(Arc::clone(&coordinator))
            .await
            .context("starting generic SIP adapter")?;

        let mut rtc_config = WebRtcConfig::default();
        rtc_config.trickle_ice = true;
        let webrtc_auth = Arc::new(
            AuthCoreHook::new(bearer_validator)
                .try_with_session_hint_subprotocol_prefix(WEBSOCKET_ATTACHMENT_PREFIX)
                .context("configuring WebRTC attachment subprotocol")?,
        );
        let webrtc = WebRtcServerBuilder::new(rtc_config)
            .with_ws(config.webrtc_ws_bind.clone())
            .with_whip(config.webrtc_whip_bind.clone())
            .with_ws_auth(webrtc_auth.clone())
            .with_whip_auth(webrtc_auth)
            .with_inbound_admission_confirmation(setup_timeout)
            .build()
            .await
            .context("starting authenticated generic WebRTC server")?;
        let ws_addr = webrtc.ws_addr().context("WebRTC WS listener missing")?;
        let whip_addr = webrtc.whip_addr().context("WebRTC WHIP listener missing")?;

        orchestrator.register(sip_adapter as Arc<dyn ConnectionAdapter>)?;
        orchestrator.register(webrtc.adapter() as Arc<dyn ConnectionAdapter>)?;

        tracing::info!(
            %sip_addr,
            %ws_addr,
            %whip_addr,
            admission_capacity,
            "authenticated generic SIP/WebRTC call execution runtime started"
        );
        Ok(Arc::new(Self {
            orchestrator,
            sip: coordinator,
            webrtc: Mutex::new(Some(webrtc)),
            execution: Mutex::new(Some(execution)),
            sip_addr,
            ws_addr,
            whip_addr,
        }))
    }

    pub async fn shutdown(&self, deadline: Duration) {
        let deadline_at = tokio::time::Instant::now() + deadline;
        // Stop policy admission first but keep the operational consumer alive
        // while listeners and their live routes emit terminal events.
        if let Some(supervisor) = self.execution.lock().await.as_ref() {
            supervisor.begin_drain();
        }
        let webrtc = self.webrtc.lock().await.take();
        let listener_budget = shutdown_budget(deadline_at);
        if tokio::time::timeout(listener_budget, async {
            let webrtc_shutdown = async {
                if let Some(server) = webrtc {
                    server.shutdown_with_deadline(listener_budget).await;
                }
            };
            let sip_shutdown = async {
                if let Err(error) = self.sip.shutdown_gracefully(Some(listener_budget)).await {
                    tracing::warn!(%error, "generic SIP coordinator did not drain cleanly");
                }
            };
            tokio::join!(webrtc_shutdown, sip_shutdown);
        })
        .await
        .is_err()
        {
            tracing::warn!("public signaling listeners exceeded the shutdown deadline");
        }
        // Keep the correctness receiver alive through listener teardown, then
        // stop its actors before aborting rvoip normalization tasks. Reversing
        // these two waits can deadlock shutdown when an actor is blocked on a
        // durable store while a lifecycle task is backpressured on that
        // actor's full operational mailbox.
        if let Some(supervisor) = self.execution.lock().await.take() {
            supervisor.shutdown(shutdown_budget(deadline_at)).await;
        }
        if tokio::time::timeout(
            shutdown_budget(deadline_at),
            self.orchestrator.drain_prepared_outbound_connections(),
        )
        .await
        .is_err()
        {
            tracing::warn!("prepared outbound drain exceeded the shutdown deadline");
        }
        if tokio::time::timeout(
            shutdown_budget(deadline_at),
            self.orchestrator.drain_connection_lifecycle_tasks(),
        )
        .await
        .is_err()
        {
            tracing::warn!("rvoip lifecycle drain exceeded the shutdown deadline");
        }
    }
}

fn shutdown_budget(deadline: tokio::time::Instant) -> Duration {
    deadline.saturating_duration_since(tokio::time::Instant::now())
}
