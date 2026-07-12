//! Generic SIP/RTP ↔ WebRTC/RTP runtime built from rvoip's first-party
//! server and adapter implementations.
//!
//! Inbound signaling is admitted through rvoip's bounded single-consumer
//! security boundary.  Bridgefu consumes one owner-bound routing hint,
//! transactionally binds the exact connection to its durable leg, and only
//! then allows the protocol adapter to report success.  The public rvoip
//! broadcast is deliberately not used for authorization or pairing.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rvoip_auth_core::BearerValidator;
use rvoip_core::adapter::{ConnectionAdapter, EndReason, RejectReason};
use rvoip_core::commands::InboundAction;
use rvoip_core::config::Config as CoreConfig;
use rvoip_core::connection::Transport;
use rvoip_core::conversation::ConversationPolicy;
use rvoip_core::ids::{ConnectionId, ParticipantId, TenantId};
use rvoip_core::session::SessionMedium;
use rvoip_core::{InboundAdmission, Orchestrator};
use rvoip_sip::{
    Config as SipConfig, SipAdapter, SipAuthService, SipListenerAuthPolicy, UnifiedCoordinator,
};
use rvoip_webrtc::signaling::auth::AuthCoreHook;
use rvoip_webrtc::{WebRtcConfig, WebRtcServer, WebRtcServerBuilder};
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::{JoinHandle, JoinSet};

use bridgefu::call_engine::{AttachmentTransport, CallId, LegId};
use bridgefu::call_service::{
    CallServiceRuntime, InboundAttachmentError, InboundAttachmentRequest, InboundAttachmentResult,
};

use crate::config::{GenericBridgeCfg, RuntimeCfg};

const WEBSOCKET_ATTACHMENT_PREFIX: &str = "bridgefu.attach.";
const SIP_BEARER_SCOPE: &str = "sip:connect";

pub struct GenericBridgeRuntime {
    _orchestrator: Arc<Orchestrator>,
    sip: Arc<UnifiedCoordinator>,
    webrtc: Mutex<Option<WebRtcServer>>,
    admission: Mutex<Option<AdmissionSupervisor>>,
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
        let admission_rx = orchestrator
            .install_inbound_admission_gate(admission_capacity, setup_timeout)
            .context("installing generic bridge admission gate")?;

        // The configured generic SIP listener is UDP today, so accepting a
        // Bearer header over cleartext is an explicit deployment choice.  The
        // credential is still validated by the exact same first-party
        // validator used by the HTTP API and WebRTC listeners.
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
            .build()
            .await
            .context("starting authenticated generic WebRTC server")?;
        let ws_addr = webrtc.ws_addr().context("WebRTC WS listener missing")?;
        let whip_addr = webrtc.whip_addr().context("WebRTC WHIP listener missing")?;

        orchestrator.register(sip_adapter as Arc<dyn ConnectionAdapter>)?;
        orchestrator.register(webrtc.adapter() as Arc<dyn ConnectionAdapter>)?;

        let admission = AdmissionSupervisor::start(
            admission_rx,
            Arc::clone(&orchestrator),
            call_runtime,
            setup_timeout,
        );

        tracing::info!(
            %sip_addr,
            %ws_addr,
            %whip_addr,
            admission_capacity,
            "authenticated generic SIP/WebRTC bridge runtime started"
        );
        Ok(Arc::new(Self {
            _orchestrator: orchestrator,
            sip: coordinator,
            webrtc: Mutex::new(Some(webrtc)),
            admission: Mutex::new(Some(admission)),
            sip_addr,
            ws_addr,
            whip_addr,
        }))
    }

    pub async fn shutdown(&self, deadline: Duration) {
        if let Some(supervisor) = self.admission.lock().await.take() {
            supervisor.shutdown(deadline).await;
        }
        if let Some(server) = self.webrtc.lock().await.take() {
            server.shutdown_with_deadline(deadline).await;
        }
        if let Err(error) = self.sip.shutdown_gracefully(Some(deadline)).await {
            tracing::warn!(%error, "generic SIP coordinator did not drain cleanly");
        }
    }
}

struct AdmissionSupervisor {
    cancel: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl AdmissionSupervisor {
    fn start(
        receiver: mpsc::Receiver<InboundAdmission>,
        orchestrator: Arc<Orchestrator>,
        call_runtime: Arc<CallServiceRuntime>,
        setup_timeout: Duration,
    ) -> Self {
        let (cancel, cancel_rx) = watch::channel(false);
        let task = tokio::spawn(run_admission_supervisor(
            receiver,
            orchestrator,
            call_runtime,
            setup_timeout,
            cancel_rx,
        ));
        Self { cancel, task }
    }

    async fn shutdown(self, deadline: Duration) {
        let _ = self.cancel.send(true);
        let mut task = self.task;
        if tokio::time::timeout(deadline, &mut task).await.is_err() {
            tracing::warn!("generic admission supervisor did not drain; aborting task");
            task.abort();
            let _ = task.await;
        }
    }
}

#[derive(Default)]
struct PendingAttachments {
    calls: HashMap<CallId, PendingCall>,
}

struct PendingCall {
    expected_legs: [LegId; 2],
    connections: HashMap<LegId, ConnectionId>,
}

impl PendingAttachments {
    fn insert(
        &mut self,
        call_id: CallId,
        expected_legs: [LegId; 2],
        leg_id: LegId,
        connection_id: ConnectionId,
    ) -> Result<Option<[ConnectionId; 2]>> {
        if !expected_legs.contains(&leg_id) || expected_legs[0] == expected_legs[1] {
            return Err(anyhow!("durable attachment result has inconsistent legs"));
        }
        let call = self.calls.entry(call_id).or_insert_with(|| PendingCall {
            expected_legs,
            connections: HashMap::with_capacity(2),
        });
        if call.expected_legs != expected_legs {
            return Err(anyhow!("durable attachment result changed call legs"));
        }
        match call.connections.get(&leg_id) {
            Some(existing) if existing == &connection_id => return Ok(None),
            Some(_) => return Err(anyhow!("durable leg already has an admitted connection")),
            None => {
                call.connections.insert(leg_id, connection_id);
            }
        }
        let Some(first) = call.connections.get(&expected_legs[0]).cloned() else {
            return Ok(None);
        };
        let Some(second) = call.connections.get(&expected_legs[1]).cloned() else {
            return Ok(None);
        };
        self.calls.remove(&call_id);
        Ok(Some([first, second]))
    }
}

async fn run_admission_supervisor(
    mut receiver: mpsc::Receiver<InboundAdmission>,
    orchestrator: Arc<Orchestrator>,
    call_runtime: Arc<CallServiceRuntime>,
    setup_timeout: Duration,
    mut cancel: watch::Receiver<bool>,
) {
    let pending = Arc::new(Mutex::new(PendingAttachments::default()));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    receiver.close();
                    break;
                }
            }
            completed = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::warn!(%error, "generic admission task panicked");
                }
            }
            admission = receiver.recv() => {
                let Some(admission) = admission else { break; };
                tasks.spawn(handle_inbound_admission(
                    admission,
                    Arc::clone(&orchestrator),
                    Arc::clone(&call_runtime),
                    Arc::clone(&pending),
                    setup_timeout,
                ));
            }
        }
    }

    // Dropping an unresolved admission is itself a fail-closed rejection.
    while let Ok(admission) = receiver.try_recv() {
        drop(admission);
    }
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            tracing::warn!(%error, "generic admission task panicked while draining");
        }
    }
}

async fn handle_inbound_admission(
    mut admission: InboundAdmission,
    orchestrator: Arc<Orchestrator>,
    call_runtime: Arc<CallServiceRuntime>,
    pending: Arc<Mutex<PendingAttachments>>,
    setup_timeout: Duration,
) {
    let connection_id = admission.connection_id().clone();
    let transport = admission.transport();
    let principal = match admission.authenticated_principal() {
        Ok(principal) => principal,
        Err(_) => {
            reject_admission(admission, RejectReason::Forbidden).await;
            return;
        }
    };
    let mut context = match admission.take_inbound_context() {
        Ok(Some(context)) if context.is_bound_to(&connection_id, transport, &principal) => context,
        _ => {
            reject_admission(admission, RejectReason::Forbidden).await;
            return;
        }
    };
    let routing_token = context.take_routing_hint().map(|hint| hint.into_secret());
    let attachment_transport = match transport {
        Transport::Sip => AttachmentTransport::Sip,
        Transport::WebRtc => AttachmentTransport::WebRtc,
        _ => {
            reject_admission(admission, RejectReason::NotAcceptable).await;
            return;
        }
    };

    let request = InboundAttachmentRequest::new(
        principal,
        routing_token,
        attachment_transport,
        call_runtime.worker().lease,
        connection_id.clone(),
    );
    let consumed = match tokio::time::timeout(
        setup_timeout,
        call_runtime.service().consume_inbound_attachment(request),
    )
    .await
    {
        Ok(Ok(consumed)) => consumed,
        Ok(Err(InboundAttachmentError::ProofRejected)) => {
            metrics::counter!("bridgefu_attachment_admission_total", "result" => "rejected")
                .increment(1);
            reject_admission(admission, RejectReason::Forbidden).await;
            return;
        }
        Ok(Err(InboundAttachmentError::Unavailable)) | Err(_) => {
            metrics::counter!("bridgefu_attachment_admission_total", "result" => "unavailable")
                .increment(1);
            reject_admission(admission, RejectReason::ServerError).await;
            return;
        }
    };

    if admission.accept().await.is_err() {
        metrics::counter!("bridgefu_attachment_admission_total", "result" => "ended").increment(1);
        return;
    }
    metrics::counter!("bridgefu_attachment_admission_total", "result" => "accepted").increment(1);

    let admission_connection = connection_id.clone();
    let pair = match register_consumed_attachment(&pending, consumed, connection_id).await {
        Ok(pair) => pair,
        Err(error) => {
            tracing::error!(%error, "durable attachment registry rejected an admitted binding");
            let _ = orchestrator
                .end_connection(
                    admission_connection,
                    EndReason::Failed {
                        detail: "attachment registry rejected binding".into(),
                    },
                )
                .await;
            return;
        }
    };
    let Some([first, second]) = pair else {
        return;
    };
    if let Err(error) =
        accept_and_bridge(Arc::clone(&orchestrator), first.clone(), second.clone()).await
    {
        metrics::counter!("bridgefu_generic_bridge_total", "result" => "error").increment(1);
        tracing::warn!(%error, "durably paired SIP/WebRTC bridge failed");
        let reason = EndReason::Failed {
            detail: "bridge setup failed".into(),
        };
        let _ = orchestrator.end_connection(first, reason.clone()).await;
        let _ = orchestrator.end_connection(second, reason).await;
    } else {
        metrics::counter!("bridgefu_generic_bridge_total", "result" => "ok").increment(1);
    }
}

async fn reject_admission(admission: InboundAdmission, reason: RejectReason) {
    let _ = admission.reject(reason).await;
}

async fn register_consumed_attachment(
    pending: &Mutex<PendingAttachments>,
    consumed: InboundAttachmentResult,
    connection_id: ConnectionId,
) -> Result<Option<[ConnectionId; 2]>> {
    let aggregate = &consumed.commit.call.aggregate;
    let expected_legs = [aggregate.legs()[0].id(), aggregate.legs()[1].id()];
    if consumed.binding.connection_id != connection_id
        || aggregate.leg(consumed.binding.leg_id).is_none()
    {
        return Err(anyhow!(
            "durable attachment binding does not match admission"
        ));
    }
    pending.lock().await.insert(
        aggregate.id(),
        expected_legs,
        consumed.binding.leg_id,
        connection_id,
    )
}

async fn accept_and_bridge(
    orchestrator: Arc<Orchestrator>,
    first: ConnectionId,
    second: ConnectionId,
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
            first.clone(),
            InboundAction::Accept {
                session_id: session.clone(),
                participant_id: ParticipantId::new(),
            },
        )
        .await?;
    orchestrator
        .route_inbound_connection(
            second.clone(),
            InboundAction::Accept {
                session_id: session,
                participant_id: ParticipantId::new(),
            },
        )
        .await?;
    let bridge = orchestrator
        .bridge_connections(first.clone(), second.clone())
        .await?;
    tracing::info!(%bridge, first = %first, second = %second, "durable SIP ↔ WebRTC bridge established");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crossed_call_arrivals_never_fifo_pair() {
        let call_a = CallId::new();
        let call_b = CallId::new();
        let legs_a = [LegId::new(), LegId::new()];
        let legs_b = [LegId::new(), LegId::new()];
        let a0 = ConnectionId::new();
        let a1 = ConnectionId::new();
        let b0 = ConnectionId::new();
        let b1 = ConnectionId::new();
        let mut pending = PendingAttachments::default();

        assert_eq!(
            pending
                .insert(call_a, legs_a, legs_a[0], a0.clone())
                .unwrap(),
            None
        );
        assert_eq!(
            pending
                .insert(call_b, legs_b, legs_b[0], b0.clone())
                .unwrap(),
            None
        );
        assert_eq!(
            pending
                .insert(call_a, legs_a, legs_a[1], a1.clone())
                .unwrap(),
            Some([a0, a1])
        );
        assert_eq!(
            pending
                .insert(call_b, legs_b, legs_b[1], b1.clone())
                .unwrap(),
            Some([b0, b1])
        );
    }

    #[test]
    fn duplicate_leg_cannot_replace_admitted_winner() {
        let call = CallId::new();
        let legs = [LegId::new(), LegId::new()];
        let winner = ConnectionId::new();
        let duplicate = ConnectionId::new();
        let peer = ConnectionId::new();
        let mut pending = PendingAttachments::default();

        pending.insert(call, legs, legs[0], winner.clone()).unwrap();
        assert!(pending.insert(call, legs, legs[0], duplicate).is_err());
        assert_eq!(
            pending.insert(call, legs, legs[1], peer.clone()).unwrap(),
            Some([winner, peer])
        );
    }

    #[test]
    fn inconsistent_call_shape_fails_closed() {
        let call = CallId::new();
        let original = [LegId::new(), LegId::new()];
        let changed = [original[0], LegId::new()];
        let mut pending = PendingAttachments::default();
        pending
            .insert(call, original, original[0], ConnectionId::new())
            .unwrap();
        assert!(pending
            .insert(call, changed, changed[1], ConnectionId::new())
            .is_err());
        assert!(pending
            .insert(
                call,
                [original[0], original[0]],
                original[0],
                ConnectionId::new()
            )
            .is_err());
    }
}
