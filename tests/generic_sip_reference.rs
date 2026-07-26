//! Hermetic reference-destination acceptance for a named SIP -> SIP route.
//!
//! This is deliberately a packet-path test.  The source, Bridgefu listener,
//! and destination are three independent rvoip SIP endpoints bound to
//! loopback sockets.  It therefore proves more than the execution-supervisor
//! lifecycle doubles: INVITE/ACK/BYE, RTP, RFC 4733, and SDES-SRTP all cross
//! their real protocol implementations.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bridgefu::api_principal::ApiPrincipal;
use bridgefu::call_engine::{
    CallId, CallState, LegDirection, LegState, MediaFlow, SignalingInitiator, TenantId, WorkerId,
};
use bridgefu::call_service::{
    build_call_service_runtime, CallExecutionSupervisor, CallRepositoryBackendConfig,
    CallServiceCoordinationConfig, CallServiceRuntime, CallServiceRuntimeConfig, CallTimeoutPolicy,
    ConfiguredSipOutboundProfile, ConfiguredSipProfileAuth, CreateCallInput,
    DisabledProviderLegExecutor, IdempotencyKey, LegEndpointConfig, NamedProfileBinding,
    NamedProfileKind, NamedProfileRole, NamedRouteBinding, NamedRouteCallContext, RequestedLeg,
    SamePrincipalAttachmentResolver, SipEndpointConfig, SipInitialContextMode,
    StaticOutboundProfileResolver, SystemCallServiceClock,
};
use bridgefu::context::ContextPolicy;
use bridgefu::coordination::DeploymentId;
use bridgefu::secret_ref::SecretRef;
use chrono::Utc;
use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod};
use rvoip_core::adapter::ConnectionAdapter;
use rvoip_core::config::Config as CoreConfig;
use rvoip_core::{Event as CoreEvent, IdentityAssurance, Jwk, Orchestrator, StreamKind};
use rvoip_sip::{
    AudioFrame, AudioSource, CallHandlerDecision, CallbackPeer, Config as SipConfig,
    DigestAuthenticator, Event as SipEvent, HeaderName, MediaSecurityProfile, SessionHandle,
    SipAdapter, SipAuthService, SipHeaderView, SipInboundContextPolicy, SipListenerAuthPolicy,
};
use tokio::sync::{mpsc, Notify};

#[path = "support/sip_fixture.rs"]
mod sip_fixture;
use sip_fixture::{reserve_tcp, reserve_udp, tls_sip_config, TestTlsFiles};

const TENANT: &str = "generic-sip-reference";
const PROFILE_ID: &str = "reference-call-center";
const PROFILE_REVISION: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn assert_fixture_exists(path: &Path) {
    assert!(path.is_file(), "TLS fixture was not written");
}

fn principal() -> ApiPrincipal {
    ApiPrincipal::new(
        AuthenticatedPrincipal {
            subject: "reference-vapi".into(),
            tenant: Some(TENANT.into()),
            scopes: vec![
                "*".into(),
                bridgefu::api_principal::CallScope::ArbitraryDestination
                    .as_str()
                    .into(),
            ],
            issuer: Some("generic-sip-reference-test".into()),
            expires_at: None,
            method: AuthenticationMethod::MutualTls,
            assurance: IdentityAssurance::Pseudonymous {
                ephemeral_key: Jwk(serde_json::json!({"kty": "test"})),
            },
        },
        Utc::now(),
    )
    .expect("valid reference principal")
}

async fn runtime() -> Arc<CallServiceRuntime> {
    runtime_with_setup_timeout(Duration::from_secs(10)).await
}

async fn runtime_with_setup_timeout(setup: Duration) -> Arc<CallServiceRuntime> {
    let mut coordination = CallServiceCoordinationConfig::new(
        DeploymentId::parse("generic-sip-reference").expect("deployment ID"),
    );
    coordination.worker_lease_ttl = Duration::from_secs(300);
    coordination.worker_renew_interval = Duration::from_secs(100);
    Arc::new(
        build_call_service_runtime(
            CallServiceRuntimeConfig {
                backend: CallRepositoryBackendConfig::Memory,
                worker_id: WorkerId::new(),
                max_calls: 4,
                worker_capabilities: BTreeSet::from(["sip".into(), "sip_egress".into()]),
                control_key: vec![0x61; 32],
                timeouts: CallTimeoutPolicy {
                    setup,
                    media_idle: Duration::from_secs(30),
                    transfer: Duration::from_secs(10),
                    ending: Duration::from_secs(10),
                },
                coordination,
            },
            Arc::new(SamePrincipalAttachmentResolver),
            Arc::new(SystemCallServiceClock),
        )
        .await
        .expect("reference call runtime"),
    )
}

fn call_input(destination: SocketAddr) -> CreateCallInput {
    call_input_uri(format!("sip:agent@{destination}"))
}

fn call_input_uri(destination: String) -> CreateCallInput {
    CreateCallInput {
        tenant_id: None,
        legs: [
            RequestedLeg {
                direction: LegDirection::Inbound,
                signaling_initiator: Some(SignalingInitiator::Remote),
                media_flow: MediaFlow::SendReceive,
                endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                    uri: None,
                    initial_context: SipInitialContextMode::None,
                }),
                amazon_connect_start: None,
            },
            RequestedLeg {
                direction: LegDirection::Outbound,
                signaling_initiator: Some(SignalingInitiator::Bridgefu),
                media_flow: MediaFlow::SendReceive,
                endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                    uri: Some(destination),
                    initial_context: SipInitialContextMode::Required,
                }),
                amazon_connect_start: None,
            },
        ],
    }
}

fn route_binding() -> NamedRouteBinding {
    NamedRouteBinding::new_with_profiles(
        "generic-sip-reference",
        Some(NamedRouteCallContext {
            correlation_id: "reference-call-0001".into(),
            metadata: BTreeMap::from([
                ("account_tier".into(), "gold".into()),
                ("must_not_forward".into(), "private-value".into()),
            ]),
        }),
        vec![NamedProfileBinding::new(
            NamedProfileRole::Destination,
            NamedProfileKind::Sip,
            PROFILE_ID,
            PROFILE_REVISION,
        )
        .expect("destination profile binding")],
    )
    .expect("named SIP route")
}

async fn wait_for_call<F>(
    runtime: &CallServiceRuntime,
    call_id: CallId,
    predicate: F,
) -> bridgefu::call_service::StoredServiceCall
where
    F: Fn(&bridgefu::call_service::StoredServiceCall) -> bool,
{
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let stored = runtime
                .service_repository()
                .load_service_call(&TenantId::parse(TENANT).expect("tenant"), call_id)
                .await
                .expect("load reference call");
            if predicate(&stored) {
                return stored;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("reference call did not reach expected state")
}

fn active_bridge_count(orchestrator: &Orchestrator) -> u64 {
    match orchestrator.capacity_report() {
        CoreEvent::CapacityReport { active_bridges, .. } => active_bridges,
        _ => unreachable!("capacity_report is always a capacity event"),
    }
}

async fn wait_for_bridges(orchestrator: &Orchestrator, expected: u64) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while active_bridge_count(orchestrator) != expected {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "bridge count did not converge: expected {expected}, observed {}",
            active_bridge_count(orchestrator)
        )
    });
}

async fn wait_for_orchestrator_idle(orchestrator: &Orchestrator) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                orchestrator.capacity_report(),
                CoreEvent::CapacityReport {
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
    .expect("reference orchestrator retained connection capacity");
}

fn tone_frame(frequency_hz: f32, timestamp: u32) -> AudioFrame {
    let samples = (0..160)
        .map(|offset| {
            let sample = timestamp.wrapping_add(offset) as f32;
            let phase = sample * std::f32::consts::TAU * frequency_hz / 8_000.0;
            (phase.sin() * 12_000.0) as i16
        })
        .collect();
    AudioFrame::new(samples, 8_000, 1, timestamp)
}

async fn send_tone(sender: &rvoip_sip::AudioSender, frequency_hz: f32) {
    for sequence in 0..16_u32 {
        sender
            .send(tone_frame(frequency_hz, sequence * 160))
            .await
            .expect("send reference RTP audio");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn receive_non_silent(receiver: &mut rvoip_sip::AudioReceiver) -> AudioFrame {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let frame = receiver.recv().await.expect("reference RTP remained live");
            if frame
                .samples
                .iter()
                .any(|sample| sample.unsigned_abs() > 500)
            {
                return frame;
            }
        }
    })
    .await
    .expect("non-silent bridged RTP was not received")
}

#[derive(Debug)]
struct ObservedInvite {
    from: String,
    correlation_id: Option<String>,
    account_tier: Option<String>,
    forbidden: Option<String>,
}

#[test]
fn named_sip_route_crosses_real_srtp_transcoding_dtmf_and_bye() {
    // The debug build of the full SIP + SRTP + MediaGraph scenario carries
    // several large async state machines. Keep this test independent of the
    // caller's `RUST_MIN_STACK` while leaving production task stacks untouched.
    std::thread::Builder::new()
        .name("generic-sip-reference".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(6)
                .thread_stack_size(8 * 1024 * 1024)
                .enable_all()
                .build()
                .expect("reference Tokio runtime")
                .block_on(Box::pin(run_named_sip_route_reference()));
        })
        .expect("spawn reference scenario")
        .join()
        .expect("reference scenario panicked");
}

async fn run_named_sip_route_reference() {
    let bridge_address = reserve_udp();
    let source_address = reserve_udp();
    let destination_address = reserve_udp();
    let runtime = runtime().await;
    let orchestrator = Orchestrator::new(CoreConfig::default());

    let context_policy = ContextPolicy {
        allow_headers: BTreeMap::from([
            ("X-Correlation-Id".into(), "correlation_id".into()),
            ("X-Account-Tier".into(), "account_tier".into()),
        ]),
    };
    let mut outbound_profiles = StaticOutboundProfileResolver::default();
    outbound_profiles.insert_sip(
        PROFILE_ID.into(),
        PROFILE_REVISION.into(),
        ConfiguredSipOutboundProfile {
            from_uri: format!("sip:bridgefu-reference@{bridge_address}"),
            outbound_proxy: None,
            auth: None,
        },
    );
    let supervisor = CallExecutionSupervisor::install_with_leg_executors_context_canary_broadcast_and_outbound_profiles(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        Arc::new(DisabledProviderLegExecutor),
        None,
        Arc::new(context_policy),
        None,
        None,
        Arc::new(outbound_profiles),
        8,
        Duration::from_secs(10),
    )
    .await
    .expect("install reference execution supervisor");

    let owner = principal();
    let listener_policy = SipListenerAuthPolicy::enabled_for_tenant(TENANT)
        .expect("tenant-bound listener")
        .with_trusted_cidr(
            "127.0.0.1/32".parse().expect("loopback CIDR"),
            owner.authenticated().clone(),
        );
    let mut bridge_config = SipConfig::local("bridgefu-reference", bridge_address.port());
    bridge_config.offered_codecs = vec![0, 8, 101];
    bridge_config.offer_srtp = true;
    bridge_config.srtp_required = true;
    let bridge_coordinator =
        rvoip_sip::UnifiedCoordinator::new_with_listener_auth(bridge_config, listener_policy)
            .await
            .expect("start authenticated Bridgefu SIP listener");
    let sip_adapter = SipAdapter::new_with_inbound_context_policy(
        Arc::clone(&bridge_coordinator),
        SipInboundContextPolicy::default(),
    )
    .await
    .expect("production SIP adapter");
    orchestrator
        .register(Arc::clone(&sip_adapter) as Arc<dyn ConnectionAdapter>)
        .expect("register production SIP adapter");

    let destination_release = Arc::new(Notify::new());
    let destination_invite_seen = Arc::new(Notify::new());
    let destination_early_media_started = Arc::new(Notify::new());
    let (invite_tx, mut invite_rx) = mpsc::channel::<ObservedInvite>(1);
    let (destination_established_tx, mut destination_established_rx) =
        mpsc::channel::<SessionHandle>(1);
    let (destination_dtmf_tx, mut destination_dtmf_rx) = mpsc::channel::<char>(4);
    let (destination_ended_tx, mut destination_ended_rx) = mpsc::channel::<()>(1);
    let mut destination_config =
        SipConfig::local("reference-call-center", destination_address.port());
    destination_config.offered_codecs = vec![8, 101];
    destination_config.offer_srtp = true;
    destination_config.srtp_required = true;
    let destination_peer = CallbackPeer::builder(destination_config)
        .on_incoming({
            let destination_release = Arc::clone(&destination_release);
            let destination_invite_seen = Arc::clone(&destination_invite_seen);
            let destination_early_media_started = Arc::clone(&destination_early_media_started);
            move |incoming| {
                let destination_release = Arc::clone(&destination_release);
                let destination_invite_seen = Arc::clone(&destination_invite_seen);
                let destination_early_media_started = Arc::clone(&destination_early_media_started);
                let invite_tx = invite_tx.clone();
                async move {
                    let observed = ObservedInvite {
                        from: incoming.from.clone(),
                        correlation_id: incoming
                            .header_str(&HeaderName::Other("X-Correlation-Id".into())),
                        account_tier: incoming
                            .header_str(&HeaderName::Other("X-Account-Tier".into())),
                        forbidden: incoming
                            .header_str(&HeaderName::Other("X-Must-Not-Forward".into())),
                    };
                    let _ = invite_tx.send(observed).await;
                    destination_invite_seen.notify_one();
                    incoming
                        .send_early_media_with_source(
                            None,
                            AudioSource::Tone {
                                frequency: 660.0,
                                amplitude: 0.5,
                            },
                        )
                        .await
                        .expect("destination 183+SDP early media");
                    destination_early_media_started.notify_one();
                    destination_release.notified().await;
                    CallHandlerDecision::Accept
                }
            }
        })
        .on_established(move |handle| {
            let destination_established_tx = destination_established_tx.clone();
            async move {
                destination_established_tx
                    .send(handle)
                    .await
                    .map_err(|_| rvoip_sip::SessionError::Other("test receiver closed".into()))
            }
        })
        .on_dtmf(move |_handle, digit| {
            let destination_dtmf_tx = destination_dtmf_tx.clone();
            async move {
                destination_dtmf_tx
                    .send(digit)
                    .await
                    .map_err(|_| rvoip_sip::SessionError::Other("test receiver closed".into()))
            }
        })
        .on_ended(move |_call_id, _reason| {
            let destination_ended_tx = destination_ended_tx.clone();
            async move {
                let _ = destination_ended_tx.send(()).await;
                Ok(())
            }
        })
        .build()
        .await
        .expect("destination callback peer");
    let destination_stop = destination_peer.shutdown_handle();
    let destination_task = tokio::spawn(destination_peer.run());

    let (source_dtmf_tx, mut source_dtmf_rx) = mpsc::channel::<char>(4);
    let (source_progress_tx, mut source_progress_rx) = mpsc::channel::<(u16, Option<String>)>(4);
    let mut source_config = SipConfig::local("reference-vapi", source_address.port());
    source_config.offered_codecs = vec![0, 101];
    source_config.offer_srtp = true;
    source_config.srtp_required = true;
    let source_peer = CallbackPeer::builder(source_config)
        .on_incoming(|_incoming| async move {
            CallHandlerDecision::Reject {
                status: 486,
                reason: "Unexpected inbound call".into(),
            }
        })
        .on_dtmf(move |_handle, digit| {
            let source_dtmf_tx = source_dtmf_tx.clone();
            async move {
                source_dtmf_tx
                    .send(digit)
                    .await
                    .map_err(|_| rvoip_sip::SessionError::Other("test receiver closed".into()))
            }
        })
        .on_progress(move |_handle, status, _reason, sdp| {
            let source_progress_tx = source_progress_tx.clone();
            async move {
                source_progress_tx
                    .send((status, sdp))
                    .await
                    .map_err(|_| rvoip_sip::SessionError::Other("test receiver closed".into()))
            }
        })
        .build()
        .await
        .expect("source callback peer");
    let source_control = source_peer.control();
    let source_stop = source_peer.shutdown_handle();
    let source_task = tokio::spawn(source_peer.run());

    let created = runtime
        .service()
        .create_named_route_call(
            &owner,
            &IdempotencyKey::parse("generic-sip-reference-call").expect("idempotency key"),
            call_input(destination_address),
            route_binding(),
        )
        .await
        .expect("create named SIP route")
        .value;
    let call_id = created.call.call_id;
    let source_leg = created
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Inbound)
        .expect("source leg");
    let source_token = source_leg
        .attachment
        .as_ref()
        .expect("source attachment")
        .token
        .clone();
    let destination_leg = created
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Outbound)
        .expect("destination leg");

    let source_session = source_control
        .invite(format!("sip:{source_token}@{bridge_address}"))
        .send()
        .await
        .expect("send source INVITE");
    let source_handle = source_control.coordinator().session(&source_session);
    tokio::time::timeout(Duration::from_secs(5), destination_invite_seen.notified())
        .await
        .expect("attach-then-dial never reached destination");
    tokio::time::timeout(
        Duration::from_secs(5),
        destination_early_media_started.notified(),
    )
    .await
    .expect("destination never established provisional SRTP media");
    let (source_progress, source_progress_sdp) =
        tokio::time::timeout(Duration::from_secs(5), source_progress_rx.recv())
            .await
            .expect("source provisional progress deadline")
            .expect("source provisional progress callback remained live");
    assert_eq!(source_progress, 180);
    assert_eq!(source_progress_sdp, None);
    let (early_media_progress, early_media_sdp) =
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let progress = source_progress_rx
                    .recv()
                    .await
                    .expect("source progress callback remained live");
                if progress.0 == 183 {
                    return progress;
                }
            }
        })
        .await
        .expect("source never received Bridgefu 183 early-media SDP");
    assert_eq!(early_media_progress, 183);
    assert!(
        early_media_sdp
            .as_deref()
            .is_some_and(|sdp| sdp.contains("m=audio")),
        "Bridgefu's provisional response must carry negotiated audio SDP"
    );
    assert!(
        source_handle
            .wait_for_answered(Some(Duration::from_millis(200)))
            .await
            .is_err(),
        "source must stay provisionally unanswered while destination is ringing"
    );
    let source_security = source_handle
        .wait_for_media_security(Some(Duration::from_secs(5)))
        .await
        .expect("source provisional SDES-SRTP negotiation");
    assert_eq!(source_security.profile, MediaSecurityProfile::RtpSavp);
    assert!(source_security.contexts_installed);
    let (source_audio_tx, mut source_audio_rx) =
        source_handle.audio().await.expect("source audio").split();
    let early_at_source = receive_non_silent(&mut source_audio_rx).await;
    assert_eq!(early_at_source.sample_rate, 8_000);
    assert_eq!(early_at_source.channels, 1);
    assert_eq!(early_at_source.samples.len(), 160);
    assert!(
        source_handle
            .wait_for_answered(Some(Duration::from_millis(200)))
            .await
            .is_err(),
        "receiving destination SRTP must not finally answer the source"
    );
    let during_dial = wait_for_call(&runtime, call_id, |stored| {
        stored
            .call
            .aggregate
            .leg(destination_leg.leg_id)
            .is_some_and(|leg| leg.state() == LegState::Signaling)
    })
    .await;
    assert_eq!(
        during_dial
            .call
            .aggregate
            .leg(source_leg.leg_id)
            .expect("source aggregate leg")
            .state(),
        LegState::Signaling
    );
    let provisional_destination_connection = during_dial
        .call
        .bindings
        .get(&destination_leg.leg_id)
        .expect("provisionally bound destination connection")
        .connection_id
        .clone();
    let provisional_graph = orchestrator
        .media_graph_snapshot(&provisional_destination_connection)
        .await
        .expect("destination early-media source graph");
    assert_eq!(
        provisional_graph.sinks.len(),
        1,
        "early media must install exactly one destination-to-ingress route"
    );
    let provisional_graph_id = provisional_graph.graph_id.clone();
    let provisional_route_id = provisional_graph.sinks[0].route_id.clone();

    let observed_invite = invite_rx.recv().await.expect("observed destination INVITE");
    assert!(observed_invite.from.contains("bridgefu-reference"));
    assert!(observed_invite
        .correlation_id
        .as_deref()
        .is_some_and(|value| value.ends_with("reference-call-0001")));
    assert!(observed_invite
        .account_tier
        .as_deref()
        .is_some_and(|value| value.ends_with("gold")));
    assert_eq!(observed_invite.forbidden, None);

    destination_release.notify_one();
    let source_handle = source_handle
        .wait_for_answered(Some(Duration::from_secs(5)))
        .await
        .expect("source answered after destination became ready");
    let destination_handle =
        tokio::time::timeout(Duration::from_secs(5), destination_established_rx.recv())
            .await
            .expect("destination establishment deadline")
            .expect("destination establishment callback");
    let active = wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;
    wait_for_bridges(&orchestrator, 1).await;

    let source_connection = active
        .call
        .bindings
        .get(&source_leg.leg_id)
        .expect("bound source connection")
        .connection_id
        .clone();
    let destination_connection = active
        .call
        .bindings
        .get(&destination_leg.leg_id)
        .expect("bound destination connection")
        .connection_id
        .clone();
    assert_eq!(destination_connection, provisional_destination_connection);
    let active_destination_graph = orchestrator
        .media_graph_snapshot(&destination_connection)
        .await
        .expect("active destination source graph");
    assert_eq!(
        active_destination_graph.graph_id, provisional_graph_id,
        "final promotion must reuse the early-media source graph and its single receiver"
    );
    assert_eq!(active_destination_graph.sinks.len(), 1);
    assert!(
        active_destination_graph
            .sinks
            .iter()
            .all(|sink| sink.route_id != provisional_route_id),
        "the acknowledged provisional route must be removed before the duplex route activates"
    );
    let source_stream = sip_adapter
        .streams(source_connection)
        .await
        .expect("source adapter streams")
        .into_iter()
        .find(|stream| stream.kind() == StreamKind::Audio)
        .expect("source audio stream");
    let destination_stream = sip_adapter
        .streams(destination_connection)
        .await
        .expect("destination adapter streams")
        .into_iter()
        .find(|stream| stream.kind() == StreamKind::Audio)
        .expect("destination audio stream");
    assert_eq!(source_stream.codec().name, "g.711-mu");
    assert_eq!(destination_stream.codec().name, "g.711-a");
    assert_eq!(source_stream.codec().clock_rate_hz, 8_000);
    assert_eq!(destination_stream.codec().clock_rate_hz, 8_000);

    let destination_security = destination_handle
        .wait_for_media_security(Some(Duration::from_secs(5)))
        .await
        .expect("destination SDES-SRTP negotiation");
    for security in [&source_security, &destination_security] {
        assert_eq!(security.profile, MediaSecurityProfile::RtpSavp);
        assert!(security.contexts_installed);
    }

    let (destination_audio_tx, mut destination_audio_rx) = destination_handle
        .audio()
        .await
        .expect("destination audio")
        .split();
    tokio::time::sleep(Duration::from_millis(100)).await;
    while source_audio_rx.try_recv().is_some() {}
    send_tone(&source_audio_tx, 440.0).await;
    let at_destination = receive_non_silent(&mut destination_audio_rx).await;
    assert_eq!(at_destination.sample_rate, 8_000);
    assert_eq!(at_destination.channels, 1);
    assert_eq!(at_destination.samples.len(), 160);
    send_tone(&destination_audio_tx, 660.0).await;
    let at_source = receive_non_silent(&mut source_audio_rx).await;
    assert_eq!(at_source.sample_rate, 8_000);
    assert_eq!(at_source.channels, 1);
    assert_eq!(at_source.samples.len(), 160);

    source_handle
        .send_dtmf('5')
        .await
        .expect("source RFC 4733 DTMF");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), destination_dtmf_rx.recv())
            .await
            .expect("source-to-destination DTMF deadline"),
        Some('5')
    );
    destination_handle
        .send_dtmf('6')
        .await
        .expect("destination RFC 4733 DTMF");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), source_dtmf_rx.recv())
            .await
            .expect("destination-to-source DTMF deadline"),
        Some('6')
    );

    source_handle
        .hangup_and_wait(Some(Duration::from_secs(5)))
        .await
        .expect("source BYE completed");
    tokio::time::timeout(Duration::from_secs(5), destination_ended_rx.recv())
        .await
        .expect("destination observed peer BYE")
        .expect("destination end callback remained live");
    let terminal = wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    assert!(terminal
        .call
        .aggregate
        .legs()
        .iter()
        .all(|leg| leg.state().is_terminal()));
    wait_for_bridges(&orchestrator, 0).await;

    supervisor.shutdown(Duration::from_secs(3)).await;
    orchestrator.drain_prepared_outbound_connections().await;
    orchestrator.drain_connection_lifecycle_tasks().await;
    wait_for_orchestrator_idle(&orchestrator).await;
    sip_adapter.drain().await.expect("drain SIP adapter");
    bridge_coordinator
        .shutdown_gracefully(Some(Duration::from_secs(3)))
        .await
        .expect("shutdown Bridgefu SIP listener");
    destination_stop.shutdown();
    source_stop.shutdown();
    destination_task
        .await
        .expect("destination callback task")
        .expect("destination callback peer shutdown");
    source_task
        .await
        .expect("source callback task")
        .expect("source callback peer shutdown");
    assert_eq!(sip_adapter.retained_task_count(), 0);
    assert_eq!(orchestrator.connection_lifecycle_task_count(), 0);
}

#[test]
fn named_route_uses_proxy_407_then_orders_local_180_and_remote_183_before_answer() {
    std::thread::Builder::new()
        .name("generic-sip-proxy-auth".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(6)
                .thread_stack_size(8 * 1024 * 1024)
                .enable_all()
                .build()
                .expect("proxy-auth Tokio runtime")
                .block_on(Box::pin(run_proxy_auth_reference()));
        })
        .expect("spawn proxy-auth scenario")
        .join()
        .expect("proxy-auth scenario panicked");
}

async fn run_proxy_auth_reference() {
    const PROXY_REALM: &str = "bridgefu-reference-proxy";
    const PROXY_USER: &str = "bridgefu-proxy-user";
    const PROXY_PASSWORD: &str = "hermetic-proxy-password";
    const PROXY_NONCE: &str = "bridgefu-proxy-nonce";

    let bridge_address = reserve_udp();
    let source_address = reserve_udp();
    let proxy_address = reserve_udp();
    let unreachable_target = reserve_udp();
    let runtime = runtime().await;
    let orchestrator = Orchestrator::new(CoreConfig::default());

    let mut outbound_profiles = StaticOutboundProfileResolver::default();
    outbound_profiles.insert_sip(
        PROFILE_ID.into(),
        PROFILE_REVISION.into(),
        ConfiguredSipOutboundProfile {
            from_uri: format!("sip:bridgefu-reference@{bridge_address}"),
            outbound_proxy: Some(format!("sip:127.0.0.1:{};lr", proxy_address.port())),
            auth: Some(ConfiguredSipProfileAuth::Digest {
                realm: Some(PROXY_REALM.into()),
                username: PROXY_USER.into(),
                password: SecretRef::new(PROXY_PASSWORD),
            }),
        },
    );
    let supervisor = CallExecutionSupervisor::install_with_leg_executors_context_canary_broadcast_and_outbound_profiles(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        Arc::new(DisabledProviderLegExecutor),
        None,
        Arc::new(ContextPolicy {
            allow_headers: BTreeMap::from([
                ("X-Correlation-Id".into(), "correlation_id".into()),
                ("X-Account-Tier".into(), "account_tier".into()),
            ]),
        }),
        None,
        None,
        Arc::new(outbound_profiles),
        8,
        Duration::from_secs(10),
    )
    .await
    .expect("install proxy-auth execution supervisor");

    let owner = principal();
    let listener_policy = SipListenerAuthPolicy::enabled_for_tenant(TENANT)
        .expect("tenant-bound proxy-auth listener")
        .with_trusted_cidr(
            "127.0.0.1/32".parse().expect("loopback CIDR"),
            owner.authenticated().clone(),
        );
    let mut bridge_config = SipConfig::local("bridgefu-proxy-auth", bridge_address.port());
    bridge_config.offered_codecs = vec![0, 101];
    bridge_config.offer_srtp = true;
    bridge_config.srtp_required = true;
    let bridge_coordinator =
        rvoip_sip::UnifiedCoordinator::new_with_listener_auth(bridge_config, listener_policy)
            .await
            .expect("start proxy-auth Bridgefu listener");
    let mut bridge_events = bridge_coordinator
        .events()
        .await
        .expect("subscribe to Bridgefu SIP progress");
    let sip_adapter = SipAdapter::new_with_inbound_context_policy(
        Arc::clone(&bridge_coordinator),
        SipInboundContextPolicy::default(),
    )
    .await
    .expect("proxy-auth SIP adapter");
    orchestrator
        .register(Arc::clone(&sip_adapter) as Arc<dyn ConnectionAdapter>)
        .expect("register proxy-auth SIP adapter");

    let mut proxy_config = SipConfig::local("reference-authenticated-proxy", proxy_address.port())
        .with_auto_180_ringing(false);
    proxy_config.offered_codecs = vec![0, 101];
    proxy_config.offer_srtp = true;
    proxy_config.srtp_required = true;
    let proxy = rvoip_sip::UnifiedCoordinator::new(proxy_config)
        .await
        .expect("start authenticated proxy fixture");
    let mut proxy_events = proxy.events().await.expect("proxy event receiver");
    let proxy_accept = Arc::new(Notify::new());
    let (proxy_authenticated_tx, mut proxy_authenticated_rx) =
        mpsc::channel::<(String, String, String, String, bool)>(1);
    let (proxy_handle_tx, mut proxy_handle_rx) = mpsc::channel::<SessionHandle>(1);
    let mut proxy_task = {
        let proxy = Arc::clone(&proxy);
        let proxy_accept = Arc::clone(&proxy_accept);
        let expected_route_port = proxy_address.port();
        tokio::spawn(async move {
            let mut challenged = false;
            loop {
                let incoming = proxy
                    .next_incoming_call(&mut proxy_events)
                    .await?
                    .ok_or_else(|| {
                        rvoip_sip::SessionError::Other(
                            "proxy event stream closed before authenticated retry".into(),
                        )
                    })?;
                let route = incoming
                    .header_str(&HeaderName::Route)
                    .ok_or_else(|| rvoip_sip::SessionError::Other("proxy Route missing".into()))?;
                if !route.contains(&expected_route_port.to_string()) || !route.contains("lr") {
                    return Err(rvoip_sip::SessionError::Other(
                        "named-route outbound proxy was not retained".into(),
                    ));
                }
                let proxy_authorization = match incoming.header(&HeaderName::ProxyAuthorization) {
                    Some(rvoip_sip::TypedHeader::ProxyAuthorization(value)) => {
                        Some(value.to_string())
                    }
                    Some(_) => {
                        return Err(rvoip_sip::SessionError::Other(
                            "proxy authorization header was not typed".into(),
                        ));
                    }
                    None => None,
                };
                if !challenged {
                    if proxy_authorization.is_some()
                        || incoming.header(&HeaderName::Authorization).is_some()
                    {
                        return Err(rvoip_sip::SessionError::Other(
                            "initial proxy request carried credentials".into(),
                        ));
                    }
                    challenged = true;
                    incoming
                        .challenge_builder(rvoip_sip::api::AuthScheme::Digest)
                        .with_realm(PROXY_REALM)
                        .with_nonce(PROXY_NONCE)
                        .with_algorithm("MD5")
                        .with_qop("auth")
                        .as_proxy_challenge(true)
                        .send()
                        .await?;
                    continue;
                }
                let proxy_authorization = proxy_authorization.ok_or_else(|| {
                    rvoip_sip::SessionError::Other(
                        "authenticated retry omitted Proxy-Authorization".into(),
                    )
                })?;
                if incoming.header(&HeaderName::Authorization).is_some() {
                    return Err(rvoip_sip::SessionError::Other(
                        "proxy retry incorrectly carried origin Authorization".into(),
                    ));
                }
                let parsed = DigestAuthenticator::parse_authorization(&proxy_authorization)
                    .map_err(|error| rvoip_sip::SessionError::AuthError(error.to_string()))?;
                let valid = DigestAuthenticator::new(PROXY_REALM)
                    .validate_response(&parsed, "INVITE", PROXY_PASSWORD)
                    .unwrap_or(false);
                incoming.send_provisional_builder(183).send().await?;
                proxy_authenticated_tx
                    .send((
                        parsed.username,
                        parsed.realm,
                        parsed.nonce,
                        parsed.uri,
                        valid,
                    ))
                    .await
                    .map_err(|_| rvoip_sip::SessionError::Other("proxy observer closed".into()))?;
                proxy_accept.notified().await;
                let handle = incoming.accept().await?;
                proxy_handle_tx.send(handle).await.map_err(|_| {
                    rvoip_sip::SessionError::Other("proxy handle observer closed".into())
                })?;
                return Ok::<_, rvoip_sip::SessionError>(());
            }
        })
    };

    let (source_progress_tx, mut source_progress_rx) = mpsc::channel::<(u16, Option<String>)>(4);
    let mut source_config = SipConfig::local("reference-proxy-source", source_address.port());
    source_config.offered_codecs = vec![0, 101];
    source_config.offer_srtp = true;
    source_config.srtp_required = true;
    let source_peer = CallbackPeer::builder(source_config)
        .on_incoming(|_incoming| async move {
            CallHandlerDecision::Reject {
                status: 486,
                reason: "Unexpected inbound call".into(),
            }
        })
        .on_progress(move |_handle, status, _reason, sdp| {
            let source_progress_tx = source_progress_tx.clone();
            async move {
                source_progress_tx
                    .send((status, sdp))
                    .await
                    .map_err(|_| rvoip_sip::SessionError::Other("progress receiver closed".into()))
            }
        })
        .build()
        .await
        .expect("proxy-auth source peer");
    let source_control = source_peer.control();
    let source_stop = source_peer.shutdown_handle();
    let source_task = tokio::spawn(source_peer.run());

    let destination_uri = format!("sip:agent@{unreachable_target}");
    let created = runtime
        .service()
        .create_named_route_call(
            &owner,
            &IdempotencyKey::parse("generic-sip-reference-proxy-auth")
                .expect("proxy-auth idempotency key"),
            call_input_uri(destination_uri),
            route_binding(),
        )
        .await
        .expect("create proxy-auth named route")
        .value;
    let call_id = created.call.call_id;
    let source_token = created
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Inbound)
        .and_then(|leg| leg.attachment.as_ref())
        .expect("proxy-auth source attachment")
        .token
        .clone();
    let source_session = source_control
        .invite(format!("sip:{source_token}@{bridge_address}"))
        .send()
        .await
        .expect("send proxy-auth source INVITE");
    let source_handle = source_control.coordinator().session(&source_session);

    let (local_status, local_sdp) =
        tokio::time::timeout(Duration::from_secs(5), source_progress_rx.recv())
            .await
            .expect("local ringback deadline")
            .expect("local ringback observer remained live");
    assert_eq!(local_status, 180);
    assert_eq!(local_sdp, None);
    let observed = tokio::time::timeout(Duration::from_secs(5), proxy_authenticated_rx.recv())
        .await
        .expect("proxy authentication deadline");
    let Some((username, realm, nonce, digest_uri, digest_valid)) = observed else {
        let result = (&mut proxy_task).await;
        panic!("proxy fixture failed before authentication evidence: {result:?}");
    };
    assert_eq!(username, PROXY_USER);
    assert_eq!(realm, PROXY_REALM);
    assert_eq!(nonce, PROXY_NONCE);
    assert_eq!(digest_uri, format!("sip:agent@{unreachable_target}"));
    assert!(digest_valid, "Proxy-Authorization digest did not validate");
    let remote_progress_sdp = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match bridge_events.next().await {
                Some(SipEvent::CallProgress {
                    status_code: 183,
                    sdp,
                    ..
                }) => return sdp,
                Some(_) => {}
                None => panic!("Bridgefu SIP progress stream closed before 183"),
            }
        }
    })
    .await
    .expect("remote 183 progress deadline");
    let remote_progress_sdp =
        remote_progress_sdp.expect("rvoip 183 helper emits negotiated early-media SDP");
    assert!(remote_progress_sdp.contains("m=audio"));
    assert!(remote_progress_sdp.contains("RTP/SAVP"));
    // The proxy fixture intentionally sends no RTP before the final answer.
    // This proves 183-with-SDP signaling order, not true remote early audio.
    assert!(
        source_handle
            .wait_for_answered(Some(Duration::from_millis(200)))
            .await
            .is_err(),
        "source was finally answered before the authenticated destination was released"
    );

    proxy_accept.notify_one();
    let source_handle = source_handle
        .wait_for_answered(Some(Duration::from_secs(5)))
        .await
        .expect("source answered after authenticated proxy destination was ready");
    let proxy_handle = tokio::time::timeout(Duration::from_secs(5), proxy_handle_rx.recv())
        .await
        .expect("proxy destination handle deadline")
        .expect("proxy destination handle");
    wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;
    wait_for_bridges(&orchestrator, 1).await;

    source_handle
        .hangup_and_wait(Some(Duration::from_secs(5)))
        .await
        .expect("proxy-auth source BYE");
    proxy_handle
        .wait_for_end(Some(Duration::from_secs(5)))
        .await
        .expect("proxy-facing destination observed teardown");
    wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    wait_for_orchestrator_idle(&orchestrator).await;

    proxy_task
        .await
        .expect("proxy task join")
        .expect("proxy challenge/accept flow");
    supervisor.shutdown(Duration::from_secs(3)).await;
    orchestrator.drain_prepared_outbound_connections().await;
    orchestrator.drain_connection_lifecycle_tasks().await;
    sip_adapter
        .drain()
        .await
        .expect("drain proxy-auth SIP adapter");
    bridge_coordinator
        .shutdown_gracefully(Some(Duration::from_secs(3)))
        .await
        .expect("shutdown proxy-auth Bridgefu listener");
    proxy
        .shutdown_gracefully(Some(Duration::from_secs(3)))
        .await
        .expect("shutdown authenticated proxy fixture");
    source_stop.shutdown();
    source_task
        .await
        .expect("proxy-auth source callback task")
        .expect("proxy-auth source peer shutdown");
    assert_eq!(sip_adapter.retained_task_count(), 0);
    assert_eq!(orchestrator.connection_lifecycle_task_count(), 0);
}

#[derive(Clone, Copy)]
enum DestinationFailureMode {
    Reject,
    SetupTimeout,
}

impl DestinationFailureMode {
    const fn setup_timeout(self) -> Duration {
        match self {
            Self::Reject => Duration::from_secs(5),
            Self::SetupTimeout => Duration::from_millis(750),
        }
    }

    const fn idempotency_key(self) -> &'static str {
        match self {
            Self::Reject => "generic-sip-reference-rejection",
            Self::SetupTimeout => "generic-sip-reference-setup-timeout",
        }
    }
}

#[test]
fn destination_486_rejection_fails_the_call_and_releases_every_route() {
    run_destination_failure_on_large_stack(DestinationFailureMode::Reject);
}

#[test]
fn deferred_destination_setup_timeout_sends_cancel_and_releases_every_route() {
    run_destination_failure_on_large_stack(DestinationFailureMode::SetupTimeout);
}

fn run_destination_failure_on_large_stack(mode: DestinationFailureMode) {
    std::thread::Builder::new()
        .name(match mode {
            DestinationFailureMode::Reject => "generic-sip-rejection".into(),
            DestinationFailureMode::SetupTimeout => "generic-sip-setup-timeout".into(),
        })
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(8 * 1024 * 1024)
                .enable_all()
                .build()
                .expect("destination failure Tokio runtime")
                .block_on(Box::pin(run_destination_failure_reference(mode)));
        })
        .expect("spawn destination failure scenario")
        .join()
        .expect("destination failure scenario panicked");
}

async fn run_destination_failure_reference(mode: DestinationFailureMode) {
    let bridge_address = reserve_udp();
    let source_address = reserve_udp();
    let destination_address = reserve_udp();
    let runtime = runtime_with_setup_timeout(mode.setup_timeout()).await;
    let orchestrator = Orchestrator::new(CoreConfig::default());

    let mut outbound_profiles = StaticOutboundProfileResolver::default();
    outbound_profiles.insert_sip(
        PROFILE_ID.into(),
        PROFILE_REVISION.into(),
        ConfiguredSipOutboundProfile {
            from_uri: format!("sip:bridgefu-reference@{bridge_address}"),
            outbound_proxy: None,
            auth: None,
        },
    );
    let supervisor = CallExecutionSupervisor::install_with_leg_executors_context_canary_broadcast_and_outbound_profiles(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        Arc::new(DisabledProviderLegExecutor),
        None,
        Arc::new(ContextPolicy {
            allow_headers: BTreeMap::from([
                ("X-Correlation-Id".into(), "correlation_id".into()),
                ("X-Account-Tier".into(), "account_tier".into()),
            ]),
        }),
        None,
        None,
        Arc::new(outbound_profiles),
        8,
        Duration::from_secs(10),
    )
    .await
    .expect("install destination failure execution supervisor");

    let owner = principal();
    let listener_policy = SipListenerAuthPolicy::enabled_for_tenant(TENANT)
        .expect("tenant-bound failure listener")
        .with_trusted_cidr(
            "127.0.0.1/32".parse().expect("loopback CIDR"),
            owner.authenticated().clone(),
        );
    let mut bridge_config = SipConfig::local("bridgefu-failure", bridge_address.port());
    bridge_config.offered_codecs = vec![0, 101];
    bridge_config.offer_srtp = true;
    bridge_config.srtp_required = true;
    let bridge_coordinator =
        rvoip_sip::UnifiedCoordinator::new_with_listener_auth(bridge_config, listener_policy)
            .await
            .expect("start destination failure Bridgefu listener");
    let sip_adapter = SipAdapter::new_with_inbound_context_policy(
        Arc::clone(&bridge_coordinator),
        SipInboundContextPolicy::default(),
    )
    .await
    .expect("destination failure SIP adapter");
    orchestrator
        .register(Arc::clone(&sip_adapter) as Arc<dyn ConnectionAdapter>)
        .expect("register destination failure SIP adapter");

    let (destination_seen_tx, mut destination_seen_rx) = mpsc::channel::<()>(1);
    let (destination_cancelled_tx, mut destination_cancelled_rx) = mpsc::channel::<()>(1);
    let mut destination_config =
        SipConfig::local("reference-failure-destination", destination_address.port());
    destination_config.offered_codecs = vec![0, 101];
    destination_config.offer_srtp = true;
    destination_config.srtp_required = true;
    let destination_peer = CallbackPeer::builder(destination_config)
        .on_incoming(move |incoming| {
            let destination_seen_tx = destination_seen_tx.clone();
            async move {
                let _ = destination_seen_tx.send(()).await;
                match mode {
                    DestinationFailureMode::Reject => CallHandlerDecision::Reject {
                        status: 486,
                        reason: "Call center busy".into(),
                    },
                    DestinationFailureMode::SetupTimeout => {
                        CallHandlerDecision::Defer(incoming.defer(Duration::from_secs(10)))
                    }
                }
            }
        })
        .on_cancelled(move |_call_id| {
            let destination_cancelled_tx = destination_cancelled_tx.clone();
            async move {
                let _ = destination_cancelled_tx.send(()).await;
                Ok(())
            }
        })
        .build()
        .await
        .expect("destination failure callback peer");
    let destination_stop = destination_peer.shutdown_handle();
    let destination_task = tokio::spawn(destination_peer.run());

    let (source_failed_tx, mut source_failed_rx) = mpsc::channel::<u16>(1);
    let mut source_config = SipConfig::local("reference-failure-source", source_address.port());
    source_config.offered_codecs = vec![0, 101];
    source_config.offer_srtp = true;
    source_config.srtp_required = true;
    let source_peer = CallbackPeer::builder(source_config)
        .on_incoming(|_incoming| async move {
            CallHandlerDecision::Reject {
                status: 486,
                reason: "Unexpected inbound call".into(),
            }
        })
        .on_failed(move |_call_id, status, _reason| {
            let source_failed_tx = source_failed_tx.clone();
            async move {
                let _ = source_failed_tx.send(status).await;
                Ok(())
            }
        })
        .build()
        .await
        .expect("destination failure source peer");
    let source_control = source_peer.control();
    let source_stop = source_peer.shutdown_handle();
    let source_task = tokio::spawn(source_peer.run());

    let created = runtime
        .service()
        .create_named_route_call(
            &owner,
            &IdempotencyKey::parse(mode.idempotency_key())
                .expect("destination failure idempotency key"),
            call_input(destination_address),
            route_binding(),
        )
        .await
        .expect("create destination failure named route")
        .value;
    let call_id = created.call.call_id;
    let source_token = created
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Inbound)
        .and_then(|leg| leg.attachment.as_ref())
        .expect("destination failure source attachment")
        .token
        .clone();
    let source_session = source_control
        .invite(format!("sip:{source_token}@{bridge_address}"))
        .send()
        .await
        .expect("send destination failure source INVITE");
    let source_handle = source_control.coordinator().session(&source_session);
    tokio::time::timeout(Duration::from_secs(5), destination_seen_rx.recv())
        .await
        .expect("destination failure INVITE deadline")
        .expect("destination failure callback remained live");
    assert!(
        source_handle
            .wait_for_answered(Some(Duration::from_secs(5)))
            .await
            .is_err(),
        "failed destination unexpectedly answered the source"
    );
    let source_failure = tokio::time::timeout(Duration::from_secs(5), source_failed_rx.recv())
        .await
        .expect("source final failure deadline")
        .expect("source failure callback remained live");
    assert!((400..=699).contains(&source_failure));
    if matches!(mode, DestinationFailureMode::SetupTimeout) {
        tokio::time::timeout(Duration::from_secs(5), destination_cancelled_rx.recv())
            .await
            .expect("timed-out destination CANCEL deadline")
            .expect("timed-out destination CANCEL callback remained live");
    }

    let terminal = wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    assert!(terminal
        .call
        .aggregate
        .legs()
        .iter()
        .all(|leg| leg.state().is_terminal()));
    wait_for_orchestrator_idle(&orchestrator).await;

    supervisor.shutdown(Duration::from_secs(3)).await;
    orchestrator.drain_prepared_outbound_connections().await;
    orchestrator.drain_connection_lifecycle_tasks().await;
    sip_adapter
        .drain()
        .await
        .expect("drain destination failure SIP adapter");
    bridge_coordinator
        .shutdown_gracefully(Some(Duration::from_secs(3)))
        .await
        .expect("shutdown destination failure Bridgefu listener");
    destination_stop.shutdown();
    source_stop.shutdown();
    destination_task
        .await
        .expect("destination failure callback task")
        .expect("destination failure callback peer shutdown");
    source_task
        .await
        .expect("destination failure source callback task")
        .expect("destination failure source peer shutdown");
    assert_eq!(sip_adapter.retained_task_count(), 0);
    assert_eq!(orchestrator.connection_lifecycle_task_count(), 0);
}

#[test]
fn provisional_source_cancel_reaches_the_real_destination_and_releases_routes() {
    std::thread::Builder::new()
        .name("generic-sip-cancel".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(8 * 1024 * 1024)
                .enable_all()
                .build()
                .expect("CANCEL Tokio runtime")
                .block_on(Box::pin(run_provisional_cancel_reference()));
        })
        .expect("spawn CANCEL scenario")
        .join()
        .expect("CANCEL scenario panicked");
}

async fn run_provisional_cancel_reference() {
    let bridge_address = reserve_udp();
    let source_address = reserve_udp();
    let destination_address = reserve_udp();
    let runtime = runtime().await;
    let orchestrator = Orchestrator::new(CoreConfig::default());

    let mut outbound_profiles = StaticOutboundProfileResolver::default();
    outbound_profiles.insert_sip(
        PROFILE_ID.into(),
        PROFILE_REVISION.into(),
        ConfiguredSipOutboundProfile {
            from_uri: format!("sip:bridgefu-reference@{bridge_address}"),
            outbound_proxy: None,
            auth: None,
        },
    );
    let supervisor = CallExecutionSupervisor::install_with_leg_executors_context_canary_broadcast_and_outbound_profiles(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        Arc::new(DisabledProviderLegExecutor),
        None,
        Arc::new(ContextPolicy {
            allow_headers: BTreeMap::from([
                ("X-Correlation-Id".into(), "correlation_id".into()),
                ("X-Account-Tier".into(), "account_tier".into()),
            ]),
        }),
        None,
        None,
        Arc::new(outbound_profiles),
        8,
        Duration::from_secs(10),
    )
    .await
    .expect("install CANCEL execution supervisor");

    let owner = principal();
    let listener_policy = SipListenerAuthPolicy::enabled_for_tenant(TENANT)
        .expect("tenant-bound listener")
        .with_trusted_cidr(
            "127.0.0.1/32".parse().expect("loopback CIDR"),
            owner.authenticated().clone(),
        );
    let mut bridge_config = SipConfig::local("bridgefu-cancel", bridge_address.port());
    bridge_config.offered_codecs = vec![0, 8, 101];
    bridge_config.offer_srtp = true;
    bridge_config.srtp_required = true;
    let bridge_coordinator =
        rvoip_sip::UnifiedCoordinator::new_with_listener_auth(bridge_config, listener_policy)
            .await
            .expect("start CANCEL Bridgefu listener");
    let sip_adapter = SipAdapter::new_with_inbound_context_policy(
        Arc::clone(&bridge_coordinator),
        SipInboundContextPolicy::default(),
    )
    .await
    .expect("CANCEL SIP adapter");
    orchestrator
        .register(Arc::clone(&sip_adapter) as Arc<dyn ConnectionAdapter>)
        .expect("register CANCEL SIP adapter");

    let (destination_invite_tx, mut destination_invite_rx) = mpsc::channel::<()>(1);
    let (destination_cancel_tx, mut destination_cancel_rx) = mpsc::channel::<()>(1);
    let mut destination_config =
        SipConfig::local("reference-cancel-destination", destination_address.port());
    destination_config.offered_codecs = vec![8, 101];
    destination_config.offer_srtp = true;
    destination_config.srtp_required = true;
    let destination_peer = CallbackPeer::builder(destination_config)
        .on_incoming(move |incoming| {
            let destination_invite_tx = destination_invite_tx.clone();
            async move {
                let _ = destination_invite_tx.send(()).await;
                CallHandlerDecision::Defer(incoming.defer(Duration::from_secs(10)))
            }
        })
        .on_cancelled(move |_call_id| {
            let destination_cancel_tx = destination_cancel_tx.clone();
            async move {
                let _ = destination_cancel_tx.send(()).await;
                Ok(())
            }
        })
        .build()
        .await
        .expect("deferred destination peer");
    let destination_stop = destination_peer.shutdown_handle();
    let destination_task = tokio::spawn(destination_peer.run());

    let mut source_config = SipConfig::local("reference-cancel-source", source_address.port());
    source_config.offered_codecs = vec![0, 101];
    source_config.offer_srtp = true;
    source_config.srtp_required = true;
    let source = rvoip_sip::UnifiedCoordinator::new(source_config)
        .await
        .expect("CANCEL source peer");

    let created = runtime
        .service()
        .create_named_route_call(
            &owner,
            &IdempotencyKey::parse("generic-sip-reference-cancel").expect("CANCEL idempotency key"),
            call_input(destination_address),
            route_binding(),
        )
        .await
        .expect("create CANCEL named route")
        .value;
    let call_id = created.call.call_id;
    let source_token = created
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Inbound)
        .and_then(|leg| leg.attachment.as_ref())
        .expect("CANCEL source attachment")
        .token
        .clone();
    let source_session = source
        .invite(
            Some(format!("sip:vapi@{source_address}")),
            format!("sip:{source_token}@{bridge_address}"),
        )
        .send()
        .await
        .expect("send provisional source INVITE");
    let source_handle = source.session(&source_session);
    tokio::time::timeout(Duration::from_secs(5), destination_invite_rx.recv())
        .await
        .expect("destination INVITE deadline")
        .expect("destination INVITE callback remained live");
    assert!(
        source_handle
            .wait_for_answered(Some(Duration::from_millis(200)))
            .await
            .is_err(),
        "source unexpectedly received a final answer"
    );

    // Depending on whether the 487 final response wins the local teardown
    // race, the caller facade may report the already-terminal session.  The
    // wire and Bridgefu lifecycle assertions below are authoritative.
    let _source_teardown = source_handle.hangup().await;
    tokio::time::timeout(Duration::from_secs(5), destination_cancel_rx.recv())
        .await
        .expect("destination CANCEL deadline")
        .expect("destination CANCEL callback remained live");
    let terminal = wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    assert!(terminal
        .call
        .aggregate
        .legs()
        .iter()
        .all(|leg| leg.state().is_terminal()));
    wait_for_bridges(&orchestrator, 0).await;

    supervisor.shutdown(Duration::from_secs(3)).await;
    orchestrator.drain_prepared_outbound_connections().await;
    orchestrator.drain_connection_lifecycle_tasks().await;
    sip_adapter.drain().await.expect("drain CANCEL SIP adapter");
    bridge_coordinator
        .shutdown_gracefully(Some(Duration::from_secs(3)))
        .await
        .expect("shutdown CANCEL Bridgefu listener");
    source
        .shutdown_gracefully(Some(Duration::from_secs(3)))
        .await
        .expect("shutdown CANCEL source");
    destination_stop.shutdown();
    destination_task
        .await
        .expect("destination CANCEL callback task")
        .expect("destination CANCEL peer shutdown");
    assert_eq!(sip_adapter.retained_task_count(), 0);
    assert_eq!(orchestrator.connection_lifecycle_task_count(), 0);
}

#[test]
fn named_sips_route_uses_verified_tls_and_profile_digest_challenge() {
    std::thread::Builder::new()
        .name("generic-sips-digest".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(6)
                .thread_stack_size(8 * 1024 * 1024)
                .enable_all()
                .build()
                .expect("SIPS Tokio runtime")
                .block_on(Box::pin(run_sips_digest_reference()));
        })
        .expect("spawn SIPS scenario")
        .join()
        .expect("SIPS scenario panicked");
}

async fn run_sips_digest_reference() {
    const DIGEST_REALM: &str = "bridgefu-reference-destination";
    const DIGEST_USER: &str = "bridgefu";
    const DIGEST_PASSWORD: &str = "hermetic-reference-password";

    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls = TestTlsFiles::create();
    assert_fixture_exists(&tls.cert);
    assert_fixture_exists(&tls.key);
    let bridge_udp = reserve_udp();
    let bridge_tls = reserve_tcp();
    let source_udp = reserve_udp();
    let source_tls = reserve_tcp();
    let destination_udp = reserve_udp();
    let destination_tls = reserve_tcp();
    let runtime = runtime().await;
    let orchestrator = Orchestrator::new(CoreConfig::default());

    let mut outbound_profiles = StaticOutboundProfileResolver::default();
    outbound_profiles.insert_sip(
        PROFILE_ID.into(),
        PROFILE_REVISION.into(),
        ConfiguredSipOutboundProfile {
            from_uri: format!(
                "sips:bridgefu-reference@localhost:{};transport=tls",
                bridge_tls.port()
            ),
            outbound_proxy: None,
            auth: Some(ConfiguredSipProfileAuth::Digest {
                realm: Some(DIGEST_REALM.into()),
                username: DIGEST_USER.into(),
                password: SecretRef::new(DIGEST_PASSWORD),
            }),
        },
    );
    let supervisor = CallExecutionSupervisor::install_with_leg_executors_context_canary_broadcast_and_outbound_profiles(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        Arc::new(DisabledProviderLegExecutor),
        None,
        Arc::new(ContextPolicy {
            allow_headers: BTreeMap::from([
                ("X-Correlation-Id".into(), "correlation_id".into()),
                ("X-Account-Tier".into(), "account_tier".into()),
            ]),
        }),
        None,
        None,
        Arc::new(outbound_profiles),
        8,
        Duration::from_secs(10),
    )
    .await
    .expect("install SIPS execution supervisor");

    let owner = principal();
    let bridge_policy = SipListenerAuthPolicy::enabled_for_tenant(TENANT)
        .expect("tenant-bound SIPS listener")
        .with_trusted_cidr(
            "127.0.0.1/32".parse().expect("loopback CIDR"),
            owner.authenticated().clone(),
        );
    let bridge_config = tls_sip_config(
        "bridgefu-sips",
        bridge_udp,
        bridge_tls,
        &tls,
        vec![0, 8, 101],
    );
    let bridge_coordinator =
        rvoip_sip::UnifiedCoordinator::new_with_listener_auth(bridge_config, bridge_policy)
            .await
            .expect("start verified Bridgefu SIPS listener");
    let sip_adapter = SipAdapter::new_with_inbound_context_policy(
        Arc::clone(&bridge_coordinator),
        SipInboundContextPolicy::default(),
    )
    .await
    .expect("SIPS adapter");
    orchestrator
        .register(Arc::clone(&sip_adapter) as Arc<dyn ConnectionAdapter>)
        .expect("register SIPS adapter");

    let destination_policy = SipListenerAuthPolicy::authenticated_for_tenant(
        "reference-call-center",
        SipAuthService::digest(DIGEST_REALM).with_digest_user(DIGEST_USER, DIGEST_PASSWORD),
    )
    .expect("Digest-protected destination policy");
    let destination_config = tls_sip_config(
        "reference-digest-destination",
        destination_udp,
        destination_tls,
        &tls,
        vec![8, 101],
    );
    let destination = rvoip_sip::UnifiedCoordinator::new_with_listener_auth(
        destination_config,
        destination_policy,
    )
    .await
    .expect("start Digest-protected SIPS destination");
    let destination_early_media_started = Arc::new(Notify::new());
    let destination_release = Arc::new(Notify::new());
    let mut destination_events = destination.events().await.expect("destination events");
    let (destination_handle_tx, mut destination_handle_rx) = mpsc::channel::<SessionHandle>(1);
    let destination_for_events = Arc::clone(&destination);
    let destination_early_media_for_events = Arc::clone(&destination_early_media_started);
    let destination_release_for_events = Arc::clone(&destination_release);
    let destination_task = tokio::spawn(async move {
        while let Some(event) = destination_events.next().await {
            match event {
                SipEvent::IncomingCall { call_id, .. } => {
                    destination_for_events
                        .send_early_media(&call_id, None)
                        .await
                        .expect("send authenticated SIPS 183+SDP");
                    destination_for_events
                        .set_audio_source(
                            &call_id,
                            AudioSource::Tone {
                                frequency: 720.0,
                                amplitude: 0.5,
                            },
                        )
                        .await
                        .expect("send authenticated SIPS early SRTP");
                    destination_early_media_for_events.notify_one();
                    destination_release_for_events.notified().await;
                    destination_for_events
                        .accept_call(&call_id)
                        .await
                        .expect("accept authenticated SIPS call after early media");
                    destination_handle_tx
                        .send(destination_for_events.session(&call_id))
                        .await
                        .expect("publish destination handle");
                }
                SipEvent::CallEnded { .. }
                | SipEvent::CallFailed { .. }
                | SipEvent::CallCancelled { .. } => break,
                _ => {}
            }
        }
    });

    let source_config = tls_sip_config(
        "reference-sips-source",
        source_udp,
        source_tls,
        &tls,
        vec![0, 101],
    );
    let source = rvoip_sip::UnifiedCoordinator::new(source_config)
        .await
        .expect("start verified SIPS source");

    let destination_uri = format!(
        "sips:agent@localhost:{};transport=tls",
        destination_tls.port()
    );
    let created = runtime
        .service()
        .create_named_route_call(
            &owner,
            &IdempotencyKey::parse("generic-sips-reference-digest").expect("SIPS idempotency key"),
            call_input_uri(destination_uri),
            route_binding(),
        )
        .await
        .expect("create SIPS named route")
        .value;
    let call_id = created.call.call_id;
    let source_leg = created
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Inbound)
        .expect("SIPS source leg");
    let destination_leg = created
        .call
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirection::Outbound)
        .expect("SIPS destination leg");
    let source_token = source_leg
        .attachment
        .as_ref()
        .expect("SIPS source attachment")
        .token
        .clone();
    let source_session = source
        .invite(
            Some(format!(
                "sips:vapi@localhost:{};transport=tls",
                source_tls.port()
            )),
            format!(
                "sips:{source_token}@localhost:{};transport=tls",
                bridge_tls.port()
            ),
        )
        .send()
        .await
        .expect("send verified SIPS source INVITE");
    let source_handle = source.session(&source_session);
    tokio::time::timeout(
        Duration::from_secs(10),
        destination_early_media_started.notified(),
    )
    .await
    .expect("authenticated SIPS destination never started early media");
    source_handle
        .wait_for_progress(
            |event| {
                matches!(
                    event,
                    SipEvent::CallProgress {
                        status_code: 183,
                        sdp: Some(sdp),
                        ..
                    } if sdp.contains("m=audio")
                )
            },
            Some(Duration::from_secs(10)),
        )
        .await
        .expect("SIPS source received no 183 with audio SDP");
    assert!(
        source_handle
            .wait_for_answered(Some(Duration::from_millis(200)))
            .await
            .is_err(),
        "SIPS source must remain unanswered during destination early media"
    );
    let source_security = source_handle
        .wait_for_media_security(Some(Duration::from_secs(5)))
        .await
        .expect("provisional SIPS source SRTP");
    assert!(source_security.contexts_installed);
    assert_eq!(source_security.profile, MediaSecurityProfile::RtpSavp);
    let (source_audio_tx, mut source_audio_rx) = source_handle
        .audio()
        .await
        .expect("provisional SIPS source audio")
        .split();
    let early_at_source = receive_non_silent(&mut source_audio_rx).await;
    assert_eq!(early_at_source.sample_rate, 8_000);
    assert_eq!(early_at_source.channels, 1);
    assert_eq!(early_at_source.samples.len(), 160);
    assert!(
        source_handle
            .wait_for_answered(Some(Duration::from_millis(200)))
            .await
            .is_err(),
        "encrypted early audio must not finally answer the SIPS source"
    );
    let during_early_media = wait_for_call(&runtime, call_id, |stored| {
        stored
            .call
            .aggregate
            .leg(destination_leg.leg_id)
            .is_some_and(|leg| leg.state() == LegState::Signaling)
    })
    .await;
    assert_eq!(
        during_early_media
            .call
            .aggregate
            .leg(source_leg.leg_id)
            .expect("SIPS source aggregate leg")
            .state(),
        LegState::Signaling
    );
    let provisional_destination_connection = during_early_media
        .call
        .bindings
        .get(&destination_leg.leg_id)
        .expect("provisionally bound SIPS destination")
        .connection_id
        .clone();
    let provisional_graph = orchestrator
        .media_graph_snapshot(&provisional_destination_connection)
        .await
        .expect("SIPS destination provisional source graph");
    assert_eq!(provisional_graph.sinks.len(), 1);
    let provisional_graph_id = provisional_graph.graph_id.clone();
    let provisional_route_id = provisional_graph.sinks[0].route_id.clone();

    destination_release.notify_one();
    let source_handle = source_handle
        .wait_for_answered(Some(Duration::from_secs(10)))
        .await
        .expect("SIPS source answered after Digest challenge");
    let destination_handle =
        tokio::time::timeout(Duration::from_secs(10), destination_handle_rx.recv())
            .await
            .expect("authenticated destination handle deadline")
            .expect("authenticated destination handle");
    let active = wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state() == CallState::Active
    })
    .await;
    wait_for_bridges(&orchestrator, 1).await;

    let active_destination_connection = active
        .call
        .bindings
        .get(&destination_leg.leg_id)
        .expect("active SIPS destination binding")
        .connection_id
        .clone();
    assert_eq!(
        active_destination_connection,
        provisional_destination_connection
    );
    let active_destination_graph = orchestrator
        .media_graph_snapshot(&active_destination_connection)
        .await
        .expect("active SIPS destination source graph");
    assert_eq!(
        active_destination_graph.graph_id, provisional_graph_id,
        "SIPS final promotion must reuse the early-media source graph and its single receiver"
    );
    assert_eq!(active_destination_graph.sinks.len(), 1);
    assert!(
        active_destination_graph
            .sinks
            .iter()
            .all(|sink| sink.route_id != provisional_route_id),
        "SIPS provisional route must be acknowledged removed before duplex activation"
    );

    let destination_security = destination_handle
        .wait_for_media_security(Some(Duration::from_secs(5)))
        .await
        .expect("SIPS destination SRTP");
    assert!(source_security.contexts_installed);
    assert!(destination_security.contexts_installed);
    assert_eq!(source_security.profile, MediaSecurityProfile::RtpSavp);
    assert_eq!(destination_security.profile, MediaSecurityProfile::RtpSavp);

    let (destination_audio_tx, mut destination_audio_rx) = destination_handle
        .audio()
        .await
        .expect("active SIPS destination audio")
        .split();
    tokio::time::sleep(Duration::from_millis(100)).await;
    while source_audio_rx.try_recv().is_some() {}
    send_tone(&source_audio_tx, 440.0).await;
    let at_destination = receive_non_silent(&mut destination_audio_rx).await;
    assert_eq!(at_destination.sample_rate, 8_000);
    assert_eq!(at_destination.channels, 1);
    send_tone(&destination_audio_tx, 880.0).await;
    let at_source = receive_non_silent(&mut source_audio_rx).await;
    assert_eq!(at_source.sample_rate, 8_000);
    assert_eq!(at_source.channels, 1);

    source_handle
        .hangup_and_wait(Some(Duration::from_secs(5)))
        .await
        .expect("SIPS source BYE");
    wait_for_call(&runtime, call_id, |stored| {
        stored.call.aggregate.state().is_terminal()
    })
    .await;
    wait_for_bridges(&orchestrator, 0).await;
    destination
        .shutdown_gracefully(Some(Duration::from_secs(3)))
        .await
        .expect("shutdown SIPS destination");
    destination_task.abort();
    match destination_task.await {
        Ok(()) => {}
        Err(error) if error.is_cancelled() => {}
        Err(error) => panic!("destination event task failed during shutdown: {error}"),
    }

    supervisor.shutdown(Duration::from_secs(3)).await;
    orchestrator.drain_prepared_outbound_connections().await;
    orchestrator.drain_connection_lifecycle_tasks().await;
    wait_for_orchestrator_idle(&orchestrator).await;
    sip_adapter.drain().await.expect("drain SIPS adapter");
    bridge_coordinator
        .shutdown_gracefully(Some(Duration::from_secs(3)))
        .await
        .expect("shutdown Bridgefu SIPS listener");
    source
        .shutdown_gracefully(Some(Duration::from_secs(3)))
        .await
        .expect("shutdown SIPS source");
    assert_eq!(sip_adapter.retained_task_count(), 0);
    assert_eq!(orchestrator.connection_lifecycle_task_count(), 0);
}
