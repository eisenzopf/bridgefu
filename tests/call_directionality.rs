use bridgefu::call_engine::{
    CallAggregate, CallCommand, EffectIntent, LegDirection, LegKind, LegSemantics, LegSpec,
    LegState, MediaFlow, SignalingInitiator, TenantId,
};
use chrono::{TimeZone, Utc};

fn at(seconds: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(1_735_689_600 + seconds, 0)
        .single()
        .expect("valid test time")
}

fn specs() -> [LegSpec; 2] {
    [
        LegSpec {
            direction: LegDirection::Outbound,
            kind: LegKind::Sip,
        },
        LegSpec {
            direction: LegDirection::Inbound,
            kind: LegKind::InteractiveWebRtc,
        },
    ]
}

#[test]
fn signaling_initiation_is_not_inferred_from_business_direction() {
    let call = CallAggregate::new_with_semantics(
        TenantId::parse("tenant-a").expect("valid tenant"),
        specs(),
        [
            LegSemantics {
                signaling_initiator: SignalingInitiator::Remote,
                media_flow: MediaFlow::SendReceive,
            },
            LegSemantics {
                signaling_initiator: SignalingInitiator::Bridgefu,
                media_flow: MediaFlow::SendReceive,
            },
        ],
        at(0),
    )
    .expect("valid explicit semantics");

    let decision = call
        .decide(CallCommand::StartConnecting {
            at: at(1),
            setup_deadline: at(60),
        })
        .expect("start call");
    let remote_outbound = call.legs()[0].id();
    let bridgefu_inbound = call.legs()[1].id();

    assert!(decision.effects().iter().any(|effect| matches!(
        effect,
        EffectIntent::AwaitLegAttachment { leg_id, .. } if *leg_id == remote_outbound
    )));
    assert!(decision.effects().iter().any(|effect| matches!(
        effect,
        EffectIntent::StartLeg { leg_id, direction: LegDirection::Inbound, .. }
            if *leg_id == bridgefu_inbound
    )));
    assert_eq!(
        decision.aggregate().legs()[0].state(),
        LegState::AwaitingAttach
    );
    assert_eq!(decision.aggregate().legs()[1].state(), LegState::Pending);
}

#[test]
fn media_flow_requires_complete_source_sink_pairs() {
    let tenant = || TenantId::parse("tenant-a").expect("valid tenant");
    let signaling = [SignalingInitiator::Remote, SignalingInitiator::Bridgefu];

    CallAggregate::new_with_semantics(
        tenant(),
        specs(),
        [
            LegSemantics {
                signaling_initiator: signaling[0],
                media_flow: MediaFlow::ReceiveOnly,
            },
            LegSemantics {
                signaling_initiator: signaling[1],
                media_flow: MediaFlow::SendOnly,
            },
        ],
        at(0),
    )
    .expect("complete left-to-right route");

    for (left, right) in [
        (MediaFlow::ReceiveOnly, MediaFlow::ReceiveOnly),
        (MediaFlow::Inactive, MediaFlow::Inactive),
    ] {
        CallAggregate::new_with_semantics(
            tenant(),
            specs(),
            [
                LegSemantics {
                    signaling_initiator: signaling[0],
                    media_flow: left,
                },
                LegSemantics {
                    signaling_initiator: signaling[1],
                    media_flow: right,
                },
            ],
            at(0),
        )
        .expect_err("incomplete route must fail before execution");
    }
}

#[test]
fn historical_aggregate_snapshots_retain_legacy_defaults() {
    let call = CallAggregate::new(
        TenantId::parse("tenant-a").expect("valid tenant"),
        specs(),
        at(0),
    );
    let mut encoded = serde_json::to_value(call).expect("serialize call");
    for leg in encoded["legs"].as_array_mut().expect("leg array") {
        let leg = leg.as_object_mut().expect("leg object");
        leg.remove("signaling_initiator");
        leg.remove("media_flow");
    }

    let restored: CallAggregate = serde_json::from_value(encoded).expect("historical snapshot");
    assert_eq!(
        restored.legs()[0].signaling_initiator(),
        SignalingInitiator::Bridgefu
    );
    assert_eq!(
        restored.legs()[1].signaling_initiator(),
        SignalingInitiator::Remote
    );
    assert!(restored
        .legs()
        .iter()
        .all(|leg| leg.media_flow() == MediaFlow::SendReceive));
}
