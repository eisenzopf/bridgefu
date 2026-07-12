use std::collections::BTreeSet;
use std::time::Duration;

use bridgefu::call_engine::{
    AggregateVersion, AttachmentConsume, AttachmentId, AttachmentIssue, AttachmentLookup,
    AttachmentTokenDigest, AttachmentTransport, BindingGeneration, CallAggregate, CallCommand,
    CallRepository, CallState, CommandCommit, CommandId, CreateCall, EffectIntent, FailureDetails,
    IdempotencyKeyDigest, LegDirection, LegKind, LegSpec, LegState, PrincipalFingerprint,
    ProviderAccountKey, ProviderCallId, ProviderEventDigest, ProviderEventInput,
    ProviderEventOutcome, ProviderEventState, ProviderPayloadDigest, RegisterWorker,
    RepositoryError, RequestDigest, StoredCall, TenantId, WorkerLease,
};
use bridgefu::call_service::{
    AmazonConnectEndpointConfig, CallExecutionPlan, CallServiceRepository, CompletedServiceEffect,
    ControlCommandOutcome, ControlCommandTransaction, ControlIntent, DtmfSequence,
    EffectResultOutcome, EffectResultReconciliation, ExternalReferenceBinding,
    ExternalReferenceValue, LegEndpointConfig, LegExecutionSpec, OutboundConnectionBind,
    OutboundConnectionBindOutcome, ProviderEndpointConfig, ProviderKind, ServiceCommandOutcome,
    ServiceCommandTransaction, ServiceCreateOutcome, ServiceCreateTransaction,
    ServiceEffectPayload, ServiceEffectPayloadInput, ServiceEffectResult, SipEndpointConfig,
    StoredServiceCall, TransferTarget, WebRtcEndpointConfig,
};
use bridgefu::persistence::MemoryRepository;
use chrono::{DateTime, TimeZone, Utc};
use rvoip_core::ids::ConnectionId;

fn at(second: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_910_000_000 + second, 0).unwrap()
}

fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn tenant(value: &str) -> TenantId {
    TenantId::parse(value).unwrap()
}

fn principal(byte: u8) -> PrincipalFingerprint {
    PrincipalFingerprint::new(digest(byte))
}

async fn register(repository: &MemoryRepository, max_calls: usize) -> WorkerLease {
    repository
        .register_worker(RegisterWorker {
            worker_id: Default::default(),
            max_calls,
            capabilities: BTreeSet::from([
                "sip".to_owned(),
                "webrtc".to_owned(),
                "twilio".to_owned(),
            ]),
            at: at(0),
        })
        .await
        .unwrap()
        .lease
}

fn sip_webrtc_create(
    owner: TenantId,
    worker: WorkerLease,
    key: u8,
) -> (ServiceCreateTransaction, AttachmentTokenDigest) {
    let initial = CallAggregate::new(
        owner,
        [
            LegSpec {
                direction: LegDirection::Inbound,
                kind: LegKind::Sip,
            },
            LegSpec {
                direction: LegDirection::Outbound,
                kind: LegKind::InteractiveWebRtc,
            },
        ],
        at(1),
    );
    let inbound = initial.legs()[0].id();
    let token_digest = AttachmentTokenDigest::new(digest(key.wrapping_add(80)));
    let plan = CallExecutionPlan::new(
        &initial,
        [
            LegExecutionSpec {
                leg_id: inbound,
                endpoint: LegEndpointConfig::Sip(SipEndpointConfig { uri: None }),
            },
            LegExecutionSpec {
                leg_id: initial.legs()[1].id(),
                endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                    signaling_uri: Some("wss://webrtc.example.test/session".to_owned()),
                }),
            },
        ],
    )
    .unwrap();
    let create = CreateCall {
        initial,
        command_id: CommandId::new(),
        command: CallCommand::StartConnecting {
            at: at(2),
            setup_deadline: at(32),
        },
        worker,
        idempotency_key: IdempotencyKeyDigest::new(digest(key)),
        request_digest: RequestDigest::new(digest(key.wrapping_add(1))),
        attachments: vec![AttachmentIssue {
            attachment_id: AttachmentId::new(),
            token_digest,
            leg_id: inbound,
            binding_generation: BindingGeneration::INITIAL,
            transport: AttachmentTransport::Sip,
            expected_principal: principal(1),
            expires_at: at(122),
        }],
        at: at(2),
    };
    (ServiceCreateTransaction { create, plan }, token_digest)
}

fn provider_create(owner: TenantId, worker: WorkerLease, key: u8) -> ServiceCreateTransaction {
    let initial = CallAggregate::new(
        owner,
        [
            LegSpec {
                direction: LegDirection::Outbound,
                kind: LegKind::Twilio,
            },
            LegSpec {
                direction: LegDirection::Inbound,
                kind: LegKind::Sip,
            },
        ],
        at(1),
    );
    let plan = CallExecutionPlan::new(
        &initial,
        [
            LegExecutionSpec {
                leg_id: initial.legs()[0].id(),
                endpoint: LegEndpointConfig::Provider(ProviderEndpointConfig {
                    provider: ProviderKind::Twilio,
                    account_profile: "twilio-sandbox".to_owned(),
                    destination: Some("+12065550100".to_owned()),
                }),
            },
            LegExecutionSpec {
                leg_id: initial.legs()[1].id(),
                endpoint: LegEndpointConfig::Sip(SipEndpointConfig { uri: None }),
            },
        ],
    )
    .unwrap();
    ServiceCreateTransaction {
        create: CreateCall {
            initial,
            command_id: CommandId::new(),
            command: CallCommand::StartConnecting {
                at: at(2),
                setup_deadline: at(32),
            },
            worker,
            idempotency_key: IdempotencyKeyDigest::new(digest(key)),
            request_digest: RequestDigest::new(digest(key.wrapping_add(1))),
            attachments: Vec::new(),
            at: at(2),
        },
        plan,
    }
}

fn created(outcome: ServiceCreateOutcome) -> StoredServiceCall {
    match outcome {
        ServiceCreateOutcome::Created(call) => call,
        ServiceCreateOutcome::Replayed(_) => panic!("expected new call"),
    }
}

async fn service_command(
    repository: &MemoryRepository,
    call: &StoredCall,
    worker: WorkerLease,
    command: CallCommand,
    at: DateTime<Utc>,
) -> StoredCall {
    let outcome = repository
        .commit_with_effect_payloads(ServiceCommandTransaction {
            command: CommandCommit {
                tenant_id: call.aggregate.tenant_id().clone(),
                call_id: call.aggregate.id(),
                expected_version: call.aggregate.version(),
                command_id: CommandId::new(),
                command,
                worker,
                attachments: Vec::new(),
                deadline_claim: None,
                at,
            },
            effect_payloads: Vec::new(),
        })
        .await
        .unwrap();
    match outcome {
        ServiceCommandOutcome::Committed(view) | ServiceCommandOutcome::Replayed(view) => {
            view.command.call
        }
    }
}

struct ActiveFixture {
    owner: TenantId,
    worker: WorkerLease,
    service_call: StoredServiceCall,
    outbound_bind: OutboundConnectionBind,
}

async fn active_fixture(key: u8) -> (MemoryRepository, ActiveFixture) {
    let repository = MemoryRepository::new();
    let worker = register(&repository, 8).await;
    let owner = tenant(&format!("active-{key}"));
    let (request, attachment_digest) = sip_webrtc_create(owner.clone(), worker, key);
    let service_call = created(repository.create_with_plan(request).await.unwrap());
    let inbound_leg = service_call.call.aggregate.legs()[0].id();
    let outbound_leg = service_call.call.aggregate.legs()[1].id();

    let candidate = repository
        .inspect_attachment(AttachmentLookup {
            token_digest: attachment_digest,
            tenant_id: owner.clone(),
            transport: AttachmentTransport::Sip,
            principal_fingerprint: principal(1),
            worker,
            at: at(3),
        })
        .await
        .unwrap();
    let consumed = repository
        .consume_attachment(AttachmentConsume {
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at: at(3),
                leg_id: inbound_leg,
                binding_generation: BindingGeneration::INITIAL,
                state: LegState::Signaling,
                failure: None,
            },
            candidate,
            connection_id: ConnectionId::from_string(format!("inbound-{key}")),
            principal_fingerprint: principal(1),
            at: at(3),
        })
        .await
        .unwrap();
    let outbound_bind = OutboundConnectionBind {
        operation_id: CommandId::new(),
        tenant_id: owner.clone(),
        call_id: service_call.call.aggregate.id(),
        leg_id: outbound_leg,
        binding_generation: BindingGeneration::INITIAL,
        worker,
        connection_id: ConnectionId::from_string(format!("outbound-{key}")),
        transport: AttachmentTransport::WebRtc,
        principal_fingerprint: principal(2),
        at: at(4),
    };
    assert!(matches!(
        repository
            .bind_outbound_connection(outbound_bind.clone())
            .await
            .unwrap(),
        OutboundConnectionBindOutcome::Bound(_)
    ));

    let mut call = consumed.commit.call;
    call = service_command(
        &repository,
        &call,
        worker,
        CallCommand::SetLegState {
            at: at(5),
            leg_id: outbound_leg,
            binding_generation: BindingGeneration::INITIAL,
            state: LegState::Signaling,
            failure: None,
        },
        at(5),
    )
    .await;
    call = service_command(
        &repository,
        &call,
        worker,
        CallCommand::SetLegState {
            at: at(6),
            leg_id: inbound_leg,
            binding_generation: BindingGeneration::INITIAL,
            state: LegState::Connected,
            failure: None,
        },
        at(6),
    )
    .await;
    call = service_command(
        &repository,
        &call,
        worker,
        CallCommand::SetLegState {
            at: at(7),
            leg_id: outbound_leg,
            binding_generation: BindingGeneration::INITIAL,
            state: LegState::Connected,
            failure: None,
        },
        at(7),
    )
    .await;
    assert_eq!(call.aggregate.state(), CallState::Active);
    (
        repository,
        ActiveFixture {
            owner,
            worker,
            service_call: StoredServiceCall {
                call,
                plan: service_call.plan,
            },
            outbound_bind,
        },
    )
}

#[tokio::test]
async fn create_plan_validation_is_atomic_and_replay_returns_original_plan() {
    let repository = MemoryRepository::new();
    let worker = register(&repository, 1).await;
    let owner = tenant("plan-owner");
    let (request, _) = sip_webrtc_create(owner.clone(), worker, 10);
    let original_plan = request.plan.clone();

    let mut unsupported = request.clone();
    unsupported.plan.version = 99;
    assert_eq!(
        repository.create_with_plan(unsupported).await,
        Err(RepositoryError::InvalidInput(
            "unsupported call execution plan version"
        ))
    );
    assert_eq!(
        repository
            .worker_snapshot(worker.worker_id)
            .await
            .unwrap()
            .reserved_calls,
        0
    );

    let duplicate = [original_plan.legs[0].clone(), original_plan.legs[0].clone()];
    assert!(CallExecutionPlan::new(&request.create.initial, duplicate).is_err());
    let mut wrong_kind = original_plan.legs.clone();
    wrong_kind[1].endpoint = LegEndpointConfig::AmazonConnect(AmazonConnectEndpointConfig {
        instance_id: "instance".to_owned(),
        contact_flow_id: "flow".to_owned(),
    });
    assert!(CallExecutionPlan::new(&request.create.initial, wrong_kind).is_err());
    let mut missing_outbound = original_plan.legs.clone();
    missing_outbound[1].endpoint = LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
        signaling_uri: None,
    });
    assert!(CallExecutionPlan::new(&request.create.initial, missing_outbound).is_err());

    let created = created(repository.create_with_plan(request.clone()).await.unwrap());
    assert_eq!(created.plan, original_plan);
    let mut alternate = request;
    alternate.plan.legs[1].endpoint = LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
        signaling_uri: Some("wss://alternate.example.test/session".to_owned()),
    });
    assert!(matches!(
        repository.create_with_plan(alternate).await.unwrap(),
        ServiceCreateOutcome::Replayed(ref replayed) if replayed.plan == original_plan
    ));
    assert_eq!(
        repository
            .load_service_call(&owner, created.call.aggregate.id())
            .await
            .unwrap()
            .plan,
        original_plan
    );
}

#[tokio::test]
async fn transfer_payload_is_ordinal_bound_atomic_and_exactly_replayed() {
    let (repository, fixture) = active_fixture(20).await;
    let before = fixture.service_call.call.clone();
    let command_id = CommandId::new();
    let transfer = |ordinal, destination: &str| ServiceCommandTransaction {
        command: CommandCommit {
            tenant_id: fixture.owner.clone(),
            call_id: before.aggregate.id(),
            expected_version: before.aggregate.version(),
            command_id,
            command: CallCommand::BeginTransfer {
                at: at(10),
                transfer_deadline: at(40),
            },
            worker: fixture.worker,
            attachments: Vec::new(),
            deadline_claim: None,
            at: at(10),
        },
        effect_payloads: vec![ServiceEffectPayloadInput {
            ordinal,
            payload: ServiceEffectPayload::Transfer {
                target: TransferTarget::Sip {
                    uri: destination.to_owned(),
                },
            },
        }],
    };

    assert_eq!(
        repository
            .commit_with_effect_payloads(transfer(0, "sip:alice@example.test"))
            .await,
        Err(RepositoryError::InvalidInput(
            "service payload ordinal does not target a compatible effect"
        ))
    );
    assert_eq!(
        repository
            .load_call(&fixture.owner, before.aggregate.id())
            .await
            .unwrap(),
        before
    );

    let request = transfer(1, "sip:alice@example.test");
    let committed = repository
        .commit_with_effect_payloads(request.clone())
        .await
        .unwrap();
    let ServiceCommandOutcome::Committed(view) = committed else {
        panic!("expected committed transfer")
    };
    assert_eq!(view.effect_payloads.len(), 1);
    assert_eq!(view.effect_payloads[0].ordinal, 1);
    assert!(matches!(
        view.command.outbox[1].intent,
        EffectIntent::ExecuteTransfer { .. }
    ));
    assert_eq!(
        repository
            .load_effect_payload(&fixture.owner, view.command.outbox[1].effect_id)
            .await
            .unwrap(),
        Some(view.effect_payloads[0].clone())
    );
    assert!(matches!(
        repository
            .commit_with_effect_payloads(request)
            .await
            .unwrap(),
        ServiceCommandOutcome::Replayed(ref replayed) if replayed == &view
    ));
    assert_eq!(
        repository
            .commit_with_effect_payloads(transfer(1, "sip:bob@example.test"))
            .await,
        Err(RepositoryError::CommandConflict)
    );
}

#[tokio::test]
async fn dtmf_control_is_fenced_claimed_completed_failed_and_replayed() {
    let (repository, fixture) = active_fixture(30).await;
    let leg = fixture.service_call.call.aggregate.legs()[1].id();
    let request = ControlCommandTransaction {
        command_id: CommandId::new(),
        tenant_id: fixture.owner.clone(),
        call_id: fixture.service_call.call.aggregate.id(),
        leg_id: leg,
        binding_generation: BindingGeneration::INITIAL,
        worker: fixture.worker,
        intent: ControlIntent::Dtmf {
            sequence: DtmfSequence {
                digits: "12#A".to_owned(),
                duration_ms: 120,
                gap_ms: 80,
            },
        },
        at: at(10),
    };
    let ControlCommandOutcome::Enqueued(view) =
        repository.enqueue_control(request.clone()).await.unwrap()
    else {
        panic!("expected enqueued control")
    };
    assert!(!format!("{view:?}").contains("12#A"));
    assert!(matches!(
        repository.enqueue_control(request).await.unwrap(),
        ControlCommandOutcome::Replayed(ref replayed) if replayed == &view
    ));

    let invalid = ControlCommandTransaction {
        command_id: CommandId::new(),
        intent: ControlIntent::Dtmf {
            sequence: DtmfSequence {
                digits: "not-dtmf".to_owned(),
                duration_ms: 120,
                gap_ms: 80,
            },
        },
        ..view_to_request(&view)
    };
    assert_eq!(
        repository.enqueue_control(invalid).await,
        Err(RepositoryError::InvalidInput("invalid DTMF digits"))
    );

    let claim = repository
        .claim_control_effects(fixture.worker, at(11), Duration::from_secs(10), 8)
        .await
        .unwrap()
        .into_iter()
        .find(|claim| claim.record.effect_id == view.effect.effect_id)
        .unwrap();
    let mut success = EffectResultReconciliation {
        tenant_id: fixture.owner.clone(),
        call_id: fixture.service_call.call.aggregate.id(),
        effect_id: claim.record.effect_id,
        worker: fixture.worker,
        claim_generation: claim.claim_generation,
        result: ServiceEffectResult::Succeeded,
        external_reference: None,
        follow_up: None,
        at: at(12),
    };
    let mut wrong_tenant = success.clone();
    wrong_tenant.tenant_id = tenant("other-tenant");
    assert_eq!(
        repository.reconcile_effect_result(wrong_tenant).await,
        Err(RepositoryError::StaleClaim)
    );
    let mut wrong_generation = success.clone();
    wrong_generation.claim_generation = Default::default();
    assert_eq!(
        repository.reconcile_effect_result(wrong_generation).await,
        Err(RepositoryError::StaleClaim)
    );
    let other_worker = register(&repository, 1).await;
    let mut wrong_worker = success.clone();
    wrong_worker.worker = other_worker;
    assert_eq!(
        repository.reconcile_effect_result(wrong_worker).await,
        Err(RepositoryError::StaleClaim)
    );

    let EffectResultOutcome::Reconciled(completed) = repository
        .reconcile_effect_result(success.clone())
        .await
        .unwrap()
    else {
        panic!("expected first reconciliation")
    };
    assert!(matches!(
        completed.effect,
        CompletedServiceEffect::Control(ref record)
            if matches!(record.state, bridgefu::call_engine::OutboxState::Succeeded { .. })
    ));
    assert!(matches!(
        repository
            .reconcile_effect_result(success.clone())
            .await
            .unwrap(),
        EffectResultOutcome::Replayed(ref replayed) if replayed == &completed
    ));
    success.result = ServiceEffectResult::Failed(FailureDetails::sanitized(
        "late_failure",
        "late failure",
        false,
    ));
    assert_eq!(
        repository.reconcile_effect_result(success).await,
        Err(RepositoryError::StaleClaim)
    );

    let failure_request = ControlCommandTransaction {
        command_id: CommandId::new(),
        at: at(13),
        ..view_to_request(&view)
    };
    let ControlCommandOutcome::Enqueued(failure_view) =
        repository.enqueue_control(failure_request).await.unwrap()
    else {
        panic!("expected second control")
    };
    let failure_claim = repository
        .claim_control_effects(fixture.worker, at(14), Duration::from_secs(10), 8)
        .await
        .unwrap()
        .into_iter()
        .find(|claim| claim.record.effect_id == failure_view.effect.effect_id)
        .unwrap();
    let failed = repository
        .reconcile_effect_result(EffectResultReconciliation {
            tenant_id: fixture.owner,
            call_id: fixture.service_call.call.aggregate.id(),
            effect_id: failure_claim.record.effect_id,
            worker: fixture.worker,
            claim_generation: failure_claim.claim_generation,
            result: ServiceEffectResult::Failed(FailureDetails::sanitized(
                "dtmf_failed",
                "DTMF failed",
                true,
            )),
            external_reference: None,
            follow_up: None,
            at: at(15),
        })
        .await
        .unwrap();
    assert!(matches!(
        failed,
        EffectResultOutcome::Reconciled(ref result)
            if matches!(
                result.effect,
                CompletedServiceEffect::Control(ref record)
                    if matches!(record.state, bridgefu::call_engine::OutboxState::Failed { .. })
            )
    ));
}

fn view_to_request(view: &bridgefu::call_service::ControlCommandView) -> ControlCommandTransaction {
    ControlCommandTransaction {
        command_id: view.command.command_id,
        tenant_id: view.command.tenant_id.clone(),
        call_id: view.command.call_id,
        leg_id: view.command.leg_id,
        binding_generation: view.command.binding_generation,
        worker: view.command.worker,
        intent: view.command.intent.clone(),
        at: view.command.recorded_at,
    }
}

#[tokio::test]
async fn control_claim_is_recovered_by_a_new_worker_fence() {
    let (repository, fixture) = active_fixture(35).await;
    let leg = fixture.service_call.call.aggregate.legs()[1].id();
    let ControlCommandOutcome::Enqueued(view) = repository
        .enqueue_control(ControlCommandTransaction {
            command_id: CommandId::new(),
            tenant_id: fixture.owner.clone(),
            call_id: fixture.service_call.call.aggregate.id(),
            leg_id: leg,
            binding_generation: BindingGeneration::INITIAL,
            worker: fixture.worker,
            intent: ControlIntent::Dtmf {
                sequence: DtmfSequence {
                    digits: "9".to_owned(),
                    duration_ms: 100,
                    gap_ms: 50,
                },
            },
            at: at(10),
        })
        .await
        .unwrap()
    else {
        panic!("expected control effect")
    };
    let old_claim = repository
        .claim_control_effects(fixture.worker, at(11), Duration::from_secs(30), 1)
        .await
        .unwrap()
        .remove(0);
    let newer = repository
        .register_worker(RegisterWorker {
            worker_id: fixture.worker.worker_id,
            max_calls: 8,
            capabilities: BTreeSet::from([
                "sip".to_owned(),
                "webrtc".to_owned(),
                "twilio".to_owned(),
            ]),
            at: at(12),
        })
        .await
        .unwrap()
        .lease;
    assert_eq!(
        repository
            .reconcile_effect_result(EffectResultReconciliation {
                tenant_id: fixture.owner.clone(),
                call_id: fixture.service_call.call.aggregate.id(),
                effect_id: old_claim.record.effect_id,
                worker: fixture.worker,
                claim_generation: old_claim.claim_generation,
                result: ServiceEffectResult::Succeeded,
                external_reference: None,
                follow_up: None,
                at: at(13),
            })
            .await,
        Err(RepositoryError::StaleWorkerFence)
    );
    assert_eq!(
        repository
            .claim_restart_calls(newer, at(13), 1)
            .await
            .unwrap()
            .len(),
        1
    );
    let recovered = repository
        .claim_control_effects(newer, at(14), Duration::from_secs(10), 1)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(recovered.record.effect_id, view.effect.effect_id);
    assert!(matches!(
        repository
            .reconcile_effect_result(EffectResultReconciliation {
                tenant_id: fixture.owner,
                call_id: fixture.service_call.call.aggregate.id(),
                effect_id: recovered.record.effect_id,
                worker: newer,
                claim_generation: recovered.claim_generation,
                result: ServiceEffectResult::Succeeded,
                external_reference: None,
                follow_up: None,
                at: at(15),
            })
            .await
            .unwrap(),
        EffectResultOutcome::Reconciled(_)
    ));
}

#[tokio::test]
async fn outbound_binding_enforces_ownership_generation_replay_and_permanent_id_uniqueness() {
    let (repository, fixture) = active_fixture(40).await;
    assert!(matches!(
        repository
            .bind_outbound_connection(fixture.outbound_bind.clone())
            .await
            .unwrap(),
        OutboundConnectionBindOutcome::Replayed(_)
    ));

    let mut wrong_tenant = fixture.outbound_bind.clone();
    wrong_tenant.operation_id = CommandId::new();
    wrong_tenant.tenant_id = tenant("wrong-owner");
    wrong_tenant.connection_id = ConnectionId::from_string("wrong-tenant-connection");
    assert_eq!(
        repository.bind_outbound_connection(wrong_tenant).await,
        Err(RepositoryError::NotFound)
    );

    let mut wrong_leg = fixture.outbound_bind.clone();
    wrong_leg.operation_id = CommandId::new();
    wrong_leg.leg_id = fixture.service_call.call.aggregate.legs()[0].id();
    wrong_leg.transport = AttachmentTransport::Sip;
    wrong_leg.connection_id = ConnectionId::from_string("wrong-leg-connection");
    assert_eq!(
        repository.bind_outbound_connection(wrong_leg).await,
        Err(RepositoryError::InvalidInput(
            "outbound binding requires an outbound leg"
        ))
    );

    let mut wrong_generation = fixture.outbound_bind.clone();
    wrong_generation.operation_id = CommandId::new();
    wrong_generation.binding_generation = serde_json::from_value(serde_json::json!(999)).unwrap();
    wrong_generation.connection_id = ConnectionId::from_string("wrong-generation-connection");
    assert_eq!(
        repository.bind_outbound_connection(wrong_generation).await,
        Err(RepositoryError::StaleClaim)
    );

    let ended = service_command(
        &repository,
        &fixture.service_call.call,
        fixture.worker,
        CallCommand::SetLegState {
            at: at(20),
            leg_id: fixture.service_call.call.aggregate.legs()[1].id(),
            binding_generation: BindingGeneration::INITIAL,
            state: LegState::Ended,
            failure: None,
        },
        at(20),
    )
    .await;
    assert!(!ended
        .bindings
        .contains_key(&fixture.service_call.call.aggregate.legs()[1].id()));

    let second_owner = tenant("second-owner");
    let (second_request, _) = sip_webrtc_create(second_owner.clone(), fixture.worker, 41);
    let second = created(repository.create_with_plan(second_request).await.unwrap());
    let reused = OutboundConnectionBind {
        operation_id: CommandId::new(),
        tenant_id: second_owner,
        call_id: second.call.aggregate.id(),
        leg_id: second.call.aggregate.legs()[1].id(),
        binding_generation: BindingGeneration::INITIAL,
        worker: fixture.worker,
        connection_id: fixture.outbound_bind.connection_id,
        transport: AttachmentTransport::WebRtc,
        principal_fingerprint: principal(9),
        at: at(21),
    };
    assert_eq!(
        repository.bind_outbound_connection(reused).await,
        Err(RepositoryError::AttachmentConflict)
    );
}

#[tokio::test]
async fn reconciliation_atomically_releases_callback_binds_reference_and_commits_follow_up() {
    let repository = MemoryRepository::new();
    let worker = register(&repository, 2).await;
    let owner = tenant("provider-owner");
    let service_call = created(
        repository
            .create_with_plan(provider_create(owner.clone(), worker, 50))
            .await
            .unwrap(),
    );
    let provider_leg = service_call.call.aggregate.legs()[0].id();
    let account = ProviderAccountKey::parse("twilio-sandbox").unwrap();
    let provider_call_id = ProviderCallId::parse("CA-before-reference").unwrap();
    let event_input = ProviderEventInput {
        account: account.clone(),
        event_digest: ProviderEventDigest::new(digest(50)),
        payload_digest: ProviderPayloadDigest::new(digest(51)),
        provider_call_id: provider_call_id.clone(),
        kind: "ringing".to_owned(),
        payload: serde_json::json!({"state": "ringing"}),
        occurred_at: Some(at(5)),
        received_at: at(6),
    };
    assert!(matches!(
        repository
            .ingest_provider_event(event_input.clone())
            .await
            .unwrap(),
        ProviderEventOutcome::Accepted(ref event)
            if event.state == ProviderEventState::PendingReference
    ));

    let claim = repository
        .claim_outbox(worker, at(7), Duration::from_secs(30), 1)
        .await
        .unwrap()
        .remove(0);
    assert!(matches!(
        claim.record.intent,
        EffectIntent::StartLeg { leg_id, .. } if leg_id == provider_leg
    ));
    let correct_follow_up = ServiceCommandTransaction {
        command: CommandCommit {
            tenant_id: owner.clone(),
            call_id: service_call.call.aggregate.id(),
            expected_version: service_call.call.aggregate.version(),
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at: at(8),
                leg_id: provider_leg,
                binding_generation: BindingGeneration::INITIAL,
                state: LegState::Signaling,
                failure: None,
            },
            worker,
            attachments: Vec::new(),
            deadline_claim: None,
            at: at(8),
        },
        effect_payloads: Vec::new(),
    };
    let base = EffectResultReconciliation {
        tenant_id: owner.clone(),
        call_id: service_call.call.aggregate.id(),
        effect_id: claim.record.effect_id,
        worker,
        claim_generation: claim.claim_generation,
        result: ServiceEffectResult::Succeeded,
        external_reference: Some(ExternalReferenceBinding {
            leg_id: provider_leg,
            binding_generation: BindingGeneration::INITIAL,
            value: ExternalReferenceValue::ProviderCall {
                account: account.clone(),
                provider_call_id: provider_call_id.clone(),
            },
        }),
        follow_up: Some(correct_follow_up.clone()),
        at: at(8),
    };

    let mut wrong_tenant = base.clone();
    wrong_tenant.tenant_id = tenant("not-owner");
    assert_eq!(
        repository.reconcile_effect_result(wrong_tenant).await,
        Err(RepositoryError::StaleClaim)
    );
    let mut wrong_generation = base.clone();
    wrong_generation.claim_generation = Default::default();
    assert_eq!(
        repository.reconcile_effect_result(wrong_generation).await,
        Err(RepositoryError::StaleClaim)
    );

    let mut crash_window = base.clone();
    crash_window
        .follow_up
        .as_mut()
        .unwrap()
        .command
        .expected_version =
        serde_json::from_value::<AggregateVersion>(serde_json::json!(999)).unwrap();
    assert_eq!(
        repository.reconcile_effect_result(crash_window).await,
        Err(RepositoryError::VersionConflict)
    );
    assert!(repository
        .load_external_reference(&owner, service_call.call.aggregate.id(), provider_leg)
        .await
        .unwrap()
        .is_none());
    assert!(matches!(
        repository
            .ingest_provider_event(event_input.clone())
            .await
            .unwrap(),
        ProviderEventOutcome::Duplicate(ref event)
            if event.state == ProviderEventState::PendingReference
    ));
    assert!(repository
        .claim_provider_events(worker, at(8), Duration::from_secs(5), 8)
        .await
        .unwrap()
        .is_empty());

    let EffectResultOutcome::Reconciled(view) = repository
        .reconcile_effect_result(base.clone())
        .await
        .unwrap()
    else {
        panic!("expected reconciliation")
    };
    assert_eq!(view.released_provider_events.len(), 1);
    assert_eq!(
        view.released_provider_events[0].state,
        ProviderEventState::Ready
    );
    assert!(view.external_reference.is_some());
    assert!(matches!(
        view.effect,
        CompletedServiceEffect::Call(ref effect)
            if matches!(effect.state, bridgefu::call_engine::OutboxState::Succeeded { .. })
    ));
    assert_eq!(
        view.follow_up
            .as_ref()
            .unwrap()
            .command
            .call
            .aggregate
            .legs()[0]
            .state(),
        LegState::Signaling
    );
    assert!(repository
        .load_external_reference(&owner, service_call.call.aggregate.id(), provider_leg)
        .await
        .unwrap()
        .is_some());
    assert!(matches!(
        repository
            .reconcile_effect_result(base.clone())
            .await
            .unwrap(),
        EffectResultOutcome::Replayed(ref replayed) if replayed == &view
    ));
    let mut mismatch = base;
    mismatch.at = at(9);
    assert_eq!(
        repository.reconcile_effect_result(mismatch).await,
        Err(RepositoryError::StaleClaim)
    );

    let ready = repository
        .claim_provider_events(worker, at(9), Duration::from_secs(5), 8)
        .await
        .unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(
        ready[0].event.state,
        ProviderEventState::Claimed {
            worker,
            generation: ready[0].claim_generation,
            claimed_at: at(9),
            expires_at: at(14),
        }
    );
}
