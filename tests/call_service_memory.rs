use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use bridgefu::call_engine::{
    AggregateVersion, AttachmentConsume, AttachmentId, AttachmentIssue, AttachmentLookup,
    AttachmentTokenDigest, AttachmentTransport, BindProviderReference, BindingGeneration,
    CallAggregate, CallCommand, CallRepository, CallState, CommandCommit, CommandId, CreateCall,
    EffectIntent, FailureDetails, IdempotencyKeyDigest, LegDirection, LegKind, LegSpec, LegState,
    OutboxCompletion, PrincipalFingerprint, ProviderAccountKey, ProviderCallId,
    ProviderEventCommit, ProviderEventDigest, ProviderEventInput, ProviderEventOutcome,
    ProviderEventState, ProviderPayloadDigest, RegisterWorker, RepositoryError, RequestDigest,
    StopLegReason, StoredCall, TenantId, WorkerLease,
};
use bridgefu::call_service::{
    AmazonConnectEndpointConfig, CallExecutionPlan, CallServiceRepository, CompletedServiceEffect,
    ControlCommandOutcome, ControlCommandTransaction, ControlIntent, DtmfSequence,
    EffectResultOutcome, EffectResultReconciliation, ExternalReferenceBinding,
    ExternalReferenceValue, LegEndpointConfig, LegExecutionSpec, OperationIdempotency,
    OutboundConnectionBind, OutboundConnectionBindOutcome, ProviderEndpointConfig, ProviderKind,
    ServiceCommandOutcome, ServiceCommandTransaction, ServiceCreateOutcome,
    ServiceCreateTransaction, ServiceEffectPayload, ServiceEffectPayloadInput, ServiceEffectResult,
    ServiceOperationKind, SipEndpointConfig, StoredServiceCall, TransferTarget,
    WebRtcEndpointConfig,
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

fn operation_idempotency(
    key: u8,
    request: u8,
    operation: ServiceOperationKind,
) -> OperationIdempotency {
    OperationIdempotency {
        key_digest: IdempotencyKeyDigest::new(digest(key)),
        request_digest: RequestDigest::new(digest(request)),
        operation,
    }
}

#[test]
fn operation_idempotency_debug_redacts_both_digests() {
    let claim = OperationIdempotency {
        key_digest: IdempotencyKeyDigest::new([0xab; 32]),
        request_digest: RequestDigest::new([0xcd; 32]),
        operation: ServiceOperationKind::TransferCall,
    };
    let rendered = format!("{claim:?}");
    assert!(rendered.contains("[redacted]"));
    assert!(!rendered.contains("171"));
    assert!(!rendered.contains("205"));
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
            operation_idempotency: None,
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
                attachments: service_call.attachments,
            },
            outbound_bind,
        },
    )
}

fn transfer_operation(
    fixture: &ActiveFixture,
    key: u8,
    request_digest: u8,
    second: i64,
    destination: &str,
    ordinal: u32,
) -> ServiceCommandTransaction {
    ServiceCommandTransaction {
        command: CommandCommit {
            tenant_id: fixture.owner.clone(),
            call_id: fixture.service_call.call.aggregate.id(),
            expected_version: fixture.service_call.call.aggregate.version(),
            command_id: CommandId::new(),
            command: CallCommand::BeginTransfer {
                at: at(second),
                transfer_deadline: at(second + 30),
            },
            worker: fixture.worker,
            attachments: Vec::new(),
            deadline_claim: None,
            at: at(second),
        },
        effect_payloads: vec![ServiceEffectPayloadInput {
            ordinal,
            payload: ServiceEffectPayload::Transfer {
                target: TransferTarget::Sip {
                    uri: destination.to_owned(),
                },
            },
        }],
        operation_idempotency: Some(operation_idempotency(
            key,
            request_digest,
            ServiceOperationKind::TransferCall,
        )),
    }
}

fn dtmf_operation(
    fixture: &ActiveFixture,
    key: u8,
    request_digest: u8,
    second: i64,
    digits: &str,
) -> ControlCommandTransaction {
    ControlCommandTransaction {
        command_id: CommandId::new(),
        tenant_id: fixture.owner.clone(),
        call_id: fixture.service_call.call.aggregate.id(),
        leg_id: fixture.service_call.call.aggregate.legs()[1].id(),
        binding_generation: BindingGeneration::INITIAL,
        worker: fixture.worker,
        intent: ControlIntent::Dtmf {
            sequence: DtmfSequence {
                digits: digits.to_owned(),
                duration_ms: 100,
                gap_ms: 50,
            },
        },
        at: at(second),
        operation_idempotency: Some(operation_idempotency(
            key,
            request_digest,
            ServiceOperationKind::DtmfCall,
        )),
    }
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
    let outbound_leg = created.call.aggregate.legs()[1].id();
    let advanced = service_command(
        &repository,
        &created.call,
        worker,
        CallCommand::SetLegState {
            at: at(3),
            leg_id: outbound_leg,
            binding_generation: BindingGeneration::INITIAL,
            state: LegState::Signaling,
            failure: None,
        },
        at(3),
    )
    .await;
    assert!(advanced.aggregate.version() > created.call.aggregate.version());
    let mut alternate = request;
    alternate.plan.legs[1].endpoint = LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
        signaling_uri: Some("wss://alternate.example.test/session".to_owned()),
    });
    let ServiceCreateOutcome::Replayed(replayed) =
        repository.create_with_plan(alternate).await.unwrap()
    else {
        panic!("expected replayed create")
    };
    assert_eq!(replayed.plan, original_plan);
    assert_eq!(replayed.call, created.call);
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
        operation_idempotency: None,
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
async fn operation_idempotency_replays_original_before_time_and_cas_evaluation() {
    let (repository, fixture) = active_fixture(21).await;
    let before = fixture.service_call.call.clone();
    let first = ServiceCommandTransaction {
        command: CommandCommit {
            tenant_id: fixture.owner.clone(),
            call_id: before.aggregate.id(),
            expected_version: before.aggregate.version(),
            command_id: CommandId::new(),
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
            ordinal: 1,
            payload: ServiceEffectPayload::Transfer {
                target: TransferTarget::Sip {
                    uri: "sip:replay@example.test".to_owned(),
                },
            },
        }],
        operation_idempotency: Some(operation_idempotency(
            201,
            202,
            ServiceOperationKind::TransferCall,
        )),
    };
    let ServiceCommandOutcome::Committed(original) = repository
        .commit_with_effect_payloads(first.clone())
        .await
        .unwrap()
    else {
        panic!("expected first operation commit")
    };

    let mut retry = first;
    retry.command.command_id = CommandId::new();
    retry.command.expected_version = original.command.call.aggregate.version();
    retry.command.command = CallCommand::BeginTransfer {
        at: at(20),
        transfer_deadline: at(50),
    };
    retry.command.at = at(20);
    assert!(matches!(
        repository
            .commit_with_effect_payloads(retry)
            .await
            .unwrap(),
        ServiceCommandOutcome::Replayed(ref replayed) if replayed == &original
    ));
}

#[tokio::test]
async fn operation_idempotency_conflicts_across_body_kind_and_create_receipt() {
    let (repository, fixture) = active_fixture(22).await;
    let original = transfer_operation(&fixture, 210, 211, 10, "sip:original@example.test", 1);
    repository
        .commit_with_effect_payloads(original)
        .await
        .unwrap();

    let changed_body = transfer_operation(&fixture, 210, 212, 11, "sip:changed@example.test", 1);
    assert_eq!(
        repository.commit_with_effect_payloads(changed_body).await,
        Err(RepositoryError::IdempotencyConflict)
    );

    let wrong_kind = ServiceCommandTransaction {
        command: CommandCommit {
            tenant_id: fixture.owner.clone(),
            call_id: fixture.service_call.call.aggregate.id(),
            expected_version: fixture.service_call.call.aggregate.version(),
            command_id: CommandId::new(),
            command: CallCommand::BeginEnding {
                at: at(12),
                ending_deadline: Some(at(42)),
                reason: StopLegReason::Requested,
            },
            worker: fixture.worker,
            attachments: Vec::new(),
            deadline_claim: None,
            at: at(12),
        },
        effect_payloads: Vec::new(),
        operation_idempotency: Some(operation_idempotency(
            210,
            211,
            ServiceOperationKind::HangupCall,
        )),
    };
    assert_eq!(
        repository.commit_with_effect_payloads(wrong_kind).await,
        Err(RepositoryError::IdempotencyConflict)
    );

    // The active fixture's call creation retained key digest 22. A later
    // operation cannot reuse that key even with a different receipt family.
    assert_eq!(
        repository
            .commit_with_effect_payloads(transfer_operation(
                &fixture,
                22,
                213,
                13,
                "sip:create-key@example.test",
                1,
            ))
            .await,
        Err(RepositoryError::IdempotencyConflict)
    );
}

#[tokio::test]
async fn failed_operation_rolls_back_receipt_and_allows_corrected_retry() {
    let (repository, fixture) = active_fixture(23).await;
    let before = repository.counts().unwrap();
    let invalid = transfer_operation(&fixture, 214, 215, 10, "sip:rollback@example.test", 0);
    assert_eq!(
        repository.commit_with_effect_payloads(invalid).await,
        Err(RepositoryError::InvalidInput(
            "service payload ordinal does not target a compatible effect"
        ))
    );
    assert_eq!(repository.counts().unwrap(), before);

    assert!(matches!(
        repository
            .commit_with_effect_payloads(transfer_operation(
                &fixture,
                214,
                215,
                11,
                "sip:rollback@example.test",
                1,
            ))
            .await
            .unwrap(),
        ServiceCommandOutcome::Committed(_)
    ));
    assert_eq!(
        repository.counts().unwrap().idempotency,
        before.idempotency + 1
    );
}

#[tokio::test]
async fn operation_idempotency_is_atomic_under_concurrent_same_key_delivery() {
    let (repository, fixture) = active_fixture(24).await;
    let repository = Arc::new(repository);
    let mut tasks = Vec::new();
    for delivery in 0..32_i64 {
        let repository = Arc::clone(&repository);
        let request = transfer_operation(
            &fixture,
            216,
            217,
            10 + delivery,
            "sip:concurrent@example.test",
            1,
        );
        tasks.push(tokio::spawn(async move {
            repository.commit_with_effect_payloads(request).await
        }));
    }

    let mut committed = 0;
    let mut replayed = 0;
    let mut views = Vec::new();
    for task in tasks {
        match task.await.unwrap().unwrap() {
            ServiceCommandOutcome::Committed(view) => {
                committed += 1;
                views.push(view);
            }
            ServiceCommandOutcome::Replayed(view) => {
                replayed += 1;
                views.push(view);
            }
        }
    }
    assert_eq!(committed, 1);
    assert_eq!(replayed, 31);
    assert!(views.windows(2).all(|pair| pair[0] == pair[1]));
}

#[tokio::test]
async fn service_managed_calls_reject_raw_mutation_completion_and_reference_bypasses() {
    let (repository, fixture) = active_fixture(25).await;
    let call = &fixture.service_call.call;
    assert_eq!(
        repository
            .commit_command(CommandCommit {
                tenant_id: fixture.owner.clone(),
                call_id: call.aggregate.id(),
                expected_version: call.aggregate.version(),
                command_id: CommandId::new(),
                command: CallCommand::BeginTransfer {
                    at: at(10),
                    transfer_deadline: at(40),
                },
                worker: fixture.worker,
                attachments: Vec::new(),
                deadline_claim: None,
                at: at(10),
            })
            .await,
        Err(RepositoryError::InvalidInput(
            "service-managed call requires service repository transaction"
        ))
    );

    let claim = repository
        .claim_outbox(fixture.worker, at(10), Duration::from_secs(10), 1)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(
        repository
            .complete_outbox(
                claim.record.effect_id,
                fixture.worker,
                claim.claim_generation,
                OutboxCompletion::Succeeded,
                at(11),
            )
            .await,
        Err(RepositoryError::InvalidInput(
            "service-managed effect requires service reconciliation"
        ))
    );

    assert_eq!(
        repository
            .bind_provider_reference(BindProviderReference {
                tenant_id: fixture.owner.clone(),
                call_id: call.aggregate.id(),
                leg_id: call.aggregate.legs()[1].id(),
                account: ProviderAccountKey::parse("unexpected-account").unwrap(),
                provider_call_id: ProviderCallId::parse("unexpected-call").unwrap(),
                worker: fixture.worker,
                at: at(11),
            })
            .await,
        Err(RepositoryError::InvalidInput(
            "service-managed call requires service repository transaction"
        ))
    );

    assert_eq!(
        repository
            .enqueue_control(ControlCommandTransaction {
                command_id: CommandId::new(),
                tenant_id: fixture.owner.clone(),
                call_id: call.aggregate.id(),
                leg_id: call.aggregate.legs()[1].id(),
                binding_generation: BindingGeneration::INITIAL,
                worker: fixture.worker,
                intent: ControlIntent::Dtmf {
                    sequence: DtmfSequence {
                        digits: "1".to_owned(),
                        duration_ms: 100,
                        gap_ms: 50,
                    },
                },
                at: at(6),
                operation_idempotency: None,
            })
            .await,
        Err(RepositoryError::InvalidInput(
            "control time predates its current binding"
        ))
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
        operation_idempotency: None,
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
    let mut before_available = success.clone();
    before_available.at = at(9);
    assert_eq!(
        repository.reconcile_effect_result(before_available).await,
        Err(RepositoryError::StaleClaim)
    );
    let mut before_claim = success.clone();
    before_claim.at = at(10);
    assert_eq!(
        repository.reconcile_effect_result(before_claim).await,
        Err(RepositoryError::StaleClaim)
    );
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

#[tokio::test]
async fn control_operation_replays_expires_and_conflicts_with_other_receipt_kinds() {
    let (repository, fixture) = active_fixture(31).await;
    let first_request = dtmf_operation(&fixture, 218, 219, 10, "1");
    let ControlCommandOutcome::Enqueued(original) = repository
        .enqueue_control(first_request.clone())
        .await
        .unwrap()
    else {
        panic!("expected first DTMF operation")
    };
    let retained_after_first = repository.counts().unwrap().idempotency;

    let mut retry = first_request;
    retry.command_id = CommandId::new();
    retry.at = at(20);
    assert!(matches!(
        repository.enqueue_control(retry).await.unwrap(),
        ControlCommandOutcome::Replayed(ref replayed) if replayed == &original
    ));

    assert_eq!(
        repository
            .enqueue_control(dtmf_operation(&fixture, 218, 220, 21, "2"))
            .await,
        Err(RepositoryError::IdempotencyConflict)
    );
    assert_eq!(
        repository
            .commit_with_effect_payloads(transfer_operation(
                &fixture,
                218,
                219,
                22,
                "sip:wrong-family@example.test",
                1,
            ))
            .await,
        Err(RepositoryError::IdempotencyConflict)
    );

    // At the exact 24-hour boundary the old receipt is expired, so the same
    // key may protect a new canonical request and result.
    let ControlCommandOutcome::Enqueued(reused) = repository
        .enqueue_control(dtmf_operation(&fixture, 218, 220, 86_410, "2"))
        .await
        .unwrap()
    else {
        panic!("expected expired key reuse")
    };
    assert_eq!(
        repository.counts().unwrap().idempotency,
        retained_after_first - 1
    );
    assert!(matches!(
        repository
            .enqueue_control(dtmf_operation(&fixture, 218, 220, 86_411, "2"))
            .await
            .unwrap(),
        ControlCommandOutcome::Replayed(ref replayed) if replayed == &reused
    ));
}

#[tokio::test]
async fn operation_idempotency_keys_are_isolated_by_tenant() {
    let repository = MemoryRepository::new();
    let worker = register(&repository, 2).await;
    let (first_create, _) = sip_webrtc_create(tenant("operation-tenant-a"), worker, 60);
    let (second_create, _) = sip_webrtc_create(tenant("operation-tenant-b"), worker, 61);
    let first = created(repository.create_with_plan(first_create).await.unwrap());
    let second = created(repository.create_with_plan(second_create).await.unwrap());

    let hangup = |call: &StoredServiceCall, second_at| ServiceCommandTransaction {
        command: CommandCommit {
            tenant_id: call.call.aggregate.tenant_id().clone(),
            call_id: call.call.aggregate.id(),
            expected_version: call.call.aggregate.version(),
            command_id: CommandId::new(),
            command: CallCommand::BeginEnding {
                at: at(second_at),
                ending_deadline: Some(at(second_at + 30)),
                reason: StopLegReason::Requested,
            },
            worker,
            attachments: Vec::new(),
            deadline_claim: None,
            at: at(second_at),
        },
        effect_payloads: Vec::new(),
        operation_idempotency: Some(operation_idempotency(
            221,
            222,
            ServiceOperationKind::HangupCall,
        )),
    };
    assert!(matches!(
        repository
            .commit_with_effect_payloads(hangup(&first, 10))
            .await
            .unwrap(),
        ServiceCommandOutcome::Committed(_)
    ));
    assert!(matches!(
        repository
            .commit_with_effect_payloads(hangup(&second, 11))
            .await
            .unwrap(),
        ServiceCommandOutcome::Committed(_)
    ));
}

#[tokio::test]
async fn controls_are_fifo_per_binding_and_block_later_claims() {
    let (repository, fixture) = active_fixture(32).await;
    let leg_id = fixture.service_call.call.aggregate.legs()[1].id();
    let request = |digit: &str, at_time| ControlCommandTransaction {
        command_id: CommandId::new(),
        tenant_id: fixture.owner.clone(),
        call_id: fixture.service_call.call.aggregate.id(),
        leg_id,
        binding_generation: BindingGeneration::INITIAL,
        worker: fixture.worker,
        intent: ControlIntent::Dtmf {
            sequence: DtmfSequence {
                digits: digit.to_owned(),
                duration_ms: 100,
                gap_ms: 50,
            },
        },
        at: at_time,
        operation_idempotency: None,
    };
    let ControlCommandOutcome::Enqueued(first) = repository
        .enqueue_control(request("1", at(10)))
        .await
        .unwrap()
    else {
        panic!("expected first control")
    };
    let ControlCommandOutcome::Enqueued(second) = repository
        .enqueue_control(request("2", at(11)))
        .await
        .unwrap()
    else {
        panic!("expected second control")
    };
    assert!(first.effect.sequence < second.effect.sequence);

    let claims = repository
        .claim_control_effects(fixture.worker, at(12), Duration::from_secs(10), 8)
        .await
        .unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].record.effect_id, first.effect.effect_id);
    assert!(repository
        .claim_control_effects(fixture.worker, at(12), Duration::from_secs(10), 8)
        .await
        .unwrap()
        .is_empty());

    repository
        .reconcile_effect_result(EffectResultReconciliation {
            tenant_id: fixture.owner.clone(),
            call_id: fixture.service_call.call.aggregate.id(),
            effect_id: claims[0].record.effect_id,
            worker: fixture.worker,
            claim_generation: claims[0].claim_generation,
            result: ServiceEffectResult::Succeeded,
            external_reference: None,
            follow_up: None,
            at: at(13),
        })
        .await
        .unwrap();
    let next = repository
        .claim_control_effects(fixture.worker, at(14), Duration::from_secs(10), 8)
        .await
        .unwrap();
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].record.effect_id, second.effect.effect_id);
}

#[tokio::test]
async fn claimed_control_is_invalidated_when_teardown_begins() {
    let (repository, fixture) = active_fixture(34).await;
    let leg_id = fixture.service_call.call.aggregate.legs()[1].id();
    let ControlCommandOutcome::Enqueued(view) = repository
        .enqueue_control(ControlCommandTransaction {
            command_id: CommandId::new(),
            tenant_id: fixture.owner.clone(),
            call_id: fixture.service_call.call.aggregate.id(),
            leg_id,
            binding_generation: BindingGeneration::INITIAL,
            worker: fixture.worker,
            intent: ControlIntent::Dtmf {
                sequence: DtmfSequence {
                    digits: "3".to_owned(),
                    duration_ms: 100,
                    gap_ms: 50,
                },
            },
            at: at(10),
            operation_idempotency: None,
        })
        .await
        .unwrap()
    else {
        panic!("expected control")
    };
    let claim = repository
        .claim_control_effects(fixture.worker, at(11), Duration::from_secs(10), 1)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(claim.record.effect_id, view.effect.effect_id);

    let ending = service_command(
        &repository,
        &fixture.service_call.call,
        fixture.worker,
        CallCommand::BeginEnding {
            at: at(12),
            ending_deadline: Some(at(30)),
            reason: StopLegReason::Requested,
        },
        at(12),
    )
    .await;
    assert_eq!(ending.aggregate.state(), CallState::Ending);
    assert_eq!(
        repository
            .reconcile_effect_result(EffectResultReconciliation {
                tenant_id: fixture.owner,
                call_id: ending.aggregate.id(),
                effect_id: claim.record.effect_id,
                worker: fixture.worker,
                claim_generation: claim.claim_generation,
                result: ServiceEffectResult::Succeeded,
                external_reference: None,
                follow_up: None,
                at: at(13),
            })
            .await,
        Err(RepositoryError::StaleClaim)
    );
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
        operation_idempotency: None,
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
            operation_idempotency: None,
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
async fn command_ids_conflict_across_control_core_and_attachment_paths() {
    let (repository, fixture) = active_fixture(45).await;
    let collision_id = CommandId::new();
    let outbound_leg = fixture.service_call.call.aggregate.legs()[1].id();
    repository
        .enqueue_control(ControlCommandTransaction {
            command_id: collision_id,
            tenant_id: fixture.owner.clone(),
            call_id: fixture.service_call.call.aggregate.id(),
            leg_id: outbound_leg,
            binding_generation: BindingGeneration::INITIAL,
            worker: fixture.worker,
            intent: ControlIntent::Dtmf {
                sequence: DtmfSequence {
                    digits: "4".to_owned(),
                    duration_ms: 100,
                    gap_ms: 50,
                },
            },
            at: at(10),
            operation_idempotency: None,
        })
        .await
        .unwrap();

    let (mut raw_create, _) = sip_webrtc_create(tenant("collision-owner"), fixture.worker, 46);
    raw_create.create.command_id = collision_id;
    assert_eq!(
        repository.create_call(raw_create.create).await,
        Err(RepositoryError::CommandConflict)
    );

    let second_owner = tenant("attachment-collision-owner");
    let (managed_create, token_digest) =
        sip_webrtc_create(second_owner.clone(), fixture.worker, 47);
    let second = created(repository.create_with_plan(managed_create).await.unwrap());
    let inbound_leg = second.call.aggregate.legs()[0].id();
    let candidate = repository
        .inspect_attachment(AttachmentLookup {
            token_digest,
            tenant_id: second_owner.clone(),
            transport: AttachmentTransport::Sip,
            principal_fingerprint: principal(1),
            worker: fixture.worker,
            at: at(3),
        })
        .await
        .unwrap();
    assert_eq!(
        repository
            .consume_attachment(AttachmentConsume {
                command_id: collision_id,
                command: CallCommand::SetLegState {
                    at: at(3),
                    leg_id: inbound_leg,
                    binding_generation: BindingGeneration::INITIAL,
                    state: LegState::Signaling,
                    failure: None,
                },
                candidate,
                connection_id: ConnectionId::from_string("collision-connection"),
                principal_fingerprint: principal(1),
                at: at(3),
            })
            .await,
        Err(RepositoryError::AttachmentRejected)
    );
    assert!(repository
        .inspect_attachment(AttachmentLookup {
            token_digest,
            tenant_id: second_owner,
            transport: AttachmentTransport::Sip,
            principal_fingerprint: principal(1),
            worker: fixture.worker,
            at: at(3),
        })
        .await
        .is_ok());
}

#[tokio::test]
async fn non_provider_leg_cannot_claim_provider_callbacks() {
    let repository = MemoryRepository::new();
    let worker = register(&repository, 1).await;
    let owner = tenant("non-provider-reference-owner");
    let (create, _) = sip_webrtc_create(owner.clone(), worker, 48);
    let service_call = created(repository.create_with_plan(create).await.unwrap());
    let account = ProviderAccountKey::parse("unrelated-provider-account").unwrap();
    let provider_call_id = ProviderCallId::parse("unrelated-provider-call").unwrap();
    let event = ProviderEventInput {
        account: account.clone(),
        event_digest: ProviderEventDigest::new(digest(248)),
        payload_digest: ProviderPayloadDigest::new(digest(249)),
        provider_call_id: provider_call_id.clone(),
        kind: "ringing".to_owned(),
        payload: serde_json::json!({"state": "ringing"}),
        occurred_at: Some(at(2)),
        received_at: at(3),
    };
    repository
        .ingest_provider_event(event.clone())
        .await
        .unwrap();

    let first = repository
        .claim_outbox(worker, at(3), Duration::from_secs(10), 1)
        .await
        .unwrap()
        .remove(0);
    assert!(matches!(
        first.record.intent,
        EffectIntent::AwaitLegAttachment { .. }
    ));
    repository
        .reconcile_effect_result(EffectResultReconciliation {
            tenant_id: owner.clone(),
            call_id: service_call.call.aggregate.id(),
            effect_id: first.record.effect_id,
            worker,
            claim_generation: first.claim_generation,
            result: ServiceEffectResult::Succeeded,
            external_reference: None,
            follow_up: None,
            at: at(4),
        })
        .await
        .unwrap();

    let start = repository
        .claim_outbox(worker, at(5), Duration::from_secs(10), 1)
        .await
        .unwrap()
        .remove(0);
    let (leg_id, binding_generation) = match start.record.intent {
        EffectIntent::StartLeg {
            leg_id,
            binding_generation,
            ..
        } => (leg_id, binding_generation),
        ref other => panic!("expected start-leg effect, got {other:?}"),
    };
    assert_eq!(
        repository
            .reconcile_effect_result(EffectResultReconciliation {
                tenant_id: owner,
                call_id: service_call.call.aggregate.id(),
                effect_id: start.record.effect_id,
                worker,
                claim_generation: start.claim_generation,
                result: ServiceEffectResult::Succeeded,
                external_reference: Some(ExternalReferenceBinding {
                    leg_id,
                    binding_generation,
                    value: ExternalReferenceValue::ProviderCall {
                        account,
                        provider_call_id,
                    },
                }),
                follow_up: None,
                at: at(6),
            })
            .await,
        Err(RepositoryError::ProviderReferenceConflict)
    );
    assert!(matches!(
        repository.ingest_provider_event(event).await.unwrap(),
        ProviderEventOutcome::Duplicate(ref event)
            if event.state == ProviderEventState::PendingReference
    ));
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
        operation_idempotency: None,
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

    assert_eq!(
        repository
            .bind_provider_reference(BindProviderReference {
                tenant_id: owner.clone(),
                call_id: service_call.call.aggregate.id(),
                leg_id: provider_leg,
                account: account.clone(),
                provider_call_id: provider_call_id.clone(),
                worker,
                at: at(8),
            })
            .await,
        Err(RepositoryError::InvalidInput(
            "service-managed call requires service repository transaction"
        ))
    );

    let mut wrong_account = base.clone();
    let Some(ExternalReferenceBinding {
        value:
            ExternalReferenceValue::ProviderCall {
                account: wrong_account_key,
                ..
            },
        ..
    }) = wrong_account.external_reference.as_mut()
    else {
        panic!("expected provider reference")
    };
    *wrong_account_key = ProviderAccountKey::parse("other-twilio-account").unwrap();
    assert_eq!(
        repository.reconcile_effect_result(wrong_account).await,
        Err(RepositoryError::ProviderReferenceConflict)
    );

    let mut wrong_reference_kind = base.clone();
    wrong_reference_kind
        .external_reference
        .as_mut()
        .unwrap()
        .value = ExternalReferenceValue::Signaling {
        namespace: "webrtc-session".to_owned(),
        value: "wrong-kind".to_owned(),
    };
    assert_eq!(
        repository
            .reconcile_effect_result(wrong_reference_kind)
            .await,
        Err(RepositoryError::ProviderReferenceConflict)
    );

    let mut wrong_follow_up_leg = base.clone();
    let CallCommand::SetLegState { leg_id, .. } = &mut wrong_follow_up_leg
        .follow_up
        .as_mut()
        .unwrap()
        .command
        .command
    else {
        panic!("expected state follow-up")
    };
    *leg_id = service_call.call.aggregate.legs()[1].id();
    assert_eq!(
        repository
            .reconcile_effect_result(wrong_follow_up_leg)
            .await,
        Err(RepositoryError::InvalidInput(
            "effect follow-up does not match claimed intent or result"
        ))
    );

    let mut wrong_follow_up_result = base.clone();
    wrong_follow_up_result.external_reference = None;
    wrong_follow_up_result.result = ServiceEffectResult::Failed(FailureDetails::sanitized(
        "provider_start_failed",
        "provider start failed",
        true,
    ));
    assert_eq!(
        repository
            .reconcile_effect_result(wrong_follow_up_result)
            .await,
        Err(RepositoryError::InvalidInput(
            "effect follow-up does not match claimed intent or result"
        ))
    );

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
    let current = &view.follow_up.as_ref().unwrap().command.call;
    assert_eq!(
        repository
            .complete_provider_event(ProviderEventCommit {
                account,
                event_digest: event_input.event_digest,
                claim_generation: ready[0].claim_generation,
                worker,
                command: CommandCommit {
                    tenant_id: owner,
                    call_id: current.aggregate.id(),
                    expected_version: current.aggregate.version(),
                    command_id: CommandId::new(),
                    command: CallCommand::SetLegState {
                        at: at(10),
                        leg_id: provider_leg,
                        binding_generation: BindingGeneration::INITIAL,
                        state: LegState::Connected,
                        failure: None,
                    },
                    worker,
                    attachments: Vec::new(),
                    deadline_claim: None,
                    at: at(10),
                },
                at: at(10),
            })
            .await,
        Err(RepositoryError::InvalidInput(
            "service-managed provider event requires service reconciliation"
        ))
    );
}
