use std::collections::BTreeSet;
use std::time::Duration;

use bridgefu::call_engine::{
    AttachmentConsume, AttachmentId, AttachmentIssue, AttachmentLookup, AttachmentTokenDigest,
    AttachmentTransport, BindingGeneration, CallAggregate, CallCommand, CallId, CallRepository,
    CommandCommit, CommandId, ConnectionBinding, CreateCall, EffectIntent, IdempotencyKeyDigest,
    LegDirection, LegId, LegKind, LegSpec, LegState, PrincipalFingerprint, ProviderAccountKey,
    ProviderCallId, RegisterWorker, RepositoryError, RequestDigest, StoredCall, TenantId,
    WorkerLease,
};
use bridgefu::call_service::{
    CallExecutionPlan, CallServiceRepository, ControlCommandOutcome, ControlCommandTransaction,
    ControlIntent, DtmfSequence, EffectResultOutcome, EffectResultReconciliation, EffectResultView,
    ExternalReferenceBinding, ExternalReferenceValue, LegEndpointConfig, LegExecutionSpec,
    OperationIdempotency, OutboundConnectionBind, OutboundConnectionBindOutcome,
    ProviderEndpointConfig, ProviderKind, ServiceCommandOutcome, ServiceCommandTransaction,
    ServiceCommandView, ServiceCreateOutcome, ServiceCreateTransaction, ServiceEffectPayload,
    ServiceEffectPayloadInput, ServiceEffectResult, ServiceOperationKind, SipEndpointConfig,
    StoredServiceCall, StoredServiceEffectPayload, TransferTarget, WebRtcEndpointConfig,
};
use bridgefu::persistence::{MemoryRepository, PostgresRepository, SqliteRepository};
use chrono::{DateTime, TimeZone, Utc};
use rvoip_core::ids::ConnectionId;

fn at(second: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_930_000_000 + second, 0).unwrap()
}

fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
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

fn tenant(value: &str) -> TenantId {
    TenantId::parse(value).unwrap()
}

fn principal(byte: u8) -> PrincipalFingerprint {
    PrincipalFingerprint::new(digest(byte))
}

async fn register<R>(repository: &R, max_calls: usize) -> WorkerLease
where
    R: CallRepository + Sync,
{
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
        at(20),
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
                at: at(21),
                setup_deadline: at(51),
            },
            worker,
            idempotency_key: IdempotencyKeyDigest::new(digest(key)),
            request_digest: RequestDigest::new(digest(key.wrapping_add(1))),
            attachments: Vec::new(),
            at: at(21),
        },
        plan,
    }
}

fn created(outcome: ServiceCreateOutcome) -> StoredServiceCall {
    match outcome {
        ServiceCreateOutcome::Created(call) => call,
        ServiceCreateOutcome::Replayed(_) => panic!("fresh service call replayed"),
    }
}

async fn service_command<R>(
    repository: &R,
    call: &StoredCall,
    worker: WorkerLease,
    command: CallCommand,
) -> (ServiceCommandTransaction, ServiceCommandView)
where
    R: CallServiceRepository + Sync,
{
    let request = ServiceCommandTransaction {
        command: CommandCommit {
            tenant_id: call.aggregate.tenant_id().clone(),
            call_id: call.aggregate.id(),
            expected_version: call.aggregate.version(),
            command_id: CommandId::new(),
            at: command.at(),
            command,
            worker,
            attachments: Vec::new(),
            deadline_claim: None,
        },
        effect_payloads: Vec::new(),
        operation_idempotency: None,
    };
    let ServiceCommandOutcome::Committed(view) = repository
        .commit_with_effect_payloads(request.clone())
        .await
        .unwrap()
    else {
        panic!("fresh service command replayed")
    };
    (request, view)
}

#[derive(Clone)]
struct ConformanceEvidence {
    owner: TenantId,
    worker: WorkerLease,
    call_id: CallId,
    control_leg_id: LegId,
    plan: CallExecutionPlan,
    command_request: ServiceCommandTransaction,
    command_view: ServiceCommandView,
    control_request: ControlCommandTransaction,
    control_view: bridgefu::call_service::ControlCommandView,
    control_reconciliation: EffectResultReconciliation,
    control_reconciliation_view: EffectResultView,
    outbound_request: OutboundConnectionBind,
    outbound_binding: ConnectionBinding,
    transfer_request: ServiceCommandTransaction,
    transfer_view: ServiceCommandView,
    transfer_payload: StoredServiceEffectPayload,
    provider_owner: TenantId,
    provider_call_id: CallId,
    provider_leg_id: LegId,
    provider_reconciliation: EffectResultReconciliation,
    provider_reconciliation_view: EffectResultView,
}

async fn assert_service_conformance<R>(repository: &R) -> ConformanceEvidence
where
    R: CallRepository + CallServiceRepository + Sync,
{
    let worker = register(repository, 4).await;
    let owner = tenant("service-conformance");
    let (create, attachment_token) = sip_webrtc_create(owner.clone(), worker, 10);
    let plan = create.plan.clone();
    let service_call = created(repository.create_with_plan(create).await.unwrap());
    let inbound_leg = service_call.call.aggregate.legs()[0].id();
    let outbound_leg = service_call.call.aggregate.legs()[1].id();

    let candidate = repository
        .inspect_attachment(AttachmentLookup {
            token_digest: attachment_token,
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
            connection_id: ConnectionId::from_string("service-inbound"),
            principal_fingerprint: principal(1),
            at: at(3),
        })
        .await
        .unwrap();
    let outbound_request = OutboundConnectionBind {
        operation_id: CommandId::new(),
        tenant_id: owner.clone(),
        call_id: service_call.call.aggregate.id(),
        leg_id: outbound_leg,
        binding_generation: BindingGeneration::INITIAL,
        worker,
        connection_id: ConnectionId::from_string("service-outbound"),
        transport: AttachmentTransport::WebRtc,
        principal_fingerprint: principal(2),
        at: at(4),
    };
    let OutboundConnectionBindOutcome::Bound(outbound_binding) = repository
        .bind_outbound_connection(outbound_request.clone())
        .await
        .unwrap()
    else {
        panic!("fresh outbound binding replayed")
    };
    assert_eq!(
        repository
            .bind_outbound_connection(outbound_request.clone())
            .await
            .unwrap(),
        OutboundConnectionBindOutcome::Replayed(outbound_binding.clone())
    );

    let (command_request, command_view) = service_command(
        repository,
        &consumed.commit.call,
        worker,
        CallCommand::SetLegState {
            at: at(5),
            leg_id: outbound_leg,
            binding_generation: BindingGeneration::INITIAL,
            state: LegState::Signaling,
            failure: None,
        },
    )
    .await;
    let (_, inbound_connected) = service_command(
        repository,
        &command_view.command.call,
        worker,
        CallCommand::SetLegState {
            at: at(6),
            leg_id: inbound_leg,
            binding_generation: BindingGeneration::INITIAL,
            state: LegState::Connected,
            failure: None,
        },
    )
    .await;
    let (_, active) = service_command(
        repository,
        &inbound_connected.command.call,
        worker,
        CallCommand::SetLegState {
            at: at(7),
            leg_id: outbound_leg,
            binding_generation: BindingGeneration::INITIAL,
            state: LegState::Connected,
            failure: None,
        },
    )
    .await;

    let control_request = ControlCommandTransaction {
        command_id: CommandId::new(),
        tenant_id: owner.clone(),
        call_id: active.command.call.aggregate.id(),
        leg_id: inbound_leg,
        binding_generation: BindingGeneration::INITIAL,
        worker,
        intent: ControlIntent::Dtmf {
            sequence: DtmfSequence {
                digits: "12#".to_owned(),
                duration_ms: 100,
                gap_ms: 50,
            },
        },
        at: at(8),
        operation_idempotency: Some(operation_idempotency(
            60,
            61,
            ServiceOperationKind::DtmfCall,
        )),
    };
    let ControlCommandOutcome::Enqueued(control_view) = repository
        .enqueue_control(control_request.clone())
        .await
        .unwrap()
    else {
        panic!("fresh control replayed")
    };
    assert_eq!(
        repository
            .enqueue_control(control_request.clone())
            .await
            .unwrap(),
        ControlCommandOutcome::Replayed(control_view.clone())
    );
    let claimed = repository
        .claim_control_effects(worker, at(9), Duration::from_secs(10), 10)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    let control_reconciliation = EffectResultReconciliation {
        tenant_id: owner.clone(),
        call_id: active.command.call.aggregate.id(),
        effect_id: claimed[0].record.effect_id,
        worker,
        claim_generation: claimed[0].claim_generation,
        result: ServiceEffectResult::Succeeded,
        external_reference: None,
        follow_up: None,
        at: at(10),
    };
    let EffectResultOutcome::Reconciled(control_reconciliation_view) = repository
        .reconcile_effect_result(control_reconciliation.clone())
        .await
        .unwrap()
    else {
        panic!("fresh control reconciliation replayed")
    };

    let transfer_command = CallCommand::BeginTransfer {
        at: at(11),
        transfer_deadline: at(41),
    };
    let decision = active
        .command
        .call
        .aggregate
        .decide(transfer_command.clone())
        .unwrap();
    let transfer_ordinal = decision
        .effects()
        .iter()
        .position(|effect| matches!(effect, EffectIntent::ExecuteTransfer { .. }))
        .unwrap() as u32;
    let transfer_request = ServiceCommandTransaction {
        command: CommandCommit {
            tenant_id: owner.clone(),
            call_id: active.command.call.aggregate.id(),
            expected_version: active.command.call.aggregate.version(),
            command_id: CommandId::new(),
            command: transfer_command,
            worker,
            attachments: Vec::new(),
            deadline_claim: None,
            at: at(11),
        },
        effect_payloads: vec![ServiceEffectPayloadInput {
            ordinal: transfer_ordinal,
            payload: ServiceEffectPayload::Transfer {
                target: TransferTarget::Sip {
                    uri: "sip:transfer@example.test".to_owned(),
                },
            },
        }],
        operation_idempotency: Some(operation_idempotency(
            62,
            63,
            ServiceOperationKind::TransferCall,
        )),
    };
    let mut invalid_transfer = transfer_request.clone();
    invalid_transfer.effect_payloads[0].ordinal = 999;
    assert_eq!(
        repository
            .commit_with_effect_payloads(invalid_transfer)
            .await,
        Err(RepositoryError::InvalidInput(
            "transfer effect requires a service payload"
        ))
    );
    let ServiceCommandOutcome::Committed(transfer_view) = repository
        .commit_with_effect_payloads(transfer_request.clone())
        .await
        .unwrap()
    else {
        panic!("rolled-back transfer command leaked")
    };
    let transfer_payload = transfer_view.effect_payloads[0].clone();
    assert_eq!(
        repository
            .load_effect_payload(&owner, transfer_payload.effect_id)
            .await
            .unwrap(),
        Some(transfer_payload.clone())
    );

    let provider_owner = tenant("provider-service-conformance");
    let provider = created(
        repository
            .create_with_plan(provider_create(provider_owner.clone(), worker, 40))
            .await
            .unwrap(),
    );
    let provider_leg_id = provider.call.aggregate.legs()[0].id();
    let claimed = repository
        .claim_outbox(worker, at(22), Duration::from_secs(20), 64)
        .await
        .unwrap();
    let claimed = claimed
        .into_iter()
        .find(|claimed| {
            claimed.record.call_id == provider.call.aggregate.id()
                && matches!(
                    claimed.record.intent,
                    EffectIntent::StartLeg { leg_id, .. } if leg_id == provider_leg_id
                )
        })
        .expect("provider start-leg effect was not claimable");
    let provider_reconciliation = EffectResultReconciliation {
        tenant_id: provider_owner.clone(),
        call_id: provider.call.aggregate.id(),
        effect_id: claimed.record.effect_id,
        worker,
        claim_generation: claimed.claim_generation,
        result: ServiceEffectResult::Succeeded,
        external_reference: Some(ExternalReferenceBinding {
            leg_id: provider_leg_id,
            binding_generation: BindingGeneration::INITIAL,
            value: ExternalReferenceValue::ProviderCall {
                account: ProviderAccountKey::parse("twilio-sandbox").unwrap(),
                provider_call_id: ProviderCallId::parse("CA-conformance").unwrap(),
            },
        }),
        follow_up: None,
        at: at(23),
    };
    let EffectResultOutcome::Reconciled(provider_reconciliation_view) = repository
        .reconcile_effect_result(provider_reconciliation.clone())
        .await
        .unwrap()
    else {
        panic!("fresh provider reconciliation replayed")
    };
    assert_eq!(
        repository
            .load_external_reference(
                &provider_owner,
                provider.call.aggregate.id(),
                provider_leg_id,
            )
            .await
            .unwrap(),
        provider_reconciliation_view.external_reference
    );

    ConformanceEvidence {
        owner,
        worker,
        call_id: active.command.call.aggregate.id(),
        control_leg_id: inbound_leg,
        plan,
        command_request,
        command_view,
        control_request,
        control_view,
        control_reconciliation,
        control_reconciliation_view,
        outbound_request,
        outbound_binding,
        transfer_request,
        transfer_view,
        transfer_payload,
        provider_owner,
        provider_call_id: provider.call.aggregate.id(),
        provider_leg_id,
        provider_reconciliation,
        provider_reconciliation_view,
    }
}

async fn assert_restart_replays<R>(repository: &R, evidence: &ConformanceEvidence)
where
    R: CallServiceRepository + Sync,
{
    assert_eq!(
        repository
            .load_service_call(&evidence.owner, evidence.call_id)
            .await
            .unwrap()
            .plan,
        evidence.plan
    );
    assert_eq!(
        repository
            .commit_with_effect_payloads(evidence.command_request.clone())
            .await
            .unwrap(),
        ServiceCommandOutcome::Replayed(evidence.command_view.clone())
    );
    assert_eq!(
        repository
            .enqueue_control(evidence.control_request.clone())
            .await
            .unwrap(),
        ControlCommandOutcome::Replayed(evidence.control_view.clone())
    );
    assert_eq!(
        repository
            .reconcile_effect_result(evidence.control_reconciliation.clone())
            .await
            .unwrap(),
        EffectResultOutcome::Replayed(evidence.control_reconciliation_view.clone())
    );
    assert_eq!(
        repository
            .bind_outbound_connection(evidence.outbound_request.clone())
            .await
            .unwrap(),
        OutboundConnectionBindOutcome::Replayed(evidence.outbound_binding.clone())
    );
    assert_eq!(
        repository
            .commit_with_effect_payloads(evidence.transfer_request.clone())
            .await
            .unwrap(),
        ServiceCommandOutcome::Replayed(evidence.transfer_view.clone())
    );
    assert_eq!(
        repository
            .load_effect_payload(&evidence.owner, evidence.transfer_payload.effect_id)
            .await
            .unwrap(),
        Some(evidence.transfer_payload.clone())
    );
    assert_eq!(
        repository
            .reconcile_effect_result(evidence.provider_reconciliation.clone())
            .await
            .unwrap(),
        EffectResultOutcome::Replayed(evidence.provider_reconciliation_view.clone())
    );
    assert_eq!(
        repository
            .load_external_reference(
                &evidence.provider_owner,
                evidence.provider_call_id,
                evidence.provider_leg_id,
            )
            .await
            .unwrap(),
        evidence.provider_reconciliation_view.external_reference
    );
}

async fn assert_two_instance_control_race<R>(left: &R, right: &R, evidence: &ConformanceEvidence)
where
    R: CallServiceRepository + Sync,
{
    let request = ControlCommandTransaction {
        command_id: CommandId::new(),
        tenant_id: evidence.owner.clone(),
        call_id: evidence.call_id,
        leg_id: evidence.control_leg_id,
        binding_generation: BindingGeneration::INITIAL,
        worker: evidence.worker,
        intent: ControlIntent::Dtmf {
            sequence: DtmfSequence {
                digits: "9".to_owned(),
                duration_ms: 100,
                gap_ms: 50,
            },
        },
        at: at(24),
        operation_idempotency: Some(operation_idempotency(
            64,
            65,
            ServiceOperationKind::DtmfCall,
        )),
    };
    let ControlCommandOutcome::Enqueued(first_view) = left.enqueue_control(request).await.unwrap()
    else {
        panic!("fresh raced control replayed")
    };
    let second_request = ControlCommandTransaction {
        command_id: CommandId::new(),
        tenant_id: evidence.owner.clone(),
        call_id: evidence.call_id,
        leg_id: evidence.control_leg_id,
        binding_generation: BindingGeneration::INITIAL,
        worker: evidence.worker,
        intent: ControlIntent::Dtmf {
            sequence: DtmfSequence {
                digits: "8".to_owned(),
                duration_ms: 100,
                gap_ms: 50,
            },
        },
        at: at(24),
        operation_idempotency: Some(operation_idempotency(
            66,
            67,
            ServiceOperationKind::DtmfCall,
        )),
    };
    let ControlCommandOutcome::Enqueued(second_view) =
        right.enqueue_control(second_request).await.unwrap()
    else {
        panic!("fresh second control replayed")
    };
    assert!(second_view.effect.sequence > first_view.effect.sequence);
    let (left_claims, right_claims) = tokio::join!(
        left.claim_control_effects(evidence.worker, at(25), Duration::from_secs(10), 10),
        right.claim_control_effects(evidence.worker, at(25), Duration::from_secs(10), 10),
    );
    let mut claims = left_claims.unwrap();
    claims.extend(right_claims.unwrap());
    assert_eq!(claims.len(), 1, "two repository instances double-claimed");
    assert_eq!(claims[0].record.effect_id, first_view.effect.effect_id);
    let reconciliation = EffectResultReconciliation {
        tenant_id: evidence.owner.clone(),
        call_id: evidence.call_id,
        effect_id: claims[0].record.effect_id,
        worker: evidence.worker,
        claim_generation: claims[0].claim_generation,
        result: ServiceEffectResult::Succeeded,
        external_reference: None,
        follow_up: None,
        at: at(26),
    };
    let (left_result, right_result) = tokio::join!(
        left.reconcile_effect_result(reconciliation.clone()),
        right.reconcile_effect_result(reconciliation),
    );
    let outcomes = [left_result.unwrap(), right_result.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, EffectResultOutcome::Reconciled(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, EffectResultOutcome::Replayed(_)))
            .count(),
        1
    );
    let next = right
        .claim_control_effects(evidence.worker, at(27), Duration::from_secs(10), 10)
        .await
        .unwrap();
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].record.effect_id, second_view.effect.effect_id);
    assert!(next[0].record.sequence > claims[0].record.sequence);
    right
        .reconcile_effect_result(EffectResultReconciliation {
            tenant_id: evidence.owner.clone(),
            call_id: evidence.call_id,
            effect_id: next[0].record.effect_id,
            worker: evidence.worker,
            claim_generation: next[0].claim_generation,
            result: ServiceEffectResult::Succeeded,
            external_reference: None,
            follow_up: None,
            at: at(28),
        })
        .await
        .unwrap();
}

fn sqlite_database(label: &str) -> (String, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!(
        "bridgefu-call-service-{label}-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    (format!("sqlite://{}", path.display()), path)
}

const SERVICE_DRIFT_CASES: &[(&str, &str)] = &[
    (
        "UPDATE call_execution_plans SET plan_version = plan_version + 1",
        "UPDATE call_execution_plans SET plan_version = plan_version - 1",
    ),
    (
        "UPDATE service_command_results SET tenant_id = tenant_id || '_drift'",
        "UPDATE service_command_results SET tenant_id = substr(tenant_id, 1, length(tenant_id) - 6)",
    ),
    (
        "UPDATE service_effect_payloads SET payload_kind = payload_kind || '_drift'",
        "UPDATE service_effect_payloads SET payload_kind = substr(payload_kind, 1, length(payload_kind) - 6)",
    ),
    (
        "UPDATE control_sequences SET last_sequence = last_sequence + 1",
        "UPDATE control_sequences SET last_sequence = last_sequence - 1",
    ),
    (
        "UPDATE control_commands SET control_kind = control_kind || '_drift'",
        "UPDATE control_commands SET control_kind = substr(control_kind, 1, length(control_kind) - 6)",
    ),
    (
        "UPDATE control_outbox SET outbox_state = outbox_state || '_drift'",
        "UPDATE control_outbox SET outbox_state = substr(outbox_state, 1, length(outbox_state) - 6)",
    ),
    (
        "UPDATE outbound_binding_results SET transport_kind = transport_kind || '_drift'",
        "UPDATE outbound_binding_results SET transport_kind = substr(transport_kind, 1, length(transport_kind) - 6)",
    ),
    (
        "UPDATE external_references SET tenant_id = tenant_id || '_drift'",
        "UPDATE external_references SET tenant_id = substr(tenant_id, 1, length(tenant_id) - 6)",
    ),
    (
        "UPDATE reconciliation_results SET tenant_id = tenant_id || '_drift'",
        "UPDATE reconciliation_results SET tenant_id = substr(tenant_id, 1, length(tenant_id) - 6)",
    ),
    (
        "UPDATE idempotency SET receipt_kind = 'service_command' WHERE receipt_kind = 'create_call'",
        "UPDATE idempotency SET receipt_kind = 'create_call' WHERE operation_kind = 'create_call' AND receipt_kind = 'service_command'",
    ),
    (
        "UPDATE idempotency SET operation_kind = 'transfer_call' WHERE receipt_kind = 'control_command' AND operation_kind = 'dtmf_call'",
        "UPDATE idempotency SET operation_kind = 'dtmf_call' WHERE receipt_kind = 'control_command' AND operation_kind = 'transfer_call'",
    ),
];

async fn assert_sqlite_service_drift_detection(
    repository: &SqliteRepository,
    evidence: &ConformanceEvidence,
) {
    for (corrupt, restore) in SERVICE_DRIFT_CASES {
        sqlx::query(corrupt)
            .execute(repository.pool())
            .await
            .unwrap();
        assert_eq!(
            repository
                .load_service_call(&evidence.owner, evidence.call_id)
                .await,
            Err(RepositoryError::Unavailable),
            "SQLite accepted normalized drift from {corrupt}"
        );
        sqlx::query(restore)
            .execute(repository.pool())
            .await
            .unwrap();
        repository
            .load_service_call(&evidence.owner, evidence.call_id)
            .await
            .unwrap();
    }
}

async fn assert_postgres_service_drift_detection(
    repository: &PostgresRepository,
    evidence: &ConformanceEvidence,
) {
    for (corrupt, restore) in SERVICE_DRIFT_CASES {
        sqlx::query(corrupt)
            .execute(repository.pool())
            .await
            .unwrap();
        assert_eq!(
            repository
                .load_service_call(&evidence.owner, evidence.call_id)
                .await,
            Err(RepositoryError::Unavailable),
            "PostgreSQL accepted normalized drift from {corrupt}"
        );
        sqlx::query(restore)
            .execute(repository.pool())
            .await
            .unwrap();
        repository
            .load_service_call(&evidence.owner, evidence.call_id)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn memory_service_repository_conformance() {
    let repository = MemoryRepository::new();
    let evidence = assert_service_conformance(&repository).await;
    assert_restart_replays(&repository, &evidence).await;
}

#[tokio::test]
async fn sqlite_service_repository_conformance_restart_and_races() {
    let (url, path) = sqlite_database("conformance");
    let first = SqliteRepository::connect(&url).await.unwrap();
    let evidence = assert_service_conformance(&first).await;
    let second = SqliteRepository::connect(&url).await.unwrap();
    assert_restart_replays(&second, &evidence).await;
    assert_two_instance_control_race(&first, &second, &evidence).await;
    assert_sqlite_service_drift_detection(&first, &evidence).await;
    first.pool().close().await;
    second.pool().close().await;
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn postgres_service_repository_conformance_restart_and_races() {
    let Some(url) = std::env::var("BRIDGEFU_TEST_POSTGRES_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
    else {
        return;
    };
    let administration = sqlx::PgPool::connect(&url).await.unwrap();
    let schema = format!("bridgefu_service_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&administration)
        .await
        .unwrap();
    let mut scoped = url::Url::parse(&url).unwrap();
    scoped
        .query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"));
    let scoped = scoped.to_string();
    let first = PostgresRepository::connect(&scoped).await.unwrap();
    let evidence = assert_service_conformance(&first).await;
    let second = PostgresRepository::connect(&scoped).await.unwrap();
    assert_restart_replays(&second, &evidence).await;
    assert_two_instance_control_race(&first, &second, &evidence).await;
    assert_postgres_service_drift_detection(&first, &evidence).await;
    first.pool().close().await;
    second.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&administration)
        .await
        .unwrap();
    administration.close().await;
}
