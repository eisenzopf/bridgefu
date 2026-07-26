use std::collections::BTreeSet;
use std::time::Duration;

use bridgefu::call_engine::{
    AttachmentConsume, AttachmentId, AttachmentIssue, AttachmentLookup, AttachmentPurpose,
    AttachmentTokenDigest, AttachmentTransport, BindingGeneration, CallAggregate, CallCommand,
    CallId, CallRepository, ClaimGeneration, CommandCommit, CommandId, ConnectionBinding,
    CreateCall, EffectId, EffectIntent, IdempotencyKeyDigest, LegDirection, LegId, LegKind,
    LegSpec, LegState, PrincipalFingerprint, ProviderAccountKey, ProviderCallId,
    ProviderEventCommit, ProviderEventDigest, ProviderEventInput, ProviderEventOutcome,
    ProviderEventState, ProviderEventTarget, ProviderPayloadDigest, ProviderReferenceRole,
    RegisterWorker, RepositoryError, RequestDigest, StopLegReason, StoredCall, TenantId,
    WorkerLease,
};
use bridgefu::call_service::{
    BoundConnectionStateCommit, CallExecutionPlan, CallServiceRepository, ControlCommandOutcome,
    ControlCommandTransaction, ControlIntent, DtmfSequence, EffectResultOutcome,
    EffectResultReconciliation, EffectResultView, ExternalReferenceBinding, ExternalReferenceValue,
    LegEndpointConfig, LegExecutionSpec, MediaActivityCommit, MediaActivityGeneration,
    OperationIdempotency, OutboundConnectionBind, OutboundConnectionBindOutcome,
    ProviderEndpointConfig, ProviderEventReconciliationOutcome,
    ProviderEventReconciliationTransaction, ProviderEventReconciliationView, ProviderKind,
    ServiceCommandOutcome, ServiceCommandTransaction, ServiceCommandView, ServiceCreateOutcome,
    ServiceCreateTransaction, ServiceEffectPayload, ServiceEffectPayloadInput, ServiceEffectResult,
    ServiceOperationKind, SipEndpointConfig, StoredServiceCall, StoredServiceEffectPayload,
    TransferTarget, WebRtcEndpointConfig,
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

fn digest_hex(byte: u8, uppercase: bool) -> String {
    digest(byte)
        .into_iter()
        .map(|value| {
            if uppercase {
                format!("{value:02X}")
            } else {
                format!("{value:02x}")
            }
        })
        .collect()
}

async fn claim_start_leg<R>(
    repository: &R,
    worker: WorkerLease,
    call_id: CallId,
    leg_id: LegId,
    claim_at: DateTime<Utc>,
) -> (EffectId, ClaimGeneration)
where
    R: CallRepository + CallServiceRepository + Sync,
{
    for _ in 0..16 {
        let claims = repository
            .claim_outbox(worker, claim_at, Duration::from_secs(30), 64)
            .await
            .unwrap();
        for claim in claims {
            if claim.record.call_id == call_id
                && matches!(
                    claim.record.intent,
                    EffectIntent::StartLeg { leg_id: claimed_leg, .. } if claimed_leg == leg_id
                )
            {
                return (claim.record.effect_id, claim.claim_generation);
            }
            repository
                .reconcile_effect_result(EffectResultReconciliation {
                    tenant_id: claim.record.tenant_id.clone(),
                    call_id: claim.record.call_id,
                    effect_id: claim.record.effect_id,
                    worker,
                    claim_generation: claim.claim_generation,
                    result: ServiceEffectResult::Succeeded,
                    external_reference: None,
                    additional_external_references: Vec::new(),
                    follow_up: None,
                    at: claim_at,
                })
                .await
                .unwrap();
        }
    }
    panic!("start effect for {call_id}/{leg_id} was not claimable")
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
                "telnyx".to_owned(),
            ]),
            at: at(0),
            lease_ttl: std::time::Duration::from_secs(300),
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
                endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                    uri: None,
                    initial_context: Default::default(),
                }),
            },
            LegExecutionSpec {
                leg_id: initial.legs()[1].id(),
                endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                    signaling_uri: Some("wss://webrtc.example.test/session".to_owned()),
                }),
            },
        ],
        principal(key),
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
            purpose: AttachmentPurpose::PublicInbound,
            leg_id: inbound,
            binding_generation: BindingGeneration::INITIAL,
            transport: AttachmentTransport::Sip,
            expected_principal: principal(1),
            expires_at: at(122),
        }],
        at: at(2),
    };
    (
        ServiceCreateTransaction {
            create,
            plan,
            alternatives: Vec::new(),
        },
        token_digest,
    )
}

fn raw_attachment_create(
    owner: TenantId,
    worker: WorkerLease,
    seed: u8,
    created_at: DateTime<Utc>,
    attachment_expires_at: DateTime<Utc>,
) -> (CreateCall, AttachmentTokenDigest, LegId) {
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
        created_at,
    );
    let inbound_leg = initial.legs()[0].id();
    let token_digest = AttachmentTokenDigest::new(digest(seed));
    let command_at = created_at + chrono::Duration::seconds(1);
    (
        CreateCall {
            initial,
            command_id: CommandId::new(),
            command: CallCommand::StartConnecting {
                at: command_at,
                setup_deadline: command_at + chrono::Duration::seconds(30),
            },
            worker,
            idempotency_key: IdempotencyKeyDigest::new(digest(seed.wrapping_add(1))),
            request_digest: RequestDigest::new(digest(seed.wrapping_add(2))),
            attachments: vec![AttachmentIssue {
                attachment_id: AttachmentId::new(),
                token_digest,
                purpose: AttachmentPurpose::PublicInbound,
                leg_id: inbound_leg,
                binding_generation: BindingGeneration::INITIAL,
                transport: AttachmentTransport::Sip,
                expected_principal: principal(1),
                expires_at: attachment_expires_at,
            }],
            at: command_at,
        },
        token_digest,
        inbound_leg,
    )
}

async fn assert_database_authoritative_attachment_expiry<R>(
    repository: &R,
    database_now: DateTime<Utc>,
) where
    R: CallRepository + Sync,
{
    let worker = register(repository, 2).await;
    let logical_now = database_now - chrono::Duration::seconds(60);

    let owner = tenant("database-authority-principal");
    let (create, token_digest, inbound_leg) = raw_attachment_create(
        owner.clone(),
        worker,
        210,
        logical_now,
        database_now + chrono::Duration::seconds(60),
    );
    repository.create_call(create).await.unwrap();
    let lookup = AttachmentLookup {
        token_digest,
        tenant_id: owner,
        transport: AttachmentTransport::Sip,
        principal_fingerprint: principal(1),
        worker,
        at: logical_now + chrono::Duration::seconds(2),
    };
    let candidate = repository.inspect_attachment(lookup.clone()).await.unwrap();
    assert_eq!(
        repository
            .consume_attachment(AttachmentConsume {
                candidate: candidate.clone(),
                command_id: CommandId::new(),
                command: CallCommand::SetLegState {
                    at: lookup.at,
                    leg_id: inbound_leg,
                    binding_generation: BindingGeneration::INITIAL,
                    state: LegState::Signaling,
                    failure: None,
                },
                connection_id: ConnectionId::from_string("database-authority-expired-principal"),
                principal_fingerprint: principal(1),
                principal_expires_at: Some(database_now - chrono::Duration::seconds(1)),
                at: lookup.at,
            })
            .await,
        Err(RepositoryError::AttachmentRejected)
    );
    repository.inspect_attachment(lookup.clone()).await.unwrap();
    repository
        .consume_attachment(AttachmentConsume {
            candidate,
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at: lookup.at,
                leg_id: inbound_leg,
                binding_generation: BindingGeneration::INITIAL,
                state: LegState::Signaling,
                failure: None,
            },
            connection_id: ConnectionId::from_string("database-authority-valid-principal"),
            principal_fingerprint: principal(1),
            principal_expires_at: None,
            at: lookup.at,
        })
        .await
        .unwrap();

    let owner = tenant("database-authority-token");
    let (create, expired_token_digest, _) = raw_attachment_create(
        owner.clone(),
        worker,
        220,
        logical_now,
        database_now - chrono::Duration::seconds(1),
    );
    repository.create_call(create).await.unwrap();
    assert!(matches!(
        repository
            .inspect_attachment(AttachmentLookup {
                token_digest: expired_token_digest,
                tenant_id: owner,
                transport: AttachmentTransport::Sip,
                principal_fingerprint: principal(1),
                worker,
                at: logical_now + chrono::Duration::seconds(2),
            })
            .await,
        Err(RepositoryError::AttachmentRejected)
    ));
}

fn provider_create(owner: TenantId, worker: WorkerLease, key: u8) -> ServiceCreateTransaction {
    let initial = CallAggregate::new(
        owner,
        [
            LegSpec {
                direction: LegDirection::Outbound,
                kind: LegKind::Telnyx,
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
                    provider: ProviderKind::Telnyx,
                    account_profile: "telnyx-sandbox".to_owned(),
                    destination: Some("+12065550100".to_owned()),
                }),
            },
            LegExecutionSpec {
                leg_id: initial.legs()[1].id(),
                endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                    uri: None,
                    initial_context: Default::default(),
                }),
            },
        ],
        principal(key),
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
        alternatives: Vec::new(),
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
        bound_connection: None,
        media_activity: None,
        replacement_connection: None,
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
    original_create: StoredServiceCall,
    control_leg_id: LegId,
    plan: CallExecutionPlan,
    command_request: ServiceCommandTransaction,
    command_view: ServiceCommandView,
    inbound_lifecycle_request: BoundConnectionStateCommit,
    inbound_lifecycle_view: ServiceCommandView,
    outbound_lifecycle_request: BoundConnectionStateCommit,
    outbound_lifecycle_view: ServiceCommandView,
    media_activity_request: MediaActivityCommit,
    media_activity_view: ServiceCommandView,
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
    provider_peer_leg_id: LegId,
    cross_call_connection_id: ConnectionId,
    provider_reconciliation: EffectResultReconciliation,
    provider_reconciliation_view: EffectResultView,
    provider_event_reconciliation: ProviderEventReconciliationTransaction,
    provider_event_reconciliation_view: ProviderEventReconciliationView,
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
            principal_expires_at: None,
            at: at(3),
        })
        .await
        .unwrap();
    let (outbound_effect_id, outbound_claim_generation) = claim_start_leg(
        repository,
        worker,
        service_call.call.aggregate.id(),
        outbound_leg,
        at(4),
    )
    .await;
    let outbound_request = OutboundConnectionBind {
        operation_id: CommandId::from_uuid(outbound_effect_id.as_uuid()).unwrap(),
        effect_id: outbound_effect_id,
        claim_generation: outbound_claim_generation,
        tenant_id: owner.clone(),
        call_id: service_call.call.aggregate.id(),
        leg_id: outbound_leg,
        binding_generation: BindingGeneration::INITIAL,
        worker,
        connection_id: ConnectionId::from_string("service-outbound"),
        transport: AttachmentTransport::WebRtc,
        principal_fingerprint: principal(10),
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
    let inbound_lifecycle_request = BoundConnectionStateCommit {
        tenant_id: owner.clone(),
        call_id: service_call.call.aggregate.id(),
        expected_version: command_view.command.call.aggregate.version(),
        command_id: CommandId::new(),
        leg_id: inbound_leg,
        binding_generation: BindingGeneration::INITIAL,
        connection_id: consumed.binding.connection_id.clone(),
        worker,
        state: LegState::Connected,
        failure: None,
        at: at(6),
    };
    let mut invalid_lifecycle_state = inbound_lifecycle_request.clone();
    invalid_lifecycle_state.command_id = CommandId::new();
    invalid_lifecycle_state.state = LegState::Pending;
    assert_eq!(
        repository
            .commit_bound_connection_state(invalid_lifecycle_state)
            .await,
        Err(RepositoryError::InvalidInput(
            "invalid bound connection lifecycle state"
        ))
    );
    let mut unknown_connection = inbound_lifecycle_request.clone();
    unknown_connection.command_id = CommandId::new();
    unknown_connection.connection_id = ConnectionId::from_string("unknown-service-connection");
    assert_eq!(
        repository
            .commit_bound_connection_state(unknown_connection)
            .await,
        Err(RepositoryError::StaleClaim)
    );
    let ServiceCommandOutcome::Committed(inbound_lifecycle_view) = repository
        .commit_bound_connection_state(inbound_lifecycle_request.clone())
        .await
        .unwrap()
    else {
        panic!("fresh inbound lifecycle command replayed")
    };
    assert_eq!(
        inbound_lifecycle_view
            .command
            .call
            .aggregate
            .leg(inbound_leg)
            .unwrap()
            .state(),
        LegState::Connected
    );

    let outbound_lifecycle_request = BoundConnectionStateCommit {
        tenant_id: owner.clone(),
        call_id: service_call.call.aggregate.id(),
        expected_version: inbound_lifecycle_view.command.call.aggregate.version(),
        command_id: CommandId::new(),
        leg_id: outbound_leg,
        binding_generation: BindingGeneration::INITIAL,
        connection_id: outbound_binding.connection_id.clone(),
        worker,
        state: LegState::Connected,
        failure: None,
        at: at(7),
    };
    let ServiceCommandOutcome::Committed(outbound_lifecycle_view) = repository
        .commit_bound_connection_state(outbound_lifecycle_request.clone())
        .await
        .unwrap()
    else {
        panic!("fresh outbound lifecycle command replayed")
    };
    let active = &outbound_lifecycle_view;

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
        additional_external_references: Vec::new(),
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

    let media_activity_request = MediaActivityCommit {
        tenant_id: owner.clone(),
        call_id: active.command.call.aggregate.id(),
        expected_version: active.command.call.aggregate.version(),
        command_id: CommandId::new(),
        leg_id: inbound_leg,
        binding_generation: BindingGeneration::INITIAL,
        connection_id: consumed.binding.connection_id.clone(),
        activity_generation: MediaActivityGeneration::INITIAL,
        worker,
        at: at(11),
        due_at: at(41),
    };
    let ServiceCommandOutcome::Committed(media_activity_view) = repository
        .commit_media_activity(media_activity_request.clone())
        .await
        .unwrap()
    else {
        panic!("fresh media activity replayed")
    };
    assert_eq!(
        media_activity_view
            .command
            .call
            .aggregate
            .deadlines()
            .get(bridgefu::call_engine::DeadlineKind::Media)
            .due_at(),
        Some(at(41))
    );
    let mut skipped_activity = media_activity_request.clone();
    skipped_activity.command_id = CommandId::new();
    skipped_activity.expected_version = media_activity_view.command.call.aggregate.version();
    skipped_activity.activity_generation = MediaActivityGeneration::INITIAL
        .next()
        .unwrap()
        .next()
        .unwrap();
    skipped_activity.at = at(12);
    skipped_activity.due_at = at(42);
    assert_eq!(
        repository.commit_media_activity(skipped_activity).await,
        Err(RepositoryError::StaleClaim)
    );
    let active = &media_activity_view;

    let transfer_command = CallCommand::BeginTransfer {
        at: at(12),
        transfer_deadline: at(42),
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
            at: at(12),
        },
        effect_payloads: vec![ServiceEffectPayloadInput {
            ordinal: transfer_ordinal,
            payload: ServiceEffectPayload::Transfer {
                target_leg_id: active.command.call.aggregate.legs()[0].id(),
                target_binding_generation: active.command.call.aggregate.legs()[0]
                    .binding_generation(),
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
        bound_connection: None,
        media_activity: None,
        replacement_connection: None,
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
    let mut foreign_leg_transfer = transfer_request.clone();
    let ServiceEffectPayload::Transfer { target_leg_id, .. } =
        &mut foreign_leg_transfer.effect_payloads[0].payload
    else {
        panic!("fixture payload must be a transfer")
    };
    *target_leg_id = provider_create(tenant("foreign-transfer"), worker, 99)
        .create
        .initial
        .legs()[0]
        .id();
    assert_eq!(
        repository
            .commit_with_effect_payloads(foreign_leg_transfer)
            .await,
        Err(RepositoryError::InvalidInput(
            "transfer target leg does not belong to call"
        ))
    );
    let mut stale_transfer = transfer_request.clone();
    let ServiceEffectPayload::Transfer {
        target_binding_generation,
        ..
    } = &mut stale_transfer.effect_payloads[0].payload
    else {
        panic!("fixture payload must be a transfer")
    };
    *target_binding_generation = serde_json::from_value(serde_json::json!(2)).unwrap();
    assert_eq!(
        repository.commit_with_effect_payloads(stale_transfer).await,
        Err(RepositoryError::StaleClaim)
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
    let provider_peer_leg_id = provider.call.aggregate.legs()[1].id();
    let provider_account = ProviderAccountKey::parse("telnyx-sandbox").unwrap();
    let provider_external_call_id = ProviderCallId::parse("CA-conformance").unwrap();
    let provider_event_digest = ProviderEventDigest::new(digest(70));
    let provider_event = ProviderEventInput {
        account: provider_account.clone(),
        event_digest: provider_event_digest,
        payload_digest: ProviderPayloadDigest::new(digest(71)),
        provider_call_id: provider_external_call_id.clone(),
        kind: "ringing".to_owned(),
        payload: serde_json::json!({"state": "ringing"}),
        occurred_at: Some(at(21)),
        received_at: at(22),
    };
    assert!(matches!(
        repository
            .ingest_provider_event(provider_event.clone())
            .await
            .unwrap(),
        ProviderEventOutcome::Accepted(ref event)
            if event.state == ProviderEventState::PendingReference
    ));
    assert!(matches!(
        repository
            .ingest_provider_event(provider_event.clone())
            .await
            .unwrap(),
        ProviderEventOutcome::Duplicate(ref event)
            if event.state == ProviderEventState::PendingReference
    ));
    let cross_call_connection_id = ConnectionId::from_string("provider-cross-call");
    let (provider_effect_id, provider_claim_generation) = claim_start_leg(
        repository,
        worker,
        provider.call.aggregate.id(),
        provider_leg_id,
        at(22),
    )
    .await;
    let OutboundConnectionBindOutcome::Bound(_) = repository
        .bind_outbound_connection(OutboundConnectionBind {
            operation_id: CommandId::from_uuid(provider_effect_id.as_uuid()).unwrap(),
            effect_id: provider_effect_id,
            claim_generation: provider_claim_generation,
            tenant_id: provider_owner.clone(),
            call_id: provider.call.aggregate.id(),
            leg_id: provider_leg_id,
            binding_generation: BindingGeneration::INITIAL,
            worker,
            connection_id: cross_call_connection_id.clone(),
            transport: AttachmentTransport::Sip,
            principal_fingerprint: principal(40),
            at: at(22),
        })
        .await
        .unwrap()
    else {
        panic!("fresh cross-call binding replayed")
    };
    let mut cross_call_guard = BoundConnectionStateCommit {
        tenant_id: owner.clone(),
        call_id: service_call.call.aggregate.id(),
        expected_version: transfer_view.command.call.aggregate.version(),
        command_id: CommandId::new(),
        leg_id: inbound_leg,
        binding_generation: BindingGeneration::INITIAL,
        connection_id: cross_call_connection_id.clone(),
        worker,
        state: LegState::Held,
        failure: None,
        at: at(22),
    };
    assert_eq!(
        repository
            .commit_bound_connection_state(cross_call_guard.clone())
            .await,
        Err(RepositoryError::StaleClaim)
    );
    cross_call_guard.command_id = inbound_lifecycle_request.command_id;
    assert_eq!(
        repository
            .commit_bound_connection_state(cross_call_guard)
            .await,
        Err(RepositoryError::CommandConflict)
    );
    let provider_start_follow_up = ServiceCommandTransaction {
        command: CommandCommit {
            tenant_id: provider_owner.clone(),
            call_id: provider.call.aggregate.id(),
            expected_version: provider.call.aggregate.version(),
            command_id: CommandId::new(),
            command: CallCommand::ProviderMediaStarted {
                at: at(23),
                leg_id: provider_leg_id,
                binding_generation: BindingGeneration::INITIAL,
            },
            worker,
            attachments: Vec::new(),
            deadline_claim: None,
            at: at(23),
        },
        effect_payloads: Vec::new(),
        operation_idempotency: None,
        bound_connection: None,
        media_activity: None,
        replacement_connection: None,
    };
    let provider_reconciliation = EffectResultReconciliation {
        tenant_id: provider_owner.clone(),
        call_id: provider.call.aggregate.id(),
        effect_id: provider_effect_id,
        worker,
        claim_generation: provider_claim_generation,
        result: ServiceEffectResult::Succeeded,
        external_reference: Some(ExternalReferenceBinding {
            leg_id: provider_leg_id,
            binding_generation: BindingGeneration::INITIAL,
            role: ProviderReferenceRole::Media,
            value: ExternalReferenceValue::ProviderCall {
                account: provider_account.clone(),
                provider_call_id: provider_external_call_id.clone(),
            },
        }),
        additional_external_references: Vec::new(),
        follow_up: Some(provider_start_follow_up),
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
        provider_reconciliation_view.released_provider_events.len(),
        1
    );
    assert_eq!(
        provider_reconciliation_view.released_provider_events[0].state,
        ProviderEventState::Ready
    );
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
    let media_reference = repository
        .load_external_reference_by_role(
            &provider_owner,
            provider.call.aggregate.id(),
            provider_leg_id,
            ProviderReferenceRole::Media,
        )
        .await
        .unwrap()
        .expect("primary provider media reference");
    assert_eq!(media_reference.role, ProviderReferenceRole::Media);

    let mut destination_effect = None;
    for _ in 0..4 {
        let claims = repository
            .claim_outbox(worker, at(24), Duration::from_secs(20), 64)
            .await
            .unwrap();
        let provider_claim = claims
            .into_iter()
            .find(|claim| claim.record.call_id == provider.call.aggregate.id())
            .expect("provider call retained an ordered effect");
        if matches!(
            provider_claim.record.intent,
            EffectIntent::ConnectProviderDestination { leg_id, .. }
                if leg_id == provider_leg_id
        ) {
            destination_effect = Some(provider_claim);
            break;
        }
        repository
            .reconcile_effect_result(EffectResultReconciliation {
                tenant_id: provider_owner.clone(),
                call_id: provider.call.aggregate.id(),
                effect_id: provider_claim.record.effect_id,
                worker,
                claim_generation: provider_claim.claim_generation,
                result: ServiceEffectResult::Succeeded,
                external_reference: None,
                additional_external_references: Vec::new(),
                follow_up: None,
                at: at(24),
            })
            .await
            .unwrap();
    }
    let destination_effect = destination_effect
        .expect("provider destination effect follows the durable media reference");
    assert_ne!(
        destination_effect.record.effect_id, provider_effect_id,
        "media and destination mutations require distinct durable command IDs"
    );
    let destination_provider_call_id = ProviderCallId::parse("CA-conformance-destination").unwrap();
    let EffectResultOutcome::Reconciled(destination_reconciliation_view) = repository
        .reconcile_effect_result(EffectResultReconciliation {
            tenant_id: provider_owner.clone(),
            call_id: provider.call.aggregate.id(),
            effect_id: destination_effect.record.effect_id,
            worker,
            claim_generation: destination_effect.claim_generation,
            result: ServiceEffectResult::Succeeded,
            external_reference: Some(ExternalReferenceBinding {
                leg_id: provider_leg_id,
                binding_generation: BindingGeneration::INITIAL,
                role: ProviderReferenceRole::Destination,
                value: ExternalReferenceValue::ProviderCall {
                    account: provider_account.clone(),
                    provider_call_id: destination_provider_call_id,
                },
            }),
            additional_external_references: Vec::new(),
            follow_up: None,
            at: at(24),
        })
        .await
        .unwrap()
    else {
        panic!("fresh provider destination reconciliation replayed")
    };
    let destination_reference = repository
        .load_external_reference_by_role(
            &provider_owner,
            provider.call.aggregate.id(),
            provider_leg_id,
            ProviderReferenceRole::Destination,
        )
        .await
        .unwrap()
        .expect("provider destination reference");
    assert_eq!(
        destination_reconciliation_view.external_reference,
        Some(destination_reference.clone())
    );
    assert_eq!(
        destination_reference.role,
        ProviderReferenceRole::Destination
    );
    assert_ne!(media_reference.value, destination_reference.value);

    let claimed_provider_event = repository
        .claim_provider_events(worker, at(24), Duration::from_secs(30), 8)
        .await
        .unwrap()
        .into_iter()
        .find(|claimed| claimed.event.event_digest == provider_event_digest)
        .expect("released provider event was not claimable");
    let provider_target = ProviderEventTarget {
        tenant_id: provider_owner.clone(),
        call_id: provider.call.aggregate.id(),
        leg_id: provider_leg_id,
        role: ProviderReferenceRole::Media,
    };
    let current_provider = repository
        .load_service_call(&provider_owner, provider.call.aggregate.id())
        .await
        .unwrap();
    let provider_follow_up = ServiceCommandTransaction {
        command: CommandCommit {
            tenant_id: provider_owner.clone(),
            call_id: provider.call.aggregate.id(),
            expected_version: current_provider.call.aggregate.version(),
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at: at(25),
                leg_id: provider_leg_id,
                binding_generation: BindingGeneration::INITIAL,
                state: LegState::Signaling,
                failure: None,
            },
            worker,
            attachments: Vec::new(),
            deadline_claim: None,
            at: at(25),
        },
        effect_payloads: Vec::new(),
        operation_idempotency: None,
        bound_connection: None,
        media_activity: None,
        replacement_connection: None,
    };
    let provider_event_reconciliation = ProviderEventReconciliationTransaction {
        account: provider_account.clone(),
        event_digest: provider_event_digest,
        claim_generation: claimed_provider_event.claim_generation,
        worker,
        target: provider_target.clone(),
        follow_up: Some(provider_follow_up.clone()),
        at: at(25),
    };

    let raw_completion = ProviderEventCommit {
        account: provider_account.clone(),
        event_digest: provider_event_digest,
        claim_generation: claimed_provider_event.claim_generation,
        worker,
        command: provider_follow_up.command.clone(),
        at: at(25),
    };
    assert_eq!(
        repository.complete_provider_event(raw_completion).await,
        Err(RepositoryError::InvalidInput(
            "service-managed provider event requires service reconciliation"
        ))
    );

    let mut stale_claim = provider_event_reconciliation.clone();
    stale_claim.claim_generation = Default::default();
    assert_eq!(
        repository.reconcile_provider_event(stale_claim).await,
        Err(RepositoryError::StaleClaim)
    );

    let mut cross_tenant = provider_event_reconciliation.clone();
    cross_tenant.target.tenant_id = tenant("provider-event-other-owner");
    assert_eq!(
        repository.reconcile_provider_event(cross_tenant).await,
        Err(RepositoryError::ProviderReferenceConflict)
    );

    let mut cross_tenant_follow_up = provider_event_reconciliation.clone();
    cross_tenant_follow_up
        .follow_up
        .as_mut()
        .unwrap()
        .command
        .tenant_id = tenant("provider-event-other-owner");
    assert_eq!(
        repository
            .reconcile_provider_event(cross_tenant_follow_up)
            .await,
        Err(RepositoryError::InvalidInput(
            "provider follow-up ownership or timestamp differs"
        ))
    );

    let mut wrong_account = provider_event_reconciliation.clone();
    wrong_account.account = ProviderAccountKey::parse("other-provider-account").unwrap();
    assert_eq!(
        repository.reconcile_provider_event(wrong_account).await,
        Err(RepositoryError::NotFound)
    );

    let mut wrong_leg = provider_event_reconciliation.clone();
    wrong_leg.target.leg_id = provider_peer_leg_id;
    assert_eq!(
        repository.reconcile_provider_event(wrong_leg).await,
        Err(RepositoryError::ProviderReferenceConflict)
    );

    let mut wrong_follow_up_leg = provider_event_reconciliation.clone();
    let CallCommand::SetLegState { leg_id, .. } = &mut wrong_follow_up_leg
        .follow_up
        .as_mut()
        .unwrap()
        .command
        .command
    else {
        panic!("expected provider leg-state follow-up")
    };
    *leg_id = provider_peer_leg_id;
    assert_eq!(
        repository
            .reconcile_provider_event(wrong_follow_up_leg)
            .await,
        Err(RepositoryError::InvalidInput(
            "provider follow-up does not match the referenced provider leg"
        ))
    );

    let mut wrong_command = provider_event_reconciliation.clone();
    wrong_command.follow_up.as_mut().unwrap().command.command = CallCommand::StartConnecting {
        at: at(25),
        setup_deadline: at(55),
    };
    assert_eq!(
        repository.reconcile_provider_event(wrong_command).await,
        Err(RepositoryError::InvalidInput(
            "provider follow-up does not match the referenced provider leg"
        ))
    );

    let mut reused_cross_call_command = provider_event_reconciliation.clone();
    reused_cross_call_command
        .follow_up
        .as_mut()
        .unwrap()
        .command
        .command_id = transfer_request.command.command_id;
    assert_eq!(
        repository
            .reconcile_provider_event(reused_cross_call_command)
            .await,
        Err(RepositoryError::CommandConflict)
    );

    let ProviderEventReconciliationOutcome::Reconciled(provider_event_reconciliation_view) =
        repository
            .reconcile_provider_event(provider_event_reconciliation.clone())
            .await
            .unwrap()
    else {
        panic!("fresh provider event reconciliation replayed")
    };
    assert_eq!(
        provider_event_reconciliation_view.event.state,
        ProviderEventState::Applied
    );
    assert!(provider_event_reconciliation_view.follow_up.is_some());
    assert_eq!(
        repository
            .reconcile_provider_event(provider_event_reconciliation.clone())
            .await
            .unwrap(),
        ProviderEventReconciliationOutcome::Replayed(provider_event_reconciliation_view.clone())
    );
    let mut mismatched_replay = provider_event_reconciliation.clone();
    mismatched_replay
        .follow_up
        .as_mut()
        .unwrap()
        .command
        .command_id = CommandId::new();
    assert_eq!(
        repository.reconcile_provider_event(mismatched_replay).await,
        Err(RepositoryError::StaleClaim)
    );
    assert!(matches!(
        repository.ingest_provider_event(provider_event).await.unwrap(),
        ProviderEventOutcome::Duplicate(ref event) if event.state == ProviderEventState::Applied
    ));

    ConformanceEvidence {
        owner,
        worker,
        call_id: active.command.call.aggregate.id(),
        original_create: service_call,
        control_leg_id: inbound_leg,
        plan,
        command_request,
        command_view,
        inbound_lifecycle_request,
        inbound_lifecycle_view,
        outbound_lifecycle_request,
        outbound_lifecycle_view,
        media_activity_request,
        media_activity_view,
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
        provider_peer_leg_id,
        cross_call_connection_id,
        provider_reconciliation,
        provider_reconciliation_view,
        provider_event_reconciliation,
        provider_event_reconciliation_view,
    }
}

async fn assert_restart_replays<R>(repository: &R, evidence: &ConformanceEvidence)
where
    R: CallServiceRepository + Sync,
{
    // The attachment was consumed and its two-minute token has expired by this
    // observation. The retained 24-hour create receipt must still return the
    // immutable original descriptors; this read must not purge or rewrite it.
    assert_eq!(
        repository
            .load_create_replay(
                &evidence.owner,
                IdempotencyKeyDigest::new(digest(10)),
                RequestDigest::new(digest(11)),
                at(123),
            )
            .await
            .unwrap(),
        Some(evidence.original_create.clone())
    );
    assert_eq!(
        repository
            .load_create_replay(
                &evidence.owner,
                IdempotencyKeyDigest::new(digest(10)),
                RequestDigest::new(digest(99)),
                at(123),
            )
            .await,
        Err(RepositoryError::IdempotencyConflict)
    );
    assert_eq!(
        repository
            .load_service_call(&evidence.owner, evidence.call_id)
            .await
            .unwrap()
            .plan,
        evidence.plan
    );
    let transfer_idempotency = evidence
        .transfer_request
        .operation_idempotency
        .as_ref()
        .expect("transfer conformance request must be idempotent");
    assert_eq!(
        repository
            .load_service_command_replay(
                &tenant("other-replay-tenant"),
                evidence.call_id,
                transfer_idempotency.key_digest,
                transfer_idempotency.request_digest,
                transfer_idempotency.operation,
                at(123),
            )
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        repository
            .load_service_command_replay(
                &evidence.owner,
                evidence.call_id,
                transfer_idempotency.key_digest,
                transfer_idempotency.request_digest,
                transfer_idempotency.operation,
                at(123),
            )
            .await
            .unwrap(),
        Some(evidence.transfer_view.clone())
    );
    assert_eq!(
        repository
            .load_service_command_replay(
                &evidence.owner,
                evidence.call_id,
                transfer_idempotency.key_digest,
                RequestDigest::new(digest(99)),
                transfer_idempotency.operation,
                at(123),
            )
            .await,
        Err(RepositoryError::IdempotencyConflict)
    );
    assert_eq!(
        repository
            .load_service_command_replay(
                &evidence.owner,
                CallId::new(),
                transfer_idempotency.key_digest,
                transfer_idempotency.request_digest,
                transfer_idempotency.operation,
                at(123),
            )
            .await,
        Err(RepositoryError::IdempotencyConflict)
    );
    assert_eq!(
        repository
            .load_service_command_replay(
                &evidence.owner,
                evidence.call_id,
                transfer_idempotency.key_digest,
                transfer_idempotency.request_digest,
                ServiceOperationKind::HangupCall,
                at(123),
            )
            .await,
        Err(RepositoryError::IdempotencyConflict)
    );
    assert_eq!(
        repository
            .load_service_command_replay(
                &evidence.owner,
                evidence.call_id,
                transfer_idempotency.key_digest,
                transfer_idempotency.request_digest,
                transfer_idempotency.operation,
                at(86_412),
            )
            .await
            .unwrap(),
        None
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
            .commit_bound_connection_state(evidence.inbound_lifecycle_request.clone())
            .await
            .unwrap(),
        ServiceCommandOutcome::Replayed(evidence.inbound_lifecycle_view.clone())
    );
    assert_eq!(
        repository
            .commit_bound_connection_state(evidence.outbound_lifecycle_request.clone())
            .await
            .unwrap(),
        ServiceCommandOutcome::Replayed(evidence.outbound_lifecycle_view.clone())
    );
    assert_eq!(
        repository
            .commit_media_activity(evidence.media_activity_request.clone())
            .await
            .unwrap(),
        ServiceCommandOutcome::Replayed(evidence.media_activity_view.clone())
    );
    let mut next_activity = evidence.media_activity_request.clone();
    next_activity.command_id = CommandId::new();
    next_activity.expected_version = evidence.transfer_view.command.call.aggregate.version();
    next_activity.activity_generation = MediaActivityGeneration::INITIAL.next().unwrap();
    next_activity.at = at(13);
    next_activity.due_at = at(43);
    assert!(matches!(
        repository
            .commit_media_activity(next_activity)
            .await
            .unwrap(),
        ServiceCommandOutcome::Committed(_)
    ));
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
            .reconcile_provider_event(evidence.provider_event_reconciliation.clone())
            .await
            .unwrap(),
        ProviderEventReconciliationOutcome::Replayed(
            evidence.provider_event_reconciliation_view.clone()
        )
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

async fn assert_expiry_and_same_key_reuse<R>(
    repository: &R,
    evidence: &ConformanceEvidence,
) -> (
    ControlCommandTransaction,
    bridgefu::call_service::ControlCommandView,
)
where
    R: CallServiceRepository + Sync,
{
    // The original DTMF receipt used key 60 at second 8. This operation is
    // deliberately much later than its fixed 24-hour retention boundary and
    // reuses the same key for a different canonical request.
    let request = ControlCommandTransaction {
        command_id: CommandId::new(),
        tenant_id: evidence.owner.clone(),
        call_id: evidence.call_id,
        leg_id: evidence.control_leg_id,
        binding_generation: BindingGeneration::INITIAL,
        worker: evidence.worker,
        intent: ControlIntent::Dtmf {
            sequence: DtmfSequence {
                digits: "7".to_owned(),
                duration_ms: 120,
                gap_ms: 60,
            },
        },
        at: at(90_000),
        operation_idempotency: Some(operation_idempotency(
            60,
            68,
            ServiceOperationKind::DtmfCall,
        )),
    };
    let ControlCommandOutcome::Enqueued(view) =
        repository.enqueue_control(request.clone()).await.unwrap()
    else {
        panic!("expired operation key unexpectedly replayed")
    };
    (request, view)
}

async fn assert_reused_key_restart<R>(
    repository: &R,
    request: ControlCommandTransaction,
    expected: bridgefu::call_service::ControlCommandView,
) where
    R: CallServiceRepository + Sync,
{
    assert_eq!(
        repository.enqueue_control(request).await.unwrap(),
        ControlCommandOutcome::Replayed(expected)
    );
}

async fn assert_control_retirement_receipt<R>(
    repository: &R,
    evidence: &ConformanceEvidence,
    effect_id: bridgefu::call_engine::EffectId,
) -> CommandId
where
    R: CallServiceRepository + Sync,
{
    let current = repository
        .load_service_call(&evidence.owner, evidence.call_id)
        .await
        .unwrap();
    let command_id = CommandId::new();
    let outcome = repository
        .commit_with_effect_payloads(ServiceCommandTransaction {
            command: CommandCommit {
                tenant_id: evidence.owner.clone(),
                call_id: evidence.call_id,
                expected_version: current.call.aggregate.version(),
                command_id,
                command: CallCommand::BeginEnding {
                    at: at(90_001),
                    ending_deadline: Some(at(90_031)),
                    reason: StopLegReason::Requested,
                },
                worker: evidence.worker,
                attachments: Vec::new(),
                deadline_claim: None,
                at: at(90_001),
            },
            effect_payloads: Vec::new(),
            operation_idempotency: None,
            bound_connection: None,
            media_activity: None,
            replacement_connection: None,
        })
        .await
        .unwrap();
    assert!(matches!(outcome, ServiceCommandOutcome::Committed(_)));
    let claimed = repository
        .claim_control_effects(evidence.worker, at(90_002), Duration::from_secs(10), 64)
        .await
        .unwrap();
    assert!(
        claimed
            .iter()
            .all(|claim| claim.record.effect_id != effect_id),
        "retired control effect remained claimable"
    );
    command_id
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
        additional_external_references: Vec::new(),
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
            additional_external_references: Vec::new(),
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
        "UPDATE calls SET service_managed = FALSE WHERE service_managed = TRUE",
        "UPDATE calls SET service_managed = TRUE WHERE service_managed = FALSE",
    ),
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
        "UPDATE idempotency SET operation_kind = 'transfer_call' WHERE receipt_kind = 'control_command' AND operation_kind = 'dtmf_call'",
        "UPDATE idempotency SET operation_kind = 'dtmf_call' WHERE receipt_kind = 'control_command' AND operation_kind = 'transfer_call'",
    ),
    (
        "UPDATE retired_operation_claims SET tenant_id = tenant_id || '_drift'",
        "UPDATE retired_operation_claims SET tenant_id = substr(tenant_id, 1, length(tenant_id) - 6)",
    ),
    (
        "UPDATE control_outbox_retirements SET failure_code = failure_code || '_drift'",
        "UPDATE control_outbox_retirements SET failure_code = substr(failure_code, 1, length(failure_code) - 6)",
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

async fn assert_sqlite_execution_authority_tamper_fails_closed(
    repository: &SqliteRepository,
    evidence: &ConformanceEvidence,
) {
    let original: Vec<u8> = sqlx::query_scalar(
        "SELECT authorization_principal_fingerprint FROM call_execution_plans WHERE call_id = ?",
    )
    .bind(evidence.call_id.to_string())
    .fetch_one(repository.pool())
    .await
    .unwrap();
    sqlx::query(
        "UPDATE call_execution_plans SET authorization_principal_fingerprint = zeroblob(32) WHERE call_id = ?",
    )
    .bind(evidence.call_id.to_string())
    .execute(repository.pool())
    .await
    .unwrap();
    assert_eq!(
        repository
            .load_service_call(&evidence.owner, evidence.call_id)
            .await,
        Err(RepositoryError::Unavailable)
    );
    sqlx::query(
        "UPDATE call_execution_plans SET authorization_principal_fingerprint = ? WHERE call_id = ?",
    )
    .bind(original)
    .bind(evidence.call_id.to_string())
    .execute(repository.pool())
    .await
    .unwrap();
    repository
        .load_service_call(&evidence.owner, evidence.call_id)
        .await
        .unwrap();

    let media_command_id = evidence.media_activity_request.command_id.to_string();
    let media_original: String =
        sqlx::query_scalar("SELECT body FROM service_command_results WHERE command_id = ?")
            .bind(&media_command_id)
            .fetch_one(repository.pool())
            .await
            .unwrap();
    sqlx::query(
        "UPDATE service_command_results SET body = json_set(body, '$.result.request.media_activity.activity_generation', 2) WHERE command_id = ?",
    )
    .bind(&media_command_id)
    .execute(repository.pool())
    .await
    .unwrap();
    assert_eq!(
        repository
            .load_service_call(&evidence.owner, evidence.call_id)
            .await,
        Err(RepositoryError::Unavailable),
        "SQLite accepted a non-consecutive media activity generation"
    );
    sqlx::query("UPDATE service_command_results SET body = ? WHERE command_id = ?")
        .bind(media_original)
        .bind(media_command_id)
        .execute(repository.pool())
        .await
        .unwrap();
    repository
        .load_service_call(&evidence.owner, evidence.call_id)
        .await
        .unwrap();
}

async fn assert_postgres_execution_authority_tamper_fails_closed(
    repository: &PostgresRepository,
    evidence: &ConformanceEvidence,
) {
    let original: Vec<u8> = sqlx::query_scalar(
        "SELECT authorization_principal_fingerprint FROM call_execution_plans WHERE call_id = $1",
    )
    .bind(evidence.call_id.as_uuid())
    .fetch_one(repository.pool())
    .await
    .unwrap();
    sqlx::query(
        "UPDATE call_execution_plans SET authorization_principal_fingerprint = decode(repeat('00', 32), 'hex') WHERE call_id = $1",
    )
    .bind(evidence.call_id.as_uuid())
    .execute(repository.pool())
    .await
    .unwrap();
    assert_eq!(
        repository
            .load_service_call(&evidence.owner, evidence.call_id)
            .await,
        Err(RepositoryError::Unavailable)
    );
    sqlx::query(
        "UPDATE call_execution_plans SET authorization_principal_fingerprint = $1 WHERE call_id = $2",
    )
    .bind(original)
    .bind(evidence.call_id.as_uuid())
    .execute(repository.pool())
    .await
    .unwrap();
    repository
        .load_service_call(&evidence.owner, evidence.call_id)
        .await
        .unwrap();

    let media_command_id = evidence.media_activity_request.command_id.to_string();
    let media_original: String = sqlx::query_scalar(
        "SELECT body::text FROM service_command_results WHERE command_id = $1::uuid",
    )
    .bind(&media_command_id)
    .fetch_one(repository.pool())
    .await
    .unwrap();
    sqlx::query(
        "UPDATE service_command_results SET body = jsonb_set(body, '{result,request,media_activity,activity_generation}', '2'::jsonb, false) WHERE command_id = $1::uuid",
    )
    .bind(&media_command_id)
    .execute(repository.pool())
    .await
    .unwrap();
    assert_eq!(
        repository
            .load_service_call(&evidence.owner, evidence.call_id)
            .await,
        Err(RepositoryError::Unavailable),
        "PostgreSQL accepted a non-consecutive media activity generation"
    );
    sqlx::query("UPDATE service_command_results SET body = $1::jsonb WHERE command_id = $2::uuid")
        .bind(media_original)
        .bind(media_command_id)
        .execute(repository.pool())
        .await
        .unwrap();
    repository
        .load_service_call(&evidence.owner, evidence.call_id)
        .await
        .unwrap();
}

async fn assert_sqlite_bound_guard_tamper_fails_closed(
    repository: &SqliteRepository,
    evidence: &ConformanceEvidence,
) {
    let command_id = evidence.inbound_lifecycle_request.command_id.to_string();
    let original: String =
        sqlx::query_scalar("SELECT body FROM service_command_results WHERE command_id = ?")
            .bind(&command_id)
            .fetch_one(repository.pool())
            .await
            .unwrap();
    let cross_call_connection_id = evidence.cross_call_connection_id.to_string();
    let changed = sqlx::query(
        "UPDATE service_command_results SET body = json_set(body, '$.result.request.bound_connection.connection_id', ?) WHERE command_id = ?",
    )
    .bind(&cross_call_connection_id)
    .bind(&command_id)
    .execute(repository.pool())
    .await
    .unwrap();
    assert_eq!(changed.rows_affected(), 1);
    let stored_guard: String = sqlx::query_scalar(
        "SELECT json_extract(body, '$.result.request.bound_connection.connection_id') FROM service_command_results WHERE command_id = ?",
    )
    .bind(&command_id)
    .fetch_one(repository.pool())
    .await
    .unwrap();
    assert_eq!(stored_guard, cross_call_connection_id);
    assert_eq!(
        repository
            .load_service_call(&evidence.owner, evidence.call_id)
            .await,
        Err(RepositoryError::Unavailable),
        "SQLite accepted a lifecycle guard backed by a different call"
    );
    sqlx::query("UPDATE service_command_results SET body = ? WHERE command_id = ?")
        .bind(original)
        .bind(command_id)
        .execute(repository.pool())
        .await
        .unwrap();
    repository
        .load_service_call(&evidence.owner, evidence.call_id)
        .await
        .unwrap();
}

async fn assert_postgres_bound_guard_tamper_fails_closed(
    repository: &PostgresRepository,
    evidence: &ConformanceEvidence,
) {
    let command_id = evidence.inbound_lifecycle_request.command_id.to_string();
    let original: String = sqlx::query_scalar(
        "SELECT body::text FROM service_command_results WHERE command_id = $1::uuid",
    )
    .bind(&command_id)
    .fetch_one(repository.pool())
    .await
    .unwrap();
    let cross_call_connection_id = evidence.cross_call_connection_id.to_string();
    let changed = sqlx::query(
        "UPDATE service_command_results SET body = jsonb_set(body, '{result,request,bound_connection,connection_id}', to_jsonb($1::text), false) WHERE command_id = $2::uuid",
    )
    .bind(&cross_call_connection_id)
    .bind(&command_id)
    .execute(repository.pool())
    .await
    .unwrap();
    assert_eq!(changed.rows_affected(), 1);
    let stored_guard: String = sqlx::query_scalar(
        "SELECT body #>> '{result,request,bound_connection,connection_id}' FROM service_command_results WHERE command_id = $1::uuid",
    )
    .bind(&command_id)
    .fetch_one(repository.pool())
    .await
    .unwrap();
    assert_eq!(stored_guard, cross_call_connection_id);
    assert_eq!(
        repository
            .load_service_call(&evidence.owner, evidence.call_id)
            .await,
        Err(RepositoryError::Unavailable),
        "PostgreSQL accepted a lifecycle guard backed by a different call"
    );
    sqlx::query("UPDATE service_command_results SET body = $1::jsonb WHERE command_id = $2::uuid")
        .bind(original)
        .bind(command_id)
        .execute(repository.pool())
        .await
        .unwrap();
    repository
        .load_service_call(&evidence.owner, evidence.call_id)
        .await
        .unwrap();
}

async fn assert_sqlite_provider_completion_tamper_fails_closed(
    repository: &SqliteRepository,
    evidence: &ConformanceEvidence,
) {
    let original: String = sqlx::query_scalar(
        "SELECT body FROM provider_completions WHERE completion_kind = 'service_reconciliation'",
    )
    .fetch_one(repository.pool())
    .await
    .unwrap();
    let changed = sqlx::query(
        "UPDATE provider_completions SET body = json_set(body, '$.row.ServiceReconciliation.request.target.leg_id', ?) WHERE completion_kind = 'service_reconciliation'",
    )
    .bind(evidence.provider_peer_leg_id.to_string())
    .execute(repository.pool())
    .await
    .unwrap();
    assert_eq!(changed.rows_affected(), 1);
    assert_eq!(
        repository
            .load_service_call(&evidence.provider_owner, evidence.provider_call_id)
            .await,
        Err(RepositoryError::Unavailable),
        "SQLite accepted a provider completion with a forged target leg"
    );
    sqlx::query(
        "UPDATE provider_completions SET body = ? WHERE completion_kind = 'service_reconciliation'",
    )
    .bind(original)
    .execute(repository.pool())
    .await
    .unwrap();
    repository
        .load_service_call(&evidence.provider_owner, evidence.provider_call_id)
        .await
        .unwrap();
}

async fn assert_postgres_provider_completion_tamper_fails_closed(
    repository: &PostgresRepository,
    evidence: &ConformanceEvidence,
) {
    let original: String = sqlx::query_scalar(
        "SELECT body::text FROM provider_completions WHERE completion_kind = 'service_reconciliation'",
    )
    .fetch_one(repository.pool())
    .await
    .unwrap();
    let changed = sqlx::query(
        "UPDATE provider_completions SET body = jsonb_set(body, '{row,ServiceReconciliation,request,target,leg_id}', to_jsonb($1::text), false) WHERE completion_kind = 'service_reconciliation'",
    )
    .bind(evidence.provider_peer_leg_id.to_string())
    .execute(repository.pool())
    .await
    .unwrap();
    assert_eq!(changed.rows_affected(), 1);
    assert_eq!(
        repository
            .load_service_call(&evidence.provider_owner, evidence.provider_call_id)
            .await,
        Err(RepositoryError::Unavailable),
        "PostgreSQL accepted a provider completion with a forged target leg"
    );
    sqlx::query(
        "UPDATE provider_completions SET body = $1::jsonb WHERE completion_kind = 'service_reconciliation'",
    )
    .bind(original)
    .execute(repository.pool())
    .await
    .unwrap();
    repository
        .load_service_call(&evidence.provider_owner, evidence.provider_call_id)
        .await
        .unwrap();
}

async fn assert_sqlite_deletion_fails_closed(
    repository: &SqliteRepository,
    owner: &TenantId,
    call_id: CallId,
    table: &str,
    predicate: &str,
) {
    let backup = format!("integrity_backup_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE TABLE {backup} AS SELECT * FROM {table} WHERE {predicate}"
    ))
    .execute(repository.pool())
    .await
    .unwrap();
    let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {backup}"))
        .fetch_one(repository.pool())
        .await
        .unwrap();
    assert_eq!(count, 1, "integrity deletion fixture was ambiguous");
    sqlx::query(&format!("DELETE FROM {table} WHERE {predicate}"))
        .execute(repository.pool())
        .await
        .unwrap();
    assert_eq!(
        repository.load_service_call(owner, call_id).await,
        Err(RepositoryError::Unavailable),
        "deletion from {table} was accepted"
    );
    sqlx::query(&format!("INSERT INTO {table} SELECT * FROM {backup}"))
        .execute(repository.pool())
        .await
        .unwrap();
    sqlx::query(&format!("DROP TABLE {backup}"))
        .execute(repository.pool())
        .await
        .unwrap();
    repository.load_service_call(owner, call_id).await.unwrap();
}

async fn assert_postgres_deletion_fails_closed(
    repository: &PostgresRepository,
    owner: &TenantId,
    call_id: CallId,
    table: &str,
    predicate: &str,
) {
    let backup = format!("integrity_backup_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE TABLE {backup} AS SELECT * FROM {table} WHERE {predicate}"
    ))
    .execute(repository.pool())
    .await
    .unwrap();
    let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {backup}"))
        .fetch_one(repository.pool())
        .await
        .unwrap();
    assert_eq!(count, 1, "integrity deletion fixture was ambiguous");
    sqlx::query(&format!("DELETE FROM {table} WHERE {predicate}"))
        .execute(repository.pool())
        .await
        .unwrap();
    assert_eq!(
        repository.load_service_call(owner, call_id).await,
        Err(RepositoryError::Unavailable),
        "deletion from {table} was accepted"
    );
    sqlx::query(&format!("INSERT INTO {table} SELECT * FROM {backup}"))
        .execute(repository.pool())
        .await
        .unwrap();
    sqlx::query(&format!("DROP TABLE {backup}"))
        .execute(repository.pool())
        .await
        .unwrap();
    repository.load_service_call(owner, call_id).await.unwrap();
}

#[tokio::test]
async fn memory_service_repository_conformance() {
    let repository = MemoryRepository::new();
    let mut evidence = assert_service_conformance(&repository).await;
    assert_restart_replays(&repository, &evidence).await;
    let current_worker = repository
        .worker_snapshot(evidence.worker.worker_id)
        .await
        .unwrap();
    let replacement = repository
        .register_worker(RegisterWorker {
            worker_id: evidence.worker.worker_id,
            max_calls: current_worker.max_calls,
            capabilities: current_worker.capabilities,
            at: at(89_999),
            lease_ttl: Duration::from_secs(300),
        })
        .await
        .unwrap()
        .lease;
    let restarted = repository
        .claim_restart_calls(replacement, at(89_999), 8)
        .await
        .unwrap();
    assert!(restarted
        .iter()
        .any(|claim| claim.call.aggregate.id() == evidence.call_id));
    assert!(restarted
        .iter()
        .any(|claim| claim.call.aggregate.id() == evidence.provider_call_id));
    evidence.worker = replacement;
    let (request, view) = assert_expiry_and_same_key_reuse(&repository, &evidence).await;
    let effect_id = view.effect.effect_id;
    assert_reused_key_restart(&repository, request, view).await;
    assert_control_retirement_receipt(&repository, &evidence, effect_id).await;
}

#[tokio::test]
async fn sqlite_attachment_expiry_uses_database_authority() {
    let (url, path) = sqlite_database("attachment-authority");
    let repository = SqliteRepository::connect(&url).await.unwrap();
    let database_now =
        sqlx::query_scalar::<_, String>("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')")
            .fetch_one(repository.pool())
            .await
            .unwrap();
    let database_now = DateTime::parse_from_rfc3339(&database_now)
        .unwrap()
        .with_timezone(&Utc);
    assert_database_authoritative_attachment_expiry(&repository, database_now).await;
    repository.pool().close().await;
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn postgres_attachment_expiry_uses_database_authority() {
    let Some(url) = std::env::var("BRIDGEFU_TEST_POSTGRES_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
    else {
        return;
    };
    let administration = sqlx::PgPool::connect(&url).await.unwrap();
    let schema = format!("bridgefu_attachment_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&administration)
        .await
        .unwrap();
    let mut scoped = url::Url::parse(&url).unwrap();
    scoped
        .query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"));
    let repository = PostgresRepository::connect(scoped.as_str()).await.unwrap();
    let database_now = sqlx::query_scalar::<_, DateTime<Utc>>("SELECT clock_timestamp()")
        .fetch_one(repository.pool())
        .await
        .unwrap();
    assert_database_authoritative_attachment_expiry(&repository, database_now).await;
    repository.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&administration)
        .await
        .unwrap();
    administration.close().await;
}

#[tokio::test]
async fn sqlite_service_repository_conformance_restart_and_races() {
    let (url, path) = sqlite_database("conformance");
    let first = SqliteRepository::connect(&url).await.unwrap();
    let evidence = assert_service_conformance(&first).await;
    let second = SqliteRepository::connect(&url).await.unwrap();
    let replay_epoch_before: i64 =
        sqlx::query_scalar("SELECT epoch FROM repository_metadata WHERE singleton = 1")
            .fetch_one(second.pool())
            .await
            .unwrap();
    assert_eq!(
        second
            .load_create_replay(
                &evidence.owner,
                IdempotencyKeyDigest::new(digest(10)),
                RequestDigest::new(digest(11)),
                at(123),
            )
            .await
            .unwrap(),
        Some(evidence.original_create.clone())
    );
    let replay_epoch_after: i64 =
        sqlx::query_scalar("SELECT epoch FROM repository_metadata WHERE singleton = 1")
            .fetch_one(second.pool())
            .await
            .unwrap();
    assert_eq!(replay_epoch_after, replay_epoch_before);
    assert_restart_replays(&second, &evidence).await;
    assert_sqlite_execution_authority_tamper_fails_closed(&second, &evidence).await;
    assert_sqlite_bound_guard_tamper_fails_closed(&second, &evidence).await;
    assert_sqlite_provider_completion_tamper_fails_closed(&second, &evidence).await;
    assert_two_instance_control_race(&first, &second, &evidence).await;
    let (request, view) = assert_expiry_and_same_key_reuse(&second, &evidence).await;
    let third = SqliteRepository::connect(&url).await.unwrap();
    let effect_id = view.effect.effect_id;
    assert_reused_key_restart(&third, request, view).await;

    assert_sqlite_deletion_fails_closed(
        &third,
        &evidence.owner,
        evidence.call_id,
        "attachments",
        &format!("call_id = '{}'", evidence.call_id),
    )
    .await;
    assert_sqlite_deletion_fails_closed(
        &third,
        &evidence.owner,
        evidence.call_id,
        "idempotency",
        &format!(
            "tenant_id = '{}' AND hex(key_digest) = '{}'",
            evidence.owner,
            digest_hex(60, true)
        ),
    )
    .await;
    assert_sqlite_deletion_fails_closed(
        &third,
        &evidence.owner,
        evidence.call_id,
        "retired_operation_claims",
        &format!("command_id = '{}'", evidence.control_request.command_id),
    )
    .await;
    assert_sqlite_deletion_fails_closed(
        &third,
        &evidence.owner,
        evidence.call_id,
        "retired_operation_claims",
        &format!(
            "command_id = '{}'",
            evidence.transfer_request.command.command_id
        ),
    )
    .await;
    assert_sqlite_deletion_fails_closed(
        &third,
        &evidence.owner,
        evidence.call_id,
        "reconciliation_results",
        &format!(
            "effect_id = '{}'",
            evidence.control_reconciliation.effect_id
        ),
    )
    .await;
    assert_sqlite_deletion_fails_closed(
        &third,
        &evidence.provider_owner,
        evidence.provider_call_id,
        "reconciliation_results",
        &format!(
            "effect_id = '{}'",
            evidence.provider_reconciliation.effect_id
        ),
    )
    .await;
    assert_sqlite_deletion_fails_closed(
        &third,
        &evidence.provider_owner,
        evidence.provider_call_id,
        "provider_completions",
        "completion_kind = 'service_reconciliation'",
    )
    .await;
    assert_sqlite_deletion_fails_closed(
        &third,
        &evidence.owner,
        evidence.call_id,
        "outbound_binding_results",
        &format!(
            "operation_id = '{}'",
            evidence.outbound_request.operation_id
        ),
    )
    .await;

    let retirement_command = assert_control_retirement_receipt(&third, &evidence, effect_id).await;
    assert_sqlite_service_drift_detection(&first, &evidence).await;
    assert!(
        sqlx::query("SELECT command_id FROM retired_operation_claims")
            .fetch_all(third.pool())
            .await
            .unwrap()
            .len()
            >= 2
    );
    let stored_retirement_command: String =
        sqlx::query_scalar("SELECT command_id FROM control_outbox_retirements WHERE effect_id = ?")
            .bind(effect_id.to_string())
            .fetch_one(third.pool())
            .await
            .unwrap();
    assert_eq!(stored_retirement_command, retirement_command.to_string());
    assert_sqlite_deletion_fails_closed(
        &third,
        &evidence.owner,
        evidence.call_id,
        "control_outbox_retirements",
        &format!("effect_id = '{effect_id}'"),
    )
    .await;

    sqlx::query(
        "UPDATE commands SET body = json_set(body, '$.command.disposition', 'ignored_noop', '$.result.command.disposition', 'ignored_noop') WHERE command_id = ?",
    )
    .bind(retirement_command.to_string())
        .execute(third.pool())
        .await
        .unwrap();
    assert_eq!(
        third
            .load_service_call(&evidence.owner, evidence.call_id)
            .await,
        Err(RepositoryError::Unavailable),
        "an ignored command was accepted as causal retirement evidence"
    );
    sqlx::query(
        "UPDATE commands SET body = json_set(body, '$.command.disposition', 'applied', '$.result.command.disposition', 'applied') WHERE command_id = ?",
    )
    .bind(retirement_command.to_string())
    .execute(third.pool())
    .await
    .unwrap();
    third
        .load_service_call(&evidence.owner, evidence.call_id)
        .await
        .unwrap();

    sqlx::query("DELETE FROM call_execution_plans WHERE call_id = ?")
        .bind(evidence.call_id.to_string())
        .execute(third.pool())
        .await
        .unwrap();
    assert_eq!(
        third
            .load_service_call(&evidence.owner, evidence.call_id)
            .await,
        Err(RepositoryError::Unavailable),
        "a managed call with a deleted execution plan was accepted as raw"
    );
    first.pool().close().await;
    second.pool().close().await;
    third.pool().close().await;
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
    let replay_epoch_before: i64 =
        sqlx::query_scalar("SELECT epoch FROM repository_metadata WHERE singleton = TRUE")
            .fetch_one(second.pool())
            .await
            .unwrap();
    assert_eq!(
        second
            .load_create_replay(
                &evidence.owner,
                IdempotencyKeyDigest::new(digest(10)),
                RequestDigest::new(digest(11)),
                at(123),
            )
            .await
            .unwrap(),
        Some(evidence.original_create.clone())
    );
    let replay_epoch_after: i64 =
        sqlx::query_scalar("SELECT epoch FROM repository_metadata WHERE singleton = TRUE")
            .fetch_one(second.pool())
            .await
            .unwrap();
    assert_eq!(replay_epoch_after, replay_epoch_before);
    assert_restart_replays(&second, &evidence).await;
    assert_postgres_execution_authority_tamper_fails_closed(&second, &evidence).await;
    assert_postgres_bound_guard_tamper_fails_closed(&second, &evidence).await;
    assert_postgres_provider_completion_tamper_fails_closed(&second, &evidence).await;
    assert_two_instance_control_race(&first, &second, &evidence).await;
    let (request, view) = assert_expiry_and_same_key_reuse(&second, &evidence).await;
    let third = PostgresRepository::connect(&scoped).await.unwrap();
    let effect_id = view.effect.effect_id;
    assert_reused_key_restart(&third, request, view).await;

    assert_postgres_deletion_fails_closed(
        &third,
        &evidence.owner,
        evidence.call_id,
        "attachments",
        &format!("call_id = '{}'::uuid", evidence.call_id),
    )
    .await;
    assert_postgres_deletion_fails_closed(
        &third,
        &evidence.owner,
        evidence.call_id,
        "idempotency",
        &format!(
            "tenant_id = '{}' AND encode(key_digest, 'hex') = '{}'",
            evidence.owner,
            digest_hex(60, false)
        ),
    )
    .await;
    assert_postgres_deletion_fails_closed(
        &third,
        &evidence.owner,
        evidence.call_id,
        "retired_operation_claims",
        &format!(
            "command_id = '{}'::uuid",
            evidence.control_request.command_id
        ),
    )
    .await;
    assert_postgres_deletion_fails_closed(
        &third,
        &evidence.owner,
        evidence.call_id,
        "retired_operation_claims",
        &format!(
            "command_id = '{}'::uuid",
            evidence.transfer_request.command.command_id
        ),
    )
    .await;
    assert_postgres_deletion_fails_closed(
        &third,
        &evidence.owner,
        evidence.call_id,
        "reconciliation_results",
        &format!(
            "effect_id = '{}'::uuid",
            evidence.control_reconciliation.effect_id
        ),
    )
    .await;
    assert_postgres_deletion_fails_closed(
        &third,
        &evidence.provider_owner,
        evidence.provider_call_id,
        "reconciliation_results",
        &format!(
            "effect_id = '{}'::uuid",
            evidence.provider_reconciliation.effect_id
        ),
    )
    .await;
    assert_postgres_deletion_fails_closed(
        &third,
        &evidence.provider_owner,
        evidence.provider_call_id,
        "provider_completions",
        "completion_kind = 'service_reconciliation'",
    )
    .await;
    assert_postgres_deletion_fails_closed(
        &third,
        &evidence.owner,
        evidence.call_id,
        "outbound_binding_results",
        &format!(
            "operation_id = '{}'::uuid",
            evidence.outbound_request.operation_id
        ),
    )
    .await;

    let retirement_command = assert_control_retirement_receipt(&third, &evidence, effect_id).await;
    assert_postgres_service_drift_detection(&first, &evidence).await;
    assert!(
        sqlx::query("SELECT command_id FROM retired_operation_claims")
            .fetch_all(third.pool())
            .await
            .unwrap()
            .len()
            >= 2
    );
    let stored_retirement_command: uuid::Uuid = sqlx::query_scalar(
        "SELECT command_id FROM control_outbox_retirements WHERE effect_id = $1",
    )
    .bind(effect_id.as_uuid())
    .fetch_one(third.pool())
    .await
    .unwrap();
    assert_eq!(
        stored_retirement_command.to_string(),
        retirement_command.to_string()
    );
    assert_postgres_deletion_fails_closed(
        &third,
        &evidence.owner,
        evidence.call_id,
        "control_outbox_retirements",
        &format!("effect_id = '{effect_id}'::uuid"),
    )
    .await;

    sqlx::query(
        "UPDATE commands SET body = jsonb_set(jsonb_set(body, '{command,disposition}', '\"ignored_noop\"'::jsonb), '{result,command,disposition}', '\"ignored_noop\"'::jsonb) WHERE command_id = $1",
    )
    .bind(retirement_command.as_uuid())
        .execute(third.pool())
        .await
        .unwrap();
    assert_eq!(
        third
            .load_service_call(&evidence.owner, evidence.call_id)
            .await,
        Err(RepositoryError::Unavailable),
        "an ignored command was accepted as causal retirement evidence"
    );
    sqlx::query(
        "UPDATE commands SET body = jsonb_set(jsonb_set(body, '{command,disposition}', '\"applied\"'::jsonb), '{result,command,disposition}', '\"applied\"'::jsonb) WHERE command_id = $1",
    )
    .bind(retirement_command.as_uuid())
    .execute(third.pool())
    .await
    .unwrap();
    third
        .load_service_call(&evidence.owner, evidence.call_id)
        .await
        .unwrap();

    sqlx::query("DELETE FROM call_execution_plans WHERE call_id = $1")
        .bind(evidence.call_id.as_uuid())
        .execute(third.pool())
        .await
        .unwrap();
    assert_eq!(
        third
            .load_service_call(&evidence.owner, evidence.call_id)
            .await,
        Err(RepositoryError::Unavailable),
        "a managed call with a deleted execution plan was accepted as raw"
    );
    first.pool().close().await;
    second.pool().close().await;
    third.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&administration)
        .await
        .unwrap();
    administration.close().await;
}
