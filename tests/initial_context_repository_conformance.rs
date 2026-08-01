use std::collections::{BTreeMap, BTreeSet};

use bridgefu::call_engine::{
    AttachmentConsume, AttachmentId, AttachmentIssue, AttachmentLookup, AttachmentPurpose,
    AttachmentTokenDigest, AttachmentTransport, BindingGeneration, CallAggregate, CallCommand,
    CallId, CallRepository, ClaimGeneration, CommandCommit, CommandId, CreateCall, DeadlineKind,
    EffectId, EffectIntent, FailureDetails, IdempotencyKeyDigest, LegDirection, LegId, LegKind,
    LegReplacementResult, LegSpec, LegState, PrincipalFingerprint, RegisterWorker, RepositoryError,
    RequestDigest, TenantId, WorkerLease,
};
use bridgefu::call_service::{
    AmazonConnectEndpointConfig, AmazonConnectStartSpec, CallExecutionPlan, CallServiceRepository,
    EffectResultReconciliation, InitialContextRecordOutcome, InitialContextRecordRequest,
    LegEndpointConfig, LegExecutionSpec, NamedProfileBinding, NamedProfileKind, NamedProfileRole,
    NamedRouteBinding, OutboundConnectionBind, OutboundConnectionBindOutcome,
    ProviderEndpointConfig, ProviderKind, ReplacementConnectionPromotion,
    ReplacementInitialContextLookup, ServiceCommandOutcome, ServiceCommandTransaction,
    ServiceCreateOutcome, ServiceCreateTransaction, ServiceEffectPayload,
    ServiceEffectPayloadInput, ServiceEffectResult, SipEndpointConfig, SipInitialContextMode,
    StoredInitialContext, WebRtcEndpointConfig,
};
use bridgefu::context::{ContextEnvelope, MAX_CONTEXT_BYTES};
use bridgefu::persistence::{MemoryRepository, PostgresRepository, SqliteRepository};
use chrono::{DateTime, TimeZone, Utc};
use rvoip_core::{ConnectionId, MessageId};

fn at(second: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_930_100_000 + second, 0).unwrap()
}

fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn principal(byte: u8) -> PrincipalFingerprint {
    PrincipalFingerprint::new(digest(byte))
}

fn generation(value: u64) -> BindingGeneration {
    serde_json::from_value(serde_json::json!(value)).unwrap()
}

#[derive(Clone)]
struct PreparedContext {
    owner: TenantId,
    call_id: CallId,
    target_leg_id: LegId,
    request: InitialContextRecordRequest,
}

async fn register<R>(repository: &R) -> WorkerLease
where
    R: CallRepository + Sync,
{
    repository
        .register_worker(RegisterWorker {
            worker_id: Default::default(),
            max_calls: 32,
            capabilities: BTreeSet::from([
                "sip".to_owned(),
                "sip_egress".to_owned(),
                "webrtc".to_owned(),
                "amazon_connect".to_owned(),
                "telnyx".to_owned(),
            ]),
            at: at(0),
            lease_ttl: std::time::Duration::from_secs(300),
        })
        .await
        .unwrap()
        .lease
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
            .claim_outbox(worker, claim_at, std::time::Duration::from_secs(30), 64)
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

async fn prepare_context<R>(repository: &R, worker: WorkerLease, seed: u8) -> PreparedContext
where
    R: CallRepository + CallServiceRepository + Sync,
{
    let base = i64::from(seed) * 10;
    let owner = TenantId::parse(format!("context-owner-{seed}")).unwrap();
    let initial = CallAggregate::new(
        owner.clone(),
        [
            LegSpec {
                direction: LegDirection::Inbound,
                kind: LegKind::InteractiveWebRtc,
            },
            LegSpec {
                direction: LegDirection::Outbound,
                kind: LegKind::Sip,
            },
        ],
        at(base),
    );
    let source_leg_id = initial.legs()[0].id();
    let target_leg_id = initial.legs()[1].id();
    let plan = CallExecutionPlan::new_with_named_route(
        &initial,
        [
            LegExecutionSpec {
                leg_id: source_leg_id,
                endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                    signaling_uri: None,
                }),
            },
            LegExecutionSpec {
                leg_id: target_leg_id,
                endpoint: LegEndpointConfig::Sip(SipEndpointConfig {
                    uri: Some("sip:context-target@example.test".to_owned()),
                    initial_context: SipInitialContextMode::Required,
                }),
            },
        ],
        principal(seed.wrapping_add(40)),
        BTreeMap::new(),
        NamedRouteBinding::new_with_profiles(
            format!("context-assistant-{seed}"),
            None,
            vec![NamedProfileBinding::new(
                NamedProfileRole::Destination,
                NamedProfileKind::Sip,
                "context-assistant",
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            )
            .unwrap()],
        )
        .unwrap(),
    )
    .unwrap();
    let token_digest = AttachmentTokenDigest::new(digest(seed.wrapping_add(80)));
    let created = repository
        .create_with_plan(ServiceCreateTransaction {
            create: CreateCall {
                initial,
                command_id: CommandId::new(),
                command: CallCommand::StartConnecting {
                    at: at(base + 1),
                    setup_deadline: at(base + 301),
                },
                worker,
                idempotency_key: IdempotencyKeyDigest::new(digest(seed)),
                request_digest: RequestDigest::new(digest(seed.wrapping_add(1))),
                attachments: vec![AttachmentIssue {
                    attachment_id: AttachmentId::new(),
                    token_digest,
                    purpose: AttachmentPurpose::PublicInbound,
                    leg_id: source_leg_id,
                    binding_generation: BindingGeneration::INITIAL,
                    transport: AttachmentTransport::WebRtc,
                    expected_principal: principal(seed.wrapping_add(2)),
                    expires_at: at(base + 121),
                }],
                at: at(base + 1),
            },
            plan,
            alternatives: Vec::new(),
        })
        .await
        .unwrap();
    let call_id = match created {
        ServiceCreateOutcome::Created(call) => call.call.aggregate.id(),
        ServiceCreateOutcome::Replayed(_) => panic!("fresh context call replayed"),
    };
    let candidate = repository
        .inspect_inbound_attachment(AttachmentLookup {
            token_digest,
            tenant_id: owner.clone(),
            transport: AttachmentTransport::WebRtc,
            principal_fingerprint: principal(seed.wrapping_add(2)),
            worker,
            at: at(base + 2),
        })
        .await
        .unwrap();
    let connection_id = ConnectionId::from_string(format!("context-source-{seed}"));
    repository
        .consume_inbound_attachment(AttachmentConsume {
            candidate,
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at: at(base + 2),
                leg_id: source_leg_id,
                binding_generation: BindingGeneration::INITIAL,
                state: LegState::Signaling,
                failure: None,
            },
            connection_id: connection_id.clone(),
            principal_fingerprint: principal(seed.wrapping_add(2)),
            principal_expires_at: None,
            at: at(base + 2),
        })
        .await
        .unwrap();

    let mut envelope = ContextEnvelope::new(
        format!("secret-correlation-{seed}"),
        owner.as_str(),
        call_id.to_string(),
        source_leg_id.to_string(),
    );
    envelope
        .metadata
        .insert("account_ref".to_owned(), format!("secret-account-{seed}"));
    let request = InitialContextRecordRequest {
        tenant_id: owner.clone(),
        call_id,
        source_connection_id: connection_id,
        source_leg_id,
        source_binding_generation: BindingGeneration::INITIAL,
        target_leg_id,
        target_binding_generation: BindingGeneration::INITIAL,
        message_id: MessageId::from_string(format!("secret-message-{seed}")),
        envelope: serde_json::to_vec(&envelope).unwrap(),
        initial_sip_headers: vec![
            (
                "X-Correlation-Id".to_owned(),
                format!("secret-correlation-{seed}"),
            ),
            ("X-Account-Ref".to_owned(), format!("secret-account-{seed}")),
        ],
        recorded_at: at(base + 3),
    };
    PreparedContext {
        owner,
        call_id,
        target_leg_id,
        request,
    }
}

async fn prepare_amazon_context<R>(repository: &R, worker: WorkerLease, seed: u8) -> PreparedContext
where
    R: CallRepository + CallServiceRepository + Sync,
{
    let base = i64::from(seed) * 10;
    let owner = TenantId::parse(format!("amazon-context-owner-{seed}")).unwrap();
    let initial = CallAggregate::new(
        owner.clone(),
        [
            LegSpec {
                direction: LegDirection::Inbound,
                kind: LegKind::InteractiveWebRtc,
            },
            LegSpec {
                direction: LegDirection::Outbound,
                kind: LegKind::AmazonConnect,
            },
        ],
        at(base),
    );
    let source_leg_id = initial.legs()[0].id();
    let target_leg_id = initial.legs()[1].id();
    let start = AmazonConnectStartSpec::new(
        "context-profile",
        "context-instance",
        "context-flow",
        BTreeMap::from([("server-owned".to_owned(), "retained".to_owned())]),
        "Context caller",
        None,
    )
    .unwrap();
    let route = NamedRouteBinding::new_with_profiles(
        "amazon-context",
        None,
        vec![NamedProfileBinding::new(
            NamedProfileRole::Destination,
            NamedProfileKind::AmazonConnect,
            "context-profile",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap()],
    )
    .unwrap();
    let plan = CallExecutionPlan::new_with_named_route(
        &initial,
        [
            LegExecutionSpec {
                leg_id: source_leg_id,
                endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                    signaling_uri: None,
                }),
            },
            LegExecutionSpec {
                leg_id: target_leg_id,
                endpoint: LegEndpointConfig::AmazonConnect(AmazonConnectEndpointConfig {
                    instance_id: "context-instance".to_owned(),
                    contact_flow_id: "context-flow".to_owned(),
                }),
            },
        ],
        principal(seed.wrapping_add(40)),
        BTreeMap::from([(target_leg_id, start)]),
        route,
    )
    .unwrap();
    let token_digest = AttachmentTokenDigest::new(digest(seed.wrapping_add(80)));
    let created = repository
        .create_with_plan(ServiceCreateTransaction {
            create: CreateCall {
                initial,
                command_id: CommandId::new(),
                command: CallCommand::StartConnecting {
                    at: at(base + 1),
                    setup_deadline: at(base + 301),
                },
                worker,
                idempotency_key: IdempotencyKeyDigest::new(digest(seed)),
                request_digest: RequestDigest::new(digest(seed.wrapping_add(1))),
                attachments: vec![AttachmentIssue {
                    attachment_id: AttachmentId::new(),
                    token_digest,
                    purpose: AttachmentPurpose::PublicInbound,
                    leg_id: source_leg_id,
                    binding_generation: BindingGeneration::INITIAL,
                    transport: AttachmentTransport::WebRtc,
                    expected_principal: principal(seed.wrapping_add(2)),
                    expires_at: at(base + 121),
                }],
                at: at(base + 1),
            },
            plan,
            alternatives: Vec::new(),
        })
        .await
        .unwrap();
    let call_id = match created {
        ServiceCreateOutcome::Created(call) => call.call.aggregate.id(),
        ServiceCreateOutcome::Replayed(_) => panic!("fresh Amazon context call replayed"),
    };
    let candidate = repository
        .inspect_inbound_attachment(AttachmentLookup {
            token_digest,
            tenant_id: owner.clone(),
            transport: AttachmentTransport::WebRtc,
            principal_fingerprint: principal(seed.wrapping_add(2)),
            worker,
            at: at(base + 2),
        })
        .await
        .unwrap();
    let connection_id = ConnectionId::from_string(format!("amazon-context-source-{seed}"));
    repository
        .consume_inbound_attachment(AttachmentConsume {
            candidate,
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at: at(base + 2),
                leg_id: source_leg_id,
                binding_generation: BindingGeneration::INITIAL,
                state: LegState::Signaling,
                failure: None,
            },
            connection_id: connection_id.clone(),
            principal_fingerprint: principal(seed.wrapping_add(2)),
            principal_expires_at: None,
            at: at(base + 2),
        })
        .await
        .unwrap();

    let mut envelope = ContextEnvelope::new(
        format!("amazon-correlation-{seed}"),
        owner.as_str(),
        call_id.to_string(),
        source_leg_id.to_string(),
    );
    envelope
        .metadata
        .insert("account_ref".to_owned(), format!("amazon-account-{seed}"));
    let request = InitialContextRecordRequest {
        tenant_id: owner.clone(),
        call_id,
        source_connection_id: connection_id,
        source_leg_id,
        source_binding_generation: BindingGeneration::INITIAL,
        target_leg_id,
        target_binding_generation: BindingGeneration::INITIAL,
        message_id: MessageId::from_string(format!("amazon-message-{seed}")),
        envelope: serde_json::to_vec(&envelope).unwrap(),
        initial_sip_headers: Vec::new(),
        recorded_at: at(base + 3),
    };
    PreparedContext {
        owner,
        call_id,
        target_leg_id,
        request,
    }
}

#[derive(Clone)]
struct PreparedReplacementContext {
    original: PreparedContext,
    lookup: ReplacementInitialContextLookup,
}

#[derive(Clone)]
struct CompletedTelnyxContext {
    original: PreparedContext,
    pending_binding_generation: BindingGeneration,
}

/// Completes the release topology that exposed the restart bug: a direct
/// WebRTC source first reaches a SIP assistant using retained initial context,
/// then the stable assistant leg is replaced by Telnyx. The first repository
/// read after promotion is intentional: SQL backends reconstruct and validate
/// their complete snapshot for that next transaction.
async fn complete_assistant_to_telnyx<R>(
    repository: &R,
    worker: WorkerLease,
    seed: u8,
) -> CompletedTelnyxContext
where
    R: CallRepository + CallServiceRepository + Sync,
{
    let base = i64::from(seed) * 10;
    let original = prepare_context(repository, worker, seed).await;
    let expected = StoredInitialContext::from(original.request.clone());
    assert_eq!(
        repository
            .record_initial_context(original.request.clone())
            .await
            .unwrap(),
        InitialContextRecordOutcome::Recorded(expected)
    );

    let (start_effect_id, start_claim_generation) = claim_start_leg(
        repository,
        worker,
        original.call_id,
        original.target_leg_id,
        at(base + 4),
    )
    .await;
    let assistant_connection = ConnectionId::from_string(format!("context-assistant-{seed}"));
    assert!(matches!(
        repository
            .bind_outbound_connection(OutboundConnectionBind {
                operation_id: CommandId::from_uuid(start_effect_id.as_uuid()).unwrap(),
                effect_id: start_effect_id,
                claim_generation: start_claim_generation,
                tenant_id: original.owner.clone(),
                call_id: original.call_id,
                leg_id: original.target_leg_id,
                binding_generation: BindingGeneration::INITIAL,
                worker,
                connection_id: assistant_connection.clone(),
                transport: AttachmentTransport::Sip,
                principal_fingerprint: principal(seed.wrapping_add(40)),
                at: at(base + 4),
            })
            .await
            .unwrap(),
        OutboundConnectionBindOutcome::Bound(_)
    ));
    repository
        .reconcile_effect_result(EffectResultReconciliation {
            tenant_id: original.owner.clone(),
            call_id: original.call_id,
            effect_id: start_effect_id,
            worker,
            claim_generation: start_claim_generation,
            result: ServiceEffectResult::Succeeded,
            external_reference: None,
            additional_external_references: Vec::new(),
            follow_up: None,
            at: at(base + 4),
        })
        .await
        .unwrap();

    commit_leg_state(
        repository,
        &original.owner,
        original.call_id,
        worker,
        original.target_leg_id,
        LegState::Signaling,
        at(base + 5),
    )
    .await;
    commit_leg_state(
        repository,
        &original.owner,
        original.call_id,
        worker,
        original.request.source_leg_id,
        LegState::Connected,
        at(base + 6),
    )
    .await;
    commit_leg_state(
        repository,
        &original.owner,
        original.call_id,
        worker,
        original.target_leg_id,
        LegState::Connected,
        at(base + 7),
    )
    .await;

    let active = repository
        .load_service_call(&original.owner, original.call_id)
        .await
        .unwrap();
    assert_eq!(
        active.call.aggregate.state(),
        bridgefu::call_engine::CallState::Active
    );
    let previous_binding_generation = active
        .call
        .aggregate
        .leg(original.target_leg_id)
        .unwrap()
        .binding_generation();
    let pending_binding_generation = previous_binding_generation.next().unwrap();
    let account_profile = "replacement-context-telnyx";
    let replacement_route = NamedRouteBinding::new_with_profiles(
        "replacement-context-telnyx",
        None,
        vec![NamedProfileBinding::new(
            NamedProfileRole::Destination,
            NamedProfileKind::Telnyx,
            account_profile,
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        )
        .unwrap()],
    )
    .unwrap();
    let begun = match repository
        .commit_with_effect_payloads(ServiceCommandTransaction {
            command: CommandCommit {
                tenant_id: original.owner.clone(),
                call_id: original.call_id,
                expected_version: active.call.aggregate.version(),
                command_id: CommandId::new(),
                command: CallCommand::BeginLegReplacement {
                    at: at(base + 8),
                    leg_id: original.target_leg_id,
                    pending_kind: LegKind::Telnyx,
                    transfer_deadline: at(base + 38),
                },
                worker,
                attachments: Vec::new(),
                deadline_claim: None,
                at: at(base + 8),
            },
            effect_payloads: vec![ServiceEffectPayloadInput {
                ordinal: 2,
                payload: ServiceEffectPayload::LegReplacement {
                    leg_id: original.target_leg_id,
                    previous_binding_generation,
                    pending_binding_generation,
                    endpoint: LegEndpointConfig::Provider(ProviderEndpointConfig {
                        provider: ProviderKind::Telnyx,
                        account_profile: account_profile.to_owned(),
                        destination: Some("+12065550123".to_owned()),
                    }),
                    amazon_connect_start: None,
                    route_id: "replacement-context-telnyx".to_owned(),
                    replacement_route: Some(replacement_route),
                    authorization_principal_fingerprint: principal(seed.wrapping_add(40)),
                },
            }],
            operation_idempotency: None,
            bound_connection: None,
            media_activity: None,
            replacement_connection: None,
        })
        .await
        .unwrap()
    {
        ServiceCommandOutcome::Committed(view) => view,
        ServiceCommandOutcome::Replayed(_) => panic!("fresh Telnyx replacement replayed"),
    };
    let deadline_generation = begun
        .command
        .call
        .aggregate
        .deadlines()
        .get(DeadlineKind::Transfer)
        .generation();
    let telnyx_connection = ConnectionId::from_string(format!("context-telnyx-{seed}"));
    assert!(matches!(
        repository
            .commit_with_effect_payloads(ServiceCommandTransaction {
                command: CommandCommit {
                    tenant_id: original.owner.clone(),
                    call_id: original.call_id,
                    expected_version: begun.command.call.aggregate.version(),
                    command_id: CommandId::new(),
                    command: CallCommand::FinishLegReplacement {
                        at: at(base + 9),
                        deadline_generation,
                        pending_binding_generation,
                        result: LegReplacementResult::Connected,
                    },
                    worker,
                    attachments: Vec::new(),
                    deadline_claim: None,
                    at: at(base + 9),
                },
                effect_payloads: Vec::new(),
                operation_idempotency: None,
                bound_connection: None,
                media_activity: None,
                replacement_connection: Some(ReplacementConnectionPromotion {
                    previous_connection_id: assistant_connection,
                    connection_id: telnyx_connection.clone(),
                    leg_id: original.target_leg_id,
                    previous_binding_generation,
                    pending_binding_generation,
                    transport: AttachmentTransport::Sip,
                    principal_fingerprint: principal(seed.wrapping_add(40)),
                }),
            })
            .await
            .unwrap(),
        ServiceCommandOutcome::Committed(_)
    ));

    let next_transaction = repository
        .load_service_call(&original.owner, original.call_id)
        .await
        .expect("the first transaction after Telnyx promotion must reload retained context");
    let current = next_transaction
        .call
        .aggregate
        .leg(original.target_leg_id)
        .unwrap();
    assert_eq!(current.kind(), LegKind::Telnyx);
    assert_eq!(current.binding_generation(), pending_binding_generation);
    assert_eq!(
        next_transaction.call.bindings[&original.target_leg_id].connection_id,
        telnyx_connection
    );
    CompletedTelnyxContext {
        original,
        pending_binding_generation,
    }
}

async fn commit_leg_state<R>(
    repository: &R,
    owner: &TenantId,
    call_id: CallId,
    worker: WorkerLease,
    leg_id: LegId,
    state: LegState,
    at: DateTime<Utc>,
) where
    R: CallServiceRepository + Sync,
{
    let stored = repository.load_service_call(owner, call_id).await.unwrap();
    let binding_generation = stored
        .call
        .aggregate
        .leg(leg_id)
        .unwrap()
        .binding_generation();
    let outcome = repository
        .commit_with_effect_payloads(ServiceCommandTransaction {
            command: CommandCommit {
                tenant_id: owner.clone(),
                call_id,
                expected_version: stored.call.aggregate.version(),
                command_id: CommandId::new(),
                command: CallCommand::SetLegState {
                    at,
                    leg_id,
                    binding_generation,
                    state,
                    failure: None,
                },
                worker,
                attachments: Vec::new(),
                deadline_claim: None,
                at,
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
}

async fn prepare_replacement_context<R>(
    repository: &R,
    worker: WorkerLease,
    seed: u8,
) -> PreparedReplacementContext
where
    R: CallRepository + CallServiceRepository + Sync,
{
    let base = i64::from(seed) * 10;
    let original = prepare_context(repository, worker, seed).await;
    let expected = StoredInitialContext::from(original.request.clone());
    assert_eq!(
        repository
            .record_initial_context(original.request.clone())
            .await
            .unwrap(),
        InitialContextRecordOutcome::Recorded(expected)
    );

    let source_leg_id = original.request.source_leg_id;
    commit_leg_state(
        repository,
        &original.owner,
        original.call_id,
        worker,
        original.target_leg_id,
        LegState::Signaling,
        at(base + 4),
    )
    .await;
    commit_leg_state(
        repository,
        &original.owner,
        original.call_id,
        worker,
        source_leg_id,
        LegState::Connected,
        at(base + 5),
    )
    .await;
    commit_leg_state(
        repository,
        &original.owner,
        original.call_id,
        worker,
        original.target_leg_id,
        LegState::Connected,
        at(base + 6),
    )
    .await;

    let stored = repository
        .load_service_call(&original.owner, original.call_id)
        .await
        .unwrap();
    let previous_binding_generation = stored
        .call
        .aggregate
        .leg(original.target_leg_id)
        .unwrap()
        .binding_generation();
    let pending_binding_generation = previous_binding_generation.next().unwrap();
    let start = AmazonConnectStartSpec::new(
        "replacement-context-profile",
        "replacement-context-instance",
        "replacement-context-flow",
        BTreeMap::from([("server_route".to_owned(), "support".to_owned())]),
        "Replacement caller",
        None,
    )
    .unwrap();
    let route = NamedRouteBinding::new_with_profiles(
        "replacement-amazon",
        None,
        vec![NamedProfileBinding::new(
            NamedProfileRole::Destination,
            NamedProfileKind::AmazonConnect,
            "replacement-context-profile",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap()],
    )
    .unwrap();
    let outcome = repository
        .commit_with_effect_payloads(ServiceCommandTransaction {
            command: CommandCommit {
                tenant_id: original.owner.clone(),
                call_id: original.call_id,
                expected_version: stored.call.aggregate.version(),
                command_id: CommandId::new(),
                command: CallCommand::BeginLegReplacement {
                    at: at(base + 7),
                    leg_id: original.target_leg_id,
                    pending_kind: LegKind::AmazonConnect,
                    transfer_deadline: at(base + 37),
                },
                worker,
                attachments: Vec::new(),
                deadline_claim: None,
                at: at(base + 7),
            },
            effect_payloads: vec![ServiceEffectPayloadInput {
                ordinal: 2,
                payload: ServiceEffectPayload::LegReplacement {
                    leg_id: original.target_leg_id,
                    previous_binding_generation,
                    pending_binding_generation,
                    endpoint: LegEndpointConfig::AmazonConnect(AmazonConnectEndpointConfig {
                        instance_id: "replacement-context-instance".to_owned(),
                        contact_flow_id: "replacement-context-flow".to_owned(),
                    }),
                    amazon_connect_start: Some(start),
                    route_id: "replacement-amazon".to_owned(),
                    replacement_route: Some(route),
                    authorization_principal_fingerprint: principal(seed.wrapping_add(40)),
                },
            }],
            operation_idempotency: None,
            bound_connection: None,
            media_activity: None,
            replacement_connection: None,
        })
        .await
        .unwrap();
    assert!(matches!(outcome, ServiceCommandOutcome::Committed(_)));

    PreparedReplacementContext {
        original: original.clone(),
        lookup: ReplacementInitialContextLookup {
            tenant_id: original.owner,
            call_id: original.call_id,
            target_leg_id: original.target_leg_id,
            previous_binding_generation,
            pending_binding_generation,
        },
    }
}

async fn assert_replacement_context_fences<R>(repository: &R, prepared: &PreparedReplacementContext)
where
    R: CallServiceRepository + Sync,
{
    let expected = StoredInitialContext::from(prepared.original.request.clone());
    assert_eq!(
        repository
            .load_replacement_initial_context(prepared.lookup.clone())
            .await
            .unwrap(),
        Some(expected.clone())
    );
    assert_eq!(
        repository
            .load_replacement_initial_context(prepared.lookup.clone())
            .await
            .unwrap(),
        Some(expected)
    );

    let mut wrong_tenant = prepared.lookup.clone();
    wrong_tenant.tenant_id = TenantId::parse("replacement-context-other-owner").unwrap();
    assert_eq!(
        repository
            .load_replacement_initial_context(wrong_tenant)
            .await,
        Err(RepositoryError::NotFound)
    );
    let mut wrong_leg = prepared.lookup.clone();
    wrong_leg.target_leg_id = prepared.original.request.source_leg_id;
    assert_eq!(
        repository.load_replacement_initial_context(wrong_leg).await,
        Err(RepositoryError::StaleClaim)
    );
    let mut wrong_previous = prepared.lookup.clone();
    wrong_previous.previous_binding_generation = prepared.lookup.pending_binding_generation;
    assert_eq!(
        repository
            .load_replacement_initial_context(wrong_previous)
            .await,
        Err(RepositoryError::StaleClaim)
    );
    let mut wrong_pending = prepared.lookup.clone();
    wrong_pending.pending_binding_generation =
        wrong_pending.pending_binding_generation.next().unwrap();
    assert_eq!(
        repository
            .load_replacement_initial_context(wrong_pending)
            .await,
        Err(RepositoryError::StaleClaim)
    );
}

async fn reject_replacement<R>(
    repository: &R,
    worker: WorkerLease,
    prepared: &PreparedReplacementContext,
) where
    R: CallServiceRepository + Sync,
{
    let stored = repository
        .load_service_call(&prepared.lookup.tenant_id, prepared.lookup.call_id)
        .await
        .unwrap();
    let deadline_generation = stored
        .call
        .aggregate
        .deadlines()
        .get(DeadlineKind::Transfer)
        .generation();
    let at = stored.call.aggregate.updated_at() + chrono::Duration::seconds(1);
    repository
        .commit_with_effect_payloads(ServiceCommandTransaction {
            command: CommandCommit {
                tenant_id: prepared.lookup.tenant_id.clone(),
                call_id: prepared.lookup.call_id,
                expected_version: stored.call.aggregate.version(),
                command_id: CommandId::new(),
                command: CallCommand::FinishLegReplacement {
                    at,
                    deadline_generation,
                    pending_binding_generation: prepared.lookup.pending_binding_generation,
                    result: LegReplacementResult::Rejected(FailureDetails::sanitized(
                        "test_replacement_rejected",
                        "the test replacement was rejected",
                        false,
                    )),
                },
                worker,
                attachments: Vec::new(),
                deadline_claim: None,
                at,
            },
            effect_payloads: Vec::new(),
            operation_idempotency: None,
            bound_connection: None,
            media_activity: None,
            replacement_connection: None,
        })
        .await
        .unwrap();
    assert_eq!(
        repository
            .load_replacement_initial_context(prepared.lookup.clone())
            .await,
        Err(RepositoryError::StaleClaim)
    );
}

async fn assert_context_conformance<R>(repository: &R) -> PreparedContext
where
    R: CallRepository + CallServiceRepository + Sync,
{
    let worker = register(repository).await;
    let primary = prepare_context(repository, worker, 1).await;
    let request_debug = format!("{:?}", primary.request);
    for secret in [
        "secret-correlation-1",
        "secret-account-1",
        "secret-message-1",
    ] {
        assert!(!request_debug.contains(secret));
    }

    let expected = StoredInitialContext::from(primary.request.clone());
    assert_eq!(
        repository
            .record_initial_context(primary.request.clone())
            .await
            .unwrap(),
        InitialContextRecordOutcome::Recorded(expected.clone())
    );
    let stored_debug = format!("{expected:?}");
    assert!(!stored_debug.contains("secret-correlation-1"));
    assert!(!stored_debug.contains("secret-account-1"));
    assert!(!stored_debug.contains("secret-message-1"));
    assert_eq!(
        repository
            .load_initial_context(
                &primary.owner,
                primary.call_id,
                primary.target_leg_id,
                BindingGeneration::INITIAL,
            )
            .await
            .unwrap(),
        Some(expected.clone())
    );
    assert_eq!(
        repository
            .record_initial_context(primary.request.clone())
            .await
            .unwrap(),
        InitialContextRecordOutcome::Replayed(expected)
    );

    let mut conflict = primary.request.clone();
    conflict.initial_sip_headers[0].1 = "different-secret".to_owned();
    let error = repository
        .record_initial_context(conflict)
        .await
        .unwrap_err();
    assert_eq!(error, RepositoryError::CommandConflict);
    assert!(!error.to_string().contains("different-secret"));

    let mut replayed_message = primary.request.clone();
    replayed_message.target_binding_generation = generation(2);
    assert_eq!(
        repository.record_initial_context(replayed_message).await,
        Err(RepositoryError::CommandConflict)
    );

    let stale_source = prepare_context(repository, worker, 2).await;
    let mut stale_source_request = stale_source.request;
    stale_source_request.source_binding_generation = generation(2);
    assert_eq!(
        repository
            .record_initial_context(stale_source_request)
            .await,
        Err(RepositoryError::StaleClaim)
    );

    let stale_target = prepare_context(repository, worker, 3).await;
    let mut stale_target_request = stale_target.request;
    stale_target_request.target_binding_generation = generation(2);
    assert_eq!(
        repository
            .record_initial_context(stale_target_request)
            .await,
        Err(RepositoryError::StaleClaim)
    );

    let foreign_connection = prepare_context(repository, worker, 4).await;
    let mut foreign_connection_request = foreign_connection.request;
    foreign_connection_request.source_connection_id = primary.request.source_connection_id.clone();
    assert_eq!(
        repository
            .record_initial_context(foreign_connection_request)
            .await,
        Err(RepositoryError::StaleClaim)
    );

    let wrong_tenant = prepare_context(repository, worker, 5).await;
    let mut wrong_tenant_request = wrong_tenant.request;
    wrong_tenant_request.tenant_id = TenantId::parse("context-other-owner").unwrap();
    wrong_tenant_request.envelope = serde_json::to_vec(&ContextEnvelope::new(
        "other-secret",
        wrong_tenant_request.tenant_id.as_str(),
        wrong_tenant_request.call_id.to_string(),
        wrong_tenant_request.source_leg_id.to_string(),
    ))
    .unwrap();
    assert_eq!(
        repository
            .record_initial_context(wrong_tenant_request)
            .await,
        Err(RepositoryError::NotFound)
    );
    assert_eq!(
        repository
            .load_initial_context(
                &TenantId::parse("context-other-owner").unwrap(),
                primary.call_id,
                primary.target_leg_id,
                BindingGeneration::INITIAL,
            )
            .await,
        Err(RepositoryError::NotFound)
    );

    let invalid_bounds = prepare_context(repository, worker, 6).await;
    let mut too_many_headers = invalid_bounds.request.clone();
    too_many_headers.initial_sip_headers = (0..33)
        .map(|index| (format!("X-Context-{index}"), "bounded".to_owned()))
        .collect();
    assert_eq!(
        repository.record_initial_context(too_many_headers).await,
        Err(RepositoryError::InvalidInput("invalid initial SIP headers"))
    );
    let mut oversized_envelope = invalid_bounds.request;
    oversized_envelope.envelope = vec![b'x'; MAX_CONTEXT_BYTES + 1];
    assert_eq!(
        repository.record_initial_context(oversized_envelope).await,
        Err(RepositoryError::InvalidInput(
            "invalid initial context record"
        ))
    );

    primary
}

async fn assert_amazon_context_conformance<R>(
    repository: &R,
    worker: WorkerLease,
) -> PreparedContext
where
    R: CallRepository + CallServiceRepository + Sync,
{
    let primary = prepare_amazon_context(repository, worker, 20).await;
    let expected = StoredInitialContext::from(primary.request.clone());
    assert!(expected.initial_sip_headers.is_empty());
    assert_eq!(
        repository
            .record_initial_context(primary.request.clone())
            .await
            .unwrap(),
        InitialContextRecordOutcome::Recorded(expected.clone())
    );
    assert_eq!(
        repository
            .record_initial_context(primary.request.clone())
            .await
            .unwrap(),
        InitialContextRecordOutcome::Replayed(expected)
    );

    let mut conflict = primary.request.clone();
    let mut envelope: ContextEnvelope = serde_json::from_slice(&conflict.envelope).unwrap();
    envelope
        .metadata
        .insert("account_ref".to_owned(), "different-account".to_owned());
    conflict.envelope = serde_json::to_vec(&envelope).unwrap();
    assert_eq!(
        repository.record_initial_context(conflict).await,
        Err(RepositoryError::CommandConflict)
    );

    let mut duplicate_message = primary.request.clone();
    duplicate_message.target_binding_generation = generation(2);
    assert_eq!(
        repository.record_initial_context(duplicate_message).await,
        Err(RepositoryError::CommandConflict)
    );

    let stale_source = prepare_amazon_context(repository, worker, 21).await;
    let mut stale_source_request = stale_source.request;
    stale_source_request.source_binding_generation = generation(2);
    assert_eq!(
        repository
            .record_initial_context(stale_source_request)
            .await,
        Err(RepositoryError::StaleClaim)
    );

    let stale_target = prepare_amazon_context(repository, worker, 22).await;
    let mut stale_target_request = stale_target.request;
    stale_target_request.target_binding_generation = generation(2);
    assert_eq!(
        repository
            .record_initial_context(stale_target_request)
            .await,
        Err(RepositoryError::StaleClaim)
    );

    let projected_headers = prepare_amazon_context(repository, worker, 23).await;
    let mut projected_headers_request = projected_headers.request;
    projected_headers_request.initial_sip_headers = vec![(
        "X-Correlation-Id".to_owned(),
        "must-not-be-retained-as-sip".to_owned(),
    )];
    assert_eq!(
        repository
            .record_initial_context(projected_headers_request)
            .await,
        Err(RepositoryError::InvalidInput(
            "initial context target is not authorized by its execution plan"
        ))
    );

    primary
}

#[tokio::test]
async fn memory_initial_context_repository_conformance() {
    let repository = MemoryRepository::new();
    assert_context_conformance(&repository).await;
    let worker = register(&repository).await;
    assert_amazon_context_conformance(&repository, worker).await;
    let replacement = prepare_replacement_context(&repository, worker, 10).await;
    assert_replacement_context_fences(&repository, &replacement).await;
    reject_replacement(&repository, worker, &replacement).await;
}

#[tokio::test]
async fn sqlite_next_transaction_and_restart_preserve_assistant_context_after_telnyx_handoff() {
    let path = std::env::temp_dir().join(format!(
        "bridgefu-initial-context-telnyx-{}.db",
        uuid::Uuid::new_v4()
    ));
    let url = format!("sqlite://{}", path.display());
    let first = SqliteRepository::connect(&url).await.unwrap();
    let worker = register(&first).await;
    let completed = complete_assistant_to_telnyx(&first, worker, 31).await;
    first.pool().close().await;

    let restarted = SqliteRepository::connect(&url).await.unwrap();
    let stored = restarted
        .load_service_call(&completed.original.owner, completed.original.call_id)
        .await
        .expect("SQLite restart must accept retained assistant context after Telnyx promotion");
    let target = stored
        .call
        .aggregate
        .leg(completed.original.target_leg_id)
        .unwrap();
    assert_eq!(target.kind(), LegKind::Telnyx);
    assert_eq!(
        target.binding_generation(),
        completed.pending_binding_generation
    );
    restarted.pool().close().await;
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn sqlite_initial_context_repository_conformance_and_restart() {
    let path = std::env::temp_dir().join(format!(
        "bridgefu-initial-context-{}.db",
        uuid::Uuid::new_v4()
    ));
    let url = format!("sqlite://{}", path.display());
    let first = SqliteRepository::connect(&url).await.unwrap();
    let primary = assert_context_conformance(&first).await;
    let worker = register(&first).await;
    let amazon = assert_amazon_context_conformance(&first, worker).await;
    let replacement = prepare_replacement_context(&first, worker, 10).await;
    assert_replacement_context_fences(&first, &replacement).await;
    first.pool().close().await;

    let restarted = SqliteRepository::connect(&url).await.unwrap();
    let expected = StoredInitialContext::from(primary.request.clone());
    assert_eq!(
        restarted
            .load_initial_context(
                &primary.owner,
                primary.call_id,
                primary.target_leg_id,
                BindingGeneration::INITIAL,
            )
            .await
            .unwrap(),
        Some(expected.clone())
    );
    assert_eq!(
        restarted
            .record_initial_context(primary.request)
            .await
            .unwrap(),
        InitialContextRecordOutcome::Replayed(expected)
    );
    let amazon_expected = StoredInitialContext::from(amazon.request.clone());
    assert_eq!(
        restarted
            .load_initial_context(
                &amazon.owner,
                amazon.call_id,
                amazon.target_leg_id,
                BindingGeneration::INITIAL,
            )
            .await
            .unwrap(),
        Some(amazon_expected.clone())
    );
    assert_eq!(
        restarted
            .record_initial_context(amazon.request)
            .await
            .unwrap(),
        InitialContextRecordOutcome::Replayed(amazon_expected)
    );
    assert_replacement_context_fences(&restarted, &replacement).await;
    reject_replacement(&restarted, worker, &replacement).await;
    restarted.pool().close().await;
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn postgres_initial_context_repository_conformance_and_restart() {
    let Some(url) = std::env::var("BRIDGEFU_TEST_POSTGRES_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
    else {
        return;
    };
    let administration = sqlx::PgPool::connect(&url).await.unwrap();
    let schema = format!("bridgefu_context_{}", uuid::Uuid::new_v4().simple());
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
    let primary = assert_context_conformance(&first).await;
    let worker = register(&first).await;
    let amazon = assert_amazon_context_conformance(&first, worker).await;
    let replacement = prepare_replacement_context(&first, worker, 10).await;
    assert_replacement_context_fences(&first, &replacement).await;
    let restarted = PostgresRepository::connect(&scoped).await.unwrap();
    let expected = StoredInitialContext::from(primary.request.clone());
    assert_eq!(
        restarted
            .load_initial_context(
                &primary.owner,
                primary.call_id,
                primary.target_leg_id,
                BindingGeneration::INITIAL,
            )
            .await
            .unwrap(),
        Some(expected.clone())
    );
    assert_eq!(
        restarted
            .record_initial_context(primary.request)
            .await
            .unwrap(),
        InitialContextRecordOutcome::Replayed(expected)
    );
    let amazon_expected = StoredInitialContext::from(amazon.request.clone());
    assert_eq!(
        restarted
            .load_initial_context(
                &amazon.owner,
                amazon.call_id,
                amazon.target_leg_id,
                BindingGeneration::INITIAL,
            )
            .await
            .unwrap(),
        Some(amazon_expected.clone())
    );
    assert_eq!(
        restarted
            .record_initial_context(amazon.request)
            .await
            .unwrap(),
        InitialContextRecordOutcome::Replayed(amazon_expected)
    );
    assert_replacement_context_fences(&restarted, &replacement).await;
    reject_replacement(&restarted, worker, &replacement).await;
    first.pool().close().await;
    restarted.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&administration)
        .await
        .unwrap();
    administration.close().await;
}

#[tokio::test]
async fn postgres_next_transaction_and_restart_preserve_assistant_context_after_telnyx_handoff() {
    let Some(url) = std::env::var("BRIDGEFU_TEST_POSTGRES_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
    else {
        return;
    };
    let administration = sqlx::PgPool::connect(&url).await.unwrap();
    let schema = format!("bridgefu_context_telnyx_{}", uuid::Uuid::new_v4().simple());
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
    let worker = register(&first).await;
    let completed = complete_assistant_to_telnyx(&first, worker, 32).await;
    let restarted = PostgresRepository::connect(&scoped).await.unwrap();
    let stored = restarted
        .load_service_call(&completed.original.owner, completed.original.call_id)
        .await
        .expect("PostgreSQL restart must accept retained assistant context after Telnyx promotion");
    let target = stored
        .call
        .aggregate
        .leg(completed.original.target_leg_id)
        .unwrap();
    assert_eq!(target.kind(), LegKind::Telnyx);
    assert_eq!(
        target.binding_generation(),
        completed.pending_binding_generation
    );
    first.pool().close().await;
    restarted.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&administration)
        .await
        .unwrap();
    administration.close().await;
}
