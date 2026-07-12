use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bridgefu::call_engine::{
    AttachmentConsume, AttachmentId, AttachmentIssue, AttachmentLookup, AttachmentTokenDigest,
    AttachmentTransport, BindProviderReference, CallAggregate, CallCommand, CallRepository,
    CommandCommit, CommandCommitOutcome, CommandId, CreateCall, CreateCallOutcome, DeadlineKind,
    IdempotencyKeyDigest, LegDirection, LegKind, LegSpec, LegState, OutboxCompletion,
    PrincipalFingerprint, ProviderAccountKey, ProviderCallId, ProviderEventCommit,
    ProviderEventDigest, ProviderEventInput, ProviderEventOutcome, ProviderEventState,
    ProviderEventTarget, ProviderPayloadDigest, RegisterWorker, RepositoryError, RequestDigest,
    StoredCall, TenantId, TerminalProviderEventAcknowledge,
    TerminalProviderEventAcknowledgeOutcome, WorkerId, WorkerLease, WorkerSnapshot,
};
use bridgefu::call_service::{
    CallExecutionPlan, CallServiceRepository, LegEndpointConfig, LegExecutionSpec,
    ServiceCreateTransaction, SipEndpointConfig, WebRtcEndpointConfig,
};
use bridgefu::persistence::{
    MemoryRepository, PostgresRepository, SqlRetentionPolicy, SqliteRepository,
};
use chrono::{DateTime, TimeZone, Utc};
use rvoip_core::ids::ConnectionId;
use serde_json::json;
use sqlx::Row;
use tokio::sync::Notify;

type Repository = Arc<dyn CallRepository>;
static POSTGRES_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn at(second: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_900_000_000 + second, 0).unwrap()
}

fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn tenant(name: &str) -> TenantId {
    TenantId::parse(name).unwrap()
}

fn principal() -> PrincipalFingerprint {
    PrincipalFingerprint::new(digest(0xa5))
}

fn new_call(owner: TenantId) -> CallAggregate {
    CallAggregate::new(
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
    )
}

fn create_request(call: CallAggregate, worker: WorkerLease, key: u8, request: u8) -> CreateCall {
    create_request_at(call, worker, key, request, at(2))
}

fn service_create_request(
    owner: TenantId,
    worker: WorkerLease,
    key: u8,
    request: u8,
) -> ServiceCreateTransaction {
    let aggregate = new_call(owner);
    let plan = CallExecutionPlan::new(
        &aggregate,
        [
            LegExecutionSpec {
                leg_id: aggregate.legs()[0].id(),
                endpoint: LegEndpointConfig::Sip(SipEndpointConfig { uri: None }),
            },
            LegExecutionSpec {
                leg_id: aggregate.legs()[1].id(),
                endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                    signaling_uri: Some("wss://upgrade.example.invalid/session".to_owned()),
                }),
            },
        ],
    )
    .unwrap();
    ServiceCreateTransaction {
        create: create_request(aggregate, worker, key, request),
        plan,
    }
}

fn create_request_at(
    call: CallAggregate,
    worker: WorkerLease,
    key: u8,
    request: u8,
    now: DateTime<Utc>,
) -> CreateCall {
    let command = CallCommand::StartConnecting {
        at: now,
        setup_deadline: now + chrono::Duration::seconds(30),
    };
    let decision = call.decide(command.clone()).unwrap();
    let leg = &decision.aggregate().legs()[0];
    CreateCall {
        initial: call,
        command_id: CommandId::new(),
        command,
        worker,
        idempotency_key: IdempotencyKeyDigest::new(digest(key)),
        request_digest: RequestDigest::new(digest(request)),
        attachments: vec![AttachmentIssue {
            attachment_id: AttachmentId::new(),
            token_digest: AttachmentTokenDigest::new(digest(key.wrapping_add(100))),
            leg_id: leg.id(),
            binding_generation: leg.binding_generation(),
            transport: AttachmentTransport::Sip,
            expected_principal: principal(),
            expires_at: now + chrono::Duration::seconds(120),
        }],
        at: now,
    }
}

async fn register(repo: &Repository, max_calls: usize) -> WorkerSnapshot {
    repo.register_worker(RegisterWorker {
        worker_id: WorkerId::new(),
        max_calls,
        capabilities: BTreeSet::from(["sip".into(), "webrtc".into()]),
        at: at(0),
    })
    .await
    .unwrap()
}

fn created(outcome: CreateCallOutcome) -> StoredCall {
    match outcome {
        CreateCallOutcome::Created(call) => call,
        CreateCallOutcome::Replayed(_) => panic!("expected a new call"),
    }
}

async fn shared_repository_conformance(repo: Repository) {
    let worker = register(&repo, 4).await;
    let owner = tenant("conformance-a");
    let request = create_request(new_call(owner.clone()), worker.lease, 1, 2);
    let attachment_digest = request.attachments[0].token_digest;
    let call = created(repo.create_call(request.clone()).await.unwrap());
    assert!(matches!(
        repo.create_call(request.clone()).await.unwrap(),
        CreateCallOutcome::Replayed(replayed) if replayed == call
    ));
    let mut conflicting = request;
    conflicting.request_digest = RequestDigest::new(digest(3));
    assert_eq!(
        repo.create_call(conflicting).await,
        Err(RepositoryError::IdempotencyConflict)
    );
    assert_eq!(
        repo.load_call(&tenant("conformance-b"), call.aggregate.id())
            .await,
        Err(RepositoryError::NotFound)
    );

    let candidate = repo
        .inspect_attachment(AttachmentLookup {
            token_digest: attachment_digest,
            tenant_id: owner.clone(),
            transport: AttachmentTransport::Sip,
            principal_fingerprint: principal(),
            worker: worker.lease,
            at: at(3),
        })
        .await
        .unwrap();
    let connection_id = ConnectionId::from_string("conn_conformance_single_use");
    let consumed = repo
        .consume_attachment(AttachmentConsume {
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at: at(4),
                leg_id: candidate.leg_id(),
                binding_generation: candidate.binding_generation(),
                state: LegState::Signaling,
                failure: None,
            },
            candidate,
            connection_id: connection_id.clone(),
            principal_fingerprint: principal(),
            at: at(4),
        })
        .await
        .unwrap();
    assert_eq!(consumed.binding.connection_id, connection_id);
    assert!(matches!(
        repo.inspect_attachment(AttachmentLookup {
            token_digest: attachment_digest,
            tenant_id: owner.clone(),
            transport: AttachmentTransport::Sip,
            principal_fingerprint: principal(),
            worker: worker.lease,
            at: at(5),
        })
        .await,
        Err(RepositoryError::AttachmentRejected)
    ));

    let current = repo.load_call(&owner, call.aggregate.id()).await.unwrap();
    let command = CommandCommit {
        tenant_id: owner.clone(),
        call_id: current.aggregate.id(),
        expected_version: current.aggregate.version(),
        command_id: CommandId::new(),
        command: CallCommand::SetLegState {
            at: at(6),
            leg_id: current.aggregate.legs()[1].id(),
            binding_generation: current.aggregate.legs()[1].binding_generation(),
            state: LegState::Signaling,
            failure: None,
        },
        worker: worker.lease,
        attachments: Vec::new(),
        deadline_claim: None,
        at: at(6),
    };
    let committed = repo.commit_command(command.clone()).await.unwrap();
    assert!(matches!(committed, CommandCommitOutcome::Committed(_)));
    assert!(matches!(
        repo.commit_command(command).await.unwrap(),
        CommandCommitOutcome::Replayed(_)
    ));

    let account = ProviderAccountKey::parse("conformance-provider").unwrap();
    let provider_call_id = ProviderCallId::parse("provider-call-conformance").unwrap();
    let event_digest = ProviderEventDigest::new(digest(40));
    assert!(matches!(
        repo.ingest_provider_event(ProviderEventInput {
            account: account.clone(),
            event_digest,
            payload_digest: ProviderPayloadDigest::new(digest(41)),
            provider_call_id: provider_call_id.clone(),
            kind: "answered".into(),
            payload: json!({"state": "answered"}),
            occurred_at: Some(at(7)),
            received_at: at(8),
        })
        .await
        .unwrap(),
        ProviderEventOutcome::Accepted(event)
            if event.state == ProviderEventState::PendingReference
    ));
    let current = repo.load_call(&owner, call.aggregate.id()).await.unwrap();
    let target_leg = current.aggregate.legs()[1].id();
    repo.bind_provider_reference(BindProviderReference {
        tenant_id: owner.clone(),
        call_id: current.aggregate.id(),
        leg_id: target_leg,
        account: account.clone(),
        provider_call_id,
        worker: worker.lease,
        at: at(9),
    })
    .await
    .unwrap();
    let claim = repo
        .claim_provider_events(worker.lease, at(10), Duration::from_secs(10), 1)
        .await
        .unwrap()
        .remove(0);
    let completion = ProviderEventCommit {
        account: account.clone(),
        event_digest,
        claim_generation: claim.claim_generation,
        worker: worker.lease,
        command: CommandCommit {
            tenant_id: owner,
            call_id: current.aggregate.id(),
            expected_version: current.aggregate.version(),
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at: at(11),
                leg_id: target_leg,
                binding_generation: current.aggregate.legs()[1].binding_generation(),
                state: LegState::Connected,
                failure: None,
            },
            worker: worker.lease,
            attachments: Vec::new(),
            deadline_claim: None,
            at: at(11),
        },
        at: at(11),
    };
    let first = repo
        .complete_provider_event(completion.clone())
        .await
        .unwrap();
    assert_eq!(first.event.state, ProviderEventState::Applied);
    let replay = repo.complete_provider_event(completion).await.unwrap();
    assert_eq!(replay.event, first.event);

    let terminal_event_digest = ProviderEventDigest::new(digest(42));
    assert!(matches!(
        repo.ingest_provider_event(ProviderEventInput {
            account: account.clone(),
            event_digest: terminal_event_digest,
            payload_digest: ProviderPayloadDigest::new(digest(43)),
            provider_call_id: ProviderCallId::parse("provider-call-conformance").unwrap(),
            kind: "completed".into(),
            payload: json!({"state": "completed"}),
            occurred_at: Some(at(12)),
            received_at: at(12),
        })
        .await
        .unwrap(),
        ProviderEventOutcome::Accepted(event) if event.state == ProviderEventState::Ready
    ));

    let outbox_claim = repo
        .claim_outbox(worker.lease, at(20), Duration::from_secs(5), 1)
        .await
        .unwrap()
        .remove(0);
    let completed_outbox = repo
        .complete_outbox(
            outbox_claim.record.effect_id,
            worker.lease,
            outbox_claim.claim_generation,
            OutboxCompletion::Succeeded,
            at(21),
        )
        .await
        .unwrap();
    assert!(matches!(
        completed_outbox.state,
        bridgefu::call_engine::OutboxState::Succeeded { .. }
    ));

    let deadline_claim = repo
        .claim_due_deadlines(worker.lease, at(33), Duration::from_secs(5), 4)
        .await
        .unwrap()
        .into_iter()
        .find(|claim| claim.record.kind == DeadlineKind::Setup)
        .expect("setup deadline remains pending while only one leg is connected");
    let current = repo
        .load_call(&tenant("conformance-a"), call.aggregate.id())
        .await
        .unwrap();
    let deadline_outcome = repo
        .commit_command(CommandCommit {
            tenant_id: tenant("conformance-a"),
            call_id: current.aggregate.id(),
            expected_version: current.aggregate.version(),
            command_id: CommandId::new(),
            command: CallCommand::DeadlineElapsed {
                at: at(34),
                kind: deadline_claim.record.kind,
                generation: deadline_claim.record.generation,
                ending_deadline: Some(at(44)),
            },
            worker: worker.lease,
            attachments: Vec::new(),
            deadline_claim: Some(deadline_claim.guard(worker.lease)),
            at: at(34),
        })
        .await
        .unwrap();
    assert!(matches!(
        deadline_outcome,
        CommandCommitOutcome::Committed(_)
    ));

    let owner = tenant("conformance-a");
    let mut current = repo.load_call(&owner, call.aggregate.id()).await.unwrap();
    for index in 0..2 {
        if current.aggregate.legs()[index].state().is_terminal() {
            continue;
        }
        let leg = &current.aggregate.legs()[index];
        let outcome = repo
            .commit_command(CommandCommit {
                tenant_id: owner.clone(),
                call_id: current.aggregate.id(),
                expected_version: current.aggregate.version(),
                command_id: CommandId::new(),
                command: CallCommand::SetLegState {
                    at: at(35 + i64::try_from(index).unwrap()),
                    leg_id: leg.id(),
                    binding_generation: leg.binding_generation(),
                    state: LegState::Ended,
                    failure: None,
                },
                worker: worker.lease,
                attachments: Vec::new(),
                deadline_claim: None,
                at: at(35 + i64::try_from(index).unwrap()),
            })
            .await
            .unwrap();
        current = match outcome {
            CommandCommitOutcome::Committed(view) | CommandCommitOutcome::Replayed(view) => {
                view.call
            }
        };
    }
    assert!(current.aggregate.state().is_terminal());
    assert!(current.assignment.released_at.is_some());
    assert!(!repo
        .release_assignment(&owner, current.aggregate.id(), worker.lease, at(38))
        .await
        .unwrap());

    let terminal_claim = repo
        .claim_provider_events(worker.lease, at(39), Duration::from_secs(5), 1)
        .await
        .unwrap()
        .remove(0);
    let acknowledgement = TerminalProviderEventAcknowledge {
        account,
        event_digest: terminal_event_digest,
        claim_generation: terminal_claim.claim_generation,
        worker: worker.lease,
        target: ProviderEventTarget {
            tenant_id: owner.clone(),
            call_id: current.aggregate.id(),
            leg_id: target_leg,
        },
        at: at(40),
    };
    assert!(matches!(
        repo.acknowledge_terminal_provider_event(acknowledgement.clone())
            .await
            .unwrap(),
        TerminalProviderEventAcknowledgeOutcome::Acknowledged(_)
    ));
    assert!(matches!(
        repo.acknowledge_terminal_provider_event(acknowledgement)
            .await
            .unwrap(),
        TerminalProviderEventAcknowledgeOutcome::Replayed(_)
    ));

    let next_worker = repo
        .register_worker(RegisterWorker {
            worker_id: worker.lease.worker_id,
            max_calls: 4,
            capabilities: BTreeSet::from(["sip".into(), "webrtc".into()]),
            at: at(41),
        })
        .await
        .unwrap();
    let restart_claims = repo
        .claim_restart_calls(next_worker.lease, at(42), 8)
        .await
        .unwrap();
    assert!(restart_claims
        .iter()
        .any(|claim| claim.call.aggregate.id() == current.aggregate.id()));
    assert!(
        repo.set_worker_draining(next_worker.lease, true, at(43))
            .await
            .unwrap()
            .draining
    );
    assert!(
        !repo
            .set_worker_draining(next_worker.lease, false, at(44))
            .await
            .unwrap()
            .draining
    );
}

fn sqlite_database(label: &str) -> (String, PathBuf) {
    let path = std::env::temp_dir().join(format!(
        "bridgefu-{label}-{}-{}.sqlite3",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    (format!("sqlite://{}", path.display()), path)
}

#[tokio::test]
async fn memory_repository_shared_conformance() {
    shared_repository_conformance(Arc::new(MemoryRepository::new())).await;
}

#[tokio::test]
async fn sqlite_repository_shared_conformance_and_schema() {
    let (url, path) = sqlite_database("conformance");
    let repository = SqliteRepository::connect(&url).await.unwrap();
    assert_required_sqlite_tables(&repository).await;
    let reconnected = SqliteRepository::connect(&url).await.unwrap();
    assert_required_sqlite_tables(&reconnected).await;
    drop(reconnected);
    let probe = prepare_read_probe(&repository).await;
    let epoch_before = sqlite_epoch(&repository).await;
    exercise_read_probe(&repository, &probe).await;
    assert_eq!(sqlite_epoch(&repository).await, epoch_before);
    shared_repository_conformance(Arc::new(repository.clone())).await;
    assert!(repository
        .retention_candidates(SqlRetentionPolicy::new(Duration::ZERO), at(1_000), 100)
        .await
        .unwrap()
        .is_empty());
    exercise_expired_idempotency(&repository).await;
    assert_eq!(
        sqlite_idempotency_count(&repository, "expired-idempotency").await,
        1
    );
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn sqlite_v1_upgrade_rewrites_create_receipt_and_claim_acquisition_time() {
    let (source_url, source_path) = sqlite_database("v3-upgrade-source");
    let source = SqliteRepository::connect(&source_url).await.unwrap();
    let source_repository: Repository = Arc::new(source.clone());
    let worker = register(&source_repository, 1).await;
    let owner = tenant("v1-upgrade-owner");
    let request = create_request(new_call(owner.clone()), worker.lease, 91, 92);
    let call_id = request.initial.id();
    source_repository.create_call(request).await.unwrap();
    let claimed = source_repository
        .claim_outbox(worker.lease, at(3), Duration::from_secs(30), 64)
        .await
        .unwrap();
    assert!(!claimed.is_empty());
    source.pool().close().await;

    let (target_url, target_path) = sqlite_database("v1-upgrade-target");
    let migration_dir = std::env::temp_dir().join(format!(
        "bridgefu-v1-sqlite-migration-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir(&migration_dir).unwrap();
    std::fs::copy(
        "migrations/sqlite/0001_call_repository.sql",
        migration_dir.join("0001_call_repository.sql"),
    )
    .unwrap();
    let options = sqlx::sqlite::SqliteConnectOptions::from_str(&target_url)
        .unwrap()
        .create_if_missing(true)
        .foreign_keys(true);
    let target = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    sqlx::migrate::Migrator::new(migration_dir.clone())
        .await
        .unwrap()
        .run(&target)
        .await
        .unwrap();
    sqlx::query("ATTACH DATABASE ? AS source")
        .bind(source_path.to_string_lossy().as_ref())
        .execute(&target)
        .await
        .unwrap();
    for statement in [
        "INSERT INTO workers SELECT * FROM source.workers",
        "INSERT INTO calls(call_id, tenant_id, aggregate_version, call_state, body) SELECT call_id, tenant_id, aggregate_version, call_state, body FROM source.calls",
        "INSERT INTO legs SELECT * FROM source.legs",
        "INSERT INTO worker_assignments SELECT * FROM source.worker_assignments",
        "INSERT INTO commands SELECT * FROM source.commands",
        "INSERT INTO idempotency(tenant_id, key_digest, request_digest, call_id, expires_at, body) SELECT tenant_id, key_digest, request_digest, call_id, expires_at, body FROM source.idempotency",
        "INSERT INTO attachments SELECT * FROM source.attachments",
        "INSERT INTO outbox SELECT * FROM source.outbox",
        "INSERT INTO deadlines SELECT * FROM source.deadlines",
    ] {
        sqlx::query(statement).execute(&target).await.unwrap();
    }
    sqlx::query("UPDATE idempotency SET body = json_remove(body, '$.row.receipt')")
        .execute(&target)
        .await
        .unwrap();
    sqlx::query("UPDATE outbox SET body = json_remove(body, '$.state.claimed_at') WHERE outbox_state = 'claimed'")
        .execute(&target)
        .await
        .unwrap();
    sqlx::query("DETACH DATABASE source")
        .execute(&target)
        .await
        .unwrap();
    target.close().await;

    let upgraded = SqliteRepository::connect(&target_url).await.unwrap();
    let idempotency =
        sqlx::query("SELECT receipt_kind, operation_kind, body FROM idempotency WHERE call_id = ?")
            .bind(call_id.to_string())
            .fetch_one(upgraded.pool())
            .await
            .unwrap();
    assert_eq!(idempotency.get::<String, _>("receipt_kind"), "create_call");
    assert_eq!(
        idempotency.get::<String, _>("operation_kind"),
        "create_call"
    );
    let body: serde_json::Value =
        serde_json::from_str(&idempotency.get::<String, _>("body")).unwrap();
    assert_eq!(
        body.pointer("/row/receipt/receipt")
            .and_then(serde_json::Value::as_str),
        Some("create_call")
    );
    let claimed =
        sqlx::query("SELECT available_at, body FROM outbox WHERE outbox_state = 'claimed' LIMIT 1")
            .fetch_one(upgraded.pool())
            .await
            .unwrap();
    let available_at = claimed.get::<String, _>("available_at");
    let body: serde_json::Value = serde_json::from_str(&claimed.get::<String, _>("body")).unwrap();
    assert_eq!(
        body.pointer("/state/claimed_at")
            .and_then(serde_json::Value::as_str),
        Some(available_at.as_str())
    );
    assert_eq!(
        upgraded
            .load_call(&owner, call_id)
            .await
            .unwrap()
            .aggregate
            .id(),
        call_id
    );
    upgraded.pool().close().await;
    std::fs::remove_file(source_path).unwrap();
    std::fs::remove_file(target_path).unwrap();
    std::fs::remove_dir_all(migration_dir).unwrap();
}

#[tokio::test]
async fn sqlite_v2_upgrade_marks_existing_execution_plans_as_service_managed() {
    let (source_url, source_path) = sqlite_database("v3-service-upgrade-source");
    let source = SqliteRepository::connect(&source_url).await.unwrap();
    let source_repository: Repository = Arc::new(source.clone());
    let worker = register(&source_repository, 1).await;
    let owner = tenant("sqlite-v2-service-upgrade-owner");
    let request = service_create_request(owner.clone(), worker.lease, 95, 96);
    let call_id = request.create.initial.id();
    source.create_with_plan(request).await.unwrap();
    source.pool().close().await;

    let (target_url, target_path) = sqlite_database("v3-service-upgrade-target");
    let migration_dir = std::env::temp_dir().join(format!(
        "bridgefu-v2-sqlite-migration-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir(&migration_dir).unwrap();
    for migration in [
        "0001_call_repository.sql",
        "0002_call_service_repository.sql",
    ] {
        std::fs::copy(
            format!("migrations/sqlite/{migration}"),
            migration_dir.join(migration),
        )
        .unwrap();
    }
    let options = sqlx::sqlite::SqliteConnectOptions::from_str(&target_url)
        .unwrap()
        .create_if_missing(true)
        .foreign_keys(true);
    let target = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    sqlx::migrate::Migrator::new(migration_dir.clone())
        .await
        .unwrap()
        .run(&target)
        .await
        .unwrap();
    sqlx::query("ATTACH DATABASE ? AS source")
        .bind(source_path.to_string_lossy().as_ref())
        .execute(&target)
        .await
        .unwrap();
    for statement in [
        "INSERT INTO workers SELECT * FROM source.workers",
        "INSERT INTO calls(call_id, tenant_id, aggregate_version, call_state, body) SELECT call_id, tenant_id, aggregate_version, call_state, body FROM source.calls",
        "INSERT INTO legs SELECT * FROM source.legs",
        "INSERT INTO worker_assignments SELECT * FROM source.worker_assignments",
        "INSERT INTO commands SELECT * FROM source.commands",
        "INSERT INTO idempotency SELECT * FROM source.idempotency",
        "INSERT INTO attachments SELECT * FROM source.attachments",
        "INSERT INTO outbox SELECT * FROM source.outbox",
        "INSERT INTO deadlines SELECT * FROM source.deadlines",
        "INSERT INTO call_execution_plans SELECT * FROM source.call_execution_plans",
    ] {
        sqlx::query(statement).execute(&target).await.unwrap();
    }
    sqlx::query("DETACH DATABASE source")
        .execute(&target)
        .await
        .unwrap();
    target.close().await;

    let upgraded = SqliteRepository::connect(&target_url).await.unwrap();
    let managed: i64 = sqlx::query_scalar("SELECT service_managed FROM calls WHERE call_id = ?")
        .bind(call_id.to_string())
        .fetch_one(upgraded.pool())
        .await
        .unwrap();
    assert_eq!(managed, 1);
    assert_eq!(
        upgraded
            .load_service_call(&owner, call_id)
            .await
            .unwrap()
            .call
            .aggregate
            .id(),
        call_id
    );
    upgraded.pool().close().await;
    std::fs::remove_file(source_path).unwrap();
    std::fs::remove_file(target_path).unwrap();
    std::fs::remove_dir_all(migration_dir).unwrap();
}

#[tokio::test]
async fn postgres_v1_upgrade_rewrites_create_receipt_and_claim_acquisition_time() {
    let Some(url) = postgres_test_url() else {
        eprintln!("BRIDGEFU_TEST_POSTGRES_URL is unset; PostgreSQL v1 upgrade test skipped");
        return;
    };
    let administration = sqlx::PgPool::connect(&url).await.unwrap();
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let source_schema = format!("bridgefu_v3_source_{suffix}");
    let target_schema = format!("bridgefu_v1_target_{suffix}");
    sqlx::query(&format!("CREATE SCHEMA {source_schema}"))
        .execute(&administration)
        .await
        .unwrap();
    sqlx::query(&format!("CREATE SCHEMA {target_schema}"))
        .execute(&administration)
        .await
        .unwrap();
    let scoped_url = |schema: &str| {
        let mut scoped = url::Url::parse(&url).unwrap();
        scoped
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        scoped.to_string()
    };
    let source_url = scoped_url(&source_schema);
    let source = PostgresRepository::connect(&source_url).await.unwrap();
    let source_repository: Repository = Arc::new(source.clone());
    let worker = register(&source_repository, 1).await;
    let owner = tenant("postgres-v1-upgrade-owner");
    let request = create_request(new_call(owner.clone()), worker.lease, 93, 94);
    let call_id = request.initial.id();
    source_repository.create_call(request).await.unwrap();
    let claimed = source_repository
        .claim_outbox(worker.lease, at(3), Duration::from_secs(30), 64)
        .await
        .unwrap();
    assert!(!claimed.is_empty());

    let migration_dir = std::env::temp_dir().join(format!(
        "bridgefu-v1-postgres-migration-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir(&migration_dir).unwrap();
    std::fs::copy(
        "migrations/postgres/0001_call_repository.sql",
        migration_dir.join("0001_call_repository.sql"),
    )
    .unwrap();
    let target_url = scoped_url(&target_schema);
    let target = sqlx::PgPool::connect(&target_url).await.unwrap();
    sqlx::migrate::Migrator::new(migration_dir.clone())
        .await
        .unwrap()
        .run(&target)
        .await
        .unwrap();
    for statement in [
        format!("INSERT INTO {target_schema}.workers SELECT * FROM {source_schema}.workers"),
        format!("INSERT INTO {target_schema}.calls(call_id, tenant_id, aggregate_version, call_state, body) SELECT call_id, tenant_id, aggregate_version, call_state, body FROM {source_schema}.calls"),
        format!("INSERT INTO {target_schema}.legs SELECT * FROM {source_schema}.legs"),
        format!("INSERT INTO {target_schema}.worker_assignments SELECT * FROM {source_schema}.worker_assignments"),
        format!("INSERT INTO {target_schema}.commands SELECT * FROM {source_schema}.commands"),
        format!("INSERT INTO {target_schema}.idempotency(tenant_id, key_digest, request_digest, call_id, expires_at, body) SELECT tenant_id, key_digest, request_digest, call_id, expires_at, body FROM {source_schema}.idempotency"),
        format!("INSERT INTO {target_schema}.attachments SELECT * FROM {source_schema}.attachments"),
        format!("INSERT INTO {target_schema}.outbox SELECT * FROM {source_schema}.outbox"),
        format!("INSERT INTO {target_schema}.deadlines SELECT * FROM {source_schema}.deadlines"),
    ] {
        sqlx::query(&statement)
            .execute(&administration)
            .await
            .unwrap();
    }
    sqlx::query(&format!(
        "UPDATE {target_schema}.idempotency SET body = body #- '{{row,receipt}}'"
    ))
    .execute(&administration)
    .await
    .unwrap();
    sqlx::query(&format!(
        "UPDATE {target_schema}.outbox SET body = body #- '{{state,claimed_at}}' WHERE outbox_state = 'claimed'"
    ))
    .execute(&administration)
    .await
    .unwrap();
    target.close().await;

    let upgraded = PostgresRepository::connect(&target_url).await.unwrap();
    let idempotency = sqlx::query(
        "SELECT receipt_kind, operation_kind, body::text AS body FROM idempotency WHERE call_id = $1",
    )
    .bind(call_id.as_uuid())
    .fetch_one(upgraded.pool())
    .await
    .unwrap();
    assert_eq!(idempotency.get::<String, _>("receipt_kind"), "create_call");
    assert_eq!(
        idempotency.get::<String, _>("operation_kind"),
        "create_call"
    );
    let body: serde_json::Value =
        serde_json::from_str(&idempotency.get::<String, _>("body")).unwrap();
    assert_eq!(
        body.pointer("/row/receipt/receipt")
            .and_then(serde_json::Value::as_str),
        Some("create_call")
    );
    let claimed = sqlx::query(
        "SELECT available_at, body::text AS body FROM outbox WHERE outbox_state = 'claimed' LIMIT 1",
    )
    .fetch_one(upgraded.pool())
    .await
    .unwrap();
    let available_at = claimed.get::<DateTime<Utc>, _>("available_at");
    let body: serde_json::Value = serde_json::from_str(&claimed.get::<String, _>("body")).unwrap();
    let claimed_at = DateTime::parse_from_rfc3339(
        body.pointer("/state/claimed_at")
            .and_then(serde_json::Value::as_str)
            .unwrap(),
    )
    .unwrap()
    .with_timezone(&Utc);
    assert_eq!(claimed_at, available_at);
    assert_eq!(
        upgraded
            .load_call(&owner, call_id)
            .await
            .unwrap()
            .aggregate
            .id(),
        call_id
    );
    upgraded.pool().close().await;
    source.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {target_schema} CASCADE"))
        .execute(&administration)
        .await
        .unwrap();
    sqlx::query(&format!("DROP SCHEMA {source_schema} CASCADE"))
        .execute(&administration)
        .await
        .unwrap();
    administration.close().await;
    std::fs::remove_dir_all(migration_dir).unwrap();
}

#[tokio::test]
async fn postgres_v2_upgrade_marks_existing_execution_plans_as_service_managed() {
    let Some(url) = postgres_test_url() else {
        eprintln!("BRIDGEFU_TEST_POSTGRES_URL is unset; PostgreSQL v2 upgrade test skipped");
        return;
    };
    let administration = sqlx::PgPool::connect(&url).await.unwrap();
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let source_schema = format!("bridgefu_v3_service_source_{suffix}");
    let target_schema = format!("bridgefu_v2_service_target_{suffix}");
    sqlx::query(&format!("CREATE SCHEMA {source_schema}"))
        .execute(&administration)
        .await
        .unwrap();
    sqlx::query(&format!("CREATE SCHEMA {target_schema}"))
        .execute(&administration)
        .await
        .unwrap();
    let scoped_url = |schema: &str| {
        let mut scoped = url::Url::parse(&url).unwrap();
        scoped
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        scoped.to_string()
    };

    let source_url = scoped_url(&source_schema);
    let source = PostgresRepository::connect(&source_url).await.unwrap();
    let source_repository: Repository = Arc::new(source.clone());
    let worker = register(&source_repository, 1).await;
    let owner = tenant("postgres-v2-service-upgrade-owner");
    let request = service_create_request(owner.clone(), worker.lease, 97, 98);
    let call_id = request.create.initial.id();
    source.create_with_plan(request).await.unwrap();

    let migration_dir = std::env::temp_dir().join(format!(
        "bridgefu-v2-postgres-migration-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir(&migration_dir).unwrap();
    for migration in [
        "0001_call_repository.sql",
        "0002_call_service_repository.sql",
    ] {
        std::fs::copy(
            format!("migrations/postgres/{migration}"),
            migration_dir.join(migration),
        )
        .unwrap();
    }
    let target_url = scoped_url(&target_schema);
    let target = sqlx::PgPool::connect(&target_url).await.unwrap();
    sqlx::migrate::Migrator::new(migration_dir.clone())
        .await
        .unwrap()
        .run(&target)
        .await
        .unwrap();
    for statement in [
        format!("INSERT INTO {target_schema}.workers SELECT * FROM {source_schema}.workers"),
        format!("INSERT INTO {target_schema}.calls(call_id, tenant_id, aggregate_version, call_state, body) SELECT call_id, tenant_id, aggregate_version, call_state, body FROM {source_schema}.calls"),
        format!("INSERT INTO {target_schema}.legs SELECT * FROM {source_schema}.legs"),
        format!("INSERT INTO {target_schema}.worker_assignments SELECT * FROM {source_schema}.worker_assignments"),
        format!("INSERT INTO {target_schema}.commands SELECT * FROM {source_schema}.commands"),
        format!("INSERT INTO {target_schema}.idempotency SELECT * FROM {source_schema}.idempotency"),
        format!("INSERT INTO {target_schema}.attachments SELECT * FROM {source_schema}.attachments"),
        format!("INSERT INTO {target_schema}.outbox SELECT * FROM {source_schema}.outbox"),
        format!("INSERT INTO {target_schema}.deadlines SELECT * FROM {source_schema}.deadlines"),
        format!("INSERT INTO {target_schema}.call_execution_plans SELECT * FROM {source_schema}.call_execution_plans"),
    ] {
        sqlx::query(&statement)
            .execute(&administration)
            .await
            .unwrap();
    }
    target.close().await;

    let upgraded = PostgresRepository::connect(&target_url).await.unwrap();
    let managed: bool = sqlx::query_scalar("SELECT service_managed FROM calls WHERE call_id = $1")
        .bind(call_id.as_uuid())
        .fetch_one(upgraded.pool())
        .await
        .unwrap();
    assert!(managed);
    assert_eq!(
        upgraded
            .load_service_call(&owner, call_id)
            .await
            .unwrap()
            .call
            .aggregate
            .id(),
        call_id
    );
    upgraded.pool().close().await;
    source.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {target_schema} CASCADE"))
        .execute(&administration)
        .await
        .unwrap();
    sqlx::query(&format!("DROP SCHEMA {source_schema} CASCADE"))
        .execute(&administration)
        .await
        .unwrap();
    administration.close().await;
    std::fs::remove_dir_all(migration_dir).unwrap();
}

#[tokio::test]
async fn sqlite_migration_checksum_drift_fails_closed_and_recovers_after_restore() {
    let (url, path) = sqlite_database("migration-checksum");
    let repository = SqliteRepository::connect(&url).await.unwrap();
    let checksum = sqlx::query("SELECT checksum FROM _sqlx_migrations WHERE version = 3")
        .fetch_one(repository.pool())
        .await
        .unwrap()
        .get::<Vec<u8>, _>("checksum");
    sqlx::query("UPDATE _sqlx_migrations SET checksum = ? WHERE version = 3")
        .bind(vec![0_u8; checksum.len()])
        .execute(repository.pool())
        .await
        .unwrap();
    assert_eq!(
        SqliteRepository::connect(&url).await.err(),
        Some(RepositoryError::Unavailable)
    );
    sqlx::query("UPDATE _sqlx_migrations SET checksum = ? WHERE version = 3")
        .bind(checksum)
        .execute(repository.pool())
        .await
        .unwrap();
    let reconnected = SqliteRepository::connect(&url).await.unwrap();
    reconnected.pool().close().await;
    repository.pool().close().await;
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn postgres_migration_checksum_drift_fails_closed_and_recovers_after_restore() {
    let Some(url) = postgres_test_url() else {
        eprintln!("BRIDGEFU_TEST_POSTGRES_URL is unset; PostgreSQL checksum test skipped");
        return;
    };
    let administration = sqlx::PgPool::connect(&url).await.unwrap();
    let schema = format!("bridgefu_checksum_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&administration)
        .await
        .unwrap();
    let mut scoped = url::Url::parse(&url).unwrap();
    scoped
        .query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"));
    let scoped = scoped.to_string();
    let repository = PostgresRepository::connect(&scoped).await.unwrap();
    let checksum = sqlx::query("SELECT checksum FROM _sqlx_migrations WHERE version = 3")
        .fetch_one(repository.pool())
        .await
        .unwrap()
        .get::<Vec<u8>, _>("checksum");
    sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = 3")
        .bind(vec![0_u8; checksum.len()])
        .execute(repository.pool())
        .await
        .unwrap();
    assert_eq!(
        PostgresRepository::connect(&scoped).await.err(),
        Some(RepositoryError::Unavailable)
    );
    sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = 3")
        .bind(checksum)
        .execute(repository.pool())
        .await
        .unwrap();
    let reconnected = PostgresRepository::connect(&scoped).await.unwrap();
    reconnected.pool().close().await;
    repository.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&administration)
        .await
        .unwrap();
    administration.close().await;
}

#[tokio::test]
async fn postgres_repository_shared_conformance_and_schema() {
    let _guard = POSTGRES_TEST_LOCK.lock().await;
    let Some(url) = postgres_test_url() else {
        eprintln!("BRIDGEFU_TEST_POSTGRES_URL is unset; PostgreSQL conformance skipped");
        return;
    };
    let repository = PostgresRepository::connect(&url).await.unwrap();
    reset_postgres(&repository).await;
    assert_required_postgres_tables(&repository).await;
    let reconnected = PostgresRepository::connect(&url).await.unwrap();
    assert_required_postgres_tables(&reconnected).await;
    drop(reconnected);
    let probe = prepare_read_probe(&repository).await;
    let epoch_before = postgres_epoch(&repository).await;
    exercise_read_probe(&repository, &probe).await;
    assert_eq!(postgres_epoch(&repository).await, epoch_before);
    shared_repository_conformance(Arc::new(repository.clone())).await;
    assert!(repository
        .retention_candidates(SqlRetentionPolicy::new(Duration::ZERO), at(1_000), 100)
        .await
        .unwrap()
        .is_empty());
    exercise_expired_idempotency(&repository).await;
    assert_eq!(
        postgres_idempotency_count(&repository, "expired-idempotency").await,
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn sqlite_two_independent_instances_serialize_races() {
    let (url, path) = sqlite_database("race");
    let left: Repository = Arc::new(SqliteRepository::connect(&url).await.unwrap());
    let right: Repository = Arc::new(SqliteRepository::connect(&url).await.unwrap());
    independent_instance_races(left, right).await;
    let _ = std::fs::remove_file(path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn postgres_two_independent_instances_serialize_races() {
    let _guard = POSTGRES_TEST_LOCK.lock().await;
    let Some(url) = postgres_test_url() else {
        eprintln!("BRIDGEFU_TEST_POSTGRES_URL is unset; PostgreSQL race suite skipped");
        return;
    };
    let left_repo = PostgresRepository::connect(&url).await.unwrap();
    reset_postgres(&left_repo).await;
    let left: Repository = Arc::new(left_repo);
    let right: Repository = Arc::new(PostgresRepository::connect(&url).await.unwrap());
    independent_instance_races(left, right).await;
}

#[tokio::test]
async fn sqlite_delta_writes_ignore_unrelated_history_and_detect_column_drift() {
    let (url, path) = sqlite_database("delta");
    let repository = SqliteRepository::connect(&url).await.unwrap();
    let (owner, worker, changed, untouched) = two_calls_for_delta(&repository).await;
    sqlx::query(&format!(
        "CREATE TRIGGER reject_unrelated_call_update BEFORE UPDATE ON calls WHEN OLD.call_id = '{}' BEGIN SELECT RAISE(ABORT, 'unrelated call rewritten'); END",
        untouched.aggregate.id()
    ))
    .execute(repository.pool())
    .await
    .unwrap();
    advance_second_leg(&repository, &owner, worker, &changed)
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER reject_unrelated_call_update")
        .execute(repository.pool())
        .await
        .unwrap();

    sqlx::query("UPDATE calls SET tenant_id = 'tampered' WHERE call_id = ?")
        .bind(untouched.aggregate.id().to_string())
        .execute(repository.pool())
        .await
        .unwrap();
    assert_eq!(
        repository.load_call(&owner, untouched.aggregate.id()).await,
        Err(RepositoryError::Unavailable)
    );
    sqlx::query("UPDATE calls SET tenant_id = ? WHERE call_id = ?")
        .bind(owner.as_str())
        .bind(untouched.aggregate.id().to_string())
        .execute(repository.pool())
        .await
        .unwrap();
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn sqlite_rejects_normalized_column_drift_for_every_body_row_family() {
    let (url, path) = sqlite_database("all-column-drift");
    let repository = SqliteRepository::connect(&url).await.unwrap();
    shared_repository_conformance(Arc::new(repository.clone())).await;
    let probe_worker_id = prepare_active_binding(&repository).await;

    let cases = [
        ("workers", "fence", "fence + 1000"),
        ("calls", "tenant_id", "tenant_id || '-drift'"),
        ("legs", "binding_generation", "binding_generation + 1000"),
        (
            "worker_assignments",
            "worker_fence",
            "worker_fence + 1000",
        ),
        (
            "connection_bindings",
            "principal_fingerprint",
            "zeroblob(32)",
        ),
        ("commands", "result_version", "result_version + 1000"),
        ("idempotency", "request_digest", "zeroblob(32)"),
        ("attachments", "worker_fence", "worker_fence + 1000"),
        (
            "provider_events",
            "event_state",
            "event_state || '_drift'",
        ),
        (
            "provider_references",
            "tenant_id",
            "tenant_id || '-drift'",
        ),
        (
            "provider_completions",
            "completion_kind",
            "CASE completion_kind WHEN 'command' THEN 'terminal_acknowledgement' ELSE 'command' END",
        ),
        ("outbox", "outbox_state", "outbox_state || '_drift'"),
        (
            "deadlines",
            "deadline_state",
            "deadline_state || '_drift'",
        ),
    ];

    for (table, column, mutation) in cases {
        sqlx::query("DROP TABLE IF EXISTS normalized_drift_backup")
            .execute(repository.pool())
            .await
            .unwrap();
        sqlx::query(&format!(
            "CREATE TABLE normalized_drift_backup AS SELECT rowid AS target_rowid, {column} AS original_value FROM {table} ORDER BY rowid LIMIT 1"
        ))
        .execute(repository.pool())
        .await
        .unwrap();
        assert_eq!(
            sqlx::query("SELECT COUNT(*) AS count FROM normalized_drift_backup")
                .fetch_one(repository.pool())
                .await
                .unwrap()
                .get::<i64, _>("count"),
            1,
            "{table} must have a conformance fixture row"
        );
        sqlx::query(&format!(
            "UPDATE {table} SET {column} = {mutation} WHERE rowid = (SELECT target_rowid FROM normalized_drift_backup)"
        ))
        .execute(repository.pool())
        .await
        .unwrap();
        assert_eq!(
            repository.worker_snapshot(probe_worker_id).await,
            Err(RepositoryError::Unavailable),
            "{table}.{column} drift was accepted"
        );
        sqlx::query(&format!(
            "UPDATE {table} SET {column} = (SELECT original_value FROM normalized_drift_backup) WHERE rowid = (SELECT target_rowid FROM normalized_drift_backup)"
        ))
        .execute(repository.pool())
        .await
        .unwrap();
        repository.worker_snapshot(probe_worker_id).await.unwrap();
    }
    sqlx::query("DROP TABLE normalized_drift_backup")
        .execute(repository.pool())
        .await
        .unwrap();
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn sqlite_raii_transaction_recovers_from_rollback_and_cancellation() {
    let (url, path) = sqlite_database("rollback-cancel");
    let repository = SqliteRepository::connect(&url).await.unwrap();
    let (owner, worker, call, _) = two_calls_for_delta(&repository).await;
    sqlx::query(
        "CREATE TRIGGER abort_command_insert BEFORE INSERT ON commands BEGIN SELECT RAISE(ABORT, 'forced command rollback'); END",
    )
    .execute(repository.pool())
    .await
    .unwrap();
    assert_eq!(
        advance_second_leg(&repository, &owner, worker, &call).await,
        Err(RepositoryError::Unavailable)
    );
    assert_eq!(
        repository
            .load_call(&owner, call.aggregate.id())
            .await
            .unwrap(),
        call
    );
    sqlx::query("DROP TRIGGER abort_command_insert")
        .execute(repository.pool())
        .await
        .unwrap();
    advance_second_leg(&repository, &owner, worker, &call)
        .await
        .unwrap();

    sqlx::query("CREATE TABLE cancellation_probe(value INTEGER NOT NULL)")
        .execute(repository.pool())
        .await
        .unwrap();
    let entered = Arc::new(Notify::new());
    let task = {
        let pool = repository.pool().clone();
        let entered = Arc::clone(&entered);
        tokio::spawn(async move {
            let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
            sqlx::query("INSERT INTO cancellation_probe(value) VALUES (1)")
                .execute(&mut *transaction)
                .await
                .unwrap();
            entered.notify_one();
            std::future::pending::<()>().await;
        })
    };
    entered.notified().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let recovered = tokio::time::timeout(
        Duration::from_secs(5),
        repository.register_worker(RegisterWorker {
            worker_id: WorkerId::new(),
            max_calls: 1,
            capabilities: BTreeSet::from(["sip".into()]),
            at: at(50),
        }),
    )
    .await
    .expect("cancelled transaction left the SQLite writer locked")
    .unwrap();
    assert_eq!(recovered.reserved_calls, 0);
    assert_eq!(
        sqlx::query("SELECT COUNT(*) AS count FROM cancellation_probe")
            .fetch_one(repository.pool())
            .await
            .unwrap()
            .get::<i64, _>("count"),
        0
    );
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn postgres_delta_writes_ignore_unrelated_history_and_detect_column_drift() {
    let _guard = POSTGRES_TEST_LOCK.lock().await;
    let Some(url) = postgres_test_url() else {
        eprintln!("BRIDGEFU_TEST_POSTGRES_URL is unset; PostgreSQL delta suite skipped");
        return;
    };
    let repository = PostgresRepository::connect(&url).await.unwrap();
    reset_postgres(&repository).await;
    let (owner, worker, changed, untouched) = two_calls_for_delta(&repository).await;
    let xmin_before: String =
        sqlx::query("SELECT xmin::text AS xmin FROM calls WHERE call_id = $1")
            .bind(untouched.aggregate.id().as_uuid())
            .fetch_one(repository.pool())
            .await
            .unwrap()
            .get("xmin");
    advance_second_leg(&repository, &owner, worker, &changed)
        .await
        .unwrap();
    let xmin_after: String = sqlx::query("SELECT xmin::text AS xmin FROM calls WHERE call_id = $1")
        .bind(untouched.aggregate.id().as_uuid())
        .fetch_one(repository.pool())
        .await
        .unwrap()
        .get("xmin");
    assert_eq!(xmin_after, xmin_before);

    sqlx::query("UPDATE calls SET tenant_id = 'tampered' WHERE call_id = $1")
        .bind(untouched.aggregate.id().as_uuid())
        .execute(repository.pool())
        .await
        .unwrap();
    assert_eq!(
        repository.load_call(&owner, untouched.aggregate.id()).await,
        Err(RepositoryError::Unavailable)
    );
}

#[tokio::test]
async fn postgres_rejects_normalized_column_drift_for_every_body_row_family() {
    let _guard = POSTGRES_TEST_LOCK.lock().await;
    let Some(url) = postgres_test_url() else {
        eprintln!("BRIDGEFU_TEST_POSTGRES_URL is unset; PostgreSQL drift suite skipped");
        return;
    };
    let repository = PostgresRepository::connect(&url).await.unwrap();
    reset_postgres(&repository).await;
    shared_repository_conformance(Arc::new(repository.clone())).await;
    let probe_worker_id = prepare_active_binding(&repository).await;

    let cases = [
        ("workers", "worker_id::text", "fence", "fence + 1000"),
        ("calls", "call_id::text", "tenant_id", "tenant_id || '-drift'"),
        ("legs", "leg_id::text", "binding_generation", "binding_generation + 1000"),
        ("worker_assignments", "call_id::text", "worker_fence", "worker_fence + 1000"),
        ("connection_bindings", "connection_id", "principal_fingerprint", "decode(repeat('00', 32), 'hex')"),
        ("commands", "command_id::text", "result_version", "result_version + 1000"),
        ("idempotency", "tenant_id || ':' || encode(key_digest, 'hex')", "request_digest", "decode(repeat('00', 32), 'hex')"),
        ("attachments", "encode(token_digest, 'hex')", "worker_fence", "worker_fence + 1000"),
        ("provider_events", "account_key || ':' || encode(event_digest, 'hex')", "event_state", "event_state || '_drift'"),
        ("provider_references", "account_key || ':' || provider_call_id", "tenant_id", "tenant_id || '-drift'"),
        ("provider_completions", "account_key || ':' || encode(event_digest, 'hex')", "completion_kind", "CASE completion_kind WHEN 'command' THEN 'terminal_acknowledgement' ELSE 'command' END"),
        ("outbox", "effect_id::text", "outbox_state", "outbox_state || '_drift'"),
        ("deadlines", "call_id::text || ':' || deadline_kind || ':' || generation::text", "deadline_state", "deadline_state || '_drift'"),
    ];

    for (table, key_expression, column, mutation) in cases {
        sqlx::query("DROP TABLE IF EXISTS normalized_drift_backup")
            .execute(repository.pool())
            .await
            .unwrap();
        sqlx::query(&format!(
            "CREATE TABLE normalized_drift_backup AS SELECT {key_expression} AS target_key, {column} AS original_value FROM {table} ORDER BY {key_expression} LIMIT 1"
        ))
        .execute(repository.pool())
        .await
        .unwrap();
        assert_eq!(
            sqlx::query("SELECT COUNT(*) AS count FROM normalized_drift_backup")
                .fetch_one(repository.pool())
                .await
                .unwrap()
                .get::<i64, _>("count"),
            1,
            "{table} must have a PostgreSQL conformance fixture row"
        );
        sqlx::query(&format!(
            "UPDATE {table} SET {column} = {mutation} WHERE {key_expression} = (SELECT target_key FROM normalized_drift_backup)"
        ))
        .execute(repository.pool())
        .await
        .unwrap();
        assert_eq!(
            repository.worker_snapshot(probe_worker_id).await,
            Err(RepositoryError::Unavailable),
            "PostgreSQL {table}.{column} drift was accepted"
        );
        sqlx::query(&format!(
            "UPDATE {table} SET {column} = (SELECT original_value FROM normalized_drift_backup) WHERE {key_expression} = (SELECT target_key FROM normalized_drift_backup)"
        ))
        .execute(repository.pool())
        .await
        .unwrap();
        repository.worker_snapshot(probe_worker_id).await.unwrap();
    }
    sqlx::query("DROP TABLE normalized_drift_backup")
        .execute(repository.pool())
        .await
        .unwrap();
}

async fn independent_instance_races(left: Repository, right: Repository) {
    let capacity_worker = register(&left, 8).await;
    let owner = tenant("race-capacity");
    let mut tasks = Vec::new();
    for index in 0..9u8 {
        let repository = if index % 2 == 0 {
            Arc::clone(&left)
        } else {
            Arc::clone(&right)
        };
        let request = create_request(
            new_call(owner.clone()),
            capacity_worker.lease,
            50 + index,
            70 + index,
        );
        tasks.push(tokio::spawn(async move {
            repository.create_call(request).await
        }));
    }
    let mut admitted = 0;
    let mut rejected = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(CreateCallOutcome::Created(_)) => admitted += 1,
            Err(RepositoryError::CapacityExceeded) => rejected += 1,
            other => panic!("unexpected capacity race result: {other:?}"),
        }
    }
    assert_eq!((admitted, rejected), (8, 1));
    assert_eq!(
        right
            .worker_snapshot(capacity_worker.lease.worker_id)
            .await
            .unwrap()
            .reserved_calls,
        8
    );

    let idempotency_worker = register(&left, 4).await;
    let request = create_request(
        new_call(tenant("race-idempotency")),
        idempotency_worker.lease,
        90,
        91,
    );
    let mut tasks = Vec::new();
    for index in 0..32 {
        let repository = if index % 2 == 0 {
            Arc::clone(&left)
        } else {
            Arc::clone(&right)
        };
        let request = request.clone();
        tasks.push(tokio::spawn(async move {
            repository.create_call(request).await.unwrap()
        }));
    }
    let mut created_count = 0;
    let mut call_ids = HashSet::new();
    for task in tasks {
        match task.await.unwrap() {
            CreateCallOutcome::Created(call) => {
                created_count += 1;
                call_ids.insert(call.aggregate.id());
            }
            CreateCallOutcome::Replayed(call) => {
                call_ids.insert(call.aggregate.id());
            }
        }
    }
    assert_eq!(created_count, 1);
    assert_eq!(call_ids.len(), 1);
    assert_eq!(
        right
            .worker_snapshot(idempotency_worker.lease.worker_id)
            .await
            .unwrap()
            .reserved_calls,
        1
    );

    let claim_worker = register(&left, 1).await;
    left.create_call(create_request(
        new_call(tenant("race-claims")),
        claim_worker.lease,
        110,
        111,
    ))
    .await
    .unwrap();
    let left_claim = {
        let left = Arc::clone(&left);
        tokio::spawn(async move {
            left.claim_outbox(claim_worker.lease, at(20), Duration::from_secs(10), 1)
                .await
                .unwrap()
        })
    };
    let right_claim = {
        let right = Arc::clone(&right);
        tokio::spawn(async move {
            right
                .claim_outbox(claim_worker.lease, at(20), Duration::from_secs(10), 1)
                .await
                .unwrap()
        })
    };
    assert_eq!(
        left_claim.await.unwrap().len() + right_claim.await.unwrap().len(),
        1
    );
}

async fn two_calls_for_delta<R: CallRepository>(
    repository: &R,
) -> (TenantId, WorkerLease, StoredCall, StoredCall) {
    let worker = repository
        .register_worker(RegisterWorker {
            worker_id: WorkerId::new(),
            max_calls: 2,
            capabilities: BTreeSet::from(["sip".into(), "webrtc".into()]),
            at: at(0),
        })
        .await
        .unwrap();
    let owner = tenant("delta-owner");
    let changed = created(
        repository
            .create_call(create_request(
                new_call(owner.clone()),
                worker.lease,
                130,
                131,
            ))
            .await
            .unwrap(),
    );
    let untouched = created(
        repository
            .create_call(create_request(
                new_call(owner.clone()),
                worker.lease,
                132,
                133,
            ))
            .await
            .unwrap(),
    );
    (owner, worker.lease, changed, untouched)
}

async fn prepare_active_binding<R: CallRepository>(repository: &R) -> WorkerId {
    let worker = repository
        .register_worker(RegisterWorker {
            worker_id: WorkerId::new(),
            max_calls: 1,
            capabilities: BTreeSet::from(["sip".into()]),
            at: at(45),
        })
        .await
        .unwrap();
    let owner = tenant("column-drift-binding");
    let request = create_request(new_call(owner.clone()), worker.lease, 150, 151);
    let token_digest = request.attachments[0].token_digest;
    repository.create_call(request).await.unwrap();
    let candidate = repository
        .inspect_attachment(AttachmentLookup {
            token_digest,
            tenant_id: owner,
            transport: AttachmentTransport::Sip,
            principal_fingerprint: principal(),
            worker: worker.lease,
            at: at(46),
        })
        .await
        .unwrap();
    repository
        .consume_attachment(AttachmentConsume {
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at: at(47),
                leg_id: candidate.leg_id(),
                binding_generation: candidate.binding_generation(),
                state: LegState::Signaling,
                failure: None,
            },
            candidate,
            connection_id: ConnectionId::from_string("conn_column_drift_active"),
            principal_fingerprint: principal(),
            at: at(47),
        })
        .await
        .unwrap();
    worker.lease.worker_id
}

async fn advance_second_leg<R: CallRepository>(
    repository: &R,
    owner: &TenantId,
    worker: WorkerLease,
    call: &StoredCall,
) -> Result<CommandCommitOutcome, RepositoryError> {
    let leg = &call.aggregate.legs()[1];
    repository
        .commit_command(CommandCommit {
            tenant_id: owner.clone(),
            call_id: call.aggregate.id(),
            expected_version: call.aggregate.version(),
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at: at(3),
                leg_id: leg.id(),
                binding_generation: leg.binding_generation(),
                state: LegState::Signaling,
                failure: None,
            },
            worker,
            attachments: Vec::new(),
            deadline_claim: None,
            at: at(3),
        })
        .await
}

async fn exercise_expired_idempotency<R: CallRepository>(repository: &R) {
    let worker = repository
        .register_worker(RegisterWorker {
            worker_id: WorkerId::new(),
            max_calls: 3,
            capabilities: BTreeSet::from(["sip".into()]),
            at: at(90),
        })
        .await
        .unwrap();
    let owner = tenant("expired-idempotency");
    for (key, request) in [(220, 221), (221, 222)] {
        repository
            .create_call(create_request_at(
                new_call(owner.clone()),
                worker.lease,
                key,
                request,
                at(100),
            ))
            .await
            .unwrap();
    }
    repository
        .create_call(create_request_at(
            new_call(owner),
            worker.lease,
            222,
            223,
            at(100 + 24 * 60 * 60 + 1),
        ))
        .await
        .unwrap();
}

async fn sqlite_idempotency_count(repository: &SqliteRepository, tenant: &str) -> i64 {
    sqlx::query("SELECT COUNT(*) AS count FROM idempotency WHERE tenant_id = ?")
        .bind(tenant)
        .fetch_one(repository.pool())
        .await
        .unwrap()
        .get("count")
}

async fn postgres_idempotency_count(repository: &PostgresRepository, tenant: &str) -> i64 {
    sqlx::query("SELECT COUNT(*) AS count FROM idempotency WHERE tenant_id = $1")
        .bind(tenant)
        .fetch_one(repository.pool())
        .await
        .unwrap()
        .get("count")
}

struct ReadProbe {
    owner: TenantId,
    worker: WorkerLease,
    call: StoredCall,
    attachment_digest: AttachmentTokenDigest,
}

async fn prepare_read_probe<R: CallRepository>(repository: &R) -> ReadProbe {
    let worker = repository
        .register_worker(RegisterWorker {
            worker_id: WorkerId::new(),
            max_calls: 1,
            capabilities: BTreeSet::from(["sip".into()]),
            at: at(-10),
        })
        .await
        .unwrap();
    let owner = tenant("read-probe");
    let request = create_request(new_call(owner.clone()), worker.lease, 200, 201);
    let attachment_digest = request.attachments[0].token_digest;
    let call = created(repository.create_call(request).await.unwrap());
    ReadProbe {
        owner,
        worker: worker.lease,
        call,
        attachment_digest,
    }
}

async fn exercise_read_probe<R: CallRepository>(repository: &R, probe: &ReadProbe) {
    assert_eq!(
        repository
            .worker_snapshot(probe.worker.worker_id)
            .await
            .unwrap()
            .lease,
        probe.worker
    );
    assert_eq!(
        repository
            .load_call(&probe.owner, probe.call.aggregate.id())
            .await
            .unwrap(),
        probe.call
    );
    assert_eq!(
        repository
            .inspect_attachment(AttachmentLookup {
                token_digest: probe.attachment_digest,
                tenant_id: probe.owner.clone(),
                transport: AttachmentTransport::Sip,
                principal_fingerprint: principal(),
                worker: probe.worker,
                at: at(3),
            })
            .await
            .unwrap()
            .call_id(),
        probe.call.aggregate.id()
    );
}

async fn sqlite_epoch(repository: &SqliteRepository) -> i64 {
    sqlx::query("SELECT epoch FROM repository_metadata WHERE singleton = 1")
        .fetch_one(repository.pool())
        .await
        .unwrap()
        .get("epoch")
}

async fn postgres_epoch(repository: &PostgresRepository) -> i64 {
    sqlx::query("SELECT epoch FROM repository_metadata WHERE singleton = TRUE")
        .fetch_one(repository.pool())
        .await
        .unwrap()
        .get("epoch")
}

const REQUIRED_TABLES: &[&str] = &[
    "attachments",
    "call_execution_plans",
    "calls",
    "commands",
    "connection_bindings",
    "control_commands",
    "control_outbox",
    "control_outbox_retirements",
    "control_sequences",
    "deadlines",
    "external_references",
    "idempotency",
    "legs",
    "outbox",
    "outbound_binding_results",
    "provider_completions",
    "provider_events",
    "provider_references",
    "retired_operation_claims",
    "reconciliation_results",
    "repository_metadata",
    "service_command_results",
    "service_effect_payloads",
    "used_connection_ids",
    "worker_assignments",
    "workers",
];

async fn assert_required_sqlite_tables(repository: &SqliteRepository) {
    let rows = sqlx::query(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '_sqlx_%' ORDER BY name",
    )
    .fetch_all(repository.pool())
    .await
    .unwrap();
    let actual = rows
        .into_iter()
        .map(|row| row.get::<String, _>("name"))
        .collect::<HashSet<_>>();
    for required in REQUIRED_TABLES {
        assert!(
            actual.contains(*required),
            "missing SQLite table {required}"
        );
    }
    let foreign_key_violations = sqlx::query("PRAGMA foreign_key_check")
        .fetch_all(repository.pool())
        .await
        .unwrap();
    assert!(foreign_key_violations.is_empty());
    let migrations = sqlx::query("SELECT version, success FROM _sqlx_migrations ORDER BY version")
        .fetch_all(repository.pool())
        .await
        .unwrap();
    assert_eq!(migrations.len(), 3);
    assert_eq!(migrations[0].get::<i64, _>("version"), 1);
    assert!(migrations[0].get::<bool, _>("success"));
    assert_eq!(migrations[1].get::<i64, _>("version"), 2);
    assert!(migrations[1].get::<bool, _>("success"));
    assert_eq!(migrations[2].get::<i64, _>("version"), 3);
    assert!(migrations[2].get::<bool, _>("success"));
    assert_eq!(
        sqlx::query("SELECT schema_version FROM repository_metadata WHERE singleton = 1")
            .fetch_one(repository.pool())
            .await
            .unwrap()
            .get::<i64, _>("schema_version"),
        3
    );
}

async fn assert_required_postgres_tables(repository: &PostgresRepository) {
    let rows = sqlx::query(
        "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = current_schema()",
    )
    .fetch_all(repository.pool())
    .await
    .unwrap();
    let actual = rows
        .into_iter()
        .map(|row| row.get::<String, _>("tablename"))
        .collect::<HashSet<_>>();
    for required in REQUIRED_TABLES {
        assert!(
            actual.contains(*required),
            "missing PostgreSQL table {required}"
        );
    }
    let migrations = sqlx::query("SELECT version, success FROM _sqlx_migrations ORDER BY version")
        .fetch_all(repository.pool())
        .await
        .unwrap();
    assert_eq!(migrations.len(), 3);
    assert_eq!(migrations[0].get::<i64, _>("version"), 1);
    assert!(migrations[0].get::<bool, _>("success"));
    assert_eq!(migrations[1].get::<i64, _>("version"), 2);
    assert!(migrations[1].get::<bool, _>("success"));
    assert_eq!(migrations[2].get::<i64, _>("version"), 3);
    assert!(migrations[2].get::<bool, _>("success"));
    assert_eq!(
        sqlx::query("SELECT schema_version FROM repository_metadata WHERE singleton = TRUE")
            .fetch_one(repository.pool())
            .await
            .unwrap()
            .get::<i64, _>("schema_version"),
        3
    );
}

fn postgres_test_url() -> Option<String> {
    std::env::var("BRIDGEFU_TEST_POSTGRES_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
}

async fn reset_postgres(repository: &PostgresRepository) {
    sqlx::query(
        "TRUNCATE TABLE provider_completions, deadlines, outbox, provider_events, provider_references, attachments, idempotency, commands, connection_bindings, worker_assignments, legs, calls, used_connection_ids, workers CASCADE",
    )
    .execute(repository.pool())
    .await
    .unwrap();
    sqlx::query(
        "UPDATE repository_metadata SET epoch = 0, provider_receipt_sequence = NULL WHERE singleton = TRUE",
    )
    .execute(repository.pool())
    .await
    .unwrap();
}
