use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use bridgefu::broadcast::{
    BroadcastCommandError, BroadcastCommandRepository, BroadcastCommandResult,
    BroadcastOperationIdentity, DurableBroadcastRuntime, DurableBroadcastSpec,
    DurableBroadcastState, DurableBroadcastTransport, MemoryBroadcastCommandRepository,
    PostgresBroadcastCommandRepository, SqliteBroadcastCommandRepository,
};
use bridgefu::call_engine::{
    BindingGeneration, CallAggregate, CallCommand, CallRepository, CommandId, CreateCall,
    IdempotencyKeyDigest, LegDirection, LegKind, LegSpec, RegisterWorker, RequestDigest, TenantId,
    WorkerFence, WorkerId, WorkerLease,
};
use bridgefu::coordination::DeploymentId;
use bridgefu::persistence::{PostgresRepository, SqliteRepository};
use chrono::{TimeDelta, Utc};
use serde_json::json;
use uuid::Uuid;

static POSTGRES_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn identity(key: u8, request: u8) -> BroadcastOperationIdentity {
    BroadcastOperationIdentity {
        idempotency_digest: [key; 32],
        request_digest: [request; 32],
    }
}

fn runtime() -> DurableBroadcastRuntime {
    DurableBroadcastRuntime {
        endpoint: json!({"uri": "moqt://relay.example.test"}),
        protocol: json!({"transport": "draft-19", "msf": "draft-01", "loc": "draft-03"}),
        lifecycle: json!({"state": "active"}),
        health: json!({"status": "healthy"}),
        sanitized_events: false,
        grant_generation: None,
    }
}

fn runtime_with_generation(generation: Uuid) -> DurableBroadcastRuntime {
    let mut runtime = runtime();
    runtime.grant_generation = Some(generation);
    runtime
}

async fn run_two<T, L, R>(left: L, right: R) -> (T, T)
where
    T: Send + 'static,
    L: FnOnce(Arc<tokio::sync::Barrier>) -> tokio::task::JoinHandle<T>,
    R: FnOnce(Arc<tokio::sync::Barrier>) -> tokio::task::JoinHandle<T>,
{
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let left = left(Arc::clone(&barrier));
    let right = right(Arc::clone(&barrier));
    barrier.wait().await;
    (left.await.unwrap(), right.await.unwrap())
}

async fn concurrent_conformance(
    repository: Arc<dyn BroadcastCommandRepository>,
    specification: &DurableBroadcastSpec,
) {
    let worker = specification.worker;

    let mut first = specification.clone();
    first.broadcast_id = Uuid::new_v4().to_string();
    let mut second = specification.clone();
    second.broadcast_id = Uuid::new_v4().to_string();
    let left_repository = Arc::clone(&repository);
    let right_repository = Arc::clone(&repository);
    let left_specification = first.clone();
    let right_specification = second.clone();
    let (left, right) = run_two(
        move |barrier| {
            tokio::spawn(async move {
                barrier.wait().await;
                left_repository
                    .enqueue_start(left_specification, identity(100, 101), 1)
                    .await
            })
        },
        move |barrier| {
            tokio::spawn(async move {
                barrier.wait().await;
                right_repository
                    .enqueue_start(right_specification, identity(102, 103), 1)
                    .await
            })
        },
    )
    .await;
    assert_eq!(
        usize::from(left.is_ok()) + usize::from(right.is_ok()),
        1,
        "left={left:?} right={right:?}"
    );
    assert!(matches!(
        left.as_ref().err().or_else(|| right.as_ref().err()),
        Some(BroadcastCommandError::CapacityExceeded)
    ));
    repository
        .fail_worker_broadcasts(worker, "test_cleanup")
        .await
        .unwrap();

    let mut duplicate = specification.clone();
    duplicate.broadcast_id = Uuid::new_v4().to_string();
    let left_repository = Arc::clone(&repository);
    let right_repository = Arc::clone(&repository);
    let left_specification = duplicate.clone();
    let right_specification = duplicate;
    let (left, right) = run_two(
        move |barrier| {
            tokio::spawn(async move {
                barrier.wait().await;
                left_repository
                    .enqueue_start(left_specification, identity(104, 105), 1)
                    .await
            })
        },
        move |barrier| {
            tokio::spawn(async move {
                barrier.wait().await;
                right_repository
                    .enqueue_start(right_specification, identity(104, 105), 1)
                    .await
            })
        },
    )
    .await;
    let left = left.unwrap();
    let right = right.unwrap();
    assert_ne!(left.replayed, right.replayed);
    assert_eq!(left.record, right.record);
    repository
        .fail_worker_broadcasts(worker, "test_cleanup")
        .await
        .unwrap();

    let mut divergent_left = specification.clone();
    divergent_left.broadcast_id = Uuid::new_v4().to_string();
    let mut divergent_right = specification.clone();
    divergent_right.broadcast_id = Uuid::new_v4().to_string();
    let left_repository = Arc::clone(&repository);
    let right_repository = Arc::clone(&repository);
    let (left, right) = run_two(
        move |barrier| {
            tokio::spawn(async move {
                barrier.wait().await;
                left_repository
                    .enqueue_start(divergent_left, identity(106, 107), 1)
                    .await
            })
        },
        move |barrier| {
            tokio::spawn(async move {
                barrier.wait().await;
                right_repository
                    .enqueue_start(divergent_right, identity(106, 108), 1)
                    .await
            })
        },
    )
    .await;
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert!(matches!(
        left.as_ref().err().or_else(|| right.as_ref().err()),
        Some(BroadcastCommandError::IdempotencyConflict)
    ));
    repository
        .fail_worker_broadcasts(worker, "test_cleanup")
        .await
        .unwrap();

    let mut stop_left = specification.clone();
    stop_left.broadcast_id = Uuid::new_v4().to_string();
    let mut stop_right = specification.clone();
    stop_right.broadcast_id = Uuid::new_v4().to_string();
    repository
        .enqueue_start(stop_left.clone(), identity(109, 110), 2)
        .await
        .unwrap();
    repository
        .enqueue_start(stop_right.clone(), identity(111, 112), 2)
        .await
        .unwrap();
    for claim in repository
        .claim(worker, Duration::from_secs(30), 8)
        .await
        .unwrap()
    {
        repository
            .complete(&claim, BroadcastCommandResult::Started(Box::new(runtime())))
            .await
            .unwrap();
    }
    let left_repository = Arc::clone(&repository);
    let right_repository = Arc::clone(&repository);
    let tenant = specification.tenant_id.clone();
    let other_tenant = tenant.clone();
    let left_id = stop_left.broadcast_id;
    let right_id = stop_right.broadcast_id;
    let (left, right) = run_two(
        move |barrier| {
            tokio::spawn(async move {
                barrier.wait().await;
                left_repository
                    .enqueue_stop(&tenant, &left_id, identity(113, 114))
                    .await
            })
        },
        move |barrier| {
            tokio::spawn(async move {
                barrier.wait().await;
                right_repository
                    .enqueue_stop(&other_tenant, &right_id, identity(113, 115))
                    .await
            })
        },
    )
    .await;
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert!(matches!(
        left.as_ref().err().or_else(|| right.as_ref().err()),
        Some(BroadcastCommandError::IdempotencyConflict)
    ));
    repository
        .fail_worker_broadcasts(worker, "test_cleanup")
        .await
        .unwrap();
}

async fn conformance(
    repository: Arc<dyn BroadcastCommandRepository>,
    specification: DurableBroadcastSpec,
) {
    concurrent_conformance(Arc::clone(&repository), &specification).await;
    let tenant = specification.tenant_id.clone();
    let worker = specification.worker;
    let first = repository
        .enqueue_start(specification.clone(), identity(1, 2), 1)
        .await
        .unwrap();
    assert!(!first.replayed);
    assert_eq!(first.record.state, DurableBroadcastState::Pending);

    let replay = repository
        .enqueue_start(specification.clone(), identity(1, 2), 1)
        .await
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.record, first.record);
    assert_eq!(
        repository
            .enqueue_start(specification.clone(), identity(1, 3), 1)
            .await
            .unwrap_err(),
        BroadcastCommandError::IdempotencyConflict
    );
    let mut capacity = specification.clone();
    capacity.broadcast_id = Uuid::new_v4().to_string();
    assert_eq!(
        repository
            .enqueue_start(capacity, identity(4, 5), 1)
            .await
            .unwrap_err(),
        BroadcastCommandError::CapacityExceeded
    );
    assert!(repository
        .get(
            &TenantId::parse("other-tenant").unwrap(),
            &specification.broadcast_id
        )
        .await
        .unwrap()
        .is_none());
    let wrong_worker = WorkerLease {
        worker_id: WorkerId::new(),
        fence: WorkerFence::INITIAL,
    };
    assert!(repository
        .claim(wrong_worker, Duration::from_secs(30), 8)
        .await
        .unwrap()
        .is_empty());

    let start = repository
        .claim(worker, Duration::from_secs(30), 8)
        .await
        .unwrap();
    assert_eq!(start.len(), 1);
    let active = repository
        .complete(
            &start[0],
            BroadcastCommandResult::Started(Box::new(runtime())),
        )
        .await
        .unwrap();
    assert_eq!(active.state, DurableBroadcastState::Active);
    assert_eq!(active.runtime, Some(runtime()));
    assert_eq!(
        repository
            .complete(
                &start[0],
                BroadcastCommandResult::Started(Box::new(runtime())),
            )
            .await
            .unwrap_err(),
        BroadcastCommandError::StaleClaim
    );

    let delete = repository
        .enqueue_stop(&tenant, &specification.broadcast_id, identity(6, 7))
        .await
        .unwrap();
    assert_eq!(delete.record.state, DurableBroadcastState::Deleting);
    let delete_replay = repository
        .enqueue_stop(&tenant, &specification.broadcast_id, identity(6, 7))
        .await
        .unwrap();
    assert!(delete_replay.replayed);
    assert_eq!(
        repository
            .enqueue_stop(&tenant, &specification.broadcast_id, identity(6, 8),)
            .await
            .unwrap_err(),
        BroadcastCommandError::IdempotencyConflict
    );
    let stop = repository
        .claim(worker, Duration::from_secs(30), 8)
        .await
        .unwrap();
    assert_eq!(stop.len(), 1);
    let deleted = repository
        .complete(&stop[0], BroadcastCommandResult::Stopped)
        .await
        .unwrap();
    assert_eq!(deleted.state, DurableBroadcastState::Deleted);
    assert!(deleted.runtime.is_none());

    let mut expiring = specification.clone();
    expiring.broadcast_id = Uuid::new_v4().to_string();
    expiring.expires_at = Utc::now() + TimeDelta::milliseconds(75);
    repository
        .enqueue_start(expiring.clone(), identity(30, 31), 1)
        .await
        .unwrap();
    let expiry_claim = repository
        .claim(worker, Duration::from_secs(30), 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    repository
        .complete(
            &expiry_claim,
            BroadcastCommandResult::Started(Box::new(runtime())),
        )
        .await
        .unwrap();
    assert!(!repository
        .reconcile_terminal(
            &expiring.broadcast_id,
            worker,
            expiring.source_binding_generation,
            Some(Uuid::new_v4()),
            "broadcast_expired",
        )
        .await
        .unwrap());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(repository
        .reconcile_terminal(
            &expiring.broadcast_id,
            worker,
            expiring.source_binding_generation,
            None,
            "broadcast_expired",
        )
        .await
        .unwrap());
    let expired = repository
        .get(&tenant, &expiring.broadcast_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(expired.state, DurableBroadcastState::Failed);
    assert_eq!(expired.failure_code.as_deref(), Some("broadcast_expired"));
    assert!(expired.runtime.is_none());
    let mut recovered_capacity = specification.clone();
    recovered_capacity.broadcast_id = Uuid::new_v4().to_string();
    repository
        .enqueue_start(recovered_capacity, identity(32, 33), 1)
        .await
        .unwrap();
    repository
        .fail_worker_broadcasts(worker, "test_cleanup")
        .await
        .unwrap();

    let mut draining = specification.clone();
    draining.broadcast_id = Uuid::new_v4().to_string();
    repository
        .enqueue_start(draining.clone(), identity(34, 35), 1)
        .await
        .unwrap();
    let drain_claim = repository
        .claim(worker, Duration::from_secs(30), 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let drain_generation = Uuid::new_v4();
    repository
        .complete(
            &drain_claim,
            BroadcastCommandResult::Started(Box::new(runtime_with_generation(drain_generation))),
        )
        .await
        .unwrap();
    repository
        .enqueue_stop(&tenant, &draining.broadcast_id, identity(36, 37))
        .await
        .unwrap();
    repository
        .fail_worker_broadcasts(worker, "worker_drained")
        .await
        .unwrap();
    let retained = repository
        .get(&tenant, &draining.broadcast_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        retained.runtime,
        Some(runtime_with_generation(drain_generation))
    );
    assert!(!repository
        .finalize_failed_cleanup(&draining.broadcast_id, worker, Some(Uuid::new_v4()))
        .await
        .unwrap());
    assert!(repository
        .finalize_failed_cleanup(&draining.broadcast_id, worker, Some(drain_generation))
        .await
        .unwrap());
    assert!(repository
        .get(&tenant, &draining.broadcast_id)
        .await
        .unwrap()
        .unwrap()
        .runtime
        .is_none());
    let drained_delete = repository
        .enqueue_stop(&tenant, &draining.broadcast_id, identity(36, 37))
        .await
        .unwrap();
    assert!(drained_delete.replayed);
    assert_eq!(drained_delete.record.state, DurableBroadcastState::Deleted);

    // Simulate a process crash: no graceful `fail_worker_broadcasts` runs.
    // Registration advances the stable worker ID to a new fence; the startup
    // sweep must fail, not adopt, the old-fence publication.
    let mut crashed = specification.clone();
    crashed.broadcast_id = Uuid::new_v4().to_string();
    repository
        .enqueue_start(crashed.clone(), identity(20, 21), 1)
        .await
        .unwrap();
    let claim = repository
        .claim(worker, Duration::from_secs(30), 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    repository
        .complete(&claim, BroadcastCommandResult::Started(Box::new(runtime())))
        .await
        .unwrap();
    let replacement = WorkerLease {
        worker_id: worker.worker_id,
        fence: serde_json::from_str("2").unwrap(),
    };
    let stale = repository
        .fail_stale_worker_broadcasts(replacement)
        .await
        .unwrap();
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].state, DurableBroadcastState::Failed);
    assert_eq!(stale[0].failure_code.as_deref(), Some("stale_worker_fence"));
    // The internal runtime descriptor retains the exact grant generation so
    // crash cleanup can retry without ever revoking a replacement lease. The
    // public API hides runtime endpoints for failed rows.
    assert_eq!(stale[0].runtime, Some(runtime()));
    assert_eq!(
        repository
            .enqueue_stop(&tenant, &crashed.broadcast_id, identity(40, 41))
            .await
            .unwrap_err(),
        BroadcastCommandError::InvalidTransition
    );
    assert!(repository
        .finalize_failed_cleanup(&crashed.broadcast_id, worker, None)
        .await
        .unwrap());
    assert!(repository
        .fail_stale_worker_broadcasts(replacement)
        .await
        .unwrap()
        .is_empty());
    let cleaned_delete = repository
        .enqueue_stop(&tenant, &crashed.broadcast_id, identity(40, 41))
        .await
        .unwrap();
    assert_eq!(cleaned_delete.record.state, DurableBroadcastState::Deleted);
    assert!(repository
        .claim(worker, Duration::from_secs(30), 8)
        .await
        .unwrap()
        .is_empty());
    assert!(repository
        .claim(replacement, Duration::from_secs(30), 8)
        .await
        .unwrap()
        .is_empty());
}

fn ephemeral_spec() -> DurableBroadcastSpec {
    DurableBroadcastSpec {
        broadcast_id: Uuid::new_v4().to_string(),
        tenant_id: TenantId::parse("tenant-broadcast-conformance").unwrap(),
        call_id: Default::default(),
        source_leg_id: Default::default(),
        source_binding_generation: BindingGeneration::INITIAL,
        worker: WorkerLease {
            worker_id: WorkerId::new(),
            fence: WorkerFence::INITIAL,
        },
        transport: DurableBroadcastTransport::Moqt,
        language: Some("en".to_owned()),
        sanitized_events: false,
        expires_at: Utc::now() + TimeDelta::hours(1),
    }
}

#[tokio::test]
async fn memory_broadcast_command_repository_conforms() {
    conformance(MemoryBroadcastCommandRepository::new(), ephemeral_spec()).await;
}

async fn seed_sql_call<R: CallRepository + Sync>(repository: &R) -> DurableBroadcastSpec {
    let now = Utc::now();
    let tenant = TenantId::parse(format!("tenant-broadcast-{}", Uuid::new_v4())).unwrap();
    let worker = repository
        .register_worker(RegisterWorker {
            worker_id: WorkerId::new(),
            max_calls: 4,
            capabilities: BTreeSet::new(),
            at: now,
            lease_ttl: Duration::from_secs(300),
        })
        .await
        .unwrap()
        .lease;
    let aggregate = CallAggregate::new(
        tenant.clone(),
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
        now,
    );
    let call_id = aggregate.id();
    let source_leg_id = aggregate.legs()[0].id();
    repository
        .create_call(CreateCall {
            initial: aggregate,
            command_id: CommandId::new(),
            command: CallCommand::StartConnecting {
                at: now,
                setup_deadline: now + TimeDelta::seconds(30),
            },
            worker,
            idempotency_key: IdempotencyKeyDigest::new([10; 32]),
            request_digest: RequestDigest::new([11; 32]),
            attachments: Vec::new(),
            at: now,
        })
        .await
        .unwrap();
    DurableBroadcastSpec {
        broadcast_id: Uuid::new_v4().to_string(),
        tenant_id: tenant,
        call_id,
        source_leg_id,
        source_binding_generation: BindingGeneration::INITIAL,
        worker,
        transport: DurableBroadcastTransport::UctpQuic,
        language: None,
        sanitized_events: false,
        expires_at: now + TimeDelta::hours(1),
    }
}

#[tokio::test]
async fn sqlite_broadcast_command_repository_conforms() {
    let path = std::env::temp_dir().join(format!("bridgefu-broadcast-{}.sqlite", Uuid::new_v4()));
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let calls = SqliteRepository::connect(&url).await.unwrap();
    let specification = seed_sql_call(&calls).await;
    let repository = SqliteBroadcastCommandRepository::connect(
        url,
        DeploymentId::parse("broadcast-conformance").unwrap(),
    )
    .await
    .unwrap();
    conformance(repository, specification).await;
    drop(calls);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
#[ignore = "requires BRIDGEFU_TEST_POSTGRES_URL"]
async fn postgres_broadcast_command_repository_conforms() {
    let _guard = POSTGRES_LOCK.lock().await;
    let url = std::env::var("BRIDGEFU_TEST_POSTGRES_URL")
        .expect("BRIDGEFU_TEST_POSTGRES_URL must be set for ignored PostgreSQL conformance");
    let calls = PostgresRepository::connect(&url).await.unwrap();
    let specification = seed_sql_call(&calls).await;
    let repository = PostgresBroadcastCommandRepository::connect(
        url,
        DeploymentId::parse("broadcast-conformance").unwrap(),
    )
    .await
    .unwrap();
    conformance(repository.clone(), specification.clone()).await;

    sqlx::query("UPDATE workers SET draining = TRUE WHERE worker_id = $1")
        .bind(specification.worker.worker_id.as_uuid())
        .execute(calls.pool())
        .await
        .unwrap();
    let mut draining = specification.clone();
    draining.broadcast_id = Uuid::new_v4().to_string();
    assert_eq!(
        repository
            .enqueue_start(draining, identity(200, 201), 1)
            .await
            .unwrap_err(),
        BroadcastCommandError::InvalidTransition
    );

    sqlx::query(
        "UPDATE workers SET draining = FALSE, lease_expires_at = clock_timestamp() - interval '1 second' \
         WHERE worker_id = $1",
    )
    .bind(specification.worker.worker_id.as_uuid())
    .execute(calls.pool())
    .await
    .unwrap();
    let mut expired = specification;
    expired.broadcast_id = Uuid::new_v4().to_string();
    assert_eq!(
        repository
            .enqueue_start(expired, identity(202, 203), 1)
            .await
            .unwrap_err(),
        BroadcastCommandError::InvalidTransition
    );
}
