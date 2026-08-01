use std::collections::BTreeSet;
use std::time::Duration;

use bridgefu::call_engine::{CallId, WorkerFence, WorkerId, WorkerLease};
use bridgefu::coordination::{
    CallRouteHint, CoordinationError, CoordinationEvent, CoordinationPayload,
    CoordinationProjection, DatabasePollReason, DeploymentId, ProjectionApplyOutcome,
    ProjectionSequence, RedisCoordinationConfig, RedisCoordinator, ReplayDigest, ReplayMarker,
    WakeupConsumer, WakeupPublisher, WakeupReason, WorkerCoordinationSnapshot,
    WorkerSelectionRequest,
};
use chrono::{TimeDelta, Utc};
use redis::streams::StreamPendingReply;
use uuid::Uuid;

fn fence(value: u64) -> WorkerFence {
    serde_json::from_value(serde_json::json!(value)).expect("valid fence")
}

fn sequence(value: i64) -> ProjectionSequence {
    ProjectionSequence::from_i64(value).expect("valid sequence")
}

fn event(deployment: &DeploymentId, value: i64, payload: CoordinationPayload) -> CoordinationEvent {
    event_at(deployment, value, payload, Utc::now())
}

fn event_at(
    deployment: &DeploymentId,
    value: i64,
    payload: CoordinationPayload,
    recorded_at: chrono::DateTime<Utc>,
) -> CoordinationEvent {
    CoordinationEvent {
        deployment: deployment.clone(),
        sequence: sequence(value),
        payload,
        recorded_at,
    }
}

#[tokio::test]
#[ignore = "requires BRIDGEFU_TEST_REDIS_URL pointing at Redis 7.2"]
async fn redis_72_projection_streams_and_database_fallback_are_conformant() {
    let url =
        std::env::var("BRIDGEFU_TEST_REDIS_URL").expect("BRIDGEFU_TEST_REDIS_URL is required");
    let deployment =
        DeploymentId::parse(format!("redis-{}", Uuid::new_v4().simple())).expect("deployment");
    assert_redis_72(&url).await;
    let config = RedisCoordinationConfig::new(&url, deployment.clone())
        .expect("config")
        .with_lease_tombstone_ttl(Duration::from_secs(5))
        .expect("tombstone policy")
        .with_projection_tombstone_ttl(Duration::from_secs(5))
        .expect("projection tombstone policy")
        .with_stream_policy(4, Duration::from_millis(250), Duration::from_millis(50))
        .expect("stream policy");
    let coordinator = RedisCoordinator::connect(config)
        .await
        .expect("Redis coordinator");
    let worker_id = WorkerId::from_uuid(Uuid::from_u128(100)).expect("worker");
    let now = Utc::now();
    let mut worker = WorkerCoordinationSnapshot {
        lease: WorkerLease {
            worker_id,
            fence: WorkerFence::INITIAL,
        },
        max_calls: 20,
        reserved_calls: 3,
        draining: false,
        capabilities: BTreeSet::from(["sip".to_owned(), "webrtc".to_owned()]),
        lease_expires_at: now + TimeDelta::milliseconds(100),
    };
    let first = event(&deployment, 1, CoordinationPayload::Worker(worker.clone()));
    assert_eq!(
        coordinator.apply(&first).await,
        Ok(ProjectionApplyOutcome::Applied)
    );
    assert_eq!(
        coordinator.apply(&first).await,
        Ok(ProjectionApplyOutcome::Duplicate)
    );
    let mut conflict = first.clone();
    if let CoordinationPayload::Worker(snapshot) = &mut conflict.payload {
        snapshot.reserved_calls = 4;
    }
    assert_eq!(
        coordinator.apply(&conflict).await,
        Err(CoordinationError::SequenceConflict)
    );
    worker.draining = true;
    assert_eq!(
        coordinator
            .apply(&event(
                &deployment,
                2,
                CoordinationPayload::Worker(worker.clone()),
            ))
            .await,
        Ok(ProjectionApplyOutcome::Applied)
    );
    worker.draining = false;
    assert_eq!(
        coordinator
            .apply(&event(
                &deployment,
                3,
                CoordinationPayload::Worker(worker.clone()),
            ))
            .await,
        Err(CoordinationError::DrainIsOneWay)
    );
    tokio::time::sleep(Duration::from_millis(150)).await;
    worker.lease_expires_at = Utc::now() + TimeDelta::seconds(5);
    assert_eq!(
        coordinator
            .apply(&event(
                &deployment,
                4,
                CoordinationPayload::Worker(worker.clone()),
            ))
            .await,
        Err(CoordinationError::LeaseExpired)
    );
    worker.lease.fence = fence(2);
    assert_eq!(
        coordinator
            .apply(&event(
                &deployment,
                5,
                CoordinationPayload::Worker(worker.clone()),
            ))
            .await,
        Ok(ProjectionApplyOutcome::Applied)
    );
    assert_eq!(
        coordinator
            .worker_hints(&WorkerSelectionRequest {
                required_capabilities: BTreeSet::from(["webrtc".to_owned()]),
                limit: 1,
            })
            .await
            .expect("hints"),
        vec![worker.clone()]
    );

    // A recovery projector may apply the t20 heartbeat at t40. Same-fence
    // validity is decided by authoritative event time, not Redis wall time.
    let delayed_worker_id = WorkerId::from_uuid(Uuid::from_u128(103)).expect("delayed worker");
    let delayed_t0 = Utc::now();
    let mut delayed_worker = WorkerCoordinationSnapshot {
        lease: WorkerLease {
            worker_id: delayed_worker_id,
            fence: WorkerFence::INITIAL,
        },
        max_calls: 5,
        reserved_calls: 0,
        draining: false,
        capabilities: BTreeSet::from(["sip".to_owned()]),
        lease_expires_at: delayed_t0 + TimeDelta::milliseconds(300),
    };
    coordinator
        .apply(&event_at(
            &deployment,
            11,
            CoordinationPayload::Worker(delayed_worker.clone()),
            delayed_t0,
        ))
        .await
        .expect("delayed initial worker");
    tokio::time::sleep(Duration::from_millis(400)).await;
    delayed_worker.lease_expires_at = delayed_t0 + TimeDelta::seconds(2);
    assert_eq!(
        coordinator
            .apply(&event_at(
                &deployment,
                12,
                CoordinationPayload::Worker(delayed_worker.clone()),
                delayed_t0 + TimeDelta::milliseconds(200),
            ))
            .await,
        Ok(ProjectionApplyOutcome::Applied)
    );

    let call_id = CallId::from_uuid(Uuid::from_u128(200)).expect("call");
    let route = CallRouteHint {
        call_id,
        worker: worker.lease,
        expires_at: Utc::now() + TimeDelta::seconds(3),
    };
    coordinator
        .apply(&event(
            &deployment,
            6,
            CoordinationPayload::Route(route.clone()),
        ))
        .await
        .expect("route projection");
    assert_eq!(coordinator.route_hint(call_id).await, Ok(Some(route)));
    let digest = ReplayDigest::new([0x33; 32]);
    coordinator
        .apply(&event(
            &deployment,
            7,
            CoordinationPayload::Replay(ReplayMarker {
                digest,
                expires_at: Utc::now() + TimeDelta::seconds(3),
            }),
        ))
        .await
        .expect("replay projection");
    assert_eq!(coordinator.replay_seen(digest).await, Ok(true));

    let above_lua_integer_precision = 9_007_199_254_740_992_i64;
    let reordered_call = CallId::from_uuid(Uuid::from_u128(201)).expect("reordered call");
    let reorder_t0 = Utc::now();
    let expired_newer_route = CallRouteHint {
        call_id: reordered_call,
        worker: worker.lease,
        expires_at: reorder_t0 + TimeDelta::milliseconds(50),
    };
    tokio::time::sleep(Duration::from_millis(75)).await;
    assert_eq!(
        coordinator
            .apply(&event_at(
                &deployment,
                above_lua_integer_precision + 1,
                CoordinationPayload::Route(expired_newer_route),
                reorder_t0,
            ))
            .await,
        Ok(ProjectionApplyOutcome::Applied)
    );
    assert_eq!(
        coordinator
            .apply(&event_at(
                &deployment,
                above_lua_integer_precision,
                CoordinationPayload::Route(CallRouteHint {
                    call_id: reordered_call,
                    worker: worker.lease,
                    expires_at: Utc::now() + TimeDelta::seconds(3),
                }),
                reorder_t0,
            ))
            .await,
        Ok(ProjectionApplyOutcome::Stale)
    );
    assert_eq!(coordinator.route_hint(reordered_call).await, Ok(None));

    assert_eq!(
        coordinator
            .apply(&event(
                &deployment,
                above_lua_integer_precision + 2,
                CoordinationPayload::RouteRemoved { call_id },
            ))
            .await,
        Ok(ProjectionApplyOutcome::Applied)
    );
    assert_eq!(
        coordinator
            .apply(&event(
                &deployment,
                above_lua_integer_precision + 1,
                CoordinationPayload::Route(CallRouteHint {
                    call_id,
                    worker: worker.lease,
                    expires_at: Utc::now() + TimeDelta::seconds(3),
                }),
            ))
            .await,
        Ok(ProjectionApplyOutcome::Stale)
    );
    assert_eq!(coordinator.route_hint(call_id).await, Ok(None));

    let reordered_digest = ReplayDigest::new([0x34; 32]);
    let replay_t0 = Utc::now();
    tokio::time::sleep(Duration::from_millis(75)).await;
    assert_eq!(
        coordinator
            .apply(&event_at(
                &deployment,
                above_lua_integer_precision + 1,
                CoordinationPayload::Replay(ReplayMarker {
                    digest: reordered_digest,
                    expires_at: replay_t0 + TimeDelta::milliseconds(50),
                }),
                replay_t0,
            ))
            .await,
        Ok(ProjectionApplyOutcome::Applied)
    );
    assert_eq!(
        coordinator
            .apply(&event_at(
                &deployment,
                above_lua_integer_precision,
                CoordinationPayload::Replay(ReplayMarker {
                    digest: reordered_digest,
                    expires_at: Utc::now() + TimeDelta::seconds(3),
                }),
                replay_t0,
            ))
            .await,
        Ok(ProjectionApplyOutcome::Stale)
    );
    assert_eq!(coordinator.replay_seen(reordered_digest).await, Ok(false));

    let precision_fence_worker =
        WorkerId::from_uuid(Uuid::from_u128(102)).expect("precision fence worker");
    let mut precision_fence_snapshot = worker.clone();
    precision_fence_snapshot.lease = WorkerLease {
        worker_id: precision_fence_worker,
        fence: fence(above_lua_integer_precision as u64),
    };
    coordinator
        .apply(&event(
            &deployment,
            8,
            CoordinationPayload::Worker(precision_fence_snapshot.clone()),
        ))
        .await
        .expect("first large fence");
    precision_fence_snapshot.lease.fence = fence((above_lua_integer_precision + 1) as u64);
    assert_eq!(
        coordinator
            .apply(&event(
                &deployment,
                9,
                CoordinationPayload::Worker(precision_fence_snapshot.clone()),
            ))
            .await,
        Ok(ProjectionApplyOutcome::Applied)
    );
    precision_fence_snapshot.lease.fence = fence(above_lua_integer_precision as u64);
    assert_eq!(
        coordinator
            .apply(&event(
                &deployment,
                10,
                CoordinationPayload::Worker(precision_fence_snapshot),
            ))
            .await,
        Err(CoordinationError::StaleFence)
    );

    let mut consumer_a = coordinator
        .wakeup_consumer(worker_id, "workers", "redis-a")
        .await
        .expect("consumer a");
    let mut consumer_b = coordinator
        .wakeup_consumer(worker_id, "workers", "redis-b")
        .await
        .expect("consumer b");
    coordinator
        .publish_wakeup(worker_id, sequence(10), WakeupReason::Effects)
        .await
        .expect("publish");
    let first_delivery = consumer_a.poll(1).await;
    assert_eq!(
        first_delivery.database_poll_reason,
        DatabasePollReason::Wakeup
    );
    assert_eq!(first_delivery.messages.len(), 1);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let reclaimed = consumer_b
        .auto_claim(Duration::from_millis(10), 1)
        .await
        .expect("auto claim");
    assert_eq!(reclaimed, first_delivery.messages);
    assert_eq!(
        consumer_b
            .acknowledge(&[reclaimed[0].entry_id.clone()])
            .await,
        Ok(1)
    );

    for value in 11..14 {
        coordinator
            .publish_wakeup(worker_id, sequence(value), WakeupReason::Controls)
            .await
            .expect("publish reclaim cursor entry");
    }
    let cursor_source = consumer_a.poll(3).await;
    assert_eq!(cursor_source.messages.len(), 3);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let first_cursor_claim = consumer_b
        .auto_claim(Duration::from_millis(10), 1)
        .await
        .expect("first cursor claim");
    let second_cursor_claim = consumer_b
        .auto_claim(Duration::from_millis(10), 1)
        .await
        .expect("second cursor claim");
    assert_eq!(first_cursor_claim.len(), 1);
    assert_eq!(second_cursor_claim.len(), 1);
    assert_ne!(
        first_cursor_claim[0].entry_id, second_cursor_claim[0].entry_id,
        "XAUTOCLAIM must continue from its persisted cursor"
    );
    consumer_b
        .acknowledge(&[
            first_cursor_claim[0].entry_id.clone(),
            second_cursor_claim[0].entry_id.clone(),
        ])
        .await
        .expect("ack cursor claims");

    let fallback = consumer_b.poll(1).await;
    assert!(fallback.messages.is_empty());
    assert_eq!(
        fallback.database_poll_reason,
        DatabasePollReason::IntervalElapsed
    );

    for value in 20..32 {
        coordinator
            .publish_wakeup(worker_id, sequence(value), WakeupReason::Assignment)
            .await
            .expect("bounded pending publish");
        let delivery = consumer_a.poll(1).await;
        assert_eq!(delivery.messages.len(), 1);
    }
    assert!(consumer_a.pending_entries() <= 4);
    assert!(
        consumer_a.pel_evictions() > 0 || consumer_a.deleted_pending_entries() > 0,
        "consumer must clean or evict stale pending hints"
    );

    for value in 40..60 {
        coordinator
            .publish_wakeup(worker_id, sequence(value), WakeupReason::Assignment)
            .await
            .expect("bounded publish");
    }
    let mut raw = redis::Client::open(url.as_str())
        .expect("client")
        .get_multiplexed_async_connection()
        .await
        .expect("connection");
    let stream_key = format!(
        "bridgefu:{{{}}}:coord:wakeup:{}",
        deployment.as_str(),
        worker_id
    );
    let length: usize = redis::cmd("XLEN")
        .arg(&stream_key)
        .query_async(&mut raw)
        .await
        .expect("stream length");
    assert!(length <= 4, "stream must be strictly bounded");
    let pending: StreamPendingReply = redis::cmd("XPENDING")
        .arg(&stream_key)
        .arg("workers")
        .query_async(&mut raw)
        .await
        .expect("pending summary");
    assert!(pending.count() <= 4, "PEL must be bounded with XLEN");

    let precision_worker = WorkerId::from_uuid(Uuid::from_u128(101)).expect("precision worker");
    let mut precision_consumer = coordinator
        .wakeup_consumer(precision_worker, "workers", "precision")
        .await
        .expect("precision consumer");
    coordinator
        .publish_wakeup(
            precision_worker,
            sequence(above_lua_integer_precision),
            WakeupReason::Effects,
        )
        .await
        .expect("first large sequence");
    coordinator
        .publish_wakeup(
            precision_worker,
            sequence(above_lua_integer_precision + 1),
            WakeupReason::Controls,
        )
        .await
        .expect("adjacent large sequence");
    let precision_messages = precision_consumer.poll(2).await.messages;
    assert_eq!(precision_messages.len(), 2);
    assert_eq!(
        precision_messages[1].sequence,
        sequence(above_lua_integer_precision + 1)
    );

    let recovery_worker = WorkerId::from_uuid(Uuid::from_u128(104)).expect("recovery worker");
    let mut recovery_consumer = coordinator
        .wakeup_consumer(recovery_worker, "recovery", "recovery-a")
        .await
        .expect("recovery consumer");
    coordinator
        .publish_wakeup(recovery_worker, sequence(1), WakeupReason::Effects)
        .await
        .expect("initial recovery wakeup");
    let initial_recovery = recovery_consumer.poll(1).await;
    assert_eq!(initial_recovery.messages.len(), 1);
    recovery_consumer
        .acknowledge(&[initial_recovery.messages[0].entry_id.clone()])
        .await
        .expect("ack recovery wakeup");

    // Idle expiry removes both Stream and group; the next poll recreates them
    // and still reaches the authoritative DB fallback interval.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let ttl_started = tokio::time::Instant::now();
    let after_ttl = recovery_consumer.poll(1).await;
    assert!(ttl_started.elapsed() >= Duration::from_millis(45));
    assert_eq!(
        after_ttl.database_poll_reason,
        DatabasePollReason::IntervalElapsed
    );
    coordinator
        .publish_wakeup(recovery_worker, sequence(2), WakeupReason::Controls)
        .await
        .expect("post-TTL wakeup");
    assert_eq!(recovery_consumer.poll(1).await.messages.len(), 1);

    let recovery_stream = format!(
        "bridgefu:{{{}}}:coord:wakeup:{}",
        deployment.as_str(),
        recovery_worker
    );
    let recovery_sequence = format!(
        "bridgefu:{{{}}}:coord:wakeup-seq:{}",
        deployment.as_str(),
        recovery_worker
    );
    let _: usize = redis::cmd("DEL")
        .arg(&[recovery_stream.as_str(), recovery_sequence.as_str()])
        .query_async(&mut raw)
        .await
        .expect("flush recovery stream");
    let after_flush = recovery_consumer.poll(1).await;
    assert_eq!(
        after_flush.database_poll_reason,
        DatabasePollReason::IntervalElapsed
    );
    coordinator
        .publish_wakeup(recovery_worker, sequence(3), WakeupReason::Assignment)
        .await
        .expect("post-flush wakeup");
    assert_eq!(recovery_consumer.poll(1).await.messages.len(), 1);

    // Kill every other normal client connection while preserving this test
    // controller. The first poll is paced DB fallback; the second uses a fresh
    // dedicated connection.
    let _: usize = redis::cmd("CLIENT")
        .arg("KILL")
        .arg("TYPE")
        .arg("normal")
        .arg("SKIPME")
        .arg("yes")
        .query_async(&mut raw)
        .await
        .expect("kill coordination connections");
    let outage_started = tokio::time::Instant::now();
    let outage = recovery_consumer.poll(1).await;
    assert!(outage_started.elapsed() >= Duration::from_millis(45));
    assert_eq!(
        outage.database_poll_reason,
        DatabasePollReason::CoordinationUnavailable
    );
    let mut published_after_outage = false;
    for _ in 0..10 {
        match coordinator
            .publish_wakeup(recovery_worker, sequence(4), WakeupReason::ProviderEvents)
            .await
        {
            Ok(()) => {
                published_after_outage = true;
                break;
            }
            Err(CoordinationError::Unavailable) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => panic!("unexpected publish error after outage: {error}"),
        }
    }
    assert!(
        published_after_outage,
        "publisher must reconnect after outage"
    );
    let recovered = recovery_consumer.poll(1).await;
    assert_eq!(recovered.database_poll_reason, DatabasePollReason::Wakeup);
    assert_eq!(recovered.messages.len(), 1);
    assert!(recovery_consumer.reconnects() >= 2);

    // Loss of every deployment key models a Redis restart without persistence.
    // Redis remains a hint layer: groups and sequences are recreated safely.
    cleanup_deployment(&mut raw, &deployment).await;
    coordinator
        .publish_wakeup(recovery_worker, sequence(1), WakeupReason::Deadlines)
        .await
        .expect("publish after state loss");
    let after_restart = recovery_consumer.poll(1).await;
    assert_eq!(
        after_restart.database_poll_reason,
        DatabasePollReason::Wakeup
    );
    assert_eq!(after_restart.messages.len(), 1);
    cleanup_deployment(&mut raw, &deployment).await;

    let default_deployment =
        DeploymentId::parse(format!("redis-default-{}", Uuid::new_v4().simple()))
            .expect("default deployment");
    let default_coordinator = RedisCoordinator::connect(
        RedisCoordinationConfig::new(&url, default_deployment.clone()).expect("default config"),
    )
    .await
    .expect("default coordinator");
    let default_worker = WorkerId::from_uuid(Uuid::from_u128(105)).expect("default worker");
    let mut default_consumer = default_coordinator
        .wakeup_consumer(default_worker, "default", "default-a")
        .await
        .expect("default consumer");
    let default_started = tokio::time::Instant::now();
    let default_fallback = default_consumer.poll(1).await;
    let default_elapsed = default_started.elapsed();
    assert!(
        default_elapsed >= Duration::from_millis(1_900)
            && default_elapsed < Duration::from_millis(2_750),
        "default fallback should be approximately two seconds, got {default_elapsed:?}"
    );
    assert_eq!(
        default_fallback.database_poll_reason,
        DatabasePollReason::IntervalElapsed
    );
    cleanup_deployment(&mut raw, &default_deployment).await;
}

async fn assert_redis_72(url: &str) {
    let client = redis::Client::open(url).expect("Redis URL");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let info: String = redis::cmd("INFO")
        .arg("server")
        .query_async(&mut connection)
        .await
        .expect("INFO server");
    let version = info
        .lines()
        .find_map(|line| line.strip_prefix("redis_version:"))
        .map(str::trim)
        .expect("redis_version");
    assert!(
        version.starts_with("7.2."),
        "integration suite requires Redis 7.2, got {version}"
    );
}

async fn cleanup_deployment(
    connection: &mut redis::aio::MultiplexedConnection,
    deployment: &DeploymentId,
) {
    let pattern = format!("bridgefu:{{{}}}:coord:*", deployment.as_str());
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(pattern)
        .query_async(connection)
        .await
        .expect("test key scan");
    if !keys.is_empty() {
        let _: usize = redis::cmd("DEL")
            .arg(keys)
            .query_async(connection)
            .await
            .expect("test cleanup");
    }
}
