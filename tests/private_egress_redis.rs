use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bridgefu::call_engine::{
    BindingGeneration, CallId, LegId, TenantId, WorkerFence, WorkerId, WorkerLease,
};
use bridgefu::private_egress::{
    PrivateEgressCommand, PrivateEgressCommandClaim, PrivateEgressCommandService,
    PrivateEgressError, PrivateEgressGatewayEpoch, PrivateEgressHandler,
    PrivateEgressHandlerResult, PrivateEgressLifecycleEvent, PrivateEgressLifecycleState,
    PrivateEgressResponse, PrivateEgressRouteAuthority, PrivateEgressRouteKey,
    PrivateEgressServiceConfig, PrivateEgressSource, PrivateEgressStateStore, PrivateEgressTarget,
    RedisPrivateEgressStateConfig, RedisPrivateEgressStateStore,
};
use uuid::Uuid;

fn source() -> PrivateEgressSource {
    PrivateEgressSource {
        tenant_id: TenantId::parse("redis-private-egress-tenant").unwrap(),
        call_id: CallId::new(),
        leg_id: LegId::new(),
        binding_generation: BindingGeneration::INITIAL,
    }
}

fn route(
    source: &PrivateEgressSource,
    target_generation: BindingGeneration,
) -> PrivateEgressRouteKey {
    PrivateEgressRouteKey::new(
        WorkerLease {
            worker_id: WorkerId::new(),
            fence: WorkerFence::INITIAL,
        },
        source,
        PrivateEgressTarget {
            leg_id: LegId::new(),
            binding_generation: target_generation,
        },
    )
}

fn epoch(gateway_id: &str) -> PrivateEgressGatewayEpoch {
    PrivateEgressGatewayEpoch::new(gateway_id, Uuid::new_v4()).unwrap()
}

async fn store(
    redis_url: String,
    prefix: String,
    entry_ttl: Duration,
) -> Arc<RedisPrivateEgressStateStore> {
    let mut config = RedisPrivateEgressStateConfig::new(redis_url, prefix);
    config.entry_ttl = entry_ttl;
    config.operation_timeout = Duration::from_secs(2);
    config.max_entries = 64;
    RedisPrivateEgressStateStore::connect(config)
        .await
        .expect("connect disposable Redis private-egress store")
}

#[tokio::test]
#[ignore = "requires BRIDGEFU_TEST_REDIS_URL pointing at disposable Redis 7.2+"]
async fn redis_private_egress_fences_epochs_and_atomically_journals_progress() {
    let redis_url =
        std::env::var("BRIDGEFU_TEST_REDIS_URL").expect("BRIDGEFU_TEST_REDIS_URL is required");
    let prefix = format!("private-egress-test-{}", Uuid::new_v4());
    let store = store(redis_url, prefix, Duration::from_secs(60)).await;
    assert!(store.is_durable());

    let first = epoch("redis-gateway-a");
    assert!(store.begin_epoch(&first, 0).await.unwrap().is_empty());
    let command_id = Uuid::new_v4();
    let digest = [0x41; 32];
    assert_eq!(
        store
            .claim_command(&first, command_id, digest, 0)
            .await
            .unwrap(),
        PrivateEgressCommandClaim::Acquired
    );
    assert_eq!(
        store
            .claim_command(&first, command_id, digest, i64::MAX)
            .await
            .unwrap(),
        PrivateEgressCommandClaim::InFlight,
        "Redis server time, not the caller clock, owns expiry"
    );
    let response = PrivateEgressResponse {
        version: 1,
        command_id,
        accepted: true,
        replayed: false,
        state: Some(PrivateEgressLifecycleState::Prepared),
        failure_code: None,
        external_reference: None,
    };
    store
        .complete_command(&first, command_id, digest, &response, 0)
        .await
        .unwrap();
    assert_eq!(
        store
            .claim_command(&first, command_id, digest, 0)
            .await
            .unwrap(),
        PrivateEgressCommandClaim::Completed(response)
    );

    let source = source();
    let route = route(&source, BindingGeneration::INITIAL);
    let prepare = Uuid::new_v4();
    store
        .claim_route_transition(
            &first,
            &route,
            prepare,
            None,
            PrivateEgressLifecycleState::Prepared,
        )
        .await
        .unwrap();
    store
        .complete_route_transition(
            &first,
            &route,
            prepare,
            PrivateEgressLifecycleState::Prepared,
            0,
        )
        .await
        .unwrap();
    let activate = Uuid::new_v4();
    store
        .claim_route_transition(
            &first,
            &route,
            activate,
            Some(PrivateEgressLifecycleState::Prepared),
            PrivateEgressLifecycleState::Active,
        )
        .await
        .unwrap();
    let progress = PrivateEgressLifecycleEvent::progress(
        route.worker,
        route.authority().source,
        route.target,
        183,
        true,
    )
    .unwrap();
    let foreign_progress = PrivateEgressLifecycleEvent::progress(
        route.worker,
        PrivateEgressSource {
            binding_generation: source.binding_generation.next().unwrap(),
            ..source.clone()
        },
        route.target,
        183,
        true,
    )
    .unwrap();
    assert_eq!(
        store
            .append_lifecycle(&first, &route, &foreign_progress, 0)
            .await,
        Err(PrivateEgressError::OwnershipMismatch)
    );
    let progress = store
        .append_lifecycle(&first, &route, &progress, i64::MAX)
        .await
        .unwrap();
    assert_eq!(progress.sequence, 1);
    assert_eq!(progress.progress_details(), Some((183, true)));
    store
        .complete_route_transition(
            &first,
            &route,
            activate,
            PrivateEgressLifecycleState::Active,
            0,
        )
        .await
        .unwrap();
    assert_eq!(
        store.unacked_lifecycle(&first, &route).await.unwrap(),
        vec![progress.clone()]
    );
    store
        .ack_lifecycle(&first, &route, progress.event_id, progress.sequence)
        .await
        .unwrap();
    store
        .ack_lifecycle(&first, &route, progress.event_id, progress.sequence)
        .await
        .expect("exact duplicate ACK is idempotent");

    let second = epoch("redis-gateway-a");
    let recovered = store.begin_epoch(&second, 0).await.unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].dead_epoch, first.instance_id);
    assert_eq!(recovered[0].key, route);
    assert!(
        matches!(
            store
                .claim_command(&second, command_id, digest, 0)
                .await
                .unwrap(),
            PrivateEgressCommandClaim::Completed(PrivateEgressResponse {
                accepted: false,
                failure_code: Some(code),
                ..
            }) if code == PrivateEgressError::DeadEpoch.code()
        ),
        "a completed Prepare response from the fenced epoch must never be replayed as accepted"
    );
    assert_eq!(
        store
            .claim_command(&second, command_id, [0x42; 32], 0)
            .await,
        Err(PrivateEgressError::ReplayConflict),
        "epoch fencing retains the original digest"
    );
    assert_eq!(
        store.assert_epoch(&first).await,
        Err(PrivateEgressError::DeadEpoch)
    );
    assert!(store
        .unacked_lifecycle(&second, &route)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(store.begin_epoch(&second, 0).await.unwrap(), recovered);
    store
        .complete_route_recovery(&second, &route)
        .await
        .unwrap();
    assert!(store.begin_epoch(&second, 0).await.unwrap().is_empty());

    let independent = epoch("redis-gateway-b");
    assert!(store.begin_epoch(&independent, 0).await.unwrap().is_empty());
    store.assert_epoch(&second).await.unwrap();
    store.assert_epoch(&independent).await.unwrap();
}

#[tokio::test]
#[ignore = "requires BRIDGEFU_TEST_REDIS_URL pointing at disposable Redis 7.2+"]
async fn redis_epoch_and_live_route_outlive_completed_record_ttl() {
    let redis_url =
        std::env::var("BRIDGEFU_TEST_REDIS_URL").expect("BRIDGEFU_TEST_REDIS_URL is required");
    let prefix = format!("private-egress-idle-test-{}", Uuid::new_v4());
    let store = store(redis_url, prefix, Duration::from_millis(100)).await;
    let epoch = epoch("redis-idle-gateway");
    store.begin_epoch(&epoch, 0).await.unwrap();
    let command_id = Uuid::new_v4();
    let digest = [0x52; 32];
    assert_eq!(
        store
            .claim_command(&epoch, command_id, digest, 0)
            .await
            .unwrap(),
        PrivateEgressCommandClaim::Acquired
    );
    store
        .complete_command(
            &epoch,
            command_id,
            digest,
            &PrivateEgressResponse {
                version: 1,
                command_id,
                accepted: true,
                replayed: false,
                state: Some(PrivateEgressLifecycleState::Prepared),
                failure_code: None,
                external_reference: None,
            },
            0,
        )
        .await
        .unwrap();
    let source = source();
    let route = route(&source, BindingGeneration::INITIAL);
    let prepare = Uuid::new_v4();
    store
        .claim_route_transition(
            &epoch,
            &route,
            prepare,
            None,
            PrivateEgressLifecycleState::Prepared,
        )
        .await
        .unwrap();
    store
        .complete_route_transition(
            &epoch,
            &route,
            prepare,
            PrivateEgressLifecycleState::Prepared,
            0,
        )
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(250)).await;
    store
        .assert_epoch(&epoch)
        .await
        .expect("active gateway epoch is persistent and fenced only by begin_epoch");
    assert_eq!(
        store
            .claim_command(&epoch, command_id, digest, 0)
            .await
            .unwrap(),
        PrivateEgressCommandClaim::Acquired,
        "completed replay records expire individually"
    );
    let activate = Uuid::new_v4();
    store
        .claim_route_transition(
            &epoch,
            &route,
            activate,
            Some(PrivateEgressLifecycleState::Prepared),
            PrivateEgressLifecycleState::Active,
        )
        .await
        .expect("record expiry must never remove a quiet live route");
}

#[derive(Default)]
struct RecoveryOnlyHandler {
    executes: AtomicUsize,
    recoveries: AtomicUsize,
}

#[async_trait]
impl PrivateEgressHandler for RecoveryOnlyHandler {
    async fn execute(
        &self,
        _authority: &PrivateEgressRouteAuthority,
        _command: &PrivateEgressCommand,
    ) -> Result<PrivateEgressHandlerResult, PrivateEgressError> {
        self.executes.fetch_add(1, Ordering::SeqCst);
        Ok(PrivateEgressHandlerResult::default())
    }

    async fn recover_dead_epoch_route(
        &self,
        _authority: &PrivateEgressRouteAuthority,
        _target: PrivateEgressTarget,
        _dead_epoch: Uuid,
    ) -> Result<(), PrivateEgressError> {
        self.recoveries.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires BRIDGEFU_TEST_REDIS_URL pointing at disposable Redis 7.2+"]
async fn redis_service_recovers_dead_routes_without_redialing_them() {
    let redis_url =
        std::env::var("BRIDGEFU_TEST_REDIS_URL").expect("BRIDGEFU_TEST_REDIS_URL is required");
    let prefix = format!("private-egress-recovery-test-{}", Uuid::new_v4());
    let store = store(redis_url, prefix, Duration::from_secs(60)).await;
    let first = epoch("redis-recovery-gateway");
    store.begin_epoch(&first, 0).await.unwrap();
    let source = source();
    let route = route(&source, BindingGeneration::INITIAL);
    let prepare = Uuid::new_v4();
    store
        .claim_route_transition(
            &first,
            &route,
            prepare,
            None,
            PrivateEgressLifecycleState::Prepared,
        )
        .await
        .unwrap();
    store
        .complete_route_transition(
            &first,
            &route,
            prepare,
            PrivateEgressLifecycleState::Prepared,
            0,
        )
        .await
        .unwrap();

    let handler = Arc::new(RecoveryOnlyHandler::default());
    let handler_trait: Arc<dyn PrivateEgressHandler> = handler.clone();
    let state_trait: Arc<dyn PrivateEgressStateStore> = store;
    let _service = PrivateEgressCommandService::new_with_state_store(
        handler_trait,
        PrivateEgressServiceConfig {
            max_active_routes: 8,
            max_replay_entries: 64,
            replay_ttl: Duration::from_secs(120),
            operation_timeout: Duration::from_secs(2),
        },
        epoch("redis-recovery-gateway"),
        state_trait,
    )
    .await
    .expect("dead route cleanup is acknowledged during service startup");

    assert_eq!(handler.recoveries.load(Ordering::SeqCst), 1);
    assert_eq!(
        handler.executes.load(Ordering::SeqCst),
        0,
        "recovery must never reconstruct or redial an old destination"
    );
}
