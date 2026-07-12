use std::collections::BTreeSet;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bridgefu::api_principal::ApiPrincipal;
use bridgefu::call_engine::{CallState, LegDirection, TenantId, WorkerId};
use bridgefu::call_service::{
    build_call_service_runtime, CallExecutionSupervisor, CallRepositoryBackendConfig,
    CallServiceCoordinationConfig, CallServiceRuntime, CallServiceRuntimeConfig, CallTimeoutPolicy,
    CreateCallInput, IdempotencyKey, LegEndpointConfig, RequestedLeg,
    SamePrincipalAttachmentResolver, SipEndpointConfig, SystemCallServiceClock,
    WebRtcEndpointConfig,
};
use bridgefu::coordination::DeploymentId;
use chrono::Utc;
use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod};
use rvoip_core::{
    config::Config as CoreConfig, IdentityAssurance, Jwk, OperationalEventStreamHealth,
    Orchestrator,
};

fn runtime_config(
    backend: CallRepositoryBackendConfig,
    worker_id: WorkerId,
) -> CallServiceRuntimeConfig {
    let mut coordination = CallServiceCoordinationConfig::new(
        DeploymentId::parse("execution-supervisor-test").unwrap(),
    );
    coordination.worker_lease_ttl = Duration::from_secs(300);
    coordination.worker_renew_interval = Duration::from_secs(100);
    CallServiceRuntimeConfig {
        backend,
        worker_id,
        max_calls: 8,
        worker_capabilities: BTreeSet::from(["sip".into(), "webrtc".into()]),
        control_key: vec![0x41; 32],
        timeouts: CallTimeoutPolicy {
            setup: Duration::from_secs(30),
            media_idle: Duration::from_secs(30),
            transfer: Duration::from_secs(30),
            ending: Duration::from_secs(30),
        },
        coordination,
    }
}

async fn runtime(
    backend: CallRepositoryBackendConfig,
    worker_id: WorkerId,
) -> Arc<CallServiceRuntime> {
    Arc::new(
        build_call_service_runtime(
            runtime_config(backend, worker_id),
            Arc::new(SamePrincipalAttachmentResolver),
            Arc::new(SystemCallServiceClock),
        )
        .await
        .unwrap(),
    )
}

fn principal() -> ApiPrincipal {
    ApiPrincipal::new(
        AuthenticatedPrincipal {
            subject: "execution-owner".into(),
            tenant: Some("execution-tenant".into()),
            scopes: vec!["*".into()],
            issuer: Some("execution-test".into()),
            expires_at: None,
            method: AuthenticationMethod::Jwt,
            assurance: IdentityAssurance::Pseudonymous {
                ephemeral_key: Jwk(serde_json::json!({"kty": "test"})),
            },
        },
        Utc::now(),
    )
    .unwrap()
}

fn two_inbound_legs() -> CreateCallInput {
    CreateCallInput {
        tenant_id: None,
        legs: [
            RequestedLeg {
                direction: LegDirection::Inbound,
                endpoint: LegEndpointConfig::Sip(SipEndpointConfig { uri: None }),
            },
            RequestedLeg {
                direction: LegDirection::Inbound,
                endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                    signaling_uri: None,
                }),
            },
        ],
    }
}

#[tokio::test]
async fn begin_drain_retains_authoritative_operational_receiver() {
    let worker_id = WorkerId::new();
    let runtime = runtime(CallRepositoryBackendConfig::Memory, worker_id).await;
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let supervisor = CallExecutionSupervisor::install(
        Arc::clone(&orchestrator),
        Arc::clone(&runtime),
        8,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(
        orchestrator.operational_event_stream_health(),
        OperationalEventStreamHealth::Healthy
    );

    supervisor.begin_drain();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        orchestrator.operational_event_stream_health(),
        OperationalEventStreamHealth::Healthy,
        "draining admission must not drop the correctness receiver"
    );

    supervisor.shutdown(Duration::from_secs(2)).await;
    drop(orchestrator);
    drop(runtime);
}

#[tokio::test]
async fn startup_recovery_finishes_old_fence_and_cleanup_before_returning() {
    let path = std::env::temp_dir().join(format!(
        "bridgefu-execution-supervisor-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let url = format!("sqlite://{}", path.display());
    let worker_id = WorkerId::from_str("00000000-0000-4000-8000-0000000000e6").unwrap();
    let first = runtime(
        CallRepositoryBackendConfig::Sqlite {
            database_url: url.clone(),
        },
        worker_id,
    )
    .await;
    let created = first
        .service()
        .create_call(
            &principal(),
            &IdempotencyKey::parse("execution-startup-recovery").unwrap(),
            two_inbound_legs(),
        )
        .await
        .unwrap();
    let call_id = created.value.call.call_id;
    let first_fence = first.worker().lease.fence;
    drop(first);

    let second = runtime(
        CallRepositoryBackendConfig::Sqlite { database_url: url },
        worker_id,
    )
    .await;
    assert!(second.worker().lease.fence > first_fence);
    let orchestrator = Orchestrator::new(CoreConfig::default());
    let supervisor = CallExecutionSupervisor::install(
        Arc::clone(&orchestrator),
        Arc::clone(&second),
        8,
        Duration::from_secs(5),
    )
    .await
    .unwrap();

    let tenant = TenantId::parse("execution-tenant").unwrap();
    let recovered = second
        .service_repository()
        .load_service_call(&tenant, call_id)
        .await
        .unwrap();
    assert!(matches!(
        recovered.call.aggregate.state(),
        CallState::Ended | CallState::Failed
    ));
    assert!(second
        .repository()
        .claim_outbox(
            second.worker().lease,
            Utc::now(),
            Duration::from_secs(60),
            64,
        )
        .await
        .unwrap()
        .is_empty());

    supervisor.shutdown(Duration::from_secs(2)).await;
    drop(orchestrator);
    drop(second);
    let _ = std::fs::remove_file(path);
}
