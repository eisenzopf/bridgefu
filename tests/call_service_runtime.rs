use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bridgefu::api_principal::ApiPrincipal;
use bridgefu::call_engine::{
    AttachmentConsume, AttachmentLookup, AttachmentTokenDigest, BindingGeneration, CallCommand,
    CommandId, LegDirection, LegState, RepositoryError, TenantId, WorkerId,
};
use bridgefu::call_service::{
    build_call_service_runtime, AttachmentPrincipalRequest, AttachmentPrincipalResolver,
    AttachmentPrincipalResolverError, CallRepositoryBackendConfig, CallServiceClock,
    CallServiceError, CallServiceRuntime, CallServiceRuntimeConfig, CallTimeoutPolicy,
    CreateCallInput, IdempotencyKey, LegEndpointConfig, RequestedLeg,
    SamePrincipalAttachmentResolver, SipEndpointConfig, WebRtcEndpointConfig,
};
use chrono::{DateTime, TimeZone, Utc};
use rvoip_auth_core::{AuthenticatedPrincipal, AuthenticationMethod};
use rvoip_core::ids::ConnectionId;
use rvoip_core::{IdentityAssurance, Jwk};
use sha2::{Digest, Sha256};

fn at(second: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_940_000_000 + second, 0).unwrap()
}

#[derive(Debug)]
struct TestClock(Mutex<DateTime<Utc>>);

impl TestClock {
    fn new(now: DateTime<Utc>) -> Self {
        Self(Mutex::new(now))
    }

    fn set(&self, now: DateTime<Utc>) {
        *self.0.lock().unwrap() = now;
    }
}

impl CallServiceClock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

#[derive(Debug, Default)]
struct SwitchableResolver(AtomicBool);

impl SwitchableResolver {
    fn set_unavailable(&self, unavailable: bool) {
        self.0.store(unavailable, Ordering::SeqCst);
    }
}

#[async_trait]
impl AttachmentPrincipalResolver for SwitchableResolver {
    async fn resolve_principal(
        &self,
        request: AttachmentPrincipalRequest<'_>,
    ) -> Result<Option<bridgefu::call_engine::PrincipalFingerprint>, AttachmentPrincipalResolverError>
    {
        if self.0.load(Ordering::SeqCst) {
            Err(AttachmentPrincipalResolverError::Unavailable)
        } else {
            Ok(Some(request.api_principal))
        }
    }
}

fn principal() -> ApiPrincipal {
    ApiPrincipal::new(
        AuthenticatedPrincipal {
            subject: "runtime-subject".into(),
            tenant: Some("runtime-tenant".into()),
            scopes: vec!["*".into()],
            issuer: Some("runtime-test".into()),
            expires_at: None,
            method: AuthenticationMethod::Jwt,
            assurance: IdentityAssurance::Pseudonymous {
                ephemeral_key: Jwk(serde_json::json!({"kty": "test"})),
            },
        },
        at(0),
    )
    .unwrap()
}

fn input() -> CreateCallInput {
    CreateCallInput {
        tenant_id: None,
        legs: [
            RequestedLeg {
                direction: LegDirection::Inbound,
                endpoint: LegEndpointConfig::Sip(SipEndpointConfig { uri: None }),
            },
            RequestedLeg {
                direction: LegDirection::Outbound,
                endpoint: LegEndpointConfig::WebRtc(WebRtcEndpointConfig {
                    signaling_uri: Some("wss://runtime.example.test/session".into()),
                }),
            },
        ],
    }
}

fn token_digest(token: &str) -> AttachmentTokenDigest {
    let raw = URL_SAFE_NO_PAD.decode(token).unwrap();
    AttachmentTokenDigest::new(Sha256::digest(raw).into())
}

async fn build(
    backend: CallRepositoryBackendConfig,
    worker_id: WorkerId,
    clock: Arc<TestClock>,
    resolver: Arc<SwitchableResolver>,
) -> CallServiceRuntime {
    build_call_service_runtime(
        CallServiceRuntimeConfig {
            backend,
            worker_id,
            max_calls: 1,
            control_key: vec![0x74; 32],
            timeouts: CallTimeoutPolicy {
                setup: Duration::from_secs(30),
                transfer: Duration::from_secs(30),
                ending: Duration::from_secs(30),
            },
        },
        resolver,
        clock,
    )
    .await
    .unwrap()
}

async fn assert_consumed_expired_replay_and_capacity(
    backend: impl Fn() -> CallRepositoryBackendConfig,
    durable_restart: bool,
) {
    let worker_id = WorkerId::from_str("00000000-0000-4000-8000-000000000077").unwrap();
    let clock = Arc::new(TestClock::new(at(0)));
    let resolver = Arc::new(SwitchableResolver::default());
    let first = build(backend(), worker_id, clock.clone(), resolver.clone()).await;
    assert_eq!(first.worker().lease.fence.as_i64(), 1);
    assert_eq!(first.worker().reserved_calls, 0);

    let owner = principal();
    let key = IdempotencyKey::parse("runtime-exact-replay").unwrap();
    let created = first
        .service()
        .create_call(&owner, &key, input())
        .await
        .unwrap();
    let attachment = created.value.call.legs[0].attachment.as_ref().unwrap();
    let stored = first
        .service_repository()
        .load_service_call(
            &TenantId::parse("runtime-tenant").unwrap(),
            created.value.call.call_id,
        )
        .await
        .unwrap();
    assert_eq!(stored.attachments.len(), 1);
    let lookup = AttachmentLookup {
        token_digest: token_digest(&attachment.token),
        tenant_id: TenantId::parse("runtime-tenant").unwrap(),
        transport: attachment.transport,
        principal_fingerprint: stored.attachments[0].expected_principal,
        worker: first.worker().lease,
        at: at(1),
    };
    let candidate = first
        .repository()
        .inspect_attachment(lookup.clone())
        .await
        .unwrap();
    first
        .repository()
        .consume_attachment(AttachmentConsume {
            candidate,
            command_id: CommandId::new(),
            command: CallCommand::SetLegState {
                at: at(1),
                leg_id: created.value.call.legs[0].leg_id,
                binding_generation: BindingGeneration::INITIAL,
                state: LegState::Signaling,
                failure: None,
            },
            connection_id: ConnectionId::new(),
            principal_fingerprint: stored.attachments[0].expected_principal,
            at: at(1),
        })
        .await
        .unwrap();
    clock.set(at(121));
    assert_eq!(
        first
            .repository()
            .inspect_attachment(AttachmentLookup {
                at: at(121),
                ..lookup
            })
            .await
            .unwrap_err(),
        RepositoryError::AttachmentRejected
    );
    let original_fence = first.worker().lease.fence.as_i64();
    let runtime = if durable_restart {
        drop(first);
        let restarted = build(backend(), worker_id, clock.clone(), resolver.clone()).await;
        assert_eq!(restarted.worker().lease.fence.as_i64(), original_fence + 1);
        assert_eq!(restarted.worker().reserved_calls, 1);
        restarted
    } else {
        first
    };

    resolver.set_unavailable(true);
    let replayed = runtime
        .service()
        .create_call(&owner, &key, input())
        .await
        .unwrap();
    assert!(replayed.replayed);
    assert_eq!(replayed.value, created.value);
    assert!(
        replayed.value.call.legs[0]
            .attachment
            .as_ref()
            .unwrap()
            .expires_at
            < clock.now()
    );

    let unavailable = runtime
        .service()
        .create_call(
            &owner,
            &IdempotencyKey::parse("runtime-dependency-outage").unwrap(),
            input(),
        )
        .await;
    assert_eq!(unavailable, Err(CallServiceError::DependencyUnavailable));
    resolver.set_unavailable(false);
    let capacity = runtime
        .service()
        .create_call(
            &owner,
            &IdempotencyKey::parse("runtime-capacity").unwrap(),
            input(),
        )
        .await;
    assert_eq!(
        capacity,
        Err(CallServiceError::Repository(
            RepositoryError::CapacityExceeded
        ))
    );
    let worker = runtime
        .repository()
        .worker_snapshot(worker_id)
        .await
        .unwrap();
    assert_eq!(worker.reserved_calls, 1);
}

#[tokio::test]
async fn memory_runtime_replays_consumed_expired_tokens_without_leaks() {
    assert_consumed_expired_replay_and_capacity(|| CallRepositoryBackendConfig::Memory, false)
        .await;
}

#[tokio::test]
async fn sqlite_runtime_restart_preserves_exact_replay_fence_and_capacity() {
    let path = std::env::temp_dir().join(format!(
        "bridgefu-call-runtime-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let url = format!("sqlite://{}", path.display());
    assert_consumed_expired_replay_and_capacity(
        || CallRepositoryBackendConfig::Sqlite {
            database_url: url.clone(),
        },
        true,
    )
    .await;
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn requested_sqlite_outage_fails_closed_without_memory_fallback() {
    let private_url = format!(
        "sqlite://{}/missing/bridgefu.sqlite",
        std::env::temp_dir()
            .join(format!("bridgefu-no-parent-{}", uuid::Uuid::new_v4()))
            .display()
    );
    let config = CallServiceRuntimeConfig {
        backend: CallRepositoryBackendConfig::Sqlite {
            database_url: private_url.clone(),
        },
        worker_id: WorkerId::new(),
        max_calls: 1,
        control_key: vec![0x74; 32],
        timeouts: CallTimeoutPolicy::default(),
    };
    assert!(!format!("{config:?}").contains(&private_url));
    let error = build_call_service_runtime(
        config,
        Arc::new(SamePrincipalAttachmentResolver),
        Arc::new(TestClock::new(at(0))),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "transactional call repository unavailable"
    );
    assert!(!format!("{error:?}").contains(&private_url));
}

#[tokio::test]
async fn invalid_control_key_is_rejected_before_repository_mutation() {
    let path = std::env::temp_dir().join(format!(
        "bridgefu-invalid-key-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let error = build_call_service_runtime(
        CallServiceRuntimeConfig {
            backend: CallRepositoryBackendConfig::Sqlite {
                database_url: format!("sqlite://{}", path.display()),
            },
            worker_id: WorkerId::new(),
            max_calls: 1,
            control_key: vec![0x74; 31],
            timeouts: CallTimeoutPolicy::default(),
        },
        Arc::new(SamePrincipalAttachmentResolver),
        Arc::new(TestClock::new(at(0))),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "control HMAC key must contain 32 to 4096 bytes"
    );
    assert!(!path.exists());
}

#[tokio::test]
async fn postgres_runtime_restart_preserves_exact_replay_fence_and_capacity() {
    let Some(url) = std::env::var("BRIDGEFU_TEST_POSTGRES_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
    else {
        return;
    };
    let administration = sqlx::PgPool::connect(&url).await.unwrap();
    let schema = format!("bridgefu_runtime_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&administration)
        .await
        .unwrap();
    let mut scoped = url::Url::parse(&url).unwrap();
    scoped
        .query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"));
    let scoped = scoped.to_string();
    assert_consumed_expired_replay_and_capacity(
        || CallRepositoryBackendConfig::Postgres {
            database_url: scoped.clone(),
        },
        true,
    )
    .await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&administration)
        .await
        .unwrap();
    administration.close().await;
}
