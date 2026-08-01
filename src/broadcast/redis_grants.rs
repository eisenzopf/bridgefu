//! Redis projection for active broadcast grants.
//!
//! A standalone MOQT relay cannot use the publisher process's in-memory grant
//! map. This projection carries only the minimum authorization state needed by
//! subscriber admission. Exact-generation deletion prevents a stale publisher
//! handle from revoking a replacement grant.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use redis::aio::ConnectionManager;
use rvoip_auth_core::AuthenticatedPrincipal;
use rvoip_moq::{
    MoqAction, MoqPeerIdentity, MoqPublisherPublicationAuthority,
    MoqPublisherPublicationAuthorityError, MoqPublisherPublicationGrant,
    MoqPublisherPublicationRequest, MoqResource, MoqRevocationChecker, MoqRevocationError,
    MoqRevocationStatus, MoqTokenBinding,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroize;

use super::token::{
    exact_subscriber_broadcast, validate_resource_id, ActiveBroadcastGrant,
    BroadcastGrantTransport, BroadcastGrantVerifier, BroadcastTokenError,
};

const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_RETRY_WINDOW: Duration = Duration::from_secs(30);
const MAX_NAMESPACE_BYTES: usize = 128;

const REGISTER_SCRIPT: &str = r#"
local clock = redis.call('TIME')
local now_ms = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local expires_ms = tonumber(ARGV[5])
if expires_ms <= now_ms then return -2 end
if redis.call('EXISTS', KEYS[1]) == 1 then return -1 end
redis.call('HSET', KEYS[1],
  'tenant', ARGV[1],
  'broadcast', ARGV[2],
  'transport', ARGV[3],
  'generation', ARGV[4],
  'expires_ms', ARGV[5])
redis.call('PEXPIREAT', KEYS[1], expires_ms)
return 1
"#;

const ACTIVE_SCRIPT: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 0 then return {} end
local clock = redis.call('TIME')
local now_ms = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local expires_ms = tonumber(redis.call('HGET', KEYS[1], 'expires_ms'))
if not expires_ms or expires_ms <= now_ms then
  redis.call('DEL', KEYS[1])
  return {}
end
return {
  redis.call('HGET', KEYS[1], 'tenant'),
  redis.call('HGET', KEYS[1], 'broadcast'),
  redis.call('HGET', KEYS[1], 'transport'),
  redis.call('HGET', KEYS[1], 'generation'),
  tostring(expires_ms)
}
"#;

const REVOKE_SCRIPT: &str = r#"
local generation = redis.call('HGET', KEYS[1], 'generation')
if not generation or generation ~= ARGV[1] then return 0 end
return redis.call('DEL', KEYS[1])
"#;

// A listener lease is keyed by the complete stable ownership tuple (issuer,
// tenant, subject), not the JWT replay ID. One refreshed credential therefore
// remains bound to the same physical listener while a second gateway cannot
// replay it, and equal subjects from distinct issuers cannot alias. The active
// grant and lease are checked and created in one Redis script so grant
// replacement cannot race admission.
const ACQUIRE_UCTP_LISTENER_SCRIPT: &str = r#"
local clock = redis.call('TIME')
local now_ms = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
if redis.call('EXISTS', KEYS[1]) == 0 then return {'-2'} end
local grant_expires = tonumber(redis.call('HGET', KEYS[1], 'expires_ms'))
local generation = redis.call('HGET', KEYS[1], 'generation')
if not grant_expires or not generation or grant_expires <= now_ms then
  redis.call('DEL', KEYS[1])
  return {'-2'}
end
if redis.call('HGET', KEYS[1], 'tenant') ~= ARGV[1]
  or redis.call('HGET', KEYS[1], 'broadcast') ~= ARGV[2]
  or redis.call('HGET', KEYS[1], 'transport') ~= 'uctp-quic' then
  return {'-2'}
end
local requested_expires = tonumber(ARGV[4])
if not requested_expires or requested_expires <= now_ms then return {'-3'} end
local expires_ms = math.min(requested_expires, grant_expires)
if redis.call('EXISTS', KEYS[2]) == 1 then return {'-1'} end
redis.call('HSET', KEYS[2],
  'tenant', ARGV[1],
  'broadcast', ARGV[2],
  'owner', ARGV[3],
  'generation', generation,
  'expires_ms', tostring(expires_ms))
redis.call('PEXPIREAT', KEYS[2], expires_ms)
return {'1', generation, tostring(expires_ms)}
"#;

const REVALIDATE_UCTP_LISTENER_SCRIPT: &str = r#"
local clock = redis.call('TIME')
local now_ms = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
if redis.call('EXISTS', KEYS[1]) == 0 or redis.call('EXISTS', KEYS[2]) == 0 then return 0 end
local grant_expires = tonumber(redis.call('HGET', KEYS[1], 'expires_ms'))
local lease_expires = tonumber(redis.call('HGET', KEYS[2], 'expires_ms'))
if not grant_expires or not lease_expires or grant_expires <= now_ms or lease_expires <= now_ms then
  return 0
end
if redis.call('HGET', KEYS[1], 'tenant') ~= ARGV[1]
  or redis.call('HGET', KEYS[1], 'broadcast') ~= ARGV[2]
  or redis.call('HGET', KEYS[1], 'transport') ~= 'uctp-quic'
  or redis.call('HGET', KEYS[1], 'generation') ~= ARGV[4]
  or redis.call('HGET', KEYS[2], 'tenant') ~= ARGV[1]
  or redis.call('HGET', KEYS[2], 'broadcast') ~= ARGV[2]
  or redis.call('HGET', KEYS[2], 'owner') ~= ARGV[3]
  or redis.call('HGET', KEYS[2], 'generation') ~= ARGV[4] then
  return 0
end
return 1
"#;

const RENEW_UCTP_LISTENER_SCRIPT: &str = r#"
local clock = redis.call('TIME')
local now_ms = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
if redis.call('EXISTS', KEYS[1]) == 0 or redis.call('EXISTS', KEYS[2]) == 0 then return -2 end
local grant_expires = tonumber(redis.call('HGET', KEYS[1], 'expires_ms'))
local lease_expires = tonumber(redis.call('HGET', KEYS[2], 'expires_ms'))
local requested_expires = tonumber(ARGV[5])
if not grant_expires or not lease_expires or not requested_expires
  or grant_expires <= now_ms or lease_expires <= now_ms or requested_expires <= now_ms then
  return -2
end
if redis.call('HGET', KEYS[1], 'tenant') ~= ARGV[1]
  or redis.call('HGET', KEYS[1], 'broadcast') ~= ARGV[2]
  or redis.call('HGET', KEYS[1], 'transport') ~= 'uctp-quic'
  or redis.call('HGET', KEYS[1], 'generation') ~= ARGV[4]
  or redis.call('HGET', KEYS[2], 'tenant') ~= ARGV[1]
  or redis.call('HGET', KEYS[2], 'broadcast') ~= ARGV[2]
  or redis.call('HGET', KEYS[2], 'owner') ~= ARGV[3]
  or redis.call('HGET', KEYS[2], 'generation') ~= ARGV[4] then
  return -2
end
local renewed_expires = math.min(requested_expires, grant_expires)
if renewed_expires < lease_expires then renewed_expires = lease_expires end
redis.call('HSET', KEYS[2], 'expires_ms', tostring(renewed_expires))
redis.call('PEXPIREAT', KEYS[2], renewed_expires)
return renewed_expires
"#;

const CLOSE_UCTP_LISTENER_SCRIPT: &str = r#"
if redis.call('HGET', KEYS[1], 'owner') ~= ARGV[1]
  or redis.call('HGET', KEYS[1], 'generation') ~= ARGV[2] then
  return 0
end
return redis.call('DEL', KEYS[1])
"#;

#[derive(Clone, Eq, PartialEq)]
pub struct RedisBroadcastGrantConfig {
    pub redis_url: String,
    pub namespace: String,
    pub operation_timeout: Duration,
    pub cleanup_retry_window: Duration,
}

impl RedisBroadcastGrantConfig {
    pub fn new(redis_url: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            redis_url: redis_url.into(),
            namespace: namespace.into(),
            operation_timeout: DEFAULT_OPERATION_TIMEOUT,
            cleanup_retry_window: DEFAULT_RETRY_WINDOW,
        }
    }
}

impl fmt::Debug for RedisBroadcastGrantConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisBroadcastGrantConfig")
            .field("redis_url", &"<redacted>")
            .field("namespace", &self.namespace)
            .field("operation_timeout", &self.operation_timeout)
            .field("cleanup_retry_window", &self.cleanup_retry_window)
            .finish()
    }
}

#[derive(Clone)]
pub struct RedisBroadcastGrantStore {
    manager: ConnectionManager,
    namespace_hex: String,
    operation_timeout: Duration,
    cleanup_retry_window: Duration,
}

impl fmt::Debug for RedisBroadcastGrantStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisBroadcastGrantStore")
            .field("namespace", &"<encoded>")
            .field("operation_timeout", &self.operation_timeout)
            .field("cleanup_retry_window", &self.cleanup_retry_window)
            .finish_non_exhaustive()
    }
}

impl RedisBroadcastGrantStore {
    pub async fn connect(
        mut config: RedisBroadcastGrantConfig,
    ) -> Result<Arc<Self>, BroadcastTokenError> {
        validate_config(&config)?;
        let client = redis::Client::open(config.redis_url.as_str());
        config.redis_url.zeroize();
        let client = client.map_err(|_| BroadcastTokenError::AuthorityUnavailable)?;
        let manager =
            tokio::time::timeout(config.operation_timeout, ConnectionManager::new(client))
                .await
                .map_err(|_| BroadcastTokenError::AuthorityUnavailable)?
                .map_err(|_| BroadcastTokenError::AuthorityUnavailable)?;
        let store = Arc::new(Self {
            manager,
            namespace_hex: hex_bytes(config.namespace.as_bytes()),
            operation_timeout: config.operation_timeout,
            cleanup_retry_window: config.cleanup_retry_window,
        });
        store.health_check().await?;
        Ok(store)
    }

    pub async fn register(
        self: &Arc<Self>,
        tenant_id: impl Into<String>,
        broadcast_id: impl Into<String>,
        transport: BroadcastGrantTransport,
        expires_at: DateTime<Utc>,
    ) -> Result<RedisBroadcastGrantLease, BroadcastTokenError> {
        let tenant_id = tenant_id.into();
        let broadcast_id = broadcast_id.into();
        validate_resource_id("tenant", &tenant_id)?;
        validate_resource_id("broadcast", &broadcast_id)?;
        if expires_at <= Utc::now() {
            return Err(BroadcastTokenError::Expired);
        }
        let generation = Uuid::new_v4();
        let key = self.key(&broadcast_id);
        let mut connection = self.manager.clone();
        let result: i64 = self
            .bounded(
                redis::Script::new(REGISTER_SCRIPT)
                    .key(key)
                    .arg(&tenant_id)
                    .arg(&broadcast_id)
                    .arg(transport_label(transport))
                    .arg(generation.to_string())
                    .arg(expires_at.timestamp_millis())
                    .invoke_async(&mut connection),
            )
            .await?;
        match result {
            1 => Ok(RedisBroadcastGrantLease {
                store: Arc::clone(self),
                broadcast_id,
                generation,
                expires_at,
                active: true,
            }),
            -1 => Err(BroadcastTokenError::Conflict),
            -2 => Err(BroadcastTokenError::Expired),
            _ => Err(BroadcastTokenError::AuthorityUnavailable),
        }
    }

    pub(crate) async fn active_grant(
        &self,
        broadcast_id: &str,
    ) -> Result<Option<ActiveBroadcastGrant>, BroadcastTokenError> {
        validate_resource_id("broadcast", broadcast_id)?;
        let mut connection = self.manager.clone();
        let values: Vec<String> = self
            .bounded(
                redis::Script::new(ACTIVE_SCRIPT)
                    .key(self.key(broadcast_id))
                    .invoke_async(&mut connection),
            )
            .await?;
        if values.is_empty() {
            return Ok(None);
        }
        if values.len() != 5 || values[1] != broadcast_id {
            return Err(BroadcastTokenError::AuthorityUnavailable);
        }
        let transport = match values[2].as_str() {
            "moqt" => BroadcastGrantTransport::Moqt,
            "uctp-quic" => BroadcastGrantTransport::UctpQuic,
            _ => return Err(BroadcastTokenError::AuthorityUnavailable),
        };
        let generation =
            Uuid::parse_str(&values[3]).map_err(|_| BroadcastTokenError::AuthorityUnavailable)?;
        let expires_millis = values[4]
            .parse::<i64>()
            .map_err(|_| BroadcastTokenError::AuthorityUnavailable)?;
        let expires_at = DateTime::from_timestamp_millis(expires_millis)
            .ok_or(BroadcastTokenError::AuthorityUnavailable)?;
        if expires_at <= Utc::now() {
            return Ok(None);
        }
        Ok(Some(ActiveBroadcastGrant {
            tenant_id: values[0].clone(),
            broadcast_id: values[1].clone(),
            transport,
            expires_at,
            generation,
        }))
    }

    pub(crate) async fn revoke_generation(
        &self,
        broadcast_id: &str,
        generation: Uuid,
    ) -> Result<bool, BroadcastTokenError> {
        validate_resource_id("broadcast", broadcast_id)?;
        let mut connection = self.manager.clone();
        let removed: i64 = self
            .bounded(
                redis::Script::new(REVOKE_SCRIPT)
                    .key(self.key(broadcast_id))
                    .arg(generation.to_string())
                    .invoke_async(&mut connection),
            )
            .await?;
        Ok(removed == 1)
    }

    pub async fn health_check(&self) -> Result<(), BroadcastTokenError> {
        let mut connection = self.manager.clone();
        let response: String = self
            .bounded(redis::cmd("PING").query_async(&mut connection))
            .await?;
        if response == "PONG" {
            Ok(())
        } else {
            Err(BroadcastTokenError::AuthorityUnavailable)
        }
    }

    /// Atomically bind one receive-only UCTP credential to one physical
    /// gateway connection while the exact UCTP grant generation is active.
    pub async fn acquire_uctp_listener(
        self: &Arc<Self>,
        principal: &AuthenticatedPrincipal,
        broadcast_id: &str,
        owner: impl Into<String>,
    ) -> Result<RedisUctpListenerLease, BroadcastTokenError> {
        validate_resource_id("broadcast", broadcast_id)?;
        let scoped_broadcast = exact_subscriber_broadcast(principal)
            .map_err(|_| BroadcastTokenError::OwnershipMismatch)?;
        if scoped_broadcast != broadcast_id || principal.is_expired() {
            return Err(BroadcastTokenError::OwnershipMismatch);
        }
        let tenant_id = principal
            .tenant
            .as_deref()
            .ok_or(BroadcastTokenError::OwnershipMismatch)?
            .to_owned();
        validate_resource_id("tenant", &tenant_id)?;
        let expires_at = principal.expires_at.ok_or(BroadcastTokenError::Expired)?;
        if expires_at <= Utc::now() {
            return Err(BroadcastTokenError::Expired);
        }
        let owner = owner.into();
        validate_listener_component(&owner)?;
        validate_listener_component(&principal.subject)?;
        if let Some(issuer) = principal.issuer.as_deref() {
            validate_listener_component(issuer)?;
        }
        let listener_key = self.listener_key(principal);
        let mut connection = self.manager.clone();
        let result: Vec<String> = self
            .bounded(
                redis::Script::new(ACQUIRE_UCTP_LISTENER_SCRIPT)
                    .key(self.key(broadcast_id))
                    .key(&listener_key)
                    .arg(&tenant_id)
                    .arg(broadcast_id)
                    .arg(&owner)
                    .arg(expires_at.timestamp_millis())
                    .invoke_async(&mut connection),
            )
            .await?;
        match result.first().map(String::as_str) {
            Some("1") if result.len() == 3 => {
                let generation = Uuid::parse_str(&result[1])
                    .map_err(|_| BroadcastTokenError::AuthorityUnavailable)?;
                let expires_at = result[2]
                    .parse::<i64>()
                    .ok()
                    .and_then(DateTime::from_timestamp_millis)
                    .ok_or(BroadcastTokenError::AuthorityUnavailable)?;
                Ok(RedisUctpListenerLease {
                    store: Arc::clone(self),
                    listener_key,
                    tenant_id,
                    broadcast_id: broadcast_id.to_owned(),
                    owner,
                    generation,
                    expires_at,
                    active: true,
                })
            }
            Some("-1") => Err(BroadcastTokenError::Conflict),
            Some("-3") => Err(BroadcastTokenError::Expired),
            Some("-2") => Err(BroadcastTokenError::Inactive),
            _ => Err(BroadcastTokenError::AuthorityUnavailable),
        }
    }

    async fn revalidate_uctp_listener(
        &self,
        lease: &RedisUctpListenerLease,
    ) -> Result<bool, BroadcastTokenError> {
        let mut connection = self.manager.clone();
        let active: i64 = self
            .bounded(
                redis::Script::new(REVALIDATE_UCTP_LISTENER_SCRIPT)
                    .key(self.key(&lease.broadcast_id))
                    .key(&lease.listener_key)
                    .arg(&lease.tenant_id)
                    .arg(&lease.broadcast_id)
                    .arg(&lease.owner)
                    .arg(lease.generation.to_string())
                    .invoke_async(&mut connection),
            )
            .await?;
        Ok(active == 1)
    }

    async fn renew_uctp_listener(
        &self,
        lease: &RedisUctpListenerLease,
        requested_expires_at: DateTime<Utc>,
    ) -> Result<Option<DateTime<Utc>>, BroadcastTokenError> {
        let mut connection = self.manager.clone();
        let expires_millis: i64 = self
            .bounded(
                redis::Script::new(RENEW_UCTP_LISTENER_SCRIPT)
                    .key(self.key(&lease.broadcast_id))
                    .key(&lease.listener_key)
                    .arg(&lease.tenant_id)
                    .arg(&lease.broadcast_id)
                    .arg(&lease.owner)
                    .arg(lease.generation.to_string())
                    .arg(requested_expires_at.timestamp_millis())
                    .invoke_async(&mut connection),
            )
            .await?;
        if expires_millis < 0 {
            return Ok(None);
        }
        DateTime::from_timestamp_millis(expires_millis)
            .map(Some)
            .ok_or(BroadcastTokenError::AuthorityUnavailable)
    }

    async fn close_uctp_listener(
        &self,
        listener_key: &str,
        owner: &str,
        generation: Uuid,
    ) -> Result<bool, BroadcastTokenError> {
        let mut connection = self.manager.clone();
        let removed: i64 = self
            .bounded(
                redis::Script::new(CLOSE_UCTP_LISTENER_SCRIPT)
                    .key(listener_key)
                    .arg(owner)
                    .arg(generation.to_string())
                    .invoke_async(&mut connection),
            )
            .await?;
        Ok(removed == 1)
    }

    fn key(&self, broadcast_id: &str) -> String {
        let digest = Sha256::digest(broadcast_id.as_bytes());
        format!(
            "bridgefu:moq:{}:broadcast-grant:{digest:x}",
            self.namespace_hex
        )
    }

    fn listener_key(&self, principal: &AuthenticatedPrincipal) -> String {
        let digest = listener_ownership_digest(principal);
        format!(
            "bridgefu:moq:{}:uctp-listener:{digest:x}",
            self.namespace_hex
        )
    }

    async fn bounded<T, F>(&self, future: F) -> Result<T, BroadcastTokenError>
    where
        F: std::future::Future<Output = redis::RedisResult<T>>,
    {
        tokio::time::timeout(self.operation_timeout, future)
            .await
            .map_err(|_| BroadcastTokenError::AuthorityUnavailable)?
            .map_err(|_| BroadcastTokenError::AuthorityUnavailable)
    }
}

/// Exact cluster-wide replay/ownership lease for one public UCTP listener.
pub struct RedisUctpListenerLease {
    store: Arc<RedisBroadcastGrantStore>,
    listener_key: String,
    tenant_id: String,
    broadcast_id: String,
    owner: String,
    generation: Uuid,
    expires_at: DateTime<Utc>,
    active: bool,
}

impl fmt::Debug for RedisUctpListenerLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisUctpListenerLease")
            .field("active", &self.active)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl RedisUctpListenerLease {
    pub async fn revalidate(&self) -> Result<bool, BroadcastTokenError> {
        if !self.active || self.expires_at <= Utc::now() {
            return Ok(false);
        }
        self.store.revalidate_uctp_listener(self).await
    }

    pub async fn renew(
        &mut self,
        principal: &AuthenticatedPrincipal,
    ) -> Result<bool, BroadcastTokenError> {
        if !self.active || principal.is_expired() {
            return Ok(false);
        }
        let broadcast_id = exact_subscriber_broadcast(principal)
            .map_err(|_| BroadcastTokenError::OwnershipMismatch)?;
        let same_owner = self.store.listener_key(principal) == self.listener_key;
        if broadcast_id != self.broadcast_id
            || principal.tenant.as_deref() != Some(self.tenant_id.as_str())
            || !same_owner
        {
            return Err(BroadcastTokenError::OwnershipMismatch);
        }
        let requested_expires_at = principal.expires_at.ok_or(BroadcastTokenError::Expired)?;
        let Some(expires_at) = self
            .store
            .renew_uctp_listener(self, requested_expires_at)
            .await?
        else {
            return Ok(false);
        };
        self.expires_at = expires_at;
        Ok(true)
    }

    pub async fn close(mut self) -> Result<bool, BroadcastTokenError> {
        let removed = self
            .store
            .close_uctp_listener(&self.listener_key, &self.owner, self.generation)
            .await?;
        self.active = false;
        Ok(removed)
    }
}

impl Drop for RedisUctpListenerLease {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let store = Arc::clone(&self.store);
        let listener_key = self.listener_key.clone();
        let owner = self.owner.clone();
        let generation = self.generation;
        let retry_until = std::cmp::min(
            self.expires_at,
            Utc::now()
                + chrono::Duration::from_std(store.cleanup_retry_window)
                    .unwrap_or_else(|_| chrono::Duration::zero()),
        );
        runtime.spawn(async move {
            loop {
                match store
                    .close_uctp_listener(&listener_key, &owner, generation)
                    .await
                {
                    Ok(_) => return,
                    Err(_) if Utc::now() < retry_until => {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    Err(_) => return,
                }
            }
        });
    }
}

#[async_trait]
impl BroadcastGrantVerifier for RedisBroadcastGrantStore {
    async fn active(
        &self,
        broadcast_id: &str,
    ) -> Result<Option<ActiveBroadcastGrant>, BroadcastTokenError> {
        self.active_grant(broadcast_id).await
    }

    async fn health_check(&self) -> Result<(), BroadcastTokenError> {
        RedisBroadcastGrantStore::health_check(self).await
    }
}

#[async_trait]
impl MoqPublisherPublicationAuthority for RedisBroadcastGrantStore {
    async fn active_publication(
        &self,
        request: &MoqPublisherPublicationRequest,
        now: DateTime<Utc>,
    ) -> Result<Option<MoqPublisherPublicationGrant>, MoqPublisherPublicationAuthorityError> {
        publisher_authority_result(
            request,
            self.active_grant(request.namespace().broadcast_id()).await,
            now,
        )
    }
}

/// Grant-level revocation policy rechecked by rvoip for an already admitted
/// MOQT session. Redis failure is an authorization dependency failure, never
/// an implicit allow.
#[derive(Clone, Debug)]
pub struct RedisBroadcastGrantRevocationChecker {
    store: Arc<RedisBroadcastGrantStore>,
}

impl RedisBroadcastGrantRevocationChecker {
    pub fn new(store: Arc<RedisBroadcastGrantStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl MoqRevocationChecker for RedisBroadcastGrantRevocationChecker {
    async fn check(
        &self,
        peer: &MoqPeerIdentity,
        _action: MoqAction,
        resource: &MoqResource,
        _binding: &MoqTokenBinding,
        _now: DateTime<Utc>,
    ) -> Result<MoqRevocationStatus, MoqRevocationError> {
        let grant = self
            .store
            .active_grant(resource.namespace().broadcast_id())
            .await
            .map_err(|_| {
                MoqRevocationError::Unavailable(
                    "broadcast grant authority is unavailable".to_owned(),
                )
            })?;
        Ok(match grant {
            Some(grant)
                if grant.transport == BroadcastGrantTransport::Moqt
                    && peer.tenant() == Some(grant.tenant_id.as_str())
                    && resource.namespace().tenant_id() == grant.tenant_id =>
            {
                MoqRevocationStatus::Active
            }
            _ => MoqRevocationStatus::Revoked,
        })
    }
}

pub struct RedisBroadcastGrantLease {
    store: Arc<RedisBroadcastGrantStore>,
    broadcast_id: String,
    generation: Uuid,
    expires_at: DateTime<Utc>,
    active: bool,
}

impl fmt::Debug for RedisBroadcastGrantLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisBroadcastGrantLease")
            .field("active", &self.active)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl RedisBroadcastGrantLease {
    pub async fn revoke(mut self) -> Result<bool, BroadcastTokenError> {
        let removed = self
            .store
            .revoke_generation(&self.broadcast_id, self.generation)
            .await?;
        self.active = false;
        Ok(removed)
    }
}

impl Drop for RedisBroadcastGrantLease {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let store = Arc::clone(&self.store);
        let broadcast_id = self.broadcast_id.clone();
        let generation = self.generation;
        let expires_at = self.expires_at;
        let retry_until = std::cmp::min(
            expires_at,
            Utc::now()
                + chrono::Duration::from_std(store.cleanup_retry_window)
                    .unwrap_or_else(|_| chrono::Duration::zero()),
        );
        runtime.spawn(async move {
            loop {
                match store.revoke_generation(&broadcast_id, generation).await {
                    Ok(_) => return,
                    Err(_) if Utc::now() < retry_until => {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    Err(_) => return,
                }
            }
        });
    }
}

fn validate_config(config: &RedisBroadcastGrantConfig) -> Result<(), BroadcastTokenError> {
    if config.namespace.is_empty()
        || config.namespace.len() > MAX_NAMESPACE_BYTES
        || config.namespace.chars().any(char::is_control)
        || config.operation_timeout.is_zero()
        || config.cleanup_retry_window.is_zero()
    {
        return Err(BroadcastTokenError::AuthorityUnavailable);
    }
    Ok(())
}

fn validate_listener_component(value: &str) -> Result<(), BroadcastTokenError> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        Err(BroadcastTokenError::Invalid)
    } else {
        Ok(())
    }
}

fn update_optional_component(digest: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            digest.update([1]);
            update_component(digest, value.as_bytes());
        }
        None => digest.update([0]),
    }
}

fn update_component(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn listener_ownership_digest(principal: &AuthenticatedPrincipal) -> sha2::digest::Output<Sha256> {
    let ownership = principal.ownership_key();
    let mut digest = Sha256::new();
    digest.update(b"bridgefu.redis.uctp-listener-ownership.v1\0");
    update_optional_component(&mut digest, ownership.issuer.as_deref());
    update_optional_component(&mut digest, ownership.tenant.as_deref());
    update_component(&mut digest, ownership.subject.as_bytes());
    digest.finalize()
}

#[cfg(test)]
mod listener_tests {
    use super::*;

    #[test]
    fn listener_ownership_key_includes_issuer_tenant_and_subject() {
        let mut principal = AuthenticatedPrincipal::anonymous();
        principal.subject = "same-subject".into();
        principal.issuer = Some("issuer-a".into());
        principal.tenant = Some("tenant-a".into());
        let baseline = listener_ownership_digest(&principal);

        let mut different_tenant = principal.clone();
        different_tenant.tenant = Some("tenant-b".into());
        assert_ne!(baseline, listener_ownership_digest(&different_tenant));

        let mut different_issuer = principal;
        different_issuer.issuer = Some("issuer-b".into());
        assert_ne!(baseline, listener_ownership_digest(&different_issuer));
    }
}

const fn transport_label(transport: BroadcastGrantTransport) -> &'static str {
    match transport {
        BroadcastGrantTransport::Moqt => "moqt",
        BroadcastGrantTransport::UctpQuic => "uctp-quic",
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn publisher_grant_for_request(
    request: &MoqPublisherPublicationRequest,
    grant: Option<&ActiveBroadcastGrant>,
    now: DateTime<Utc>,
) -> Result<Option<MoqPublisherPublicationGrant>, BroadcastTokenError> {
    let Some(grant) = grant else {
        return Ok(None);
    };
    if grant.transport != BroadcastGrantTransport::Moqt
        || grant.tenant_id != request.namespace().tenant_id()
        || grant.broadcast_id != request.namespace().broadcast_id()
        || grant.expires_at <= now
    {
        return Ok(None);
    }
    MoqPublisherPublicationGrant::new(grant.generation.to_string(), grant.expires_at)
        .map(Some)
        .map_err(|_| BroadcastTokenError::AuthorityUnavailable)
}

fn publisher_authority_result(
    request: &MoqPublisherPublicationRequest,
    grant: Result<Option<ActiveBroadcastGrant>, BroadcastTokenError>,
    now: DateTime<Utc>,
) -> Result<Option<MoqPublisherPublicationGrant>, MoqPublisherPublicationAuthorityError> {
    let grant = grant.map_err(|_| MoqPublisherPublicationAuthorityError::Unavailable)?;
    publisher_grant_for_request(request, grant.as_ref(), now)
        .map_err(|_| MoqPublisherPublicationAuthorityError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_and_debug_are_secret_safe() {
        let config =
            RedisBroadcastGrantConfig::new("rediss://user:secret@example.invalid", "deployment-a");
        let debug = format!("{config:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("user"));
        assert!(validate_config(&config).is_ok());

        let mut invalid = config;
        invalid.operation_timeout = Duration::ZERO;
        assert_eq!(
            validate_config(&invalid),
            Err(BroadcastTokenError::AuthorityUnavailable)
        );
    }

    #[test]
    fn publisher_authority_requires_exact_live_moqt_grant() {
        let now = Utc::now();
        let request = MoqPublisherPublicationRequest::new(
            [7_u8; 32],
            rvoip_moq::MoqNamespace::new("tenant-a", "broadcast-a").unwrap(),
        );
        let mut grant = ActiveBroadcastGrant {
            tenant_id: "tenant-a".into(),
            broadcast_id: "broadcast-a".into(),
            transport: BroadcastGrantTransport::Moqt,
            expires_at: now + chrono::Duration::minutes(1),
            generation: Uuid::new_v4(),
        };
        let admitted = publisher_grant_for_request(&request, Some(&grant), now)
            .unwrap()
            .expect("exact live grant must authorize");
        assert_eq!(admitted.fence(), grant.generation.to_string());

        grant.tenant_id = "tenant-b".into();
        assert!(publisher_grant_for_request(&request, Some(&grant), now)
            .unwrap()
            .is_none());
        grant.tenant_id = "tenant-a".into();
        grant.broadcast_id = "broadcast-b".into();
        assert!(publisher_grant_for_request(&request, Some(&grant), now)
            .unwrap()
            .is_none());
        grant.broadcast_id = "broadcast-a".into();
        grant.transport = BroadcastGrantTransport::UctpQuic;
        assert!(publisher_grant_for_request(&request, Some(&grant), now)
            .unwrap()
            .is_none());
        grant.transport = BroadcastGrantTransport::Moqt;
        grant.expires_at = now;
        assert!(publisher_grant_for_request(&request, Some(&grant), now)
            .unwrap()
            .is_none());

        assert_eq!(
            publisher_authority_result(
                &request,
                Err(BroadcastTokenError::AuthorityUnavailable),
                now,
            ),
            Err(MoqPublisherPublicationAuthorityError::Unavailable)
        );
        assert_eq!(
            publisher_authority_result(&request, Ok(None), now),
            Ok(None)
        );
    }
}
