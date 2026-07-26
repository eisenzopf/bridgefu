//! Redis-backed private-egress command, route, and lifecycle authority.
//!
//! Every gateway identity is placed in one Redis Cluster hash slot. Lua
//! scripts use Redis server time and atomically fence epochs, transition
//! routes, and append lifecycle records. Client wall-clock values supplied by
//! the compatibility trait are intentionally ignored. Hash keys remain
//! persistent: bounded scripts expire individual replay/tombstone/ACK records
//! so a quiet but active route cannot disappear when the replay TTL elapses.

use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use redis::aio::ConnectionManager;
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::private_egress::{
    PrivateEgressError, PrivateEgressLifecycleEvent, PrivateEgressLifecycleState,
    PrivateEgressResponse, PrivateEgressRouteAuthority,
};
use crate::private_egress_state::{
    PrivateEgressCommandClaim, PrivateEgressGatewayEpoch, PrivateEgressRecoveredRoute,
    PrivateEgressRouteKey, PrivateEgressStateStore,
};

const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_ENTRY_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const DEFAULT_MAX_ENTRIES: usize = 16_384;
const MAX_PREFIX_BYTES: usize = 128;
const MAX_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

const BEGIN_EPOCH_SCRIPT: &str = r#"
local clock = redis.call('TIME')
local now_ms = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local epoch = ARGV[1]
local ttl = tonumber(ARGV[2])

local commands = redis.call('HGETALL', KEYS[2])
for i = 1, #commands, 2 do
  local id = commands[i]
  local record = cjson.decode(commands[i + 1])
  if record.epoch ~= epoch then
    record.epoch = epoch
    record.response_json = cjson.encode({
      version = 1,
      command_id = id,
      accepted = false,
      replayed = false,
      state = cjson.null,
      failure_code = 'dead_epoch',
      external_reference = cjson.null
    })
    record.completed_at_ms = tostring(now_ms)
    record.expires_at_ms = tostring(now_ms + ttl)
    redis.call('HSET', KEYS[2], id, cjson.encode(record))
  elseif record.response_json ~= '' and tonumber(record.expires_at_ms) <= now_ms then
    redis.call('HDEL', KEYS[2], id)
  end
end

local routes = redis.call('HGETALL', KEYS[3])
local recovered = {}
for i = 1, #routes, 2 do
  local field = routes[i]
  local record = cjson.decode(routes[i + 1])
  local terminal = record.state == 'ended' or record.state == 'failed'
  if terminal and record.recovery_required ~= true
      and record.tombstoned_at_ms ~= ''
      and tonumber(record.expires_at_ms) <= now_ms then
    redis.call('HDEL', KEYS[3], field)
  else
    if record.epoch ~= epoch and (record.recovery_required == true
        or record.pending_command ~= '' or not terminal) then
      record.pending_command = ''
      record.pending_next = ''
      record.state = 'failed'
      record.tombstoned_at_ms = tostring(now_ms)
      record.recovery_required = true
      record.expires_at_ms = tostring(now_ms + ttl)
      redis.call('HSET', KEYS[3], field, cjson.encode(record))
    end
    if record.recovery_required == true then
      table.insert(recovered, record.epoch)
      table.insert(recovered, record.key_json)
    end
  end
end

local lifecycle = redis.call('HGETALL', KEYS[4])
for i = 1, #lifecycle, 2 do
  local id = lifecycle[i]
  local record = cjson.decode(lifecycle[i + 1])
  if record.epoch ~= epoch
      or (record.acked == true and tonumber(record.expires_at_ms) <= now_ms) then
    redis.call('HDEL', KEYS[4], id)
  end
end

redis.call('SET', KEYS[1], epoch)
for index = 2, 4 do
  if redis.call('EXISTS', KEYS[index]) == 1 then
    redis.call('PERSIST', KEYS[index])
  end
end
return recovered
"#;

const ASSERT_EPOCH_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
redis.call('PERSIST', KEYS[1])
for index = 2, 4 do
  if redis.call('EXISTS', KEYS[index]) == 1 then
    redis.call('PERSIST', KEYS[index])
  end
end
return 1
"#;

const COMPLETE_RECOVERY_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return -9 end
local value = redis.call('HGET', KEYS[2], ARGV[2])
if not value then return -1 end
local record = cjson.decode(value)
if record.recovery_required ~= true or record.state ~= 'failed'
    or record.tombstoned_at_ms == '' then return -3 end
local clock = redis.call('TIME')
local now_ms = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
record.recovery_required = false
record.expires_at_ms = tostring(now_ms + tonumber(ARGV[3]))
redis.call('HSET', KEYS[2], ARGV[2], cjson.encode(record))
redis.call('PERSIST', KEYS[1])
redis.call('PERSIST', KEYS[2])
return 1
"#;

const CLAIM_COMMAND_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return {'dead_epoch'} end
local clock = redis.call('TIME')
local now_ms = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local ttl = tonumber(ARGV[4])
local values = redis.call('HGETALL', KEYS[2])
for i = 1, #values, 2 do
  local record = cjson.decode(values[i + 1])
  if record.response_json ~= '' and tonumber(record.expires_at_ms) <= now_ms then
    redis.call('HDEL', KEYS[2], values[i])
  end
end
local value = redis.call('HGET', KEYS[2], ARGV[2])
if value then
  local record = cjson.decode(value)
  if record.digest ~= ARGV[3] then return {'replay_conflict'} end
  if record.response_json ~= '' then return {'completed', record.response_json} end
  return {'in_flight'}
end
if redis.call('HLEN', KEYS[2]) >= tonumber(ARGV[5]) then return {'capacity'} end
local record = {
  epoch = ARGV[1],
  digest = ARGV[3],
  response_json = '',
  created_at_ms = tostring(now_ms),
  completed_at_ms = '',
  expires_at_ms = tostring(now_ms + ttl)
}
redis.call('HSET', KEYS[2], ARGV[2], cjson.encode(record))
redis.call('PERSIST', KEYS[1])
redis.call('PERSIST', KEYS[2])
return {'acquired'}
"#;

const COMPLETE_COMMAND_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return -9 end
local value = redis.call('HGET', KEYS[2], ARGV[2])
if not value then return -1 end
local record = cjson.decode(value)
if record.epoch ~= ARGV[1] or record.digest ~= ARGV[3] then return -2 end
if record.response_json ~= '' then
  if record.response_json == ARGV[4] then return 1 else return -2 end
end
local clock = redis.call('TIME')
local now_ms = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local ttl = tonumber(ARGV[5])
record.response_json = ARGV[4]
record.completed_at_ms = tostring(now_ms)
record.expires_at_ms = tostring(now_ms + ttl)
redis.call('HSET', KEYS[2], ARGV[2], cjson.encode(record))
redis.call('PERSIST', KEYS[1])
redis.call('PERSIST', KEYS[2])
return 1
"#;

const CLAIM_ROUTE_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return -9 end
local clock = redis.call('TIME')
local now_ms = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local ttl = tonumber(ARGV[9])
local routes = redis.call('HGETALL', KEYS[2])
for i = 1, #routes, 2 do
  local record = cjson.decode(routes[i + 1])
  if record.recovery_required ~= true and record.tombstoned_at_ms ~= ''
      and tonumber(record.expires_at_ms) <= now_ms then
    redis.call('HDEL', KEYS[2], routes[i])
  end
end
local value = redis.call('HGET', KEYS[2], ARGV[2])
local record
if value then
  record = cjson.decode(value)
  if record.epoch ~= ARGV[1] or record.state ~= ARGV[4]
      or record.pending_command ~= '' or record.tombstoned_at_ms ~= ''
      or record.recovery_required == true then return -3 end
else
  if ARGV[4] ~= '' then return -3 end
  if redis.call('HLEN', KEYS[2]) >= tonumber(ARGV[8]) then return -4 end
  record = {
    epoch = ARGV[1],
    key_json = ARGV[6],
    source_digest = ARGV[7],
    state = '',
    pending_command = '',
    pending_next = '',
    next_sequence = 0,
    tombstoned_at_ms = '',
    recovery_required = false,
    expires_at_ms = tostring(now_ms + ttl)
  }
end
record.pending_command = ARGV[3]
record.pending_next = ARGV[5]
record.expires_at_ms = tostring(now_ms + ttl)
redis.call('HSET', KEYS[2], ARGV[2], cjson.encode(record))
redis.call('PERSIST', KEYS[1])
redis.call('PERSIST', KEYS[2])
return 1
"#;

const COMPLETE_ROUTE_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return -9 end
local value = redis.call('HGET', KEYS[2], ARGV[2])
if not value then return -3 end
local record = cjson.decode(value)
if record.epoch ~= ARGV[1] or record.pending_command ~= ARGV[3]
    or record.pending_next ~= ARGV[4] then return -3 end
local clock = redis.call('TIME')
local now_ms = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local ttl = tonumber(ARGV[5])
record.pending_command = ''
record.pending_next = ''
record.state = ARGV[4]
if ARGV[4] == 'ended' or ARGV[4] == 'failed' then
  record.tombstoned_at_ms = tostring(now_ms)
end
record.expires_at_ms = tostring(now_ms + ttl)
redis.call('HSET', KEYS[2], ARGV[2], cjson.encode(record))
redis.call('PERSIST', KEYS[1])
redis.call('PERSIST', KEYS[2])
return 1
"#;

const ABORT_ROUTE_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return -9 end
local value = redis.call('HGET', KEYS[2], ARGV[2])
if not value then return -3 end
local record = cjson.decode(value)
if record.epoch ~= ARGV[1] or record.pending_command ~= ARGV[3] then return -3 end
if record.state == '' then
  redis.call('HDEL', KEYS[2], ARGV[2])
else
  local clock = redis.call('TIME')
  local now_ms = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
  record.pending_command = ''
  record.pending_next = ''
  record.expires_at_ms = tostring(now_ms + tonumber(ARGV[4]))
  redis.call('HSET', KEYS[2], ARGV[2], cjson.encode(record))
  redis.call('PERSIST', KEYS[2])
end
redis.call('PERSIST', KEYS[1])
return 1
"#;

const FAIL_SOURCE_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return {'dead_epoch'} end
local clock = redis.call('TIME')
local now_ms = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local ttl = tonumber(ARGV[3])
local routes = redis.call('HGETALL', KEYS[2])
local failed = {'ok'}
for i = 1, #routes, 2 do
  local field = routes[i]
  local record = cjson.decode(routes[i + 1])
  local terminal = record.state == 'ended' or record.state == 'failed'
  if record.epoch == ARGV[1] and record.source_digest == ARGV[2]
      and (record.pending_command ~= '' or not terminal) then
    record.pending_command = ''
    record.pending_next = ''
    record.state = 'failed'
    record.tombstoned_at_ms = tostring(now_ms)
    record.recovery_required = false
    record.expires_at_ms = tostring(now_ms + ttl)
    redis.call('HSET', KEYS[2], field, cjson.encode(record))
    table.insert(failed, record.key_json)
  end
end
redis.call('PERSIST', KEYS[1])
if redis.call('EXISTS', KEYS[2]) == 1 then redis.call('PERSIST', KEYS[2]) end
return failed
"#;

const APPEND_LIFECYCLE_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return {'dead_epoch'} end
local clock = redis.call('TIME')
local now_ms = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local ttl = tonumber(ARGV[6])
local lifecycle = redis.call('HGETALL', KEYS[3])
for i = 1, #lifecycle, 2 do
  local record = cjson.decode(lifecycle[i + 1])
  if record.acked == true and tonumber(record.expires_at_ms) <= now_ms then
    redis.call('HDEL', KEYS[3], lifecycle[i])
  end
end
if redis.call('HEXISTS', KEYS[3], ARGV[3]) == 1 then return {'replay_conflict'} end
if redis.call('HLEN', KEYS[3]) >= tonumber(ARGV[7]) then return {'capacity'} end
local value = redis.call('HGET', KEYS[2], ARGV[2])
if not value then return {'invalid_transition'} end
local route = cjson.decode(value)
if route.epoch ~= ARGV[1] or route.recovery_required == true
    or route.tombstoned_at_ms ~= '' then return {'invalid_transition'} end
local event = cjson.decode(ARGV[4])
if tonumber(ARGV[5]) ~= 1 or tonumber(event.version) ~= 1 then
  return {'invalid_transition'}
end
if event.kind.kind == 'progress' then
  local pending_ok = route.pending_command == '' or route.pending_next == 'active'
  local status = tonumber(event.kind.status_code)
  if route.state ~= 'prepared' or not pending_ok or not status
      or status < 100 or status > 199 then return {'invalid_transition'} end
else
  if event.kind.kind ~= 'state' or route.pending_command ~= '' then
    return {'invalid_transition'}
  end
  local next = event.kind.state
  local allowed = false
  if route.state == 'prepared' then
    allowed = next == 'prepared' or next == 'active' or next == 'ended' or next == 'failed'
  elseif route.state == 'active' then
    allowed = next == 'active' or next == 'ended' or next == 'failed'
  end
  if not allowed then return {'invalid_transition'} end
  route.state = next
  if next == 'ended' or next == 'failed' then route.tombstoned_at_ms = tostring(now_ms) end
end
route.next_sequence = tonumber(route.next_sequence) + 1
route.expires_at_ms = tostring(now_ms + ttl)
event.gateway_epoch = ARGV[1]
event.sequence = route.next_sequence
local event_json = cjson.encode(event)
local record = {
  epoch = ARGV[1],
  route_field = ARGV[2],
  sequence = route.next_sequence,
  event_json = event_json,
  acked = false,
  expires_at_ms = tostring(now_ms + ttl)
}
redis.call('HSET', KEYS[2], ARGV[2], cjson.encode(route))
redis.call('HSET', KEYS[3], ARGV[3], cjson.encode(record))
redis.call('PERSIST', KEYS[1])
for index = 2, 3 do redis.call('PERSIST', KEYS[index]) end
return {'ok', event_json}
"#;

const ACK_LIFECYCLE_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return -9 end
local value = redis.call('HGET', KEYS[2], ARGV[3])
if not value then return -1 end
local record = cjson.decode(value)
if record.epoch ~= ARGV[1] or record.route_field ~= ARGV[2]
    or tonumber(record.sequence) ~= tonumber(ARGV[4]) then return -5 end
local clock = redis.call('TIME')
local now_ms = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local ttl = tonumber(ARGV[5])
record.acked = true
record.expires_at_ms = tostring(now_ms + ttl)
redis.call('HSET', KEYS[2], ARGV[3], cjson.encode(record))
redis.call('PERSIST', KEYS[1])
redis.call('PERSIST', KEYS[2])
return 1
"#;

const UNACKED_LIFECYCLE_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return {'dead_epoch'} end
local records = redis.call('HVALS', KEYS[2])
local result = {'ok'}
for i = 1, #records do
  local record = cjson.decode(records[i])
  if record.epoch == ARGV[1] and record.route_field == ARGV[2]
      and record.acked ~= true then
    table.insert(result, tostring(record.sequence))
    table.insert(result, record.event_json)
  end
end
redis.call('PERSIST', KEYS[1])
if redis.call('EXISTS', KEYS[2]) == 1 then redis.call('PERSIST', KEYS[2]) end
return result
"#;

/// Shared Redis configuration for one deployment's gateway state.
#[derive(Clone, Eq, PartialEq)]
pub struct RedisPrivateEgressStateConfig {
    /// Redis or Redis-compatible TLS URL. Debug output always redacts it.
    pub redis_url: String,
    /// Deployment namespace mixed into cluster-slot keys.
    pub prefix: String,
    /// Retention for completed commands, terminal routes, and acknowledged
    /// lifecycle records. Live, in-flight, unacknowledged, and
    /// recovery-required records never expire merely because they are quiet.
    pub entry_ttl: Duration,
    /// Hard deadline applied independently to connect, health, and each
    /// atomic script operation.
    pub operation_timeout: Duration,
    /// Independent upper bound for each command, route, and lifecycle hash.
    pub max_entries: usize,
}

impl RedisPrivateEgressStateConfig {
    #[must_use]
    pub fn new(redis_url: impl Into<String>, prefix: impl Into<String>) -> Self {
        Self {
            redis_url: redis_url.into(),
            prefix: prefix.into(),
            entry_ttl: DEFAULT_ENTRY_TTL,
            operation_timeout: DEFAULT_OPERATION_TIMEOUT,
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }
}

impl fmt::Debug for RedisPrivateEgressStateConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisPrivateEgressStateConfig")
            .field("redis_url", &"<redacted>")
            .field("prefix", &self.prefix)
            .field("entry_ttl", &self.entry_ttl)
            .field("operation_timeout", &self.operation_timeout)
            .field("max_entries", &self.max_entries)
            .finish()
    }
}

#[derive(Clone)]
pub struct RedisPrivateEgressStateStore {
    manager: ConnectionManager,
    prefix_hex: String,
    entry_ttl_ms: i64,
    operation_timeout: Duration,
    max_entries: usize,
}

impl fmt::Debug for RedisPrivateEgressStateStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisPrivateEgressStateStore")
            .field("prefix", &"<encoded>")
            .field("entry_ttl_ms", &self.entry_ttl_ms)
            .field("operation_timeout", &self.operation_timeout)
            .field("max_entries", &self.max_entries)
            .finish_non_exhaustive()
    }
}

impl RedisPrivateEgressStateStore {
    pub async fn connect(
        mut config: RedisPrivateEgressStateConfig,
    ) -> Result<Arc<Self>, PrivateEgressError> {
        validate_config(&config)?;
        let client = redis::Client::open(config.redis_url.as_str());
        config.redis_url.zeroize();
        let client = client.map_err(|_| PrivateEgressError::StateUnavailable)?;
        let manager =
            tokio::time::timeout(config.operation_timeout, ConnectionManager::new(client))
                .await
                .map_err(|_| PrivateEgressError::StateUnavailable)?
                .map_err(|_| PrivateEgressError::StateUnavailable)?;
        let store = Arc::new(Self {
            manager,
            prefix_hex: hex_bytes(config.prefix.as_bytes()),
            entry_ttl_ms: duration_ms(config.entry_ttl)?,
            operation_timeout: config.operation_timeout,
            max_entries: config.max_entries,
        });
        store.health_check().await?;
        Ok(store)
    }

    pub async fn health_check(&self) -> Result<(), PrivateEgressError> {
        let mut connection = self.manager.clone();
        let response: String = self
            .bounded(redis::cmd("PING").query_async(&mut connection))
            .await?;
        if response == "PONG" {
            Ok(())
        } else {
            Err(PrivateEgressError::StateUnavailable)
        }
    }

    async fn bounded<T, F>(&self, future: F) -> Result<T, PrivateEgressError>
    where
        F: Future<Output = redis::RedisResult<T>>,
    {
        tokio::time::timeout(self.operation_timeout, future)
            .await
            .map_err(|_| PrivateEgressError::StateUnavailable)?
            .map_err(|_| PrivateEgressError::StateUnavailable)
    }

    fn keys(&self, gateway_id: &str) -> RedisGatewayKeys {
        gateway_keys(&self.prefix_hex, gateway_id)
    }

    fn route_field(key: &PrivateEgressRouteKey) -> Result<String, PrivateEgressError> {
        digest_json(b"bridgefu.private-egress.route.v1\0", key)
    }

    fn source_digest(
        authority: &PrivateEgressRouteAuthority,
    ) -> Result<String, PrivateEgressError> {
        digest_json(
            b"bridgefu.private-egress.source.v1\0",
            &(authority.worker, &authority.source),
        )
    }
}

struct RedisGatewayKeys {
    epoch: String,
    commands: String,
    routes: String,
    lifecycle: String,
}

#[async_trait]
impl PrivateEgressStateStore for RedisPrivateEgressStateStore {
    fn is_durable(&self) -> bool {
        true
    }

    async fn begin_epoch(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        _at_ms: i64,
    ) -> Result<Vec<PrivateEgressRecoveredRoute>, PrivateEgressError> {
        let keys = self.keys(&epoch.gateway_id);
        let mut connection = self.manager.clone();
        let values: Vec<String> = self
            .bounded(
                redis::Script::new(BEGIN_EPOCH_SCRIPT)
                    .key(keys.epoch)
                    .key(keys.commands)
                    .key(keys.routes)
                    .key(keys.lifecycle)
                    .arg(epoch.instance_id.to_string())
                    .arg(self.entry_ttl_ms)
                    .invoke_async(&mut connection),
            )
            .await?;
        if values.len() % 2 != 0 {
            return Err(PrivateEgressError::StateUnavailable);
        }
        values
            .chunks_exact(2)
            .map(|pair| {
                Ok(PrivateEgressRecoveredRoute {
                    dead_epoch: Uuid::parse_str(&pair[0])
                        .map_err(|_| PrivateEgressError::StateUnavailable)?,
                    key: serde_json::from_str(&pair[1])
                        .map_err(|_| PrivateEgressError::StateUnavailable)?,
                })
            })
            .collect()
    }

    async fn assert_epoch(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
    ) -> Result<(), PrivateEgressError> {
        let keys = self.keys(&epoch.gateway_id);
        let mut connection = self.manager.clone();
        let active: i64 = self
            .bounded(
                redis::Script::new(ASSERT_EPOCH_SCRIPT)
                    .key(keys.epoch)
                    .key(keys.commands)
                    .key(keys.routes)
                    .key(keys.lifecycle)
                    .arg(epoch.instance_id.to_string())
                    .invoke_async(&mut connection),
            )
            .await?;
        if active == 1 {
            Ok(())
        } else {
            Err(PrivateEgressError::DeadEpoch)
        }
    }

    async fn complete_route_recovery(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        key: &PrivateEgressRouteKey,
    ) -> Result<(), PrivateEgressError> {
        let keys = self.keys(&epoch.gateway_id);
        let mut connection = self.manager.clone();
        let result: i64 = self
            .bounded(
                redis::Script::new(COMPLETE_RECOVERY_SCRIPT)
                    .key(keys.epoch)
                    .key(keys.routes)
                    .arg(epoch.instance_id.to_string())
                    .arg(Self::route_field(key)?)
                    .arg(self.entry_ttl_ms)
                    .invoke_async(&mut connection),
            )
            .await?;
        map_transition_result(result)
    }

    async fn claim_command(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        command_id: Uuid,
        digest: [u8; 32],
        _at_ms: i64,
    ) -> Result<PrivateEgressCommandClaim, PrivateEgressError> {
        let keys = self.keys(&epoch.gateway_id);
        let mut connection = self.manager.clone();
        let values: Vec<String> = self
            .bounded(
                redis::Script::new(CLAIM_COMMAND_SCRIPT)
                    .key(keys.epoch)
                    .key(keys.commands)
                    .arg(epoch.instance_id.to_string())
                    .arg(command_id.to_string())
                    .arg(hex_bytes(&digest))
                    .arg(self.entry_ttl_ms)
                    .arg(self.max_entries)
                    .invoke_async(&mut connection),
            )
            .await?;
        match values.first().map(String::as_str) {
            Some("acquired") if values.len() == 1 => Ok(PrivateEgressCommandClaim::Acquired),
            Some("in_flight") if values.len() == 1 => Ok(PrivateEgressCommandClaim::InFlight),
            Some("completed") if values.len() == 2 => serde_json::from_str(&values[1])
                .map(PrivateEgressCommandClaim::Completed)
                .map_err(|_| PrivateEgressError::StateUnavailable),
            Some("replay_conflict") => Err(PrivateEgressError::ReplayConflict),
            Some("capacity") => Err(PrivateEgressError::CapacityExceeded),
            Some("dead_epoch") => Err(PrivateEgressError::DeadEpoch),
            _ => Err(PrivateEgressError::StateUnavailable),
        }
    }

    async fn complete_command(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        command_id: Uuid,
        digest: [u8; 32],
        response: &PrivateEgressResponse,
        _at_ms: i64,
    ) -> Result<(), PrivateEgressError> {
        let keys = self.keys(&epoch.gateway_id);
        let response =
            serde_json::to_string(response).map_err(|_| PrivateEgressError::StateUnavailable)?;
        let mut connection = self.manager.clone();
        let result: i64 = self
            .bounded(
                redis::Script::new(COMPLETE_COMMAND_SCRIPT)
                    .key(keys.epoch)
                    .key(keys.commands)
                    .arg(epoch.instance_id.to_string())
                    .arg(command_id.to_string())
                    .arg(hex_bytes(&digest))
                    .arg(response)
                    .arg(self.entry_ttl_ms)
                    .invoke_async(&mut connection),
            )
            .await?;
        match result {
            1 => Ok(()),
            -9 => Err(PrivateEgressError::DeadEpoch),
            -2 => Err(PrivateEgressError::ReplayConflict),
            _ => Err(PrivateEgressError::StateUnavailable),
        }
    }

    async fn claim_route_transition(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        key: &PrivateEgressRouteKey,
        command_id: Uuid,
        expected: Option<PrivateEgressLifecycleState>,
        next: PrivateEgressLifecycleState,
    ) -> Result<(), PrivateEgressError> {
        let keys = self.keys(&epoch.gateway_id);
        let authority = key.authority();
        let mut connection = self.manager.clone();
        let result: i64 = self
            .bounded(
                redis::Script::new(CLAIM_ROUTE_SCRIPT)
                    .key(keys.epoch)
                    .key(keys.routes)
                    .arg(epoch.instance_id.to_string())
                    .arg(Self::route_field(key)?)
                    .arg(command_id.to_string())
                    .arg(expected.map(state_label).unwrap_or(""))
                    .arg(state_label(next))
                    .arg(
                        serde_json::to_string(key)
                            .map_err(|_| PrivateEgressError::StateUnavailable)?,
                    )
                    .arg(Self::source_digest(&authority)?)
                    .arg(self.max_entries)
                    .arg(self.entry_ttl_ms)
                    .invoke_async(&mut connection),
            )
            .await?;
        map_transition_result(result)
    }

    async fn complete_route_transition(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        key: &PrivateEgressRouteKey,
        command_id: Uuid,
        next: PrivateEgressLifecycleState,
        _at_ms: i64,
    ) -> Result<(), PrivateEgressError> {
        let keys = self.keys(&epoch.gateway_id);
        let mut connection = self.manager.clone();
        let result: i64 = self
            .bounded(
                redis::Script::new(COMPLETE_ROUTE_SCRIPT)
                    .key(keys.epoch)
                    .key(keys.routes)
                    .arg(epoch.instance_id.to_string())
                    .arg(Self::route_field(key)?)
                    .arg(command_id.to_string())
                    .arg(state_label(next))
                    .arg(self.entry_ttl_ms)
                    .invoke_async(&mut connection),
            )
            .await?;
        map_transition_result(result)
    }

    async fn abort_route_transition(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        key: &PrivateEgressRouteKey,
        command_id: Uuid,
    ) -> Result<(), PrivateEgressError> {
        let keys = self.keys(&epoch.gateway_id);
        let mut connection = self.manager.clone();
        let result: i64 = self
            .bounded(
                redis::Script::new(ABORT_ROUTE_SCRIPT)
                    .key(keys.epoch)
                    .key(keys.routes)
                    .arg(epoch.instance_id.to_string())
                    .arg(Self::route_field(key)?)
                    .arg(command_id.to_string())
                    .arg(self.entry_ttl_ms)
                    .invoke_async(&mut connection),
            )
            .await?;
        map_transition_result(result)
    }

    async fn fail_source(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        authority: &PrivateEgressRouteAuthority,
        _at_ms: i64,
    ) -> Result<Vec<PrivateEgressRouteKey>, PrivateEgressError> {
        let keys = self.keys(&epoch.gateway_id);
        let mut connection = self.manager.clone();
        let values: Vec<String> = self
            .bounded(
                redis::Script::new(FAIL_SOURCE_SCRIPT)
                    .key(keys.epoch)
                    .key(keys.routes)
                    .arg(epoch.instance_id.to_string())
                    .arg(Self::source_digest(authority)?)
                    .arg(self.entry_ttl_ms)
                    .invoke_async(&mut connection),
            )
            .await?;
        match values.first().map(String::as_str) {
            Some("ok") => values[1..]
                .iter()
                .map(|value| {
                    serde_json::from_str(value).map_err(|_| PrivateEgressError::StateUnavailable)
                })
                .collect(),
            Some("dead_epoch") => Err(PrivateEgressError::DeadEpoch),
            _ => Err(PrivateEgressError::StateUnavailable),
        }
    }

    async fn append_lifecycle(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        key: &PrivateEgressRouteKey,
        event: &PrivateEgressLifecycleEvent,
        _at_ms: i64,
    ) -> Result<PrivateEgressLifecycleEvent, PrivateEgressError> {
        if event.worker != key.worker
            || event.source != key.authority().source
            || event.target != key.target
            || !event.gateway_epoch.is_nil()
            || event.sequence != 0
        {
            return Err(PrivateEgressError::OwnershipMismatch);
        }
        let keys = self.keys(&epoch.gateway_id);
        let event_json =
            serde_json::to_string(event).map_err(|_| PrivateEgressError::StateUnavailable)?;
        let mut connection = self.manager.clone();
        let values: Vec<String> = self
            .bounded(
                redis::Script::new(APPEND_LIFECYCLE_SCRIPT)
                    .key(keys.epoch)
                    .key(keys.routes)
                    .key(keys.lifecycle)
                    .arg(epoch.instance_id.to_string())
                    .arg(Self::route_field(key)?)
                    .arg(event.event_id.to_string())
                    .arg(event_json)
                    .arg(event.version)
                    .arg(self.entry_ttl_ms)
                    .arg(self.max_entries)
                    .invoke_async(&mut connection),
            )
            .await?;
        match values.first().map(String::as_str) {
            Some("ok") if values.len() == 2 => {
                serde_json::from_str(&values[1]).map_err(|_| PrivateEgressError::StateUnavailable)
            }
            Some("dead_epoch") => Err(PrivateEgressError::DeadEpoch),
            Some("replay_conflict") => Err(PrivateEgressError::ReplayConflict),
            Some("capacity") => Err(PrivateEgressError::CapacityExceeded),
            Some("invalid_transition") => Err(PrivateEgressError::InvalidTransition),
            _ => Err(PrivateEgressError::StateUnavailable),
        }
    }

    async fn ack_lifecycle(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        key: &PrivateEgressRouteKey,
        event_id: Uuid,
        sequence: u64,
    ) -> Result<(), PrivateEgressError> {
        let keys = self.keys(&epoch.gateway_id);
        let mut connection = self.manager.clone();
        let result: i64 = self
            .bounded(
                redis::Script::new(ACK_LIFECYCLE_SCRIPT)
                    .key(keys.epoch)
                    .key(keys.lifecycle)
                    .arg(epoch.instance_id.to_string())
                    .arg(Self::route_field(key)?)
                    .arg(event_id.to_string())
                    .arg(sequence)
                    .arg(self.entry_ttl_ms)
                    .invoke_async(&mut connection),
            )
            .await?;
        match result {
            1 => Ok(()),
            -9 => Err(PrivateEgressError::DeadEpoch),
            -5 => Err(PrivateEgressError::OwnershipMismatch),
            _ => Err(PrivateEgressError::InvalidResponse),
        }
    }

    async fn unacked_lifecycle(
        &self,
        epoch: &PrivateEgressGatewayEpoch,
        key: &PrivateEgressRouteKey,
    ) -> Result<Vec<PrivateEgressLifecycleEvent>, PrivateEgressError> {
        let keys = self.keys(&epoch.gateway_id);
        let mut connection = self.manager.clone();
        let values: Vec<String> = self
            .bounded(
                redis::Script::new(UNACKED_LIFECYCLE_SCRIPT)
                    .key(keys.epoch)
                    .key(keys.lifecycle)
                    .arg(epoch.instance_id.to_string())
                    .arg(Self::route_field(key)?)
                    .invoke_async(&mut connection),
            )
            .await?;
        match values.first().map(String::as_str) {
            Some("ok") if values.len() % 2 == 1 => {
                let mut events = values[1..]
                    .chunks_exact(2)
                    .map(|pair| {
                        let sequence = pair[0]
                            .parse::<u64>()
                            .map_err(|_| PrivateEgressError::StateUnavailable)?;
                        let event: PrivateEgressLifecycleEvent = serde_json::from_str(&pair[1])
                            .map_err(|_| PrivateEgressError::StateUnavailable)?;
                        if event.sequence != sequence {
                            return Err(PrivateEgressError::StateUnavailable);
                        }
                        Ok(event)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                events.sort_by_key(|event| event.sequence);
                Ok(events)
            }
            Some("dead_epoch") => Err(PrivateEgressError::DeadEpoch),
            _ => Err(PrivateEgressError::StateUnavailable),
        }
    }
}

fn map_transition_result(result: i64) -> Result<(), PrivateEgressError> {
    match result {
        1 => Ok(()),
        -9 => Err(PrivateEgressError::DeadEpoch),
        -4 => Err(PrivateEgressError::CapacityExceeded),
        -3 => Err(PrivateEgressError::InvalidTransition),
        _ => Err(PrivateEgressError::StateUnavailable),
    }
}

fn state_label(state: PrivateEgressLifecycleState) -> &'static str {
    match state {
        PrivateEgressLifecycleState::Prepared => "prepared",
        PrivateEgressLifecycleState::Active => "active",
        PrivateEgressLifecycleState::Ended => "ended",
        PrivateEgressLifecycleState::Failed => "failed",
    }
}

fn validate_config(config: &RedisPrivateEgressStateConfig) -> Result<(), PrivateEgressError> {
    if config.redis_url.is_empty()
        || config.prefix.is_empty()
        || config.prefix.len() > MAX_PREFIX_BYTES
        || config.prefix.chars().any(char::is_control)
        || config.entry_ttl.is_zero()
        || config.operation_timeout.is_zero()
        || config.operation_timeout > MAX_OPERATION_TIMEOUT
        || config.max_entries == 0
        || duration_ms(config.entry_ttl).is_err()
    {
        Err(PrivateEgressError::StateUnavailable)
    } else {
        Ok(())
    }
}

fn duration_ms(duration: Duration) -> Result<i64, PrivateEgressError> {
    i64::try_from(duration.as_millis()).map_err(|_| PrivateEgressError::StateUnavailable)
}

fn digest_json<T: Serialize>(domain: &[u8], value: &T) -> Result<String, PrivateEgressError> {
    let encoded = serde_json::to_vec(value).map_err(|_| PrivateEgressError::StateUnavailable)?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(encoded);
    let digest = digest.finalize();
    Ok(format!("{digest:x}"))
}

fn gateway_keys(prefix_hex: &str, gateway_id: &str) -> RedisGatewayKeys {
    let mut digest = Sha256::new();
    digest.update(b"bridgefu.private-egress.redis-slot.v1\0");
    digest.update(prefix_hex.as_bytes());
    digest.update([0]);
    digest.update(gateway_id.as_bytes());
    let digest = digest.finalize();
    let slot = format!("{digest:x}");
    let base = format!("bridgefu:private-egress:{{{slot}}}");
    RedisGatewayKeys {
        epoch: format!("{base}:epoch"),
        commands: format!("{base}:commands"),
        routes: format!("{base}:routes"),
        lifecycle: format!("{base}:lifecycle"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redis_configuration_and_keys_are_bounded_and_secret_safe() {
        let config = RedisPrivateEgressStateConfig::new(
            "rediss://user:secret@example.invalid",
            "deployment-a",
        );
        let debug = format!("{config:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("user"));
        assert!(validate_config(&config).is_ok());

        let mut invalid = config;
        invalid.entry_ttl = Duration::ZERO;
        assert_eq!(
            validate_config(&invalid),
            Err(PrivateEgressError::StateUnavailable)
        );
        invalid.entry_ttl = DEFAULT_ENTRY_TTL;
        invalid.operation_timeout = MAX_OPERATION_TIMEOUT + Duration::from_millis(1);
        assert_eq!(
            validate_config(&invalid),
            Err(PrivateEgressError::StateUnavailable)
        );
    }

    #[test]
    fn gateway_keys_share_one_cluster_hash_slot_without_gateway_disclosure() {
        let keys = gateway_keys(&hex_bytes(b"deployment-a"), "gateway-secret-name");
        let tag = |key: &str| {
            key.split_once('{')
                .and_then(|(_, rest)| rest.split_once('}'))
                .map(|(tag, _)| tag.to_owned())
                .unwrap()
        };
        assert_eq!(tag(&keys.epoch), tag(&keys.commands));
        assert_eq!(tag(&keys.epoch), tag(&keys.routes));
        assert_eq!(tag(&keys.epoch), tag(&keys.lifecycle));
        assert!(!keys.epoch.contains("gateway-secret-name"));
    }
}
