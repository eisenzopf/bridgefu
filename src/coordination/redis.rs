//! Redis 7.2 projection cache and payload-free Streams wakeups.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use redis::aio::{ConnectionManager, MultiplexedConnection};
use redis::streams::{StreamAutoClaimReply, StreamId, StreamReadReply};

use crate::call_engine::{CallId, WorkerId};

use super::{
    validate_poll_interval, CallRouteHint, CoordinationError, CoordinationEvent,
    CoordinationPayload, CoordinationProjection, DatabasePollReason, DeploymentId,
    ProjectionApplyOutcome, ProjectionSequence, ReplayDigest, ReplayMarker, WakeupConsumer,
    WakeupMessage, WakeupPoll, WakeupPublisher, WakeupReason, WorkerCoordinationSnapshot,
    WorkerSelectionRequest,
};

const WORKER_APPLY_SCRIPT: &str = r#"
local function decimal_compare(left, right)
  left = string.gsub(left, '^0+', '')
  right = string.gsub(right, '^0+', '')
  if left == '' then left = '0' end
  if right == '' then right = '0' end
  if string.len(left) < string.len(right) then return -1 end
  if string.len(left) > string.len(right) then return 1 end
  if left < right then return -1 end
  if left > right then return 1 end
  return 0
end
local current_seq = redis.call('HGET', KEYS[1], 'seq')
local current_body = redis.call('HGET', KEYS[1], 'body')
local current_fence = redis.call('HGET', KEYS[1], 'fence')
local current_draining = redis.call('HGET', KEYS[1], 'draining')
local current_expiry = redis.call('HGET', KEYS[1], 'lease_expiry_ms')
local incoming_expiry = tonumber(ARGV[5])
local clock = redis.call('TIME')
local now_ms = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
if current_seq then
  local sequence_order = decimal_compare(ARGV[1], current_seq)
  if sequence_order < 0 then return -1 end
  if sequence_order == 0 then
    if current_body == ARGV[2] then return 0 else return -2 end
  end
  local fence_order = decimal_compare(ARGV[3], current_fence)
  if fence_order < 0 then return -5 end
  if fence_order == 0 then
    if tonumber(current_expiry) <= now_ms then return -3 end
    if current_draining == '1' and ARGV[4] == '0' then return -4 end
  end
end
redis.call('HSET', KEYS[1],
  'seq', ARGV[1], 'body', ARGV[2], 'fence', ARGV[3],
  'draining', ARGV[4], 'lease_expiry_ms', ARGV[5])
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_ms)
redis.call('ZADD', KEYS[2], incoming_expiry, ARGV[6])
local keep_until = math.max(incoming_expiry, now_ms) + tonumber(ARGV[7])
redis.call('PEXPIREAT', KEYS[1], keep_until)
return 1
"#;

const EXPIRING_APPLY_SCRIPT: &str = r#"
local function decimal_compare(left, right)
  left = string.gsub(left, '^0+', '')
  right = string.gsub(right, '^0+', '')
  if left == '' then left = '0' end
  if right == '' then right = '0' end
  if string.len(left) < string.len(right) then return -1 end
  if string.len(left) > string.len(right) then return 1 end
  if left < right then return -1 end
  if left > right then return 1 end
  return 0
end
local expiry_ms = tonumber(ARGV[3])
local clock = redis.call('TIME')
local now_ms = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
if expiry_ms <= now_ms then return -1 end
local current_seq = redis.call('HGET', KEYS[1], 'seq')
local current_body = redis.call('HGET', KEYS[1], 'body')
if current_seq then
  local sequence_order = decimal_compare(ARGV[1], current_seq)
  if sequence_order < 0 then return -1 end
  if sequence_order == 0 then
    if current_body == ARGV[2] then return 0 else return -2 end
  end
end
redis.call('HSET', KEYS[1], 'seq', ARGV[1], 'body', ARGV[2])
redis.call('PEXPIREAT', KEYS[1], expiry_ms)
return 1
"#;

const WAKEUP_SCRIPT: &str = r#"
local function decimal_compare(left, right)
  left = string.gsub(left, '^0+', '')
  right = string.gsub(right, '^0+', '')
  if left == '' then left = '0' end
  if right == '' then right = '0' end
  if string.len(left) < string.len(right) then return -1 end
  if string.len(left) > string.len(right) then return 1 end
  if left < right then return -1 end
  if left > right then return 1 end
  return 0
end
local current_seq = redis.call('HGET', KEYS[1], 'seq')
local current_reason = redis.call('HGET', KEYS[1], 'reason')
if current_seq then
  local sequence_order = decimal_compare(ARGV[1], current_seq)
  if sequence_order < 0 then return -1 end
  if sequence_order == 0 then
    if current_reason == ARGV[2] then return 0 else return -2 end
  end
end
redis.call('HSET', KEYS[1], 'seq', ARGV[1], 'reason', ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[4])
redis.call('XADD', KEYS[2], 'MAXLEN', ARGV[3], '*',
  'seq', ARGV[1], 'reason', ARGV[2])
redis.call('PEXPIRE', KEYS[2], ARGV[4])
return 1
"#;

/// Redis connection and key-retention policy.
#[derive(Clone)]
pub struct RedisCoordinationConfig {
    url: String,
    /// Deployment key namespace.
    pub deployment: DeploymentId,
    /// Require `rediss://`; set in clustered modes.
    pub clustered: bool,
    /// Retain expired worker fence tombstones to reject same-fence resurrection.
    pub lease_tombstone_ttl: Duration,
    /// Maximum approximate entries per worker Stream.
    pub max_stream_len: usize,
    /// Stream and wakeup-sequence idle retention.
    pub stream_ttl: Duration,
    /// Bounded XREADGROUP block interval before mandatory DB fallback.
    pub database_fallback_interval: Duration,
}

impl RedisCoordinationConfig {
    /// Constructs a safe standalone configuration. URLs are never formatted by `Debug`.
    pub fn new(
        url: impl Into<String>,
        deployment: DeploymentId,
    ) -> Result<Self, CoordinationError> {
        let config = Self {
            url: url.into(),
            deployment,
            clustered: false,
            lease_tombstone_ttl: Duration::from_secs(24 * 60 * 60),
            max_stream_len: 10_000,
            stream_ttl: Duration::from_secs(24 * 60 * 60),
            database_fallback_interval: Duration::from_secs(2),
        };
        config.validate()?;
        Ok(config)
    }

    /// Enables clustered-mode TLS enforcement.
    #[must_use]
    pub fn clustered(mut self, clustered: bool) -> Self {
        self.clustered = clustered;
        self
    }

    /// Sets expired-fence retention. Same-fence resurrection remains rejected
    /// until this tombstone expires; clustered deployments should keep the
    /// default 24-hour window unless their worker-ID reuse policy is stricter.
    pub fn with_lease_tombstone_ttl(mut self, ttl: Duration) -> Result<Self, CoordinationError> {
        self.lease_tombstone_ttl = ttl;
        self.validate()?;
        Ok(self)
    }

    /// Sets bounded Stream retention and the mandatory authoritative-database
    /// fallback interval.
    pub fn with_stream_policy(
        mut self,
        max_len: usize,
        ttl: Duration,
        database_fallback_interval: Duration,
    ) -> Result<Self, CoordinationError> {
        self.max_stream_len = max_len;
        self.stream_ttl = ttl;
        self.database_fallback_interval = database_fallback_interval;
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> Result<(), CoordinationError> {
        if self.url.is_empty()
            || (!self.url.starts_with("redis://") && !self.url.starts_with("rediss://"))
        {
            return Err(CoordinationError::InvalidInput("invalid Redis URL scheme"));
        }
        if self.clustered && !self.url.starts_with("rediss://") {
            return Err(CoordinationError::InvalidInput(
                "clustered Redis coordination requires rediss",
            ));
        }
        if self.lease_tombstone_ttl.is_zero()
            || self.lease_tombstone_ttl > Duration::from_secs(7 * 24 * 60 * 60)
            || self.stream_ttl.is_zero()
            || self.stream_ttl > Duration::from_secs(7 * 24 * 60 * 60)
            || self.max_stream_len == 0
            || self.max_stream_len > 1_000_000
        {
            return Err(CoordinationError::InvalidInput(
                "invalid Redis coordination retention",
            ));
        }
        validate_poll_interval(self.database_fallback_interval)
    }
}

impl std::fmt::Debug for RedisCoordinationConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedisCoordinationConfig")
            .field("url", &"[redacted]")
            .field("deployment", &self.deployment)
            .field("clustered", &self.clustered)
            .field("lease_tombstone_ttl", &self.lease_tombstone_ttl)
            .field("max_stream_len", &self.max_stream_len)
            .field("stream_ttl", &self.stream_ttl)
            .field(
                "database_fallback_interval",
                &self.database_fallback_interval,
            )
            .finish()
    }
}

#[derive(Clone, Debug)]
struct RedisKeyspace {
    prefix: String,
}

impl RedisKeyspace {
    fn new(deployment: &DeploymentId) -> Self {
        Self {
            prefix: format!("bridgefu:{{{}}}:coord", deployment.as_str()),
        }
    }

    fn workers(&self) -> String {
        format!("{}:workers", self.prefix)
    }

    fn worker(&self, worker_id: impl std::fmt::Display) -> String {
        format!("{}:worker:{worker_id}", self.prefix)
    }

    fn route(&self, call_id: CallId) -> String {
        format!("{}:route:{call_id}", self.prefix)
    }

    fn replay(&self, digest: ReplayDigest) -> String {
        format!("{}:replay:{}", self.prefix, encode_digest(digest))
    }

    fn wakeup_sequence(&self, worker_id: WorkerId) -> String {
        format!("{}:wakeup-seq:{worker_id}", self.prefix)
    }

    fn wakeup_stream(&self, worker_id: WorkerId) -> String {
        format!("{}:wakeup:{worker_id}", self.prefix)
    }
}

/// Redis projection/cache. It never reserves calls or authorizes tenants.
#[derive(Clone)]
pub struct RedisCoordinator {
    client: redis::Client,
    manager: ConnectionManager,
    config: RedisCoordinationConfig,
    keys: RedisKeyspace,
}

impl std::fmt::Debug for RedisCoordinator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedisCoordinator")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl RedisCoordinator {
    /// Connects a projection manager. Connection errors are redacted.
    pub async fn connect(config: RedisCoordinationConfig) -> Result<Self, CoordinationError> {
        config.validate()?;
        let client =
            redis::Client::open(config.url.as_str()).map_err(|_| CoordinationError::Unavailable)?;
        let manager = ConnectionManager::new(client.clone())
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        let keys = RedisKeyspace::new(&config.deployment);
        Ok(Self {
            client,
            manager,
            config,
            keys,
        })
    }

    /// Creates a consumer with its own dedicated blocking connection.
    pub async fn wakeup_consumer(
        &self,
        worker_id: WorkerId,
        group: impl Into<String>,
        consumer: impl Into<String>,
    ) -> Result<RedisWakeupConsumer, CoordinationError> {
        let group = validate_stream_name(group.into())?;
        let consumer = validate_stream_name(consumer.into())?;
        let stream_key = self.keys.wakeup_stream(worker_id);
        let mut connection = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        let create = redis::cmd("XGROUP")
            .arg("CREATE")
            .arg(&stream_key)
            .arg(&group)
            .arg("0")
            .arg("MKSTREAM")
            .query_async::<String>(&mut connection)
            .await;
        if let Err(error) = create {
            if error.code() != Some("BUSYGROUP") {
                return Err(CoordinationError::Unavailable);
            }
        }
        Ok(RedisWakeupConsumer {
            connection,
            stream_key,
            group,
            consumer,
            poll_interval: self.config.database_fallback_interval,
        })
    }

    async fn redis_now(&self) -> Result<DateTime<Utc>, CoordinationError> {
        let mut connection = self.manager.clone();
        let millis = redis::cmd("EVAL")
            .arg("local t=redis.call('TIME'); return tonumber(t[1])*1000+math.floor(tonumber(t[2])/1000)")
            .arg(0)
            .query_async::<i64>(&mut connection)
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        DateTime::from_timestamp_millis(millis).ok_or(CoordinationError::InvalidData)
    }

    async fn apply_worker(
        &self,
        sequence: ProjectionSequence,
        worker: &WorkerCoordinationSnapshot,
    ) -> Result<ProjectionApplyOutcome, CoordinationError> {
        worker.validate()?;
        let body = serde_json::to_string(worker).map_err(|_| CoordinationError::InvalidData)?;
        let tombstone_ms = duration_millis(self.config.lease_tombstone_ttl)?;
        let mut connection = self.manager.clone();
        let code = redis::cmd("EVAL")
            .arg(WORKER_APPLY_SCRIPT)
            .arg(2)
            .arg(self.keys.worker(worker.lease.worker_id))
            .arg(self.keys.workers())
            .arg(sequence.as_i64())
            .arg(body)
            .arg(worker.lease.fence.as_i64())
            .arg(if worker.draining { 1 } else { 0 })
            .arg(worker.lease_expires_at.timestamp_millis())
            .arg(worker.lease.worker_id.to_string())
            .arg(tombstone_ms)
            .query_async::<i64>(&mut connection)
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        decode_apply_code(code)
    }

    async fn apply_expiring<T: serde::Serialize>(
        &self,
        key: String,
        sequence: ProjectionSequence,
        value: &T,
        expires_at: DateTime<Utc>,
    ) -> Result<ProjectionApplyOutcome, CoordinationError> {
        let body = serde_json::to_string(value).map_err(|_| CoordinationError::InvalidData)?;
        let mut connection = self.manager.clone();
        let code = redis::cmd("EVAL")
            .arg(EXPIRING_APPLY_SCRIPT)
            .arg(1)
            .arg(key)
            .arg(sequence.as_i64())
            .arg(body)
            .arg(expires_at.timestamp_millis())
            .query_async::<i64>(&mut connection)
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        decode_apply_code(code)
    }

    async fn apply_wakeup(
        &self,
        worker_id: WorkerId,
        sequence: ProjectionSequence,
        reason: WakeupReason,
    ) -> Result<ProjectionApplyOutcome, CoordinationError> {
        let mut connection = self.manager.clone();
        let code = redis::cmd("EVAL")
            .arg(WAKEUP_SCRIPT)
            .arg(2)
            .arg(self.keys.wakeup_sequence(worker_id))
            .arg(self.keys.wakeup_stream(worker_id))
            .arg(sequence.as_i64())
            .arg(reason.as_str())
            .arg(self.config.max_stream_len)
            .arg(duration_millis(self.config.stream_ttl)?)
            .query_async::<i64>(&mut connection)
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        decode_apply_code(code)
    }

    async fn worker_body(
        &self,
        worker_id: impl std::fmt::Display,
    ) -> Result<Option<WorkerCoordinationSnapshot>, CoordinationError> {
        let mut connection = self.manager.clone();
        let body = redis::cmd("HGET")
            .arg(self.keys.worker(worker_id))
            .arg("body")
            .query_async::<Option<String>>(&mut connection)
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        body.map(|body| serde_json::from_str(&body).map_err(|_| CoordinationError::InvalidData))
            .transpose()
    }
}

#[async_trait]
impl CoordinationProjection for RedisCoordinator {
    async fn apply(
        &self,
        event: &CoordinationEvent,
    ) -> Result<ProjectionApplyOutcome, CoordinationError> {
        event.validate()?;
        if event.deployment != self.config.deployment {
            return Err(CoordinationError::InvalidInput(
                "coordination deployment mismatch",
            ));
        }
        match &event.payload {
            CoordinationPayload::Worker(worker) => self.apply_worker(event.sequence, worker).await,
            CoordinationPayload::Route(route) => {
                self.apply_expiring(
                    self.keys.route(route.call_id),
                    event.sequence,
                    route,
                    route.expires_at,
                )
                .await
            }
            CoordinationPayload::Replay(marker) => {
                self.apply_expiring(
                    self.keys.replay(marker.digest),
                    event.sequence,
                    marker,
                    marker.expires_at,
                )
                .await
            }
            CoordinationPayload::WakeWorker { worker_id, reason } => {
                self.apply_wakeup(*worker_id, event.sequence, *reason).await
            }
        }
    }

    async fn worker_hints(
        &self,
        request: &WorkerSelectionRequest,
    ) -> Result<Vec<WorkerCoordinationSnapshot>, CoordinationError> {
        request.validate()?;
        let now = self.redis_now().await?;
        let mut connection = self.manager.clone();
        redis::cmd("ZREMRANGEBYSCORE")
            .arg(self.keys.workers())
            .arg("-inf")
            .arg(now.timestamp_millis())
            .query_async::<usize>(&mut connection)
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        let ids = redis::cmd("ZRANGEBYSCORE")
            .arg(self.keys.workers())
            .arg(format!("({}", now.timestamp_millis()))
            .arg("+inf")
            .query_async::<Vec<String>>(&mut connection)
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        let mut workers = Vec::new();
        for id in ids {
            if let Some(worker) = self.worker_body(&id).await? {
                if worker.lease_expires_at > now
                    && !worker.draining
                    && worker.reserved_calls < worker.max_calls
                    && request
                        .required_capabilities
                        .is_subset(&worker.capabilities)
                {
                    workers.push(worker);
                }
            }
        }
        sort_workers(&mut workers);
        workers.truncate(request.limit);
        Ok(workers)
    }

    async fn route_hint(
        &self,
        call_id: CallId,
    ) -> Result<Option<CallRouteHint>, CoordinationError> {
        let mut connection = self.manager.clone();
        let body = redis::cmd("HGET")
            .arg(self.keys.route(call_id))
            .arg("body")
            .query_async::<Option<String>>(&mut connection)
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        let Some(body) = body else {
            return Ok(None);
        };
        let route: CallRouteHint =
            serde_json::from_str(&body).map_err(|_| CoordinationError::InvalidData)?;
        let now = self.redis_now().await?;
        if route.expires_at <= now {
            return Ok(None);
        }
        let Some(worker) = self.worker_body(route.worker.worker_id).await? else {
            return Ok(None);
        };
        Ok((worker.lease == route.worker && worker.lease_expires_at > now).then_some(route))
    }

    async fn replay_seen(&self, digest: ReplayDigest) -> Result<bool, CoordinationError> {
        let mut connection = self.manager.clone();
        let body = redis::cmd("HGET")
            .arg(self.keys.replay(digest))
            .arg("body")
            .query_async::<Option<String>>(&mut connection)
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        let Some(body) = body else {
            return Ok(false);
        };
        let marker: ReplayMarker =
            serde_json::from_str(&body).map_err(|_| CoordinationError::InvalidData)?;
        Ok(marker.expires_at > self.redis_now().await?)
    }
}

#[async_trait]
impl WakeupPublisher for RedisCoordinator {
    async fn publish_wakeup(
        &self,
        worker_id: WorkerId,
        sequence: ProjectionSequence,
        reason: WakeupReason,
    ) -> Result<(), CoordinationError> {
        self.apply_wakeup(worker_id, sequence, reason)
            .await
            .map(|_| ())
    }
}

/// Dedicated blocking Redis Streams consumer.
pub struct RedisWakeupConsumer {
    connection: MultiplexedConnection,
    stream_key: String,
    group: String,
    consumer: String,
    poll_interval: Duration,
}

impl std::fmt::Debug for RedisWakeupConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedisWakeupConsumer")
            .field("stream_key", &"[deployment-scoped]")
            .field("group", &self.group)
            .field("consumer", &self.consumer)
            .field("poll_interval", &self.poll_interval)
            .finish()
    }
}

#[async_trait]
impl WakeupConsumer for RedisWakeupConsumer {
    async fn poll(&mut self, count: usize) -> WakeupPoll {
        let count = count.clamp(1, 1_024);
        let block_ms = u64::try_from(self.poll_interval.as_millis()).unwrap_or(u64::MAX);
        let result = redis::cmd("XREADGROUP")
            .arg("GROUP")
            .arg(&self.group)
            .arg(&self.consumer)
            .arg("COUNT")
            .arg(count)
            .arg("BLOCK")
            .arg(block_ms)
            .arg("STREAMS")
            .arg(&self.stream_key)
            .arg(">")
            .query_async::<StreamReadReply>(&mut self.connection)
            .await;
        match result {
            Ok(reply) => match parse_read_reply(reply) {
                Ok(messages) => WakeupPoll {
                    database_poll_reason: if messages.is_empty() {
                        DatabasePollReason::IntervalElapsed
                    } else {
                        DatabasePollReason::Wakeup
                    },
                    messages,
                },
                Err(_) => WakeupPoll {
                    messages: Vec::new(),
                    database_poll_reason: DatabasePollReason::CoordinationUnavailable,
                },
            },
            Err(_) => WakeupPoll {
                messages: Vec::new(),
                database_poll_reason: DatabasePollReason::CoordinationUnavailable,
            },
        }
    }

    async fn auto_claim(
        &mut self,
        min_idle: Duration,
        count: usize,
    ) -> Result<Vec<WakeupMessage>, CoordinationError> {
        if min_idle.is_zero() || count == 0 || count > 1_024 {
            return Err(CoordinationError::InvalidInput(
                "invalid wakeup auto-claim request",
            ));
        }
        let reply = redis::cmd("XAUTOCLAIM")
            .arg(&self.stream_key)
            .arg(&self.group)
            .arg(&self.consumer)
            .arg(duration_millis(min_idle)?)
            .arg("0-0")
            .arg("COUNT")
            .arg(count)
            .query_async::<StreamAutoClaimReply>(&mut self.connection)
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        parse_stream_ids(reply.claimed)
    }

    async fn acknowledge(&mut self, entry_ids: &[String]) -> Result<usize, CoordinationError> {
        if entry_ids.is_empty() {
            return Ok(0);
        }
        redis::cmd("XACK")
            .arg(&self.stream_key)
            .arg(&self.group)
            .arg(entry_ids)
            .query_async::<usize>(&mut self.connection)
            .await
            .map_err(|_| CoordinationError::Unavailable)
    }
}

fn parse_read_reply(reply: StreamReadReply) -> Result<Vec<WakeupMessage>, CoordinationError> {
    let ids = reply
        .keys
        .into_iter()
        .flat_map(|key| key.ids)
        .collect::<Vec<_>>();
    parse_stream_ids(ids)
}

fn parse_stream_ids(ids: Vec<StreamId>) -> Result<Vec<WakeupMessage>, CoordinationError> {
    ids.into_iter()
        .map(|id| {
            let sequence = id
                .map
                .get("seq")
                .ok_or(CoordinationError::InvalidData)
                .and_then(redis_string)?
                .parse::<i64>()
                .map_err(|_| CoordinationError::InvalidData)
                .and_then(ProjectionSequence::from_i64)?;
            let reason = id
                .map
                .get("reason")
                .ok_or(CoordinationError::InvalidData)
                .and_then(redis_string)
                .and_then(|reason| WakeupReason::parse(&reason))?;
            Ok(WakeupMessage {
                entry_id: id.id,
                sequence,
                reason,
            })
        })
        .collect()
}

fn redis_string(value: &redis::Value) -> Result<String, CoordinationError> {
    redis::from_redis_value(value.clone()).map_err(|_| CoordinationError::InvalidData)
}

fn decode_apply_code(code: i64) -> Result<ProjectionApplyOutcome, CoordinationError> {
    match code {
        1 => Ok(ProjectionApplyOutcome::Applied),
        0 => Ok(ProjectionApplyOutcome::Duplicate),
        -1 => Ok(ProjectionApplyOutcome::Stale),
        -2 => Err(CoordinationError::SequenceConflict),
        -3 => Err(CoordinationError::LeaseExpired),
        -4 => Err(CoordinationError::DrainIsOneWay),
        -5 => Err(CoordinationError::StaleFence),
        _ => Err(CoordinationError::InvalidData),
    }
}

fn duration_millis(duration: Duration) -> Result<u64, CoordinationError> {
    u64::try_from(duration.as_millis())
        .map_err(|_| CoordinationError::InvalidInput("duration is too large"))
}

fn encode_digest(digest: ReplayDigest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest.expose_bytes() {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn validate_stream_name(value: String) -> Result<String, CoordinationError> {
    if value.is_empty()
        || value.len() > 128
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        Err(CoordinationError::InvalidInput(
            "invalid Redis consumer or group name",
        ))
    } else {
        Ok(value)
    }
}

fn sort_workers(workers: &mut [WorkerCoordinationSnapshot]) {
    workers.sort_by(|left, right| {
        let left_load = (left.reserved_calls as u128) * (right.max_calls as u128);
        let right_load = (right.reserved_calls as u128) * (left.max_calls as u128);
        left_load
            .cmp(&right_load)
            .then(left.reserved_calls.cmp(&right.reserved_calls))
            .then(left.lease.worker_id.cmp(&right.lease.worker_id))
            .then(right.lease.fence.cmp(&left.lease.fence))
    });
}
