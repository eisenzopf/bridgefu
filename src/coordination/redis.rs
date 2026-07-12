//! Redis 7.2 projection cache and payload-free Streams wakeups.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use redis::aio::{ConnectionManager, MultiplexedConnection};
use redis::streams::{
    StreamAutoClaimReply, StreamId, StreamPendingCountReply, StreamPendingReply, StreamReadReply,
};
use zeroize::Zeroize;

use crate::call_engine::{CallId, WorkerId};

use super::{
    validate_poll_interval, CallRouteHint, CoordinationError, CoordinationEvent,
    CoordinationPayload, CoordinationProjection, DatabasePollReason, DeploymentId,
    ProjectionApplyOutcome, ProjectionSequence, ReplayDigest, ReplayMarker, WakeupConsumer,
    WakeupMessage, WakeupPoll, WakeupPublisher, WakeupReason, WorkerCoordinationSnapshot,
    WorkerSelectionRequest,
};

const MAX_WORKER_CANDIDATES: usize = 4_096;
const MIN_WORKER_CANDIDATES: usize = 64;
const CANDIDATE_OVERSAMPLE: usize = 8;
const RESPONSE_TIMEOUT_GRACE: Duration = Duration::from_millis(250);
const OUTER_TIMEOUT_GRACE: Duration = Duration::from_millis(500);
const INITIAL_RECONNECT_BACKOFF: Duration = Duration::from_millis(50);

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
local event_time = tonumber(ARGV[8])
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
    if tonumber(current_expiry) <= event_time then return -3 end
    if current_draining == '1' and ARGV[4] == '0' then return -4 end
  end
end
redis.call('HSET', KEYS[1],
  'seq', ARGV[1], 'body', ARGV[2], 'fence', ARGV[3],
  'draining', ARGV[4], 'lease_expiry_ms', ARGV[5],
  'recorded_at_ms', ARGV[8])
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
local clock = redis.call('TIME')
local now_ms = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local current_seq = redis.call('HGET', KEYS[1], 'seq')
local current_body = redis.call('HGET', KEYS[1], 'body')
local current_active = redis.call('HGET', KEYS[1], 'active')
if current_seq and not current_active then current_active = '1' end
if current_seq then
  local sequence_order = decimal_compare(ARGV[1], current_seq)
  if sequence_order < 0 then return -1 end
  if sequence_order == 0 then
    if current_body == ARGV[2] and current_active == ARGV[5] then return 0 else return -2 end
  end
end
local expiry_ms = tonumber(ARGV[3])
redis.call('HSET', KEYS[1],
  'seq', ARGV[1], 'body', ARGV[2], 'expiry_ms', ARGV[3], 'active', ARGV[5])
local keep_until = math.max(expiry_ms, now_ms) + tonumber(ARGV[4])
redis.call('PEXPIREAT', KEYS[1], keep_until)
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
    /// Retain route/replay sequence tombstones after their payload expires.
    pub projection_tombstone_ttl: Duration,
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
            projection_tombstone_ttl: Duration::from_secs(24 * 60 * 60),
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

    /// Sets route/replay sequence-tombstone retention. Payload visibility still
    /// ends at its authoritative expiry; only the sequence survives this long.
    pub fn with_projection_tombstone_ttl(
        mut self,
        ttl: Duration,
    ) -> Result<Self, CoordinationError> {
        self.projection_tombstone_ttl = ttl;
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

    pub(crate) fn validate(&self) -> Result<(), CoordinationError> {
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
            || self.projection_tombstone_ttl.is_zero()
            || self.projection_tombstone_ttl > Duration::from_secs(7 * 24 * 60 * 60)
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
            .field("projection_tombstone_ttl", &self.projection_tombstone_ttl)
            .field("max_stream_len", &self.max_stream_len)
            .field("stream_ttl", &self.stream_ttl)
            .field(
                "database_fallback_interval",
                &self.database_fallback_interval,
            )
            .finish()
    }
}

impl Drop for RedisCoordinationConfig {
    fn drop(&mut self) {
        self.url.zeroize();
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
    pub async fn connect(mut config: RedisCoordinationConfig) -> Result<Self, CoordinationError> {
        config.validate()?;
        let client = redis::Client::open(config.url.as_str());
        config.url.zeroize();
        let client = client.map_err(|_| CoordinationError::Unavailable)?;
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
        let mut result = RedisWakeupConsumer {
            client: self.client.clone(),
            connection: None,
            stream_key: self.keys.wakeup_stream(worker_id),
            group,
            consumer,
            poll_interval: self.config.database_fallback_interval,
            stream_ttl: self.config.stream_ttl,
            max_stream_len: self.config.max_stream_len,
            next_reconnect_at: None,
            reconnect_backoff: INITIAL_RECONNECT_BACKOFF,
            auto_claim_cursor: "0-0".to_owned(),
            pending_entries: 0,
            pel_evictions: 0,
            deleted_pending_entries: 0,
            reconnects: 0,
        };
        result.ensure_ready().await?;
        Ok(result)
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
        recorded_at: DateTime<Utc>,
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
            .arg(recorded_at.timestamp_millis())
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
        active: bool,
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
            .arg(duration_millis(self.config.projection_tombstone_ttl)?)
            .arg(if active { 1 } else { 0 })
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
            CoordinationPayload::Worker(worker) => {
                self.apply_worker(event.sequence, event.recorded_at, worker)
                    .await
            }
            CoordinationPayload::Route(route) => {
                self.apply_expiring(
                    self.keys.route(route.call_id),
                    event.sequence,
                    route,
                    route.expires_at,
                    true,
                )
                .await
            }
            CoordinationPayload::RouteRemoved { call_id } => {
                self.apply_expiring(
                    self.keys.route(*call_id),
                    event.sequence,
                    call_id,
                    event.recorded_at,
                    false,
                )
                .await
            }
            CoordinationPayload::Replay(marker) => {
                self.apply_expiring(
                    self.keys.replay(marker.digest),
                    event.sequence,
                    marker,
                    marker.expires_at,
                    true,
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
            .arg("LIMIT")
            .arg(0)
            .arg(
                request
                    .limit
                    .saturating_mul(CANDIDATE_OVERSAMPLE)
                    .clamp(MIN_WORKER_CANDIDATES, MAX_WORKER_CANDIDATES),
            )
            .query_async::<Vec<String>>(&mut connection)
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut reads = redis::pipe();
        for id in &ids {
            reads.cmd("HGET").arg(self.keys.worker(id)).arg("body");
        }
        let bodies = reads
            .query_async::<Vec<Option<String>>>(&mut connection)
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        let mut workers = Vec::new();
        for body in bodies.into_iter().flatten() {
            let worker: WorkerCoordinationSnapshot =
                serde_json::from_str(&body).map_err(|_| CoordinationError::InvalidData)?;
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
        sort_workers(&mut workers);
        workers.truncate(request.limit);
        Ok(workers)
    }

    async fn route_hint(
        &self,
        call_id: CallId,
    ) -> Result<Option<CallRouteHint>, CoordinationError> {
        let mut connection = self.manager.clone();
        let (body, active) = redis::cmd("HMGET")
            .arg(self.keys.route(call_id))
            .arg("body")
            .arg("active")
            .query_async::<(Option<String>, Option<String>)>(&mut connection)
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        if active.as_deref() == Some("0") {
            return Ok(None);
        }
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
        let (body, active) = redis::cmd("HMGET")
            .arg(self.keys.replay(digest))
            .arg("body")
            .arg("active")
            .query_async::<(Option<String>, Option<String>)>(&mut connection)
            .await
            .map_err(|_| CoordinationError::Unavailable)?;
        if active.as_deref() == Some("0") {
            return Ok(false);
        }
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
    client: redis::Client,
    connection: Option<MultiplexedConnection>,
    stream_key: String,
    group: String,
    consumer: String,
    poll_interval: Duration,
    stream_ttl: Duration,
    max_stream_len: usize,
    next_reconnect_at: Option<tokio::time::Instant>,
    reconnect_backoff: Duration,
    auto_claim_cursor: String,
    pending_entries: usize,
    pel_evictions: u64,
    deleted_pending_entries: u64,
    reconnects: u64,
}

impl std::fmt::Debug for RedisWakeupConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedisWakeupConsumer")
            .field("stream_key", &"[deployment-scoped]")
            .field("group", &self.group)
            .field("consumer", &self.consumer)
            .field("poll_interval", &self.poll_interval)
            .field("pending_entries", &self.pending_entries)
            .field("pel_evictions", &self.pel_evictions)
            .field("deleted_pending_entries", &self.deleted_pending_entries)
            .field("reconnects", &self.reconnects)
            .finish()
    }
}

impl RedisWakeupConsumer {
    /// Last measured consumer-group pending-entry count.
    #[must_use]
    pub const fn pending_entries(&self) -> usize {
        self.pending_entries
    }

    /// Hints deliberately evicted from the PEL to enforce the configured
    /// bound. Every consumer still performs periodic authoritative DB polls.
    #[must_use]
    pub const fn pel_evictions(&self) -> u64 {
        self.pel_evictions
    }

    /// Stale PEL references Redis removed while scanning with XAUTOCLAIM.
    #[must_use]
    pub const fn deleted_pending_entries(&self) -> u64 {
        self.deleted_pending_entries
    }

    /// Successful dedicated-connection recreations, including the initial one.
    #[must_use]
    pub const fn reconnects(&self) -> u64 {
        self.reconnects
    }

    fn response_timeout(&self) -> Duration {
        self.poll_interval
            .checked_add(RESPONSE_TIMEOUT_GRACE)
            .unwrap_or(self.poll_interval)
    }

    fn outer_timeout(&self) -> Duration {
        self.poll_interval
            .checked_add(OUTER_TIMEOUT_GRACE)
            .unwrap_or(self.poll_interval)
    }

    async fn ensure_ready(&mut self) -> Result<(), CoordinationError> {
        if self.connection.is_some() {
            return Ok(());
        }
        if let Some(next_attempt) = self.next_reconnect_at {
            tokio::time::sleep_until(next_attempt).await;
        }
        let connection_config = redis::AsyncConnectionConfig::new()
            .set_connection_timeout(Some(RESPONSE_TIMEOUT_GRACE))
            .set_response_timeout(Some(self.response_timeout()));
        let connection = self
            .client
            .get_multiplexed_async_connection_with_config(&connection_config)
            .await;
        let mut connection = match connection {
            Ok(connection) => connection,
            Err(_) => {
                self.mark_connection_failed();
                return Err(CoordinationError::Unavailable);
            }
        };
        match create_consumer_group(
            &mut connection,
            &self.stream_key,
            &self.group,
            self.stream_ttl,
        )
        .await
        {
            Ok(created) => {
                if created {
                    self.auto_claim_cursor = "0-0".to_owned();
                    self.pending_entries = 0;
                }
                self.connection = Some(connection);
                self.next_reconnect_at = None;
                self.reconnect_backoff = INITIAL_RECONNECT_BACKOFF;
                self.reconnects = self.reconnects.saturating_add(1);
                Ok(())
            }
            Err(_) => {
                self.mark_connection_failed();
                Err(CoordinationError::Unavailable)
            }
        }
    }

    async fn recreate_group(&mut self) -> Result<(), CoordinationError> {
        let Some(connection) = self.connection.as_mut() else {
            return Err(CoordinationError::Unavailable);
        };
        let created =
            create_consumer_group(connection, &self.stream_key, &self.group, self.stream_ttl).await;
        let created = match created {
            Ok(created) => created,
            Err(error) => {
                self.mark_connection_failed();
                return Err(error);
            }
        };
        if created {
            self.auto_claim_cursor = "0-0".to_owned();
            self.pending_entries = 0;
        }
        Ok(())
    }

    fn mark_connection_failed(&mut self) {
        self.connection = None;
        self.next_reconnect_at = Some(tokio::time::Instant::now() + self.reconnect_backoff);
        self.reconnect_backoff = self
            .reconnect_backoff
            .saturating_mul(2)
            .min(self.poll_interval);
    }

    async fn read_once(&mut self, count: usize) -> Result<Vec<WakeupMessage>, CoordinationError> {
        self.ensure_ready().await?;
        let mut recreated = false;
        loop {
            let result = {
                let connection = self
                    .connection
                    .as_mut()
                    .ok_or(CoordinationError::Unavailable)?;
                redis::cmd("XREADGROUP")
                    .arg("GROUP")
                    .arg(&self.group)
                    .arg(&self.consumer)
                    .arg("COUNT")
                    .arg(count)
                    .arg("BLOCK")
                    .arg(duration_millis(self.poll_interval)?)
                    .arg("STREAMS")
                    .arg(&self.stream_key)
                    .arg(">")
                    .query_async::<StreamReadReply>(connection)
                    .await
            };
            match result {
                Ok(reply) => return parse_read_reply(reply),
                Err(error) if is_no_group(&error) && !recreated => {
                    self.recreate_group().await?;
                    recreated = true;
                }
                Err(_) => {
                    self.mark_connection_failed();
                    return Err(CoordinationError::Unavailable);
                }
            }
        }
    }

    async fn maintain_pel(&mut self) -> Result<(), CoordinationError> {
        self.ensure_ready().await?;
        let pending = {
            let connection = self
                .connection
                .as_mut()
                .ok_or(CoordinationError::Unavailable)?;
            redis::cmd("XPENDING")
                .arg(&self.stream_key)
                .arg(&self.group)
                .query_async::<StreamPendingReply>(connection)
                .await
        };
        let pending = match pending {
            Ok(pending) => pending.count(),
            Err(error) if is_no_group(&error) => {
                self.recreate_group().await?;
                self.pending_entries = 0;
                return Ok(());
            }
            Err(_) => {
                self.mark_connection_failed();
                return Err(CoordinationError::Unavailable);
            }
        };
        if pending <= self.max_stream_len {
            self.pending_entries = pending;
            return Ok(());
        }

        let excess = pending - self.max_stream_len;
        let oldest = {
            let connection = self
                .connection
                .as_mut()
                .ok_or(CoordinationError::Unavailable)?;
            redis::cmd("XPENDING")
                .arg(&self.stream_key)
                .arg(&self.group)
                .arg("-")
                .arg("+")
                .arg(excess)
                .query_async::<StreamPendingCountReply>(connection)
                .await
        };
        let oldest = match oldest {
            Ok(oldest) => oldest,
            Err(_) => {
                self.mark_connection_failed();
                return Err(CoordinationError::Unavailable);
            }
        };
        let ids = oldest
            .ids
            .into_iter()
            .map(|pending| pending.id)
            .collect::<Vec<_>>();
        let evicted = if ids.is_empty() {
            0
        } else {
            let connection = self
                .connection
                .as_mut()
                .ok_or(CoordinationError::Unavailable)?;
            let result = redis::cmd("XACK")
                .arg(&self.stream_key)
                .arg(&self.group)
                .arg(ids)
                .query_async::<usize>(connection)
                .await;
            match result {
                Ok(evicted) => evicted,
                Err(_) => {
                    self.mark_connection_failed();
                    return Err(CoordinationError::Unavailable);
                }
            }
        };
        self.pel_evictions = self.pel_evictions.saturating_add(evicted as u64);
        self.pending_entries = pending.saturating_sub(evicted);
        Ok(())
    }

    async fn pace_unavailable(&self, started_at: tokio::time::Instant) {
        tokio::time::sleep_until(started_at + self.poll_interval).await;
    }
}

#[async_trait]
impl WakeupConsumer for RedisWakeupConsumer {
    async fn poll(&mut self, count: usize) -> WakeupPoll {
        let count = count.clamp(1, 1_024);
        let started_at = tokio::time::Instant::now();
        let result = tokio::time::timeout(self.outer_timeout(), self.read_once(count)).await;
        match result {
            Ok(Ok(messages)) => {
                let _ = self.maintain_pel().await;
                WakeupPoll {
                    database_poll_reason: if messages.is_empty() {
                        DatabasePollReason::IntervalElapsed
                    } else {
                        DatabasePollReason::Wakeup
                    },
                    messages,
                }
            }
            Ok(Err(_)) => {
                self.pace_unavailable(started_at).await;
                WakeupPoll {
                    messages: Vec::new(),
                    database_poll_reason: DatabasePollReason::CoordinationUnavailable,
                }
            }
            Err(_) => {
                self.mark_connection_failed();
                self.pace_unavailable(started_at).await;
                WakeupPoll {
                    messages: Vec::new(),
                    database_poll_reason: DatabasePollReason::CoordinationUnavailable,
                }
            }
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
        self.ensure_ready().await?;
        let mut recreated = false;
        loop {
            let reply = {
                let connection = self
                    .connection
                    .as_mut()
                    .ok_or(CoordinationError::Unavailable)?;
                redis::cmd("XAUTOCLAIM")
                    .arg(&self.stream_key)
                    .arg(&self.group)
                    .arg(&self.consumer)
                    .arg(duration_millis(min_idle)?)
                    .arg(&self.auto_claim_cursor)
                    .arg("COUNT")
                    .arg(count)
                    .query_async::<StreamAutoClaimReply>(connection)
                    .await
            };
            match reply {
                Ok(reply) => {
                    self.auto_claim_cursor = reply.next_stream_id;
                    self.deleted_pending_entries = self
                        .deleted_pending_entries
                        .saturating_add(reply.deleted_ids.len() as u64);
                    let messages = parse_stream_ids(reply.claimed)?;
                    self.maintain_pel().await?;
                    return Ok(messages);
                }
                Err(error) if is_no_group(&error) && !recreated => {
                    self.recreate_group().await?;
                    recreated = true;
                }
                Err(_) => {
                    self.mark_connection_failed();
                    return Err(CoordinationError::Unavailable);
                }
            }
        }
    }

    async fn acknowledge(&mut self, entry_ids: &[String]) -> Result<usize, CoordinationError> {
        if entry_ids.is_empty() {
            return Ok(0);
        }
        if entry_ids.len() > 1_024 || entry_ids.iter().any(|id| !valid_stream_id(id)) {
            return Err(CoordinationError::InvalidInput(
                "invalid wakeup acknowledgement",
            ));
        }
        self.ensure_ready().await?;
        let acknowledged = {
            let connection = self
                .connection
                .as_mut()
                .ok_or(CoordinationError::Unavailable)?;
            redis::cmd("XACK")
                .arg(&self.stream_key)
                .arg(&self.group)
                .arg(entry_ids)
                .query_async::<usize>(connection)
                .await
        };
        match acknowledged {
            Ok(acknowledged) => {
                self.maintain_pel().await?;
                Ok(acknowledged)
            }
            Err(error) if is_no_group(&error) => {
                self.recreate_group().await?;
                Ok(0)
            }
            Err(_) => {
                self.mark_connection_failed();
                Err(CoordinationError::Unavailable)
            }
        }
    }
}

async fn create_consumer_group(
    connection: &mut MultiplexedConnection,
    stream_key: &str,
    group: &str,
    stream_ttl: Duration,
) -> Result<bool, CoordinationError> {
    let create = redis::cmd("XGROUP")
        .arg("CREATE")
        .arg(stream_key)
        .arg(group)
        .arg("0")
        .arg("MKSTREAM")
        .query_async::<String>(connection)
        .await;
    let created = match create {
        Ok(_) => true,
        Err(error) if error.code() == Some("BUSYGROUP") => false,
        Err(_) => return Err(CoordinationError::Unavailable),
    };
    redis::cmd("PEXPIRE")
        .arg(stream_key)
        .arg(duration_millis(stream_ttl)?)
        .query_async::<bool>(connection)
        .await
        .map_err(|_| CoordinationError::Unavailable)?;
    Ok(created)
}

fn is_no_group(error: &redis::RedisError) -> bool {
    error.code() == Some("NOGROUP")
}

fn valid_stream_id(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let Some((milliseconds, sequence)) = value.split_once('-') else {
        return false;
    };
    !milliseconds.is_empty()
        && !sequence.is_empty()
        && milliseconds.bytes().all(|byte| byte.is_ascii_digit())
        && sequence.bytes().all(|byte| byte.is_ascii_digit())
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
