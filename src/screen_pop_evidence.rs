//! Bounded, short-lived evidence for the StandardCharter screen-pop path.
//!
//! The store deliberately keeps the raw correlation id only as its private
//! lookup key. Public snapshots contain a truncated SHA-256 fingerprint and a finite set
//! of lifecycle stages; they never expose the correlation id or arbitrary
//! provider/rvoip error text.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use rvoip_amazon_connect::{ScreenPopLifecycleEvent, ScreenPopLifecycleStage};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;

pub const DEFAULT_SCREEN_POP_EVIDENCE_TTL: Duration = Duration::from_secs(15 * 60);
pub const DEFAULT_SCREEN_POP_EVIDENCE_CAPACITY: usize = 10_000;
const MAX_CORRELATION_ID_BYTES: usize = 256;
const FINGERPRINT_HEX_CHARS: usize = 12;

/// A finite, ordered stage in the SIP -> Amazon Connect handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreenPopStage {
    SipInviteReceived,
    AttributesMapped,
    ContactStarted,
    MediaConnected,
    TeardownStarted,
    Terminated,
    Failed,
}

impl ScreenPopStage {
    fn rank(self) -> u8 {
        match self {
            Self::SipInviteReceived => 0,
            Self::AttributesMapped => 1,
            Self::ContactStarted => 2,
            Self::MediaConnected => 3,
            Self::TeardownStarted => 4,
            Self::Terminated | Self::Failed => 5,
        }
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Terminated | Self::Failed)
    }

    fn metric_label(self) -> &'static str {
        match self {
            Self::SipInviteReceived => "sip_invite_received",
            Self::AttributesMapped => "attributes_mapped",
            Self::ContactStarted => "contact_started",
            Self::MediaConnected => "media_connected",
            Self::TeardownStarted => "teardown_started",
            Self::Terminated => "terminated",
            Self::Failed => "failed",
        }
    }
}

/// Sanitized terminal outcomes. Callers map transport-specific details into
/// this finite vocabulary before recording evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreenPopTerminalReason {
    NormalHangup,
    SipHangup,
    ConnectHangup,
    Cancelled,
    SetupTimeout,
    SignalingTimeout,
    MediaTimeout,
    ControlFailure,
    SignalingFailure,
    MediaFailure,
    Shutdown,
    InternalError,
}

/// One public lifecycle observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScreenPopObservedStage {
    pub observed: bool,
    pub at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_reason: Option<ScreenPopTerminalReason>,
}

/// Fixed-shape stage object used by the staging smoke contract. Declaration
/// order is lifecycle order, so serialized diagnostics remain easy to read.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ScreenPopStages {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sip_invite_received: Option<ScreenPopObservedStage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes_mapped: Option<ScreenPopObservedStage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_started: Option<ScreenPopObservedStage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_connected: Option<ScreenPopObservedStage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub teardown_started: Option<ScreenPopObservedStage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminated: Option<ScreenPopObservedStage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed: Option<ScreenPopObservedStage>,
}

/// Redacted response returned by the diagnostics API.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScreenPopEvidence {
    pub correlation_fingerprint: String,
    pub stages: ScreenPopStages,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ScreenPopEvidenceError {
    #[error("evidence TTL must be greater than zero")]
    InvalidTtl,
    #[error("evidence capacity must be greater than zero")]
    InvalidCapacity,
    #[error("correlation id must contain between 1 and {MAX_CORRELATION_ID_BYTES} bytes")]
    InvalidCorrelationId,
    #[error("the first evidence stage must be sip_invite_received")]
    MissingInitialStage,
    #[error("terminal stages require a sanitized terminal reason")]
    MissingTerminalReason,
    #[error("non-terminal stages cannot carry a terminal reason")]
    UnexpectedTerminalReason,
    #[error("stage was recorded out of order")]
    OutOfOrder,
    #[error("stage timestamp precedes the previous stage")]
    TimestampRegression,
    #[error("a conflicting duplicate stage was recorded")]
    ConflictingDuplicate,
    #[error("evidence is already terminal")]
    AlreadyTerminal,
}

trait MonotonicClock: Send + Sync {
    fn now(&self) -> Instant;
}

struct SystemClock;

impl MonotonicClock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Clone)]
pub struct ScreenPopEvidenceStore {
    inner: Arc<Mutex<StoreInner>>,
    ttl: Duration,
    capacity: usize,
    clock: Arc<dyn MonotonicClock>,
}

struct StoreInner {
    entries: HashMap<String, EvidenceEntry>,
    age_index: BTreeMap<u64, String>,
    next_sequence: u64,
}

struct EvidenceEntry {
    stages: Vec<StoredStage>,
    touched_at: Instant,
    sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredStage {
    stage: ScreenPopStage,
    at: DateTime<Utc>,
    terminal_reason: Option<ScreenPopTerminalReason>,
}

impl ScreenPopEvidenceStore {
    pub fn new(ttl: Duration, capacity: usize) -> Result<Self, ScreenPopEvidenceError> {
        Self::with_clock(ttl, capacity, Arc::new(SystemClock))
    }

    fn with_clock(
        ttl: Duration,
        capacity: usize,
        clock: Arc<dyn MonotonicClock>,
    ) -> Result<Self, ScreenPopEvidenceError> {
        if ttl.is_zero() {
            return Err(ScreenPopEvidenceError::InvalidTtl);
        }
        if capacity == 0 {
            return Err(ScreenPopEvidenceError::InvalidCapacity);
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(StoreInner {
                entries: HashMap::new(),
                age_index: BTreeMap::new(),
                next_sequence: 0,
            })),
            ttl,
            capacity,
            clock,
        })
    }

    /// Record a lifecycle observation using the process wall clock.
    pub fn record_now(
        &self,
        correlation_id: &str,
        stage: ScreenPopStage,
        terminal_reason: Option<ScreenPopTerminalReason>,
    ) -> Result<ScreenPopEvidence, ScreenPopEvidenceError> {
        self.record(correlation_id, stage, Utc::now(), terminal_reason)
    }

    /// Record a lifecycle observation with an event-supplied timestamp.
    ///
    /// Replaying an identical stage is idempotent and retains its original
    /// timestamp. New stages must be monotonic; terminal reasons use the
    /// finite [`ScreenPopTerminalReason`] vocabulary so diagnostics cannot
    /// leak arbitrary error text.
    pub fn record(
        &self,
        correlation_id: &str,
        stage: ScreenPopStage,
        at: DateTime<Utc>,
        terminal_reason: Option<ScreenPopTerminalReason>,
    ) -> Result<ScreenPopEvidence, ScreenPopEvidenceError> {
        validate_correlation_id(correlation_id)?;
        validate_reason(stage, terminal_reason)?;

        let now = self.clock.now();
        let mut inner = self.lock();
        purge_expired(&mut inner, now, self.ttl);

        if let Some(entry) = inner.entries.get(correlation_id) {
            if let Some(existing) = entry.stages.iter().find(|seen| seen.stage == stage) {
                if existing.terminal_reason != terminal_reason {
                    record_metric(stage, "rejected");
                    return Err(ScreenPopEvidenceError::ConflictingDuplicate);
                }
                record_metric(stage, "duplicate");
                return Ok(self.snapshot(correlation_id, &entry.stages));
            }
            let last = entry.stages.last().expect("stored evidence has one stage");
            if last.stage.is_terminal() {
                record_metric(stage, "rejected");
                return Err(ScreenPopEvidenceError::AlreadyTerminal);
            }
            if stage.rank() <= last.stage.rank() {
                record_metric(stage, "rejected");
                return Err(ScreenPopEvidenceError::OutOfOrder);
            }
            if at < last.at {
                record_metric(stage, "rejected");
                return Err(ScreenPopEvidenceError::TimestampRegression);
            }
        } else if stage != ScreenPopStage::SipInviteReceived {
            record_metric(stage, "rejected");
            return Err(ScreenPopEvidenceError::MissingInitialStage);
        }

        if !inner.entries.contains_key(correlation_id) && inner.entries.len() >= self.capacity {
            evict_oldest(&mut inner);
            metrics::counter!(
                "bridgefu_screen_pop_evidence_evictions_total",
                "reason" => "capacity"
            )
            .increment(1);
        }

        let sequence = next_sequence(&mut inner);
        if let Some(old_sequence) = inner
            .entries
            .get(correlation_id)
            .map(|entry| entry.sequence)
        {
            inner.age_index.remove(&old_sequence);
            let entry = inner
                .entries
                .get_mut(correlation_id)
                .expect("entry existed before age-index update");
            entry.stages.push(StoredStage {
                stage,
                at,
                terminal_reason,
            });
            entry.touched_at = now;
            entry.sequence = sequence;
        } else {
            inner.entries.insert(
                correlation_id.to_owned(),
                EvidenceEntry {
                    stages: vec![StoredStage {
                        stage,
                        at,
                        terminal_reason,
                    }],
                    touched_at: now,
                    sequence,
                },
            );
        }
        inner.age_index.insert(sequence, correlation_id.to_owned());
        let snapshot = self.snapshot(
            correlation_id,
            &inner
                .entries
                .get(correlation_id)
                .expect("entry was inserted")
                .stages,
        );
        metrics::gauge!("bridgefu_screen_pop_evidence_entries").set(inner.entries.len() as f64);
        record_metric(stage, "recorded");
        Ok(snapshot)
    }

    /// Return a redacted snapshot. Lookups do not extend the TTL.
    pub fn get(&self, correlation_id: &str) -> Option<ScreenPopEvidence> {
        if validate_correlation_id(correlation_id).is_err() {
            return None;
        }
        let now = self.clock.now();
        let mut inner = self.lock();
        purge_expired(&mut inner, now, self.ttl);
        inner
            .entries
            .get(correlation_id)
            .map(|entry| self.snapshot(correlation_id, &entry.stages))
    }

    pub fn len(&self) -> usize {
        let now = self.clock.now();
        let mut inner = self.lock();
        purge_expired(&mut inner, now, self.ttl);
        inner.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn snapshot(&self, correlation_id: &str, stages: &[StoredStage]) -> ScreenPopEvidence {
        let mut public_stages = ScreenPopStages::default();
        for stage in stages {
            let observed = Some(ScreenPopObservedStage {
                observed: true,
                at: stage.at,
                terminal_reason: stage.terminal_reason,
            });
            match stage.stage {
                ScreenPopStage::SipInviteReceived => public_stages.sip_invite_received = observed,
                ScreenPopStage::AttributesMapped => public_stages.attributes_mapped = observed,
                ScreenPopStage::ContactStarted => public_stages.contact_started = observed,
                ScreenPopStage::MediaConnected => public_stages.media_connected = observed,
                ScreenPopStage::TeardownStarted => public_stages.teardown_started = observed,
                ScreenPopStage::Terminated => public_stages.terminated = observed,
                ScreenPopStage::Failed => public_stages.failed = observed,
            }
        }
        ScreenPopEvidence {
            correlation_fingerprint: fingerprint(correlation_id),
            stages: public_stages,
        }
    }

    fn lock(&self) -> MutexGuard<'_, StoreInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Start the Bridgefu consumer for rvoip's sanitized lifecycle feed.
///
/// The caller must create `receiver` with `server.subscribe_lifecycle()` before
/// starting `server.serve()`, otherwise the broadcast channel cannot replay
/// setup events emitted before subscription.
pub fn spawn_lifecycle_ingest(
    mut receiver: broadcast::Receiver<ScreenPopLifecycleEvent>,
    store: ScreenPopEvidenceStore,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                received = receiver.recv() => {
                    match received {
                        Ok(event) => {
                            record_lifecycle_event(&store, event);
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            metrics::counter!(
                                "bridgefu_screen_pop_lifecycle_errors_total",
                                "error" => "receiver_lagged"
                            )
                            .increment(skipped);
                            tracing::warn!(skipped, "screen-pop lifecycle receiver lagged");
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            metrics::counter!(
                                "bridgefu_screen_pop_lifecycle_errors_total",
                                "error" => "receiver_closed"
                            )
                            .increment(1);
                            break;
                        }
                    }
                }
            }
        }
    })
}

/// Map and record one rvoip lifecycle event. This is also the deterministic
/// seam used by the StandardCharter diagnostics contract test.
pub fn record_lifecycle_event(
    store: &ScreenPopEvidenceStore,
    event: ScreenPopLifecycleEvent,
) -> LifecycleRecordResult {
    let stage_label = lifecycle_stage_label(event.stage);
    let lag = Utc::now()
        .signed_duration_since(event.occurred_at)
        .to_std()
        .unwrap_or_default()
        .as_secs_f64();
    metrics::histogram!(
        "bridgefu_screen_pop_lifecycle_lag_seconds",
        "stage" => stage_label
    )
    .record(lag);

    let Some(correlation_id) = event.correlation_id.as_deref() else {
        metrics::counter!(
            "bridgefu_screen_pop_lifecycle_errors_total",
            "error" => "missing_correlation"
        )
        .increment(1);
        return LifecycleRecordResult::MissingCorrelation;
    };
    let (stage, terminal_reason) = map_lifecycle_stage(event.stage);
    match store.record(correlation_id, stage, event.occurred_at, terminal_reason) {
        Ok(_) => {
            metrics::counter!(
                "bridgefu_screen_pop_lifecycle_events_total",
                "stage" => stage_label,
                "result" => "recorded"
            )
            .increment(1);
            LifecycleRecordResult::Recorded
        }
        Err(error) => {
            metrics::counter!(
                "bridgefu_screen_pop_lifecycle_events_total",
                "stage" => stage_label,
                "result" => "rejected"
            )
            .increment(1);
            metrics::counter!(
                "bridgefu_screen_pop_lifecycle_errors_total",
                "error" => "store_rejected"
            )
            .increment(1);
            tracing::warn!(stage = stage_label, error = %error, "screen-pop lifecycle evidence rejected");
            LifecycleRecordResult::Rejected(error)
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum LifecycleRecordResult {
    Recorded,
    MissingCorrelation,
    Rejected(ScreenPopEvidenceError),
}

fn map_lifecycle_stage(
    stage: ScreenPopLifecycleStage,
) -> (ScreenPopStage, Option<ScreenPopTerminalReason>) {
    match stage {
        ScreenPopLifecycleStage::SipInviteReceived => (ScreenPopStage::SipInviteReceived, None),
        ScreenPopLifecycleStage::AttributesMapped => (ScreenPopStage::AttributesMapped, None),
        ScreenPopLifecycleStage::ContactStarted => (ScreenPopStage::ContactStarted, None),
        ScreenPopLifecycleStage::MediaConnected => (ScreenPopStage::MediaConnected, None),
        ScreenPopLifecycleStage::TeardownStarted => (ScreenPopStage::TeardownStarted, None),
        ScreenPopLifecycleStage::Terminated => (
            ScreenPopStage::Terminated,
            Some(ScreenPopTerminalReason::NormalHangup),
        ),
        ScreenPopLifecycleStage::Failed => (
            ScreenPopStage::Failed,
            Some(ScreenPopTerminalReason::InternalError),
        ),
    }
}

fn lifecycle_stage_label(stage: ScreenPopLifecycleStage) -> &'static str {
    match stage {
        ScreenPopLifecycleStage::SipInviteReceived => "sip_invite_received",
        ScreenPopLifecycleStage::AttributesMapped => "attributes_mapped",
        ScreenPopLifecycleStage::ContactStarted => "contact_started",
        ScreenPopLifecycleStage::MediaConnected => "media_connected",
        ScreenPopLifecycleStage::TeardownStarted => "teardown_started",
        ScreenPopLifecycleStage::Terminated => "terminated",
        ScreenPopLifecycleStage::Failed => "failed",
    }
}

fn validate_correlation_id(correlation_id: &str) -> Result<(), ScreenPopEvidenceError> {
    if correlation_id.is_empty() || correlation_id.len() > MAX_CORRELATION_ID_BYTES {
        return Err(ScreenPopEvidenceError::InvalidCorrelationId);
    }
    Ok(())
}

fn validate_reason(
    stage: ScreenPopStage,
    terminal_reason: Option<ScreenPopTerminalReason>,
) -> Result<(), ScreenPopEvidenceError> {
    match (stage.is_terminal(), terminal_reason) {
        (true, None) => Err(ScreenPopEvidenceError::MissingTerminalReason),
        (false, Some(_)) => Err(ScreenPopEvidenceError::UnexpectedTerminalReason),
        _ => Ok(()),
    }
}

fn next_sequence(inner: &mut StoreInner) -> u64 {
    let sequence = inner.next_sequence;
    inner.next_sequence = inner.next_sequence.wrapping_add(1);
    sequence
}

fn purge_expired(inner: &mut StoreInner, now: Instant, ttl: Duration) {
    while let Some((&sequence, correlation_id)) = inner.age_index.first_key_value() {
        let correlation_id = correlation_id.clone();
        let expired = inner
            .entries
            .get(&correlation_id)
            .map(|entry| now.saturating_duration_since(entry.touched_at) >= ttl)
            .unwrap_or(true);
        if !expired {
            break;
        }
        inner.age_index.remove(&sequence);
        inner.entries.remove(&correlation_id);
        metrics::counter!(
            "bridgefu_screen_pop_evidence_evictions_total",
            "reason" => "ttl"
        )
        .increment(1);
    }
}

fn evict_oldest(inner: &mut StoreInner) {
    if let Some((sequence, correlation_id)) = inner
        .age_index
        .first_key_value()
        .map(|(sequence, correlation_id)| (*sequence, correlation_id.clone()))
    {
        inner.age_index.remove(&sequence);
        inner.entries.remove(&correlation_id);
    }
}

fn fingerprint(correlation_id: &str) -> String {
    let digest = Sha256::digest(correlation_id.as_bytes());
    let mut output = String::with_capacity(FINGERPRINT_HEX_CHARS);
    for byte in &digest[..FINGERPRINT_HEX_CHARS / 2] {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn record_metric(stage: ScreenPopStage, result: &'static str) {
    metrics::counter!(
        "bridgefu_screen_pop_evidence_records_total",
        "stage" => stage.metric_label(),
        "result" => result
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;
    use metrics_exporter_prometheus::PrometheusBuilder;

    struct ManualClock(Mutex<Instant>);

    impl ManualClock {
        fn new() -> Arc<Self> {
            Arc::new(Self(Mutex::new(Instant::now())))
        }

        fn advance(&self, duration: Duration) {
            let mut now = self.0.lock().expect("manual clock lock");
            *now += duration;
        }
    }

    impl MonotonicClock for ManualClock {
        fn now(&self) -> Instant {
            *self.0.lock().expect("manual clock lock")
        }
    }

    fn store(clock: Arc<ManualClock>, ttl: Duration, capacity: usize) -> ScreenPopEvidenceStore {
        ScreenPopEvidenceStore::with_clock(ttl, capacity, clock).expect("valid store")
    }

    #[test]
    fn stages_are_ordered_and_identical_replays_are_idempotent() {
        let clock = ManualClock::new();
        let store = store(clock, Duration::from_secs(60), 4);
        let at = Utc::now();
        let first = store
            .record("corr-1", ScreenPopStage::SipInviteReceived, at, None)
            .unwrap();
        let duplicate = store
            .record(
                "corr-1",
                ScreenPopStage::SipInviteReceived,
                at + TimeDelta::seconds(5),
                None,
            )
            .unwrap();
        assert_eq!(first, duplicate);

        store
            .record(
                "corr-1",
                ScreenPopStage::AttributesMapped,
                at + TimeDelta::seconds(1),
                None,
            )
            .unwrap();
        let terminal = store
            .record(
                "corr-1",
                ScreenPopStage::Failed,
                at + TimeDelta::seconds(2),
                Some(ScreenPopTerminalReason::SignalingTimeout),
            )
            .unwrap();
        let serialized = serde_json::to_string(&terminal).unwrap();
        let invite = serialized.find("sip_invite_received").unwrap();
        let mapped = serialized.find("attributes_mapped").unwrap();
        let failed = serialized.find("failed").unwrap();
        assert!(invite < mapped && mapped < failed);
        assert!(terminal.stages.sip_invite_received.is_some());
        assert!(terminal.stages.attributes_mapped.is_some());
        assert_eq!(
            terminal
                .stages
                .failed
                .as_ref()
                .and_then(|stage| stage.terminal_reason),
            Some(ScreenPopTerminalReason::SignalingTimeout)
        );
        assert!(terminal.stages.failed.as_ref().unwrap().observed);
        assert_eq!(
            store.record(
                "corr-1",
                ScreenPopStage::MediaConnected,
                at + TimeDelta::seconds(3),
                None,
            ),
            Err(ScreenPopEvidenceError::AlreadyTerminal)
        );
    }

    #[test]
    fn rejects_out_of_order_and_regressing_timestamps() {
        let clock = ManualClock::new();
        let store = store(clock, Duration::from_secs(60), 4);
        let at = Utc::now();
        assert_eq!(
            store.record("corr-1", ScreenPopStage::ContactStarted, at, None),
            Err(ScreenPopEvidenceError::MissingInitialStage)
        );
        store
            .record("corr-1", ScreenPopStage::SipInviteReceived, at, None)
            .unwrap();
        store
            .record(
                "corr-1",
                ScreenPopStage::ContactStarted,
                at + TimeDelta::seconds(2),
                None,
            )
            .unwrap();
        assert_eq!(
            store.record(
                "corr-1",
                ScreenPopStage::AttributesMapped,
                at + TimeDelta::seconds(3),
                None,
            ),
            Err(ScreenPopEvidenceError::OutOfOrder)
        );
        assert_eq!(
            store.record(
                "corr-1",
                ScreenPopStage::MediaConnected,
                at + TimeDelta::seconds(1),
                None,
            ),
            Err(ScreenPopEvidenceError::TimestampRegression)
        );
    }

    #[test]
    fn ttl_and_capacity_bound_memory() {
        let clock = ManualClock::new();
        let store = store(clock.clone(), Duration::from_secs(10), 2);
        let at = Utc::now();
        store
            .record("oldest", ScreenPopStage::SipInviteReceived, at, None)
            .unwrap();
        clock.advance(Duration::from_secs(1));
        store
            .record("middle", ScreenPopStage::SipInviteReceived, at, None)
            .unwrap();
        clock.advance(Duration::from_secs(1));
        store
            .record("newest", ScreenPopStage::SipInviteReceived, at, None)
            .unwrap();
        assert_eq!(store.len(), 2);
        assert!(store.get("oldest").is_none());
        assert!(store.get("middle").is_some());

        clock.advance(Duration::from_secs(10));
        assert_eq!(store.len(), 0);
        assert!(store.get("newest").is_none());
    }

    #[test]
    fn response_and_metrics_never_expose_raw_correlation_ids() {
        let clock = ManualClock::new();
        let store = store(clock, Duration::from_secs(60), 4);
        let correlation = "+14155550199-super-secret";
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let evidence = metrics::with_local_recorder(&recorder, || {
            store
                .record_now(correlation, ScreenPopStage::SipInviteReceived, None)
                .unwrap()
        });

        let body = serde_json::to_string(&evidence).unwrap();
        assert!(!body.contains(correlation));
        assert_eq!(evidence.correlation_fingerprint.len(), 12);
        assert!(evidence
            .correlation_fingerprint
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase()));
        let metrics = handle.render();
        assert!(!metrics.contains(correlation));
        assert!(metrics.contains("stage=\"sip_invite_received\""));
        assert!(!metrics.contains("correlation_id="));
    }

    #[test]
    fn rvoip_lifecycle_feed_matches_standardcharter_diagnostics_contract() {
        let clock = ManualClock::new();
        let store = store(clock, Duration::from_secs(60), 4);
        let correlation = "+14155550199";
        let base = DateTime::parse_from_rfc3339("2026-07-10T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        metrics::with_local_recorder(&recorder, || {
            for (offset, stage) in [
                ScreenPopLifecycleStage::SipInviteReceived,
                ScreenPopLifecycleStage::AttributesMapped,
                ScreenPopLifecycleStage::ContactStarted,
                ScreenPopLifecycleStage::MediaConnected,
                ScreenPopLifecycleStage::TeardownStarted,
                ScreenPopLifecycleStage::Terminated,
            ]
            .into_iter()
            .enumerate()
            {
                assert_eq!(
                    record_lifecycle_event(
                        &store,
                        ScreenPopLifecycleEvent {
                            stage,
                            correlation_id: Some(correlation.into()),
                            occurred_at: base + TimeDelta::seconds(offset as i64),
                        },
                    ),
                    LifecycleRecordResult::Recorded
                );
            }
        });

        let evidence = store.get(correlation).expect("correlated evidence");
        let json = serde_json::to_value(&evidence).unwrap();
        let serialized = serde_json::to_string(&json).unwrap();
        assert!(!serialized.contains(correlation));
        assert_eq!(json.as_object().unwrap().len(), 2);
        assert_eq!(json["correlation_fingerprint"], "e8d461284346");
        for stage in [
            "sip_invite_received",
            "attributes_mapped",
            "contact_started",
            "media_connected",
            "teardown_started",
            "terminated",
        ] {
            assert_eq!(json["stages"][stage]["observed"], true);
            assert!(json["stages"][stage]["at"].is_string());
        }
        assert_eq!(
            json["stages"]["terminated"]["terminal_reason"],
            "normal_hangup"
        );
        assert!(json["stages"].get("failed").is_none());

        let metrics = handle.render();
        assert!(!metrics.contains(correlation));
        assert!(!metrics.contains("correlation_id="));
        assert!(metrics.contains("stage=\"media_connected\""));
        assert!(metrics.contains("stage=\"terminated\""));

        let failed_correlation = "failed-correlation";
        assert_eq!(
            record_lifecycle_event(
                &store,
                ScreenPopLifecycleEvent {
                    stage: ScreenPopLifecycleStage::SipInviteReceived,
                    correlation_id: Some(failed_correlation.into()),
                    occurred_at: base,
                },
            ),
            LifecycleRecordResult::Recorded
        );
        assert_eq!(
            record_lifecycle_event(
                &store,
                ScreenPopLifecycleEvent {
                    stage: ScreenPopLifecycleStage::Failed,
                    correlation_id: Some(failed_correlation.into()),
                    occurred_at: base + TimeDelta::seconds(1),
                },
            ),
            LifecycleRecordResult::Recorded
        );
        assert_eq!(
            store
                .get(failed_correlation)
                .unwrap()
                .stages
                .failed
                .unwrap()
                .terminal_reason,
            Some(ScreenPopTerminalReason::InternalError)
        );
        assert_eq!(
            record_lifecycle_event(
                &store,
                ScreenPopLifecycleEvent {
                    stage: ScreenPopLifecycleStage::SipInviteReceived,
                    correlation_id: None,
                    occurred_at: base,
                },
            ),
            LifecycleRecordResult::MissingCorrelation
        );
    }

    #[tokio::test]
    async fn lifecycle_ingest_stops_on_shutdown() {
        let clock = ManualClock::new();
        let store = store(clock, Duration::from_secs(60), 4);
        let (events_tx, events_rx) = broadcast::channel(4);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = spawn_lifecycle_ingest(events_rx, store.clone(), shutdown_rx);
        events_tx
            .send(ScreenPopLifecycleEvent {
                stage: ScreenPopLifecycleStage::SipInviteReceived,
                correlation_id: Some("corr-shutdown".into()),
                occurred_at: Utc::now(),
            })
            .unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            while store.get("corr-shutdown").is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("lifecycle event was consumed");
        shutdown_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("lifecycle task stopped")
            .expect("lifecycle task did not panic");
    }
}
