//! Manual Gate 11 UCTP direct-fanout qualification.
//!
//! This exercises the bounded, nonblocking `UctpBroadcastPublisher` target
//! fanout used by authenticated network listeners. It is intentionally ignored
//! and a smoke run is never represented as one-hour release evidence.

#[path = "support/qualification.rs"]
mod qualification_support;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use metrics_exporter_prometheus::PrometheusBuilder;
use qualification_support::{
    bounded_environment_u64, bounded_environment_usize, current_rss_bytes, git_revision,
    host_evidence, memory_growth_percent, prometheus_counter_sum, rvoip_registry_evidence,
    write_report, HostEvidence, LatencyHistogram, QualificationMode, RevisionEvidence,
    RvoipRegistryEvidence,
};
use rvoip_core::broadcast::{BroadcastPublisher, BroadcastTransport};
use rvoip_core::ids::StreamId;
use rvoip_core::stream::{MediaFrame, StreamKind};
use rvoip_quic::UctpBroadcastPublisher;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const FRAME_PERIOD: Duration = Duration::from_millis(20);
const RELEASE_LISTENERS: usize = 1_000;
const RELEASE_DURATION: Duration = Duration::from_secs(60 * 60);
const RELEASE_WARMUP: Duration = Duration::from_secs(5 * 60);
const MAX_RELEASE_P95_US: u64 = 100_000;
const MAX_RELEASE_MEMORY_GROWTH_PERCENT: f64 = 10.0;
const MIN_DELIVERY_RATIO: f64 = 0.99;
const OPUS_SILENCE: &[u8] = &[0x78, 0x00];

#[derive(Clone, Copy)]
struct QualificationParameters {
    listeners: usize,
    active_duration: Duration,
    warmup: Duration,
}

impl QualificationMode {
    fn uctp_parameters(self) -> QualificationParameters {
        match self {
            Self::Release => QualificationParameters {
                listeners: RELEASE_LISTENERS,
                active_duration: RELEASE_DURATION,
                warmup: RELEASE_WARMUP,
            },
            Self::Smoke => QualificationParameters {
                listeners: bounded_environment_usize(
                    "BRIDGEFU_UCTP_SMOKE_LISTENERS",
                    32,
                    1,
                    RELEASE_LISTENERS,
                ),
                active_duration: Duration::from_secs(bounded_environment_u64(
                    "BRIDGEFU_UCTP_SMOKE_SECONDS",
                    5,
                    3,
                    60,
                )),
                warmup: Duration::from_secs(1),
            },
        }
    }
}

#[derive(Default)]
struct FanoutCounters {
    source_frames_sent: AtomicU64,
    source_frames_dropped: AtomicU64,
    deliveries: AtomicU64,
}

#[derive(Serialize)]
struct UctpQualificationReport {
    schema: &'static str,
    mode: QualificationMode,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    bridgefu: RevisionEvidence,
    rvoip: RvoipRegistryEvidence,
    host: HostEvidence,
    transport: BroadcastTransport,
    protocol_version: String,
    listeners: usize,
    listener_capacity: usize,
    capacity_rejection_verified: bool,
    active_elapsed_ms: u128,
    source_frames_sent: u64,
    source_frames_dropped: u64,
    expected_deliveries: u64,
    deliveries: u64,
    delivery_ratio: f64,
    minimum_listener_deliveries: u64,
    maximum_listener_deliveries: u64,
    publisher_dropped_frames: u64,
    latency_p95_upper_bound_us: Option<u64>,
    warmup_rss_bytes: Option<u64>,
    final_rss_bytes: Option<u64>,
    steady_state_memory_growth_percent: Option<f64>,
    release_thresholds: ReleaseThresholds,
    scope: &'static str,
    passed: bool,
}

#[derive(Serialize)]
struct ReleaseThresholds {
    listeners: usize,
    active_duration_seconds: u64,
    minimum_delivery_ratio: f64,
    latency_p95_us: u64,
    steady_state_memory_growth_percent: f64,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "manual Gate 11 UCTP fanout qualification; select smoke or release explicitly"]
async fn qualifies_uctp_direct_fanout() {
    let mode = QualificationMode::from_environment("UCTP fanout");
    let parameters = mode.uctp_parameters();
    assert!(parameters.warmup < parameters.active_duration);

    let metrics = PrometheusBuilder::new()
        .install_recorder()
        .expect("install isolated qualification metrics recorder");
    let started_at = Utc::now();
    let wall_started = Instant::now();
    let publisher =
        UctpBroadcastPublisher::new("qualification-session", "audio/main", 10, RELEASE_LISTENERS)
            .expect("construct bounded UCTP publisher");
    let descriptor = publisher.descriptor();
    assert_eq!(descriptor.transport, BroadcastTransport::UctpQuic);

    let counters = Arc::new(FanoutCounters::default());
    let latency = Arc::new(LatencyHistogram::new());
    let mut registrations = Vec::with_capacity(parameters.listeners);
    let mut receivers = Vec::with_capacity(parameters.listeners);
    for _ in 0..parameters.listeners {
        let (target, receiver) = mpsc::channel(10);
        registrations.push(
            publisher
                .add_subscriber(target)
                .expect("admit direct UCTP listener target"),
        );
        receivers.push(spawn_listener(
            receiver,
            Arc::clone(&counters),
            Arc::clone(&latency),
        ));
    }
    assert_eq!(publisher.subscriber_count(), parameters.listeners);

    let capacity_rejection_verified = if parameters.listeners == RELEASE_LISTENERS {
        let (overflow, _receiver) = mpsc::channel(1);
        publisher.add_subscriber(overflow).is_err()
    } else {
        // Smoke still proves the configured release ceiling without allocating
        // an additional 1,000 receiver tasks.
        let capacity_probe = UctpBroadcastPublisher::new("capacity", "audio/main", 1, 1).unwrap();
        let (first, _first_receiver) = mpsc::channel(1);
        let (overflow, _overflow_receiver) = mpsc::channel(1);
        capacity_probe.add_subscriber(first).unwrap();
        let rejected = capacity_probe.add_subscriber(overflow).is_err();
        Arc::clone(&capacity_probe).close().await.unwrap();
        rejected
    };
    assert!(capacity_rejection_verified);

    let cancellation = CancellationToken::new();
    let source = spawn_source(
        publisher.frames_out(),
        Arc::clone(&counters),
        cancellation.clone(),
    );
    tokio::time::sleep(parameters.warmup).await;
    let warmup_rss_bytes = current_rss_bytes();
    tokio::time::sleep(parameters.active_duration - parameters.warmup).await;
    let final_rss_bytes = current_rss_bytes();
    let active_elapsed = wall_started.elapsed();

    cancellation.cancel();
    source.await.expect("UCTP source task panicked");
    let source_frames_sent = counters.source_frames_sent.load(Ordering::Relaxed);
    let expected_deliveries = source_frames_sent.saturating_mul(parameters.listeners as u64);
    wait_for_delivery_quiescence(&counters.deliveries, expected_deliveries).await;

    for registration in registrations {
        assert!(publisher.remove_subscriber(registration));
    }
    Arc::clone(&publisher)
        .close()
        .await
        .expect("close UCTP publisher");
    let listener_deliveries = join_receivers(receivers).await;
    let deliveries = listener_deliveries.iter().sum::<u64>();
    let minimum_listener_deliveries = listener_deliveries.iter().copied().min().unwrap_or(0);
    let maximum_listener_deliveries = listener_deliveries.iter().copied().max().unwrap_or(0);
    assert_eq!(deliveries, counters.deliveries.load(Ordering::Relaxed));

    let source_frames_dropped = counters.source_frames_dropped.load(Ordering::Relaxed);
    let delivery_ratio = if expected_deliveries == 0 {
        0.0
    } else {
        deliveries as f64 / expected_deliveries as f64
    };
    let latency_p95_upper_bound_us = latency.percentile_upper_bound_us(0.95);
    let steady_state_memory_growth_percent =
        memory_growth_percent(warmup_rss_bytes, final_rss_bytes);
    let publisher_dropped_frames = prometheus_counter_sum(
        &metrics.render(),
        "rvoip_uctp_broadcast_dropped_frames_total",
    );
    let nominal_frames = parameters.active_duration.as_millis() as u64 / 20;
    let minimum_source_frames = nominal_frames.saturating_mul(9) / 10;
    let common_passed = capacity_rejection_verified
        && source_frames_sent >= minimum_source_frames
        && source_frames_dropped == 0
        && deliveries <= expected_deliveries
        && delivery_ratio >= MIN_DELIVERY_RATIO
        && minimum_listener_deliveries > 0
        && publisher_dropped_frames == expected_deliveries.saturating_sub(deliveries);
    let passed = common_passed
        && match mode {
            QualificationMode::Smoke => {
                latency_p95_upper_bound_us.is_some_and(|value| value <= MAX_RELEASE_P95_US * 2)
            }
            QualificationMode::Release => {
                active_elapsed >= RELEASE_DURATION
                    && latency_p95_upper_bound_us.is_some_and(|value| value <= MAX_RELEASE_P95_US)
                    && steady_state_memory_growth_percent
                        .is_some_and(|value| value < MAX_RELEASE_MEMORY_GROWTH_PERCENT)
            }
        };

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let report = UctpQualificationReport {
        schema: "bridgefu.qualification.uctp-fanout.v2",
        mode,
        started_at,
        finished_at: Utc::now(),
        bridgefu: git_revision(&manifest_dir),
        rvoip: rvoip_registry_evidence(&manifest_dir),
        host: host_evidence(),
        transport: descriptor.transport,
        protocol_version: descriptor.protocol_version,
        listeners: parameters.listeners,
        listener_capacity: RELEASE_LISTENERS,
        capacity_rejection_verified,
        active_elapsed_ms: active_elapsed.as_millis(),
        source_frames_sent,
        source_frames_dropped,
        expected_deliveries,
        deliveries,
        delivery_ratio,
        minimum_listener_deliveries,
        maximum_listener_deliveries,
        publisher_dropped_frames,
        latency_p95_upper_bound_us,
        warmup_rss_bytes,
        final_rss_bytes,
        steady_state_memory_growth_percent,
        release_thresholds: ReleaseThresholds {
            listeners: RELEASE_LISTENERS,
            active_duration_seconds: RELEASE_DURATION.as_secs(),
            minimum_delivery_ratio: MIN_DELIVERY_RATIO,
            latency_p95_us: MAX_RELEASE_P95_US,
            steady_state_memory_growth_percent: MAX_RELEASE_MEMORY_GROWTH_PERCENT,
        },
        scope: "in-process UctpBroadcastPublisher fanout to already-authenticated network target queues; QUIC handshake and RTP datagram wire behavior are outside this harness",
        passed,
    };
    let report_path = write_report(
        &manifest_dir,
        "BRIDGEFU_UCTP_QUALIFICATION_OUTPUT",
        "uctp-fanout",
        started_at,
        &report,
    );
    eprintln!("UCTP qualification report: {}", report_path.display());
    eprintln!(
        "UCTP qualification wall time: {:.2?}",
        wall_started.elapsed()
    );
    assert!(
        passed,
        "UCTP fanout qualification failed; retained evidence is at {}",
        report_path.display()
    );
}

fn spawn_source(
    sender: mpsc::Sender<MediaFrame>,
    counters: Arc<FanoutCounters>,
    cancellation: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let stream_id = StreamId::new();
        let mut timestamp = 0_u32;
        let mut interval = tokio::time::interval_at(tokio::time::Instant::now(), FRAME_PERIOD);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => break,
                _ = interval.tick() => {
                    let frame = MediaFrame {
                        stream_id: stream_id.clone(),
                        kind: StreamKind::Audio,
                        payload: Bytes::from_static(OPUS_SILENCE),
                        timestamp_rtp: timestamp,
                        captured_at: Utc::now(),
                        payload_type: Some(111),
                    };
                    timestamp = timestamp.wrapping_add(960);
                    match sender.try_send(frame) {
                        Ok(()) => {
                            counters.source_frames_sent.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            counters.source_frames_dropped.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => break,
                    }
                }
            }
        }
    })
}

fn spawn_listener(
    mut receiver: mpsc::Receiver<MediaFrame>,
    counters: Arc<FanoutCounters>,
    latency: Arc<LatencyHistogram>,
) -> JoinHandle<u64> {
    tokio::spawn(async move {
        let mut received = 0_u64;
        while let Some(frame) = receiver.recv().await {
            latency.observe(frame.captured_at);
            received = received.saturating_add(1);
            counters.deliveries.fetch_add(1, Ordering::Relaxed);
        }
        received
    })
}

async fn wait_for_delivery_quiescence(deliveries: &AtomicU64, expected: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut previous = deliveries.load(Ordering::Relaxed);
    let mut unchanged = 0_u8;
    while tokio::time::Instant::now() < deadline && previous < expected {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let current = deliveries.load(Ordering::Relaxed);
        if current == previous {
            unchanged = unchanged.saturating_add(1);
            if unchanged >= 5 {
                break;
            }
        } else {
            previous = current;
            unchanged = 0;
        }
    }
}

async fn join_receivers(receivers: Vec<JoinHandle<u64>>) -> Vec<u64> {
    let mut totals = Vec::with_capacity(receivers.len());
    for receiver in receivers {
        totals.push(receiver.await.expect("UCTP listener task panicked"));
    }
    totals
}
