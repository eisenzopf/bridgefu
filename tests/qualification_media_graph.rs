//! Manual Gate 11 worker-media qualification.
//!
//! This ignored test is deliberately not release evidence unless it runs in
//! `release` mode. The release profile fixes the acceptance parameters at 100
//! bidirectional PCMU<->Opus calls, a 10 call/s ramp, and one hour with every
//! call active. A short `smoke` profile exercises the same code without
//! representing itself as completion of the release gate.

#[path = "support/qualification.rs"]
mod qualification_support;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures_util::future::join_all;
use qualification_support::{rvoip_registry_evidence, RvoipRegistryEvidence};
use rvoip_core::capability::CodecInfo;
use rvoip_core::ids::StreamId;
use rvoip_core::media_graph::{ManagedMediaRoute, MediaGraphHandle};
use rvoip_core::stream::{MediaFrame, StreamKind};
use rvoip_core::{start_media_graph, MediaGraphPolicy};
use rvoip_media_core::codec::audio::{AudioCodec, OpusCodec, OpusConfig};
use rvoip_media_core::types::{AudioFrame, SampleRate};
use serde::Serialize;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const FRAME_PERIOD: Duration = Duration::from_millis(20);
const RELEASE_CALLS: usize = 100;
const RELEASE_CALL_ATTEMPTS_PER_SECOND: u64 = 10;
const RELEASE_DURATION: Duration = Duration::from_secs(60 * 60);
const RELEASE_WARMUP: Duration = Duration::from_secs(5 * 60);
const MAX_RELEASE_P95_US: u64 = 100_000;
const MAX_RELEASE_MEMORY_GROWTH_PERCENT: f64 = 10.0;
const LATENCY_BUCKET_WIDTH_US: u64 = 100;
const LATENCY_MAX_US: u64 = 1_000_000;
const PCMU_SILENCE: [u8; 160] = [0xff; 160];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum QualificationMode {
    Smoke,
    Release,
}

impl QualificationMode {
    fn from_environment() -> Self {
        match env::var("BRIDGEFU_QUALIFICATION_MODE").as_deref() {
            Ok("smoke") => Self::Smoke,
            Ok("release") => {
                assert_eq!(
                    env::var("BRIDGEFU_QUALIFICATION_ACKNOWLEDGE_ONE_HOUR").as_deref(),
                    Ok("1"),
                    "release mode requires BRIDGEFU_QUALIFICATION_ACKNOWLEDGE_ONE_HOUR=1"
                );
                assert_eq!(
                    env::consts::OS,
                    "linux",
                    "release memory evidence is supported only on Linux"
                );
                Self::Release
            }
            Ok(other) => {
                panic!("invalid BRIDGEFU_QUALIFICATION_MODE={other:?}; expected smoke or release")
            }
            Err(_) => panic!(
                "set BRIDGEFU_QUALIFICATION_MODE=smoke or release before running this ignored test"
            ),
        }
    }

    fn parameters(self) -> QualificationParameters {
        match self {
            Self::Release => QualificationParameters {
                calls: RELEASE_CALLS,
                call_attempts_per_second: RELEASE_CALL_ATTEMPTS_PER_SECOND,
                active_duration: RELEASE_DURATION,
                warmup: RELEASE_WARMUP,
            },
            Self::Smoke => QualificationParameters {
                calls: bounded_environment_usize(
                    "BRIDGEFU_QUALIFICATION_SMOKE_CALLS",
                    4,
                    1,
                    RELEASE_CALLS,
                ),
                call_attempts_per_second: RELEASE_CALL_ATTEMPTS_PER_SECOND,
                active_duration: Duration::from_secs(bounded_environment_u64(
                    "BRIDGEFU_QUALIFICATION_SMOKE_SECONDS",
                    10,
                    3,
                    60,
                )),
                warmup: Duration::from_secs(2),
            },
        }
    }
}

#[derive(Clone, Copy)]
struct QualificationParameters {
    calls: usize,
    call_attempts_per_second: u64,
    active_duration: Duration,
    warmup: Duration,
}

#[derive(Default)]
struct LoadCounters {
    source_frames_sent: AtomicU64,
    source_frames_dropped: AtomicU64,
    sink_frames_received: AtomicU64,
}

struct LatencyHistogram {
    buckets: Vec<AtomicU64>,
    overflow: AtomicU64,
}

impl LatencyHistogram {
    fn new() -> Self {
        let bucket_count = (LATENCY_MAX_US / LATENCY_BUCKET_WIDTH_US) as usize + 1;
        Self {
            buckets: (0..bucket_count).map(|_| AtomicU64::new(0)).collect(),
            overflow: AtomicU64::new(0),
        }
    }

    fn observe(&self, captured_at: DateTime<Utc>) {
        let elapsed_us = Utc::now()
            .signed_duration_since(captured_at)
            .num_microseconds()
            .unwrap_or(i64::MAX)
            .max(0) as u64;
        let bucket = (elapsed_us / LATENCY_BUCKET_WIDTH_US) as usize;
        if let Some(counter) = self.buckets.get(bucket) {
            counter.fetch_add(1, Ordering::Relaxed);
        } else {
            self.overflow.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn percentile_upper_bound_us(&self, percentile: f64) -> Option<u64> {
        let bucket_counts = self
            .buckets
            .iter()
            .map(|bucket| bucket.load(Ordering::Relaxed))
            .collect::<Vec<_>>();
        let total = bucket_counts.iter().sum::<u64>() + self.overflow.load(Ordering::Relaxed);
        if total == 0 {
            return None;
        }
        let target = ((total as f64) * percentile).ceil() as u64;
        let mut seen = 0_u64;
        for (index, count) in bucket_counts.into_iter().enumerate() {
            seen = seen.saturating_add(count);
            if seen >= target {
                return Some(((index as u64) + 1) * LATENCY_BUCKET_WIDTH_US);
            }
        }
        Some(LATENCY_MAX_US.saturating_add(1))
    }
}

struct QualifiedCall {
    graphs: [MediaGraphHandle; 2],
    _routes: [ManagedMediaRoute; 2],
    tasks: Vec<JoinHandle<()>>,
}

#[derive(Serialize)]
struct RevisionEvidence {
    revision: String,
    dirty: bool,
}

#[derive(Serialize)]
struct HostEvidence {
    os: &'static str,
    architecture: &'static str,
    logical_cpus: usize,
    kernel: String,
}

#[derive(Serialize)]
struct MediaQualificationReport {
    schema: &'static str,
    mode: QualificationMode,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    bridgefu: RevisionEvidence,
    rvoip: RvoipRegistryEvidence,
    host: HostEvidence,
    calls: usize,
    media_graphs: usize,
    call_attempts_per_second: u64,
    setup_elapsed_ms: u128,
    all_calls_active_ms: u128,
    source_frames_sent: u64,
    source_frames_dropped: u64,
    sink_frames_received: u64,
    graph_dropped_frames: u64,
    graph_evictions: u64,
    graph_transcode_operations: u64,
    graph_transcode_errors: u64,
    latency_p95_upper_bound_us: Option<u64>,
    warmup_rss_bytes: Option<u64>,
    final_rss_bytes: Option<u64>,
    steady_state_memory_growth_percent: Option<f64>,
    release_thresholds: ReleaseThresholds,
    passed: bool,
}

#[derive(Serialize)]
struct ReleaseThresholds {
    calls: usize,
    call_attempts_per_second: u64,
    active_duration_seconds: u64,
    latency_p95_us: u64,
    steady_state_memory_growth_percent: f64,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "manual Gate 11 load qualification; select smoke or release explicitly"]
async fn qualifies_bidirectional_transcoded_worker_media() {
    let mode = QualificationMode::from_environment();
    let parameters = mode.parameters();
    assert!(parameters.warmup < parameters.active_duration);

    let started_at = Utc::now();
    let started = Instant::now();
    let counters = Arc::new(LoadCounters::default());
    let latency = Arc::new(LatencyHistogram::new());
    let cancellation = CancellationToken::new();
    let opus_silence = canonical_opus_silence();
    let ramp_period = Duration::from_secs_f64(1.0 / parameters.call_attempts_per_second as f64);
    let mut ramp = tokio::time::interval_at(tokio::time::Instant::now(), ramp_period);
    ramp.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let setup_started = Instant::now();
    let mut calls = Vec::with_capacity(parameters.calls);

    for _ in 0..parameters.calls {
        ramp.tick().await;
        calls.push(
            create_qualified_call(
                Arc::clone(&counters),
                Arc::clone(&latency),
                cancellation.clone(),
                opus_silence.clone(),
            )
            .await,
        );
    }
    let setup_elapsed = setup_started.elapsed();

    tokio::time::sleep(parameters.warmup).await;
    let warmup_rss_bytes = current_rss_bytes();
    tokio::time::sleep(parameters.active_duration - parameters.warmup).await;
    let final_rss_bytes = current_rss_bytes();
    let all_calls_active = setup_started.elapsed().saturating_sub(setup_elapsed);

    cancellation.cancel();
    for task in calls.iter_mut().flat_map(|call| call.tasks.drain(..)) {
        task.await.expect("qualification media task panicked");
    }

    let snapshots = join_all(
        calls
            .iter()
            .flat_map(|call| call.graphs.iter().cloned())
            .map(|graph| async move { graph.snapshot().await }),
    )
    .await;
    let graph_dropped_frames = snapshots
        .iter()
        .map(|snapshot| snapshot.dropped_frames)
        .sum();
    let graph_evictions = snapshots.iter().map(|snapshot| snapshot.evictions).sum();
    let graph_transcode_operations = snapshots
        .iter()
        .map(|snapshot| snapshot.transcode_operations)
        .sum();
    let graph_transcode_errors = snapshots
        .iter()
        .map(|snapshot| snapshot.transcode_errors)
        .sum();

    join_all(
        calls
            .iter()
            .flat_map(|call| call.graphs.iter().cloned())
            .map(|graph| async move { graph.shutdown_and_wait().await }),
    )
    .await
    .into_iter()
    .for_each(|result| {
        result.expect("media graph failed to converge during qualification teardown");
    });

    let source_frames_sent = counters.source_frames_sent.load(Ordering::Relaxed);
    let source_frames_dropped = counters.source_frames_dropped.load(Ordering::Relaxed);
    let sink_frames_received = counters.sink_frames_received.load(Ordering::Relaxed);
    let latency_p95_upper_bound_us = latency.percentile_upper_bound_us(0.95);
    let steady_state_memory_growth_percent =
        memory_growth_percent(warmup_rss_bytes, final_rss_bytes);
    let delivery_ratio = if source_frames_sent == 0 {
        0.0
    } else {
        sink_frames_received as f64 / source_frames_sent as f64
    };
    let common_passed = source_frames_dropped == 0
        && graph_dropped_frames == 0
        && graph_evictions == 0
        && graph_transcode_errors == 0
        && graph_transcode_operations > 0
        && delivery_ratio >= 0.99;
    let passed = common_passed
        && match mode {
            QualificationMode::Smoke => {
                latency_p95_upper_bound_us.is_some_and(|value| value <= MAX_RELEASE_P95_US * 2)
            }
            QualificationMode::Release => {
                all_calls_active >= RELEASE_DURATION
                    && setup_elapsed <= Duration::from_secs(12)
                    && latency_p95_upper_bound_us.is_some_and(|value| value <= MAX_RELEASE_P95_US)
                    && steady_state_memory_growth_percent
                        .is_some_and(|value| value < MAX_RELEASE_MEMORY_GROWTH_PERCENT)
            }
        };

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let report = MediaQualificationReport {
        schema: "bridgefu.qualification.media.v2",
        mode,
        started_at,
        finished_at: Utc::now(),
        bridgefu: git_revision(&manifest_dir),
        rvoip: rvoip_registry_evidence(&manifest_dir),
        host: host_evidence(),
        calls: parameters.calls,
        media_graphs: parameters.calls * 2,
        call_attempts_per_second: parameters.call_attempts_per_second,
        setup_elapsed_ms: setup_elapsed.as_millis(),
        all_calls_active_ms: all_calls_active.as_millis(),
        source_frames_sent,
        source_frames_dropped,
        sink_frames_received,
        graph_dropped_frames,
        graph_evictions,
        graph_transcode_operations,
        graph_transcode_errors,
        latency_p95_upper_bound_us,
        warmup_rss_bytes,
        final_rss_bytes,
        steady_state_memory_growth_percent,
        release_thresholds: ReleaseThresholds {
            calls: RELEASE_CALLS,
            call_attempts_per_second: RELEASE_CALL_ATTEMPTS_PER_SECOND,
            active_duration_seconds: RELEASE_DURATION.as_secs(),
            latency_p95_us: MAX_RELEASE_P95_US,
            steady_state_memory_growth_percent: MAX_RELEASE_MEMORY_GROWTH_PERCENT,
        },
        passed,
    };
    let report_path = write_report(&manifest_dir, &report);
    eprintln!("qualification report: {}", report_path.display());
    eprintln!("qualification wall time: {:.2?}", started.elapsed());
    assert!(
        passed,
        "media qualification failed; retained evidence is at {}",
        report_path.display()
    );
}

async fn create_qualified_call(
    counters: Arc<LoadCounters>,
    latency: Arc<LatencyHistogram>,
    cancellation: CancellationToken,
    opus_silence: Bytes,
) -> QualifiedCall {
    let pcmu = CodecInfo::from_name_with_defaults("pcmu");
    let opus = CodecInfo::from_name_with_defaults("opus");
    let policy = MediaGraphPolicy {
        max_sinks: 1,
        ..MediaGraphPolicy::default()
    };

    let (pcmu_source_tx, pcmu_source_rx) = mpsc::channel(10);
    let pcmu_graph =
        start_media_graph(pcmu_source_rx, pcmu.clone(), policy.clone()).expect("PCMU media graph");
    let (opus_sink_tx, opus_sink_rx) = mpsc::channel(10);
    let pcmu_to_opus = pcmu_graph
        .add_managed_sink(opus.clone(), opus_sink_tx)
        .expect("PCMU to Opus route");

    let (opus_source_tx, opus_source_rx) = mpsc::channel(10);
    let opus_graph = start_media_graph(opus_source_rx, opus, policy).expect("Opus media graph");
    let (pcmu_sink_tx, pcmu_sink_rx) = mpsc::channel(10);
    let opus_to_pcmu = opus_graph
        .add_managed_sink(pcmu, pcmu_sink_tx)
        .expect("Opus to PCMU route");

    tokio::time::timeout(Duration::from_secs(2), pcmu_to_opus.wait_active())
        .await
        .expect("PCMU to Opus route activation deadline")
        .expect("PCMU to Opus route activation");
    tokio::time::timeout(Duration::from_secs(2), opus_to_pcmu.wait_active())
        .await
        .expect("Opus to PCMU route activation deadline")
        .expect("Opus to PCMU route activation");

    let tasks = vec![
        spawn_source(
            pcmu_source_tx,
            Bytes::from_static(&PCMU_SILENCE),
            0,
            160,
            Arc::clone(&counters),
            cancellation.clone(),
        ),
        spawn_source(
            opus_source_tx,
            opus_silence,
            111,
            960,
            Arc::clone(&counters),
            cancellation,
        ),
        spawn_sink(opus_sink_rx, Arc::clone(&counters), Arc::clone(&latency)),
        spawn_sink(pcmu_sink_rx, counters, latency),
    ];

    QualifiedCall {
        graphs: [pcmu_graph, opus_graph],
        _routes: [pcmu_to_opus, opus_to_pcmu],
        tasks,
    }
}

fn spawn_source(
    sender: mpsc::Sender<MediaFrame>,
    payload: Bytes,
    payload_type: u8,
    timestamp_step: u32,
    counters: Arc<LoadCounters>,
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
                        payload: payload.clone(),
                        timestamp_rtp: timestamp,
                        captured_at: Utc::now(),
                        payload_type: Some(payload_type),
                    };
                    timestamp = timestamp.wrapping_add(timestamp_step);
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

fn spawn_sink(
    mut receiver: mpsc::Receiver<MediaFrame>,
    counters: Arc<LoadCounters>,
    latency: Arc<LatencyHistogram>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(frame) = receiver.recv().await {
            latency.observe(frame.captured_at);
            counters
                .sink_frames_received
                .fetch_add(1, Ordering::Relaxed);
        }
    })
}

fn canonical_opus_silence() -> Bytes {
    let mut codec = OpusCodec::new(
        SampleRate::Rate48000,
        1,
        OpusConfig {
            frame_size_ms: 20.0,
            ..OpusConfig::default()
        },
    )
    .expect("Opus encoder");
    let frame = AudioFrame::new(vec![0; 960], 48_000, 1, 0);
    Bytes::from(codec.encode(&frame).expect("canonical Opus silence"))
}

fn bounded_environment_usize(name: &str, default: usize, min: usize, max: usize) -> usize {
    let value = env::var(name)
        .ok()
        .map(|raw| {
            raw.parse::<usize>()
                .unwrap_or_else(|_| panic!("{name} must be an integer"))
        })
        .unwrap_or(default);
    assert!(
        (min..=max).contains(&value),
        "{name} must be in {min}..={max}"
    );
    value
}

fn bounded_environment_u64(name: &str, default: u64, min: u64, max: u64) -> u64 {
    let value = env::var(name)
        .ok()
        .map(|raw| {
            raw.parse::<u64>()
                .unwrap_or_else(|_| panic!("{name} must be an integer"))
        })
        .unwrap_or(default);
    assert!(
        (min..=max).contains(&value),
        "{name} must be in {min}..={max}"
    );
    value
}

fn current_rss_bytes() -> Option<u64> {
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        if let Some(kib) = status.lines().find_map(|line| {
            line.strip_prefix("VmRSS:")
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse::<u64>().ok())
        }) {
            return Some(kib.saturating_mul(1024));
        }
    }
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    String::from_utf8(output.stdout)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(|kib| kib.saturating_mul(1024))
}

fn memory_growth_percent(warmup: Option<u64>, final_value: Option<u64>) -> Option<f64> {
    let warmup = warmup?;
    let final_value = final_value?;
    if warmup == 0 {
        return None;
    }
    Some(((final_value as f64 - warmup as f64) / warmup as f64) * 100.0)
}

fn git_revision(path: &Path) -> RevisionEvidence {
    RevisionEvidence {
        revision: command_output(
            "git",
            &["-C", path.to_string_lossy().as_ref(), "rev-parse", "HEAD"],
        )
        .unwrap_or_else(|| "unavailable".to_string()),
        dirty: Command::new("git")
            .args([
                "-C",
                path.to_string_lossy().as_ref(),
                "status",
                "--porcelain",
            ])
            .output()
            .map_or(true, |output| !output.stdout.is_empty()),
    }
}

fn host_evidence() -> HostEvidence {
    HostEvidence {
        os: env::consts::OS,
        architecture: env::consts::ARCH,
        logical_cpus: std::thread::available_parallelism().map_or(1, usize::from),
        kernel: command_output("uname", &["-a"]).unwrap_or_else(|| "unavailable".to_string()),
    }
}

fn command_output(program: &str, arguments: &[&str]) -> Option<String> {
    let output = Command::new(program).args(arguments).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn write_report(manifest_dir: &Path, report: &MediaQualificationReport) -> PathBuf {
    let path = env::var_os("BRIDGEFU_QUALIFICATION_OUTPUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            manifest_dir.join(format!(
                "target/qualification/media-{}.json",
                report.started_at.format("%Y%m%dT%H%M%SZ")
            ))
        });
    fs::create_dir_all(path.parent().expect("qualification report parent"))
        .expect("create qualification report directory");
    fs::write(
        &path,
        serde_json::to_vec_pretty(report).expect("serialize qualification report"),
    )
    .expect("write qualification report");
    path
}
