//! Shared, identifier-free helpers for manual release qualification tests.
//!
//! Each integration-test binary imports a different subset of this module.
#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

pub const LATENCY_BUCKET_WIDTH_US: u64 = 100;
const LATENCY_MAX_US: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationMode {
    Smoke,
    Release,
}

impl QualificationMode {
    pub fn from_environment(profile: &str) -> Self {
        match env::var("BRIDGEFU_QUALIFICATION_MODE").as_deref() {
            Ok("smoke") => Self::Smoke,
            Ok("release") => {
                assert_eq!(
                    env::var("BRIDGEFU_QUALIFICATION_ACKNOWLEDGE_ONE_HOUR").as_deref(),
                    Ok("1"),
                    "{profile} release mode requires BRIDGEFU_QUALIFICATION_ACKNOWLEDGE_ONE_HOUR=1"
                );
                assert_eq!(
                    env::consts::OS,
                    "linux",
                    "{profile} release memory evidence is supported only on Linux"
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
}

#[derive(Serialize)]
pub struct RevisionEvidence {
    revision: String,
    dirty: bool,
}

#[derive(Serialize)]
pub struct HostEvidence {
    os: &'static str,
    architecture: &'static str,
    logical_cpus: usize,
    kernel: String,
}

pub struct LatencyHistogram {
    buckets: Vec<AtomicU64>,
    overflow: AtomicU64,
}

impl LatencyHistogram {
    pub fn new() -> Self {
        let bucket_count = (LATENCY_MAX_US / LATENCY_BUCKET_WIDTH_US) as usize + 1;
        Self {
            buckets: (0..bucket_count).map(|_| AtomicU64::new(0)).collect(),
            overflow: AtomicU64::new(0),
        }
    }

    pub fn observe(&self, captured_at: DateTime<Utc>) {
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

    pub fn percentile_upper_bound_us(&self, percentile: f64) -> Option<u64> {
        let total = self
            .buckets
            .iter()
            .map(|bucket| bucket.load(Ordering::Relaxed))
            .sum::<u64>()
            .saturating_add(self.overflow.load(Ordering::Relaxed));
        if total == 0 {
            return None;
        }
        let target = ((total as f64) * percentile).ceil() as u64;
        let mut seen = 0_u64;
        for (index, bucket) in self.buckets.iter().enumerate() {
            seen = seen.saturating_add(bucket.load(Ordering::Relaxed));
            if seen >= target {
                return Some(((index as u64) + 1) * LATENCY_BUCKET_WIDTH_US);
            }
        }
        Some(LATENCY_MAX_US.saturating_add(1))
    }
}

pub fn bounded_environment_usize(name: &str, default: usize, min: usize, max: usize) -> usize {
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

pub fn bounded_environment_u64(name: &str, default: u64, min: u64, max: u64) -> u64 {
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

pub fn current_rss_bytes() -> Option<u64> {
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

pub fn memory_growth_percent(warmup: Option<u64>, final_value: Option<u64>) -> Option<f64> {
    let warmup = warmup?;
    let final_value = final_value?;
    if warmup == 0 {
        return None;
    }
    Some(((final_value as f64 - warmup as f64) / warmup as f64) * 100.0)
}

pub fn git_revision(path: &Path) -> RevisionEvidence {
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

pub fn host_evidence() -> HostEvidence {
    HostEvidence {
        os: env::consts::OS,
        architecture: env::consts::ARCH,
        logical_cpus: std::thread::available_parallelism().map_or(1, usize::from),
        kernel: command_output("uname", &["-sr"]).unwrap_or_else(|| "unavailable".to_string()),
    }
}

pub fn write_report<T: Serialize>(
    manifest_dir: &Path,
    output_environment: &str,
    default_stem: &str,
    started_at: DateTime<Utc>,
    report: &T,
) -> PathBuf {
    let path = env::var_os(output_environment)
        .or_else(|| env::var_os("BRIDGEFU_QUALIFICATION_OUTPUT"))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            manifest_dir.join(format!(
                "target/qualification/{default_stem}-{}.json",
                started_at.format("%Y%m%dT%H%M%SZ")
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

pub fn prometheus_counter_sum(rendered: &str, metric: &str) -> u64 {
    prometheus_counter_sum_matching(rendered, metric, None)
}

pub fn prometheus_counter_sum_with_label(
    rendered: &str,
    metric: &str,
    label_fragment: &str,
) -> u64 {
    prometheus_counter_sum_matching(rendered, metric, Some(label_fragment))
}

fn prometheus_counter_sum_matching(
    rendered: &str,
    metric: &str,
    label_fragment: Option<&str>,
) -> u64 {
    rendered
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let (name_and_labels, value) = line.rsplit_once(' ')?;
            let name = name_and_labels
                .split_once('{')
                .map_or(name_and_labels, |v| v.0);
            (name == metric && label_fragment.is_none_or(|label| name_and_labels.contains(label)))
                .then(|| value.parse::<f64>().ok())
                .flatten()
        })
        .map(|value| value.max(0.0) as u64)
        .sum()
}

fn command_output(program: &str, arguments: &[&str]) -> Option<String> {
    let output = Command::new(program).args(arguments).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}
