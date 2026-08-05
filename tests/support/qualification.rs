//! Shared, identifier-free helpers for manual release qualification tests.
//!
//! Each integration-test binary imports a different subset of this module.
#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

pub const LATENCY_BUCKET_WIDTH_US: u64 = 100;
pub const COORDINATED_RVOIP_VERSION: &str = "0.3.5";
const LATENCY_MAX_US: u64 = 1_000_000;
pub const CRATES_IO_REGISTRY_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
pub const RVOIP_SIP_DIALOG_PATCH_SOURCE: &str = "git+https://github.com/eisenzopf/rvoip.git?rev=c701081159a579d7bc5495f45ea9ae1bdc241d56#c701081159a579d7bc5495f45ea9ae1bdc241d56";
const REQUIRED_RVOIP_PACKAGES: &[&str] = &[
    "rvoip-amazon-connect",
    "rvoip-auth-core",
    "rvoip-core",
    "rvoip-media-core",
    "rvoip-moq",
    "rvoip-quic",
    "rvoip-redis",
    "rvoip-sip",
    "rvoip-uctp",
    "rvoip-webrtc",
    "rvoip-webrtc-stack",
];

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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CargoPackageEvidence {
    name: String,
    version: String,
    source: String,
    checksum: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RvoipLockEvidence {
    release_version: &'static str,
    lockfile: &'static str,
    packages: Vec<CargoPackageEvidence>,
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

pub fn rvoip_lock_evidence(manifest_dir: &Path) -> RvoipLockEvidence {
    let lockfile = fs::read_to_string(manifest_dir.join("Cargo.lock"))
        .expect("read Bridgefu Cargo.lock for rvoip dependency evidence");
    let mut packages = parse_lock_packages(&lockfile)
        .into_iter()
        .filter(|package| package.name.starts_with("rvoip-"))
        .map(|package| {
            assert_eq!(
                package.version, COORDINATED_RVOIP_VERSION,
                "{} must resolve to the coordinated rvoip release",
                package.name
            );
            let expected_source = if package.name == "rvoip-sip-dialog" {
                RVOIP_SIP_DIALOG_PATCH_SOURCE
            } else {
                CRATES_IO_REGISTRY_SOURCE
            };
            assert_eq!(
                package.source.as_deref(),
                Some(expected_source),
                "{} must resolve from its approved immutable source",
                package.name
            );
            let checksum = if package.name == "rvoip-sip-dialog" {
                assert!(
                    package.checksum.is_none(),
                    "Git-patched rvoip-sip-dialog must not claim a registry checksum"
                );
                None
            } else {
                Some(
                    package
                        .checksum
                        .filter(|checksum| {
                            checksum.len() == 64
                                && checksum.bytes().all(|byte| byte.is_ascii_hexdigit())
                        })
                        .unwrap_or_else(|| {
                            panic!("{} must have a Cargo.lock checksum", package.name)
                        }),
                )
            };
            CargoPackageEvidence {
                name: package.name,
                version: package.version,
                source: package.source.expect("validated immutable source"),
                checksum,
            }
        })
        .collect::<Vec<_>>();
    packages.sort_by(|left, right| left.name.cmp(&right.name));

    let package_names = packages
        .iter()
        .map(|package| package.name.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        package_names.len(),
        packages.len(),
        "Cargo.lock must contain one coordinated version of each rvoip package"
    );
    for required in REQUIRED_RVOIP_PACKAGES {
        assert!(
            package_names.contains(required),
            "Cargo.lock is missing required coordinated package {required}"
        );
    }

    RvoipLockEvidence {
        release_version: COORDINATED_RVOIP_VERSION,
        lockfile: "Cargo.lock",
        packages,
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

#[derive(Default)]
struct LockPackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

fn parse_lock_packages(lockfile: &str) -> Vec<LockPackage> {
    let mut packages = Vec::new();
    let mut current = None;
    for line in lockfile.lines().map(str::trim) {
        if line == "[[package]]" {
            if let Some(package) = current.take() {
                packages.push(package);
            }
            current = Some(LockPackage::default());
            continue;
        }
        let Some(package) = current.as_mut() else {
            continue;
        };
        if let Some(value) = lock_string_value(line, "name") {
            package.name = value.to_string();
        } else if let Some(value) = lock_string_value(line, "version") {
            package.version = value.to_string();
        } else if let Some(value) = lock_string_value(line, "source") {
            package.source = Some(value.to_string());
        } else if let Some(value) = lock_string_value(line, "checksum") {
            package.checksum = Some(value.to_string());
        }
    }
    if let Some(package) = current {
        packages.push(package);
    }
    packages
}

fn lock_string_value<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let (name, value) = line.split_once('=')?;
    if name.trim() != field {
        return None;
    }
    value.trim().strip_prefix('"')?.strip_suffix('"')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_evidence_uses_the_coordinated_checked_release_and_dialog_backport() {
        let evidence = rvoip_lock_evidence(Path::new(env!("CARGO_MANIFEST_DIR")));
        assert_eq!(evidence.release_version, "0.3.5");
        let dialog = evidence
            .packages
            .iter()
            .find(|package| package.name == "rvoip-sip-dialog")
            .expect("dialog package evidence");
        assert_eq!(dialog.source, RVOIP_SIP_DIALOG_PATCH_SOURCE);
        assert_eq!(dialog.checksum, None);
        assert!(evidence
            .packages
            .iter()
            .filter(|package| package.name != "rvoip-sip-dialog")
            .all(|package| package.version == "0.3.5"
                && package.source == CRATES_IO_REGISTRY_SOURCE
                && package
                    .checksum
                    .as_ref()
                    .is_some_and(|checksum| checksum.len() == 64)));
    }
}
