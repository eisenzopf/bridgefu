//! Manual Gate 11 chaos qualification orchestrator.
//!
//! This ignored test composes already-deterministic failure, security, and
//! lifecycle tests from Bridgefu and rvoip. It intentionally does not expose
//! child-process output: the retained JSON contains only aggregate test
//! counts and static scenario descriptors. A passing run is a finite chaos
//! smoke, never the one-hour release qualification.
//!
//! Bridgefu scenarios run under Bridgefu's Cargo.lock. Published rvoip source
//! scenarios are selected from that locked graph, but each runs under the
//! registry package's own packaged Cargo.lock. The report records those as
//! separate dependency graphs rather than attaching Bridgefu lock evidence to
//! the independently locked package-source test commands.

#[path = "support/qualification.rs"]
mod qualification_support;

use chrono::{DateTime, Utc};
use qualification_support::{
    git_revision, host_evidence, rvoip_registry_evidence, write_report, HostEvidence,
    RevisionEvidence, RvoipRegistryEvidence, COORDINATED_RVOIP_VERSION, CRATES_IO_REGISTRY_SOURCE,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::io::{Read, Result as IoResult};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const REPORT_SCHEMA: &str = "bridgefu.qualification.chaos.v3";
const MANUAL_ACKNOWLEDGEMENT: &str = "BRIDGEFU_CHAOS_ACKNOWLEDGE_MANUAL";
const CHILD_TARGET_ENVIRONMENT: &str = "BRIDGEFU_CHAOS_CHILD_TARGET_DIR";
const OUTPUT_ENVIRONMENT: &str = "BRIDGEFU_CHAOS_QUALIFICATION_OUTPUT";
const MAX_RETAINED_CHILD_OUTPUT_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ScenarioScope {
    LocalDeterministic,
    ExternalCredentialed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ScenarioStatus {
    Passed,
    Failed,
    SkippedExternal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Workspace {
    Bridgefu,
    Rvoip,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DependencyResolution {
    BridgefuCargoLock,
    IndependentRegistryPackageCargoLock,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum TargetKind {
    Library,
    Binary,
    Integration,
}

#[derive(Clone, Copy)]
struct ScenarioSpec {
    id: &'static str,
    category: &'static str,
    scope: ScenarioScope,
    workspace: Workspace,
    package: Option<&'static str>,
    target_kind: TargetKind,
    target: Option<&'static str>,
    features: Option<&'static str>,
    test: &'static str,
    ignored: bool,
    required_environment: &'static [&'static str],
    timeout_seconds: u64,
    evidence_scope: &'static str,
}

#[derive(Serialize)]
struct ScenarioEvidence {
    id: &'static str,
    category: &'static str,
    scope: ScenarioScope,
    status: ScenarioStatus,
    workspace: Workspace,
    dependency_resolution: DependencyResolution,
    package: Option<&'static str>,
    target_kind: TargetKind,
    target: Option<&'static str>,
    test: &'static str,
    required_environment_names: &'static [&'static str],
    evidence_scope: &'static str,
    duration_ms: u128,
    tests_passed: u64,
    tests_failed: u64,
    tests_ignored: u64,
    exit_code: Option<i32>,
    timed_out: bool,
    child_output_retained: bool,
}

#[derive(Serialize)]
struct RvoipPackageSourceExecutionEvidence {
    selected_packages: Vec<String>,
    release_version: &'static str,
    source: &'static str,
    source_selection: &'static str,
    source_identity_evidence: &'static str,
    child_command: &'static str,
    child_lockfile: &'static str,
    bridgefu_lockfile_applied_to_child_commands: bool,
    dependency_graph_relation: &'static str,
}

#[derive(Default, Debug, Eq, PartialEq)]
struct ParsedTestSummary {
    passed: u64,
    failed: u64,
    ignored: u64,
}

#[derive(Serialize)]
struct ChaosSummary {
    scenarios_total: usize,
    local_total: usize,
    external_total: usize,
    passed: usize,
    failed: usize,
    skipped_external: usize,
    local_matrix_passed: bool,
    external_matrix_complete: bool,
    finite_chaos_smoke_passed: bool,
}

#[derive(Serialize)]
struct ChaosQualificationReport {
    schema: &'static str,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    bridgefu: RevisionEvidence,
    bridgefu_locked_rvoip_graph: RvoipRegistryEvidence,
    rvoip_package_source_execution: RvoipPackageSourceExecutionEvidence,
    host: HostEvidence,
    execution_profile: &'static str,
    isolated_child_target: bool,
    output_policy: &'static str,
    summary: ChaosSummary,
    scenarios: Vec<ScenarioEvidence>,
    release_criterion_satisfied: bool,
    release_criterion_reason: &'static str,
    known_limits: &'static [&'static str],
}

#[derive(Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoMetadataPackage>,
}

#[derive(Deserialize)]
struct CargoMetadataPackage {
    name: String,
    version: String,
    source: Option<String>,
    manifest_path: PathBuf,
}

const SCENARIOS: &[ScenarioSpec] = &[
    ScenarioSpec {
        id: "media_graph_slow_consumer",
        category: "media_loss_backpressure",
        scope: ScenarioScope::LocalDeterministic,
        workspace: Workspace::Rvoip,
        package: Some("rvoip-core"),
        target_kind: TargetKind::Library,
        target: None,
        features: None,
        test: "media_graph::tests::slow_sink_is_evicted_and_reported",
        ignored: false,
        required_environment: &[],
        timeout_seconds: 1_200,
        evidence_scope: "bounded drop-oldest pressure and slow-sink eviction",
    },
    ScenarioSpec {
        id: "rtp_loss_jitter_buffer",
        category: "media_loss_jitter",
        scope: ScenarioScope::LocalDeterministic,
        workspace: Workspace::Rvoip,
        package: Some("rvoip-rtp-core"),
        target_kind: TargetKind::Library,
        target: None,
        features: None,
        test: "buffer::jitter::tests::test_packet_loss",
        ignored: false,
        required_environment: &[],
        timeout_seconds: 1_200,
        evidence_scope: "deterministic RTP sequence gap through the adaptive jitter buffer",
    },
    ScenarioSpec {
        id: "sip_malformed_framing",
        category: "malformed_signaling",
        scope: ScenarioScope::LocalDeterministic,
        workspace: Workspace::Rvoip,
        package: Some("rvoip-sip-core"),
        target_kind: TargetKind::Library,
        target: None,
        features: None,
        test: "framing::tests::rejects_invalid_non_utf8_and_overflow_content_length_in_both_modes",
        ignored: false,
        required_environment: &[],
        timeout_seconds: 1_200,
        evidence_scope: "non-UTF8, invalid, and overflowing SIP Content-Length fail closed",
    },
    ScenarioSpec {
        id: "whep_malformed_offer",
        category: "malformed_signaling",
        scope: ScenarioScope::LocalDeterministic,
        workspace: Workspace::Rvoip,
        package: Some("rvoip-webrtc"),
        target_kind: TargetKind::Integration,
        target: Some("whep_draft04_server"),
        features: Some("signaling-whip"),
        test: "malformed_player_offers_never_receive_a_counter_offer",
        ignored: false,
        required_environment: &[],
        timeout_seconds: 1_200,
        evidence_scope: "malformed WHEP offer cannot receive a resource or counter-offer",
    },
    ScenarioSpec {
        id: "telnyx_retry_exhaustion",
        category: "provider_outage",
        scope: ScenarioScope::LocalDeterministic,
        workspace: Workspace::Bridgefu,
        package: None,
        target_kind: TargetKind::Binary,
        target: Some("bridgefu"),
        features: None,
        test: "providers::tests::telnyx_exhausted_errors_have_safe_retry_classification",
        ignored: false,
        required_environment: &[],
        timeout_seconds: 1_200,
        evidence_scope: "mock Telnyx 429/5xx/timeout exhaustion and safe retry classification",
    },
    ScenarioSpec {
        id: "telnyx_circuit_recovery",
        category: "provider_outage",
        scope: ScenarioScope::LocalDeterministic,
        workspace: Workspace::Bridgefu,
        package: None,
        target_kind: TargetKind::Binary,
        target: Some("bridgefu"),
        features: None,
        test: "providers::tests::telnyx_circuit_breaker_opens_rejects_and_recovers_with_one_probe",
        ignored: false,
        required_environment: &[],
        timeout_seconds: 1_200,
        evidence_scope: "bounded circuit open, rejection, half-open probe, and recovery",
    },
    ScenarioSpec {
        id: "lease_renewal_outage",
        category: "store_interruption",
        scope: ScenarioScope::LocalDeterministic,
        workspace: Workspace::Bridgefu,
        package: None,
        target_kind: TargetKind::Library,
        target: None,
        features: None,
        test: "call_service::runtime::tests::renewal_outage_cannot_extend_the_last_confirmed_lease",
        ignored: false,
        required_environment: &[],
        timeout_seconds: 1_200,
        evidence_scope: "injected lease-store outage cannot extend execution authority",
    },
    ScenarioSpec {
        id: "sqlite_requested_outage",
        category: "store_interruption",
        scope: ScenarioScope::LocalDeterministic,
        workspace: Workspace::Bridgefu,
        package: None,
        target_kind: TargetKind::Integration,
        target: Some("call_service_runtime"),
        features: None,
        test: "requested_sqlite_outage_fails_closed_without_memory_fallback",
        ignored: false,
        required_environment: &[],
        timeout_seconds: 1_200,
        evidence_scope: "requested durable backend outage fails closed without memory fallback",
    },
    ScenarioSpec {
        id: "worker_drain_join",
        category: "worker_drain",
        scope: ScenarioScope::LocalDeterministic,
        workspace: Workspace::Bridgefu,
        package: None,
        target_kind: TargetKind::Integration,
        target: Some("call_service_runtime"),
        features: None,
        test: "explicit_shutdown_drains_worker_and_joins_supervisor",
        ignored: false,
        required_environment: &[],
        timeout_seconds: 1_200,
        evidence_scope: "worker is marked draining and its owned supervisor is joined",
    },
    ScenarioSpec {
        id: "moqt_relay_session_loss",
        category: "relay_loss",
        scope: ScenarioScope::LocalDeterministic,
        workspace: Workspace::Rvoip,
        package: Some("rvoip-moq"),
        target_kind: TargetKind::Library,
        target: None,
        features: None,
        test: "publisher::tests::successful_reconnect_updates_the_observable_connection",
        ignored: false,
        required_environment: &[],
        timeout_seconds: 1_200,
        evidence_scope: "injected relay session loss reconnects and updates observable ownership",
    },
    ScenarioSpec {
        id: "attachment_expiry_race",
        category: "token_expiry_replay",
        scope: ScenarioScope::LocalDeterministic,
        workspace: Workspace::Bridgefu,
        package: None,
        target_kind: TargetKind::Library,
        target: None,
        features: None,
        test: "call_service::service::tests::inbound_attachment_rechecks_principal_and_token_expiry_after_blocked_inspection",
        ignored: false,
        required_environment: &[],
        timeout_seconds: 1_200,
        evidence_scope: "principal and attachment expiry are rechecked after a blocked inspection",
    },
    ScenarioSpec {
        id: "attachment_single_use_replay",
        category: "token_expiry_replay",
        scope: ScenarioScope::LocalDeterministic,
        workspace: Workspace::Bridgefu,
        package: None,
        target_kind: TargetKind::Library,
        target: None,
        features: None,
        test: "call_service::service::tests::inbound_attachment_service_binds_exact_leg_and_rejects_replay",
        ignored: false,
        required_environment: &[],
        timeout_seconds: 1_200,
        evidence_scope: "single-use attachment binds one exact leg and rejects replay",
    },
    ScenarioSpec {
        id: "call_quota_exhaustion",
        category: "quota_exhaustion",
        scope: ScenarioScope::LocalDeterministic,
        workspace: Workspace::Bridgefu,
        package: None,
        target_kind: TargetKind::Library,
        target: None,
        features: None,
        test: "call_service::service::tests::capacity_and_scope_fail_without_partial_call",
        ignored: false,
        required_environment: &[],
        timeout_seconds: 1_200,
        evidence_scope: "call capacity and scope exhaustion create no partial call",
    },
    ScenarioSpec {
        id: "broadcast_authority_backend_loss",
        category: "quota_and_authority",
        scope: ScenarioScope::LocalDeterministic,
        workspace: Workspace::Bridgefu,
        package: None,
        target_kind: TargetKind::Library,
        target: None,
        features: None,
        test: "broadcast::token::tests::standalone_validator_uses_shared_grants_and_fails_closed_on_backend_loss",
        ignored: false,
        required_environment: &[],
        timeout_seconds: 1_200,
        evidence_scope: "broadcast authorization fails closed when shared authority is unavailable",
    },
    ScenarioSpec {
        id: "redis_connection_loss_recovery",
        category: "store_interruption",
        scope: ScenarioScope::ExternalCredentialed,
        workspace: Workspace::Bridgefu,
        package: None,
        target_kind: TargetKind::Integration,
        target: Some("redis_coordination"),
        features: None,
        test: "redis_72_projection_streams_and_database_fallback_are_conformant",
        ignored: true,
        required_environment: &["BRIDGEFU_TEST_REDIS_URL"],
        timeout_seconds: 1_200,
        evidence_scope: "disposable Redis connection kill, state loss, fallback, and reconnect",
    },
    ScenarioSpec {
        id: "postgres_projector_crash_reclaim",
        category: "store_interruption",
        scope: ScenarioScope::ExternalCredentialed,
        workspace: Workspace::Bridgefu,
        package: None,
        target_kind: TargetKind::Integration,
        target: Some("coordination_sql"),
        features: None,
        test: "postgres_two_instances_have_one_ordered_claim_winner",
        ignored: true,
        required_environment: &["BRIDGEFU_TEST_POSTGRES_URL"],
        timeout_seconds: 1_200,
        evidence_scope: "disposable PostgreSQL projector crash, stale claim, and exact reclaim",
    },
];

#[test]
#[ignore = "manual Gate 11 finite chaos qualification; never one-hour release evidence"]
fn qualifies_deterministic_chaos_matrix() {
    assert_eq!(
        env::var(MANUAL_ACKNOWLEDGEMENT).as_deref(),
        Ok("1"),
        "set BRIDGEFU_CHAOS_ACKNOWLEDGE_MANUAL=1 before running this manual matrix"
    );

    validate_scenarios(SCENARIOS).expect("static chaos scenario matrix must be valid");
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let rvoip_manifests = resolve_rvoip_registry_manifests(&manifest_dir, SCENARIOS)
        .expect("resolve exact rvoip 0.3.5 registry package manifests");
    let child_target = env::var_os(CHILD_TARGET_ENVIRONMENT)
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir.join("target/qualification/chaos-cargo-target"));
    let started_at = Utc::now();
    let mut scenarios = Vec::with_capacity(SCENARIOS.len());

    for spec in SCENARIOS {
        if !required_environment_is_present(spec.required_environment) {
            scenarios.push(skipped_external(spec));
            continue;
        }
        scenarios.push(run_scenario(
            spec,
            &manifest_dir,
            &rvoip_manifests,
            &child_target,
        ));
    }

    let summary = summarize(&scenarios);
    let rvoip_package_source_execution = rvoip_package_source_execution_evidence(&rvoip_manifests);
    let report = ChaosQualificationReport {
        schema: REPORT_SCHEMA,
        started_at,
        finished_at: Utc::now(),
        bridgefu: git_revision(&manifest_dir),
        bridgefu_locked_rvoip_graph: rvoip_registry_evidence(&manifest_dir),
        rvoip_package_source_execution,
        host: host_evidence(),
        execution_profile: "finite_deterministic_smoke",
        isolated_child_target: true,
        output_policy: "child stdout/stderr discarded after aggregate test-count parsing",
        summary,
        scenarios,
        release_criterion_satisfied: false,
        release_criterion_reason: "this finite matrix does not execute any one-hour load profile or deployed-cloud chaos campaign",
        known_limits: &[
            "rvoip source-package tests use each published package's packaged Cargo.lock, not Bridgefu's Cargo.lock; their independently locked transitive graph is not application dependency evidence",
            "local media impairment covers deterministic queue pressure and RTP jitter-buffer loss, not a one-hour network impairment campaign",
            "local provider outage uses Telnyx mocks and does not replace a restricted live test-account workflow",
            "local relay loss uses the rvoip relay connector seam and does not replace a separately deployed relay-tier failure test",
            "PostgreSQL server-process interruption is not claimed by the projector crash/reclaim scenario",
            "missing external Redis or PostgreSQL configuration is reported as skipped_external, never passed",
        ],
    };
    let report_path = write_report(
        &manifest_dir,
        OUTPUT_ENVIRONMENT,
        "chaos",
        started_at,
        &report,
    );
    eprintln!("Gate 11 finite chaos report: {}", report_path.display());

    assert_eq!(
        report.summary.failed, 0,
        "one or more chaos scenarios failed; inspect the redacted JSON and rerun the named exact test"
    );
    assert!(
        report.summary.local_matrix_passed,
        "the deterministic local chaos matrix is incomplete"
    );
    assert!(!report.release_criterion_satisfied);
}

fn run_scenario(
    spec: &ScenarioSpec,
    bridgefu_dir: &Path,
    rvoip_manifests: &BTreeMap<String, PathBuf>,
    child_target: &Path,
) -> ScenarioEvidence {
    let started = Instant::now();
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command
        .env("CARGO_TARGET_DIR", child_target)
        .env("CARGO_TERM_COLOR", "never")
        .env("RUST_BACKTRACE", "0")
        .env("RUST_LOG", "off")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match spec.workspace {
        Workspace::Bridgefu => {
            command
                .current_dir(bridgefu_dir)
                .args(["test", "--locked", "--quiet"]);
            if let Some(package) = spec.package {
                command.args(["-p", package]);
            }
        }
        Workspace::Rvoip => {
            let package = spec
                .package
                .expect("rvoip registry scenario must identify its package");
            let manifest = rvoip_manifests
                .get(package)
                .expect("validated rvoip registry package manifest");
            command
                .current_dir(manifest.parent().expect("registry package manifest parent"))
                .args(["test", "--locked", "--quiet", "--manifest-path"])
                .arg(manifest);
        }
    }
    if let Some(features) = spec.features {
        command.args(["--features", features]);
    }
    match spec.target_kind {
        TargetKind::Library => {
            command.arg("--lib");
        }
        TargetKind::Binary => {
            command.args(["--bin", spec.target.expect("binary target")]);
        }
        TargetKind::Integration => {
            command.args(["--test", spec.target.expect("integration target")]);
        }
    }
    command.arg(spec.test).arg("--");
    if spec.ignored {
        command.arg("--ignored");
    }
    command.arg("--exact");

    let spawned = command.spawn();
    let Ok(mut child) = spawned else {
        return failed_to_spawn(spec, started.elapsed());
    };
    let stdout_reader = child
        .stdout
        .take()
        .map(|stdout| thread::spawn(move || read_bounded_tail(stdout)));
    let stderr_reader = child
        .stderr
        .take()
        .map(|stderr| thread::spawn(move || read_bounded_tail(stderr)));
    let (status, timed_out) = wait_bounded(&mut child, Duration::from_secs(spec.timeout_seconds));
    let stdout = join_reader(stdout_reader);
    let stderr = join_reader(stderr_reader);
    let summary = parse_test_summary(&stdout, &stderr);
    let passed = status.as_ref().is_some_and(ExitStatus::success)
        && !timed_out
        && summary.passed == 1
        && summary.failed == 0;

    ScenarioEvidence {
        id: spec.id,
        category: spec.category,
        scope: spec.scope,
        status: if passed {
            ScenarioStatus::Passed
        } else {
            ScenarioStatus::Failed
        },
        workspace: spec.workspace,
        dependency_resolution: dependency_resolution(spec.workspace),
        package: spec.package,
        target_kind: spec.target_kind,
        target: spec.target,
        test: spec.test,
        required_environment_names: spec.required_environment,
        evidence_scope: spec.evidence_scope,
        duration_ms: started.elapsed().as_millis(),
        tests_passed: summary.passed,
        tests_failed: summary.failed,
        tests_ignored: summary.ignored,
        exit_code: status.and_then(|status| status.code()),
        timed_out,
        child_output_retained: false,
    }
}

fn resolve_rvoip_registry_manifests(
    bridgefu_dir: &Path,
    scenarios: &[ScenarioSpec],
) -> Result<BTreeMap<String, PathBuf>, String> {
    let expected = scenarios
        .iter()
        .filter(|scenario| scenario.workspace == Workspace::Rvoip)
        .map(|scenario| {
            scenario
                .package
                .ok_or_else(|| format!("rvoip scenario {} has no package", scenario.id))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .current_dir(bridgefu_dir)
        .args(["metadata", "--locked", "--format-version", "1"])
        .output()
        .map_err(|error| format!("could not execute cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed with status {}",
            output.status
        ));
    }
    let metadata = serde_json::from_slice::<CargoMetadata>(&output.stdout)
        .map_err(|error| format!("invalid cargo metadata JSON: {error}"))?;
    let mut manifests = BTreeMap::new();
    for package in metadata
        .packages
        .into_iter()
        .filter(|package| expected.contains(package.name.as_str()))
    {
        if package.version != COORDINATED_RVOIP_VERSION {
            return Err(format!(
                "{} resolved to {}, expected {}",
                package.name, package.version, COORDINATED_RVOIP_VERSION
            ));
        }
        if package.source.as_deref() != Some(CRATES_IO_REGISTRY_SOURCE) {
            return Err(format!(
                "{} did not resolve from crates.io: {:?}",
                package.name, package.source
            ));
        }
        if !package.manifest_path.is_file() {
            return Err(format!(
                "{} registry manifest is unavailable at {}",
                package.name,
                package.manifest_path.display()
            ));
        }
        let package_lockfile = package
            .manifest_path
            .parent()
            .expect("registry package manifest parent")
            .join("Cargo.lock");
        if !package_lockfile.is_file() {
            return Err(format!(
                "{} registry package has no packaged Cargo.lock for independent locked test execution",
                package.name
            ));
        }
        if manifests
            .insert(package.name.clone(), package.manifest_path)
            .is_some()
        {
            return Err(format!(
                "{} resolved to multiple registry manifests",
                package.name
            ));
        }
    }
    for package in expected {
        if !manifests.contains_key(package) {
            return Err(format!(
                "cargo metadata did not resolve required registry package {package}"
            ));
        }
    }
    Ok(manifests)
}

fn rvoip_package_source_execution_evidence(
    manifests: &BTreeMap<String, PathBuf>,
) -> RvoipPackageSourceExecutionEvidence {
    RvoipPackageSourceExecutionEvidence {
        selected_packages: manifests.keys().cloned().collect(),
        release_version: COORDINATED_RVOIP_VERSION,
        source: CRATES_IO_REGISTRY_SOURCE,
        source_selection: "cargo metadata --locked from the Bridgefu manifest",
        source_identity_evidence:
            "matching name/version/source/checksum entries in bridgefu_locked_rvoip_graph",
        child_command: "cargo test --locked --manifest-path <registry-package>/Cargo.toml",
        child_lockfile: "the selected published package's packaged Cargo.lock",
        bridgefu_lockfile_applied_to_child_commands: false,
        dependency_graph_relation:
            "independently locked package-source test graph; not Bridgefu application dependency evidence",
    }
}

const fn dependency_resolution(workspace: Workspace) -> DependencyResolution {
    match workspace {
        Workspace::Bridgefu => DependencyResolution::BridgefuCargoLock,
        Workspace::Rvoip => DependencyResolution::IndependentRegistryPackageCargoLock,
    }
}

fn skipped_external(spec: &ScenarioSpec) -> ScenarioEvidence {
    debug_assert_eq!(spec.scope, ScenarioScope::ExternalCredentialed);
    ScenarioEvidence {
        id: spec.id,
        category: spec.category,
        scope: spec.scope,
        status: ScenarioStatus::SkippedExternal,
        workspace: spec.workspace,
        dependency_resolution: dependency_resolution(spec.workspace),
        package: spec.package,
        target_kind: spec.target_kind,
        target: spec.target,
        test: spec.test,
        required_environment_names: spec.required_environment,
        evidence_scope: spec.evidence_scope,
        duration_ms: 0,
        tests_passed: 0,
        tests_failed: 0,
        tests_ignored: 0,
        exit_code: None,
        timed_out: false,
        child_output_retained: false,
    }
}

fn failed_to_spawn(spec: &ScenarioSpec, elapsed: Duration) -> ScenarioEvidence {
    ScenarioEvidence {
        id: spec.id,
        category: spec.category,
        scope: spec.scope,
        status: ScenarioStatus::Failed,
        workspace: spec.workspace,
        dependency_resolution: dependency_resolution(spec.workspace),
        package: spec.package,
        target_kind: spec.target_kind,
        target: spec.target,
        test: spec.test,
        required_environment_names: spec.required_environment,
        evidence_scope: spec.evidence_scope,
        duration_ms: elapsed.as_millis(),
        tests_passed: 0,
        tests_failed: 0,
        tests_ignored: 0,
        exit_code: None,
        timed_out: false,
        child_output_retained: false,
    }
}

fn required_environment_is_present(names: &[&str]) -> bool {
    names.iter().all(|name| {
        env::var_os(name)
            .and_then(|value| value.into_string().ok())
            .is_some_and(|value| !value.trim().is_empty())
    })
}

fn wait_bounded(child: &mut std::process::Child, timeout: Duration) -> (Option<ExitStatus>, bool) {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return (Some(status), false),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill();
                return (child.wait().ok(), true);
            }
            Err(_) => {
                let _ = child.kill();
                return (child.wait().ok(), false);
            }
        }
    }
}

fn read_bounded_tail(mut reader: impl Read) -> IoResult<Vec<u8>> {
    let mut retained = Vec::with_capacity(MAX_RETAINED_CHILD_OUTPUT_BYTES);
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(retained);
        }
        if count >= MAX_RETAINED_CHILD_OUTPUT_BYTES {
            retained.clear();
            retained.extend_from_slice(&buffer[count - MAX_RETAINED_CHILD_OUTPUT_BYTES..count]);
            continue;
        }
        let excess = retained
            .len()
            .saturating_add(count)
            .saturating_sub(MAX_RETAINED_CHILD_OUTPUT_BYTES);
        if excess > 0 {
            retained.drain(..excess);
        }
        retained.extend_from_slice(&buffer[..count]);
    }
}

fn join_reader(reader: Option<thread::JoinHandle<IoResult<Vec<u8>>>>) -> Vec<u8> {
    reader
        .and_then(|reader| reader.join().ok())
        .and_then(Result::ok)
        .unwrap_or_default()
}

fn parse_test_summary(stdout: &[u8], stderr: &[u8]) -> ParsedTestSummary {
    let mut summary = ParsedTestSummary::default();
    for output in [stdout, stderr] {
        let text = String::from_utf8_lossy(output);
        for line in text.lines().filter(|line| line.contains("test result:")) {
            summary.passed = summary
                .passed
                .saturating_add(summary_value(line, "passed").unwrap_or(0));
            summary.failed = summary
                .failed
                .saturating_add(summary_value(line, "failed").unwrap_or(0));
            summary.ignored = summary
                .ignored
                .saturating_add(summary_value(line, "ignored").unwrap_or(0));
        }
    }
    summary
}

fn summary_value(line: &str, label: &str) -> Option<u64> {
    let marker = format!(" {label};");
    line.split_once(&marker)
        .and_then(|(prefix, _)| prefix.split_whitespace().next_back())
        .and_then(|value| value.parse().ok())
}

fn summarize(scenarios: &[ScenarioEvidence]) -> ChaosSummary {
    let local_total = scenarios
        .iter()
        .filter(|scenario| scenario.scope == ScenarioScope::LocalDeterministic)
        .count();
    let external_total = scenarios.len().saturating_sub(local_total);
    let passed = scenarios
        .iter()
        .filter(|scenario| scenario.status == ScenarioStatus::Passed)
        .count();
    let failed = scenarios
        .iter()
        .filter(|scenario| scenario.status == ScenarioStatus::Failed)
        .count();
    let skipped_external = scenarios
        .iter()
        .filter(|scenario| scenario.status == ScenarioStatus::SkippedExternal)
        .count();
    let local_matrix_passed = scenarios.iter().all(|scenario| {
        scenario.scope != ScenarioScope::LocalDeterministic
            || scenario.status == ScenarioStatus::Passed
    });
    let external_matrix_complete = scenarios.iter().all(|scenario| {
        scenario.scope != ScenarioScope::ExternalCredentialed
            || scenario.status == ScenarioStatus::Passed
    });
    ChaosSummary {
        scenarios_total: scenarios.len(),
        local_total,
        external_total,
        passed,
        failed,
        skipped_external,
        local_matrix_passed,
        external_matrix_complete,
        finite_chaos_smoke_passed: failed == 0 && local_matrix_passed,
    }
}

fn validate_scenarios(scenarios: &[ScenarioSpec]) -> Result<(), &'static str> {
    let mut ids = BTreeSet::new();
    for scenario in scenarios {
        if !ids.insert(scenario.id)
            || scenario.id.is_empty()
            || !scenario
                .id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err("scenario identifiers must be unique lowercase safe tokens");
        }
        if scenario.test.is_empty() || scenario.timeout_seconds == 0 {
            return Err("scenario test and timeout are required");
        }
        if matches!(
            scenario.target_kind,
            TargetKind::Binary | TargetKind::Integration
        ) && scenario.target.is_none()
        {
            return Err("binary and integration scenario targets are required");
        }
        if scenario.scope == ScenarioScope::LocalDeterministic
            && !scenario.required_environment.is_empty()
        {
            return Err("local deterministic scenario cannot require external environment");
        }
        if scenario.scope == ScenarioScope::ExternalCredentialed
            && scenario.required_environment.is_empty()
        {
            return Err("external scenario must name its required environment");
        }
    }
    Ok(())
}

#[test]
fn parses_exact_test_counts_without_retaining_diagnostics() {
    let output = b"running 1 test\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 99 filtered out; finished in 0.01s\n";
    assert_eq!(
        parse_test_summary(output, b"credential-shaped canary"),
        ParsedTestSummary {
            passed: 1,
            failed: 0,
            ignored: 0,
        }
    );
    assert_eq!(
        parse_test_summary(b"running 0 tests", b""),
        ParsedTestSummary::default()
    );
}

#[test]
fn resolves_upstream_scenarios_from_locked_registry_packages() {
    let manifests =
        resolve_rvoip_registry_manifests(Path::new(env!("CARGO_MANIFEST_DIR")), SCENARIOS)
            .expect("resolve upstream chaos packages");
    let expected = SCENARIOS
        .iter()
        .filter(|scenario| scenario.workspace == Workspace::Rvoip)
        .filter_map(|scenario| scenario.package)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        manifests
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        expected
    );
    assert!(manifests.values().all(|manifest| manifest
        .parent()
        .expect("registry manifest parent")
        .join("Cargo.lock")
        .is_file()));
}

#[test]
fn report_separates_bridgefu_lock_evidence_from_rvoip_source_test_resolution() {
    let manifests =
        resolve_rvoip_registry_manifests(Path::new(env!("CARGO_MANIFEST_DIR")), SCENARIOS)
            .expect("resolve upstream chaos packages");
    let evidence = rvoip_package_source_execution_evidence(&manifests);
    let json = serde_json::to_value(evidence).expect("serialize source execution evidence");

    assert_eq!(json["release_version"], COORDINATED_RVOIP_VERSION);
    assert_eq!(json["source"], CRATES_IO_REGISTRY_SOURCE);
    assert_eq!(json["bridgefu_lockfile_applied_to_child_commands"], false);
    assert_eq!(
        json["dependency_graph_relation"],
        "independently locked package-source test graph; not Bridgefu application dependency evidence"
    );
    assert!(json["child_command"]
        .as_str()
        .is_some_and(|command| command.contains("cargo test --locked")));
}

#[test]
fn static_scenario_matrix_is_safe_unique_and_truthfully_scoped() {
    validate_scenarios(SCENARIOS).expect("valid static matrix");
    assert!(SCENARIOS.iter().any(|scenario| {
        scenario.scope == ScenarioScope::ExternalCredentialed
            && scenario.required_environment == ["BRIDGEFU_TEST_REDIS_URL"]
    }));
    assert!(SCENARIOS.iter().all(|scenario| {
        !scenario.test.contains("secret") && !scenario.evidence_scope.contains("secret")
    }));
}
