#!/usr/bin/env python3
"""Protected release-level qualification controller for the flagship recipe.

Live component commands create strict, redacted observations under one guarded
AWS execution. ``assemble`` accepts only the exact call/failure/negative/soak,
zero-state, lifecycle, and teardown matrix tied to one immutable candidate.
Structural checks or hand-authored booleans cannot substitute for those inputs.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import ipaddress
import json
import math
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]
RECIPE_ROOT = ROOT / "recipes" / "vapi-amazon-connect-screen-pop"
QUALIFICATION = RECIPE_ROOT / "qualification"
LIVE_SCRIPT = ROOT / "scripts" / "aws-recipe-live-test.py"
VALIDATOR = ROOT / "scripts" / "validate-recipe-evidence.py"
LIVE_SPEC = importlib.util.spec_from_file_location(
    "bridgefu_aws_live_qualification", LIVE_SCRIPT
)
if LIVE_SPEC is None or LIVE_SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("unable to load the guarded AWS lifecycle controller")
LIVE = importlib.util.module_from_spec(LIVE_SPEC)
sys.modules[LIVE_SPEC.name] = LIVE
LIVE_SPEC.loader.exec_module(LIVE)
COLLECTOR_PATH = ROOT / "scripts" / "collect-recipe-call-evidence.py"
COLLECTOR_SPEC = importlib.util.spec_from_file_location(
    "bridgefu_call_evidence_qualification", COLLECTOR_PATH
)
if COLLECTOR_SPEC is None or COLLECTOR_SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("unable to load the protected per-call evidence controller")
COLLECTOR = importlib.util.module_from_spec(COLLECTOR_SPEC)
sys.modules[COLLECTOR_SPEC.name] = COLLECTOR
COLLECTOR_SPEC.loader.exec_module(COLLECTOR)

RECIPE = "vapi-amazon-connect-screen-pop@1"
PRODUCER = "bridgefu-qualification-controller@1"
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_PACKAGED_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_PACKAGED_EVIDENCE_FILES = 512
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CORRELATION = re.compile(r"bf1_[A-Za-z0-9_-]{43}")
CALL_SCHEMA = QUALIFICATION / "call-observation-v1.schema.json"
FAILURE_SCHEMA = QUALIFICATION / "failure-drill-observation-v1.schema.json"
NEGATIVE_SCHEMA = QUALIFICATION / "negative-observation-v1.schema.json"
SOAK_SCHEMA = QUALIFICATION / "soak-observation-v1.schema.json"
ZERO_SCHEMA = QUALIFICATION / "zero-state-observation-v1.schema.json"
MISSING_CONTEXT_PARTICIPANT_SCHEMA = (
    QUALIFICATION / "missing-context-participant-observation-v1.schema.json"
)
FINAL_SCHEMA = QUALIFICATION / "evidence-v1.schema.json"
MATRIX = QUALIFICATION / "matrix.yaml"
SIP_NEGATIVE_SOURCE = ROOT / "examples" / "recipe_sip_negative.rs"
SIP_SOURCE = ROOT / "examples" / "recipe_sip_source.rs"
AGENT_HARNESS = QUALIFICATION / "agent-workspace-playwright.mjs"
SOURCE_SCHEMA = QUALIFICATION / "source-observation-v1.schema.json"
ZERO_STATE_PHASE_FILES = {
    "pre_lifecycle": "zero-state-pre-lifecycle-evidence.json",
    "final": "zero-state-evidence.json",
}
PACKAGED_EVIDENCE_DIRECTORIES = {
    "call-evidence": {".json"},
    "failure-evidence": {".json"},
    "negative-evidence": {".json"},
    "network-observations": {".json"},
    "participant-observations": {".json"},
    "screenshots": {".png"},
    "source-observations": {".json"},
}
PACKAGED_EVIDENCE_FILES = {
    "soak-evidence.json",
    "zero-state-pre-lifecycle-evidence.json",
}
PACKAGED_NEGATIVE_IDS = {
    "prepare_auth_rejected",
    "prepare_conflicting_replay_rejected",
    "malformed_payload_rejected",
    "missing_correlation_header_rejected",
    "duplicate_correlation_header_rejected",
    "expired_attachment_rejected",
    "attachment_replay_rejected",
    "source_cancellation_cleanup",
    "missing_context_fail_open",
}
PACKAGED_FAILURE_IDS = {"process_restart", "dependency_timeout", "host_recovery"}
COMPONENT_SCHEMAS = (
    CALL_SCHEMA,
    FAILURE_SCHEMA,
    NEGATIVE_SCHEMA,
    SOAK_SCHEMA,
    ZERO_SCHEMA,
    MISSING_CONTEXT_PARTICIPANT_SCHEMA,
    FINAL_SCHEMA,
)
FORBIDDEN_KEYS = {
    "call_id",
    "contact_id",
    "correlation_id",
    "credential",
    "customer_name",
    "headers",
    "issue_summary",
    "password",
    "raw",
    "recording",
    "sip_uri",
    "source_call_id",
    "source_org_id",
    "token",
    "transcript",
    "vapi_call_id",
    "verification_status",
}


class QualificationError(RuntimeError):
    """Safe qualification failure without customer or call identifiers."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise QualificationError(
            "qualification evidence has an invalid timestamp"
        ) from error
    if parsed.tzinfo is None:
        raise QualificationError(
            "qualification evidence timestamp is not timezone-aware"
        )
    return parsed.astimezone(dt.timezone.utc)


def regular_file(path: Path, maximum: int = MAX_JSON_BYTES) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise QualificationError(
            "required qualification evidence is unavailable"
        ) from error
    if not stat.S_ISREG(details.st_mode) or path.is_symlink():
        raise QualificationError(
            "qualification evidence must be a regular non-symlink file"
        )
    if details.st_size <= 0 or details.st_size > maximum:
        raise QualificationError("qualification evidence exceeds its size boundary")


def load_json(path: Path) -> Any:
    regular_file(path)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationError(
            "qualification evidence is not valid UTF-8 JSON"
        ) from error


def sha256_file(path: Path) -> str:
    regular_file(path, 64 * 1024 * 1024)
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def controller_revision() -> str:
    return sha256_file(Path(__file__))


def validate_schema(value: Any, path: Path) -> None:
    jsonschema.Draft202012Validator(
        load_json(path), format_checker=jsonschema.FormatChecker()
    ).validate(value)


def reject_sensitive(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower()
            if normalized in FORBIDDEN_KEYS or normalized.startswith("raw_"):
                raise QualificationError(
                    "redacted qualification evidence has a forbidden field"
                )
            reject_sensitive(child)
    elif isinstance(value, list):
        for child in value:
            reject_sensitive(child)
    elif isinstance(value, str) and CORRELATION.search(value):
        raise QualificationError(
            "redacted qualification evidence contains a raw correlation value"
        )


def write_private_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    if path.exists() or temporary.exists():
        raise QualificationError(
            "refusing to overwrite retained qualification evidence"
        )
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
        temporary.replace(path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def revision_contract(ledger: Mapping[str, Any]) -> dict[str, str]:
    fields = {
        "release_id": ledger.get("release_id"),
        "source_tree_sha256": ledger.get("publication_source_tree_sha256"),
        "image": ledger.get("bridgefu_image_uri"),
    }
    if (
        not isinstance(fields["release_id"], str)
        or re.fullmatch(r"[0-9a-f]{20}", fields["release_id"]) is None
        or not isinstance(fields["source_tree_sha256"], str)
        or SHA256.fullmatch(fields["source_tree_sha256"]) is None
        or not isinstance(fields["image"], str)
        or re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", fields["image"]) is None
    ):
        raise QualificationError("immutable candidate revision contract is incomplete")
    return fields  # type: ignore[return-value]


def exact_component(
    path: Path,
    schema: Path,
    ledger: Mapping[str, Any],
    *,
    controller_owned: bool,
) -> dict[str, Any]:
    value = load_json(path)
    validate_schema(value, schema)
    reject_sensitive(value)
    if (
        not isinstance(value, dict)
        or value.get("execution_id") != ledger.get("execution_id")
        or value.get("recipe") != RECIPE
        or value.get("revisions") != revision_contract(ledger)
    ):
        raise QualificationError(
            "component evidence does not match the immutable candidate"
        )
    if controller_owned and (
        value.get("producer") != PRODUCER
        or value.get("producer_revision_sha256") != controller_revision()
    ):
        raise QualificationError(
            "component evidence is not bound to this controller revision"
        )
    return value


def evidence_files(directory: Path) -> list[Path]:
    if not directory.is_dir() or directory.is_symlink():
        raise QualificationError(
            "required qualification evidence directory is unavailable"
        )
    files = sorted(directory.glob("*.json"))
    if not files or len(files) > 256:
        raise QualificationError("qualification evidence file count is out of bounds")
    for path in files:
        regular_file(path)
    return files


def p95(values: Iterable[float]) -> float:
    ordered = sorted(float(value) for value in values)
    if not ordered or any(not math.isfinite(value) or value < 0 for value in ordered):
        raise QualificationError("latency evidence is empty or invalid")
    index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return round(ordered[index], 3)


def exact_candidate_ledger(execution_id: str) -> tuple[Path, dict[str, Any]]:
    path, ledger = LIVE.load_ledger(execution_id)
    if ledger.get("status") != "destroyed" or not ledger.get("lifecycle_test_passed"):
        raise QualificationError(
            "final assembly requires lifecycle proof and completed teardown"
        )
    if ledger.get("publication_source_tree_sha256") != LIVE.working_tree_digest(ROOT):
        raise QualificationError(
            "working tree no longer matches the immutable candidate"
        )
    validate_qualification_posture(ledger)
    return path, ledger


def validate_qualification_posture(ledger: Mapping[str, Any]) -> str:
    security = ledger.get("sip_security")
    dns_mode = ledger.get("dns_mode")
    zone_id = ledger.get("public_hosted_zone_id")
    if security == "sip_rtp":
        if dns_mode != "ip_only" or zone_id != "none":
            raise QualificationError(
                "IP-only SIP/RTP qualification must not retain a DNS zone"
            )
        return security
    if security == "sips_srtp":
        if dns_mode not in {"existing_route53_zone", "temporary_delegated_zone"}:
            raise QualificationError(
                "SIPS/SRTP qualification requires a public DNS posture"
            )
        if not isinstance(zone_id, str) or not zone_id or zone_id == "none":
            raise QualificationError(
                "SIPS/SRTP qualification requires a public hosted zone"
            )
        if (
            dns_mode == "temporary_delegated_zone"
            and ledger.get("delegation_verified") is not True
        ):
            raise QualificationError(
                "public DNS delegation was not retained as verified"
            )
        return security
    raise QualificationError("qualification ledger has an unsupported SIP posture")


def required_scenarios_for_ledger(
    matrix: Mapping[str, Any], ledger: Mapping[str, Any]
) -> list[Mapping[str, Any]]:
    security = validate_qualification_posture(ledger)
    scenarios = matrix.get("required_scenarios")
    required_by_security = matrix.get("required_scenario_ids_by_sip_security")
    if not isinstance(scenarios, list):
        raise QualificationError("qualification matrix has no scenario catalog")
    if not isinstance(required_by_security, dict) or not isinstance(
        required_by_security.get(security), list
    ):
        raise QualificationError(
            "qualification matrix has no requirement for the deployed SIP posture"
        )
    required_ids = required_by_security[security]
    if len(required_ids) != len(set(required_ids)):
        raise QualificationError(
            "qualification matrix repeats a required scenario"
        )
    required = [
        scenario
        for scenario in scenarios
        if isinstance(scenario, dict)
        and scenario.get("id") in required_ids
    ]
    if (
        len(required) != 3
        or {item.get("id") for item in required} != set(required_ids)
        or sum(item.get("source") == "vapi_web" for item in required) != 1
        or sum(item.get("source") == "sip" for item in required) != 2
        or any(
            item.get("security")
            != ("deployed" if item.get("source") == "vapi_web" else security)
            for item in required
        )
    ):
        raise QualificationError(
            "qualification matrix does not define the exact deployed SIP posture"
        )
    return required


def required_checks_for_ledger(
    matrix: Mapping[str, Any], ledger: Mapping[str, Any]
) -> set[str]:
    security = validate_qualification_posture(ledger)
    checks_by_security = matrix.get("required_checks_by_sip_security")
    checks = (
        checks_by_security.get(security)
        if isinstance(checks_by_security, dict)
        else None
    )
    if (
        not isinstance(checks, list)
        or len(checks) != 14
        or len(checks) != len(set(checks))
        or any(not isinstance(item, str) or not item for item in checks)
    ):
        raise QualificationError(
            "qualification matrix check set is invalid for the deployed SIP posture"
        )
    return set(checks)


def validate_structural(path: Path, ledger: Mapping[str, Any]) -> dict[str, Any]:
    value = load_json(path)
    reject_sensitive(value)
    fingerprint = value.get("recipe_fingerprint") if isinstance(value, dict) else None
    checks = value.get("checks") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or value.get("execution_id") != ledger.get("execution_id")
        or value.get("recipe") != RECIPE
        or value.get("release_id") != ledger.get("release_id")
        or value.get("image_digest")
        != str(ledger.get("bridgefu_image_uri", "")).rsplit("@", 1)[-1]
        or not isinstance(fingerprint, str)
        or SHA256.fullmatch(fingerprint) is None
        or not isinstance(checks, dict)
        or not checks
        or not all(item is True for item in checks.values())
        or value.get("customer_data_retained") is not False
    ):
        raise QualificationError(
            "structural evidence does not match the verified deployment"
        )
    return value


def validate_lifecycle(path: Path, ledger: Mapping[str, Any]) -> dict[str, Any]:
    value = load_json(path)
    reject_sensitive(value)
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or value.get("execution_id") != ledger.get("execution_id")
        or value.get("recipe") != RECIPE
        or value.get("release_id") != ledger.get("release_id")
        or value.get("safe_update", {}).get("completed") is not True
        or value.get("intentional_failure", {}).get("rollback_complete") is not True
        or value.get("intentional_failure", {}).get("working_artifact_restored")
        is not True
        or value.get("customer_data_retained") is not False
    ):
        raise QualificationError("lifecycle evidence is incomplete")
    return value


def validate_teardown(path: Path) -> dict[str, Any]:
    value = load_json(path)
    if not isinstance(value, dict) or LIVE.inventory_has_leftovers(value):
        raise QualificationError("teardown inventory is not zero")
    expected = {
        "checked_at",
        "tagged_resource_arns",
        "active_stack_names",
        "review_stack_ids",
        "connect_log_group_names",
        "iam_role_names",
        "iam_policy_arns",
        "demo_site_bucket_names",
        "artifact_bucket_names",
        "ecr_repository_names",
        "cloudfront_distribution_ids",
        "cloudfront_cache_policy_ids",
        "cloudfront_response_headers_policy_ids",
        "cloudfront_origin_access_control_ids",
        "private_tls_secret_arns",
        "temporary_secret_arns",
        "connect_instance_arns",
        "elastic_ip_allocation_ids",
        "active_codebuild_build_ids",
        "vapi_resource_ids",
    }
    if set(value) != expected or any(
        value[name] != [] for name in expected - {"checked_at"}
    ):
        raise QualificationError("teardown inventory shape is incomplete")
    parse_timestamp(value["checked_at"])
    return value


def call_matrix(
    ledger: Mapping[str, Any], negative_by_id: Mapping[str, tuple[Path, dict[str, Any]]]
) -> tuple[list[dict[str, Any]], set[str], list[dt.datetime], list[dt.datetime]]:
    matrix = yaml.safe_load(MATRIX.read_text(encoding="utf-8"))
    required_checks = required_checks_for_ledger(matrix, ledger)
    required_pairs = {
        (scenario["id"], network["id"])
        for scenario in required_scenarios_for_ledger(matrix, ledger)
        for network in matrix["adverse_network_profiles"]
    }
    by_pair: dict[tuple[str, str], dict[str, tuple[Path, dict[str, Any]]]] = (
        defaultdict(dict)
    )
    starts: list[dt.datetime] = []
    ends: list[dt.datetime] = []
    for evidence_path in evidence_files(
        LIVE.ledger_path(ledger["execution_id"]).parent / "call-evidence"
    ):
        call = exact_component(
            evidence_path, CALL_SCHEMA, ledger, controller_owned=False
        )
        pair = (call["scenario_id"], call["network"]["profile"])
        origin = call["hangup_origin"]
        if pair not in required_pairs or origin in by_pair[pair]:
            raise QualificationError(
                "call evidence matrix contains an unexpected duplicate"
            )
        by_pair[pair][origin] = (evidence_path, call)
        starts.append(parse_timestamp(call["started_at"]))
        ends.append(parse_timestamp(call["ended_at"]))
    if set(by_pair) != required_pairs or any(
        set(origins) != {"source", "agent"} for origins in by_pair.values()
    ):
        raise QualificationError(
            "call evidence does not contain both hangups for every matrix row"
        )

    replay_component = negative_by_id["attachment_replay_rejected"][1]
    missing_component = negative_by_id["missing_context_fail_open"][1]
    if (
        replay_component["outcome"] != "replay_rejected"
        or missing_component["outcome"] != "failed_open"
        or missing_component["checks"]["agent_workspace_observed"] is not True
    ):
        raise QualificationError(
            "release-wide replay or missing-context evidence is incomplete"
        )

    scenarios: list[dict[str, Any]] = []
    all_hashes: set[str] = set()
    for scenario_id, network_profile in sorted(required_pairs):
        paths_calls = by_pair[(scenario_id, network_profile)]
        source_path, source_call = paths_calls["source"]
        agent_path, agent_call = paths_calls["agent"]
        calls = (source_call, agent_call)
        call_hashes = sorted((sha256_file(source_path), sha256_file(agent_path)))
        if all_hashes.intersection(call_hashes):
            raise QualificationError("call evidence hash was reused across matrix rows")
        all_hashes.update(call_hashes)
        shared_checks = (
            "actual_transfer_header",
            "context_persisted",
            "amazon_attribute_mapped",
            "connect_contact_started_once",
            "agent_screen_visible",
            "audio_source_to_agent_non_silent",
            "audio_agent_to_source_non_silent",
            "dtmf_source_to_agent",
            "dtmf_agent_to_source",
            "cleanup_zero_state",
        )
        checks = {
            name: all(call["checks"][name] is True for call in calls)
            for name in shared_checks
        }
        checks.update(
            {
                "source_hangup_cleanup": source_call["checks"][
                    "originating_hangup_cleanup"
                ]
                is True,
                "agent_hangup_cleanup": agent_call["checks"][
                    "originating_hangup_cleanup"
                ]
                is True,
                "replay_rejected": replay_component["passed"] is True,
                "missing_context_fail_open": missing_component["passed"] is True,
            }
        )
        if set(checks) != required_checks or not all(checks.values()):
            raise QualificationError("one or more aggregated scenario checks failed")
        audio_values = [
            call["timings"][direction]
            for call in calls
            for direction in (
                "source_to_agent_latency_ms_p95",
                "agent_to_source_latency_ms_p95",
            )
        ]
        scenarios.append(
            {
                "id": scenario_id,
                "network_profile": network_profile,
                "call_evidence_sha256": call_hashes,
                "checks": checks,
                "setup_latency_ms_p95": p95(
                    call["timings"]["setup_latency_ms"] for call in calls
                ),
                "audio_latency_ms_p95": p95(audio_values),
                "passed": True,
            }
        )
    return scenarios, all_hashes, starts, ends


def component_map(
    ledger: Mapping[str, Any], directory_name: str, schema: Path
) -> tuple[
    dict[str, tuple[Path, dict[str, Any]]], list[dt.datetime], list[dt.datetime]
]:
    result: dict[str, tuple[Path, dict[str, Any]]] = {}
    starts: list[dt.datetime] = []
    ends: list[dt.datetime] = []
    directory = LIVE.ledger_path(ledger["execution_id"]).parent / directory_name
    for path in evidence_files(directory):
        value = exact_component(path, schema, ledger, controller_owned=True)
        identifier = value["id"]
        if identifier in result:
            raise QualificationError("component evidence contains a duplicate case")
        result[identifier] = (path, value)
        starts.append(parse_timestamp(value["started_at"]))
        ends.append(parse_timestamp(value["ended_at"]))
    return result, starts, ends


def release_artifact_sha(manifest: Mapping[str, Any], artifact: str) -> str:
    matches = [
        item.get("sha256")
        for item in manifest.get("artifacts", [])
        if item.get("path") == artifact
    ]
    if (
        len(matches) != 1
        or not isinstance(matches[0], str)
        or SHA256.fullmatch(matches[0]) is None
    ):
        raise QualificationError("release manifest is missing an exact artifact digest")
    return matches[0]


def stable_live_ledger(
    execution_id: str,
) -> tuple[Path, dict[str, Any], dict[str, str]]:
    path, ledger = LIVE.load_ledger(execution_id)
    if ledger.get("status") not in {"verified", "updated", "lifecycle_verified"}:
        raise QualificationError(
            "live qualification requires a verified stable deployment"
        )
    if ledger.get("publication_source_tree_sha256") != LIVE.working_tree_digest(ROOT):
        raise QualificationError(
            "working tree no longer matches the immutable candidate"
        )
    environment = LIVE.assume_env(ledger, "qualification")
    stack = LIVE.stack_description(ledger, environment, ledger["stack_name"])
    if stack.get("StackStatus") not in {
        "CREATE_COMPLETE",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
    }:
        raise QualificationError("recipe stack is not stable")
    if LIVE.outputs(stack).get("BridgefuImage") != ledger.get("bridgefu_image_uri"):
        raise QualificationError("deployed image no longer matches the candidate")
    validate_qualification_posture(ledger)
    return path, ledger, environment


def runtime_instance_ids(
    ledger: Mapping[str, Any], qualification_environment: Mapping[str, str]
) -> list[str]:
    profile = ledger.get("runtime_profile", "starter")
    if profile == "starter":
        stack_id = LIVE.nested_stack_id(
            dict(ledger), dict(qualification_environment), "StarterRuntime"
        )
        runtime = LIVE.outputs(
            LIVE.stack_description(
                dict(ledger), dict(qualification_environment), stack_id
            )
        )
        instance_ids = [runtime.get("InstanceId", "")]
    else:
        response = LIVE.aws_json(
            [
                "ec2",
                "describe-instances",
                "--region",
                str(ledger["region"]),
                "--filters",
                f"Name=tag:BridgefuExecutionId,Values={ledger['execution_id']}",
                "Name=tag:ManagedBy,Values=bridgefu-cloudformation",
                "Name=instance-state-name,Values=running",
            ],
            env=dict(qualification_environment),
        )
        instance_ids = sorted(
            instance["InstanceId"]
            for reservation in response.get("Reservations", [])
            for instance in reservation.get("Instances", [])
        )
    expected = 1 if profile == "starter" else 4
    if (
        len(instance_ids) != expected
        or len(set(instance_ids)) != expected
        or any(re.fullmatch(r"i-[0-9a-f]{8,32}", item) is None for item in instance_ids)
    ):
        raise QualificationError("runtime instance inventory is not exact")
    return instance_ids


METRIC_NAMES = {
    "bridgefu_process_ready",
    "bridgefu_active_sessions",
    "bridgefu_gateway_native_active_routes",
    "bridgefu_private_forwarding_active_routes",
    "bridgefu_amazon_durable_cleanups_pending",
    "bridgefu_amazon_pending_contact_cleanups",
}
METRIC_LINE = re.compile(
    r"^(bridgefu_[a-z0-9_]+)(?:\{[^{}\r\n]{0,1024}\})?[ \t]+"
    r"(-?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+))(?:[ \t]+[0-9]+)?$"
)


def zero_metric_script(window_seconds: int) -> str:
    if not 60 <= window_seconds <= 1800:
        raise QualificationError("zero-state observation window is out of bounds")
    selectors = "|".join(sorted(METRIC_NAMES))
    return f"""set -euo pipefail
sample() {{
  marker="$1"
  printf '%s\n' "$marker"
  curl --silent --show-error --fail --max-time 5 http://127.0.0.1:9090/metrics \
    | grep -E '^({selectors})(\\{{|[[:space:]])'
}}
sample bridgefu-zero-sample-1
sleep {window_seconds}
sample bridgefu-zero-sample-2
"""


def parse_metric_samples(outputs: Iterable[str]) -> list[dict[str, float]]:
    combined = [{name: 0.0 for name in METRIC_NAMES} for _ in range(2)]
    readiness_observations = [0, 0]
    output_count = 0
    for output in outputs:
        output_count += 1
        sample_index: int | None = None
        seen_markers: set[int] = set()
        seen_ready = [False, False]
        for line in output.splitlines():
            if line == "bridgefu-zero-sample-1":
                sample_index = 0
                seen_markers.add(0)
                continue
            if line == "bridgefu-zero-sample-2":
                sample_index = 1
                seen_markers.add(1)
                continue
            match = METRIC_LINE.fullmatch(line)
            if (
                match is None
                or sample_index is None
                or match.group(1) not in METRIC_NAMES
            ):
                continue
            value = float(match.group(2))
            if not math.isfinite(value) or value < 0:
                raise QualificationError("runtime zero-state metric is invalid")
            name = match.group(1)
            combined[sample_index][name] += value
            if name == "bridgefu_process_ready":
                seen_ready[sample_index] = True
        if seen_markers != {0, 1} or not all(seen_ready):
            raise QualificationError("runtime zero-state samples are incomplete")
        for index, observed in enumerate(seen_ready):
            readiness_observations[index] += int(observed)
    if output_count == 0 or readiness_observations != [output_count, output_count]:
        raise QualificationError("runtime readiness was not observed on every host")
    return combined


def bounded_test_contacts(
    ledger: Mapping[str, Any], qualification_environment: Mapping[str, str]
) -> tuple[int, int]:
    stack_ready = next(
        (
            event.get("at")
            for event in ledger.get("events", [])
            if event.get("event") == "stack_ready"
        ),
        None,
    )
    if not isinstance(stack_ready, str):
        raise QualificationError("deployment start time is unavailable")
    start = parse_timestamp(stack_ready) - dt.timedelta(minutes=5)
    end = dt.datetime.now(dt.timezone.utc)
    instance_id = str(ledger["connect_instance_arn"]).rsplit("/", 1)[-1]
    result = LIVE.aws_json(
        [
            "connect",
            "search-contacts",
            "--region",
            str(ledger["region"]),
            "--instance-id",
            instance_id,
            "--time-range",
            json.dumps(
                {
                    "Type": "INITIATION_TIMESTAMP",
                    "StartTime": start.isoformat(),
                    "EndTime": end.isoformat(),
                },
                separators=(",", ":"),
            ),
            "--search-criteria",
            json.dumps(
                {"Channels": ["VOICE"], "InitiationMethods": ["WEBRTC_API"]},
                separators=(",", ":"),
            ),
            "--max-items",
            "1000",
        ],
        env=dict(qualification_environment),
    )
    contacts = result.get("Contacts", [])
    if (
        result.get("NextToken")
        or not isinstance(contacts, list)
        or len(contacts) > 1000
    ):
        raise QualificationError(
            "Connect contact search exceeded its evidence boundary"
        )
    active = 0
    for contact in contacts:
        if (
            not isinstance(contact, dict)
            or contact.get("Channel") != "VOICE"
            or contact.get("InitiationMethod") != "WEBRTC_API"
            or not isinstance(contact.get("Id"), str)
        ):
            raise QualificationError(
                "Connect contact search returned an unexpected shape"
            )
        if "DisconnectTimestamp" not in contact:
            active += 1
    return len(contacts), active


def active_test_contacts(
    ledger: Mapping[str, Any], qualification_environment: Mapping[str, str]
) -> int:
    return bounded_test_contacts(ledger, qualification_environment)[1]


def zero_state(args: argparse.Namespace) -> None:
    if args.confirm != args.execution_id:
        raise QualificationError(
            "zero-state observation requires the exact execution ID"
    )
    path, ledger, qualification_environment = stable_live_ledger(args.execution_id)
    phase = getattr(args, "phase", "final")
    try:
        output_name = ZERO_STATE_PHASE_FILES[phase]
    except KeyError as error:  # pragma: no cover - argparse owns the public boundary.
        raise QualificationError("zero-state phase is invalid") from error
    output = path.parent / output_name
    if output.exists():
        raise QualificationError(f"{phase.replace('_', '-')} zero-state evidence already exists")
    counts = observe_zero_counts(ledger, qualification_environment, args.window_seconds)
    evidence = {
        "schema_version": 1,
        "producer": PRODUCER,
        "producer_revision_sha256": controller_revision(),
        "execution_id": args.execution_id,
        "recipe": RECIPE,
        "observed_at": utc_now(),
        "observation_window_seconds": args.window_seconds,
        "sources": {
            "bridgefu_metrics": True,
            "connect_contact_query": True,
            "runtime_readiness": True,
        },
        **counts,
        "redacted": True,
        "customer_data_retained": False,
    }
    reject_sensitive(evidence)
    validate_schema(evidence, ZERO_SCHEMA)
    write_private_json(output, evidence)
    LIVE.record(path, ledger, f"{phase}_zero_state_observed")
    print(output)


def negative_output_path(execution: Path, identifier: str) -> Path:
    return execution / "negative-evidence" / f"{identifier}.json"


def write_negative_evidence(
    path: Path,
    ledger: Mapping[str, Any],
    *,
    identifier: str,
    started_at: str,
    outcome: str,
    call_evidence_sha256: str | None,
    agent_workspace_observed: bool,
    zero_state_counts: Mapping[str, int],
    supporting_evidence_sha256: Iterable[str] = (),
) -> None:
    evidence = {
        "schema_version": 1,
        "producer": PRODUCER,
        "producer_revision_sha256": controller_revision(),
        "execution_id": ledger["execution_id"],
        "recipe": RECIPE,
        "id": identifier,
        "started_at": started_at,
        "ended_at": utc_now(),
        "revisions": revision_contract(ledger),
        "outcome": outcome,
        "call_evidence_sha256": call_evidence_sha256,
        "supporting_evidence_sha256": sorted(supporting_evidence_sha256),
        "checks": {
            "stimulus_applied": True,
            "expected_outcome_observed": True,
            "no_duplicate_contact": True,
            "agent_workspace_observed": agent_workspace_observed,
        },
        "zero_state": dict(zero_state_counts),
        "passed": True,
        "redacted": True,
        "customer_data_retained": False,
    }
    reject_sensitive(evidence)
    validate_schema(evidence, NEGATIVE_SCHEMA)
    write_private_json(path, evidence)


def wait_for_contact_total(
    ledger: Mapping[str, Any],
    qualification_environment: Mapping[str, str],
    expected: int,
    *,
    timeout_seconds: int = 60,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while True:
        total, _ = bounded_test_contacts(ledger, qualification_environment)
        if total == expected:
            return
        if total > expected or time.monotonic() >= deadline:
            raise QualificationError("Connect contact count did not converge exactly")
        time.sleep(2)


def synthetic_prepare_payload(nonce: str, *, changed: bool = False) -> dict[str, Any]:
    return {
        "message": {
            "type": "tool-calls",
            "call": {
                "id": f"call_bridgefu_negative_{nonce}",
                "orgId": "org_bridgefu_qualification",
            },
            "toolCallList": [
                {
                    "id": f"tool_bridgefu_negative_{nonce}",
                    "name": "prepare_handoff",
                    "arguments": {
                        "customer_name": (
                            "Bridgefu Synthetic Caller Changed"
                            if changed
                            else "Bridgefu Synthetic Caller"
                        ),
                        "issue_summary": "Qualification negative-case context.",
                        "intent": "qualification",
                        "verification_status": "synthetic",
                    },
                }
            ],
        }
    }


HTTP_NEGATIVE_IDS = {
    "prepare_auth_rejected",
    "prepare_conflicting_replay_rejected",
    "malformed_payload_rejected",
}


def negative_http(args: argparse.Namespace) -> None:
    if args.confirm != args.execution_id:
        raise QualificationError("HTTP negative case requires the exact execution ID")
    path, ledger, qualification_environment = stable_live_ledger(args.execution_id)
    if args.id not in HTTP_NEGATIVE_IDS:
        raise QualificationError("unknown HTTP negative case")
    output = negative_output_path(path.parent, args.id)
    if output.exists():
        raise QualificationError("negative-case evidence already exists")
    before, _ = bounded_test_contacts(ledger, qualification_environment)
    handoff = COLLECTOR.nested_outputs(
        ledger, qualification_environment, "HandoffService"
    )
    webhook = LIVE.secret_value(
        ledger, qualification_environment, handoff["VapiWebhookSecretArn"]
    )
    nonce = os.urandom(12).hex()
    started_at = utc_now()
    if args.id == "prepare_auth_rejected":
        status, body = LIVE.http_post(
            handoff["PrepareUrl"],
            os.urandom(32).hex(),
            synthetic_prepare_payload(nonce),
        )
        expected = (401, {"error": "unauthorized"})
        outcome = "rejected"
    elif args.id == "prepare_conflicting_replay_rejected":
        first_status, first_body = LIVE.http_post(
            handoff["PrepareUrl"], webhook, synthetic_prepare_payload(nonce)
        )
        if first_status != 200 or first_body != {
            "results": [
                {
                    "name": "prepare_handoff",
                    "toolCallId": f"tool_bridgefu_negative_{nonce}",
                    "result": {"status": "prepared"},
                }
            ]
        }:
            raise QualificationError("conflicting-replay setup was not created exactly")
        status, body = LIVE.http_post(
            handoff["PrepareUrl"],
            webhook,
            synthetic_prepare_payload(nonce, changed=True),
        )
        expected = (409, {"error": "handoff_replay_conflict"})
        outcome = "conflict_rejected"
    else:
        status, body = LIVE.http_post(
            handoff["PrepareUrl"],
            webhook,
            {"message": {"type": "tool-calls"}},
        )
        expected = (400, {"error": "invalid_vapi_call"})
        outcome = "rejected"
    if (status, body) != expected:
        raise QualificationError(
            "live HTTP negative outcome did not match its contract"
        )
    wait_for_contact_total(
        ledger, qualification_environment, before, timeout_seconds=10
    )
    zero = observe_zero_counts(ledger, qualification_environment, args.window_seconds)
    write_negative_evidence(
        output,
        ledger,
        identifier=args.id,
        started_at=started_at,
        outcome=outcome,
        call_evidence_sha256=None,
        supporting_evidence_sha256=(),
        agent_workspace_observed=False,
        zero_state_counts=zero,
    )
    LIVE.record(path, ledger, "negative_case_completed", case=args.id)
    print(output)


SIP_NEGATIVE_CASES = {
    "missing_correlation_header_rejected": "missing-correlation-header",
    "duplicate_correlation_header_rejected": "duplicate-correlation-header",
    "expired_attachment_rejected": "expired-attachment",
    "source_cancellation_cleanup": "source-cancellation",
}


def packaged_example_command(example: str) -> list[str]:
    """Use the immutable release binary in CodeBuild, or cargo for manual runs."""
    if example not in {"recipe_sip_negative", "recipe_sip_source"}:
        raise QualificationError("packaged qualification example is unsupported")
    if os.environ.get("BRIDGEFU_PACKAGED_SOURCE") != "1":
        return ["cargo", "run", "--locked", "--quiet", "--example", example, "--"]
    executable = ROOT / "target" / "release" / "examples" / example
    try:
        details = executable.lstat()
    except FileNotFoundError as error:
        raise QualificationError("packaged qualification example is missing") from error
    if (
        executable.is_symlink()
        or not stat.S_ISREG(details.st_mode)
        or details.st_mode & 0o111 == 0
    ):
        raise QualificationError("packaged qualification example is unsafe")
    return [os.fspath(executable)]


def private_negative_observation(
    observation_path: Path,
    session: Mapping[str, Any],
    identifier: str,
) -> dict[str, Any]:
    regular_file(observation_path)
    if observation_path.stat().st_mode & 0o077:
        raise QualificationError("SIP negative observation must be mode 0600")
    value = load_json(observation_path)
    expected = {
        "schema_version",
        "producer",
        "producer_revision_sha256",
        "execution_id",
        "id",
        "correlation_fingerprint",
        "source_call_fingerprint",
        "started_at",
        "ended_at",
        "transport",
        "invite_count",
        "wire_header_count",
        "cancel_count",
        "rejection_status",
        "answered",
        "cancellation_completed",
        "redacted",
    }
    expected_headers = {
        "missing_correlation_header_rejected": 0,
        "duplicate_correlation_header_rejected": 2,
        "expired_attachment_rejected": 1,
        "source_cancellation_cleanup": 1,
    }
    cancellation = identifier == "source_cancellation_cleanup"
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("schema_version") != 1
        or value.get("producer") != "bridgefu-recipe-sip-negative@1"
        or value.get("producer_revision_sha256") != sha256_file(SIP_NEGATIVE_SOURCE)
        or value.get("execution_id") != session.get("execution_id")
        or value.get("id") != identifier
        or value.get("correlation_fingerprint")
        != session.get("correlation_fingerprint")
        or value.get("source_call_fingerprint")
        != session.get("source_call_fingerprint")
        or value.get("transport")
        != ("tls" if session.get("security") == "sips_srtp" else "udp")
        or value.get("invite_count") != 1
        or value.get("wire_header_count") != expected_headers[identifier]
        or value.get("cancel_count") != (1 if cancellation else 0)
        or value.get("answered") is not False
        or value.get("cancellation_completed") is not cancellation
        or value.get("redacted") is not True
        or (cancellation and value.get("rejection_status") is not None)
        or (
            not cancellation
            and (
                not isinstance(value.get("rejection_status"), int)
                or not 300 <= value["rejection_status"] <= 699
            )
        )
    ):
        raise QualificationError("SIP negative observation does not match its session")
    parse_timestamp(value["started_at"])
    parse_timestamp(value["ended_at"])
    reject_sensitive(value)
    return value


def runtime_log_outputs(
    ledger: Mapping[str, Any], qualification_environment: Mapping[str, str]
) -> tuple[dict[str, str], dict[str, str]]:
    runtime_logical = (
        "HighAvailabilityRuntime"
        if ledger.get("runtime_profile") == "high_availability"
        else "StarterRuntime"
    )
    return (
        COLLECTOR.nested_outputs(ledger, qualification_environment, runtime_logical),
        COLLECTOR.nested_outputs(ledger, qualification_environment, "HandoffService"),
    )


def wait_for_session_logs(
    ledger: Mapping[str, Any],
    qualification_environment: Mapping[str, str],
    session: Mapping[str, Any],
    *,
    lookup_result: str | None,
    required_stages: set[str],
    timeout_seconds: int = 120,
) -> tuple[dict[str, int], list[str]]:
    runtime, handoff = runtime_log_outputs(ledger, qualification_environment)
    deadline = time.monotonic() + timeout_seconds
    while True:
        runtime_events = COLLECTOR.filter_log_events(
            ledger,
            qualification_environment,
            runtime["RuntimeLogGroupName"],
            session["correlation_fingerprint"],
            session["started_epoch_ms"],
        )
        lookup_events = COLLECTOR.filter_log_events(
            ledger,
            qualification_environment,
            handoff["LookupLogGroupName"],
            session["correlation_fingerprint"],
            session["started_epoch_ms"],
        )
        stages, _, results = COLLECTOR.log_evidence(
            runtime_events, lookup_events, session["correlation_fingerprint"]
        )
        if required_stages.issubset(stages) and (
            lookup_result is None or lookup_result in results
        ):
            return stages, results
        if time.monotonic() >= deadline:
            raise QualificationError("correlated negative-case logs did not converge")
        time.sleep(3)


def negative_sip(args: argparse.Namespace) -> None:
    if args.confirm != args.execution_id:
        raise QualificationError("SIP negative case requires the exact execution ID")
    path, ledger, qualification_environment = stable_live_ledger(args.execution_id)
    if args.id not in SIP_NEGATIVE_CASES:
        raise QualificationError("unknown SIP negative case")
    output = negative_output_path(path.parent, args.id)
    if output.exists():
        raise QualificationError("negative-case evidence already exists")
    session_path = args.session.resolve()
    session = COLLECTOR.require_private_session(session_path, args.execution_id)
    COLLECTOR.validate_private_session(
        session, args.execution_id, ledger, qualification_environment
    )
    if (
        session.get("scenario_id") not in COLLECTOR.DIRECT_SCENARIOS
        or session.get("network_profile") != "baseline"
    ):
        raise QualificationError("SIP negative case requires a baseline direct session")
    before, _ = bounded_test_contacts(ledger, qualification_environment)
    observation_dir = path.parent / "negative-observations"
    observation_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(observation_dir, 0o700)
    observation_path = (
        observation_dir / f"{args.id}-{session['session_id']}.private.json"
    )
    if observation_path.exists():
        raise QualificationError("SIP negative observation already exists")
    command = [
        *packaged_example_command("recipe_sip_negative"),
        "--session",
        os.fspath(session_path),
        "--output",
        os.fspath(observation_path),
        "--case",
        SIP_NEGATIVE_CASES[args.id],
        "--timeout-seconds",
        "180",
    ]
    if args.id == "expired_attachment_rejected":
        handoff = COLLECTOR.nested_outputs(
            ledger, qualification_environment, "HandoffService"
        )
        root = LIVE.outputs(
            LIVE.stack_description(
                dict(ledger),
                dict(qualification_environment),
                str(ledger["stack_name"]),
            )
        )
        row = COLLECTOR.get_handoff_row(
            ledger,
            qualification_environment,
            root["HandoffTableName"],
            session["correlation_id"],
        )
        COLLECTOR.verify_handoff_row(row, session)
        if not handoff:
            raise QualificationError("handoff service outputs are unavailable")
        not_before = max(int(time.time()), int(row["attachment_expires_at"]) + 2)
        command.extend(["--not-before-epoch", str(not_before)])
    environment = os.environ.copy()
    environment["RUST_LOG"] = "error"
    with COLLECTOR.controlled_network(
        path,
        ledger,
        qualification_environment,
        "baseline",
        session["session_id"],
    ):
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=360,
        )
    if result.returncode != 0:
        raise QualificationError("protected SIP negative probe failed")
    observation = private_negative_observation(observation_path, session, args.id)
    if args.id == "source_cancellation_cleanup":
        stages, _ = wait_for_session_logs(
            ledger,
            qualification_environment,
            session,
            lookup_result=None,
            required_stages={"sip_invite_received", "teardown_started", "terminated"},
        )
        contact_count = stages.get("contact_started", 0)
        if contact_count not in {0, 1}:
            raise QualificationError("source cancellation started duplicate contacts")
        wait_for_contact_total(
            ledger, qualification_environment, before + contact_count
        )
        outcome = "cancelled_cleanly"
    else:
        wait_for_contact_total(
            ledger, qualification_environment, before, timeout_seconds=10
        )
        outcome = "rejected"
    zero = observe_zero_counts(ledger, qualification_environment, args.window_seconds)
    write_negative_evidence(
        output,
        ledger,
        identifier=args.id,
        started_at=observation["started_at"],
        outcome=outcome,
        call_evidence_sha256=None,
        supporting_evidence_sha256=(sha256_file(observation_path),),
        agent_workspace_observed=False,
        zero_state_counts=zero,
    )
    session_path.unlink()
    LIVE.record(path, ledger, "negative_case_completed", case=args.id)
    print(output)


def negative_from_call(args: argparse.Namespace) -> None:
    if args.confirm != args.execution_id:
        raise QualificationError(
            "call-derived negative case requires exact confirmation"
        )
    path, ledger, qualification_environment = stable_live_ledger(args.execution_id)
    if args.id != "attachment_replay_rejected":
        raise QualificationError("unknown call-derived negative case")
    output = negative_output_path(path.parent, args.id)
    if output.exists():
        raise QualificationError("negative-case evidence already exists")
    call_path = args.call_evidence.resolve()
    if call_path.parent != (path.parent / "call-evidence").resolve():
        raise QualificationError("call-derived evidence must be a retained matrix call")
    call = exact_component(call_path, CALL_SCHEMA, ledger, controller_owned=False)
    if (
        call.get("scenario_id") not in COLLECTOR.DIRECT_SCENARIOS
        or call.get("observations", {}).get("attachment_replay_rejected") is not True
        or call.get("checks", {}).get("connect_contact_started_once") is not True
    ):
        raise QualificationError(
            "retained call did not prove one-use attachment replay"
        )
    started_at = utc_now()
    zero = observe_zero_counts(ledger, qualification_environment, args.window_seconds)
    write_negative_evidence(
        output,
        ledger,
        identifier=args.id,
        started_at=started_at,
        outcome="replay_rejected",
        call_evidence_sha256=sha256_file(call_path),
        supporting_evidence_sha256=(sha256_file(call_path),),
        agent_workspace_observed=False,
        zero_state_counts=zero,
    )
    LIVE.record(path, ledger, "negative_case_completed", case=args.id)
    print(output)


def delete_synthetic_context(
    ledger_path: Path,
    ledger: Mapping[str, Any],
    qualification_environment: Mapping[str, str],
    table_name: str,
    session: Mapping[str, Any],
    row: Mapping[str, Any],
    *,
    expected_status: str = "RESERVED",
) -> None:
    if expected_status not in {"PREPARED", "RESERVED"}:
        raise QualificationError("synthetic context deletion status is invalid")
    if row.get("handoff_status") != expected_status:
        raise QualificationError(
            "synthetic context row is not in its exact expected state"
        )
    token = os.urandom(8).hex()
    key_path = ledger_path.parent / f"context-delete-key-{token}.private.json"
    names_path = ledger_path.parent / f"context-delete-names-{token}.private.json"
    values_path = ledger_path.parent / f"context-delete-values-{token}.private.json"
    write_private_json(key_path, {"correlation_id": {"S": session["correlation_id"]}})
    write_private_json(
        names_path,
        {
            "#customer": "customer_name",
            "#intent": "intent",
            "#status": "handoff_status",
            "#verification": "verification_status",
            "#fingerprint": "vapi_call_fingerprint",
        },
    )
    write_private_json(
        values_path,
        {
            ":customer": {"S": "Bridgefu Synthetic Caller"},
            ":intent": {"S": "qualification"},
            ":status": {"S": expected_status},
            ":verification": {"S": "synthetic"},
            ":fingerprint": {"S": row["vapi_call_fingerprint"]},
        },
    )
    try:
        response = LIVE.aws_json(
            [
                "dynamodb",
                "delete-item",
                "--region",
                str(ledger["region"]),
                "--table-name",
                table_name,
                "--key",
                f"file://{key_path}",
                "--condition-expression",
                "#customer = :customer AND #intent = :intent AND #status = :status "
                "AND #verification = :verification AND #fingerprint = :fingerprint",
                "--expression-attribute-names",
                f"file://{names_path}",
                "--expression-attribute-values",
                f"file://{values_path}",
                "--return-values",
                "ALL_OLD",
            ],
            env=dict(qualification_environment),
        )
        deleted = COLLECTOR.decode_dynamo_item(response.get("Attributes"))
        if deleted != dict(row):
            raise QualificationError(
                "synthetic context deletion returned a changed row"
            )
        remaining = LIVE.aws_json(
            [
                "dynamodb",
                "get-item",
                "--region",
                str(ledger["region"]),
                "--table-name",
                table_name,
                "--key",
                f"file://{key_path}",
                "--consistent-read",
            ],
            env=dict(qualification_environment),
        )
        if remaining.get("Item"):
            raise QualificationError(
                "synthetic context row still exists after deletion"
            )
    finally:
        key_path.unlink(missing_ok=True)
        names_path.unlink(missing_ok=True)
        values_path.unlink(missing_ok=True)


def validate_missing_context_observers(
    session: Mapping[str, Any],
    participant_path: Path,
    source_path: Path,
    screenshot_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    participant = load_json(participant_path)
    validate_schema(participant, MISSING_CONTEXT_PARTICIPANT_SCHEMA)
    reject_sensitive(participant)
    source = load_json(source_path)
    validate_schema(source, SOURCE_SCHEMA)
    reject_sensitive(source)
    identity = (
        participant.get("execution_id") == session.get("execution_id")
        and source.get("execution_id") == session.get("execution_id")
        and participant.get("scenario_id") == session.get("scenario_id")
        and source.get("scenario_id") == session.get("scenario_id")
        and participant.get("hangup_origin") == "source"
        and source.get("hangup_origin") == "source"
        and participant.get("correlation_fingerprint")
        == session.get("correlation_fingerprint")
        and source.get("correlation_fingerprint")
        == session.get("correlation_fingerprint")
        and participant.get("source_call_fingerprint")
        == session.get("source_call_fingerprint")
        and source.get("source_call_fingerprint")
        == session.get("source_call_fingerprint")
    )
    if (
        not identity
        or participant.get("producer_revision_sha256") != sha256_file(AGENT_HARNESS)
        or source.get("producer_revision_sha256") != sha256_file(SIP_SOURCE)
        or source.get("signaling", {}).get("attachment_replay_rejected") is not True
        or source.get("hangup", {}).get("cleanup_observed") is not True
        or participant.get("hangup", {}).get("cleanup_observed") is not True
    ):
        raise QualificationError(
            "missing-context observers do not match the live session"
        )
    COLLECTOR.regular_bounded_file(screenshot_path, COLLECTOR.MAX_SCREENSHOT_BYTES)
    screenshot_digest = sha256_file(screenshot_path)
    if (
        participant["generic_screen"]["screenshot_sha256"] != screenshot_digest
        or COLLECTOR.marker_latency_ms(
            source["media"]["source_marker_sent_at_ms"],
            participant["media"]["source_marker_observed_at_ms"],
        )
        > 5_000
        or COLLECTOR.marker_latency_ms(
            participant["media"]["agent_marker_sent_at_ms"],
            source["media"]["agent_marker_observed_at_ms"],
        )
        > 5_000
    ):
        raise QualificationError(
            "missing-context screen or media evidence is incomplete"
        )
    return participant, source


def negative_missing_context(args: argparse.Namespace) -> None:
    if args.confirm != args.execution_id:
        raise QualificationError("missing-context case requires exact confirmation")
    path, ledger, qualification_environment = stable_live_ledger(args.execution_id)
    output = negative_output_path(path.parent, "missing_context_fail_open")
    if output.exists():
        raise QualificationError("negative-case evidence already exists")
    session_path = args.session.resolve()
    session = COLLECTOR.require_private_session(session_path, args.execution_id)
    COLLECTOR.validate_private_session(
        session, args.execution_id, ledger, qualification_environment
    )
    if (
        session.get("scenario_id") not in COLLECTOR.DIRECT_SCENARIOS
        or session.get("hangup_origin") != "source"
        or session.get("network_profile") != "baseline"
    ):
        raise QualificationError(
            "missing-context case requires a source-hangup baseline direct session"
        )
    storage_state = args.storage_state.resolve()
    COLLECTOR.regular_bounded_file(storage_state, MAX_JSON_BYTES)
    if storage_state.stat().st_mode & 0o077:
        raise QualificationError("Agent Workspace storage state must be mode 0600")
    COLLECTOR.validate_connect_url(args.connect_url)
    root_outputs = LIVE.outputs(
        LIVE.stack_description(
            dict(ledger),
            dict(qualification_environment),
            str(ledger["stack_name"]),
        )
    )
    table_name = root_outputs["HandoffTableName"]
    row = COLLECTOR.get_handoff_row(
        ledger,
        qualification_environment,
        table_name,
        session["correlation_id"],
    )
    COLLECTOR.verify_handoff_row(row, session)
    before, _ = bounded_test_contacts(ledger, qualification_environment)
    started_at = utc_now()
    delete_synthetic_context(
        path,
        ledger,
        qualification_environment,
        table_name,
        session,
        row,
    )

    participant_dir = path.parent / "participant-observations"
    source_dir = path.parent / "source-observations"
    screenshot_dir = path.parent / "screenshots"
    for directory in (participant_dir, source_dir, screenshot_dir):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
    basename = f"missing-context-{session['session_id']}"
    participant_path = participant_dir / f"{basename}.json"
    source_path = source_dir / f"{basename}.json"
    screenshot_path = screenshot_dir / f"{basename}.png"
    if any(item.exists() for item in (participant_path, source_path, screenshot_path)):
        raise QualificationError("missing-context observer output already exists")
    agent_command = [
        "node",
        os.fspath(AGENT_HARNESS),
        "observe",
        "--session",
        os.fspath(session_path),
        "--storage-state",
        os.fspath(storage_state),
        "--connect-url",
        args.connect_url,
        "--screenshot",
        os.fspath(screenshot_path),
        "--observation",
        os.fspath(participant_path),
        "--timeout-seconds",
        str(args.observer_timeout_seconds),
        "--expect-missing-context",
    ]
    if args.headed:
        agent_command.append("--headed")
    source_command = [
        *packaged_example_command("recipe_sip_source"),
        "--session",
        os.fspath(session_path),
        "--output",
        os.fspath(source_path),
        "--timeout-seconds",
        str(args.observer_timeout_seconds),
    ]
    process_environment = os.environ.copy()
    process_environment["RUST_LOG"] = "error"
    agent: subprocess.Popen[str] | None = None
    source: subprocess.Popen[str] | None = None
    with COLLECTOR.controlled_network(
        path,
        ledger,
        qualification_environment,
        "baseline",
        session["session_id"],
    ):
        try:
            agent = subprocess.Popen(
                agent_command,
                cwd=ROOT,
                env=process_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            time.sleep(3)
            if agent.poll() is not None:
                raise QualificationError(
                    "missing-context Agent Workspace observer stopped"
                )
            source = subprocess.Popen(
                source_command,
                cwd=ROOT,
                env=process_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            deadline = time.monotonic() + args.observer_timeout_seconds + 60
            while agent.poll() is None or source.poll() is None:
                if agent.poll() not in {None, 0} or source.poll() not in {None, 0}:
                    raise QualificationError("a missing-context live observer failed")
                if time.monotonic() >= deadline:
                    raise QualificationError(
                        "missing-context observers exceeded their deadline"
                    )
                time.sleep(0.25)
            if agent.returncode != 0 or source.returncode != 0:
                raise QualificationError("a missing-context live observer failed")
        finally:
            if source is not None:
                COLLECTOR.terminate_process(source)
                source.communicate(timeout=5)
            if agent is not None:
                COLLECTOR.terminate_process(agent)
                agent.communicate(timeout=5)
    validate_missing_context_observers(
        session, participant_path, source_path, screenshot_path
    )
    stages, results = wait_for_session_logs(
        ledger,
        qualification_environment,
        session,
        lookup_result="unavailable",
        required_stages=set(COLLECTOR.REQUIRED_LIFECYCLE),
    )
    runtime, _ = runtime_log_outputs(ledger, qualification_environment)
    runtime_events = COLLECTOR.filter_log_events(
        ledger,
        qualification_environment,
        runtime["RuntimeLogGroupName"],
        session["correlation_fingerprint"],
        session["started_epoch_ms"],
    )
    if (
        stages.get("contact_started") != 1
        or results.count("unavailable") != 1
        or not COLLECTOR.sip_invite_header_evidence(
            runtime_events, session["correlation_fingerprint"]
        )
    ):
        raise QualificationError("missing-context lifecycle or lookup was not exact")
    wait_for_contact_total(ledger, qualification_environment, before + 1)
    zero = observe_zero_counts(ledger, qualification_environment, args.window_seconds)
    supporting = tuple(
        sha256_file(item) for item in (participant_path, source_path, screenshot_path)
    )
    write_negative_evidence(
        output,
        ledger,
        identifier="missing_context_fail_open",
        started_at=started_at,
        outcome="failed_open",
        call_evidence_sha256=None,
        supporting_evidence_sha256=supporting,
        agent_workspace_observed=True,
        zero_state_counts=zero,
    )
    session_path.unlink()
    LIVE.record(
        path, ledger, "negative_case_completed", case="missing_context_fail_open"
    )
    print(output)


def soak_pending_path(execution: Path) -> Path:
    return execution / "soak-pending.private.json"


def soak_monitor_start_script(token: str) -> str:
    if re.fullmatch(r"[0-9a-f]{12}", token) is None:
        raise QualificationError("soak monitor token is invalid")
    script = r"""set -euo pipefail
token="__TOKEN__"
root=/run/bridgefu-qualification
collector="$root/soak-$token"
output="$root/soak-$token.csv"
unit="bridgefu-soak-$token"
install -d -m 0700 "$root"
test ! -e "$collector"
test ! -e "$output"
cat > "$collector" <<'BRIDGEFU_SOAK'
#!/usr/bin/env bash
set -euo pipefail
output="$1"
metric_sum() {
  metric="$1"
  printf '%s\n' "$metrics" | awk -v metric="$metric" '
    $1 == metric || index($1, metric "{") == 1 { value += $2 }
    END { printf "%.6f", value + 0 }
  '
}
while true; do
  mapfile -t containers < <(docker ps --quiet)
  test "${#containers[@]}" -ge 1
  pids=()
  for container in "${containers[@]}"; do
    pid="$(docker inspect --format '{{.State.Pid}}' "$container")"
    test "$pid" -gt 1
    pids+=("$pid")
  done
  cpu_total=0
  memory_total=0
  descriptor_total=0
  for pid in "${pids[@]}"; do
    cpu="$(ps -p "$pid" -o %cpu= | tr -d ' ')"
    memory="$(ps -p "$pid" -o %mem= | tr -d ' ')"
    test -n "$cpu"
    test -n "$memory"
    cpu_total="$(awk -v left="$cpu_total" -v right="$cpu" 'BEGIN { printf "%.6f", left + right }')"
    memory_total="$(awk -v left="$memory_total" -v right="$memory" 'BEGIN { printf "%.6f", left + right }')"
    descriptors="$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 -printf . 2>/dev/null | wc -c)"
    descriptor_total=$((descriptor_total + descriptors))
  done
  processors="$(nproc)"
  cpu_percent="$(awk -v value="$cpu_total" -v processors="$processors" '
    BEGIN { value = value / processors; if (value > 100) value = 100; printf "%.3f", value }
  ')"
  memory_percent="$(awk -v value="$memory_total" '
    BEGIN { if (value > 100) value = 100; printf "%.3f", value }
  ')"
  rtp_ports="$(ss -Huan | awk '
    {
      endpoint = $4
      count = split(endpoint, parts, ":")
      port = parts[count] + 0
      if (port >= 16384 && port <= 32767) seen[endpoint] = 1
    }
    END { for (endpoint in seen) total += 1; print total + 0 }
  ')"
  iface="$(ip -o route show to default | awk 'NR == 1 {print $5}')"
  test -n "$iface"
  rx_errors="$(cat "/sys/class/net/$iface/statistics/rx_errors")"
  tx_errors="$(cat "/sys/class/net/$iface/statistics/tx_errors")"
  network_errors=$((rx_errors + tx_errors))
  metrics="$(curl --silent --show-error --fail --max-time 5 http://127.0.0.1:9090/metrics)"
  media_drops="$(awk -v left="$(metric_sum bridgefu_gateway_native_media_dropped_total)" \
    -v right="$(metric_sum bridgefu_private_forwarding_drops_total)" \
    'BEGIN { printf "%.0f", left + right }')"
  cleanup_backlog="$(awk \
    -v left="$(metric_sum bridgefu_amazon_durable_cleanups_pending)" \
    -v right="$(metric_sum bridgefu_amazon_pending_contact_cleanups)" \
    'BEGIN { printf "%.0f", left + right }')"
  printf 'bridgefu-soak-sample-v1,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(date +%s)" "$cpu_percent" "$memory_percent" "$descriptor_total" \
    "$rtp_ports" "$network_errors" "$media_drops" "$cleanup_backlog" >> "$output"
  chmod 0600 "$output"
  sleep 30
done
BRIDGEFU_SOAK
chmod 0700 "$collector"
systemd-run --quiet --unit="$unit" --property=RuntimeMaxSec=5400 "$collector" "$output"
for _ in $(seq 1 15); do
  if test -s "$output" && systemctl is-active --quiet "$unit.service"; then
    printf 'bridgefu-soak-monitor-started-v1\n'
    exit 0
  fi
  sleep 1
done
exit 42
"""
    return script.replace("__TOKEN__", token)


def soak_monitor_finish_script(token: str) -> str:
    if re.fullmatch(r"[0-9a-f]{12}", token) is None:
        raise QualificationError("soak monitor token is invalid")
    return f"""set -euo pipefail
token="{token}"
root=/run/bridgefu-qualification
collector="$root/soak-$token"
output="$root/soak-$token.csv"
unit="bridgefu-soak-$token"
test -f "$collector"
test -s "$output"
systemctl stop "$unit.service" >/dev/null 2>&1 || true
printf 'bridgefu-soak-monitor-evidence-v1,%s\n' "$token"
tail -n 140 "$output"
rm -f "$collector" "$output"
systemctl reset-failed "$unit.service" >/dev/null 2>&1 || true
"""


def parse_soak_samples(
    outputs: Iterable[str], token: str, started_at: dt.datetime, ended_at: dt.datetime
) -> dict[str, int | float]:
    hosts = 0
    cpu_max = 0.0
    memory_max = 0.0
    descriptors_max = 0
    rtp_max = 0
    network_delta = 0
    media_delta = 0
    cleanup_max = 0
    for output in outputs:
        lines = output.splitlines()
        marker = f"bridgefu-soak-monitor-evidence-v1,{token}"
        if lines.count(marker) != 1:
            raise QualificationError("soak monitor evidence marker is incomplete")
        rows: list[tuple[int, float, float, int, int, int, int, int]] = []
        for line in lines[lines.index(marker) + 1 :]:
            fields = line.split(",")
            if len(fields) != 9 or fields[0] != "bridgefu-soak-sample-v1":
                raise QualificationError("soak monitor sample shape is invalid")
            try:
                row = (
                    int(fields[1]),
                    float(fields[2]),
                    float(fields[3]),
                    int(fields[4]),
                    int(fields[5]),
                    int(fields[6]),
                    int(fields[7]),
                    int(fields[8]),
                )
            except ValueError as error:
                raise QualificationError(
                    "soak monitor sample is not numeric"
                ) from error
            if (
                not 0 <= row[1] <= 100
                or not 0 <= row[2] <= 100
                or any(value < 0 for value in row[3:])
            ):
                raise QualificationError("soak monitor sample is outside its boundary")
            rows.append(row)
        if len(rows) < 100 or len(rows) > 140:
            raise QualificationError("soak monitor sample count is incomplete")
        epochs = [row[0] for row in rows]
        if epochs != sorted(epochs) or len(set(epochs)) != len(epochs):
            raise QualificationError("soak monitor sample timestamps are not monotonic")
        if (
            epochs[0] > int(started_at.timestamp()) + 90
            or epochs[-1] < int(ended_at.timestamp()) - 90
        ):
            raise QualificationError(
                "soak monitor did not cover the qualification window"
            )
        if any(
            right[metric] < left[metric]
            for left, right in zip(rows, rows[1:])
            for metric in (5, 6)
        ):
            raise QualificationError("soak error counters reset during the observation")
        hosts += 1
        cpu_max = max(cpu_max, *(row[1] for row in rows))
        memory_max = max(memory_max, *(row[2] for row in rows))
        descriptors_max = max(descriptors_max, *(row[3] for row in rows))
        rtp_max = max(rtp_max, *(row[4] for row in rows))
        network_delta += rows[-1][5] - rows[0][5]
        media_delta += rows[-1][6] - rows[0][6]
        cleanup_max = max(cleanup_max, *(row[7] for row in rows))
    if hosts == 0:
        raise QualificationError("soak monitor produced no host evidence")
    if rtp_max < 1:
        raise QualificationError(
            "soak monitor never observed a local RTP socket during retained calls"
        )
    return {
        "cpu_percent_max": round(cpu_max, 3),
        "memory_percent_max": round(memory_max, 3),
        "file_descriptors_max": descriptors_max,
        "rtp_ports_in_use_max": rtp_max,
        "network_errors": network_delta,
        "media_drops": media_delta,
        "cleanup_backlog_max": cleanup_max,
    }


def pending_soak(path: Path, ledger: Mapping[str, Any]) -> dict[str, Any]:
    regular_file(path)
    if path.stat().st_mode & 0o077:
        raise QualificationError("pending soak evidence must be mode 0600")
    value = load_json(path)
    expected = {
        "schema_version",
        "producer",
        "producer_revision_sha256",
        "execution_id",
        "recipe",
        "started_at",
        "revisions",
        "token",
        "target_count",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("schema_version") != 1
        or value.get("producer") != PRODUCER
        or value.get("producer_revision_sha256") != controller_revision()
        or value.get("execution_id") != ledger.get("execution_id")
        or value.get("recipe") != RECIPE
        or value.get("revisions") != revision_contract(ledger)
        or re.fullmatch(r"[0-9a-f]{12}", str(value.get("token", ""))) is None
        or value.get("target_count")
        != (1 if ledger.get("runtime_profile", "starter") == "starter" else 4)
    ):
        raise QualificationError("pending soak evidence is invalid")
    parse_timestamp(value["started_at"])
    return value


def soak_start(args: argparse.Namespace) -> None:
    if args.confirm != args.execution_id:
        raise QualificationError("soak start requires the exact execution ID")
    path, ledger, qualification_environment = stable_live_ledger(args.execution_id)
    pending_path = soak_pending_path(path.parent)
    output = path.parent / "soak-evidence.json"
    if pending_path.exists() or output.exists():
        raise QualificationError("soak evidence already exists or is pending")
    call_directory = path.parent / "call-evidence"
    if call_directory.exists() and any(call_directory.glob("*.json")):
        raise QualificationError("soak must begin before retained matrix calls")
    instance_ids = runtime_instance_ids(ledger, qualification_environment)
    token = os.urandom(6).hex()
    started_at = utc_now()
    outputs = LIVE.ssm_shell(
        dict(ledger),
        dict(qualification_environment),
        instance_ids,
        soak_monitor_start_script(token),
    )
    if len(outputs) != len(instance_ids) or any(
        "bridgefu-soak-monitor-started-v1" not in output for output in outputs
    ):
        raise QualificationError("soak host monitors did not start exactly")
    value = {
        "schema_version": 1,
        "producer": PRODUCER,
        "producer_revision_sha256": controller_revision(),
        "execution_id": args.execution_id,
        "recipe": RECIPE,
        "started_at": started_at,
        "revisions": revision_contract(ledger),
        "token": token,
        "target_count": len(instance_ids),
    }
    write_private_json(pending_path, value)
    LIVE.record(path, ledger, "soak_observation_started")
    print(pending_path)


def soak_call_evidence(
    execution: Path,
    ledger: Mapping[str, Any],
    started_at: dt.datetime,
    ended_at: dt.datetime,
) -> tuple[list[str], list[float], list[float]]:
    matrix = yaml.safe_load(MATRIX.read_text(encoding="utf-8"))
    required = {
        (scenario["id"], network["id"], origin)
        for scenario in required_scenarios_for_ledger(matrix, ledger)
        for network in matrix["adverse_network_profiles"]
        for origin in ("source", "agent")
    }
    observed: dict[tuple[str, str, str], Path] = {}
    starts: list[dt.datetime] = []
    ends: list[dt.datetime] = []
    setup: list[float] = []
    audio: list[float] = []
    for call_path in evidence_files(execution / "call-evidence"):
        call = exact_component(call_path, CALL_SCHEMA, ledger, controller_owned=False)
        key = (call["scenario_id"], call["network"]["profile"], call["hangup_origin"])
        if key not in required or key in observed:
            raise QualificationError(
                "soak call matrix contains an unexpected duplicate"
            )
        call_start = parse_timestamp(call["started_at"])
        call_end = parse_timestamp(call["ended_at"])
        if call_start < started_at or call_end > ended_at or call_end < call_start:
            raise QualificationError("soak call falls outside the observation window")
        observed[key] = call_path
        starts.append(call_start)
        ends.append(call_end)
        setup.append(call["timings"]["setup_latency_ms"])
        audio.extend(
            [
                call["timings"]["source_to_agent_latency_ms_p95"],
                call["timings"]["agent_to_source_latency_ms_p95"],
            ]
        )
    if set(observed) != required:
        raise QualificationError("soak call matrix is incomplete")
    ordered_starts = sorted(starts)
    if (
        ordered_starts[0] > started_at + dt.timedelta(minutes=10)
        or max(ends) < started_at + dt.timedelta(minutes=50)
        or any(
            (right - left).total_seconds() > 600
            for left, right in zip(ordered_starts, ordered_starts[1:])
        )
    ):
        raise QualificationError("soak calls were not distributed across the hour")
    hashes = sorted(sha256_file(path) for path in observed.values())
    if len(set(hashes)) != len(required):
        raise QualificationError("soak call evidence hashes are not unique")
    return hashes, setup, audio


def cloudwatch_soak_errors(
    ledger_path: Path,
    ledger: Mapping[str, Any],
    qualification_environment: Mapping[str, str],
    started_at: dt.datetime,
    ended_at: dt.datetime,
) -> tuple[int, int]:
    handoff = COLLECTOR.nested_outputs(
        ledger, qualification_environment, "HandoffService"
    )
    vapi = COLLECTOR.nested_outputs(ledger, qualification_environment, "VapiResources")
    functions = [
        handoff["PrepareFunctionName"],
        handoff["TransferFunctionName"],
        handoff["LookupFunctionName"],
        vapi["ProvisionerFunctionName"],
    ]
    table_name = handoff["HandoffTableName"]
    queries: list[dict[str, Any]] = []
    for index, function in enumerate(functions):
        queries.append(
            {
                "Id": f"lambda{index}",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/Lambda",
                        "MetricName": "Errors",
                        "Dimensions": [{"Name": "FunctionName", "Value": function}],
                    },
                    "Period": 60,
                    "Stat": "Sum",
                },
                "ReturnData": True,
            }
        )
    for index, metric in enumerate(("SystemErrors", "ThrottledRequests")):
        queries.append(
            {
                "Id": f"dynamo{index}",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/DynamoDB",
                        "MetricName": metric,
                        "Dimensions": [{"Name": "TableName", "Value": table_name}],
                    },
                    "Period": 60,
                    "Stat": "Sum",
                },
                "ReturnData": True,
            }
        )
    query_path = ledger_path.parent / f"soak-metrics-{os.urandom(6).hex()}.private.json"
    write_private_json(query_path, {"queries": queries})
    try:
        query_document = load_json(query_path)
        result = LIVE.aws_json(
            [
                "cloudwatch",
                "get-metric-data",
                "--region",
                str(ledger["region"]),
                "--start-time",
                started_at.isoformat(),
                "--end-time",
                ended_at.isoformat(),
                "--metric-data-queries",
                json.dumps(query_document["queries"], separators=(",", ":")),
                "--scan-by",
                "TimestampAscending",
                "--max-datapoints",
                "10080",
            ],
            env=dict(qualification_environment),
        )
    finally:
        query_path.unlink(missing_ok=True)
    rows = result.get("MetricDataResults", [])
    expected_ids = {query["Id"] for query in queries}
    if (
        result.get("NextToken")
        or not isinstance(rows, list)
        or {row.get("Id") for row in rows} != expected_ids
        or any(row.get("StatusCode") != "Complete" for row in rows)
    ):
        raise QualificationError("CloudWatch soak error metrics are incomplete")
    totals: dict[str, float] = {}
    for row in rows:
        values = row.get("Values", [])
        if not isinstance(values, list) or any(
            not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0
            for value in values
        ):
            raise QualificationError("CloudWatch soak metric value is invalid")
        totals[row["Id"]] = sum(float(value) for value in values)
    lambda_errors = sum(totals[f"lambda{index}"] for index in range(len(functions)))
    dynamodb_errors = totals["dynamo0"] + totals["dynamo1"]
    if not lambda_errors.is_integer() or not dynamodb_errors.is_integer():
        raise QualificationError("CloudWatch soak error counts are not integral")
    return int(lambda_errors), int(dynamodb_errors)


def soak_finish(args: argparse.Namespace) -> None:
    if args.confirm != args.execution_id:
        raise QualificationError("soak finish requires the exact execution ID")
    path, ledger, qualification_environment = stable_live_ledger(args.execution_id)
    output = path.parent / "soak-evidence.json"
    if output.exists():
        raise QualificationError("soak evidence already exists")
    pending_path = soak_pending_path(path.parent)
    pending = pending_soak(pending_path, ledger)
    started_at = parse_timestamp(pending["started_at"])
    ended_at = dt.datetime.now(dt.timezone.utc)
    elapsed = (ended_at - started_at).total_seconds()
    if not 3600 <= elapsed <= 3_900:
        raise QualificationError(
            "soak observation must finish between 60 and 65 minutes"
        )
    call_hashes, setup_latencies, audio_latencies = soak_call_evidence(
        path.parent, ledger, started_at, ended_at
    )
    instance_ids = runtime_instance_ids(ledger, qualification_environment)
    host_outputs = LIVE.ssm_shell(
        dict(ledger),
        dict(qualification_environment),
        instance_ids,
        soak_monitor_finish_script(pending["token"]),
    )
    if len(host_outputs) != pending["target_count"]:
        raise QualificationError("soak host evidence target count changed")
    telemetry = parse_soak_samples(host_outputs, pending["token"], started_at, ended_at)
    lambda_errors, dynamodb_errors = cloudwatch_soak_errors(
        path,
        ledger,
        qualification_environment,
        started_at,
        ended_at,
    )
    telemetry.update(
        {"lambda_errors": lambda_errors, "dynamodb_errors": dynamodb_errors}
    )
    if any(
        telemetry[name] != 0
        for name in (
            "network_errors",
            "media_drops",
            "lambda_errors",
            "dynamodb_errors",
            "cleanup_backlog_max",
        )
    ):
        raise QualificationError("soak telemetry observed production errors or backlog")
    zero = observe_zero_counts(ledger, qualification_environment, args.window_seconds)
    evidence = {
        "schema_version": 1,
        "producer": PRODUCER,
        "producer_revision_sha256": controller_revision(),
        "execution_id": args.execution_id,
        "recipe": RECIPE,
        "started_at": pending["started_at"],
        "ended_at": ended_at.isoformat().replace("+00:00", "Z"),
        "minutes": int(elapsed // 60),
        "revisions": revision_contract(ledger),
        "attempted_calls": len(call_hashes),
        "completed_calls": len(call_hashes),
        "unexpected_failures": 0,
        "call_evidence_sha256": call_hashes,
        "setup_latency_ms_p95": p95(setup_latencies),
        "audio_latency_ms_p95": p95(audio_latencies),
        "telemetry": telemetry,
        "zero_state": zero,
        "passed": True,
        "redacted": True,
        "customer_data_retained": False,
    }
    reject_sensitive(evidence)
    validate_schema(evidence, SOAK_SCHEMA)
    write_private_json(output, evidence)
    pending_path.unlink()
    LIVE.record(path, ledger, "soak_observation_completed")
    print(output)


def observe_zero_counts(
    ledger: Mapping[str, Any],
    qualification_environment: Mapping[str, str],
    window_seconds: int,
) -> dict[str, int]:
    instance_ids = runtime_instance_ids(ledger, qualification_environment)
    samples = parse_metric_samples(
        LIVE.ssm_shell(
            dict(ledger),
            dict(qualification_environment),
            instance_ids,
            zero_metric_script(window_seconds),
        )
    )
    count_samples = [
        {
            "active_calls": sample["bridgefu_active_sessions"],
            "active_routes": sample["bridgefu_gateway_native_active_routes"]
            + sample["bridgefu_private_forwarding_active_routes"],
            "cleanup_backlog": sample["bridgefu_amazon_durable_cleanups_pending"]
            + sample["bridgefu_amazon_pending_contact_cleanups"],
        }
        for sample in samples
    ]
    for sample in count_samples:
        for name, metric in sample.items():
            if metric < 0 or not metric.is_integer():
                raise QualificationError(
                    f"runtime {name} metric is not an integer count"
                )
    active_calls = max(int(sample["active_calls"]) for sample in count_samples)
    active_routes = max(int(sample["active_routes"]) for sample in count_samples)
    cleanup_backlog = max(int(sample["cleanup_backlog"]) for sample in count_samples)
    if any(sample["bridgefu_process_ready"] < 1 for sample in samples):
        raise QualificationError(
            "runtime was not ready throughout zero-state observation"
        )
    active_contacts = active_test_contacts(ledger, qualification_environment)
    if any(
        value != 0
        for value in (active_calls, active_contacts, active_routes, cleanup_backlog)
    ):
        raise QualificationError(
            "final zero-state observation found active recipe work"
        )
    return {
        "active_calls": active_calls,
        "active_contacts": active_contacts,
        "active_routes": active_routes,
        "cleanup_backlog": cleanup_backlog,
    }


def ssm_marker_action(
    ledger: Mapping[str, Any],
    qualification_environment: Mapping[str, str],
    instance_ids: list[str],
    script: str,
    marker: str,
) -> float:
    started = time.monotonic()
    outputs = LIVE.ssm_shell(
        dict(ledger),
        dict(qualification_environment),
        instance_ids,
        script,
    )
    if len(outputs) != len(instance_ids) or any(
        marker not in output for output in outputs
    ):
        raise QualificationError("failure drill did not produce its controlled marker")
    return round(time.monotonic() - started, 3)


def process_restart_action(
    ledger: Mapping[str, Any],
    qualification_environment: Mapping[str, str],
    instance_ids: list[str],
) -> float:
    if len(instance_ids) != 1:
        raise QualificationError("Starter process restart requires one exact host")
    script = """set -euo pipefail
old_pid="$(docker inspect --format '{{.State.Pid}}' bridgefu)"
test "$old_pid" -gt 1
systemctl stop bridgefu.service
if curl --silent --show-error --fail --max-time 2 http://127.0.0.1:9090/readyz >/dev/null 2>&1; then
  exit 42
fi
systemctl start bridgefu.service
for _ in $(seq 1 90); do
  if curl --silent --show-error --fail --max-time 2 http://127.0.0.1:9090/readyz >/dev/null 2>&1; then
    new_pid="$(docker inspect --format '{{.State.Pid}}' bridgefu)"
    if test "$new_pid" -gt 1 && test "$new_pid" != "$old_pid"; then
      printf 'bridgefu-process-restart-recovered-v1\n'
      exit 0
    fi
  fi
  sleep 1
done
exit 43
"""
    return ssm_marker_action(
        ledger,
        qualification_environment,
        instance_ids,
        script,
        "bridgefu-process-restart-recovered-v1",
    )


def dependency_timeout_start_script(token: str) -> str:
    """Install a bounded HAProxy tarpit while Bridgefu itself stays ready."""
    if re.fullmatch(r"[0-9a-f]{12}", token) is None:
        raise QualificationError("dependency timeout token is invalid")
    script = r'''set -euo pipefail
token="__TOKEN__"
root=/run/bridgefu-qualification
wrapper="$root/dependency-$token"
unit="bridgefu-dependency-$token"
backup="$root/haproxy-$token.cfg"
active="$root/haproxy-$token.active"
restored="$root/haproxy-$token.restored"
install -d -m 0700 "$root"
test ! -e "$wrapper"
test ! -e "$backup"
test ! -e "$active"
test ! -e "$restored"
cat > "$wrapper" <<'BRIDGEFU_DEPENDENCY'
#!/usr/bin/env bash
set -euo pipefail
token="$1"
root=/run/bridgefu-qualification
backup="$root/haproxy-$token.cfg"
injected="$root/haproxy-$token.injected"
active="$root/haproxy-$token.active"
restored="$root/haproxy-$token.restored"
cleanup() {
  status=$?
  if test -s "$backup"; then
    install -o root -g haproxy -m 0640 "$backup" /etc/haproxy/haproxy.cfg
    haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null
    systemctl reload haproxy.service
    test "$(sha256sum /etc/haproxy/haproxy.cfg | awk '{print $1}')" = \
      "$(sha256sum "$backup" | awk '{print $1}')"
    touch "$restored"
    chmod 0600 "$restored"
  fi
  rm -f "$active" "$injected"
  exit "$status"
}
trap cleanup EXIT
cp --preserve=mode,ownership /etc/haproxy/haproxy.cfg "$backup"
chmod 0600 "$backup"
awk '
  /^[[:space:]]*timeout server 12s[[:space:]]*$/ {
    print
    print "    timeout tarpit 15s"
    next
  }
  /^[[:space:]]*acl exact_reservation_method method POST[[:space:]]*$/ {
    print
    print "    http-request tarpit if exact_reservation exact_reservation_method"
    next
  }
  { print }
' "$backup" > "$injected"
test "$(grep -c '^[[:space:]]*timeout tarpit 15s$' "$injected")" -eq 1
test "$(grep -c '^[[:space:]]*http-request tarpit if exact_reservation exact_reservation_method$' "$injected")" -eq 1
install -o root -g haproxy -m 0640 "$injected" /etc/haproxy/haproxy.cfg
haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null
systemctl reload haproxy.service
test "$(systemctl is-active haproxy.service)" = active
test "$(systemctl is-active bridgefu.service)" = active
curl --silent --show-error --fail --max-time 5 http://127.0.0.1:9090/readyz >/dev/null
control_bind="$(awk '/^[[:space:]]*bind[[:space:]]/ { print $2; exit }' /etc/haproxy/haproxy.cfg)"
test -n "$control_bind"
scheme=http
curl_tls=()
if grep -Eq '^[[:space:]]*bind[[:space:]].*[[:space:]]ssl([[:space:]]|$)' /etc/haproxy/haproxy.cfg; then
  scheme=https
  curl_tls=(--insecure)
fi
set +e
curl --silent --output /dev/null --max-time 1 --request POST \
  "${curl_tls[@]}" "$scheme://$control_bind/v1/routes/support/calls"
curl_status=$?
set -e
test "$curl_status" -eq 28
touch "$active"
chmod 0600 "$active"
sleep 90
BRIDGEFU_DEPENDENCY
chmod 0700 "$wrapper"
systemd-run --quiet --unit="$unit" --property=RuntimeMaxSec=95 "$wrapper" "$token"
for _ in $(seq 1 30); do
  if test -f "$active" \
    && systemctl is-active --quiet "$unit.service" \
    && systemctl is-active --quiet bridgefu.service \
    && curl --silent --show-error --fail --max-time 2 http://127.0.0.1:9090/readyz >/dev/null; then
    printf 'bridgefu-dependency-timeout-active-v1\n'
    exit 0
  fi
  sleep 1
done
exit 42
'''
    return script.replace("__TOKEN__", token)


def dependency_timeout_finish_script(token: str) -> str:
    if re.fullmatch(r"[0-9a-f]{12}", token) is None:
        raise QualificationError("dependency timeout token is invalid")
    return f'''set -euo pipefail
token="{token}"
root=/run/bridgefu-qualification
wrapper="$root/dependency-$token"
unit="bridgefu-dependency-$token"
backup="$root/haproxy-$token.cfg"
active="$root/haproxy-$token.active"
restored="$root/haproxy-$token.restored"
test -f "$wrapper"
test -s "$backup"
systemctl stop "$unit.service" >/dev/null 2>&1 || true
for _ in $(seq 1 30); do
  if test -f "$restored" \
    && test ! -e "$active" \
    && test "$(sha256sum /etc/haproxy/haproxy.cfg | awk '{{print $1}}')" = \
      "$(sha256sum "$backup" | awk '{{print $1}}')" \
    && systemctl is-active --quiet haproxy.service \
    && systemctl is-active --quiet bridgefu.service \
    && curl --silent --show-error --fail --max-time 2 http://127.0.0.1:9090/readyz >/dev/null; then
    rm -f "$wrapper" "$backup" "$restored"
    systemctl reset-failed "$unit.service" >/dev/null 2>&1 || true
    printf 'bridgefu-dependency-timeout-recovered-v1\n'
    exit 0
  fi
  sleep 1
done
exit 43
'''


def dependency_timeout_action(
    ledger: Mapping[str, Any],
    qualification_environment: Mapping[str, str],
    instance_ids: list[str],
) -> float:
    if len(instance_ids) != 1:
        raise QualificationError("Starter dependency timeout requires one exact host")
    ledger_path = LIVE.ledger_path(str(ledger["execution_id"]))
    handoff = COLLECTOR.nested_outputs(
        ledger, qualification_environment, "HandoffService"
    )
    webhook = LIVE.secret_value(
        dict(ledger),
        dict(qualification_environment),
        handoff["VapiWebhookSecretArn"],
    )
    correlation_key = LIVE.secret_value(
        dict(ledger),
        dict(qualification_environment),
        handoff["CorrelationKeySecretArn"],
    )
    nonce = os.urandom(12).hex()
    call_id = f"call_bridgefu_negative_{nonce}"
    org_id = "org_bridgefu_qualification"
    before, _ = bounded_test_contacts(ledger, qualification_environment)
    status, body = LIVE.http_post(
        handoff["PrepareUrl"], webhook, synthetic_prepare_payload(nonce)
    )
    if status != 200 or body != {
        "results": [
            {
                "name": "prepare_handoff",
                "toolCallId": f"tool_bridgefu_negative_{nonce}",
                "result": {"status": "prepared"},
            }
        ]
    }:
        raise QualificationError("dependency timeout setup was not prepared exactly")
    correlation_id = COLLECTOR.derive_correlation_id(
        correlation_key, str(ledger["execution_id"]), org_id, call_id
    )
    row = COLLECTOR.get_handoff_row(
        ledger,
        qualification_environment,
        handoff["HandoffTableName"],
        correlation_id,
    )
    if (
        row.get("schema_version") != 1
        or row.get("correlation_id") != correlation_id
        or row.get("handoff_status") != "PREPARED"
        or row.get("customer_name") != "Bridgefu Synthetic Caller"
        or row.get("issue_summary") != "Qualification negative-case context."
        or row.get("intent") != "qualification"
        or row.get("verification_status") != "synthetic"
        or not isinstance(row.get("expires_at"), int)
        or row["expires_at"] <= int(time.time())
        or not SHA256.fullmatch(str(row.get("content_hash", "")))
        or not SHA256.fullmatch(str(row.get("vapi_call_fingerprint", "")))
    ):
        raise QualificationError("dependency timeout setup row is not exact")
    token = os.urandom(6).hex()
    started = time.monotonic()
    fault_started = False
    try:
        start_outputs = LIVE.ssm_shell(
            dict(ledger),
            dict(qualification_environment),
            instance_ids,
            dependency_timeout_start_script(token),
        )
        if len(start_outputs) != 1 or (
            "bridgefu-dependency-timeout-active-v1" not in start_outputs[0]
        ):
            raise QualificationError("dependency timeout fault did not become active")
        fault_started = True
        transfer_status, transfer_body = LIVE.http_post(
            handoff["TransferUrl"],
            webhook,
            {
                "message": {
                    "type": "transfer-destination-request",
                    "call": {"id": call_id, "orgId": org_id},
                }
            },
        )
        if (transfer_status, transfer_body) != (
            503,
            {"error": "bridgefu_reservation_unavailable"},
        ):
            raise QualificationError(
                "dependency timeout did not produce the exact unavailable response"
            )
        wait_for_contact_total(
            ledger, qualification_environment, before, timeout_seconds=10
        )
    finally:
        recovery_error: Exception | None = None
        if fault_started:
            try:
                finish_outputs = LIVE.ssm_shell(
                    dict(ledger),
                    dict(qualification_environment),
                    instance_ids,
                    dependency_timeout_finish_script(token),
                )
                if len(finish_outputs) != 1 or (
                    "bridgefu-dependency-timeout-recovered-v1"
                    not in finish_outputs[0]
                ):
                    raise QualificationError(
                        "dependency timeout control proxy did not restore exactly"
                    )
            except Exception as error:  # Preserve cleanup even if recovery proof fails.
                recovery_error = error
        current = COLLECTOR.get_handoff_row(
            ledger,
            qualification_environment,
            handoff["HandoffTableName"],
            correlation_id,
        )
        current_status = current.get("handoff_status")
        if current_status not in {"PREPARED", "RESERVED"}:
            raise QualificationError(
                "dependency timeout synthetic row changed unexpectedly"
            )
        delete_synthetic_context(
            ledger_path,
            ledger,
            qualification_environment,
            handoff["HandoffTableName"],
            {"correlation_id": correlation_id},
            current,
            expected_status=str(current_status),
        )
        if recovery_error is not None:
            raise recovery_error
    return round(time.monotonic() - started, 3)


def tcp_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def wait_ssm_online(
    ledger: Mapping[str, Any],
    qualification_environment: Mapping[str, str],
    instance_id: str,
    timeout_seconds: int,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        response = LIVE.aws_json(
            [
                "ssm",
                "describe-instance-information",
                "--region",
                str(ledger["region"]),
                "--filters",
                f"Key=InstanceIds,Values={instance_id}",
            ],
            env=dict(qualification_environment),
        )
        entries = response.get("InstanceInformationList", [])
        if len(entries) == 1 and entries[0].get("PingStatus") == "Online":
            return
        time.sleep(2)
    raise QualificationError("recovered host did not return to SSM")


def host_recovery_endpoint(
    ledger: Mapping[str, Any],
    parameters: Mapping[str, str],
    runtime: Mapping[str, str],
) -> tuple[str, int, str]:
    security = validate_qualification_posture(ledger)
    if parameters.get("SipSecurity") != security:
        raise QualificationError(
            "deployed SIP posture does not match the qualification ledger"
        )
    if security == "sip_rtp":
        public_ip = runtime.get("PublicIp")
        try:
            address = ipaddress.ip_address(str(public_ip))
        except ValueError as error:
            raise QualificationError(
                "IP-only runtime did not return a valid public EIP"
            ) from error
        if (
            not isinstance(address, ipaddress.IPv4Address)
            or not address.is_global
            or runtime.get("SipHostname") != str(address)
        ):
            raise QualificationError(
                "IP-only runtime does not advertise its exact public EIP"
            )
        return str(address), 5060, "SIP"

    hostname = ledger.get("sip_hostname")
    if (
        not isinstance(hostname, str)
        or not hostname
        or runtime.get("SipHostname") != hostname
    ):
        raise QualificationError(
            "secure runtime does not advertise the reviewed SIP hostname"
        )
    return hostname, 5061, "SIPS"


def host_recovery_action(
    ledger: Mapping[str, Any],
    qualification_environment: Mapping[str, str],
    instance_ids: list[str],
) -> float:
    if len(instance_ids) != 1:
        raise QualificationError("Starter host recovery requires one exact host")
    parameters = {
        item["ParameterKey"]: item.get("ParameterValue", "")
        for item in LIVE.stack_description(
            dict(ledger), dict(qualification_environment), str(ledger["stack_name"])
        ).get("Parameters", [])
    }
    runtime, _ = runtime_log_outputs(ledger, qualification_environment)
    host, port, protocol = host_recovery_endpoint(ledger, parameters, runtime)
    if not tcp_open(host, port):
        raise QualificationError(
            f"{protocol} listener is not ready before host recovery"
        )
    started = time.monotonic()
    LIVE.aws_json(
        [
            "ec2",
            "reboot-instances",
            "--region",
            str(ledger["region"]),
            "--instance-ids",
            instance_ids[0],
        ],
        env=dict(qualification_environment),
    )
    degraded_deadline = time.monotonic() + 180
    while time.monotonic() < degraded_deadline and tcp_open(host, port):
        time.sleep(0.5)
    if tcp_open(host, port):
        raise QualificationError("host reboot did not produce an observable outage")
    recovery_deadline = time.monotonic() + 600
    while time.monotonic() < recovery_deadline and not tcp_open(host, port):
        time.sleep(2)
    if not tcp_open(host, port):
        raise QualificationError(
            f"{protocol} listener did not recover after host reboot"
        )
    wait_ssm_online(ledger, qualification_environment, instance_ids[0], 180)
    outputs = LIVE.ssm_shell(
        dict(ledger),
        dict(qualification_environment),
        instance_ids,
        """set -euo pipefail
curl --silent --show-error --fail --max-time 5 http://127.0.0.1:9090/readyz >/dev/null
test "$(systemctl is-active bridgefu.service)" = active
printf 'bridgefu-host-recovery-ready-v1\n'
""",
    )
    if len(outputs) != 1 or "bridgefu-host-recovery-ready-v1" not in outputs[0]:
        raise QualificationError("runtime readiness did not recover after host reboot")
    return round(time.monotonic() - started, 3)


def pending_failure_path(execution: Path, identifier: str) -> Path:
    return execution / "failure-pending" / f"{identifier}.private.json"


def failure_start(args: argparse.Namespace) -> None:
    if args.confirm != args.execution_id:
        raise QualificationError("failure drill requires the exact execution ID")
    path, ledger, qualification_environment = stable_live_ledger(args.execution_id)
    profile = ledger.get("runtime_profile", "starter")
    matrix = yaml.safe_load(MATRIX.read_text(encoding="utf-8"))
    if args.id not in matrix["required_failure_drills"][profile]:
        raise QualificationError(
            "failure drill is not required for this deployment profile"
        )
    if profile != "starter":
        raise QualificationError(
            "HA failure drills use the separate slot/failover controller"
        )
    pending = pending_failure_path(path.parent, args.id)
    output = path.parent / "failure-evidence" / f"{args.id}.json"
    if pending.exists() or output.exists():
        raise QualificationError("failure drill already has pending or final evidence")
    observe_zero_counts(ledger, qualification_environment, args.window_seconds)
    instance_ids = runtime_instance_ids(ledger, qualification_environment)
    started_at = utc_now()
    if args.id == "process_restart":
        controller = "aws-ssm"
        recovery_seconds = process_restart_action(
            ledger, qualification_environment, instance_ids
        )
    elif args.id == "dependency_timeout":
        controller = "aws-ssm"
        recovery_seconds = dependency_timeout_action(
            ledger, qualification_environment, instance_ids
        )
    elif args.id == "host_recovery":
        controller = "aws-ec2"
        recovery_seconds = host_recovery_action(
            ledger, qualification_environment, instance_ids
        )
    else:  # pragma: no cover - guarded by the matrix
        raise QualificationError("unsupported Starter failure drill")
    value = {
        "schema_version": 1,
        "producer": PRODUCER,
        "producer_revision_sha256": controller_revision(),
        "execution_id": args.execution_id,
        "recipe": RECIPE,
        "deployment_profile": profile,
        "id": args.id,
        "started_at": started_at,
        "recovered_at": utc_now(),
        "recovery_seconds": recovery_seconds,
        "revisions": revision_contract(ledger),
        "fault_controller": controller,
        "target_count": len(instance_ids),
        "fault_applied": True,
        "degraded_state_observed": True,
    }
    reject_sensitive(value)
    write_private_json(pending, value)
    LIVE.record(path, ledger, "failure_drill_recovered", drill=args.id)
    print(pending)


def load_pending_failure(
    path: Path, ledger: Mapping[str, Any], identifier: str
) -> dict[str, Any]:
    regular_file(path)
    if path.stat().st_mode & 0o077:
        raise QualificationError(
            "pending failure evidence permissions must be mode 0600"
        )
    value = load_json(path)
    expected = {
        "schema_version",
        "producer",
        "producer_revision_sha256",
        "execution_id",
        "recipe",
        "deployment_profile",
        "id",
        "started_at",
        "recovered_at",
        "recovery_seconds",
        "revisions",
        "fault_controller",
        "target_count",
        "fault_applied",
        "degraded_state_observed",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("schema_version") != 1
        or value.get("producer") != PRODUCER
        or value.get("producer_revision_sha256") != controller_revision()
        or value.get("execution_id") != ledger.get("execution_id")
        or value.get("recipe") != RECIPE
        or value.get("deployment_profile") != ledger.get("runtime_profile", "starter")
        or value.get("id") != identifier
        or value.get("revisions") != revision_contract(ledger)
        or value.get("fault_applied") is not True
        or value.get("degraded_state_observed") is not True
        or not isinstance(value.get("recovery_seconds"), (int, float))
        or not 0 <= value["recovery_seconds"] <= 3600
    ):
        raise QualificationError("pending failure evidence is invalid")
    parse_timestamp(value["started_at"])
    parse_timestamp(value["recovered_at"])
    return value


def failure_finish(args: argparse.Namespace) -> None:
    if args.confirm != args.execution_id:
        raise QualificationError(
            "failure evidence finish requires the exact execution ID"
        )
    path, ledger, qualification_environment = stable_live_ledger(args.execution_id)
    pending_path = pending_failure_path(path.parent, args.id)
    pending = load_pending_failure(pending_path, ledger, args.id)
    call_path = args.post_recovery_call.resolve()
    expected_parent = (path.parent / "call-evidence").resolve()
    if call_path.parent != expected_parent:
        raise QualificationError("post-recovery call must be retained matrix evidence")
    call = exact_component(call_path, CALL_SCHEMA, ledger, controller_owned=False)
    if parse_timestamp(call["started_at"]) < parse_timestamp(pending["recovered_at"]):
        raise QualificationError("post-recovery call predates the recovered runtime")
    zero = observe_zero_counts(ledger, qualification_environment, args.window_seconds)
    output = path.parent / "failure-evidence" / f"{args.id}.json"
    evidence = {
        "schema_version": 1,
        "producer": PRODUCER,
        "producer_revision_sha256": controller_revision(),
        "execution_id": args.execution_id,
        "recipe": RECIPE,
        "deployment_profile": ledger.get("runtime_profile", "starter"),
        "id": args.id,
        "started_at": pending["started_at"],
        "ended_at": utc_now(),
        "revisions": revision_contract(ledger),
        "fault": {
            "controller": pending["fault_controller"],
            "target_count": pending["target_count"],
            "applied": True,
            "degraded_state_observed": True,
        },
        "recovery": {
            "seconds": pending["recovery_seconds"],
            "readiness_restored": True,
            "post_recovery_call_sha256": sha256_file(call_path),
        },
        "zero_state": zero,
        "passed": True,
        "redacted": True,
        "customer_data_retained": False,
    }
    reject_sensitive(evidence)
    validate_schema(evidence, FAILURE_SCHEMA)
    write_private_json(output, evidence)
    pending_path.unlink()
    LIVE.record(path, ledger, "failure_drill_evidence_completed", drill=args.id)
    print(output)


def packaged_relative_path(value: str) -> PurePosixPath:
    try:
        relative = PurePosixPath(value)
    except TypeError as error:
        raise QualificationError("packaged evidence path is invalid") from error
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.name.endswith(".private.json")
    ):
        raise QualificationError("packaged evidence path is unsafe")
    if len(relative.parts) == 1:
        if relative.name not in PACKAGED_EVIDENCE_FILES:
            raise QualificationError("packaged evidence top-level file is unsupported")
        return relative
    extensions = PACKAGED_EVIDENCE_DIRECTORIES.get(relative.parts[0])
    if len(relative.parts) != 2 or extensions is None or relative.suffix not in extensions:
        raise QualificationError("packaged evidence path is unsupported")
    return relative


def packaged_inventory(
    source: Path, summary: Mapping[str, Any]
) -> dict[str, tuple[Path, str, int]]:
    entries = summary.get("official_evidence")
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_PACKAGED_EVIDENCE_FILES:
        raise QualificationError("packaged evidence inventory count is invalid")
    inventory: dict[str, tuple[Path, str, int]] = {}
    total = 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "sha256",
            "size_bytes",
        }:
            raise QualificationError("packaged evidence inventory shape is invalid")
        relative = packaged_relative_path(entry.get("path"))
        name = relative.as_posix()
        digest = entry.get("sha256")
        size_bytes = entry.get("size_bytes")
        if (
            name in inventory
            or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
            or not isinstance(size_bytes, int)
            or isinstance(size_bytes, bool)
            or not 0 < size_bytes <= MAX_PACKAGED_EVIDENCE_BYTES
        ):
            raise QualificationError("packaged evidence inventory entry is invalid")
        path = source.joinpath(*relative.parts)
        regular_file(path, MAX_PACKAGED_EVIDENCE_BYTES)
        if path.stat().st_size != size_bytes or sha256_file(path) != digest:
            raise QualificationError("packaged evidence inventory digest changed")
        inventory[name] = (path, digest, size_bytes)
        total += size_bytes
    if total > MAX_PACKAGED_EVIDENCE_BYTES:
        raise QualificationError("packaged evidence inventory exceeds its byte bound")
    actual: set[str] = set()
    for path in source.rglob("*"):
        if path.is_symlink():
            raise QualificationError("packaged evidence tree contains a symlink")
        if not path.is_file():
            continue
        relative = path.relative_to(source).as_posix()
        if relative == "runner-summary.json":
            continue
        packaged_relative_path(relative)
        actual.add(relative)
    if actual != set(inventory):
        raise QualificationError("packaged archive and signed inventory differ")
    return inventory


def packaged_component_map(
    source: Path,
    directory: str,
    schema: Path,
    ledger: Mapping[str, Any],
) -> dict[str, tuple[Path, dict[str, Any]]]:
    result: dict[str, tuple[Path, dict[str, Any]]] = {}
    paths = sorted((source / directory).glob("*.json"))
    if not paths:
        raise QualificationError("packaged component evidence is absent")
    for path in paths:
        component = exact_component(path, schema, ledger, controller_owned=True)
        identifier = component.get("id")
        if not isinstance(identifier, str) or identifier in result:
            raise QualificationError("packaged component evidence has a duplicate")
        result[identifier] = (path, component)
    return result


def validate_packaged_full_evidence(
    source: Path,
    summary: Mapping[str, Any],
    ledger: Mapping[str, Any],
) -> dict[str, tuple[Path, str, int]]:
    matrix = yaml.safe_load(MATRIX.read_text(encoding="utf-8"))
    if set(matrix.get("required_failure_drills", {}).get("starter", [])) != (
        PACKAGED_FAILURE_IDS
    ):
        raise QualificationError("packaged Starter failure contract changed")
    scenarios = [
        str(item["id"]) for item in required_scenarios_for_ledger(matrix, ledger)
    ]
    jobs = [
        {
            "scenario": scenario,
            "network_profile": network["id"],
            "hangup_origin": origin,
        }
        for scenario in scenarios
        for network in matrix["adverse_network_profiles"]
        for origin in ("source", "agent")
    ]
    expected_summary_fields = {
        "schema_version",
        "execution_id",
        "suite",
        "scenarios",
        "matrix",
        "qualification_stage",
        "passed",
        "source_tree_sha256",
        "official_evidence",
    }
    if (
        set(summary) != expected_summary_fields
        or summary.get("schema_version") != 1
        or summary.get("execution_id") != ledger.get("execution_id")
        or summary.get("suite") != "full"
        or summary.get("scenarios") != scenarios
        or summary.get("matrix") != jobs
        or summary.get("qualification_stage") != "pre_lifecycle"
        or summary.get("passed") is not True
        or summary.get("source_tree_sha256")
        != ledger.get("publication_source_tree_sha256")
    ):
        raise QualificationError("packaged full-run summary is not exact")
    inventory = packaged_inventory(source, summary)

    calls: dict[tuple[str, str, str], tuple[Path, dict[str, Any]]] = {}
    for path in sorted((source / "call-evidence").glob("*.json")):
        call = exact_component(path, CALL_SCHEMA, ledger, controller_owned=False)
        key = (
            str(call.get("scenario_id")),
            str(call.get("network", {}).get("profile")),
            str(call.get("hangup_origin")),
        )
        if key in calls:
            raise QualificationError("packaged call matrix contains a duplicate")
        calls[key] = (path, call)
    expected_calls = {
        (job["scenario"], job["network_profile"], job["hangup_origin"])
        for job in jobs
    }
    if set(calls) != expected_calls:
        raise QualificationError("packaged call matrix is incomplete")
    call_hashes = {sha256_file(path) for path, _ in calls.values()}
    if len(call_hashes) != len(expected_calls):
        raise QualificationError("packaged call evidence hashes are not unique")

    negatives = packaged_component_map(
        source, "negative-evidence", NEGATIVE_SCHEMA, ledger
    )
    if set(negatives) != PACKAGED_NEGATIVE_IDS:
        raise QualificationError("packaged negative-case matrix is incomplete")
    replay = negatives["attachment_replay_rejected"][1]
    missing = negatives["missing_context_fail_open"][1]
    if (
        replay.get("call_evidence_sha256") not in call_hashes
        or replay.get("outcome") != "replay_rejected"
        or missing.get("outcome") != "failed_open"
        or missing.get("checks", {}).get("agent_workspace_observed") is not True
    ):
        raise QualificationError("packaged release-wide negative proof is incomplete")

    failures = packaged_component_map(
        source, "failure-evidence", FAILURE_SCHEMA, ledger
    )
    if set(failures) != PACKAGED_FAILURE_IDS or any(
        component.get("deployment_profile") != "starter"
        or component.get("recovery", {}).get("post_recovery_call_sha256")
        not in call_hashes
        for _, component in failures.values()
    ):
        raise QualificationError("packaged Starter failure matrix is incomplete")

    soak_path = source / "soak-evidence.json"
    soak = exact_component(soak_path, SOAK_SCHEMA, ledger, controller_owned=True)
    if (
        soak.get("minutes", 0) < matrix["required_soak_minutes"]
        or soak.get("attempted_calls") != len(expected_calls)
        or soak.get("completed_calls") != len(expected_calls)
        or set(soak.get("call_evidence_sha256", [])) != call_hashes
    ):
        raise QualificationError("packaged soak does not bind the full call matrix")

    zero_path = source / "zero-state-pre-lifecycle-evidence.json"
    zero = load_json(zero_path)
    validate_schema(zero, ZERO_SCHEMA)
    reject_sensitive(zero)
    if (
        zero.get("execution_id") != ledger.get("execution_id")
        or zero.get("recipe") != RECIPE
        or zero.get("producer") != PRODUCER
        or zero.get("producer_revision_sha256") != controller_revision()
    ):
        raise QualificationError("packaged pre-lifecycle zero state is not exact")

    for name, (path, _, _) in inventory.items():
        if path.suffix == ".json" and not name.startswith(
            ("call-evidence/", "failure-evidence/", "negative-evidence/")
        ) and name not in {
            "soak-evidence.json",
            "zero-state-pre-lifecycle-evidence.json",
        }:
            reject_sensitive(load_json(path))
    return inventory


def copy_packaged_inventory(
    execution: Path, inventory: Mapping[str, tuple[Path, str, int]]
) -> None:
    token = os.urandom(6).hex()
    for relative, (source, expected_digest, expected_size) in sorted(
        inventory.items()
    ):
        target = execution.joinpath(*PurePosixPath(relative).parts)
        if target.exists() or target.is_symlink():
            regular_file(target, MAX_PACKAGED_EVIDENCE_BYTES)
            if (
                target.stat().st_size != expected_size
                or sha256_file(target) != expected_digest
            ):
                raise QualificationError(
                    "canonical evidence conflicts with the packaged import"
                )
            continue
        if target.parent.exists() or target.parent.is_symlink():
            parent_details = target.parent.lstat()
            if target.parent.is_symlink() or not stat.S_ISDIR(parent_details.st_mode):
                raise QualificationError(
                    "canonical evidence parent is not a regular directory"
                )
        else:
            target.parent.mkdir(parents=True, exist_ok=False, mode=0o700)
        os.chmod(target.parent, 0o700)
        temporary = target.with_name(f".{target.name}.import-{token}")
        if temporary.exists() or temporary.is_symlink():
            raise QualificationError("packaged evidence staging path already exists")
        try:
            shutil.copyfile(source, temporary)
            os.chmod(temporary, 0o600)
            regular_file(temporary, MAX_PACKAGED_EVIDENCE_BYTES)
            if (
                temporary.stat().st_size != expected_size
                or sha256_file(temporary) != expected_digest
            ):
                raise QualificationError("packaged evidence changed while importing")
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)


def import_packaged(args: argparse.Namespace) -> None:
    if args.confirm != args.execution_id:
        raise QualificationError("packaged evidence import requires exact confirmation")
    ledger_path, ledger, _ = stable_live_ledger(args.execution_id)
    if ledger.get("status") != "verified" or ledger.get("lifecycle_test_passed"):
        raise QualificationError(
            "full packaged evidence must be imported before the lifecycle test"
        )
    supplied_source = args.source_directory
    try:
        details = supplied_source.lstat()
    except OSError as error:
        raise QualificationError("packaged evidence directory is unavailable") from error
    source = supplied_source.resolve()
    if (
        supplied_source.is_symlink()
        or not stat.S_ISDIR(details.st_mode)
        or source.parent != ledger_path.parent.resolve()
        or source == ledger_path.parent.resolve()
    ):
        raise QualificationError(
            "packaged evidence must be one execution-owned regular directory"
        )
    summary_path = source / "runner-summary.json"
    summary = load_json(summary_path)
    if not isinstance(summary, dict):
        raise QualificationError("packaged runner summary is invalid")
    inventory = validate_packaged_full_evidence(source, summary, ledger)
    copy_packaged_inventory(ledger_path.parent, inventory)
    LIVE.record(
        ledger_path,
        ledger,
        "packaged_full_evidence_imported",
        evidence_files=len(inventory),
        source_tree_sha256=summary["source_tree_sha256"],
    )
    print(ledger_path.parent)


def assemble(args: argparse.Namespace) -> None:
    if args.confirm != args.execution_id:
        raise QualificationError(
            "assembly requires the exact execution ID confirmation"
        )
    path, ledger = exact_candidate_ledger(args.execution_id)
    execution = path.parent
    structural_path = execution / "qualification-evidence.json"
    lifecycle_path = execution / "lifecycle-evidence.json"
    teardown_path = execution / "teardown-inventory.json"
    structural = validate_structural(structural_path, ledger)
    validate_lifecycle(lifecycle_path, ledger)
    teardown = validate_teardown(teardown_path)

    negative, negative_starts, negative_ends = component_map(
        ledger, "negative-evidence", NEGATIVE_SCHEMA
    )
    required_negative = {
        "prepare_auth_rejected",
        "prepare_conflicting_replay_rejected",
        "malformed_payload_rejected",
        "missing_correlation_header_rejected",
        "duplicate_correlation_header_rejected",
        "expired_attachment_rejected",
        "attachment_replay_rejected",
        "source_cancellation_cleanup",
        "missing_context_fail_open",
    }
    if set(negative) != required_negative:
        raise QualificationError("negative-case evidence matrix is incomplete")
    scenarios, call_hashes, call_starts, call_ends = call_matrix(ledger, negative)

    failure, failure_starts, failure_ends = component_map(
        ledger, "failure-evidence", FAILURE_SCHEMA
    )
    matrix = yaml.safe_load(MATRIX.read_text(encoding="utf-8"))
    profile = ledger.get("runtime_profile", "starter")
    required_drills = set(matrix["required_failure_drills"][profile])
    if set(failure) != required_drills:
        raise QualificationError("failure-drill evidence matrix is incomplete")
    failure_rows = []
    for identifier in sorted(failure):
        evidence_path, value = failure[identifier]
        if (
            value["deployment_profile"] != profile
            or value["recovery"]["post_recovery_call_sha256"] not in call_hashes
        ):
            raise QualificationError(
                "failure drill is not tied to a retained recovery call"
            )
        failure_rows.append(
            {
                "id": identifier,
                "evidence_sha256": sha256_file(evidence_path),
                "passed": True,
                "recovery_seconds": value["recovery"]["seconds"],
                "cleanup_zero": True,
            }
        )

    negative_rows = [
        {
            "id": identifier,
            "evidence_sha256": sha256_file(negative[identifier][0]),
            "passed": True,
            "cleanup_zero": True,
        }
        for identifier in sorted(negative)
    ]

    soak_path = execution / "soak-evidence.json"
    soak = exact_component(soak_path, SOAK_SCHEMA, ledger, controller_owned=True)
    soak_started = parse_timestamp(soak["started_at"])
    soak_ended = parse_timestamp(soak["ended_at"])
    if (
        (soak_ended - soak_started).total_seconds()
        < matrix["required_soak_minutes"] * 60
        or soak["minutes"] < matrix["required_soak_minutes"]
        or soak["attempted_calls"] != soak["completed_calls"]
        or soak["completed_calls"] != len(soak["call_evidence_sha256"])
        or set(soak["call_evidence_sha256"]) != call_hashes
    ):
        raise QualificationError("soak evidence duration or call set is incomplete")
    zero_path = execution / "zero-state-evidence.json"
    zero = load_json(zero_path)
    validate_schema(zero, ZERO_SCHEMA)
    reject_sensitive(zero)
    if (
        zero.get("execution_id") != args.execution_id
        or zero.get("recipe") != RECIPE
        or zero.get("producer_revision_sha256") != controller_revision()
    ):
        raise QualificationError("zero-state evidence is not bound to this controller")

    release_manifest_path = execution / "release" / "manifest.json"
    release_manifest = load_json(release_manifest_path)
    revisions = revision_contract(ledger)
    if (
        release_manifest.get("bridgefu", {}).get("source_tree_sha256")
        != revisions["source_tree_sha256"]
        or release_manifest.get("bridgefu", {}).get("image_uri") != revisions["image"]
    ):
        raise QualificationError(
            "release manifest no longer matches the immutable candidate"
        )

    all_starts = call_starts + failure_starts + negative_starts + [soak_started]
    all_ends = call_ends + failure_ends + negative_ends + [soak_ended]
    if not all_starts or not all_ends:
        raise QualificationError("qualification evidence has no bounded time range")
    teardown_time = parse_timestamp(teardown["checked_at"])
    if teardown_time < max(all_ends):
        raise QualificationError(
            "teardown inventory predates live qualification evidence"
        )

    evidence = {
        "schema_version": 1,
        "recipe": RECIPE,
        "execution_id": args.execution_id,
        "deployment_profile": profile,
        "sip_security": validate_qualification_posture(ledger),
        "region": ledger["region"],
        "started_at": min(all_starts).isoformat().replace("+00:00", "Z"),
        "ended_at": teardown_time.isoformat().replace("+00:00", "Z"),
        "revisions": {
            **revisions,
            "recipe_fingerprint": structural["recipe_fingerprint"],
            "release_manifest_sha256": sha256_file(release_manifest_path),
            "cloudformation_sha256": release_artifact_sha(
                release_manifest, "recipe/cloudformation/template.yaml"
            ),
            "qualification_controller_sha256": controller_revision(),
        },
        "scenarios": scenarios,
        "failure_drills": failure_rows,
        "negative_cases": negative_rows,
        "soak": {
            "started_at": soak["started_at"],
            "ended_at": soak["ended_at"],
            "minutes": soak["minutes"],
            "attempted_calls": soak["attempted_calls"],
            "completed_calls": soak["completed_calls"],
            "unexpected_failures": soak["unexpected_failures"],
            "setup_latency_ms_p95": soak["setup_latency_ms_p95"],
            "audio_latency_ms_p95": soak["audio_latency_ms_p95"],
            "call_evidence_sha256": soak["call_evidence_sha256"],
            "telemetry": soak["telemetry"],
            "evidence_sha256": sha256_file(soak_path),
            "cleanup_zero": True,
        },
        "zero_state": {
            "observed_at": zero["observed_at"],
            "evidence_sha256": sha256_file(zero_path),
            "active_calls": zero["active_calls"],
            "active_contacts": zero["active_contacts"],
            "active_routes": zero["active_routes"],
            "cleanup_backlog": zero["cleanup_backlog"],
        },
        "teardown": {
            "observed_at": teardown["checked_at"],
            "inventory_sha256": sha256_file(teardown_path),
            "test_owned_resources": 0,
            "customer_resources_mutated": False,
        },
        "provenance": {
            "structural_evidence_sha256": sha256_file(structural_path),
            "lifecycle_evidence_sha256": sha256_file(lifecycle_path),
            "call_evidence_count": len(call_hashes),
            "failure_evidence_count": len(failure_rows),
            "negative_evidence_count": len(negative_rows),
        },
        "redacted": True,
        "customer_data_retained": False,
    }
    reject_sensitive(evidence)
    validate_schema(evidence, FINAL_SCHEMA)
    output = execution / "release-qualification-evidence.json"
    write_private_json(output, evidence)
    result = subprocess.run(
        [sys.executable, os.fspath(VALIDATOR), os.fspath(output)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        output.unlink(missing_ok=True)
        raise QualificationError(
            "assembled evidence failed the independent semantic validator"
        )
    LIVE.record(path, ledger, "release_qualification_evidence_assembled")
    print(output)


def contract(_args: argparse.Namespace) -> None:
    for schema in COMPONENT_SCHEMAS:
        regular_file(schema)
        jsonschema.Draft202012Validator.check_schema(load_json(schema))
    matrix = yaml.safe_load(MATRIX.read_text(encoding="utf-8"))
    if (
        matrix.get("recipe") != RECIPE
        or matrix.get("support_candidate") != "supported"
        or len(matrix.get("required_scenarios", [])) != 5
        or matrix.get("required_scenario_ids_by_sip_security")
        != {
            "sip_rtp": ["sip-rtp-pcmu", "sip-rtp-pcma", "vapi-web-transfer"],
            "sips_srtp": [
                "sips-srtp-pcmu",
                "sips-srtp-pcma",
                "vapi-web-transfer",
            ],
        }
        or set(matrix.get("required_checks_by_sip_security", {}))
        != {"sip_rtp", "sips_srtp"}
        or any(
            set(checks) != set(matrix.get("required_checks", []))
            for checks in matrix.get(
                "required_checks_by_sip_security", {}
            ).values()
        )
        or len(matrix.get("adverse_network_profiles", [])) != 2
        or matrix.get("required_soak_minutes") != 60
    ):
        raise QualificationError("qualification matrix contract changed unexpectedly")
    if not SHA256.fullmatch(controller_revision()):
        raise QualificationError("qualification controller revision is invalid")
    print("protected release qualification contracts are valid")


def observation_window(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "observation window must be an integer"
        ) from error
    if not 60 <= parsed <= 1800:
        raise argparse.ArgumentTypeError(
            "observation window must be between 60 and 1800 seconds"
        )
    return parsed


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    subparsers = value.add_subparsers(dest="command", required=True)
    subparsers.add_parser("contract").set_defaults(function=contract)
    zero = subparsers.add_parser("zero-state")
    zero.add_argument("--execution-id", required=True)
    zero.add_argument("--window-seconds", type=observation_window, default=60)
    zero.add_argument(
        "--phase",
        choices=tuple(ZERO_STATE_PHASE_FILES),
        default="final",
        help="retain a distinct pre-lifecycle or final post-lifecycle observation",
    )
    zero.add_argument("--confirm", required=True)
    zero.set_defaults(function=zero_state)
    http_negative = subparsers.add_parser("negative-http")
    http_negative.add_argument("--execution-id", required=True)
    http_negative.add_argument("--id", choices=sorted(HTTP_NEGATIVE_IDS), required=True)
    http_negative.add_argument("--window-seconds", type=observation_window, default=60)
    http_negative.add_argument("--confirm", required=True)
    http_negative.set_defaults(function=negative_http)
    sip_negative = subparsers.add_parser("negative-sip")
    sip_negative.add_argument("--execution-id", required=True)
    sip_negative.add_argument("--id", choices=sorted(SIP_NEGATIVE_CASES), required=True)
    sip_negative.add_argument("--session", type=Path, required=True)
    sip_negative.add_argument("--window-seconds", type=observation_window, default=60)
    sip_negative.add_argument("--confirm", required=True)
    sip_negative.set_defaults(function=negative_sip)
    replay_negative = subparsers.add_parser("negative-from-call")
    replay_negative.add_argument("--execution-id", required=True)
    replay_negative.add_argument(
        "--id", choices=("attachment_replay_rejected",), required=True
    )
    replay_negative.add_argument("--call-evidence", type=Path, required=True)
    replay_negative.add_argument(
        "--window-seconds", type=observation_window, default=60
    )
    replay_negative.add_argument("--confirm", required=True)
    replay_negative.set_defaults(function=negative_from_call)
    missing = subparsers.add_parser("negative-missing-context")
    missing.add_argument("--execution-id", required=True)
    missing.add_argument("--session", type=Path, required=True)
    missing.add_argument("--connect-url", required=True)
    missing.add_argument("--storage-state", type=Path, required=True)
    missing.add_argument(
        "--observer-timeout-seconds",
        type=COLLECTOR.bounded_observer_timeout,
        default=180,
    )
    missing.add_argument("--window-seconds", type=observation_window, default=60)
    missing.add_argument("--headed", action="store_true")
    missing.add_argument("--confirm", required=True)
    missing.set_defaults(function=negative_missing_context)
    soak_begin = subparsers.add_parser("soak-start")
    soak_begin.add_argument("--execution-id", required=True)
    soak_begin.add_argument("--confirm", required=True)
    soak_begin.set_defaults(function=soak_start)
    soak_end = subparsers.add_parser("soak-finish")
    soak_end.add_argument("--execution-id", required=True)
    soak_end.add_argument("--window-seconds", type=observation_window, default=60)
    soak_end.add_argument("--confirm", required=True)
    soak_end.set_defaults(function=soak_finish)
    for command, function in (
        ("failure-start", failure_start),
        ("failure-finish", failure_finish),
    ):
        failure = subparsers.add_parser(command)
        failure.add_argument("--execution-id", required=True)
        failure.add_argument(
            "--id",
            required=True,
            choices=("process_restart", "dependency_timeout", "host_recovery"),
        )
        failure.add_argument("--window-seconds", type=observation_window, default=60)
        failure.add_argument("--confirm", required=True)
        if command == "failure-finish":
            failure.add_argument("--post-recovery-call", type=Path, required=True)
        failure.set_defaults(function=function)
    packaged = subparsers.add_parser("import-packaged")
    packaged.add_argument("--execution-id", required=True)
    packaged.add_argument("--source-directory", type=Path, required=True)
    packaged.add_argument("--confirm", required=True)
    packaged.set_defaults(function=import_packaged)
    assembly = subparsers.add_parser("assemble")
    assembly.add_argument("--execution-id", required=True)
    assembly.add_argument("--confirm", required=True)
    assembly.set_defaults(function=assemble)
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        with LIVE.execution_lock(args.execution_id):
            args.function(args)
    except (
        QualificationError,
        LIVE.LiveTestError,
        COLLECTOR.EvidenceError,
        jsonschema.ValidationError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except subprocess.TimeoutExpired:
        print(
            "error: protected qualification subprocess exceeded its deadline",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
