#!/usr/bin/env python3
"""Protected per-call evidence collector for the flagship Bridgefu recipe.

The controller has three deliberately separate trust boundaries:

* ``start-direct`` creates one synthetic handoff and a mode-0600 private
  session containing the expiring SIP attachment and raw correlation value.
* the controlled SIP source and Agent Workspace Playwright harness exercise
  the call and independently write strict, redacted observation shapes;
* ``collect`` independently reads DynamoDB and CloudWatch under the temporary
  qualifier role, joins observations by a 12-hex SHA-256 fingerprint, writes
  redacted evidence, and removes the raw session after success.

It never treats structural checks, a participant assertion, or a signaling
stage alone as media evidence. It cannot create a production support claim.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import importlib.util
import ipaddress
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
QUALIFICATION = (
    ROOT / "recipes" / "vapi-amazon-connect-screen-pop" / "qualification"
)
PARTICIPANT_SCHEMA = QUALIFICATION / "participant-observation-v1.schema.json"
SOURCE_SCHEMA = QUALIFICATION / "source-observation-v1.schema.json"
VAPI_SOURCE_SCHEMA = QUALIFICATION / "vapi-source-observation-v1.schema.json"
CALL_SCHEMA = QUALIFICATION / "call-observation-v1.schema.json"
AGENT_HARNESS = QUALIFICATION / "agent-workspace-playwright.mjs"
VAPI_HARNESS = QUALIFICATION / "vapi-web-playwright.mjs"
SOURCE_HARNESS = ROOT / "examples" / "recipe_sip_source.rs"
LIVE_SCRIPT = ROOT / "scripts" / "aws-recipe-live-test.py"
LIVE_SPEC = importlib.util.spec_from_file_location("bridgefu_aws_live", LIVE_SCRIPT)
if LIVE_SPEC is None or LIVE_SPEC.loader is None:  # pragma: no cover - import guard
    raise RuntimeError("unable to load guarded AWS lifecycle controller")
LIVE = importlib.util.module_from_spec(LIVE_SPEC)
sys.modules[LIVE_SPEC.name] = LIVE
LIVE_SPEC.loader.exec_module(LIVE)

RECIPE = "vapi-amazon-connect-screen-pop@1"
CORRELATION = re.compile(r"^bf1_[A-Za-z0-9_-]{43}$")
FINGERPRINT = re.compile(r"^[0-9a-f]{12}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SCENARIOS = {
    "sip-rtp-pcmu": ("sip_rtp", "pcmu"),
    "sip-rtp-pcma": ("sip_rtp", "pcma"),
    "sips-srtp-pcmu": ("sips_srtp", "pcmu"),
    "sips-srtp-pcma": ("sips_srtp", "pcma"),
    "vapi-web-transfer": ("deployed", "negotiated"),
}
DIRECT_SCENARIOS = frozenset(SCENARIOS) - {"vapi-web-transfer"}
SIP_SECURITY_POSTURES = frozenset({"sip_rtp", "sips_srtp"})
NETWORK_PROFILES: dict[str, dict[str, int | float]] = {
    "baseline": {
        "delay_ms": 0,
        "jitter_ms": 0,
        "loss_percent": 0,
        "reorder_percent": 0,
    },
    "moderate-wan": {
        "delay_ms": 80,
        "jitter_ms": 20,
        "loss_percent": 1,
        "reorder_percent": 0.1,
    },
}
NETWORK_CONTROLLER = "bridgefu-aws-tc-netem-controller@1"
DISPLAY_FIELDS = (
    "customer_name",
    "issue_summary",
    "intent",
    "verification_status",
)
REQUIRED_LIFECYCLE = (
    "sip_invite_received",
    "attributes_mapped",
    "contact_started",
    "media_connected",
    "teardown_started",
    "terminated",
)
FORBIDDEN_EVIDENCE_KEYS = {
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
    "token",
    "transcript",
    "vapi_call_id",
    "source_call_id",
    "source_org_id",
    "verification_status",
}
MAX_JSON_BYTES = 1024 * 1024
MAX_SCREENSHOT_BYTES = 10 * 1024 * 1024
MAX_SITE_BUNDLE_BYTES = 2 * 1024 * 1024
CHECKIP_URL = "https://checkip.amazonaws.com/"
VAPI_API_BASE = "https://api.vapi.ai"
SITE_FILES = frozenset(
    {
        "index.html",
        "style.css",
        "app.js",
        "app.js.LEGAL.txt",
        "third-party-licenses.json",
    }
)
SESSION_FIELDS = {
    "schema_version",
    "execution_id",
    "recipe",
    "release_id",
    "source_tree_sha256",
    "image",
    "session_id",
    "scenario_id",
    "hangup_origin",
    "security",
    "codec",
    "network_profile",
    "network_contract",
    "started_at",
    "started_epoch_ms",
    "correlation_id",
    "correlation_fingerprint",
    "source_call_id",
    "source_org_id",
    "source_call_fingerprint",
    "sip_uri",
    "sip_header",
    "expected_context",
    "session_hmac",
}


class EvidenceError(RuntimeError):
    """Safe, identifier-free qualification failure."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def correlation_fingerprint(correlation_id: str) -> str:
    if CORRELATION.fullmatch(correlation_id) is None:
        raise EvidenceError("private session has an invalid correlation contract")
    return hashlib.sha256(correlation_id.encode("ascii")).hexdigest()[:12]


def regular_bounded_file(path: Path, maximum: int) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise EvidenceError("required evidence file is unavailable") from error
    if not stat.S_ISREG(details.st_mode) or path.is_symlink():
        raise EvidenceError("evidence input must be a regular non-symlink file")
    if details.st_size <= 0 or details.st_size > maximum:
        raise EvidenceError("evidence input exceeds its size boundary")


def load_json(path: Path, maximum: int = MAX_JSON_BYTES) -> Any:
    regular_bounded_file(path, maximum)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError("evidence input is not valid UTF-8 JSON") from error


def write_private_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    if temporary.exists():
        raise EvidenceError("private evidence temporary path already exists")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
        temporary.replace(path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def require_private_session(path: Path, execution_id: str) -> dict[str, Any]:
    expected_root = (LIVE.ledger_path(execution_id).parent / "call-sessions").resolve()
    resolved = path.resolve()
    if not resolved.is_relative_to(expected_root):
        raise EvidenceError("private session must stay inside its execution directory")
    regular_bounded_file(resolved, MAX_JSON_BYTES)
    if resolved.stat().st_mode & 0o077:
        raise EvidenceError("private session permissions must be mode 0600")
    value = load_json(resolved)
    if not isinstance(value, dict):
        raise EvidenceError("private session must be a JSON object")
    return value


def reject_sensitive_evidence(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower()
            if normalized in FORBIDDEN_EVIDENCE_KEYS or normalized.startswith("raw_"):
                raise EvidenceError("redacted evidence contains a forbidden field")
            reject_sensitive_evidence(child)
    elif isinstance(value, list):
        for child in value:
            reject_sensitive_evidence(child)
    elif isinstance(value, str) and CORRELATION.search(value):
        raise EvidenceError("redacted evidence contains a raw correlation identifier")


def validate_schema(value: Any, schema_path: Path) -> None:
    schema = load_json(schema_path)
    jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    ).validate(value)


def stable_deployment(execution_id: str) -> tuple[Path, dict[str, Any], dict[str, str]]:
    path, ledger = LIVE.load_ledger(execution_id)
    if ledger.get("status") not in {
        "deployed",
        "verified",
        "updated",
        "lifecycle_verified",
    }:
        raise EvidenceError("call qualification requires a verified stable deployment")
    current_digest = LIVE.working_tree_digest(ROOT)
    if ledger.get("publication_source_tree_sha256") != current_digest:
        raise EvidenceError("working tree no longer matches the immutable candidate")
    environment = LIVE.assume_env(ledger, "qualification")
    recipe_stack_id = LIVE.deployed_recipe_stack_id(ledger, environment)
    stack = LIVE.stack_description(ledger, environment, recipe_stack_id)
    if stack.get("StackStatus") not in {
        "CREATE_COMPLETE",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
    }:
        raise EvidenceError("recipe stack is not in a stable complete state")
    root_outputs = LIVE.outputs(stack)
    if root_outputs.get("BridgefuImage") != ledger.get("bridgefu_image_uri"):
        raise EvidenceError("deployed image does not match the qualification candidate")
    return path, ledger, environment


def network_controller_revision() -> str:
    return sha256_file(Path(__file__))


def owned_runtime_instance_ids(
    ledger: Mapping[str, Any], qualification_environment: Mapping[str, str]
) -> list[str]:
    profile = ledger.get("runtime_profile", "starter")
    if profile == "starter":
        runtime = nested_outputs(ledger, qualification_environment, "StarterRuntime")
        instance_ids = [runtime.get("InstanceId", "")]
    elif profile == "high_availability":
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
    else:
        raise EvidenceError("network control requires a known runtime profile")
    expected_count = 1 if profile == "starter" else 4
    if (
        len(instance_ids) != expected_count
        or len(set(instance_ids)) != expected_count
        or any(re.fullmatch(r"i-[0-9a-f]{8,32}", value) is None for value in instance_ids)
    ):
        raise EvidenceError("runtime instance inventory is not exact")
    details = LIVE.aws_json(
        [
            "ec2",
            "describe-instances",
            "--region",
            str(ledger["region"]),
            "--instance-ids",
            *instance_ids,
        ],
        env=dict(qualification_environment),
    )
    instances = [
        instance
        for reservation in details.get("Reservations", [])
        for instance in reservation.get("Instances", [])
    ]
    for instance in instances:
        tags = {item["Key"]: item["Value"] for item in instance.get("Tags", [])}
        if (
            instance.get("State", {}).get("Name") != "running"
            or tags.get("BridgefuExecutionId") != ledger["execution_id"]
            or tags.get("ManagedBy") != "bridgefu-cloudformation"
        ):
            raise EvidenceError("network control target is not an owned running host")
    if {instance["InstanceId"] for instance in instances} != set(instance_ids):
        raise EvidenceError("runtime instance inventory changed during verification")
    return instance_ids


def send_owned_ssm_command(
    ledger: Mapping[str, Any],
    deployment_environment: Mapping[str, str],
    instance_ids: list[str],
    script: str,
    *,
    purpose: str,
) -> list[str]:
    if len(script.encode("utf-8")) > 16_384:
        raise EvidenceError("qualification host command exceeds its boundary")
    response = LIVE.aws_json(
        [
            "ssm",
            "send-command",
            "--region",
            str(ledger["region"]),
            "--document-name",
            "AWS-RunShellScript",
            "--instance-ids",
            *instance_ids,
            "--parameters",
            json.dumps(
                {"commands": [script], "executionTimeout": ["120"]},
                separators=(",", ":"),
            ),
            "--timeout-seconds",
            "120",
            "--max-concurrency",
            "1",
            "--max-errors",
            "0",
            "--comment",
            f"Bridgefu {purpose} {ledger['execution_id']}",
        ],
        env=dict(deployment_environment),
    )
    command_id = response.get("Command", {}).get("CommandId")
    if not isinstance(command_id, str) or re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f-]{27,40}", command_id
    ) is None:
        raise EvidenceError("qualification host command was not accepted")
    outputs: list[str] = []
    for instance_id in instance_ids:
        deadline = time.monotonic() + 150
        invocation: Mapping[str, Any] | None = None
        while time.monotonic() < deadline:
            candidate = LIVE.aws_json(
                [
                    "ssm",
                    "get-command-invocation",
                    "--region",
                    str(ledger["region"]),
                    "--command-id",
                    command_id,
                    "--instance-id",
                    instance_id,
                ],
                env=dict(deployment_environment),
                check=False,
            )
            if isinstance(candidate, dict):
                status = candidate.get("Status")
                if status == "Success":
                    invocation = candidate
                    break
                if status in {
                    "Cancelled",
                    "Cancelling",
                    "Failed",
                    "TimedOut",
                    "Undeliverable",
                    "Terminated",
                }:
                    raise EvidenceError("qualification host command failed")
            time.sleep(1)
        if invocation is None:
            raise EvidenceError("qualification host command did not finish in time")
        output = invocation.get("StandardOutputContent", "")
        if not isinstance(output, str) or len(output.encode("utf-8")) > 16_384:
            raise EvidenceError("qualification host command output is invalid")
        outputs.append(output)
    return outputs


def network_clean_script() -> str:
    return """set -euo pipefail
command -v tc >/dev/null
iface="$(ip -o route show to default | awk 'NR == 1 {print $5}')"
test -n "$iface"
state="$(tc qdisc show dev "$iface")"
if printf '%s\n' "$state" | grep -Eq '(^|[[:space:]])netem([[:space:]]|$)'; then
  exit 42
fi
printf 'bridgefu-network-clean-v1\n'
"""


def network_apply_script(token: str) -> str:
    if re.fullmatch(r"[0-9a-f]{12}", token) is None:
        raise EvidenceError("network control token is invalid")
    unit = f"bridgefu-netem-{token}"
    cleanup = f"/run/bridgefu-qualification/{token}-clear"
    return f"""set -euo pipefail
command -v tc >/dev/null
iface="$(ip -o route show to default | awk 'NR == 1 {{print $5}}')"
test -n "$iface"
state="$(tc qdisc show dev "$iface")"
if printf '%s\n' "$state" | grep -Eq '(^|[[:space:]])netem([[:space:]]|$)'; then
  exit 42
fi
install -d -m 0700 /run/bridgefu-qualification
cat > {cleanup} <<'BRIDGEFU_CLEAR'
#!/usr/bin/env bash
set -u
iface="$(ip -o route show to default | awk 'NR == 1 {{print $5}}')"
if test -n "$iface"; then
  tc qdisc del dev "$iface" root >/dev/null 2>&1 || true
fi
rm -f -- "$0"
BRIDGEFU_CLEAR
chmod 0700 {cleanup}
tc qdisc replace dev "$iface" root netem delay 80ms 20ms distribution normal loss random 1% reorder 0.1%
state="$(tc qdisc show dev "$iface")"
printf '%s\n' "$state" | grep -Eq '(^|[[:space:]])netem([[:space:]]|$)'
printf '%s\n' "$state" | grep -Fq 'delay 80ms 20ms'
printf '%s\n' "$state" | grep -Eq 'loss (random )?1%'
printf '%s\n' "$state" | grep -Fq 'reorder 0.1%'
systemd-run --quiet --unit={unit} --on-active=15m {cleanup}
printf 'bridgefu-network-moderate-wan-v1\n'
"""


def network_clear_script(token: str) -> str:
    if re.fullmatch(r"[0-9a-f]{12}", token) is None:
        raise EvidenceError("network control token is invalid")
    unit = f"bridgefu-netem-{token}"
    cleanup = f"/run/bridgefu-qualification/{token}-clear"
    return f"""set -euo pipefail
iface="$(ip -o route show to default | awk 'NR == 1 {{print $5}}')"
test -n "$iface"
systemctl stop {unit}.timer {unit}.service >/dev/null 2>&1 || true
tc qdisc del dev "$iface" root >/dev/null 2>&1 || true
rm -f {cleanup}
state="$(tc qdisc show dev "$iface")"
if printf '%s\n' "$state" | grep -Eq '(^|[[:space:]])netem([[:space:]]|$)'; then
  exit 42
fi
printf 'bridgefu-network-cleared-v1\n'
"""


@contextmanager
def controlled_network(
    path: Path,
    ledger: dict[str, Any],
    qualification_environment: Mapping[str, str],
    profile: str,
    session_id: str,
) -> Iterator[dict[str, Any]]:
    settings = NETWORK_PROFILES.get(profile)
    if settings is None:
        raise EvidenceError("unknown adverse-network profile")
    if re.fullmatch(r"[0-9a-f]{24}", session_id) is None:
        raise EvidenceError("network control requires a bounded session identity")
    instance_ids = owned_runtime_instance_ids(ledger, qualification_environment)
    clean_outputs = send_owned_ssm_command(
        ledger,
        qualification_environment,
        instance_ids,
        network_clean_script(),
        purpose="network preflight",
    )
    if any("bridgefu-network-clean-v1" not in output for output in clean_outputs):
        raise EvidenceError("runtime network preflight did not prove a clean state")
    token = session_id[:12]
    impairment_applied = profile == "moderate-wan"
    if impairment_applied:
        applied_outputs = send_owned_ssm_command(
            ledger,
            qualification_environment,
            instance_ids,
            network_apply_script(token),
            purpose="moderate WAN impairment",
        )
        if any(
            "bridgefu-network-moderate-wan-v1" not in output
            for output in applied_outputs
        ):
            raise EvidenceError("runtime network impairment did not converge")
    observation: dict[str, Any] = {
        "schema_version": 1,
        "producer": NETWORK_CONTROLLER,
        "producer_revision_sha256": network_controller_revision(),
        "execution_id": ledger["execution_id"],
        "session_id": session_id,
        "profile": profile,
        "settings": dict(settings),
        "target_count": len(instance_ids),
        "verified_clean_before": True,
        "impairment_applied": impairment_applied,
        "verified_during_call": True,
        "removed_after_call": False,
        "started_at": utc_now(),
        "ended_at": None,
        "redacted": True,
    }
    LIVE.record(path, ledger, "network_profile_started", profile=profile)
    body_error: BaseException | None = None
    try:
        yield observation
    except BaseException as error:
        body_error = error
        raise
    finally:
        try:
            if impairment_applied:
                cleared_outputs = send_owned_ssm_command(
                    ledger,
                    qualification_environment,
                    instance_ids,
                    network_clear_script(token),
                    purpose="network impairment cleanup",
                )
            else:
                cleared_outputs = send_owned_ssm_command(
                    ledger,
                    qualification_environment,
                    instance_ids,
                    network_clean_script(),
                    purpose="network postflight",
                )
            expected_marker = (
                "bridgefu-network-cleared-v1"
                if impairment_applied
                else "bridgefu-network-clean-v1"
            )
            if any(expected_marker not in output for output in cleared_outputs):
                raise EvidenceError("runtime network cleanup did not converge")
            observation["removed_after_call"] = True
            observation["ended_at"] = utc_now()
            LIVE.record(path, ledger, "network_profile_cleared", profile=profile)
        except BaseException:
            LIVE.record(path, ledger, "network_profile_cleanup_failed", profile=profile)
            if body_error is None:
                raise


def write_network_observation(
    path: Path, ledger: Mapping[str, Any], observation: Mapping[str, Any]
) -> Path:
    if observation.get("removed_after_call") is not True:
        raise EvidenceError("network observation cannot be retained before cleanup")
    output = path.parent / "network-observations" / (
        f"{observation['session_id']}.private.json"
    )
    write_private_json(output, observation)
    return output


def validated_network_observation(
    value_path: Path,
    execution_path: Path,
    ledger: Mapping[str, Any],
    session: Mapping[str, Any],
) -> tuple[Path, dict[str, Any]]:
    resolved = value_path.resolve()
    expected_parent = (execution_path.parent / "network-observations").resolve()
    if resolved.parent != expected_parent:
        raise EvidenceError("network observation must stay inside its execution directory")
    regular_bounded_file(resolved, MAX_JSON_BYTES)
    if resolved.stat().st_mode & 0o077:
        raise EvidenceError("network observation permissions must be mode 0600")
    value = load_json(resolved)
    expected_keys = {
        "schema_version",
        "producer",
        "producer_revision_sha256",
        "execution_id",
        "session_id",
        "profile",
        "settings",
        "target_count",
        "verified_clean_before",
        "impairment_applied",
        "verified_during_call",
        "removed_after_call",
        "started_at",
        "ended_at",
        "redacted",
    }
    profile = session.get("network_profile")
    expected_count = 1 if ledger.get("runtime_profile", "starter") == "starter" else 4
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or value.get("schema_version") != 1
        or value.get("producer") != NETWORK_CONTROLLER
        or value.get("producer_revision_sha256") != network_controller_revision()
        or value.get("execution_id") != ledger.get("execution_id")
        or value.get("session_id") != session.get("session_id")
        or value.get("profile") != profile
        or value.get("settings") != NETWORK_PROFILES.get(str(profile))
        or value.get("target_count") != expected_count
        or value.get("verified_clean_before") is not True
        or value.get("impairment_applied") != (profile == "moderate-wan")
        or value.get("verified_during_call") is not True
        or value.get("removed_after_call") is not True
        or value.get("redacted") is not True
        or not isinstance(value.get("started_at"), str)
        or not isinstance(value.get("ended_at"), str)
    ):
        raise EvidenceError("network observation does not match the controlled call")
    started = parse_timestamp(value["started_at"])
    ended = parse_timestamp(value["ended_at"])
    if ended < started:
        raise EvidenceError("network observation timestamps are inconsistent")
    final = {
        "profile": value["profile"],
        "controller": value["producer"],
        "controller_revision_sha256": value["producer_revision_sha256"],
        "settings": value["settings"],
        "target_count": value["target_count"],
        "verified_clean_before": value["verified_clean_before"],
        "impairment_applied": value["impairment_applied"],
        "verified_during_call": value["verified_during_call"],
        "removed_after_call": value["removed_after_call"],
    }
    reject_sensitive_evidence(final)
    return resolved, final


def stack_parameters(
    ledger: Mapping[str, Any], environment: Mapping[str, str]
) -> dict[str, str]:
    mutable_ledger = dict(ledger)
    mutable_environment = dict(environment)
    recipe_stack_id = LIVE.deployed_recipe_stack_id(
        mutable_ledger, mutable_environment
    )
    stack = LIVE.stack_description(
        mutable_ledger, mutable_environment, recipe_stack_id
    )
    return {
        item["ParameterKey"]: item.get("ParameterValue", "")
        for item in stack.get("Parameters", [])
    }


def nested_outputs(
    ledger: Mapping[str, Any],
    environment: Mapping[str, str],
    logical_id: str,
) -> dict[str, str]:
    mutable_ledger = dict(ledger)
    mutable_environment = dict(environment)
    recipe_stack_id = LIVE.deployed_recipe_stack_id(
        mutable_ledger, mutable_environment
    )
    stack_id = LIVE.nested_stack_id(
        mutable_ledger, mutable_environment, logical_id, recipe_stack_id
    )
    return LIVE.outputs(
        LIVE.stack_description(mutable_ledger, mutable_environment, stack_id)
    )


def synthetic_context(scenario_id: str, hangup_origin: str) -> dict[str, str]:
    return {
        "customer_name": "Bridgefu Synthetic Caller",
        "issue_summary": f"Qualification {scenario_id} {hangup_origin} hangup.",
        "intent": "qualification",
        "verification_status": "synthetic",
    }


def session_authentication(value: Mapping[str, Any], key: str) -> str:
    unsigned = {name: field for name, field in value.items() if name != "session_hmac"}
    encoded = json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hmac.new(key.encode("utf-8"), encoded, hashlib.sha256).hexdigest()


def derive_correlation_id(
    key: str, execution_id: str, source_org_id: str, source_call_id: str
) -> str:
    for value in (execution_id, source_org_id, source_call_id):
        if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value) is None:
            raise EvidenceError("private source identity is invalid")
    material = f"bridgefu|{execution_id}|{source_org_id}|{source_call_id}".encode()
    digest = hmac.new(key.encode(), material, hashlib.sha256).digest()
    return "bf1_" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def sip_source_command(
    session_path: Path, output_path: Path, timeout_seconds: int
) -> list[str]:
    arguments = [
        "--session",
        os.fspath(session_path),
        "--output",
        os.fspath(output_path),
        "--timeout-seconds",
        str(timeout_seconds),
    ]
    if os.environ.get("BRIDGEFU_PACKAGED_SOURCE") == "1":
        executable = ROOT / "target" / "release" / "examples" / "recipe_sip_source"
        try:
            details = executable.lstat()
        except FileNotFoundError as error:
            raise EvidenceError(
                "packaged SIP source release binary is missing"
            ) from error
        if (
            executable.is_symlink()
            or not stat.S_ISREG(details.st_mode)
            or details.st_mode & 0o111 == 0
        ):
            raise EvidenceError("packaged SIP source release binary is unsafe")
        return [os.fspath(executable), *arguments]
    return [
        "cargo",
        "run",
        "--locked",
        "--quiet",
        "--example",
        "recipe_sip_source",
        "--",
        *arguments,
    ]


def validate_private_session(
    session: Mapping[str, Any],
    execution_id: str,
    ledger: Mapping[str, Any],
    environment: Mapping[str, str],
) -> tuple[str, dict[str, str]]:
    if set(session) != SESSION_FIELDS:
        raise EvidenceError("private session has unknown or missing fields")
    scenario = session.get("scenario_id")
    if scenario not in SCENARIOS:
        raise EvidenceError("private session does not identify a qualified scenario")
    deployed_security = stack_parameters(ledger, environment).get("SipSecurity")
    security, codec = scenario_contract(str(scenario), deployed_security)
    expected_scheme = "sips" if security == "sips_srtp" else "sip"
    correlation_id = session.get("correlation_id")
    source_call_id = session.get("source_call_id")
    source_org_id = session.get("source_org_id")
    network_profile = session.get("network_profile")
    if (
        session.get("schema_version") != 1
        or session.get("execution_id") != execution_id
        or session.get("recipe") != RECIPE
        or session.get("release_id") != ledger.get("release_id")
        or session.get("source_tree_sha256")
        != ledger.get("publication_source_tree_sha256")
        or session.get("image") != ledger.get("bridgefu_image_uri")
        or session.get("hangup_origin") not in {"source", "agent"}
        or session.get("security") != security
        or session.get("codec") != codec
        or network_profile not in NETWORK_PROFILES
        or session.get("network_contract") != NETWORK_PROFILES.get(str(network_profile))
        or not isinstance(session.get("started_epoch_ms"), int)
        or not isinstance(session.get("started_at"), str)
        or not isinstance(correlation_id, str)
        or not isinstance(source_call_id, str)
        or not isinstance(source_org_id, str)
        or FINGERPRINT.fullmatch(str(session.get("source_call_fingerprint", "")))
        is None
        or session.get("sip_header")
        != {"name": "X-Correlation-Id", "value": correlation_id}
        or session.get("expected_context")
        != synthetic_context(scenario, str(session.get("hangup_origin")))
    ):
        raise EvidenceError("private session does not match the deployed candidate")
    sip_uri = session.get("sip_uri")
    if scenario == "vapi-web-transfer":
        if sip_uri is not None:
            raise EvidenceError("Vapi session cannot pre-assert its server-selected SIP URI")
    elif not isinstance(sip_uri, str) or not sip_uri.startswith(f"{expected_scheme}:"):
        raise EvidenceError("direct session SIP URI does not match its security posture")
    parse_timestamp(session["started_at"])
    handoff = nested_outputs(ledger, environment, "HandoffService")
    correlation_key = LIVE.secret_value(
        dict(ledger),
        dict(environment),
        handoff["CorrelationKeySecretArn"],
    )
    expected_hmac = session_authentication(session, correlation_key)
    if not hmac.compare_digest(str(session.get("session_hmac", "")), expected_hmac):
        raise EvidenceError("private session authentication failed")
    fingerprint = correlation_fingerprint(correlation_id)
    if fingerprint != session.get("correlation_fingerprint"):
        raise EvidenceError("private session fingerprint mismatch")
    expected_correlation = derive_correlation_id(
        correlation_key,
        execution_id,
        source_org_id,
        source_call_id,
    )
    expected_source_fingerprint = hashlib.sha256(source_call_id.encode("ascii")).hexdigest()[
        :12
    ]
    if (
        expected_source_fingerprint != session["source_call_fingerprint"]
        or expected_correlation != correlation_id
    ):
        raise EvidenceError("private source identity does not bind the correlation")
    return fingerprint, handoff


def scenario_contract(
    scenario: str, deployed_security: str | None
) -> tuple[str, str]:
    if deployed_security not in SIP_SECURITY_POSTURES:
        raise EvidenceError("deployed SIP posture is unsupported")
    catalog = SCENARIOS.get(scenario)
    if catalog is None:
        raise EvidenceError("scenario is not in the qualification catalog")
    catalog_security, codec = catalog
    if scenario == "vapi-web-transfer":
        if catalog_security != "deployed":
            raise EvidenceError("Vapi scenario posture contract is invalid")
        return deployed_security, codec
    if catalog_security != deployed_security:
        raise EvidenceError("scenario security does not match the deployed SIP posture")
    return catalog_security, codec


def parse_public_ipv4(value: str) -> str:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as error:
        raise EvidenceError("current qualification source IP is invalid") from error
    if address.version != 4 or not address.is_global:
        raise EvidenceError("current qualification source must be one public IPv4 address")
    return str(address)


def require_bound_public_source(ledger: Mapping[str, Any]) -> None:
    bound = ledger.get("qualification_source_cidr")
    try:
        network = ipaddress.ip_network(str(bound), strict=True)
    except ValueError as error:
        raise EvidenceError("qualification source /32 is not bound") from error
    if network.version != 4 or network.prefixlen != 32 or not network.is_global:
        raise EvidenceError("qualification source must be one bound public IPv4 /32")
    request = urllib.request.Request(
        CHECKIP_URL,
        headers={"User-Agent": "bridgefu-qualification/1"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
            if response.status != 200:
                raise EvidenceError("could not verify the current qualification source")
            payload = response.read(65)
    except (OSError, TimeoutError) as error:
        raise EvidenceError("could not verify the current qualification source") from error
    if len(payload) > 64:
        raise EvidenceError("qualification source response exceeded its boundary")
    try:
        current = parse_public_ipv4(payload.decode("ascii"))
    except UnicodeDecodeError as error:
        raise EvidenceError("qualification source response is not ASCII") from error
    if f"{current}/32" != str(network):
        raise EvidenceError(
            "current public IP does not match the bound qualification source /32"
        )


def released_artifact(
    ledger: Mapping[str, Any], relative_path: str, maximum: int
) -> tuple[Path, str]:
    release = LIVE.ledger_path(ledger["execution_id"]).parent / "release"
    manifest = load_json(release / "manifest.json")
    artifacts = manifest.get("artifacts") if isinstance(manifest, dict) else None
    if not isinstance(artifacts, list):
        raise EvidenceError("immutable release manifest is unavailable")
    matches = [
        item
        for item in artifacts
        if isinstance(item, dict) and item.get("path") == relative_path
    ]
    if len(matches) != 1 or set(matches[0]) != {"path", "sha256", "size_bytes"}:
        raise EvidenceError("immutable release artifact is not uniquely manifested")
    expected_digest = matches[0].get("sha256")
    expected_size = matches[0].get("size_bytes")
    path = release / relative_path
    regular_bounded_file(path, maximum)
    if (
        not isinstance(expected_digest, str)
        or SHA256.fullmatch(expected_digest) is None
        or not isinstance(expected_size, int)
        or expected_size != path.stat().st_size
        or sha256_file(path) != expected_digest
    ):
        raise EvidenceError("immutable release artifact digest or size changed")
    return path, expected_digest


def extract_site_bundle(bundle: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    os.chmod(destination, 0o700)
    try:
        with zipfile.ZipFile(bundle) as archive:
            members = archive.infolist()
            if {member.filename for member in members} != SITE_FILES:
                raise EvidenceError("immutable demo-site bundle file set changed")
            for member in members:
                mode = (member.external_attr >> 16) & 0o170000
                if (
                    member.is_dir()
                    or member.flag_bits & 0x1
                    or mode not in {0, 0o100000}
                    or member.file_size <= 0
                    or member.file_size > MAX_SITE_BUNDLE_BYTES
                ):
                    raise EvidenceError("immutable demo-site bundle member is unsafe")
                payload = archive.read(member)
                if len(payload) != member.file_size:
                    raise EvidenceError("immutable demo-site bundle member is incomplete")
                output = destination / member.filename
                descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    with os.fdopen(descriptor, "wb") as handle:
                        handle.write(payload)
                except BaseException:
                    output.unlink(missing_ok=True)
                    raise
    except (OSError, zipfile.BadZipFile) as error:
        raise EvidenceError("immutable demo-site bundle is invalid") from error


def vapi_call(api_key: str, call_id: str) -> dict[str, Any]:
    if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", call_id) is None:
        raise EvidenceError("private Vapi call identity is invalid")
    request = urllib.request.Request(
        f"{VAPI_API_BASE}/call/{urllib.parse.quote(call_id, safe='')}",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "bridgefu-qualification/1",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
            if response.status != 200:
                raise EvidenceError("Vapi call verification returned a non-success status")
            payload = response.read(MAX_JSON_BYTES + 1)
    except (OSError, TimeoutError, urllib.error.HTTPError) as error:
        raise EvidenceError("Vapi call verification request failed") from error
    if len(payload) > MAX_JSON_BYTES:
        raise EvidenceError("Vapi call verification response exceeded its boundary")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError("Vapi call verification response is invalid") from error
    if not isinstance(value, dict):
        raise EvidenceError("Vapi call verification response has the wrong shape")
    return value


def walk_json(value: Any) -> Iterable[Any]:
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_json(child)


def vapi_tool_names(call: Mapping[str, Any]) -> set[str]:
    names: set[str] = set()
    for item in walk_json(call):
        if not isinstance(item, dict):
            continue
        function = item.get("function")
        if isinstance(function, dict) and isinstance(function.get("name"), str):
            names.add(function["name"])
        for key in ("toolName", "name"):
            name = item.get(key)
            if isinstance(name, str) and name in {"prepare_handoff", "transferCall"}:
                names.add(name)
    return names


def vapi_call_identity(
    call: Mapping[str, Any], expected_call_id: str, expected_assistant_id: str
) -> str:
    source_call_fingerprint = hashlib.sha256(expected_call_id.encode("ascii")).hexdigest()[
        :12
    ]
    if (
        call.get("id") != expected_call_id
        or call.get("assistantId") != expected_assistant_id
        or FINGERPRINT.fullmatch(source_call_fingerprint) is None
        or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", str(call.get("orgId", "")))
        is None
    ):
        raise EvidenceError("Vapi call does not match the recipe-owned assistant")
    return str(call["orgId"])


def verify_vapi_call_contract(
    call: Mapping[str, Any], session: Mapping[str, Any], assistant_id: str
) -> None:
    vapi_call_identity(call, session["source_call_id"], assistant_id)
    tools = vapi_tool_names(call)
    destination = call.get("destination")
    transfers = call.get("transfers")
    status = call.get("status")
    ended_reason = call.get("endedReason")
    transfer_observed = (
        isinstance(destination, dict)
        or isinstance(transfers, list)
        and len(transfers) > 0
        or ended_reason == "assistant-forwarded-call"
    )
    if (
        status != "ended"
        or not transfer_observed
        or "prepare_handoff" not in tools
        or "transferCall" not in tools
    ):
        raise EvidenceError("Vapi call did not prove the prepare and transfer contract")


def wait_for_vapi_call_contract(
    api_key: str,
    session: Mapping[str, Any],
    assistant_id: str,
    wait_seconds: int,
) -> None:
    deadline = time.monotonic() + min(wait_seconds, 60)
    while True:
        call = vapi_call(api_key, session["source_call_id"])
        try:
            verify_vapi_call_contract(call, session, assistant_id)
            return
        except EvidenceError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(min(2, max(0.1, deadline - time.monotonic())))


def create_direct_session(
    args: argparse.Namespace,
    path: Path,
    ledger: dict[str, Any],
    environment: dict[str, str],
    *,
    session_id: str | None = None,
) -> Path:
    parameters = stack_parameters(ledger, environment)
    security, codec = scenario_contract(
        args.scenario, parameters.get("SipSecurity")
    )
    handoff = nested_outputs(ledger, environment, "HandoffService")
    webhook = LIVE.secret_value(
        ledger,
        environment,
        handoff["VapiWebhookSecretArn"],
    )
    correlation_key = LIVE.secret_value(
        ledger,
        environment,
        handoff["CorrelationKeySecretArn"],
    )
    nonce = session_id or secrets.token_hex(12)
    if re.fullmatch(r"[0-9a-f]{24}", nonce) is None:
        raise EvidenceError("direct call session ID has the wrong shape")
    call_id = f"call_bridgefu_{nonce}"
    org_id = "org_bridgefu_qualification"
    tool_id = f"tool_bridgefu_{nonce}"
    context = synthetic_context(args.scenario, args.hangup_origin)
    prepare_payload = {
        "message": {
            "type": "tool-calls",
            "call": {"id": call_id, "orgId": org_id},
            "toolCallList": [
                {
                    "id": tool_id,
                    "name": "prepare_handoff",
                    "arguments": context,
                }
            ],
        }
    }
    started_at = utc_now()
    started_epoch_ms = int(time.time() * 1000)
    prepare_status, prepare_body = LIVE.http_post(
        handoff["PrepareUrl"], webhook, prepare_payload
    )
    replay_status, replay_body = LIVE.http_post(
        handoff["PrepareUrl"], webhook, prepare_payload
    )
    if (
        prepare_status != 200
        or replay_status != 200
        or prepare_body != replay_body
    ):
        raise EvidenceError("synthetic prepare/replay contract failed")
    correlation_id = derive_correlation_id(
        correlation_key,
        args.execution_id,
        org_id,
        call_id,
    )
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
    destination = transfer_body.get("destination", {})
    expected_scheme = "sips" if security == "sips_srtp" else "sip"
    if (
        transfer_status != 200
        or destination.get("type") != "sip"
        or not destination.get("sipUri", "").startswith(f"{expected_scheme}:")
        or destination.get("sipHeaders") != {"X-Correlation-Id": correlation_id}
    ):
        raise EvidenceError("synthetic transfer did not return one exact recipe header")
    session: dict[str, Any] = {
        "schema_version": 1,
        "execution_id": args.execution_id,
        "recipe": RECIPE,
        "release_id": ledger["release_id"],
        "source_tree_sha256": ledger["publication_source_tree_sha256"],
        "image": ledger["bridgefu_image_uri"],
        "session_id": nonce,
        "scenario_id": args.scenario,
        "hangup_origin": args.hangup_origin,
        "security": security,
        "codec": codec,
        "network_profile": args.network_profile,
        "network_contract": dict(NETWORK_PROFILES[args.network_profile]),
        "started_at": started_at,
        "started_epoch_ms": started_epoch_ms,
        "correlation_id": correlation_id,
        "correlation_fingerprint": correlation_fingerprint(correlation_id),
        "source_call_id": call_id,
        "source_org_id": org_id,
        "source_call_fingerprint": hashlib.sha256(call_id.encode("ascii")).hexdigest()[
            :12
        ],
        "sip_uri": destination["sipUri"],
        "sip_header": {"name": "X-Correlation-Id", "value": correlation_id},
        "expected_context": context,
    }
    session["session_hmac"] = session_authentication(session, correlation_key)
    output = path.parent / "call-sessions" / (
        f"{args.scenario}-{args.hangup_origin}-{nonce}.private.json"
    )
    write_private_json(output, session)
    LIVE.record(
        path,
        ledger,
        "direct_call_session_created",
        scenario=args.scenario,
        hangup_origin=args.hangup_origin,
        network_profile=args.network_profile,
    )
    return output


def start_direct(args: argparse.Namespace) -> None:
    if args.confirm != args.execution_id:
        raise EvidenceError("start-direct requires the exact execution ID confirmation")
    if args.scenario not in DIRECT_SCENARIOS:
        raise EvidenceError("start-direct supports only the four direct SIP scenarios")
    path, ledger, environment = stable_deployment(args.execution_id)
    output = create_direct_session(args, path, ledger, environment)
    print(output)


def decode_dynamo_item(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise EvidenceError("handoff row is unavailable")
    decoded: dict[str, Any] = {}
    for key, typed in item.items():
        if not isinstance(key, str) or not isinstance(typed, dict) or len(typed) != 1:
            raise EvidenceError("handoff row violates its bounded DynamoDB shape")
        kind, value = next(iter(typed.items()))
        if kind == "S" and isinstance(value, str):
            decoded[key] = value
        elif kind == "N" and isinstance(value, str) and re.fullmatch(r"-?[0-9]+", value):
            decoded[key] = int(value)
        else:
            raise EvidenceError("handoff row contains an unsupported DynamoDB value")
    return decoded


def get_handoff_row(
    ledger: Mapping[str, Any],
    environment: Mapping[str, str],
    table_name: str,
    correlation_id: str,
) -> dict[str, Any]:
    key_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=LIVE.ledger_path(ledger["execution_id"]).parent,
            delete=False,
        ) as handle:
            os.chmod(handle.name, 0o600)
            json.dump({"correlation_id": {"S": correlation_id}}, handle)
            key_path = Path(handle.name)
        response = LIVE.aws_json(
            [
                "dynamodb",
                "get-item",
                "--region",
                ledger["region"],
                "--table-name",
                table_name,
                "--key",
                f"file://{key_path}",
                "--consistent-read",
            ],
            env=dict(environment),
        )
        return decode_dynamo_item(response.get("Item") if isinstance(response, dict) else None)
    finally:
        if key_path is not None:
            key_path.unlink(missing_ok=True)


def verify_handoff_row(row: Mapping[str, Any], session: Mapping[str, Any]) -> None:
    allowed = {
        "schema_version",
        "correlation_id",
        *DISPLAY_FIELDS,
        "vapi_call_reference",
        "vapi_call_fingerprint",
        "content_hash",
        "created_at",
        "updated_at",
        "expires_at",
        "handoff_status",
        "bridgefu_call_id",
        "attachment_expires_at",
    }
    required = {
        "schema_version",
        "correlation_id",
        *DISPLAY_FIELDS,
        "vapi_call_fingerprint",
        "content_hash",
        "created_at",
        "updated_at",
        "expires_at",
        "handoff_status",
        "bridgefu_call_id",
        "attachment_expires_at",
    }
    if not required.issubset(row) or not set(row).issubset(allowed):
        raise EvidenceError("handoff row fields do not match the recipe contract")
    if (
        row.get("schema_version") != 1
        or row.get("correlation_id") != session.get("correlation_id")
        or row.get("handoff_status") not in {"RESERVED", "CONSUMED"}
        or not isinstance(row.get("expires_at"), int)
        or row["expires_at"] <= int(time.time())
        or not isinstance(row.get("bridgefu_call_id"), str)
        or not isinstance(row.get("attachment_expires_at"), int)
        or not SHA256.fullmatch(str(row.get("content_hash", "")))
        or not SHA256.fullmatch(str(row.get("vapi_call_fingerprint", "")))
    ):
        raise EvidenceError("handoff row identity, state, or expiry check failed")
    expected = session.get("expected_context")
    if not isinstance(expected, dict) or any(row.get(field) != expected.get(field) for field in DISPLAY_FIELDS):
        raise EvidenceError("handoff row does not contain the exact synthetic context")


def message_payloads(message: str) -> Iterable[dict[str, Any]]:
    candidates = [message]
    if "\n" in message.strip():
        candidates.extend(message.splitlines())
    seen: set[str] = set()
    for candidate in candidates:
        candidate = candidate.strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        if not candidate.startswith("{"):
            brace = candidate.find("{")
            if brace < 0:
                continue
            candidate = candidate[brace:]
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if not isinstance(value, dict):
            continue
        yield value
        wrapped = value.get("log")
        if isinstance(wrapped, str) and wrapped not in seen:
            candidates.append(wrapped)
        fields = value.get("fields")
        if isinstance(fields, dict):
            merged = dict(fields)
            if "timestamp" in value:
                merged.setdefault("timestamp", value["timestamp"])
            yield merged


def log_evidence(
    runtime_events: Iterable[Mapping[str, Any]],
    lookup_events: Iterable[Mapping[str, Any]],
    fingerprint: str,
) -> tuple[dict[str, int], dict[str, str], list[str]]:
    if FINGERPRINT.fullmatch(fingerprint) is None:
        raise EvidenceError("invalid correlation fingerprint")
    stage_counts: dict[str, int] = {}
    stage_times: dict[str, str] = {}
    lookup_results: list[str] = []
    for event in runtime_events:
        message = event.get("message")
        if not isinstance(message, str):
            continue
        for payload in message_payloads(message):
            if (
                payload.get("event") == "bridgefu_screen_pop_lifecycle"
                and payload.get("correlation_fingerprint") == fingerprint
                and payload.get("stage") in REQUIRED_LIFECYCLE
            ):
                stage = payload["stage"]
                stage_counts[stage] = stage_counts.get(stage, 0) + 1
                observed_at = payload.get("occurred_at") or payload.get("timestamp")
                if isinstance(observed_at, str):
                    stage_times.setdefault(stage, observed_at)
    for event in lookup_events:
        message = event.get("message")
        if not isinstance(message, str):
            continue
        for payload in message_payloads(message):
            if (
                payload.get("event") == "bridgefu_correlation_evidence"
                and payload.get("operation") == "connect_lookup"
                and payload.get("correlation_fingerprint") == fingerprint
                and payload.get("result") in {"available", "unavailable", "internal_error"}
            ):
                lookup_results.append(payload["result"])
    return stage_counts, stage_times, lookup_results


def sip_invite_header_evidence(
    runtime_events: Iterable[Mapping[str, Any]], fingerprint: str
) -> bool:
    if FINGERPRINT.fullmatch(fingerprint) is None:
        raise EvidenceError("invalid correlation fingerprint")
    observations: set[tuple[str, int]] = set()
    for event in runtime_events:
        message = event.get("message")
        if not isinstance(message, str):
            continue
        for payload in message_payloads(message):
            if (
                payload.get("event") == "bridgefu_sip_invite_evidence"
                and payload.get("correlation_fingerprint") == fingerprint
                and payload.get("header_name") == "x-correlation-id"
                and payload.get("header_count") == 1
            ):
                observations.add((payload["header_name"], payload["header_count"]))
    return observations == {("x-correlation-id", 1)}


def filter_log_events(
    ledger: Mapping[str, Any],
    environment: Mapping[str, str],
    log_group: str,
    fingerprint: str,
    started_epoch_ms: int,
) -> list[dict[str, Any]]:
    response = LIVE.aws_json(
        [
            "logs",
            "filter-log-events",
            "--region",
            ledger["region"],
            "--log-group-name",
            log_group,
            "--start-time",
            str(max(0, started_epoch_ms - 60_000)),
            "--filter-pattern",
            f'"{fingerprint}"',
        ],
        env=dict(environment),
    )
    events = response.get("events", []) if isinstance(response, dict) else []
    return [event for event in events if isinstance(event, dict)]


def parse_timestamp(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvidenceError("lifecycle evidence contains an invalid timestamp") from error
    if parsed.tzinfo is None:
        raise EvidenceError("lifecycle evidence timestamp is not timezone-aware")
    return parsed.astimezone(dt.timezone.utc)


def percentile_95(latencies: Iterable[int]) -> float:
    values = sorted(latencies)
    if len(values) < 3 or any(value < 0 or value > 5_000 for value in values):
        raise EvidenceError("media marker latency evidence is incomplete or out of bounds")
    rank = max(0, (95 * len(values) + 99) // 100 - 1)
    return float(values[rank])


def marker_latency_ms(sent: Any, observed: Any) -> float:
    if not isinstance(sent, list) or not isinstance(observed, list):
        raise EvidenceError("media marker timestamps are unavailable")
    if not 5 <= len(sent) <= 32 or not 3 <= len(observed) <= 16:
        raise EvidenceError("media marker timestamp cardinality is out of bounds")
    if any(not isinstance(value, int) for value in [*sent, *observed]):
        raise EvidenceError("media marker timestamps must be integer milliseconds")
    if sent != sorted(sent) or observed != sorted(observed):
        raise EvidenceError("media marker timestamps must be monotonic")
    latencies = []
    previous_index = -1
    for received_at in observed:
        candidates = [
            index
            for index, sent_at in enumerate(sent)
            if previous_index < index
            and sent_at <= received_at
            and received_at - sent_at <= 5_000
        ]
        if not candidates:
            continue
        index = candidates[-1]
        latencies.append(received_at - sent[index])
        previous_index = index
    return percentile_95(latencies)


def collect(args: argparse.Namespace) -> None:
    if args.confirm != args.execution_id:
        raise EvidenceError("collect requires the exact execution ID confirmation")
    path, ledger, environment = stable_deployment(args.execution_id)
    session_path = args.session.resolve()
    session = require_private_session(session_path, args.execution_id)
    fingerprint, handoff = validate_private_session(
        session,
        args.execution_id,
        ledger,
        environment,
    )
    network_path, network = validated_network_observation(
        args.network_observation,
        path,
        ledger,
        session,
    )

    participant = load_json(args.participant_observation)
    validate_schema(participant, PARTICIPANT_SCHEMA)
    reject_sensitive_evidence(participant)
    if (
        participant["execution_id"] != args.execution_id
        or participant["scenario_id"] != session["scenario_id"]
        or participant["hangup_origin"] != session["hangup_origin"]
        or participant["hangup"]["origin"] != session["hangup_origin"]
        or participant["correlation_fingerprint"] != fingerprint
        or participant["source_call_fingerprint"]
        != session["source_call_fingerprint"]
    ):
        raise EvidenceError("participant observation does not match the private session")
    regular_bounded_file(args.screenshot, MAX_SCREENSHOT_BYTES)
    screenshot_digest = sha256_file(args.screenshot)
    if screenshot_digest != participant["screen_pop"]["screenshot_sha256"]:
        raise EvidenceError("participant screenshot digest mismatch")
    harness_digest = sha256_file(AGENT_HARNESS)
    if participant["producer_revision_sha256"] != harness_digest:
        raise EvidenceError("participant observation is not bound to this harness revision")

    source = load_json(args.source_observation)
    source_schema = (
        VAPI_SOURCE_SCHEMA
        if session["scenario_id"] == "vapi-web-transfer"
        else SOURCE_SCHEMA
    )
    validate_schema(source, source_schema)
    reject_sensitive_evidence(source)
    if (
        source["execution_id"] != args.execution_id
        or source["scenario_id"] != session["scenario_id"]
        or source["hangup_origin"] != session["hangup_origin"]
        or source["hangup"]["origin"] != session["hangup_origin"]
        or source["correlation_fingerprint"] != fingerprint
        or source["source_call_fingerprint"] != session["source_call_fingerprint"]
    ):
        raise EvidenceError("source observation does not match the private session")
    source_harness = (
        VAPI_HARNESS
        if session["scenario_id"] == "vapi-web-transfer"
        else SOURCE_HARNESS
    )
    source_harness_digest = sha256_file(source_harness)
    if source["producer_revision_sha256"] != source_harness_digest:
        raise EvidenceError("source observation is not bound to this source revision")
    security = str(session["security"])
    codec = str(session["codec"])
    source_site_bundle_sha256: str | None = None
    vapi_call_contract_verified = False
    if session["scenario_id"] == "vapi-web-transfer":
        _, source_site_bundle_sha256 = released_artifact(
            ledger,
            "artifacts/demo-site/demo-site.zip",
            MAX_SITE_BUNDLE_BYTES,
        )
        if (
            session["security"] not in SIP_SECURITY_POSTURES
            or session["codec"] != "negotiated"
            or source["media"]["security"] != "srtp"
            or source["media"]["codec"] != "negotiated"
            or source["site_bundle_sha256"] != source_site_bundle_sha256
        ):
            raise EvidenceError("Vapi source changed the browser transfer contract")
        vapi_outputs = nested_outputs(ledger, environment, "VapiResources")
        vapi_secret_arn = ledger.get("vapi_api_key_secret_arn")
        if not isinstance(vapi_secret_arn, str):
            raise EvidenceError("temporary Vapi verification secret is unavailable")
        private_key = LIVE.secret_value(ledger, environment, vapi_secret_arn)
        wait_for_vapi_call_contract(
            private_key,
            session,
            vapi_outputs["AssistantId"],
            args.wait_seconds,
        )
        vapi_call_contract_verified = True
    else:
        expected_scheme = "sips" if security == "sips_srtp" else "sip"
        expected_transport = "tls" if security == "sips_srtp" else "udp"
        expected_media_security = "srtp" if security == "sips_srtp" else "rtp"
        if (
            session["security"] != security
            or session["codec"] != codec
            or source["signaling"]["scheme"] != expected_scheme
            or source["signaling"]["transport"] != expected_transport
            or source["media"]["security"] != expected_media_security
            or source["media"]["codec"] != codec
        ):
            raise EvidenceError("source observation changed the scenario transport contract")

    recipe_stack_id = LIVE.deployed_recipe_stack_id(ledger, environment)
    root_stack = LIVE.stack_description(ledger, environment, recipe_stack_id)
    root_outputs = LIVE.outputs(root_stack)
    row = get_handoff_row(
        ledger,
        environment,
        root_outputs["HandoffTableName"],
        session["correlation_id"],
    )
    verify_handoff_row(row, session)
    runtime_logical_id = (
        "HighAvailabilityRuntime"
        if ledger.get("runtime_profile") == "high_availability"
        else "StarterRuntime"
    )
    runtime = nested_outputs(ledger, environment, runtime_logical_id)

    deadline = time.monotonic() + args.wait_seconds
    stage_counts: dict[str, int] = {}
    stage_times: dict[str, str] = {}
    lookup_results: list[str] = []
    invite_header_verified = False
    while True:
        runtime_events = filter_log_events(
            ledger,
            environment,
            runtime["RuntimeLogGroupName"],
            fingerprint,
            session["started_epoch_ms"],
        )
        lookup_events = filter_log_events(
            ledger,
            environment,
            handoff["LookupLogGroupName"],
            fingerprint,
            session["started_epoch_ms"],
        )
        stage_counts, stage_times, lookup_results = log_evidence(
            runtime_events,
            lookup_events,
            fingerprint,
        )
        invite_header_verified = sip_invite_header_evidence(runtime_events, fingerprint)
        if (
            set(stage_counts) == set(REQUIRED_LIFECYCLE)
            and "available" in lookup_results
            and invite_header_verified
        ):
            break
        if time.monotonic() >= deadline:
            raise EvidenceError("correlated runtime/lookup evidence did not converge")
        time.sleep(min(5, max(0.1, deadline - time.monotonic())))

    if stage_counts.get("contact_started") != 1:
        raise EvidenceError("correlated lifecycle did not start exactly one Connect contact")
    if any(stage_counts.get(stage, 0) < 1 for stage in REQUIRED_LIFECYCLE):
        raise EvidenceError("correlated lifecycle is incomplete")
    setup_latency_ms = (
        parse_timestamp(stage_times["media_connected"])
        - parse_timestamp(stage_times["sip_invite_received"])
    ).total_seconds() * 1000
    if not 0 <= setup_latency_ms <= 30_000:
        raise EvidenceError("correlated setup latency exceeds the evidence contract")

    participant_media = participant["media"]
    source_media = source["media"]
    screen_pop = participant["screen_pop"]
    source_to_agent_latency_ms_p95 = marker_latency_ms(
        source_media["source_marker_sent_at_ms"],
        participant_media["source_marker_observed_at_ms"],
    )
    agent_to_source_latency_ms_p95 = marker_latency_ms(
        participant_media["agent_marker_sent_at_ms"],
        source_media["agent_marker_observed_at_ms"],
    )
    source_hangup = source["hangup"]
    participant_hangup = participant["hangup"]
    source_local_end = source_hangup[
        "local_end_completed"
        if session["scenario_id"] == "vapi-web-transfer"
        else "local_bye_completed"
    ]
    source_remote_end = source_hangup[
        "remote_end_observed"
        if session["scenario_id"] == "vapi-web-transfer"
        else "remote_bye_observed"
    ]
    originating_hangup_cleanup = (
        source_local_end
        and participant_hangup["remote_end_observed"]
        if session["hangup_origin"] == "source"
        else participant_hangup["local_end_completed"]
        and source_remote_end
    )
    checks = {
        "actual_transfer_header": (
            (
                session["scenario_id"] == "vapi-web-transfer"
                or source["signaling"]["invite_sent"]
                and source["signaling"]["wire_header_name"] == "x-correlation-id"
                and source["signaling"]["wire_header_count"] == 1
            )
            and invite_header_verified
            and "sip_invite_received" in stage_counts
        ),
        "context_persisted": True,
        "amazon_attribute_mapped": "attributes_mapped" in stage_counts,
        "connect_contact_started_once": stage_counts.get("contact_started") == 1,
        "connect_lookup_available": "available" in lookup_results,
        "media_connected": "media_connected" in stage_counts,
        "agent_screen_visible": screen_pop["visible"]
        and set(screen_pop["visible_fields"]) == set(DISPLAY_FIELDS),
        "audio_source_to_agent_non_silent": (
            source_media["source_to_agent_marker_frames_sent"] >= 5
            and participant_media["source_to_agent_marker_frames"] >= 3
        ),
        "audio_agent_to_source_non_silent": (
            participant_media["agent_to_source_marker_frames_sent"] >= 5
            and source_media["agent_to_source_marker_frames"] >= 3
        ),
        "dtmf_source_to_agent": (
            source_media["dtmf_source_to_agent_sent"]
            and participant_media["dtmf_source_to_agent_observed"]
        ),
        "dtmf_agent_to_source": (
            participant_media["dtmf_agent_to_source_sent"]
            and source_media["dtmf_agent_to_source_observed"]
        ),
        "originating_hangup_cleanup": originating_hangup_cleanup,
        "cleanup_zero_state": (
            source_hangup["cleanup_observed"]
            and participant_hangup["cleanup_observed"]
            and "teardown_started" in stage_counts
            and "terminated" in stage_counts
        ),
    }
    if not all(checks.values()):
        raise EvidenceError("one or more per-call qualification checks failed")
    evidence = {
        "schema_version": 1,
        "recipe": RECIPE,
        "execution_id": args.execution_id,
        "scenario_id": session["scenario_id"],
        "network": network,
        "hangup_origin": session["hangup_origin"],
        "started_at": session["started_at"],
        "ended_at": utc_now(),
        "revisions": {
            "release_id": ledger["release_id"],
            "source_tree_sha256": ledger["publication_source_tree_sha256"],
            "image": ledger["bridgefu_image_uri"],
        },
        "correlation_fingerprint": fingerprint,
        "checks": checks,
        "timings": {
            "setup_latency_ms": round(setup_latency_ms, 3),
            "source_to_agent_latency_ms_p95": source_to_agent_latency_ms_p95,
            "agent_to_source_latency_ms_p95": agent_to_source_latency_ms_p95,
        },
        "observations": {
            "runtime_lifecycle_stages": sorted(stage_counts),
            "lookup_result": "available",
            "source_producer": source["producer"],
            "source_producer_revision_sha256": source[
                "producer_revision_sha256"
            ],
            "source_site_bundle_sha256": source_site_bundle_sha256,
            "vapi_call_contract_verified": vapi_call_contract_verified,
            "attachment_replay_rejected": (
                None
                if session["scenario_id"] == "vapi-web-transfer"
                else source["signaling"]["attachment_replay_rejected"]
            ),
            "participant_producer": participant["producer"],
            "participant_producer_revision_sha256": participant[
                "producer_revision_sha256"
            ],
            "screenshot_sha256": screenshot_digest,
        },
        "passed": True,
        "redacted": True,
        "customer_data_retained": False,
    }
    reject_sensitive_evidence(evidence)
    validate_schema(evidence, CALL_SCHEMA)
    output = path.parent / "call-evidence" / (
        f"{session['scenario_id']}-{session['hangup_origin']}-{session['session_id']}.json"
    )
    write_private_json(output, evidence)
    session_path.unlink()
    network_path.unlink()
    LIVE.record(
        path,
        ledger,
        "call_evidence_collected",
        scenario=session["scenario_id"],
        hangup_origin=session["hangup_origin"],
    )
    print(output)


def terminate_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


SAFE_AGENT_FAILURE_PREFIXES = (
    "authenticated Agent Workspace was not ready",
    "Agent Workspace could not select Available",
    "Agent Workspace did not become Available",
    "Agent Workspace did not receive an answerable synthetic contact",
    "Agent Workspace did not auto-accept the synthetic contact",
    "Agent Workspace did not render the exact synthetic screen pop",
    "Agent Workspace did not render the missing-context guide",
    "Agent Workspace media/DTMF browser observations did not converge",
    "Agent Workspace keypad control was not available",
    "Agent Workspace did not expose DTMF digit 6",
    "Agent Workspace end-call control was unavailable",
    "Agent Workspace did not observe the source hangup",
    "Agent Workspace contact controls did not clean up",
    "Agent Workspace final media evidence is incomplete",
    "Agent Workspace harness failed",
)

SAFE_SOURCE_FAILURE_PREFIXES = (
    "controlled recipe call was not answered",
    "SRTP negotiation was not observed",
    "SRTP contexts were not installed",
    "plaintext RTP scenario unexpectedly negotiated SRTP",
    "opening controlled recipe audio",
    "sending source marker frame",
    "sending source marker spacing",
    "sending source in-band DTMF",
    "sending source in-band DTMF spacing",
    "sending source RFC 4733 DTMF",
    "agent-to-source DTMF was not observed",
    "agent marker observation timed out",
    "agent marker observer stopped unexpectedly",
    "agent-to-source audio marker evidence is incomplete",
    "source BYE did not complete",
    "agent BYE was not observed",
    "agent BYE observer stopped",
    "sending the controlled attachment replay",
    "one-use SIP attachment replay was answered",
    "wire-level INVITE/header/transport evidence failed",
    "immutable Vapi demo site did not become ready",
    "stock Vapi webCall did not start",
    "Vapi transfer trigger was not accepted exactly once",
    "Vapi browser media/DTMF observations did not converge",
    "Vapi browser could not originate hangup",
    "Vapi browser did not observe terminal cleanup",
    "Vapi browser cleanup was not stable",
    "Vapi browser final media evidence is incomplete",
    "Vapi browser observer failed",
)


def agent_failure_detail(process: subprocess.Popen[str]) -> str | None:
    try:
        _, error = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        return None
    if not isinstance(error, str):
        return None
    for line in error.splitlines():
        if not line.startswith("error: "):
            continue
        detail = line.removeprefix("error: ")
        for prefix in SAFE_AGENT_FAILURE_PREFIXES:
            if detail.startswith(prefix):
                return prefix
    return None


def agent_failure(process: subprocess.Popen[str], message: str) -> EvidenceError:
    detail = agent_failure_detail(process)
    return EvidenceError(f"{message}: {detail}" if detail else message)


def source_failure_detail(process: subprocess.Popen[str]) -> str | None:
    try:
        _, error = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        return None
    if not isinstance(error, str):
        return None
    for line in error.splitlines():
        detail = None
        if line.startswith("Error: "):
            detail = line.removeprefix("Error: ")
        elif line.startswith("error: "):
            detail = line.removeprefix("error: ")
        if detail is None:
            continue
        for prefix in SAFE_SOURCE_FAILURE_PREFIXES:
            if detail.startswith(prefix):
                return prefix
    return None


def source_failure(process: subprocess.Popen[str], message: str) -> EvidenceError:
    detail = source_failure_detail(process)
    return EvidenceError(f"{message}: {detail}" if detail else message)


def validate_connect_url(value: str) -> None:
    try:
        connect_url = urllib.parse.urlsplit(value)
    except ValueError as error:
        raise EvidenceError("Agent Workspace URL is invalid") from error
    if (
        connect_url.scheme != "https"
        or connect_url.username is not None
        or connect_url.password is not None
        or connect_url.hostname is None
        or not connect_url.hostname.endswith(".my.connect.aws")
        or not connect_url.path.startswith("/agent-app-v2/")
        or connect_url.fragment
    ):
        raise EvidenceError("use the default HTTPS Amazon Connect Agent Workspace URL")


def run_direct_with_deployment(
    args: argparse.Namespace,
    path: Path,
    ledger: dict[str, Any],
    environment: dict[str, str],
    prepared_network_observation: dict[str, Any] | None = None,
) -> tuple[Path, Path, Path, Path] | None:
    session_path = args.session.resolve()
    session = require_private_session(session_path, args.execution_id)
    validate_private_session(session, args.execution_id, ledger, environment)
    require_bound_public_source(ledger)
    scenario = session.get("scenario_id")
    hangup = session.get("hangup_origin")
    session_id = session.get("session_id")
    if (
        scenario not in DIRECT_SCENARIOS
        or hangup not in {"source", "agent"}
        or not isinstance(session_id, str)
        or re.fullmatch(r"[0-9a-f]{24}", session_id) is None
    ):
        raise EvidenceError("private session does not identify a direct call")
    storage_state = args.storage_state.resolve()
    regular_bounded_file(storage_state, MAX_JSON_BYTES)
    if storage_state.stat().st_mode & 0o077:
        raise EvidenceError("Agent Workspace storage state must be mode 0600")
    validate_connect_url(args.connect_url)

    participant_dir = path.parent / "participant-observations"
    source_dir = path.parent / "source-observations"
    screenshot_dir = path.parent / "screenshots"
    for directory in (participant_dir, source_dir, screenshot_dir):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
    basename = f"{scenario}-{hangup}-{session_id}"
    participant_path = participant_dir / f"{basename}.json"
    source_path = source_dir / f"{basename}.json"
    screenshot_path = screenshot_dir / f"{basename}.png"
    for output in (participant_path, source_path, screenshot_path):
        if output.exists():
            raise EvidenceError("direct observer evidence output already exists")

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
    ]
    if args.headed:
        agent_command.append("--headed")
    source_command = sip_source_command(
        session_path, source_path, args.observer_timeout_seconds
    )
    process_environment = os.environ.copy()
    process_environment["RUST_LOG"] = "error"
    agent: subprocess.Popen[str] | None = None
    source: subprocess.Popen[str] | None = None
    network_observation: dict[str, Any]
    network_context = (
        nullcontext(prepared_network_observation)
        if prepared_network_observation is not None
        else controlled_network(
            path,
            ledger,
            environment,
            str(session["network_profile"]),
            session_id,
        )
    )
    with network_context as network_observation:
        try:
            agent = subprocess.Popen(
                agent_command,
                cwd=ROOT,
                env=process_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(3)
            if agent.poll() is not None:
                raise agent_failure(
                    agent, "Agent Workspace observer stopped before the call"
                )
            source = subprocess.Popen(
                source_command,
                cwd=ROOT,
                env=process_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            deadline = time.monotonic() + args.observer_timeout_seconds + 60
            while agent.poll() is None or source.poll() is None:
                if agent.poll() not in {None, 0}:
                    raise agent_failure(
                        agent, "the protected Agent Workspace observer failed"
                    )
                if source.poll() not in {None, 0}:
                    raise source_failure(
                        source, "the protected direct SIP source failed"
                    )
                if time.monotonic() >= deadline:
                    raise EvidenceError(
                        "protected direct-call observers exceeded their deadline"
                    )
                time.sleep(0.25)
            if agent.returncode != 0:
                raise agent_failure(
                    agent, "the protected Agent Workspace observer failed"
                )
            if source.returncode != 0:
                raise source_failure(source, "the protected direct SIP source failed")
        finally:
            if source is not None:
                terminate_process(source)
                if source.stderr is not None and not source.stderr.closed:
                    source.communicate(timeout=5)
            if agent is not None:
                terminate_process(agent)
                agent.communicate(timeout=5)
    if prepared_network_observation is not None:
        return session_path, participant_path, source_path, screenshot_path

    network_path = write_network_observation(path, ledger, network_observation)

    collect(
        argparse.Namespace(
            execution_id=args.execution_id,
            session=session_path,
            participant_observation=participant_path,
            source_observation=source_path,
            screenshot=screenshot_path,
            network_observation=network_path,
            wait_seconds=args.wait_seconds,
            confirm=args.confirm,
        )
    )
    return None


def run_direct(args: argparse.Namespace) -> None:
    if args.confirm != args.execution_id:
        raise EvidenceError("run-direct requires the exact execution ID confirmation")
    path, ledger, environment = stable_deployment(args.execution_id)
    run_direct_with_deployment(args, path, ledger, environment)


def run_direct_fresh(args: argparse.Namespace) -> None:
    if args.confirm != args.execution_id:
        raise EvidenceError(
            "run-direct-fresh requires the exact execution ID confirmation"
        )
    if args.scenario not in DIRECT_SCENARIOS:
        raise EvidenceError(
            "run-direct-fresh supports only the four direct SIP scenarios"
        )
    # Keep every expensive live operation ahead of reservation creation. A
    # named-route call has a short setup deadline; both CloudFormation
    # validation and the SSM-backed network controller can otherwise spend
    # that entire window before the INVITE is sent.
    path, ledger, environment = stable_deployment(args.execution_id)
    session_id = secrets.token_hex(12)
    with controlled_network(
        path,
        ledger,
        environment,
        args.network_profile,
        session_id,
    ) as network_observation:
        session_path = create_direct_session(
            args,
            path,
            ledger,
            environment,
            session_id=session_id,
        )
        direct_args = argparse.Namespace(**vars(args), session=session_path)
        observation_paths = run_direct_with_deployment(
            direct_args,
            path,
            ledger,
            environment,
            network_observation,
        )
    if observation_paths is None:
        raise EvidenceError("fresh direct call did not return its observations")
    session_path, participant_path, source_path, screenshot_path = observation_paths
    network_path = write_network_observation(path, ledger, network_observation)
    collect(
        argparse.Namespace(
            execution_id=args.execution_id,
            session=session_path,
            participant_observation=participant_path,
            source_observation=source_path,
            screenshot=screenshot_path,
            network_observation=network_path,
            wait_seconds=args.wait_seconds,
            confirm=args.confirm,
        )
    )


def wait_for_ready_file(
    process: subprocess.Popen[str], path: Path, timeout_seconds: int
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise source_failure(
                process,
                "protected browser source stopped before its handshake",
            )
        if path.exists():
            if path.stat().st_mode & 0o077:
                raise EvidenceError("private browser handshake must be mode 0600")
            value = load_json(path)
            if isinstance(value, dict):
                return value
            raise EvidenceError("private browser handshake has the wrong shape")
        time.sleep(0.25)
    raise EvidenceError("protected browser source handshake exceeded its deadline")


def initial_vapi_identity(
    api_key: str,
    call_id: str,
    assistant_id: str,
    timeout_seconds: int = 30,
) -> str:
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            return vapi_call_identity(
                vapi_call(api_key, call_id),
                call_id,
                assistant_id,
            )
        except EvidenceError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(min(2, max(0.1, deadline - time.monotonic())))


def run_vapi(args: argparse.Namespace) -> None:
    if args.confirm != args.execution_id:
        raise EvidenceError("run-vapi requires the exact execution ID confirmation")
    path, ledger, environment = stable_deployment(args.execution_id)
    validate_connect_url(args.connect_url)
    parameters = stack_parameters(ledger, environment)
    security, codec = scenario_contract(
        "vapi-web-transfer", parameters.get("SipSecurity")
    )
    storage_state = args.storage_state.resolve()
    regular_bounded_file(storage_state, MAX_JSON_BYTES)
    if storage_state.stat().st_mode & 0o077:
        raise EvidenceError("Agent Workspace storage state must be mode 0600")
    public_key = os.environ.get("VAPI_PUBLIC_KEY", "")
    if (
        not 8 <= len(public_key) <= 256
        or re.search(r"[\s<>\"']", public_key)
    ):
        raise EvidenceError("VAPI_PUBLIC_KEY must contain the browser-safe Vapi public key")
    vapi_secret_arn = ledger.get("vapi_api_key_secret_arn")
    if not isinstance(vapi_secret_arn, str):
        raise EvidenceError("temporary Vapi verification secret is unavailable")
    private_key = LIVE.secret_value(ledger, environment, vapi_secret_arn)
    vapi_outputs = nested_outputs(ledger, environment, "VapiResources")
    assistant_id = vapi_outputs.get("AssistantId")
    if not isinstance(assistant_id, str) or re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,40}", assistant_id
    ) is None:
        raise EvidenceError("recipe-owned Vapi assistant output is invalid")
    handoff = nested_outputs(ledger, environment, "HandoffService")
    correlation_key = LIVE.secret_value(
        ledger,
        environment,
        handoff["CorrelationKeySecretArn"],
    )
    bundle, site_bundle_digest = released_artifact(
        ledger,
        "artifacts/demo-site/demo-site.zip",
        MAX_SITE_BUNDLE_BYTES,
    )

    nonce = secrets.token_hex(12)
    basename = f"vapi-web-transfer-{args.hangup_origin}-{nonce}"
    call_sessions = path.parent / "call-sessions"
    participant_dir = path.parent / "participant-observations"
    source_dir = path.parent / "source-observations"
    screenshot_dir = path.parent / "screenshots"
    for directory in (call_sessions, participant_dir, source_dir, screenshot_dir):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
    session_path = call_sessions / f"{basename}.private.json"
    ready_path = call_sessions / f"{basename}.browser-ready.private.json"
    trigger_path = call_sessions / f"{basename}.trigger.private.json"
    participant_path = participant_dir / f"{basename}.json"
    source_path = source_dir / f"{basename}.json"
    screenshot_path = screenshot_dir / f"{basename}.png"
    for output in (
        session_path,
        ready_path,
        trigger_path,
        participant_path,
        source_path,
        screenshot_path,
    ):
        if output.exists():
            raise EvidenceError("Vapi observer output already exists")

    browser: subprocess.Popen[str] | None = None
    agent: subprocess.Popen[str] | None = None
    completed = False
    with tempfile.TemporaryDirectory(
        prefix=f".{basename}-",
        dir=path.parent,
    ) as directory:
        private_directory = Path(directory)
        os.chmod(private_directory, 0o700)
        site_dir = private_directory / "site"
        extract_site_bundle(bundle, site_dir)
        browser_command = [
            "node",
            os.fspath(VAPI_HARNESS),
            "observe",
            "--site-dir",
            os.fspath(site_dir),
            "--assistant-id",
            assistant_id,
            "--session",
            os.fspath(session_path),
            "--ready",
            os.fspath(ready_path),
            "--trigger",
            os.fspath(trigger_path),
            "--observation",
            os.fspath(source_path),
            "--site-bundle-sha256",
            site_bundle_digest,
            "--hangup-origin",
            args.hangup_origin,
            "--timeout-seconds",
            str(args.observer_timeout_seconds),
        ]
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
        ]
        if args.headed:
            browser_command.append("--headed")
            agent_command.append("--headed")
        browser_environment = os.environ.copy()
        browser_environment["VAPI_PUBLIC_KEY"] = public_key
        agent_environment = os.environ.copy()
        agent_environment.pop("VAPI_PUBLIC_KEY", None)
        try:
            browser = subprocess.Popen(
                browser_command,
                cwd=ROOT,
                env=browser_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            ready = wait_for_ready_file(
                browser,
                ready_path,
                args.observer_timeout_seconds,
            )
            if set(ready) != {
                "schema_version",
                "call_id",
                "source_call_fingerprint",
                "started_at",
                "started_epoch_ms",
            }:
                raise EvidenceError("private browser handshake shape changed")
            call_id = ready.get("call_id")
            started_at = ready.get("started_at")
            started_epoch_ms = ready.get("started_epoch_ms")
            if (
                ready.get("schema_version") != 1
                or not isinstance(call_id, str)
                or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", call_id) is None
                or not isinstance(started_at, str)
                or not isinstance(started_epoch_ms, int)
                or abs(int(time.time() * 1000) - started_epoch_ms) > 120_000
                or ready.get("source_call_fingerprint")
                != hashlib.sha256(call_id.encode("ascii")).hexdigest()[:12]
            ):
                raise EvidenceError("private browser handshake identity is invalid")
            parse_timestamp(started_at)
            org_id = initial_vapi_identity(private_key, call_id, assistant_id)
            correlation_id = derive_correlation_id(
                correlation_key,
                args.execution_id,
                org_id,
                call_id,
            )
            session: dict[str, Any] = {
                "schema_version": 1,
                "execution_id": args.execution_id,
                "recipe": RECIPE,
                "release_id": ledger["release_id"],
                "source_tree_sha256": ledger["publication_source_tree_sha256"],
                "image": ledger["bridgefu_image_uri"],
                "session_id": nonce,
                "scenario_id": "vapi-web-transfer",
                "hangup_origin": args.hangup_origin,
                "security": security,
                "codec": codec,
                "network_profile": args.network_profile,
                "network_contract": dict(NETWORK_PROFILES[args.network_profile]),
                "started_at": started_at,
                "started_epoch_ms": started_epoch_ms,
                "correlation_id": correlation_id,
                "correlation_fingerprint": correlation_fingerprint(correlation_id),
                "source_call_id": call_id,
                "source_org_id": org_id,
                "source_call_fingerprint": ready["source_call_fingerprint"],
                "sip_uri": None,
                "sip_header": {"name": "X-Correlation-Id", "value": correlation_id},
                "expected_context": synthetic_context(
                    "vapi-web-transfer", args.hangup_origin
                ),
            }
            session["session_hmac"] = session_authentication(session, correlation_key)
            write_private_json(session_path, session)
            validate_private_session(session, args.execution_id, ledger, environment)
            network_observation: dict[str, Any]
            with controlled_network(
                path,
                ledger,
                environment,
                args.network_profile,
                nonce,
            ) as network_observation:
                agent = subprocess.Popen(
                    agent_command,
                    cwd=ROOT,
                    env=agent_environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                time.sleep(3)
                if agent.poll() is not None or browser.poll() is not None:
                    if agent.poll() is not None:
                        raise agent_failure(
                            agent, "a protected Vapi observer stopped before transfer"
                        )
                    raise source_failure(
                        browser, "a protected Vapi observer stopped before transfer"
                    )
                write_private_json(trigger_path, {"schema_version": 1})
                deadline = time.monotonic() + args.observer_timeout_seconds + 60
                while agent.poll() is None or browser.poll() is None:
                    if agent.poll() not in {None, 0} or browser.poll() not in {
                        None,
                        0,
                    }:
                        if agent.poll() not in {None, 0}:
                            raise agent_failure(agent, "a protected Vapi observer failed")
                        raise source_failure(browser, "a protected Vapi observer failed")
                    if time.monotonic() >= deadline:
                        raise EvidenceError(
                            "protected Vapi observers exceeded their deadline"
                        )
                    time.sleep(0.25)
                if agent.returncode != 0 or browser.returncode != 0:
                    if agent.returncode != 0:
                        raise agent_failure(agent, "a protected Vapi observer failed")
                    raise source_failure(browser, "a protected Vapi observer failed")
            network_path = write_network_observation(
                path, ledger, network_observation
            )
            collect(
                argparse.Namespace(
                    execution_id=args.execution_id,
                    session=session_path,
                    participant_observation=participant_path,
                    source_observation=source_path,
                    screenshot=screenshot_path,
                    network_observation=network_path,
                    wait_seconds=args.wait_seconds,
                    confirm=args.confirm,
                )
            )
            completed = True
        finally:
            if agent is not None:
                terminate_process(agent)
                agent.communicate(timeout=5)
            if browser is not None:
                terminate_process(browser)
                browser.communicate(timeout=5)
            ready_path.unlink(missing_ok=True)
            trigger_path.unlink(missing_ok=True)
            if not completed:
                session_path.unlink(missing_ok=True)


def contract(_args: argparse.Namespace) -> None:
    for path in (
        PARTICIPANT_SCHEMA,
        SOURCE_SCHEMA,
        VAPI_SOURCE_SCHEMA,
        CALL_SCHEMA,
        AGENT_HARNESS,
        SOURCE_HARNESS,
        VAPI_HARNESS,
    ):
        regular_bounded_file(path, MAX_JSON_BYTES)
    for schema_path in (
        PARTICIPANT_SCHEMA,
        SOURCE_SCHEMA,
        VAPI_SOURCE_SCHEMA,
        CALL_SCHEMA,
    ):
        jsonschema.Draft202012Validator.check_schema(load_json(schema_path))
    source = AGENT_HARNESS.read_text(encoding="utf-8")
    for required in (
        "bridgefu-agent-workspace-playwright@1",
        "correlation_fingerprint",
        "screenshot_sha256",
        "dtmf_source_to_agent_observed",
        "dtmf_agent_to_source_sent",
    ):
        if required not in source:
            raise EvidenceError("Agent Workspace harness is missing a required contract")
    vapi_source = VAPI_HARNESS.read_text(encoding="utf-8")
    for required in (
        "bridgefu-vapi-web-playwright@1",
        "source_call_fingerprint",
        "transfer_trigger_sent",
        "dtmf_agent_to_source_observed",
    ):
        if required not in vapi_source:
            raise EvidenceError("Vapi browser harness is missing a required contract")
    print("protected per-call evidence contracts are valid")


def bounded_wait_seconds(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("wait seconds must be an integer") from error
    if not 1 <= parsed <= 300:
        raise argparse.ArgumentTypeError("wait seconds must be between 1 and 300")
    return parsed


def bounded_observer_timeout(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("observer timeout must be an integer") from error
    if not 30 <= parsed <= 600:
        raise argparse.ArgumentTypeError("observer timeout must be between 30 and 600")
    return parsed


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    subparsers = value.add_subparsers(dest="command", required=True)
    subparsers.add_parser("contract").set_defaults(function=contract)
    start = subparsers.add_parser("start-direct")
    start.add_argument("--execution-id", required=True)
    start.add_argument("--scenario", choices=sorted(DIRECT_SCENARIOS), required=True)
    start.add_argument("--hangup-origin", choices=("source", "agent"), required=True)
    start.add_argument(
        "--network-profile", choices=sorted(NETWORK_PROFILES), default="baseline"
    )
    start.add_argument("--confirm", required=True)
    start.set_defaults(function=start_direct)
    run = subparsers.add_parser("run-direct")
    run.add_argument("--execution-id", required=True)
    run.add_argument("--session", type=Path, required=True)
    run.add_argument("--connect-url", required=True)
    run.add_argument("--storage-state", type=Path, required=True)
    run.add_argument("--observer-timeout-seconds", type=bounded_observer_timeout, default=180)
    run.add_argument("--wait-seconds", type=bounded_wait_seconds, default=120)
    run.add_argument("--headed", action="store_true")
    run.add_argument("--confirm", required=True)
    run.set_defaults(function=run_direct)
    fresh = subparsers.add_parser("run-direct-fresh")
    fresh.add_argument("--execution-id", required=True)
    fresh.add_argument("--scenario", choices=sorted(DIRECT_SCENARIOS), required=True)
    fresh.add_argument("--hangup-origin", choices=("source", "agent"), required=True)
    fresh.add_argument(
        "--network-profile", choices=sorted(NETWORK_PROFILES), default="baseline"
    )
    fresh.add_argument("--connect-url", required=True)
    fresh.add_argument("--storage-state", type=Path, required=True)
    fresh.add_argument(
        "--observer-timeout-seconds", type=bounded_observer_timeout, default=180
    )
    fresh.add_argument("--wait-seconds", type=bounded_wait_seconds, default=120)
    fresh.add_argument("--headed", action="store_true")
    fresh.add_argument("--confirm", required=True)
    fresh.set_defaults(function=run_direct_fresh)
    vapi = subparsers.add_parser("run-vapi")
    vapi.add_argument("--execution-id", required=True)
    vapi.add_argument("--hangup-origin", choices=("source", "agent"), required=True)
    vapi.add_argument(
        "--network-profile", choices=sorted(NETWORK_PROFILES), default="baseline"
    )
    vapi.add_argument("--connect-url", required=True)
    vapi.add_argument("--storage-state", type=Path, required=True)
    vapi.add_argument(
        "--observer-timeout-seconds",
        type=bounded_observer_timeout,
        default=240,
    )
    vapi.add_argument("--wait-seconds", type=bounded_wait_seconds, default=120)
    vapi.add_argument("--headed", action="store_true")
    vapi.add_argument("--confirm", required=True)
    vapi.set_defaults(function=run_vapi)
    finish = subparsers.add_parser("collect")
    finish.add_argument("--execution-id", required=True)
    finish.add_argument("--session", type=Path, required=True)
    finish.add_argument("--participant-observation", type=Path, required=True)
    finish.add_argument("--source-observation", type=Path, required=True)
    finish.add_argument("--screenshot", type=Path, required=True)
    finish.add_argument("--network-observation", type=Path, required=True)
    finish.add_argument("--wait-seconds", type=bounded_wait_seconds, default=120)
    finish.add_argument("--confirm", required=True)
    finish.set_defaults(function=collect)
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        with LIVE.execution_lock(args.execution_id):
            args.function(args)
    except (EvidenceError, LIVE.LiveTestError, jsonschema.ValidationError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
