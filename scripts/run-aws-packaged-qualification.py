#!/usr/bin/env python3
"""Execute protected Bridgefu call scenarios inside the ephemeral AWS runner."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / "scripts" / "collect-recipe-call-evidence.py"
QUALIFICATION = ROOT / "scripts" / "run-recipe-qualification.py"
AGENT = (
    ROOT
    / "recipes"
    / "vapi-amazon-connect-screen-pop"
    / "qualification"
    / "agent-workspace-playwright.mjs"
)
LIVE_SCRIPT = ROOT / "scripts" / "aws-recipe-live-test.py"
LIVE_SPEC = importlib.util.spec_from_file_location(
    "bridgefu_packaged_qualification_live", LIVE_SCRIPT
)
if LIVE_SPEC is None or LIVE_SPEC.loader is None:  # pragma: no cover - import guard
    raise RuntimeError("unable to load guarded AWS lifecycle controller")
LIVE = importlib.util.module_from_spec(LIVE_SPEC)
sys.modules[LIVE_SPEC.name] = LIVE
LIVE_SPEC.loader.exec_module(LIVE)
SCENARIOS = {
    "sip-rtp-pcmu",
    "sip-rtp-pcma",
    "sips-srtp-pcmu",
    "sips-srtp-pcma",
    "vapi-web-transfer",
}
DIRECT_SCENARIOS = SCENARIOS - {"vapi-web-transfer"}
NETWORK_PROFILES = ("baseline", "moderate-wan")
HANGUP_ORIGINS = ("source", "agent")
FAILURE_DRILLS = ("process_restart", "dependency_timeout", "host_recovery")
HTTP_NEGATIVES = (
    "prepare_auth_rejected",
    "prepare_conflicting_replay_rejected",
    "malformed_payload_rejected",
)
SIP_NEGATIVES = (
    "missing_correlation_header_rejected",
    "duplicate_correlation_header_rejected",
    "expired_attachment_rejected",
    "source_cancellation_cleanup",
)
MAX_ARCHIVE_FILES = 512
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_COMPRESSED_ARCHIVE_BYTES = 65 * 1024 * 1024
FULL_CALL_INTERVAL_SECONDS = 300
FULL_SOAK_FINISH_SECONDS = 3_605
SAFE_EVIDENCE_DIRECTORIES = {
    "call-evidence": {".json"},
    "failure-evidence": {".json"},
    "negative-evidence": {".json"},
    "network-observations": {".json"},
    "participant-observations": {".json"},
    "screenshots": {".png"},
    "source-observations": {".json"},
}
SAFE_EVIDENCE_FILES = {
    "soak-evidence.json",
    "zero-state-pre-lifecycle-evidence.json",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PINNED_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
DEBIAN_SNAPSHOT = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
RUST_TOOLCHAIN = re.compile(r"^[1-9][0-9]*\.[0-9]+\.[0-9]+$")
GNU_TARGET = re.compile(r"^x86_64-unknown-linux-gnu\.([0-9]+)\.([0-9]+)$")
GLIBC_VERSION = re.compile(rb"GLIBC_([0-9]+)\.([0-9]+)")
QUALIFICATION_PLATFORM = "linux/amd64"
QUALIFICATION_TARGET = "x86_64-unknown-linux-gnu.2.31"
QUALIFICATION_RUST_TOOLCHAIN = "1.95.0"
QUALIFICATION_DEBIAN_SNAPSHOT = "20260202T000000Z"
MAXIMUM_GLIBC = (2, 31)
LIVE_STATE_OVERRIDE_ENV = "BRIDGEFU_AWS_LIVE_STATE_DIR"


class RunnerError(RuntimeError):
    pass


def ensure_connect_agent_available(
    ledger: dict[str, Any], username: str
) -> None:
    """Select the one disposable agent's routable status through Connect's API."""

    instance_arn = ledger.get("connect_instance_arn")
    expected_arn = re.compile(
        rf"^arn:{re.escape(str(ledger.get('partition', '')))}:connect:"
        rf"{re.escape(str(ledger.get('region', '')))}:"
        rf"{re.escape(str(ledger.get('account_id', '')))}:instance/"
        r"([A-Za-z0-9-]+)$"
    )
    match = expected_arn.fullmatch(instance_arn or "")
    if (
        ledger.get("connect_mode") != "disposable"
        or match is None
        or username != "bridgefu-demo-agent"
    ):
        raise RunnerError("Connect availability target is not the exact disposable agent")
    instance_id = match.group(1)
    environment = LIVE.assume_env(ledger, "qualification")
    users = LIVE.aws_json(
        [
            "connect",
            "list-users",
            "--region",
            ledger["region"],
            "--instance-id",
            instance_id,
        ],
        env=environment,
    )
    statuses = LIVE.aws_json(
        [
            "connect",
            "list-agent-statuses",
            "--region",
            ledger["region"],
            "--instance-id",
            instance_id,
        ],
        env=environment,
    )
    if not isinstance(users, dict) or not isinstance(statuses, dict):
        raise RunnerError("Connect availability lookup did not return objects")
    user_summaries = users.get("UserSummaryList")
    status_summaries = statuses.get("AgentStatusSummaryList")
    if not isinstance(user_summaries, list) or not isinstance(
        status_summaries, list
    ):
        raise RunnerError("Connect availability lookup did not return lists")
    user_matches = [
        item
        for item in user_summaries
        if isinstance(item, dict)
        and item.get("Username") == username
        and item.get("Arn", "").startswith(f"{instance_arn}/agent/")
        and re.fullmatch(r"[A-Za-z0-9-]{1,100}", item.get("Id", ""))
    ]
    status_matches = [
        item
        for item in status_summaries
        if isinstance(item, dict)
        and item.get("Name") == "Available"
        and item.get("Type") == "ROUTABLE"
        and item.get("Arn", "").startswith(f"{instance_arn}/agent-state/")
        and re.fullmatch(r"[A-Za-z0-9-]{1,100}", item.get("Id", ""))
    ]
    if len(user_matches) != 1 or len(status_matches) != 1:
        raise RunnerError("Connect availability lookup was not exact")
    result = subprocess.run(
        [
            "aws",
            "connect",
            "put-user-status",
            "--region",
            ledger["region"],
            "--instance-id",
            instance_id,
            "--user-id",
            user_matches[0]["Id"],
            "--agent-status-id",
            status_matches[0]["Id"],
            "--output",
            "json",
            "--no-cli-pager",
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    already_available = (
        result.returncode != 0
        and "InvalidRequestException" in result.stderr
        and "User already in requested status" in result.stderr
    )
    if result.returncode != 0 and not already_available:
        raise RunnerError("Connect could not set the generated agent Available")


def create_packaged_state_root() -> tuple[Path, Path]:
    """Create an isolated durable-state-shaped root for this ephemeral build."""

    container = Path(tempfile.mkdtemp(prefix="bridgefu-packaged-state-")).resolve()
    state_root = container / "bridgefu" / "aws-live"
    state_root.mkdir(parents=True, mode=0o700)
    for directory in (container, state_root.parent, state_root):
        os.chmod(directory, 0o700)
    if "target" in state_root.parts or state_root.is_relative_to(ROOT.resolve()):
        shutil.rmtree(container)
        raise RunnerError("packaged state root is not isolated from build outputs")
    return container, state_root


def command(arguments: list[str], *, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        arguments, cwd=ROOT, env=env, check=False, capture_output=True, text=True
    )
    if result.returncode != 0:
        safe = (result.stderr or result.stdout or "runner command failed").strip()
        raise RunnerError(safe[-2_000:])
    return (result.stdout or "").strip()


def private_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pinned_image_argument(dockerfile: Path, name: str) -> str:
    prefix = f"ARG {name}="
    matches = [
        line.removeprefix(prefix)
        for line in dockerfile.read_text(encoding="utf-8").splitlines()
        if line.startswith(prefix)
    ]
    if len(matches) != 1 or PINNED_IMAGE.fullmatch(matches[0]) is None:
        raise RunnerError(f"packaged qualification Dockerfile has no unique {name}")
    return matches[0]


def unique_argument(
    dockerfile: Path, name: str, pattern: re.Pattern[str], label: str
) -> str:
    prefix = f"ARG {name}="
    matches = [
        line.removeprefix(prefix)
        for line in dockerfile.read_text(encoding="utf-8").splitlines()
        if line.startswith(prefix)
    ]
    if len(matches) != 1 or pattern.fullmatch(matches[0]) is None:
        raise RunnerError(
            f"packaged qualification Dockerfile has no unique pinned {label}"
        )
    return matches[0]


def qualification_builder_images() -> dict[str, str]:
    dockerfile = ROOT / "deploy" / "Dockerfile.qualification"
    if (
        dockerfile.is_symlink()
        or not dockerfile.is_file()
        or not 0 < dockerfile.stat().st_size <= 64 * 1024
    ):
        raise RunnerError("packaged qualification Dockerfile is invalid")
    parent = pinned_image_argument(dockerfile, "QUALIFICATION_BUILDER_IMAGE")
    amd64 = pinned_image_argument(dockerfile, "QUALIFICATION_BUILDER_AMD64_IMAGE")
    arm64 = pinned_image_argument(dockerfile, "QUALIFICATION_BUILDER_ARM64_IMAGE")
    values = (parent, amd64, arm64)
    stems = {value.rsplit("@sha256:", 1)[0] for value in values}
    digests = {value.rsplit("@sha256:", 1)[1] for value in values}
    if len(stems) != 1 or len(digests) != len(values):
        raise RunnerError("packaged qualification builder bindings are invalid")
    return {
        "multi_platform_index": parent,
        "linux/amd64": amd64,
        "linux/arm64": arm64,
    }


def qualification_builder_configuration() -> dict[str, str]:
    dockerfile = ROOT / "deploy" / "Dockerfile.qualification"
    snapshot = unique_argument(
        dockerfile,
        "QUALIFICATION_DEBIAN_SNAPSHOT",
        DEBIAN_SNAPSHOT,
        "qualification Debian snapshot",
    )
    toolchain = unique_argument(
        dockerfile,
        "QUALIFICATION_RUST_TOOLCHAIN",
        RUST_TOOLCHAIN,
        "qualification Rust toolchain",
    )
    target = unique_argument(
        dockerfile,
        "QUALIFICATION_TARGET",
        GNU_TARGET,
        "qualification target",
    )
    target_match = GNU_TARGET.fullmatch(target)
    if target_match is None:
        raise RunnerError("packaged qualification target is invalid")
    maximum_glibc = (int(target_match.group(1)), int(target_match.group(2)))
    if (
        snapshot != QUALIFICATION_DEBIAN_SNAPSHOT
        or toolchain != QUALIFICATION_RUST_TOOLCHAIN
        or target != QUALIFICATION_TARGET
        or maximum_glibc != MAXIMUM_GLIBC
    ):
        raise RunnerError("packaged qualification builder configuration changed")
    return {
        "debian_snapshot": snapshot,
        "rust_toolchain": toolchain,
        "target": target,
        "maximum_glibc": f"{maximum_glibc[0]}.{maximum_glibc[1]}",
    }


def qualification_binary_glibc(binary: Path) -> str:
    data = binary.read_bytes()
    header = data[:20]
    if (
        len(header) != 20
        or header[:6] != b"\x7fELF\x02\x01"
        or header[18:20] != b"\x3e\x00"
    ):
        raise RunnerError("packaged qualification binary has the wrong platform")
    versions = {
        (int(match.group(1)), int(match.group(2)))
        for match in GLIBC_VERSION.finditer(data)
    }
    if not versions or max(versions) > MAXIMUM_GLIBC:
        raise RunnerError("packaged qualification binary has incompatible glibc")
    maximum = max(versions)
    return f"{maximum[0]}.{maximum[1]}"


def validate_qualification_builder(builder: object) -> dict[str, str]:
    expected_images = qualification_builder_images()
    expected_configuration = qualification_builder_configuration()
    host = builder.get("host_platform") if isinstance(builder, dict) else None
    glibc = builder.get("binary_glibc") if isinstance(builder, dict) else None
    if (
        not isinstance(builder, dict)
        or set(builder)
        != {
            "binary_glibc",
            "debian_snapshot",
            "host_platform",
            "image",
            "images",
            "maximum_glibc",
            "rust_toolchain",
            "target",
        }
        or host not in {"linux/amd64", "linux/arm64"}
        or builder.get("images") != expected_images
        or builder.get("image") != expected_images.get(host)
        or any(
            builder.get(key) != value for key, value in expected_configuration.items()
        )
        or not isinstance(glibc, dict)
        or set(glibc) != {"recipe_sip_source", "recipe_sip_negative"}
        or any(not isinstance(value, str) for value in glibc.values())
    ):
        raise RunnerError("published qualification builder contract is invalid")
    return glibc


def canonical_json_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, separators=(",", ":"), sort_keys=True, ensure_ascii=True
        ).encode("ascii")
    ).hexdigest()


def load_input(path: Path) -> dict[str, Any]:
    details = path.lstat()
    if (
        not stat.S_ISREG(details.st_mode)
        or path.is_symlink()
        or details.st_mode & 0o077
        or details.st_size > 2_000_000
    ):
        raise RunnerError("runner input must be a bounded regular file")
    value = json.loads(path.read_text(encoding="utf-8"))
    required = {
        "schema_version",
        "execution_id",
        "suite",
        "scenarios",
        "connect_url",
        "agent_credential_secret_arn",
        "vapi_public_key_secret_arn",
        "ledger",
        "recovery_authority",
        "evidence_bucket",
        "evidence_key",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise RunnerError("runner input shape changed")
    if value.get("schema_version") != 1 or value.get("suite") not in {"smoke", "full"}:
        raise RunnerError("runner input version or suite is invalid")
    scenarios = value.get("scenarios")
    if (
        not isinstance(scenarios, list)
        or not scenarios
        or len(scenarios) > 20
        or len(scenarios) != len(set(scenarios))
        or any(scenario not in SCENARIOS for scenario in scenarios)
    ):
        raise RunnerError("runner scenario set is invalid")
    if value["suite"] == "full" and (
        len(scenarios) != 3
        or sum(scenario in DIRECT_SCENARIOS for scenario in scenarios) != 2
        or scenarios.count("vapi-web-transfer") != 1
    ):
        raise RunnerError(
            "full runner input must contain the deployed three-scenario matrix"
        )
    ledger = value.get("ledger")
    if not isinstance(ledger, dict) or ledger.get("execution_id") != value.get(
        "execution_id"
    ):
        raise RunnerError("runner ledger identity mismatch")
    recovery_authority = value.get("recovery_authority")
    if (
        not isinstance(recovery_authority, dict)
        or recovery_authority.get("execution_id") != value.get("execution_id")
        or recovery_authority.get("schema_version") != 1
        or canonical_json_sha256(recovery_authority)
        != ledger.get("recovery_authority_sha256")
    ):
        raise RunnerError("runner recovery authority identity mismatch")
    execution_id = value.get("execution_id")
    if (
        not isinstance(execution_id, str)
        or re.fullmatch(r"bft-[a-z0-9-]{4,20}", execution_id) is None
        or value.get("connect_url") != ledger.get("connect_login_url")
        or value.get("agent_credential_secret_arn")
        != ledger.get("agent_credential_secret_arn")
        or value.get("vapi_public_key_secret_arn")
        != ledger.get("vapi_public_key_secret_arn")
        or value.get("evidence_bucket") != ledger.get("artifact_bucket")
        or not isinstance(value.get("evidence_key"), str)
        or re.fullmatch(
            rf"qualification/{re.escape(execution_id)}/runs/"
            r"(?:smoke|full)-[0-9]{9,12}/evidence\.tar\.gz",
            value["evidence_key"],
        )
        is None
    ):
        raise RunnerError("runner input is not bound to its execution resources")
    secure = ledger.get("sip_security") == "sips_srtp"
    expected_scenarios = (
        (
            ["sips-srtp-pcmu", "sips-srtp-pcma"]
            if secure
            else ["sip-rtp-pcmu", "sip-rtp-pcma"]
        )
        + ["vapi-web-transfer"]
        if value["suite"] == "full"
        else (["sips-srtp-pcmu"] if secure else ["sip-rtp-pcmu"])
        + ["vapi-web-transfer"]
    )
    if scenarios != expected_scenarios:
        raise RunnerError("runner scenarios do not match the deployed SIP posture")
    if (
        value["suite"] == "full"
        and ledger.get("runtime_profile", "starter") != "starter"
    ):
        raise RunnerError(
            "full packaged qualification supports the Starter profile only"
        )
    return value


def secret_json(arn: str, region: str) -> dict[str, str]:
    raw = command(
        [
            "aws",
            "secretsmanager",
            "get-secret-value",
            "--region",
            region,
            "--secret-id",
            arn,
            "--query",
            "SecretString",
            "--output",
            "text",
            "--no-cli-pager",
        ]
    )
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RunnerError("runner secret has an invalid shape")
    return {str(key): str(item) for key, item in value.items()}


def published_object(ledger: Mapping[str, Any], relative: str) -> dict[str, Any]:
    published = ledger.get("published_objects")
    value = published.get(relative) if isinstance(published, dict) else None
    if (
        not isinstance(value, dict)
        or set(value) != {"key", "version_id", "sha256", "size_bytes"}
        or not isinstance(value.get("key"), str)
        or not value["key"].endswith(f"/{relative}")
        or not isinstance(value.get("version_id"), str)
        or not value["version_id"]
        or not isinstance(value.get("sha256"), str)
        or SHA256.fullmatch(value["sha256"]) is None
        or not isinstance(value.get("size_bytes"), int)
        or isinstance(value.get("size_bytes"), bool)
        or not 0 < value["size_bytes"] <= MAX_ARCHIVE_BYTES
    ):
        raise RunnerError("published release object binding is incomplete")
    return value


def download_published_object(
    ledger: Mapping[str, Any], region: str, relative: str, destination: Path
) -> dict[str, Any]:
    record = published_object(ledger, relative)
    if destination.exists() or destination.is_symlink():
        raise RunnerError("runner release artifact destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(destination.parent, 0o700)
    command(
        [
            "aws",
            "s3api",
            "get-object",
            "--region",
            region,
            "--bucket",
            str(ledger["artifact_bucket"]),
            "--key",
            record["key"],
            "--version-id",
            record["version_id"],
            os.fspath(destination),
            "--no-cli-pager",
        ]
    )
    details = destination.lstat()
    if (
        destination.is_symlink()
        or not stat.S_ISREG(details.st_mode)
        or details.st_size != record["size_bytes"]
        or sha256_file(destination) != record["sha256"]
    ):
        raise RunnerError(
            "downloaded release artifact differs from its immutable object"
        )
    os.chmod(destination, 0o600)
    return record


def materialize_release_artifacts(
    ledger: Mapping[str, Any], region: str, evidence_dir: Path
) -> None:
    release = evidence_dir / "release"
    manifest_record = download_published_object(
        ledger, region, "manifest.json", release / "manifest.json"
    )
    materialized_paths = (
        "artifacts/demo-site/demo-site.zip",
        "artifacts/runtime/starter-runtime.zip",
        "artifacts/runtime/manifest.json",
        "artifacts/qualification/manifest.json",
    )
    records = {
        relative: download_published_object(
            ledger, region, relative, release.joinpath(*PurePosixPath(relative).parts)
        )
        for relative in materialized_paths
    }
    qualification_archive = published_object(
        ledger, "artifacts/qualification/qualification-source.zip"
    )
    try:
        manifest = json.loads((release / "manifest.json").read_text(encoding="utf-8"))
        runtime_manifest = json.loads(
            (release / "artifacts/runtime/manifest.json").read_text(encoding="utf-8")
        )
        qualification_manifest = json.loads(
            (release / "artifacts/qualification/manifest.json").read_text(
                encoding="utf-8"
            )
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RunnerError("immutable release manifest is invalid") from error
    artifacts = manifest.get("artifacts") if isinstance(manifest, dict) else None
    by_path = {
        item.get("path"): item
        for item in artifacts or []
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    bridgefu = manifest.get("bridgefu") if isinstance(manifest, dict) else None
    if (
        manifest_record["sha256"] != ledger.get("release_manifest_sha256")
        or not isinstance(bridgefu, dict)
        or bridgefu.get("source_tree_sha256")
        != ledger.get("publication_source_tree_sha256")
        or bridgefu.get("image_uri") != ledger.get("bridgefu_image_uri")
        or any(
            by_path.get(relative, {}).get("sha256") != record["sha256"]
            or by_path.get(relative, {}).get("size_bytes") != record["size_bytes"]
            for relative, record in {
                **records,
                "artifacts/qualification/qualification-source.zip": qualification_archive,
            }.items()
        )
    ):
        raise RunnerError(
            "immutable release manifest does not bind the packaged candidate"
        )
    runtime_artifact = (
        runtime_manifest.get("artifact") if isinstance(runtime_manifest, dict) else None
    )
    runtime_record = records["artifacts/runtime/starter-runtime.zip"]
    if (
        not isinstance(runtime_manifest, dict)
        or not isinstance(runtime_artifact, dict)
        or runtime_manifest.get("schema_version") != 1
        or runtime_manifest.get("recipe") != "vapi-amazon-connect-screen-pop"
        or runtime_artifact.get("path") != "starter-runtime.zip"
        or runtime_artifact.get("sha256") != runtime_record["sha256"]
        or runtime_artifact.get("size_bytes") != runtime_record["size_bytes"]
    ):
        raise RunnerError("published runtime archive is not manifest-bound")
    expected_binary_paths = [
        "target/release/examples/recipe_sip_source",
        "target/release/examples/recipe_sip_negative",
    ]
    qualification_files = (
        qualification_manifest.get("files")
        if isinstance(qualification_manifest, dict)
        else None
    )
    qualification_by_path = {
        item.get("path"): item
        for item in qualification_files or []
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    archive_binding = (
        qualification_manifest.get("archive")
        if isinstance(qualification_manifest, dict)
        else None
    )
    builder = (
        qualification_manifest.get("builder")
        if isinstance(qualification_manifest, dict)
        else None
    )
    builder_glibc = validate_qualification_builder(builder)
    if (
        not isinstance(qualification_manifest, dict)
        or qualification_manifest.get("schema_version") != 2
        or qualification_manifest.get("source_tree_sha256")
        != ledger.get("publication_source_tree_sha256")
        or qualification_manifest.get("binary_platform") != QUALIFICATION_PLATFORM
        or qualification_manifest.get("qualification_binaries") != expected_binary_paths
        or not isinstance(archive_binding, dict)
        or archive_binding.get("path") != "qualification-source.zip"
        or archive_binding.get("sha256") != qualification_archive["sha256"]
        or archive_binding.get("size_bytes") != qualification_archive["size_bytes"]
    ):
        raise RunnerError("published qualification archive is not manifest-bound")
    for relative in expected_binary_paths:
        binary = ROOT.joinpath(*PurePosixPath(relative).parts)
        entry = qualification_by_path.get(relative)
        if (
            not isinstance(entry, dict)
            or binary.is_symlink()
            or not binary.is_file()
            or not os.access(binary, os.X_OK)
            or entry.get("size_bytes") != binary.stat().st_size
            or entry.get("sha256") != sha256_file(binary)
            or builder_glibc.get(binary.name) != qualification_binary_glibc(binary)
        ):
            raise RunnerError("packaged qualification binary is not manifest-bound")


def qualification_jobs(
    suite: str, scenarios: Iterable[str]
) -> list[tuple[str, str, str]]:
    scenario_list = list(scenarios)
    profiles = ("baseline",) if suite == "smoke" else NETWORK_PROFILES
    return [
        (scenario, profile, origin)
        for scenario in scenario_list
        for profile in profiles
        for origin in HANGUP_ORIGINS
    ]


def output_path(output: str, parent: Path, label: str) -> Path:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        raise RunnerError(f"{label} did not return an evidence path")
    path = Path(lines[-1]).resolve()
    if path.parent != parent.resolve() or not path.is_file() or path.is_symlink():
        raise RunnerError(f"{label} returned an unexpected evidence path")
    return path


def run_call(
    execution_id: str,
    scenario: str,
    network_profile: str,
    origin: str,
    connect_url: str,
    storage_state: Path,
    environment: dict[str, str],
    evidence_dir: Path,
) -> Path:
    if scenario == "vapi-web-transfer":
        output = command(
            [
                "python3",
                os.fspath(COLLECTOR),
                "run-vapi",
                "--execution-id",
                execution_id,
                "--hangup-origin",
                origin,
                "--network-profile",
                network_profile,
                "--connect-url",
                connect_url,
                "--storage-state",
                os.fspath(storage_state),
                "--confirm",
                execution_id,
            ],
            env=environment,
        )
    else:
        output = command(
            [
                "python3",
                os.fspath(COLLECTOR),
                "run-direct-fresh",
                "--execution-id",
                execution_id,
                "--scenario",
                scenario,
                "--hangup-origin",
                origin,
                "--network-profile",
                network_profile,
                "--connect-url",
                connect_url,
                "--storage-state",
                os.fspath(storage_state),
                "--confirm",
                execution_id,
            ],
            env=environment,
        )
    return output_path(output, evidence_dir / "call-evidence", "retained call")


def run_controller(
    execution_id: str,
    arguments: list[str],
    environment: dict[str, str],
) -> str:
    return command(
        [
            "python3",
            os.fspath(QUALIFICATION),
            *arguments,
            "--execution-id",
            execution_id,
            "--confirm",
            execution_id,
        ],
        env=environment,
    )


def finish_failure_drills(
    execution_id: str,
    call_path: Path,
    environment: dict[str, str],
) -> None:
    for identifier in FAILURE_DRILLS:
        run_controller(
            execution_id,
            [
                "failure-finish",
                "--id",
                identifier,
                "--post-recovery-call",
                os.fspath(call_path),
            ],
            environment,
        )


def run_negative(
    index: int,
    execution_id: str,
    direct_scenario: str,
    first_call: Path,
    connect_url: str,
    storage_state: Path,
    environment: dict[str, str],
    evidence_dir: Path,
) -> None:
    if index == 0:
        run_controller(
            execution_id,
            [
                "negative-from-call",
                "--id",
                "attachment_replay_rejected",
                "--call-evidence",
                os.fspath(first_call),
            ],
            environment,
        )
        return
    if 1 <= index <= len(HTTP_NEGATIVES):
        run_controller(
            execution_id,
            ["negative-http", "--id", HTTP_NEGATIVES[index - 1]],
            environment,
        )
        return
    sip_index = index - 1 - len(HTTP_NEGATIVES)
    if 0 <= sip_index < len(SIP_NEGATIVES):
        session = start_direct_session(
            execution_id,
            direct_scenario,
            "source",
            "baseline",
            environment,
            evidence_dir,
        )
        run_controller(
            execution_id,
            [
                "negative-sip",
                "--id",
                SIP_NEGATIVES[sip_index],
                "--session",
                os.fspath(session),
            ],
            environment,
        )
        return
    if index == 1 + len(HTTP_NEGATIVES) + len(SIP_NEGATIVES):
        session = start_direct_session(
            execution_id,
            direct_scenario,
            "source",
            "baseline",
            environment,
            evidence_dir,
        )
        run_controller(
            execution_id,
            [
                "negative-missing-context",
                "--session",
                os.fspath(session),
                "--connect-url",
                connect_url,
                "--storage-state",
                os.fspath(storage_state),
            ],
            environment,
        )
        return
    raise RunnerError("full qualification negative schedule changed unexpectedly")


def wait_until(started: float, offset_seconds: int) -> None:
    while True:
        remaining = started + offset_seconds - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(30, remaining))


def run_full_suite(
    execution_id: str,
    scenarios: list[str],
    connect_url: str,
    storage_state: Path,
    environment: dict[str, str],
    evidence_dir: Path,
) -> list[tuple[str, str, str]]:
    direct_scenarios = [
        scenario for scenario in scenarios if scenario in DIRECT_SCENARIOS
    ]
    if len(direct_scenarios) != 2:
        raise RunnerError("full qualification has no exact direct SIP scenario pair")
    for identifier in FAILURE_DRILLS:
        run_controller(
            execution_id,
            ["failure-start", "--id", identifier],
            environment,
        )
    run_controller(execution_id, ["soak-start"], environment)
    soak_started = time.monotonic()
    jobs = qualification_jobs("full", scenarios)
    first_call: Path | None = None
    for index, (scenario, network_profile, origin) in enumerate(jobs):
        wait_until(soak_started, index * FULL_CALL_INTERVAL_SECONDS)
        call_path = run_call(
            execution_id,
            scenario,
            network_profile,
            origin,
            connect_url,
            storage_state,
            environment,
            evidence_dir,
        )
        if first_call is None:
            if scenario not in DIRECT_SCENARIOS:
                raise RunnerError(
                    "first retained recovery call must be a direct SIP call"
                )
            first_call = call_path
            finish_failure_drills(execution_id, call_path, environment)
        if index < 9:
            run_negative(
                index,
                execution_id,
                direct_scenarios[0],
                first_call,
                connect_url,
                storage_state,
                environment,
                evidence_dir,
            )
    wait_until(soak_started, FULL_SOAK_FINISH_SECONDS)
    if time.monotonic() - soak_started > 3_885:
        raise RunnerError(
            "full qualification work exceeded the bounded soak finish window"
        )
    run_controller(execution_id, ["soak-finish"], environment)
    run_controller(
        execution_id,
        ["zero-state", "--phase", "pre_lifecycle"],
        environment,
    )
    return jobs


def safe_relative_evidence(path: Path, directory: Path) -> str | None:
    relative = PurePosixPath(path.relative_to(directory).as_posix())
    if relative.is_absolute() or any(
        part in {"", ".", ".."} for part in relative.parts
    ):
        raise RunnerError("runner evidence path is unsafe")
    if relative.name.endswith(".private.json"):
        return None
    if len(relative.parts) == 1:
        return relative.as_posix() if relative.name in SAFE_EVIDENCE_FILES else None
    allowed_extensions = SAFE_EVIDENCE_DIRECTORIES.get(relative.parts[0])
    if len(relative.parts) != 2 or allowed_extensions is None:
        return None
    if relative.suffix not in allowed_extensions:
        raise RunnerError("runner evidence file extension is unsafe")
    return relative.as_posix()


def official_evidence_inventory(directory: Path) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    total = 0
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise RunnerError("runner evidence tree contains a symlink")
        if not path.is_file():
            continue
        relative = safe_relative_evidence(path, directory)
        if relative is None:
            continue
        details = path.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_size <= 0:
            raise RunnerError("runner evidence must contain bounded regular files")
        total += details.st_size
        inventory.append(
            {
                "path": relative,
                "sha256": sha256_file(path),
                "size_bytes": details.st_size,
            }
        )
        if len(inventory) > MAX_ARCHIVE_FILES or total > MAX_ARCHIVE_BYTES:
            raise RunnerError("runner evidence exceeds its archive boundary")
    if not inventory:
        raise RunnerError("runner produced no official evidence")
    return inventory


def archive_evidence(
    directory: Path, output: Path, inventory: Iterable[Mapping[str, Any]]
) -> str:
    paths = [str(item["path"]) for item in inventory] + ["runner-summary.json"]
    with tarfile.open(output, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        for relative in sorted(paths):
            path = directory / relative
            if not path.is_file() or path.is_symlink():
                raise RunnerError("official evidence changed before archival")
            archive.add(path, arcname=relative, recursive=False)
    os.chmod(output, 0o600)
    if output.stat().st_size > MAX_COMPRESSED_ARCHIVE_BYTES:
        raise RunnerError("compressed official evidence exceeds its archive boundary")
    return sha256_file(output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    value = load_input(args.input)
    ledger = value["ledger"]
    execution_id = value["execution_id"]
    region = ledger["region"]
    build_id = os.environ.get("CODEBUILD_BUILD_ID", "")
    project_name = ledger.get("qualification_project_name")
    if (
        not isinstance(project_name, str)
        or re.fullmatch(
            rf"{re.escape(project_name)}:"
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            build_id,
        )
        is None
    ):
        raise RunnerError("CodeBuild identity is not bound to the runner project")
    state_container, state_root = create_packaged_state_root()
    environment = os.environ.copy()
    environment[LIVE_STATE_OVERRIDE_ENV] = os.fspath(state_root)
    environment["BRIDGEFU_PACKAGED_SOURCE"] = "1"
    try:
        evidence_dir = state_root / execution_id
        evidence_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(evidence_dir, 0o700)
        private_json(evidence_dir / "ledger.json", ledger)
        private_json(
            evidence_dir / "recovery-authority.json", value["recovery_authority"]
        )
        marker = (ROOT / ".bridgefu-source-tree-sha256").read_text().strip()
        if SHA256.fullmatch(marker) is None or marker != ledger.get(
            "publication_source_tree_sha256"
        ):
            raise RunnerError(
                "packaged source digest differs from the deployed candidate"
            )
        materialize_release_artifacts(ledger, region, evidence_dir)

        credential = secret_json(value["agent_credential_secret_arn"], region)
        credential_path = evidence_dir / "agent-credential.private.json"
        storage_state = evidence_dir / "agent-workspace.private.json"
        private_json(credential_path, credential)
        public_secret = value.get("vapi_public_key_secret_arn")
        if public_secret:
            public_value = secret_json(public_secret, region)
            public_key = public_value.get("public_key", "")
            if not public_key:
                raise RunnerError("Vapi public-key secret is incomplete")
            environment["VAPI_PUBLIC_KEY"] = public_key
        command(
            [
                "node",
                os.fspath(AGENT),
                "auth",
                "--connect-url",
                value["connect_url"],
                "--storage-state",
                os.fspath(storage_state),
                "--credential-file",
                os.fspath(credential_path),
                "--timeout-seconds",
                "300",
            ],
            env=environment,
        )
        ensure_connect_agent_available(ledger, credential["username"])
        if value["suite"] == "full":
            jobs = run_full_suite(
                execution_id,
                value["scenarios"],
                value["connect_url"],
                storage_state,
                environment,
                evidence_dir,
            )
        else:
            jobs = qualification_jobs("smoke", value["scenarios"])
            for scenario, network_profile, origin in jobs:
                run_call(
                    execution_id,
                    scenario,
                    network_profile,
                    origin,
                    value["connect_url"],
                    storage_state,
                    environment,
                    evidence_dir,
                )
        inventory = official_evidence_inventory(evidence_dir)
        private_json(
            evidence_dir / "runner-summary.json",
            {
                "schema_version": 1,
                "execution_id": execution_id,
                "suite": value["suite"],
                "scenarios": value["scenarios"],
                "matrix": [
                    {
                        "scenario": scenario,
                        "network_profile": network_profile,
                        "hangup_origin": origin,
                    }
                    for scenario, network_profile, origin in jobs
                ],
                "qualification_stage": (
                    "pre_lifecycle" if value["suite"] == "full" else "smoke"
                ),
                "passed": True,
                "source_tree_sha256": marker,
                "official_evidence": inventory,
            },
        )
        archive = ROOT / f"{execution_id}-evidence.tar.gz"
        digest = archive_evidence(evidence_dir, archive, inventory)
        command(
            [
                "aws",
                "s3api",
                "put-object",
                "--region",
                region,
                "--bucket",
                value["evidence_bucket"],
                "--key",
                value["evidence_key"],
                "--body",
                os.fspath(archive),
                "--server-side-encryption",
                "AES256",
                "--metadata",
                (
                    f"sha256={digest},execution-id={execution_id},"
                    f"build-id={build_id}"
                ),
                "--no-cli-pager",
            ]
        )
        print(json.dumps({"evidence_key": value["evidence_key"], "sha256": digest}))
    finally:
        shutil.rmtree(state_container)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, RunnerError) as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
