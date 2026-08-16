#!/usr/bin/env python3
"""Run the credential-free Bridgefu role and media-runtime smoke.

This runner intentionally exercises loopback and in-process role lifecycles.
It does not contact AWS, GCP, Amazon Connect, Telnyx, or a public registry, and
it does not claim the credentialed deployment smoke required to close Gate 10.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
import tomllib


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TIMEOUT_SECONDS = 600
OUTPUT_LIMIT = 2 * 1024 * 1024
RVOIP_RELEASE_VERSION = "0.3.8"
REQUIRED_RVOIP_PACKAGES = {
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
}
REMOVED_ENVIRONMENT_PREFIXES = (
    "AWS_",
    "BRIDGEFU_",
    "CARGO_",
    "GOOGLE_",
    "GCP_",
    "OTEL_",
    "RVOIP_",
    "RUST_",
    "RUSTC_",
    "RUSTDOC_",
    "TELNYX_",
    "TWILIO_",
    "VONAGE_",
)
REMOVED_ENVIRONMENT_KEYS = {
    "BRIDGEFU_TEST_POSTGRES_URL",
    "BRIDGEFU_TEST_REDIS_URL",
    "DATABASE_URL",
    "REDIS_URL",
    "RUSTFLAGS",
}
PRESERVED_TOOLCHAIN_KEYS = {"CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN"}


@dataclass(frozen=True)
class Check:
    name: str
    proof: str
    command: tuple[str, ...]


def checks(binary: Path, cargo: str) -> tuple[Check, ...]:
    return (
        Check(
            "compose-role-preflight",
            "all eight rendered services pass strict typed role/configuration preflight",
            (
                sys.executable,
                str(ROOT / "config" / "check-compose-profiles.py"),
                str(binary),
            ),
        ),
        Check(
            "process-mode-dispatch",
            "all-in-one, gateway, worker, and moq-relay dispatch to their exact runner",
            (
                cargo,
                "test",
                "--locked",
                "--bin",
                "bridgefu",
                "tests::gateway_mode_dispatches_to_the_gateway_runner_without_fallback",
                "--",
                "--exact",
            ),
        ),
        Check(
            "role-preflight-and-lifecycle",
            "split-role isolation, bounded admission, dependency health, and drain pass",
            (
                cargo,
                "test",
                "--locked",
                "--bin",
                "bridgefu",
                "process_role::tests",
                "--",
                "--test-threads=1",
            ),
        ),
        Check(
            "operational-health-contract",
            "/readyz follows lifecycle while /livez stays live during bounded drain",
            (
                cargo,
                "test",
                "--locked",
                "--bin",
                "bridgefu",
                "observability::tests::role_readiness_tracks_concrete_lifecycle",
                "--",
                "--exact",
            ),
        ),
        Check(
            "moq-relay-diagnostics-auth",
            "the relay diagnostics route rejects missing, malformed, and oversized bearers",
            (
                cargo,
                "test",
                "--locked",
                "--bin",
                "bridgefu",
                "moq_relay_role::tests::diagnostics_bearer_is_exact_and_bounded_and_absence_fails_closed",
                "--",
                "--exact",
            ),
        ),
        Check(
            "private-forwarding-loopback",
            "the concrete gateway/worker mTLS UCTP dependency and drain work on loopback",
            (
                cargo,
                "test",
                "--locked",
                "--test",
                "private_forwarding",
                "--",
                "--test-threads=1",
            ),
        ),
        Check(
            "durable-call-media-runtime",
            "a durable SIP/WebRTC call owns bidirectional codec-exact media and cleanup",
            (
                cargo,
                "test",
                "--locked",
                "--test",
                "call_execution_supervisor",
                "sip_webrtc_media_graph_is_directional_codec_exact_and_cleanup_owned",
                "--",
                "--exact",
            ),
        ),
        Check(
            "durable-context-runtime",
            "initial SIP context and later transport-neutral DataMessages cross the owned call graph",
            (
                cargo,
                "test",
                "--locked",
                "--test",
                "call_execution_supervisor",
                "inbound_sip_context_reaches_the_peer_data_channel_and_later_messages_bridge",
                "--",
                "--exact",
            ),
        ),
        Check(
            "durable-broadcast-runtime",
            "a connected durable source feeds managed broadcasts, tokens, diagnostics, and exact cleanup",
            (
                cargo,
                "test",
                "--locked",
                "--bin",
                "bridgefu",
                "api::tests::durable_broadcasts_share_real_source_and_cleanup_managed_state",
                "--",
                "--exact",
            ),
        ),
    )


def sanitized_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in PRESERVED_TOOLCHAIN_KEYS
        or (
            key not in REMOVED_ENVIRONMENT_KEYS
            and not key.startswith(REMOVED_ENVIRONMENT_PREFIXES)
        )
    }
    environment.update(
        {
            "CARGO_TERM_COLOR": "never",
            "CARGO_INCREMENTAL": "0",
            "RUST_BACKTRACE": "0",
            "RUST_TEST_THREADS": "1",
        }
    )
    return environment


def output_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def display_command(command: tuple[str, ...]) -> list[str]:
    root = str(ROOT)
    return [argument.replace(root, ".") for argument in command]


def repository_state(path: Path, *, required: bool) -> dict[str, object]:
    if not path.is_dir():
        if required:
            raise SystemExit(f"required source repository is absent: {path}")
        return {"present": False}
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=path,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=path,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
    except subprocess.CalledProcessError:
        if required:
            raise
        return {"present": True, "git_repository": False}
    untracked_count = sum(line.startswith("??") for line in status)
    tracked_dirty = any(not line.startswith("??") for line in status)
    return {
        "present": True,
        "git_repository": True,
        "revision": revision,
        "tracked_worktree_dirty": tracked_dirty,
        "untracked_files_present": untracked_count > 0,
        "untracked_file_count": untracked_count,
    }


def locked_dependency_state(lock_path: Path) -> dict[str, object]:
    lock = tomllib.loads(lock_path.read_text())
    packages = [
        package
        for package in lock["package"]
        if package["name"] == "rvoip" or package["name"].startswith("rvoip-")
    ]
    if not packages:
        raise SystemExit("Cargo.lock contains no rvoip packages")

    invalid = [
        (package["name"], package["version"], package.get("source"))
        for package in packages
        if package["version"] != RVOIP_RELEASE_VERSION
        or not package.get("source", "").startswith("registry+")
        or len(package.get("checksum", "")) != 64
    ]
    if invalid:
        raise SystemExit(
            "Cargo.lock contains non-registry, non-0.3.8, or unchecked rvoip "
            f"packages: {invalid}"
        )

    names = [package["name"] for package in packages]
    if len(names) != len(set(names)):
        raise SystemExit("Cargo.lock contains multiple versions of an rvoip package")
    missing = REQUIRED_RVOIP_PACKAGES - set(names)
    if missing:
        raise SystemExit(
            f"Cargo.lock is missing required rvoip packages: {sorted(missing)}"
        )

    return {
        "release_version": RVOIP_RELEASE_VERSION,
        "lockfile": "Cargo.lock",
        "packages": [
            {
                "name": package["name"],
                "version": package["version"],
                "source_kind": "registry",
                "checksum": package["checksum"],
            }
            for package in sorted(packages, key=lambda package: package["name"])
        ],
    }


def source_state() -> dict[str, object]:
    return {
        "bridgefu": repository_state(ROOT, required=True),
        "rvoip": locked_dependency_state(ROOT / "Cargo.lock"),
    }


def execute(check: Check, timeout_seconds: int) -> dict[str, object]:
    started = time.monotonic()
    timed_out = False
    try:
        result = subprocess.run(
            check.command,
            cwd=ROOT,
            env=sanitized_environment(),
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
        )
        return_code = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    except subprocess.TimeoutExpired as error:
        timed_out = True
        return_code = 124
        stdout = error.stdout or b""
        stderr = error.stderr or b""

    if len(stdout) > OUTPUT_LIMIT or len(stderr) > OUTPUT_LIMIT:
        return_code = 125
    passed = return_code == 0 and not timed_out
    evidence = {
        "name": check.name,
        "proof": check.proof,
        "command": display_command(check.command),
        "passed": passed,
        "timed_out": timed_out,
        "exit_code": return_code,
        "duration_millis": round((time.monotonic() - started) * 1000),
        "stdout_bytes": len(stdout),
        "stdout_sha256": output_digest(stdout),
        "stderr_bytes": len(stderr),
        "stderr_sha256": output_digest(stderr),
    }
    if not passed:
        sys.stderr.write(f"runtime smoke check failed: {check.name}\n")
        # These checks receive a credential-free environment. Bounded tails
        # retain enough compiler/test context without putting full output into
        # the evidence artifact.
        sys.stderr.buffer.write(stdout[-8192:])
        sys.stderr.buffer.write(stderr[-8192:])
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()

    binary = args.binary.resolve()
    plan = checks(binary, args.cargo)
    if args.list:
        for check in plan:
            print(f"{check.name}: {check.proof}")
        return
    if not binary.is_file():
        raise SystemExit(f"Bridgefu binary does not exist: {binary}")
    if args.timeout_seconds < 1 or args.timeout_seconds > 3600:
        raise SystemExit("--timeout-seconds must be between 1 and 3600")

    results = [execute(check, args.timeout_seconds) for check in plan]
    passed = all(result["passed"] for result in results)
    evidence = {
        "schema_version": 1,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "scope": "credential-free process/configuration/call/media/context/broadcast lifecycle smoke",
        "explicit_exclusions": [
            "carrier or provider calls",
            "Amazon Connect and Chime",
            "public or externally routed SIP, WebRTC, UCTP, or MOQT traffic",
            "cloud apply, smoke, and destroy",
            "release load and chaos criteria",
        ],
        "source": source_state(),
        "environment": {
            "os": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "passed": passed,
        "release_criterion_satisfied": False,
        "checks": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    if not passed:
        raise SystemExit("credential-free runtime smoke failed")


if __name__ == "__main__":
    main()
