#!/usr/bin/env python3
"""Validate the immutable live-qualification evidence required for Setup releases."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path

SCHEMA = "bridgefu.setup-release-qualification/v1"
REQUIRED_GATES = (
    "packagedDesktop",
    "companionCli",
    "cloudFormation",
    "vapireTemplateAssistant",
    "liveAwsVapiQualification",
    "managedDemoCompatibility",
    "cleanupZeroResources",
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")


def _parse_time(value: object) -> dt.datetime:
    if not isinstance(value, str):
        raise ValueError("completedAt must be an RFC 3339 string")
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("completedAt must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def validate(
    path: Path,
    *,
    expected_commit: str,
    expected_sha256: str,
    now: dt.datetime | None = None,
) -> dict[str, object]:
    raw = path.read_bytes()
    actual_hash = hashlib.sha256(raw).hexdigest()
    if actual_hash != expected_sha256:
        raise ValueError("qualification evidence SHA-256 does not match the reviewed input")
    evidence = json.loads(raw)
    if not isinstance(evidence, dict) or evidence.get("schema") != SCHEMA:
        raise ValueError("unsupported setup qualification evidence schema")
    if not GIT_SHA.fullmatch(expected_commit) or evidence.get("sourceCommit") != expected_commit:
        raise ValueError("qualification evidence is not bound to this source revision")
    if evidence.get("overall") != "passed":
        raise ValueError("qualification evidence is not passing")
    execution_id = evidence.get("executionId")
    if not isinstance(execution_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{5,63}", execution_id):
        raise ValueError("qualification evidence has an invalid executionId")
    gates = evidence.get("gates")
    if not isinstance(gates, dict):
        raise ValueError("qualification evidence gates are missing")
    failed = [name for name in REQUIRED_GATES if gates.get(name) != "passed"]
    if failed:
        raise ValueError(f"qualification evidence is missing passing gates: {failed}")
    artifacts = evidence.get("artifactHashes")
    if not isinstance(artifacts, dict) or not artifacts:
        raise ValueError("qualification evidence must bind its retained artifacts")
    if any(not isinstance(name, str) or not SHA256.fullmatch(value or "") for name, value in artifacts.items()):
        raise ValueError("qualification artifact hashes must be named SHA-256 values")
    completed = _parse_time(evidence.get("completedAt"))
    current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    age = current - completed
    if age < dt.timedelta(0) or age > dt.timedelta(days=30):
        raise ValueError("qualification evidence must be no more than 30 days old")
    return evidence


def _self_test() -> None:
    import tempfile

    now = dt.datetime(2026, 8, 8, tzinfo=dt.timezone.utc)
    commit = "a" * 40
    evidence = {
        "schema": SCHEMA,
        "sourceCommit": commit,
        "executionId": "bft-20260808-release",
        "completedAt": now.isoformat().replace("+00:00", "Z"),
        "overall": "passed",
        "gates": {name: "passed" for name in REQUIRED_GATES},
        "artifactHashes": {"qualification.json": "b" * 64},
    }
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "evidence.json"
        path.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        validate(path, expected_commit=commit, expected_sha256=digest, now=now)
        evidence["gates"]["liveAwsVapiQualification"] = "failed"
        path.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        try:
            validate(path, expected_commit=commit, expected_sha256=digest, now=now)
        except ValueError:
            return
    raise AssertionError("self-test accepted failed live qualification evidence")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path, nargs="?")
    parser.add_argument("--expected-commit")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        _self_test()
        print("setup release qualification checker self-test passed")
        return 0
    if not args.evidence or not args.expected_commit or not args.expected_sha256:
        parser.error("evidence, --expected-commit, and --expected-sha256 are required")
    validated = validate(
        args.evidence,
        expected_commit=args.expected_commit,
        expected_sha256=args.expected_sha256,
    )
    print(f"qualified {validated['executionId']} for {validated['sourceCommit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
