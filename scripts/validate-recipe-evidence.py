#!/usr/bin/env python3
"""Validate redacted flagship recipe evidence against schema and exact matrix."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

import jsonschema
import yaml


MAX_EVIDENCE_BYTES = 2 * 1024 * 1024


def parse_timestamp(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise SystemExit("evidence timestamp is not timezone-aware")
    return parsed.astimezone(dt.timezone.utc)


def load_json(path: Path) -> object:
    if not path.is_file() or path.stat().st_size > MAX_EVIDENCE_BYTES:
        raise SystemExit("evidence must be a bounded regular file")
    return json.loads(path.read_text())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    qualification = (
        root / "recipes" / "vapi-amazon-connect-screen-pop" / "qualification"
    )
    schema = json.loads((qualification / "evidence-v1.schema.json").read_text())
    matrix = yaml.safe_load((qualification / "matrix.yaml").read_text())
    evidence = load_json(args.evidence)
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(evidence)

    sip_security = evidence["sip_security"]
    required_checks_by_security = matrix.get("required_checks_by_sip_security", {})
    required_scenarios_by_security = matrix.get(
        "required_scenario_ids_by_sip_security", {}
    )
    if (
        set(required_checks_by_security) != {"sip_rtp", "sips_srtp"}
        or set(required_scenarios_by_security) != {"sip_rtp", "sips_srtp"}
        or sip_security not in required_checks_by_security
        or sip_security not in required_scenarios_by_security
    ):
        raise SystemExit("qualification matrix has no exact SIP posture contract")
    required_checks = set(required_checks_by_security[sip_security])
    required_scenarios = set(required_scenarios_by_security[sip_security])
    catalog = {
        item["id"]: item
        for item in matrix.get("required_scenarios", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    if (
        len(required_checks) != len(required_checks_by_security[sip_security])
        or len(required_scenarios)
        != len(required_scenarios_by_security[sip_security])
        or len(required_scenarios) != 3
        or any(identifier not in catalog for identifier in required_scenarios)
        or any(
            catalog[identifier].get("security")
            != (
                "deployed"
                if catalog[identifier].get("source") == "vapi_web"
                else sip_security
            )
            for identifier in required_scenarios
        )
    ):
        raise SystemExit("qualification matrix SIP posture contract is invalid")
    network_profiles = {item["id"] for item in matrix["adverse_network_profiles"]}
    observed_pairs: set[tuple[str, str]] = set()
    call_digests: set[str] = set()
    for scenario in evidence["scenarios"]:
        checks = scenario["checks"]
        if set(checks) != required_checks or not all(
            checks[name] is True for name in required_checks
        ):
            raise SystemExit(
                f"scenario {scenario['id']} does not contain the exact passing checks"
            )
        pair = (scenario["id"], scenario["network_profile"])
        if pair in observed_pairs:
            raise SystemExit(f"duplicate scenario/network evidence: {pair}")
        observed_pairs.add(pair)
        digests = set(scenario["call_evidence_sha256"])
        if len(digests) != 2 or call_digests.intersection(digests):
            raise SystemExit("scenario call evidence hashes are duplicate or reused")
        call_digests.update(digests)
    required_pairs = {
        (scenario, network)
        for scenario in required_scenarios
        for network in network_profiles
    }
    if observed_pairs != required_pairs:
        missing = sorted(required_pairs - observed_pairs)
        extra = sorted(observed_pairs - required_pairs)
        raise SystemExit(f"scenario/network matrix mismatch; missing={missing}, extra={extra}")

    profile = evidence["deployment_profile"]
    required_drills = set(matrix["required_failure_drills"][profile])
    observed_drills = {item["id"] for item in evidence["failure_drills"]}
    if observed_drills != required_drills or len(evidence["failure_drills"]) != len(
        required_drills
    ):
        raise SystemExit(
            "failure drill matrix mismatch; "
            f"missing={sorted(required_drills - observed_drills)}, "
            f"extra={sorted(observed_drills - required_drills)}"
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
    observed_negative = {item["id"] for item in evidence["negative_cases"]}
    if observed_negative != required_negative or len(evidence["negative_cases"]) != len(
        required_negative
    ):
        raise SystemExit("negative-case matrix mismatch")

    started = parse_timestamp(evidence["started_at"])
    ended = parse_timestamp(evidence["ended_at"])
    soak_started = parse_timestamp(evidence["soak"]["started_at"])
    soak_ended = parse_timestamp(evidence["soak"]["ended_at"])
    if not started <= soak_started < soak_ended <= ended:
        raise SystemExit("qualification/soak timestamps are inconsistent")
    elapsed_minutes = (soak_ended - soak_started).total_seconds() / 60
    if elapsed_minutes < matrix["required_soak_minutes"]:
        raise SystemExit("soak wall-clock duration is below the matrix minimum")
    soak = evidence["soak"]
    if (
        soak["minutes"] < matrix["required_soak_minutes"]
        or soak["attempted_calls"] != soak["completed_calls"]
        or len(soak["call_evidence_sha256"]) != soak["completed_calls"]
    ):
        raise SystemExit("soak call counts or retained hashes are inconsistent")
    provenance = evidence["provenance"]
    if (
        provenance["call_evidence_count"] != len(call_digests)
        or provenance["failure_evidence_count"] != len(required_drills)
        or provenance["negative_evidence_count"] != len(required_negative)
    ):
        raise SystemExit("provenance counts do not match the retained evidence")
    print("recipe qualification evidence passed schema and semantic matrix")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
