from __future__ import annotations

import json
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


RECIPE = Path(__file__).resolve().parents[2]
ROOT = RECIPE.parents[1]
VALIDATOR = ROOT / "scripts" / "validate-recipe-evidence.py"


class QualificationAssetTests(unittest.TestCase):
    def evidence(self, sip_security="sip_rtp"):
        matrix = yaml.safe_load((RECIPE / "qualification/matrix.yaml").read_text())
        checks = {
            name: True
            for name in matrix["required_checks_by_sip_security"][sip_security]
        }
        required_ids = set(
            matrix["required_scenario_ids_by_sip_security"][sip_security]
        )
        scenarios = []
        call_hashes = []
        for scenario in matrix["required_scenarios"]:
            if scenario["id"] not in required_ids:
                continue
            for network in matrix["adverse_network_profiles"]:
                pair_hashes = [
                    hashlib.sha256(
                        f"{scenario['id']}:{network['id']}:{origin}".encode()
                    ).hexdigest()
                    for origin in ("source", "agent")
                ]
                call_hashes.extend(pair_hashes)
                scenarios.append(
                    {
                        "id": scenario["id"],
                        "network_profile": network["id"],
                        "call_evidence_sha256": pair_hashes,
                        "checks": checks,
                        "setup_latency_ms_p95": 500,
                        "audio_latency_ms_p95": 180,
                        "passed": True,
                    }
                )
        drills = [
            {
                "id": name,
                "evidence_sha256": hashlib.sha256(name.encode()).hexdigest(),
                "passed": True,
                "recovery_seconds": 30,
                "cleanup_zero": True,
            }
            for name in matrix["required_failure_drills"]["starter"]
        ]
        negative_names = [
            "prepare_auth_rejected",
            "prepare_conflicting_replay_rejected",
            "malformed_payload_rejected",
            "missing_correlation_header_rejected",
            "duplicate_correlation_header_rejected",
            "expired_attachment_rejected",
            "attachment_replay_rejected",
            "source_cancellation_cleanup",
            "missing_context_fail_open",
        ]
        negative = [
            {
                "id": name,
                "evidence_sha256": hashlib.sha256(f"negative:{name}".encode()).hexdigest(),
                "passed": True,
                "cleanup_zero": True,
            }
            for name in negative_names
        ]
        return {
            "schema_version": 1,
            "recipe": "vapi-amazon-connect-screen-pop@1",
            "execution_id": "bft-test1234",
            "deployment_profile": "starter",
            "sip_security": sip_security,
            "region": "us-west-2",
            "started_at": "2026-07-31T00:00:00Z",
            "ended_at": "2026-07-31T01:01:00Z",
            "revisions": {
                "release_id": "0" * 20,
                "source_tree_sha256": "1" * 64,
                "image": f"example.test/bridgefu@sha256:{'a' * 64}",
                "recipe_fingerprint": "b" * 64,
                "release_manifest_sha256": "c" * 64,
                "cloudformation_sha256": "d" * 64,
                "qualification_controller_sha256": "e" * 64,
            },
            "scenarios": scenarios,
            "failure_drills": drills,
            "negative_cases": negative,
            "soak": {
                "started_at": "2026-07-31T00:00:00Z",
                "ended_at": "2026-07-31T01:00:00Z",
                "minutes": 60,
                "attempted_calls": len(call_hashes),
                "completed_calls": len(call_hashes),
                "unexpected_failures": 0,
                "setup_latency_ms_p95": 500,
                "audio_latency_ms_p95": 180,
                "call_evidence_sha256": call_hashes,
                "telemetry": {
                    "cpu_percent_max": 40,
                    "memory_percent_max": 35,
                    "file_descriptors_max": 512,
                    "rtp_ports_in_use_max": 20,
                    "network_errors": 0,
                    "media_drops": 0,
                    "lambda_errors": 0,
                    "dynamodb_errors": 0,
                    "cleanup_backlog_max": 0,
                },
                "evidence_sha256": "f" * 64,
                "cleanup_zero": True,
            },
            "zero_state": {
                "observed_at": "2026-07-31T01:00:30Z",
                "evidence_sha256": "6" * 64,
                "active_calls": 0,
                "active_contacts": 0,
                "active_routes": 0,
                "cleanup_backlog": 0,
            },
            "teardown": {
                "observed_at": "2026-07-31T01:01:00Z",
                "inventory_sha256": "7" * 64,
                "test_owned_resources": 0,
                "customer_resources_mutated": False,
            },
            "provenance": {
                "structural_evidence_sha256": "8" * 64,
                "lifecycle_evidence_sha256": "9" * 64,
                "call_evidence_count": len(call_hashes),
                "failure_evidence_count": len(drills),
                "negative_evidence_count": len(negative),
            },
            "redacted": True,
            "customer_data_retained": False,
        }

    def validate(self, evidence):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as stream:
            json.dump(evidence, stream)
            stream.flush()
            return subprocess.run(
                [sys.executable, str(VALIDATOR), stream.name],
                capture_output=True,
                text=True,
            )

    def test_each_sip_posture_passes_only_its_exact_matrix(self):
        for sip_security in ("sip_rtp", "sips_srtp"):
            with self.subTest(sip_security=sip_security):
                evidence = self.evidence(sip_security)
                result = self.validate(evidence)
                self.assertEqual(result.returncode, 0, result.stderr)
                evidence["scenarios"][0]["checks"]["dtmf_agent_to_source"] = False
                result = self.validate(evidence)
                self.assertNotEqual(result.returncode, 0)

    def test_clear_evidence_cannot_claim_the_secure_posture(self):
        evidence = self.evidence("sip_rtp")
        evidence["sip_security"] = "sips_srtp"
        result = self.validate(evidence)
        self.assertNotEqual(result.returncode, 0)

    def test_evidence_contract_has_no_sensitive_payload_fields(self):
        schema = (RECIPE / "qualification/evidence-v1.schema.json").read_text()
        for forbidden in (
            "correlation_id",
            "customer_name",
            "issue_summary",
            "transcript",
            "recording",
            "private_key",
        ):
            self.assertNotIn(forbidden, schema)


if __name__ == "__main__":
    unittest.main()
