from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


RECIPE = Path(__file__).resolve().parents[2]
ROOT = RECIPE.parents[1]
CONTROLLER_PATH = ROOT / "scripts" / "run-recipe-qualification.py"
SPEC = importlib.util.spec_from_file_location(
    "bridgefu_release_qualification", CONTROLLER_PATH
)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("unable to load release qualification controller")
CONTROLLER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CONTROLLER
SPEC.loader.exec_module(CONTROLLER)


class ReleaseQualificationControllerTests(unittest.TestCase):
    def ledger(self, security: str = "sip_rtp"):
        dns = security == "sips_srtp"
        return {
            "execution_id": "bft-test1234",
            "release_id": "a" * 20,
            "publication_source_tree_sha256": "b" * 64,
            "bridgefu_image_uri": f"example.test/bridgefu@sha256:{'c' * 64}",
            "runtime_profile": "starter",
            "sip_security": security,
            "dns_mode": "existing_route53_zone" if dns else "ip_only",
            "public_hosted_zone_id": "ZTEST" if dns else "none",
            "sip_hostname": "sip.example.test" if dns else "unused.bridgefu.invalid",
        }

    def call(self, scenario: str, network: str, origin: str, index: int):
        source_producer = (
            "bridgefu-vapi-web-playwright@1"
            if scenario == "vapi-web-transfer"
            else "bridgefu-recipe-sip-source@1"
        )
        return {
            "schema_version": 1,
            "recipe": CONTROLLER.RECIPE,
            "execution_id": "bft-test1234",
            "scenario_id": scenario,
            "network": {
                "profile": network,
                "controller": "bridgefu-aws-tc-netem-controller@1",
                "controller_revision_sha256": "d" * 64,
                "settings": (
                    {
                        "delay_ms": 0,
                        "jitter_ms": 0,
                        "loss_percent": 0,
                        "reorder_percent": 0,
                    }
                    if network == "baseline"
                    else {
                        "delay_ms": 80,
                        "jitter_ms": 20,
                        "loss_percent": 1,
                        "reorder_percent": 0.1,
                    }
                ),
                "target_count": 1,
                "verified_clean_before": True,
                "impairment_applied": network == "moderate-wan",
                "verified_during_call": True,
                "removed_after_call": True,
            },
            "hangup_origin": origin,
            "started_at": f"2026-08-01T00:{index:02d}:00Z",
            "ended_at": f"2026-08-01T00:{index:02d}:30Z",
            "revisions": {
                "release_id": "a" * 20,
                "source_tree_sha256": "b" * 64,
                "image": f"example.test/bridgefu@sha256:{'c' * 64}",
            },
            "correlation_fingerprint": f"{index:012x}",
            "checks": {
                "actual_transfer_header": True,
                "context_persisted": True,
                "amazon_attribute_mapped": True,
                "connect_contact_started_once": True,
                "connect_lookup_available": True,
                "media_connected": True,
                "agent_screen_visible": True,
                "audio_source_to_agent_non_silent": True,
                "audio_agent_to_source_non_silent": True,
                "dtmf_source_to_agent": True,
                "dtmf_agent_to_source": True,
                "originating_hangup_cleanup": True,
                "cleanup_zero_state": True,
            },
            "timings": {
                "setup_latency_ms": 500 + index,
                "source_to_agent_latency_ms_p95": 100 + index,
                "agent_to_source_latency_ms_p95": 120 + index,
            },
            "observations": {
                "runtime_lifecycle_stages": [
                    "attributes_mapped",
                    "contact_started",
                    "media_connected",
                    "sip_invite_received",
                    "teardown_started",
                    "terminated",
                ],
                "lookup_result": "available",
                "source_producer": source_producer,
                "source_producer_revision_sha256": "e" * 64,
                "source_site_bundle_sha256": (
                    "f" * 64 if scenario == "vapi-web-transfer" else None
                ),
                "vapi_call_contract_verified": scenario == "vapi-web-transfer",
                "attachment_replay_rejected": (
                    None if scenario == "vapi-web-transfer" else True
                ),
                "participant_producer": "bridgefu-agent-workspace-playwright@1",
                "participant_producer_revision_sha256": "1" * 64,
                "screenshot_sha256": "2" * 64,
            },
            "passed": True,
            "redacted": True,
            "customer_data_retained": False,
        }

    def test_call_matrix_requires_two_origins_for_the_deployed_sip_posture(self):
        postures = {
            "sip_rtp": ["sip-rtp-pcmu", "sip-rtp-pcma", "vapi-web-transfer"],
            "sips_srtp": [
                "sips-srtp-pcmu",
                "sips-srtp-pcma",
                "vapi-web-transfer",
            ],
        }
        for security, scenarios in postures.items():
            with self.subTest(security=security), tempfile.TemporaryDirectory() as directory:
                execution = Path(directory)
                calls = execution / "call-evidence"
                calls.mkdir()
                index = 1
                for scenario in scenarios:
                    for network in ("baseline", "moderate-wan"):
                        for origin in ("source", "agent"):
                            value = self.call(scenario, network, origin, index)
                            (calls / f"{index:02d}.json").write_text(json.dumps(value))
                            index += 1
                negative = {
                    "attachment_replay_rejected": (
                        execution / "replay.json",
                        {"outcome": "replay_rejected", "passed": True},
                    ),
                    "missing_context_fail_open": (
                        execution / "missing.json",
                        {
                            "outcome": "failed_open",
                            "passed": True,
                            "checks": {"agent_workspace_observed": True},
                        },
                    ),
                }
                with mock.patch.object(
                    CONTROLLER.LIVE,
                    "ledger_path",
                    return_value=execution / "ledger.json",
                ):
                    rows, hashes, starts, ends = CONTROLLER.call_matrix(
                        self.ledger(security), negative
                    )
                self.assertEqual(len(rows), 6)
                self.assertEqual(len(hashes), 12)
                self.assertEqual(len(starts), 12)
                self.assertEqual(len(ends), 12)
                self.assertTrue(all(all(row["checks"].values()) for row in rows))

    def test_network_posture_and_host_recovery_endpoint_are_mode_specific(self):
        clear = self.ledger("sip_rtp")
        self.assertEqual(CONTROLLER.validate_qualification_posture(clear), "sip_rtp")
        self.assertEqual(
            CONTROLLER.host_recovery_endpoint(
                clear,
                {"SipSecurity": "sip_rtp"},
                {"PublicIp": "8.8.8.8", "SipHostname": "8.8.8.8"},
            ),
            ("8.8.8.8", 5060, "SIP"),
        )

        secure = self.ledger("sips_srtp")
        self.assertEqual(
            CONTROLLER.host_recovery_endpoint(
                secure,
                {"SipSecurity": "sips_srtp"},
                {"SipHostname": "sip.example.test"},
            ),
            ("sip.example.test", 5061, "SIPS"),
        )

        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.host_recovery_endpoint(
                clear,
                {"SipSecurity": "sips_srtp"},
                {"PublicIp": "8.8.8.8", "SipHostname": "8.8.8.8"},
            )
        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.validate_qualification_posture(
                {**clear, "public_hosted_zone_id": "ZUNEXPECTED"}
            )

    def test_contracts_and_redaction_fail_closed(self):
        for schema in CONTROLLER.COMPONENT_SCHEMAS:
            CONTROLLER.jsonschema.Draft202012Validator.check_schema(
                json.loads(schema.read_text())
            )
        self.assertEqual(CONTROLLER.p95([1, 2, 3, 4]), 4.0)
        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.reject_sensitive({"correlation_id": "secret"})
        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.reject_sensitive({"value": "bf1_" + "A" * 43})

    def test_zero_state_metrics_require_two_ready_samples_per_host(self):
        output = """bridgefu-zero-sample-1
bridgefu_process_ready{role="all-in-one"} 1
bridgefu_active_sessions{tenant="support"} 0
bridgefu_gateway_native_active_routes 0
bridgefu_amazon_durable_cleanups_pending 0
bridgefu_amazon_pending_contact_cleanups 0
bridgefu-zero-sample-2
bridgefu_process_ready{role="all-in-one"} 1
bridgefu_active_sessions{tenant="support"} 0
bridgefu_gateway_native_active_routes 0
bridgefu_amazon_durable_cleanups_pending 0
bridgefu_amazon_pending_contact_cleanups 0
"""
        samples = CONTROLLER.parse_metric_samples([output])
        self.assertEqual(len(samples), 2)
        self.assertEqual(samples[0]["bridgefu_active_sessions"], 0)
        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.parse_metric_samples(
                [output.replace("bridgefu-zero-sample-2", "")]
            )

    def test_sip_negative_observation_binds_wire_counts_and_source_revision(self):
        session = {
            "execution_id": "bft-test1234",
            "security": "sips_srtp",
            "correlation_fingerprint": "a" * 12,
            "source_call_fingerprint": "b" * 12,
        }
        observation = {
            "schema_version": 1,
            "producer": "bridgefu-recipe-sip-negative@1",
            "producer_revision_sha256": CONTROLLER.sha256_file(
                CONTROLLER.SIP_NEGATIVE_SOURCE
            ),
            "execution_id": "bft-test1234",
            "id": "duplicate_correlation_header_rejected",
            "correlation_fingerprint": "a" * 12,
            "source_call_fingerprint": "b" * 12,
            "started_at": "2026-08-01T00:00:00Z",
            "ended_at": "2026-08-01T00:00:01Z",
            "transport": "tls",
            "invite_count": 1,
            "wire_header_count": 2,
            "cancel_count": 0,
            "rejection_status": 403,
            "answered": False,
            "cancellation_completed": False,
            "redacted": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "negative.private.json"
            path.write_text(json.dumps(observation))
            os.chmod(path, 0o600)
            value = CONTROLLER.private_negative_observation(
                path, session, "duplicate_correlation_header_rejected"
            )
            self.assertEqual(value["wire_header_count"], 2)
            observation["wire_header_count"] = 1
            path.write_text(json.dumps(observation))
            with self.assertRaises(CONTROLLER.QualificationError):
                CONTROLLER.private_negative_observation(
                    path, session, "duplicate_correlation_header_rejected"
                )

    def test_soak_samples_cover_window_and_reject_counter_reset(self):
        start = CONTROLLER.parse_timestamp("2026-08-01T00:00:00Z")
        end = CONTROLLER.parse_timestamp("2026-08-01T01:00:00Z")
        token = "a" * 12
        lines = [f"bridgefu-soak-monitor-evidence-v1,{token}"]
        epoch = int(start.timestamp())
        for index in range(100):
            lines.append(
                "bridgefu-soak-sample-v1,"
                f"{epoch + index * 36},10.0,20.0,40,1,{index},{index},0"
            )
        output = "\n".join(lines) + "\n"
        telemetry = CONTROLLER.parse_soak_samples([output], token, start, end)
        self.assertEqual(telemetry["network_errors"], 99)
        self.assertEqual(telemetry["media_drops"], 99)
        reset = output.replace(
            f"{epoch + 99 * 36},10.0,20.0,40,1,99,99,0",
            f"{epoch + 99 * 36},10.0,20.0,40,1,0,0,0",
        )
        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.parse_soak_samples([reset], token, start, end)
        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.parse_soak_samples(
                [output.replace(",40,1,", ",40,0,")], token, start, end
            )

    def test_dependency_timeout_fault_is_bounded_and_keeps_bridgefu_ready(self):
        start = CONTROLLER.dependency_timeout_start_script("a" * 12)
        finish = CONTROLLER.dependency_timeout_finish_script("a" * 12)
        self.assertIn("http-request tarpit", start)
        self.assertIn("RuntimeMaxSec=95", start)
        self.assertIn("systemctl is-active --quiet bridgefu.service", start)
        self.assertIn("http://127.0.0.1:9090/readyz", start)
        self.assertIn('test "$curl_status" -eq 28', start)
        self.assertNotIn("docker pause", start)
        self.assertIn("sha256sum /etc/haproxy/haproxy.cfg", finish)
        self.assertIn("bridgefu-dependency-timeout-recovered-v1", finish)

    def test_dependency_timeout_requires_exact_503_and_cleans_prepared_row(self):
        row = {
            "schema_version": 1,
            "correlation_id": "bf1_" + "A" * 43,
            "handoff_status": "PREPARED",
            "customer_name": "Bridgefu Synthetic Caller",
            "issue_summary": "Qualification negative-case context.",
            "intent": "qualification",
            "verification_status": "synthetic",
            "expires_at": 4_102_444_800,
            "content_hash": "d" * 64,
            "vapi_call_fingerprint": "e" * 64,
        }
        handoff = {
            "VapiWebhookSecretArn": "arn:webhook",
            "CorrelationKeySecretArn": "arn:correlation",
            "PrepareUrl": "https://example.test/prepare",
            "TransferUrl": "https://example.test/transfer",
            "HandoffTableName": "table",
        }

        def ssm(_ledger, _environment, _instances, script):
            if "bridgefu-dependency-timeout-active-v1" in script:
                return ["bridgefu-dependency-timeout-active-v1"]
            return ["bridgefu-dependency-timeout-recovered-v1"]

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            CONTROLLER.LIVE, "ledger_path", return_value=Path(directory) / "ledger.json"
        ), mock.patch.object(
            CONTROLLER.COLLECTOR, "nested_outputs", return_value=handoff
        ), mock.patch.object(
            CONTROLLER.LIVE, "secret_value", side_effect=("webhook", "key")
        ), mock.patch.object(
            CONTROLLER, "bounded_test_contacts", return_value=(0, 0)
        ), mock.patch.object(
            CONTROLLER.LIVE,
            "http_post",
            side_effect=(
                (
                    200,
                    {
                        "results": [
                            {
                                "name": "prepare_handoff",
                                "toolCallId": mock.ANY,
                                "result": {"status": "prepared"},
                            }
                        ]
                    },
                ),
                (503, {"error": "bridgefu_reservation_unavailable"}),
            ),
        ), mock.patch.object(
            CONTROLLER.COLLECTOR,
            "derive_correlation_id",
            return_value=row["correlation_id"],
        ), mock.patch.object(
            CONTROLLER.COLLECTOR, "get_handoff_row", return_value=row
        ), mock.patch.object(
            CONTROLLER.LIVE, "ssm_shell", side_effect=ssm
        ), mock.patch.object(
            CONTROLLER, "wait_for_contact_total"
        ), mock.patch.object(
            CONTROLLER, "delete_synthetic_context"
        ) as delete:
            elapsed = CONTROLLER.dependency_timeout_action(
                {"execution_id": "bft-test1234"}, {}, ["i-12345678"]
            )
        self.assertGreaterEqual(elapsed, 0)
        self.assertEqual(delete.call_args.kwargs["expected_status"], "PREPARED")

    def test_packaged_examples_use_the_prebuilt_release_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "target/release/examples/recipe_sip_source"
            executable.parent.mkdir(parents=True)
            executable.write_text("binary")
            os.chmod(executable, 0o700)
            with mock.patch.object(CONTROLLER, "ROOT", root), mock.patch.dict(
                os.environ, {"BRIDGEFU_PACKAGED_SOURCE": "1"}
            ):
                self.assertEqual(
                    CONTROLLER.packaged_example_command("recipe_sip_source"),
                    [os.fspath(executable)],
                )

    def test_teardown_validator_requires_the_current_complete_inventory(self):
        fields = {
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
        value = {"checked_at": "2026-08-01T00:00:00Z"}
        value.update({field: [] for field in fields})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "teardown.json"
            path.write_text(json.dumps(value))
            self.assertEqual(CONTROLLER.validate_teardown(path), value)
            value.pop("elastic_ip_allocation_ids")
            path.write_text(json.dumps(value))
            with self.assertRaises(CONTROLLER.QualificationError):
                CONTROLLER.validate_teardown(path)

    def test_packaged_evidence_paths_reject_traversal(self):
        self.assertEqual(
            CONTROLLER.packaged_relative_path("call-evidence/call.json").as_posix(),
            "call-evidence/call.json",
        )
        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.packaged_relative_path("../ledger.json")

    def test_pre_lifecycle_and_final_zero_state_are_distinct_files(self):
        with tempfile.TemporaryDirectory() as directory:
            execution = Path(directory)
            ledger_path = execution / "ledger.json"
            ledger = {"execution_id": "bft-test1234"}
            counts = {
                "active_calls": 0,
                "active_contacts": 0,
                "active_routes": 0,
                "cleanup_backlog": 0,
            }
            with mock.patch.object(
                CONTROLLER,
                "stable_live_ledger",
                return_value=(ledger_path, ledger, {}),
            ), mock.patch.object(
                CONTROLLER, "observe_zero_counts", return_value=counts
            ), mock.patch.object(CONTROLLER.LIVE, "record"):
                for phase in ("pre_lifecycle", "final"):
                    CONTROLLER.zero_state(
                        type(
                            "Args",
                            (),
                            {
                                "execution_id": "bft-test1234",
                                "confirm": "bft-test1234",
                                "phase": phase,
                                "window_seconds": 60,
                            },
                        )()
                    )
            self.assertTrue(
                (execution / "zero-state-pre-lifecycle-evidence.json").is_file()
            )
            self.assertTrue((execution / "zero-state-evidence.json").is_file())


if __name__ == "__main__":
    unittest.main()
