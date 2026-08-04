from __future__ import annotations

import importlib.util
import copy
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import jsonschema


RECIPE = Path(__file__).resolve().parents[2]
ROOT = RECIPE.parents[1]
COLLECTOR_PATH = ROOT / "scripts" / "collect-recipe-call-evidence.py"
QUALIFICATION_PATH = ROOT / "scripts" / "run-recipe-qualification.py"
SPEC = importlib.util.spec_from_file_location("bridgefu_call_evidence", COLLECTOR_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import guard
    raise RuntimeError("unable to load call evidence collector")
COLLECTOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = COLLECTOR
SPEC.loader.exec_module(COLLECTOR)


class CallEvidenceCollectorTests(unittest.TestCase):
    def test_cloudformation_descriptions_use_exact_stack_ids(self):
        for path, minimum_exact_uses in (
            (COLLECTOR_PATH, 3),
            (QUALIFICATION_PATH, 4),
        ):
            with self.subTest(path=path.name):
                source = path.read_text()
                self.assertNotIn(
                    'LIVE.stack_description(ledger, environment, ledger["stack_name"])',
                    source,
                )
                self.assertNotIn(
                    'LIVE.stack_description(dict(ledger), dict(environment), ledger["stack_name"])',
                    source,
                )
                self.assertNotIn(
                    'dict(qualification_environment), str(ledger["stack_name"])',
                    source,
                )
                self.assertGreaterEqual(
                    source.count('ledger["stack_id"]'), minimum_exact_uses
                )

    def participant(self):
        return {
            "schema_version": 1,
            "producer": "bridgefu-agent-workspace-playwright@1",
            "producer_revision_sha256": "a" * 64,
            "execution_id": "bft-test1234",
            "scenario_id": "sips-srtp-pcmu",
            "hangup_origin": "source",
            "correlation_fingerprint": "123456abcdef",
            "source_call_fingerprint": "abcdef123456",
            "observed_at": "2026-08-01T12:00:20Z",
            "screen_pop": {
                "visible": True,
                "visible_fields": list(COLLECTOR.DISPLAY_FIELDS),
                "screenshot_sha256": "b" * 64,
            },
            "media": {
                "source_to_agent_marker_frames": 10,
                "source_marker_observed_at_ms": [1_250, 2_250, 3_250, 4_250, 5_250],
                "agent_marker_sent_at_ms": [10_000, 11_000, 12_000, 13_000, 14_000],
                "agent_to_source_marker_frames_sent": 25,
                "dtmf_source_to_agent_observed": True,
                "dtmf_agent_to_source_sent": True,
            },
            "hangup": {
                "origin": "source",
                "local_end_completed": False,
                "remote_end_observed": True,
                "cleanup_observed": True,
            },
            "redacted": True,
        }

    def source(self):
        return {
            "schema_version": 1,
            "producer": "bridgefu-recipe-sip-source@1",
            "producer_revision_sha256": "c" * 64,
            "execution_id": "bft-test1234",
            "scenario_id": "sips-srtp-pcmu",
            "hangup_origin": "source",
            "correlation_fingerprint": "123456abcdef",
            "source_call_fingerprint": "abcdef123456",
            "observed_at": "2026-08-01T12:00:21Z",
            "signaling": {
                "scheme": "sips",
                "transport": "tls",
                "invite_sent": True,
                "wire_header_name": "x-correlation-id",
                "wire_header_count": 1,
                "answered": True,
                "attachment_replay_rejected": True,
            },
            "media": {
                "codec": "pcmu",
                "security": "srtp",
                "source_marker_sent_at_ms": [
                    1_000,
                    2_000,
                    3_000,
                    4_000,
                    5_000,
                    6_000,
                ],
                "agent_marker_observed_at_ms": [10_200, 11_200, 12_200, 13_200, 14_200],
                "source_to_agent_marker_frames_sent": 30,
                "agent_to_source_marker_frames": 10,
                "dtmf_source_to_agent_sent": True,
                "dtmf_agent_to_source_observed": True,
            },
            "hangup": {
                "origin": "source",
                "local_bye_completed": True,
                "remote_bye_observed": False,
                "cleanup_observed": True,
            },
            "redacted": True,
        }

    def call(self):
        checks = {
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
        }
        return {
            "schema_version": 1,
            "recipe": "vapi-amazon-connect-screen-pop@1",
            "execution_id": "bft-test1234",
            "scenario_id": "sips-srtp-pcmu",
            "network": {
                "profile": "baseline",
                "controller": "bridgefu-aws-tc-netem-controller@1",
                "controller_revision_sha256": "9" * 64,
                "settings": {
                    "delay_ms": 0,
                    "jitter_ms": 0,
                    "loss_percent": 0,
                    "reorder_percent": 0,
                },
                "target_count": 1,
                "verified_clean_before": True,
                "impairment_applied": False,
                "verified_during_call": True,
                "removed_after_call": True,
            },
            "hangup_origin": "source",
            "started_at": "2026-08-01T12:00:00Z",
            "ended_at": "2026-08-01T12:00:30Z",
            "revisions": {
                "release_id": "d" * 20,
                "source_tree_sha256": "e" * 64,
                "image": f"example.test/bridgefu@sha256:{'f' * 64}",
            },
            "correlation_fingerprint": "123456abcdef",
            "checks": checks,
            "timings": {
                "setup_latency_ms": 1_000,
                "source_to_agent_latency_ms_p95": 250,
                "agent_to_source_latency_ms_p95": 200,
            },
            "observations": {
                "runtime_lifecycle_stages": sorted(COLLECTOR.REQUIRED_LIFECYCLE),
                "lookup_result": "available",
                "source_producer": "bridgefu-recipe-sip-source@1",
                "source_producer_revision_sha256": "c" * 64,
                "source_site_bundle_sha256": None,
                "vapi_call_contract_verified": False,
                "attachment_replay_rejected": True,
                "participant_producer": "bridgefu-agent-workspace-playwright@1",
                "participant_producer_revision_sha256": "a" * 64,
                "screenshot_sha256": "b" * 64,
            },
            "passed": True,
            "redacted": True,
            "customer_data_retained": False,
        }

    def vapi_source(self):
        value = self.source()
        value.pop("signaling")
        value.update(
            {
                "producer": "bridgefu-vapi-web-playwright@1",
                "site_bundle_sha256": "d" * 64,
                "browser_sdk_version": "2.5.2",
                "scenario_id": "vapi-web-transfer",
                "vapi": {
                    "web_call_started": True,
                    "transfer_trigger_sent": True,
                    "call_end_observed": True,
                },
            }
        )
        value["media"]["codec"] = "negotiated"
        value["media"]["security"] = "srtp"
        value["hangup"] = {
            "origin": "source",
            "local_end_completed": True,
            "remote_end_observed": False,
            "cleanup_observed": True,
        }
        return value

    def test_structured_logs_are_deduplicated_and_joined_by_fingerprint(self):
        runtime = [
            {
                "message": (
                    '{"timestamp":"2026-08-01T12:00:00Z","fields":'
                    '{"event":"bridgefu_screen_pop_lifecycle",'
                    '"correlation_fingerprint":"123456abcdef",'
                    '"stage":"contact_started",'
                    '"occurred_at":"2026-08-01T12:00:01Z"}}'
                )
            },
            {
                "message": (
                    '{"event":"bridgefu_sip_invite_evidence",'
                    '"correlation_fingerprint":"123456abcdef",'
                    '"header_name":"x-correlation-id","header_count":1}'
                )
            },
        ]
        lookup = [
            {
                "message": (
                    '{"event":"bridgefu_correlation_evidence",'
                    '"operation":"connect_lookup","result":"available",'
                    '"correlation_fingerprint":"123456abcdef"}'
                )
            }
        ]
        counts, times, results = COLLECTOR.log_evidence(
            runtime, lookup, "123456abcdef"
        )
        self.assertEqual(counts, {"contact_started": 1})
        self.assertEqual(times, {"contact_started": "2026-08-01T12:00:01Z"})
        self.assertEqual(results, ["available"])
        self.assertTrue(
            COLLECTOR.sip_invite_header_evidence(runtime, "123456abcdef")
        )
        runtime[-1]["message"] = runtime[-1]["message"].replace(
            '"header_count":1', '"header_count":2'
        )
        self.assertFalse(
            COLLECTOR.sip_invite_header_evidence(runtime, "123456abcdef")
        )

    def test_marker_latency_matches_observed_subsequence_and_rejects_tampering(self):
        sent = [1_000, 2_000, 3_000, 4_000, 5_000, 6_000]
        observed = [1_250, 2_250, 3_250, 4_250, 5_250]
        self.assertEqual(COLLECTOR.marker_latency_ms(sent, observed), 250.0)
        with self.assertRaises(COLLECTOR.EvidenceError):
            COLLECTOR.marker_latency_ms(sent, [900, 2_250, 3_250])
        with self.assertRaises(COLLECTOR.EvidenceError):
            COLLECTOR.marker_latency_ms(sent, [1_250, 2_250, 12_000])

    def test_qualification_source_parser_accepts_only_global_ipv4(self):
        self.assertEqual(COLLECTOR.parse_public_ipv4("8.8.8.8\n"), "8.8.8.8")
        for value in ("127.0.0.1", "10.0.0.1", "::1", "not-an-address"):
            with self.subTest(value=value):
                with self.assertRaises(COLLECTOR.EvidenceError):
                    COLLECTOR.parse_public_ipv4(value)

    def test_observer_and_call_schemas_fail_closed(self):
        participant = self.participant()
        source = self.source()
        call = self.call()
        COLLECTOR.validate_schema(participant, COLLECTOR.PARTICIPANT_SCHEMA)
        COLLECTOR.validate_schema(source, COLLECTOR.SOURCE_SCHEMA)
        COLLECTOR.validate_schema(call, COLLECTOR.CALL_SCHEMA)
        COLLECTOR.validate_schema(
            self.vapi_source(), COLLECTOR.VAPI_SOURCE_SCHEMA
        )

        vapi_call = copy.deepcopy(call)
        vapi_call["scenario_id"] = "vapi-web-transfer"
        vapi_call["observations"].update(
            {
                "source_producer": "bridgefu-vapi-web-playwright@1",
                "source_site_bundle_sha256": "d" * 64,
                "vapi_call_contract_verified": True,
                "attachment_replay_rejected": None,
            }
        )
        COLLECTOR.validate_schema(vapi_call, COLLECTOR.CALL_SCHEMA)

        source["signaling"]["transport"] = "udp"
        with self.assertRaises(jsonschema.ValidationError):
            COLLECTOR.validate_schema(source, COLLECTOR.SOURCE_SCHEMA)
        call["observations"]["runtime_lifecycle_stages"].pop()
        with self.assertRaises(jsonschema.ValidationError):
            COLLECTOR.validate_schema(call, COLLECTOR.CALL_SCHEMA)

    def test_correlation_derivation_matches_the_lambda_contract(self):
        self.assertEqual(
            COLLECTOR.derive_correlation_id(
                "k" * 32,
                "bft-test1234",
                "org_test",
                "call_test",
            ),
            "bf1_NlBgAHb4u7HAun9Uajj4Ijfx0UncXTSClFf7Q1kUEd0",
        )
        with self.assertRaises(COLLECTOR.EvidenceError):
            COLLECTOR.derive_correlation_id("k" * 32, "bad|id", "org", "call")

    def test_packaged_direct_calls_use_the_prebuilt_release_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "target/release/examples/recipe_sip_source"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"binary")
            executable.chmod(0o755)
            with mock.patch.object(COLLECTOR, "ROOT", root), mock.patch.dict(
                COLLECTOR.os.environ,
                {"BRIDGEFU_PACKAGED_SOURCE": "1"},
            ):
                command = COLLECTOR.sip_source_command(
                    Path("session.json"), Path("source.json"), 180
                )
            self.assertEqual(command[0], str(executable))
            self.assertNotIn("cargo", command)

            executable.chmod(0o644)
            with mock.patch.object(COLLECTOR, "ROOT", root), mock.patch.dict(
                COLLECTOR.os.environ,
                {"BRIDGEFU_PACKAGED_SOURCE": "1"},
            ):
                with self.assertRaises(COLLECTOR.EvidenceError):
                    COLLECTOR.sip_source_command(
                        Path("session.json"), Path("source.json"), 180
                    )

    def test_vapi_call_contract_requires_owned_assistant_and_both_tools(self):
        call = {
            "id": "call_test",
            "assistantId": "assistant_test",
            "orgId": "org_test",
            "status": "ended",
            "endedReason": "assistant-forwarded-call",
            "artifact": {
                "messages": [
                    {"toolName": "prepare_handoff"},
                    {"name": "transferCall"},
                ]
            },
        }
        session = {"source_call_id": "call_test"}
        COLLECTOR.verify_vapi_call_contract(call, session, "assistant_test")
        call["artifact"]["messages"].pop()
        with self.assertRaises(COLLECTOR.EvidenceError):
            COLLECTOR.verify_vapi_call_contract(call, session, "assistant_test")

    def test_scenarios_follow_the_deployed_sip_posture(self):
        self.assertEqual(
            COLLECTOR.scenario_contract("vapi-web-transfer", "sip_rtp"),
            ("sip_rtp", "negotiated"),
        )
        self.assertEqual(
            COLLECTOR.scenario_contract("vapi-web-transfer", "sips_srtp"),
            ("sips_srtp", "negotiated"),
        )
        self.assertEqual(
            COLLECTOR.scenario_contract("sip-rtp-pcmu", "sip_rtp"),
            ("sip_rtp", "pcmu"),
        )
        with self.assertRaises(COLLECTOR.EvidenceError):
            COLLECTOR.scenario_contract("sips-srtp-pcmu", "sip_rtp")
        with self.assertRaises(COLLECTOR.EvidenceError):
            COLLECTOR.scenario_contract("vapi-web-transfer", "unsupported")

        vapi_harness = COLLECTOR.VAPI_HARNESS.read_text(encoding="utf-8")
        self.assertIn(
            '!["sips_srtp", "sip_rtp"].includes(session.security)',
            vapi_harness,
        )

    def test_site_bundle_extractor_rejects_path_or_file_set_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "site.zip"
            with zipfile.ZipFile(bundle, "w") as archive:
                for name in sorted(COLLECTOR.SITE_FILES):
                    archive.writestr(name, b"safe")
            COLLECTOR.extract_site_bundle(bundle, root / "site")
            self.assertEqual(
                {path.name for path in (root / "site").iterdir()},
                COLLECTOR.SITE_FILES,
            )

            unsafe = root / "unsafe.zip"
            with zipfile.ZipFile(unsafe, "w") as archive:
                archive.writestr("../outside", b"unsafe")
            with self.assertRaises(COLLECTOR.EvidenceError):
                COLLECTOR.extract_site_bundle(unsafe, root / "unsafe")

    def test_redaction_rejects_raw_identifiers_and_sensitive_keys(self):
        COLLECTOR.reject_sensitive_evidence(self.call())
        with self.assertRaises(COLLECTOR.EvidenceError):
            COLLECTOR.reject_sensitive_evidence(
                {"value": "bf1_" + "A" * 43, "redacted": True}
            )
        with self.assertRaises(COLLECTOR.EvidenceError):
            COLLECTOR.reject_sensitive_evidence({"contact_id": "opaque"})

    def test_contract_binds_both_real_observer_sources(self):
        COLLECTOR.contract(None)
        source_digest = COLLECTOR.sha256_file(COLLECTOR.SOURCE_HARNESS)
        browser_digest = COLLECTOR.sha256_file(COLLECTOR.AGENT_HARNESS)
        self.assertRegex(source_digest, r"^[0-9a-f]{64}$")
        self.assertRegex(browser_digest, r"^[0-9a-f]{64}$")
        self.assertNotEqual(source_digest, browser_digest)


if __name__ == "__main__":
    unittest.main()
