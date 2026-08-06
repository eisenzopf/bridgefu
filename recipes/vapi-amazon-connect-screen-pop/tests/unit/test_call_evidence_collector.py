from __future__ import annotations

import ast
import contextlib
import copy
import importlib.util
import json
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
    def test_agent_failure_detail_only_exposes_allowlisted_prefix(self):
        safe = mock.Mock()
        safe.communicate.return_value = (
            "",
            "error: Agent Workspace could not select Available: locator detail\n",
        )
        unsafe = mock.Mock()
        unsafe.communicate.return_value = ("", "error: credential=value\n")
        self.assertEqual(
            COLLECTOR.agent_failure_detail(safe),
            "Agent Workspace could not select Available",
        )
        self.assertIsNone(COLLECTOR.agent_failure_detail(unsafe))

    def test_source_failure_detail_only_exposes_allowlisted_prefix(self):
        safe = mock.Mock()
        safe.communicate.return_value = (
            "",
            "Error: agent-to-source DTMF was not observed\n",
        )
        unsafe = mock.Mock()
        unsafe.communicate.return_value = ("", "Error: private-session-secret\n")
        self.assertEqual(
            COLLECTOR.source_failure_detail(safe),
            "agent-to-source DTMF was not observed",
        )
        self.assertIsNone(COLLECTOR.source_failure_detail(unsafe))

        vapi = mock.Mock()
        vapi.communicate.return_value = (
            "",
            "error: stock Vapi webCall did not start: provider detail\n",
        )
        self.assertEqual(
            COLLECTOR.source_failure_detail(vapi),
            "stock Vapi webCall did not start",
        )

    def test_vapi_browser_stderr_is_captured_for_allowlisted_diagnostics(self):
        source = COLLECTOR_PATH.read_text()
        browser_block = source.split("browser = subprocess.Popen(", 1)[1].split(
            ")\n", 1
        )[0]
        self.assertIn("stderr=subprocess.PIPE", browser_block)
        self.assertIn(
            'raise source_failure(\n                process,\n                "protected browser source stopped before its handshake",',
            source,
        )

    def test_direct_source_pairs_in_band_and_rfc4733_dtmf(self):
        source = (ROOT / "examples" / "recipe_sip_source.rs").read_text()
        in_band = source.index("send_in_band_dtmf_five(&sender")
        rfc4733 = source.index(".send_dtmf('5')", in_band)
        self.assertLess(in_band, rfc4733)
        self.assertIn("DTMF_FIVE_LOW_FREQUENCY: f32 = 770.0", source)
        self.assertIn("DTMF_FIVE_HIGH_FREQUENCY: f32 = 1_336.0", source)
        self.assertIn("DTMF_SIX_LOW_FREQUENCY: f64 = 770.0", source)
        self.assertIn("DTMF_SIX_HIGH_FREQUENCY: f64 = 1_477.0", source)
        self.assertIn("if !in_band_agent_dtmf && !rfc4733_agent_dtmf", source)
        remote_bye = source.index("agent BYE observer stopped")
        replay_settle = source.index(
            "tokio::time::sleep(Duration::from_millis(500)).await", remote_bye
        )
        replay_invite = source.index("let replay_call_id = control", replay_settle)
        self.assertLess(remote_bye, replay_settle)
        self.assertLess(replay_settle, replay_invite)

    def test_agent_probe_pairs_keypad_with_audible_dtmf_six(self):
        source = (
            RECIPE / "qualification/agent-workspace-playwright.mjs"
        ).read_text()
        self.assertIn("AGENT_DTMF_SIX_LOW_HZ = 770", source)
        self.assertIn("AGENT_DTMF_SIX_HIGH_HZ = 1_477", source)
        self.assertIn("const inDtmfSix =", source)
        marker_probe = source.split("if (inPulse) {", 1)[1].split(
            "} else if (inDtmfSix)", 1
        )[0]
        self.assertIn("AGENT_MARKER_HZ", marker_probe)
        self.assertIn("AGENT_DTMF_SIX_LOW_HZ", marker_probe)
        self.assertIn("AGENT_DTMF_SIX_HIGH_HZ", marker_probe)
        keypad = source.index("const keypadOpened = await clickButton")
        digit = source.index("const keypadDigitSent = keypadOpened", keypad)
        streams = source.index('sendDigitsViaConnectStreams(page, "6")', digit)
        media_wait = source.index(
            '"Agent Workspace media/DTMF browser observations did not converge"'
        )
        self.assertLess(keypad, digit)
        self.assertLess(digit, streams)
        self.assertLess(streams, media_wait)
        self.assertIn("/Number pad/i", source[keypad:digit])
        self.assertIn(
            'clickNestedNumberPadDigit(page, "6", 1_500)', source[digit:streams]
        )
        nested_helper = source.split(
            "async function clickNestedNumberPadDigit", 1
        )[1].split("async function sendDigitsViaConnectStreams", 1)[0]
        self.assertIn('iframe[title="Contact Control Panel Number Pad"]', nested_helper)
        self.assertIn("frameHandle?.contentFrame()", nested_helper)
        self.assertIn('numberPad.getByRole("button"', nested_helper)
        streams_helper = source.split(
            "async function sendDigitsViaConnectStreams", 1
        )[1].split("async function buttonVisible", 1)[0]
        self.assertIn("const agent = new streams.Agent()", streams_helper)
        self.assertIn("contact.getActiveInitialConnection?.()", streams_helper)
        self.assertIn("connection.sendDigits(value, callbacks)", streams_helper)

    def test_cloudformation_descriptions_use_exact_stack_ids(self):
        for path, minimum_helper_uses in (
            (COLLECTOR_PATH, 4),
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
                    source.count("LIVE.deployed_recipe_stack_id("),
                    minimum_helper_uses,
                )
                tree = ast.parse(source)
                nested_calls = [
                    node
                    for node in ast.walk(tree)
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "LIVE"
                    and node.func.attr == "nested_stack_id"
                ]
                self.assertTrue(nested_calls)
                for call in nested_calls:
                    self.assertEqual(len(call.args), 4)

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
        runtime = [
            {
                "message": json.dumps(
                    {"log": f'{event["message"]}\n', "stream": "stdout"}
                )
            }
            for event in runtime
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
        envelope = json.loads(runtime[-1]["message"])
        envelope["log"] = envelope["log"].replace(
            '"header_count":1', '"header_count":2'
        )
        runtime[-1]["message"] = json.dumps(envelope)
        self.assertFalse(
            COLLECTOR.sip_invite_header_evidence(runtime, "123456abcdef")
        )

    def test_marker_latency_matches_observed_subsequence_and_rejects_tampering(self):
        sent = [1_000, 2_000, 3_000, 4_000, 5_000, 6_000]
        observed = [1_250, 2_250, 3_250, 4_250, 5_250]
        self.assertEqual(COLLECTOR.marker_latency_ms(sent, observed), 250.0)
        self.assertEqual(
            COLLECTOR.marker_latency_ms(sent, [*observed, 6_250, 7_000]), 250.0
        )
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

    def test_fresh_direct_call_validates_before_creating_the_attachment(self):
        args = COLLECTOR.argparse.Namespace(
            execution_id="bft-test1234",
            confirm="bft-test1234",
            scenario="sip-rtp-pcmu",
            hangup_origin="source",
            network_profile="baseline",
            connect_url="https://example.my.connect.aws/agent-app-v2/",
            storage_state=Path("storage.json"),
            observer_timeout_seconds=180,
            wait_seconds=120,
            headed=False,
        )
        order: list[str] = []
        deployment = (Path("ledger.json"), {"execution_id": args.execution_id}, {})
        session = Path("fresh.private.json")
        participant = Path("participant.json")
        source = Path("source.json")
        screenshot = Path("screenshot.png")

        @contextlib.contextmanager
        def controlled(*_arguments):
            order.append("network")
            observation = {"controller": "test", "removed_after_call": False}
            yield observation
            observation["removed_after_call"] = True
            order.append("network-cleanup")

        with mock.patch.object(
            COLLECTOR,
            "stable_deployment",
            side_effect=lambda _execution_id: (order.append("validate"), deployment)[1],
        ) as stable, mock.patch.object(
            COLLECTOR,
            "controlled_network",
            side_effect=controlled,
        ) as network, mock.patch.object(
            COLLECTOR.secrets,
            "token_hex",
            return_value="0123456789abcdef01234567",
        ), mock.patch.object(
            COLLECTOR,
            "create_direct_session",
            side_effect=lambda *_arguments, **_keywords: (
                order.append("reserve"),
                session,
            )[1],
        ) as create, mock.patch.object(
            COLLECTOR,
            "run_direct_with_deployment",
            side_effect=lambda *_arguments: (
                order.append("observe"),
                (session, participant, source, screenshot),
            )[1],
        ) as observe:
            with mock.patch.object(
                COLLECTOR,
                "write_network_observation",
                side_effect=lambda *_arguments: (
                    order.append("retain-network"),
                    Path("network.json"),
                )[1],
            ) as retain, mock.patch.object(
                COLLECTOR,
                "collect",
                side_effect=lambda *_arguments: order.append("collect"),
            ) as collect:
                COLLECTOR.run_direct_fresh(args)

        self.assertEqual(
            order,
            [
                "validate",
                "network",
                "reserve",
                "observe",
                "network-cleanup",
                "retain-network",
                "collect",
            ],
        )
        stable.assert_called_once_with(args.execution_id)
        network.assert_called_once_with(
            *deployment,
            args.network_profile,
            "0123456789abcdef01234567",
        )
        create.assert_called_once_with(
            args,
            *deployment,
            session_id="0123456789abcdef01234567",
        )
        observed_args = observe.call_args.args[0]
        self.assertEqual(observed_args.session, session)
        self.assertTrue(observe.call_args.args[-1]["removed_after_call"])
        retain.assert_called_once_with(
            *deployment[:2],
            observe.call_args.args[-1],
        )
        collected_args = collect.call_args.args[0]
        self.assertEqual(collected_args.session, session)
        self.assertEqual(collected_args.participant_observation, participant)
        self.assertEqual(collected_args.source_observation, source)
        self.assertEqual(collected_args.screenshot, screenshot)
        self.assertEqual(collected_args.network_observation, Path("network.json"))

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
