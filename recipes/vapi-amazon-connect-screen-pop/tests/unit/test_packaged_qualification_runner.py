from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import shutil
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


RECIPE = Path(__file__).resolve().parents[2]
ROOT = RECIPE.parents[1]
RUNNER_PATH = ROOT / "scripts" / "run-aws-packaged-qualification.py"
SPEC = importlib.util.spec_from_file_location(
    "bridgefu_packaged_qualification", RUNNER_PATH
)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("unable to load packaged qualification runner")
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class PackagedQualificationRunnerTests(unittest.TestCase):
    def test_connect_agent_availability_is_exact_and_idempotent(self):
        ledger = {
            "execution_id": "bft-test1234",
            "connect_mode": "disposable",
            "connect_instance_arn": (
                "arn:aws:connect:us-west-2:123456789012:instance/instance-1"
            ),
            "partition": "aws",
            "region": "us-west-2",
            "account_id": "123456789012",
        }
        responses = [
            {
                "UserSummaryList": [
                    {
                        "Username": "bridgefu-demo-agent",
                        "Id": "user-1",
                        "Arn": ledger["connect_instance_arn"] + "/agent/user-1",
                    }
                ]
            },
            {
                "AgentStatusSummaryList": [
                    {
                        "Name": "Available",
                        "Type": "ROUTABLE",
                        "Id": "status-1",
                        "Arn": (
                            ledger["connect_instance_arn"]
                            + "/agent-state/status-1"
                        ),
                    }
                ]
            },
        ]
        completed = RUNNER.subprocess.CompletedProcess(
            [],
            255,
            "",
            "InvalidRequestException: User already in requested status",
        )
        with mock.patch.object(
            RUNNER.LIVE, "assume_env", return_value={"AWS_REGION": "us-west-2"}
        ), mock.patch.object(
            RUNNER.LIVE, "aws_json", side_effect=responses
        ), mock.patch.object(
            RUNNER.subprocess, "run", return_value=completed
        ) as put:
            RUNNER.ensure_connect_agent_available(ledger, "bridgefu-demo-agent")

        invocation = put.call_args.args[0]
        self.assertIn("put-user-status", invocation)
        self.assertEqual(invocation[invocation.index("--user-id") + 1], "user-1")
        self.assertEqual(
            invocation[invocation.index("--agent-status-id") + 1], "status-1"
        )

    def test_connect_agent_availability_rejects_an_ambiguous_user(self):
        ledger = {
            "execution_id": "bft-test1234",
            "connect_mode": "disposable",
            "connect_instance_arn": (
                "arn:aws:connect:us-west-2:123456789012:instance/instance-1"
            ),
            "partition": "aws",
            "region": "us-west-2",
            "account_id": "123456789012",
        }
        duplicate = {
            "Username": "bridgefu-demo-agent",
            "Id": "user-1",
            "Arn": ledger["connect_instance_arn"] + "/agent/user-1",
        }
        with mock.patch.object(
            RUNNER.LIVE, "assume_env", return_value={"AWS_REGION": "us-west-2"}
        ), mock.patch.object(
            RUNNER.LIVE,
            "aws_json",
            side_effect=[
                {"UserSummaryList": [duplicate, duplicate]},
                {"AgentStatusSummaryList": []},
            ],
        ), self.assertRaisesRegex(RUNNER.RunnerError, "lookup was not exact"):
            RUNNER.ensure_connect_agent_available(ledger, "bridgefu-demo-agent")

    def test_packaged_state_root_is_private_isolated_and_matches_live_override(self):
        container, state_root = RUNNER.create_packaged_state_root()
        try:
            self.assertEqual(state_root.parts[-2:], ("bridgefu", "aws-live"))
            self.assertFalse(state_root.is_relative_to(ROOT.resolve()))
            self.assertNotIn("target", state_root.parts)
            for directory in (container, state_root.parent, state_root):
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            environment = os.environ.copy()
            environment[RUNNER.LIVE_STATE_OVERRIDE_ENV] = os.fspath(state_root)
            self.assertEqual(
                environment[RUNNER.LIVE_STATE_OVERRIDE_ENV], str(state_root)
            )
        finally:
            shutil.rmtree(container)

    def test_smoke_is_quick_and_full_is_the_exact_twelve_call_matrix(self):
        scenarios = ["sip-rtp-pcmu", "sip-rtp-pcma", "vapi-web-transfer"]
        smoke = RUNNER.qualification_jobs(
            "smoke", ["sip-rtp-pcmu", "vapi-web-transfer"]
        )
        full = RUNNER.qualification_jobs("full", scenarios)
        self.assertEqual(len(smoke), 4)
        self.assertEqual({job[1] for job in smoke}, {"baseline"})
        self.assertEqual(len(full), 12)
        self.assertEqual(
            (len(full) - 1) * RUNNER.FULL_CALL_INTERVAL_SECONDS,
            55 * 60,
        )
        self.assertTrue(60 * 60 <= RUNNER.FULL_SOAK_FINISH_SECONDS <= 65 * 60)
        self.assertEqual(
            len(RUNNER.HTTP_NEGATIVES) + len(RUNNER.SIP_NEGATIVES) + 2,
            9,
        )
        self.assertEqual(
            set(RUNNER.FAILURE_DRILLS),
            {"process_restart", "dependency_timeout", "host_recovery"},
        )
        self.assertEqual(
            set(full),
            {
                (scenario, network, origin)
                for scenario in scenarios
                for network in ("baseline", "moderate-wan")
                for origin in ("source", "agent")
            },
        )

    def test_direct_call_reserves_and_observes_in_one_collector_process(self):
        retained = Path("/private/call-evidence/direct.json")
        with mock.patch.object(
            RUNNER, "command", return_value=os.fspath(retained)
        ) as command, mock.patch.object(
            RUNNER, "output_path", return_value=retained
        ):
            result = RUNNER.run_call(
                "bft-test1234",
                "sip-rtp-pcmu",
                "baseline",
                "source",
                "https://example.my.connect.aws/agent-app-v2/",
                Path("/private/storage.json"),
                {"BRIDGEFU_PACKAGED_SOURCE": "1"},
                Path("/private"),
            )

        self.assertEqual(result, retained)
        invocation = command.call_args.args[0]
        self.assertIn("run-direct-fresh", invocation)
        self.assertNotIn("start-direct", invocation)
        self.assertNotIn("run-direct", invocation)
        self.assertEqual(invocation[invocation.index("--scenario") + 1], "sip-rtp-pcmu")
        self.assertEqual(invocation[invocation.index("--hangup-origin") + 1], "source")
        self.assertEqual(invocation[invocation.index("--network-profile") + 1], "baseline")

    def test_official_archive_excludes_ledger_release_and_private_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public = {
                "call-evidence/one.json": {"passed": True},
                "failure-evidence/process_restart.json": {"passed": True},
                "negative-evidence/rejected.json": {"passed": True},
                "soak-evidence.json": {"passed": True},
                "zero-state-pre-lifecycle-evidence.json": {"active_calls": 0},
            }
            for relative, value in public.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(value))
            (root / "ledger.json").write_text('{"secret":"arn"}')
            (root / "call-sessions").mkdir()
            (root / "call-sessions" / "raw.private.json").write_text("{}")
            (root / "call-evidence" / "raw.private.json").write_text("{}")
            (root / "release").mkdir()
            (root / "release" / "manifest.json").write_text("{}")

            inventory = RUNNER.official_evidence_inventory(root)
            self.assertEqual({item["path"] for item in inventory}, set(public))
            RUNNER.private_json(
                root / "runner-summary.json",
                {"schema_version": 1, "official_evidence": inventory},
            )
            archive = root / "archive.tar.gz"
            RUNNER.archive_evidence(root, archive, inventory)
            with tarfile.open(archive, "r:gz") as bundle:
                self.assertEqual(
                    {item.name for item in bundle.getmembers()},
                    set(public) | {"runner-summary.json"},
                )

    def test_full_input_rejects_a_partial_scenario_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "execution_id": "bft-test1234",
                        "suite": "full",
                        "scenarios": ["sip-rtp-pcmu", "vapi-web-transfer"],
                        "connect_url": "https://example.my.connect.aws/agent-app-v2/",
                        "agent_credential_secret_arn": "arn:agent",
                        "vapi_public_key_secret_arn": "arn:vapi",
                        "ledger": {"execution_id": "bft-test1234"},
                        "evidence_bucket": "bucket",
                        "evidence_key": "key",
                    }
                )
            )
            with self.assertRaises(RUNNER.RunnerError):
                RUNNER.load_input(path)

    def test_full_input_accepts_the_exact_ip_only_execution_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            ledger = {
                "execution_id": "bft-test1234",
                "runtime_profile": "starter",
                "sip_security": "sip_rtp",
                "connect_login_url": ("https://example.my.connect.aws/agent-app-v2/"),
                "agent_credential_secret_arn": "arn:agent",
                "vapi_public_key_secret_arn": "arn:vapi",
                "artifact_bucket": "bucket",
            }
            recovery_authority = {
                "schema_version": 1,
                "authority_kind": "initialized_execution",
                "execution_id": "bft-test1234",
            }
            ledger["recovery_authority_sha256"] = RUNNER.canonical_json_sha256(
                recovery_authority
            )
            value = {
                "schema_version": 1,
                "execution_id": "bft-test1234",
                "suite": "full",
                "scenarios": [
                    "sip-rtp-pcmu",
                    "sip-rtp-pcma",
                    "vapi-web-transfer",
                ],
                "connect_url": ledger["connect_login_url"],
                "agent_credential_secret_arn": "arn:agent",
                "vapi_public_key_secret_arn": "arn:vapi",
                "ledger": ledger,
                "recovery_authority": recovery_authority,
                "evidence_bucket": "bucket",
                "evidence_key": (
                    "qualification/bft-test1234/runs/" "full-1785690000/evidence.tar.gz"
                ),
            }
            path.write_text(json.dumps(value))
            os.chmod(path, 0o600)
            self.assertEqual(RUNNER.load_input(path), value)

    def test_release_materialization_pins_versions_and_verifies_digests(self):
        demo = b"immutable demo bundle"
        runtime = b"immutable runtime bundle"
        qualification_archive = b"immutable qualification archive"
        header = bytearray(20)
        header[:6] = b"\x7fELF\x02\x01"
        header[18:20] = b"\x3e\x00"
        binaries = {
            "target/release/examples/recipe_sip_source": (
                bytes(header) + b"source\0GLIBC_2.31\0"
            ),
            "target/release/examples/recipe_sip_negative": (
                bytes(header) + b"negative\0GLIBC_2.31\0"
            ),
        }
        builder_images = RUNNER.qualification_builder_images()
        builder_configuration = RUNNER.qualification_builder_configuration()
        qualification_dockerfile = (
            RUNNER.ROOT / "deploy" / "Dockerfile.qualification"
        ).read_bytes()
        runtime_manifest = (
            json.dumps(
                {
                    "schema_version": 1,
                    "recipe": "vapi-amazon-connect-screen-pop",
                    "artifact": {
                        "path": "starter-runtime.zip",
                        "sha256": hashlib.sha256(runtime).hexdigest(),
                        "size_bytes": len(runtime),
                    },
                }
            )
            + "\n"
        ).encode()
        qualification_manifest = (
            json.dumps(
                {
                    "schema_version": 2,
                    "source_tree_sha256": "b" * 64,
                    "archive": {
                        "path": "qualification-source.zip",
                        "sha256": hashlib.sha256(qualification_archive).hexdigest(),
                        "size_bytes": len(qualification_archive),
                    },
                    "binary_platform": "linux/amd64",
                    "builder": {
                        "host_platform": "linux/amd64",
                        "image": builder_images["linux/amd64"],
                        "images": builder_images,
                        **builder_configuration,
                        "binary_glibc": {
                            "recipe_sip_source": "2.31",
                            "recipe_sip_negative": "2.31",
                        },
                    },
                    "qualification_binaries": list(binaries),
                    "files": [
                        {
                            "path": path,
                            "sha256": hashlib.sha256(payload).hexdigest(),
                            "size_bytes": len(payload),
                        }
                        for path, payload in binaries.items()
                    ],
                }
            )
            + "\n"
        ).encode()
        payloads = {
            "artifacts/demo-site/demo-site.zip": demo,
            "artifacts/runtime/starter-runtime.zip": runtime,
            "artifacts/runtime/manifest.json": runtime_manifest,
            "artifacts/qualification/manifest.json": qualification_manifest,
            "artifacts/qualification/qualification-source.zip": qualification_archive,
        }
        manifest_value = {
            "bridgefu": {
                "source_tree_sha256": "b" * 64,
                "image_uri": f"example.test/bridgefu@sha256:{'c' * 64}",
            },
            "artifacts": [
                {
                    "path": relative,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size_bytes": len(payload),
                }
                for relative, payload in payloads.items()
            ],
        }
        manifest = (json.dumps(manifest_value) + "\n").encode()
        manifest_digest = hashlib.sha256(manifest).hexdigest()
        records = {
            "manifest.json": {
                "key": "qualification/bft-test1234/release/manifest.json",
                "version_id": "manifest-version",
                "sha256": manifest_digest,
                "size_bytes": len(manifest),
            },
        }
        records.update(
            {
                relative: {
                    "key": f"qualification/bft-test1234/release/{relative}",
                    "version_id": f"version-{index}",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size_bytes": len(payload),
                }
                for index, (relative, payload) in enumerate(payloads.items(), 1)
            }
        )
        ledger = {
            "artifact_bucket": "bucket",
            "published_objects": records,
            "release_manifest_sha256": manifest_digest,
            "publication_source_tree_sha256": "b" * 64,
            "bridgefu_image_uri": f"example.test/bridgefu@sha256:{'c' * 64}",
        }
        calls: list[list[str]] = []

        def download(arguments, *, env=None):
            del env
            calls.append(arguments)
            key = arguments[arguments.index("--key") + 1]
            destination = Path(arguments[-2])
            relative = key.split("/release/", 1)[1]
            destination.write_bytes(
                manifest if relative == "manifest.json" else payloads[relative]
            )
            return "{}"

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            RUNNER, "command", side_effect=download
        ), mock.patch.object(RUNNER, "ROOT", Path(directory)):
            execution = Path(directory)
            packaged_dockerfile = execution / "deploy" / "Dockerfile.qualification"
            packaged_dockerfile.parent.mkdir(parents=True)
            packaged_dockerfile.write_bytes(qualification_dockerfile)
            for relative, payload in binaries.items():
                binary = execution / relative
                binary.parent.mkdir(parents=True, exist_ok=True)
                binary.write_bytes(payload)
                os.chmod(binary, 0o700)
            RUNNER.materialize_release_artifacts(ledger, "us-west-2", execution)
            self.assertEqual(
                (execution / "release/manifest.json").read_bytes(), manifest
            )
            self.assertEqual(
                (execution / "release/artifacts/demo-site/demo-site.zip").read_bytes(),
                demo,
            )
        self.assertEqual(
            {call[call.index("--version-id") + 1] for call in calls},
            {
                "manifest-version",
                "version-1",
                "version-2",
                "version-3",
                "version-4",
            },
        )

    def test_qualification_builder_contract_rejects_mismatched_image(self):
        images = RUNNER.qualification_builder_images()
        configuration = RUNNER.qualification_builder_configuration()
        contract = {
            "host_platform": "linux/arm64",
            "image": images["linux/arm64"],
            "images": images,
            **configuration,
            "binary_glibc": {
                "recipe_sip_source": "2.31",
                "recipe_sip_negative": "2.31",
            },
        }
        self.assertEqual(
            RUNNER.validate_qualification_builder(contract),
            contract["binary_glibc"],
        )
        contract["image"] = images["linux/amd64"]
        with self.assertRaisesRegex(RUNNER.RunnerError, "builder contract"):
            RUNNER.validate_qualification_builder(contract)
        contract["image"] = images["linux/arm64"]
        contract["rust_toolchain"] = "1.96.0"
        with self.assertRaisesRegex(RUNNER.RunnerError, "builder contract"):
            RUNNER.validate_qualification_builder(contract)


if __name__ == "__main__":
    unittest.main()
