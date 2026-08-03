from __future__ import annotations

import errno
import base64
import copy
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "scripts" / "aws-recipe-live-test.py"
SPEC = importlib.util.spec_from_file_location("aws_recipe_live_state", SCRIPT)
assert SPEC and SPEC.loader
LIVE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LIVE
SPEC.loader.exec_module(LIVE)


class LiveStateStorageTests(unittest.TestCase):
    def state_environment(self, parent: Path) -> dict[str, str]:
        root = parent.resolve() / "bridgefu" / "aws-live"
        return {LIVE.LIVE_STATE_OVERRIDE_ENV: os.fspath(root)}

    def test_default_xdg_and_override_roots_are_private_and_outside_repo(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            home = base / "home"
            home.mkdir(mode=0o700)
            with mock.patch.dict(LIVE.os.environ, {}, clear=True), mock.patch.object(
                LIVE.Path, "home", return_value=home
            ):
                expected = home / ".local" / "state" / "bridgefu" / "aws-live"
                self.assertEqual(LIVE.live_state_root(), expected)
                self.assertEqual(LIVE.ensure_live_state_root(), expected)
                self.assertEqual(expected.stat().st_mode & 0o777, 0o700)
                self.assertFalse(expected.is_relative_to(ROOT))

            xdg = base / "xdg"
            xdg.mkdir(mode=0o700)
            with mock.patch.dict(
                LIVE.os.environ, {"XDG_STATE_HOME": os.fspath(xdg)}, clear=True
            ):
                self.assertEqual(
                    LIVE.live_state_root(), xdg / "bridgefu" / "aws-live"
                )

            override_parent = base / "override"
            override_parent.mkdir(mode=0o700)
            environment = self.state_environment(override_parent)
            with mock.patch.dict(LIVE.os.environ, environment, clear=True):
                self.assertEqual(
                    LIVE.ensure_live_state_root(),
                    override_parent / "bridgefu" / "aws-live",
                )

    def test_state_root_rejects_symlinks_repo_target_and_relative_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            real = base / "real"
            real.mkdir(mode=0o700)
            linked = base / "linked"
            linked.symlink_to(real, target_is_directory=True)
            with mock.patch.dict(
                LIVE.os.environ, {"XDG_STATE_HOME": os.fspath(linked)}, clear=True
            ):
                with self.assertRaisesRegex(LIVE.LiveTestError, "symlinks"):
                    LIVE.live_state_root()

            invalid = (
                Path("relative/bridgefu/aws-live"),
                ROOT / "durable" / "bridgefu" / "aws-live",
                base / "safe" / "target" / "bridgefu" / "aws-live",
            )
            for candidate in invalid:
                with self.subTest(candidate=candidate), mock.patch.dict(
                    LIVE.os.environ,
                    {LIVE.LIVE_STATE_OVERRIDE_ENV: os.fspath(candidate)},
                    clear=True,
                ):
                    with self.assertRaises(LIVE.LiveTestError):
                        LIVE.live_state_root()

    def test_atomic_json_is_private_and_preserves_old_json_on_write_failure(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            LIVE.os.environ, self.state_environment(Path(directory)), clear=True
        ):
            path = LIVE.ensure_live_state_root() / "bft-safe1" / "ledger.json"
            LIVE.atomic_json(path, {"version": "old"})
            details = path.stat()
            self.assertTrue(stat.S_ISREG(details.st_mode))
            self.assertEqual(details.st_uid, os.getuid())
            self.assertEqual(details.st_nlink, 1)
            self.assertEqual(details.st_mode & 0o777, 0o600)

            real_write = LIVE.os.write
            calls = 0

            def interrupted_write(descriptor: int, value: bytes) -> int:
                nonlocal calls
                calls += 1
                if calls == 1:
                    return real_write(descriptor, value[:5])
                raise OSError(errno.ENOSPC, "simulated full filesystem")

            with mock.patch.object(LIVE.os, "write", side_effect=interrupted_write):
                with self.assertRaises(OSError):
                    LIVE.atomic_json(path, {"version": "new", "padding": "x" * 100})
            self.assertEqual(json.loads(path.read_text()), {"version": "old"})
            self.assertEqual(list(path.parent.glob(".*.tmp")), [])

    def test_atomic_and_durable_reads_reject_symlink_and_hardlink_targets(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            LIVE.os.environ, self.state_environment(Path(directory)), clear=True
        ):
            execution = LIVE.ensure_live_state_root() / "bft-safe1"
            execution.mkdir(mode=0o700)
            ledger = execution / "ledger.json"
            LIVE.atomic_json(ledger, {"execution_id": "bft-safe1"})
            alias = execution / "ledger-hardlink.json"
            os.link(ledger, alias)
            with self.assertRaisesRegex(LIVE.LiveTestError, "private"):
                LIVE.validate_durable_ledger(ledger, "bft-safe1")
            with self.assertRaisesRegex(LIVE.LiveTestError, "private"):
                LIVE.atomic_json(ledger, {"execution_id": "bft-safe1"})
            alias.unlink()

            outside = Path(directory) / "outside.json"
            outside.write_text("unchanged")
            symlink = execution / "symlink.json"
            symlink.symlink_to(outside)
            with self.assertRaisesRegex(LIVE.LiveTestError, "private"):
                LIVE.atomic_json(symlink, {"changed": True})
            self.assertEqual(outside.read_text(), "unchanged")

    def test_immutable_write_never_removes_a_preexisting_authority(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            LIVE.os.environ, self.state_environment(Path(directory)), clear=True
        ):
            execution = LIVE.ensure_live_state_root() / "bft-safe1"
            authority = execution / "recovery-authority.json"
            LIVE.immutable_private_json(authority, {"authority": "original"})
            before = authority.read_bytes()
            with self.assertRaises(FileExistsError):
                LIVE.immutable_private_json(authority, {"authority": "replacement"})
            self.assertEqual(authority.read_bytes(), before)

    def test_execution_lock_is_exclusive_and_inherited_reentry_is_safe(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            LIVE.os.environ, self.state_environment(Path(directory)), clear=True
        ):
            with LIVE.exclusive_state_lock("bft-safe1.lock"):
                with self.assertRaisesRegex(LIVE.LiveTestError, "holds"):
                    with LIVE.exclusive_state_lock("bft-safe1.lock"):
                        self.fail("a second independent lock acquisition succeeded")
            with LIVE.execution_lock("bft-safe1"):
                token = LIVE.os.environ[LIVE.LIVE_LOCK_TOKEN_ENV]
                with LIVE.execution_lock("bft-safe1"):
                    self.assertEqual(LIVE.os.environ[LIVE.LIVE_LOCK_TOKEN_ENV], token)
                descriptor = int(token.rsplit(":", 1)[1])
                child = LIVE.command(
                    [
                        sys.executable,
                        "-c",
                        (
                            "import os,sys;fd=int(sys.argv[1]);"
                            "\ntry: os.fstat(fd)"
                            "\nexcept OSError: print('closed')"
                            "\nelse: print('open')"
                        ),
                        str(descriptor),
                    ]
                )
                self.assertEqual(child.stdout.strip(), "closed")
            self.assertNotIn(LIVE.LIVE_LOCK_TOKEN_ENV, LIVE.os.environ)
            forged = "bft-safe1:" + "f" * 64 + ":0"
            with mock.patch.dict(
                LIVE.os.environ, {LIVE.LIVE_LOCK_TOKEN_ENV: forged}, clear=False
            ):
                with self.assertRaisesRegex(LIVE.LiveTestError, "not held"):
                    with LIVE.execution_lock("bft-safe1"):
                        self.fail("a forged inherited lock token bypassed flock")

    def test_lock_descriptor_survives_a_three_process_controller_chain(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            LIVE.os.environ, self.state_environment(Path(directory)), clear=True
        ):
            grandchild = (
                "import importlib.util,sys;"
                f"p={str(SCRIPT)!r};"
                "s=importlib.util.spec_from_file_location('grandchild_live',p);"
                "m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;"
                "s.loader.exec_module(m);"
                "c=m.execution_lock('bft-safe1');c.__enter__();print('locked');"
                "c.__exit__(None,None,None)"
            )
            child = (
                "import os,subprocess,sys;"
                "fd=int(os.environ['BRIDGEFU_AWS_LIVE_LOCK_TOKEN'].rsplit(':',1)[1]);"
                f"r=subprocess.run([sys.executable,'-c',{grandchild!r}],"
                "env=os.environ.copy(),pass_fds=(fd,),capture_output=True,text=True);"
                "print(r.stdout,end='');print(r.stderr,end='',file=sys.stderr);"
                "raise SystemExit(r.returncode)"
            )
            with LIVE.execution_lock("bft-safe1"):
                result = subprocess.run(
                    [sys.executable, "-c", child],
                    env=os.environ.copy(),
                    pass_fds=LIVE.live_lock_pass_fds(),
                    capture_output=True,
                    text=True,
                    check=False,
                )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "locked\n")

    def test_legacy_migration_survives_repository_target_deletion(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repository = base / "checkout"
            legacy = repository / "target" / "aws-live" / "bft-safe1"
            legacy.mkdir(parents=True)
            legacy_payload = {
                "schema_version": 1,
                "execution_id": "bft-safe1",
                "created_at": "2026-08-03T00:00:00Z",
                "qualification_deadline_at": "2026-08-03T08:00:00Z",
                "account_id": "123456789012",
                "partition": "aws",
                "region": "us-west-2",
                "project": LIVE.PROJECT,
                "managed_by": LIVE.MANAGED_BY,
                "recipe": LIVE.RECIPE,
                "stack_name": "bridgefu-bft-safe1",
                "qualification_stack_name": "bridgefu-bft-safe1-qualification",
                "bootstrap_stack_name": "bridgefu-bft-safe1-bootstrap",
                "artifact_bucket": "bridgefu-recipe-123456789012-us-west-2-bft-safe1",
                "ecr_repository": "bridgefu-test/bft-safe1",
                "connect_mode": "disposable",
                "max_usd": 200.0,
                "events": [],
            }
            (legacy / "ledger.json").write_text(json.dumps(legacy_payload))
            durable_parent = base / "durable"
            durable_parent.mkdir(mode=0o700)
            environment = self.state_environment(durable_parent)
            with mock.patch.dict(
                LIVE.os.environ, environment, clear=True
            ), mock.patch.object(LIVE, "root_dir", return_value=repository):
                path, migrated = LIVE.load_ledger("bft-safe1")
                before = hashlib.sha256(path.read_bytes()).hexdigest()
                self.assertEqual(migrated["execution_id"], "bft-safe1")
                self.assertEqual(migrated["state_revision"], 1)
                self.assertFalse((legacy / "ledger.json").exists())
                self.assertEqual(len(list(legacy.glob("ledger.migrated-*.json"))), 1)
                self.assertTrue((path.parent / "state-migration-evidence.json").is_file())
                shutil.rmtree(repository / "target")
                loaded_path, loaded = LIVE.load_ledger("bft-safe1")
                self.assertEqual(loaded, migrated)
                self.assertEqual(hashlib.sha256(loaded_path.read_bytes()).hexdigest(), before)

    def test_dual_legacy_and_durable_authorities_fail_closed_on_divergence(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repository = base / "checkout"
            legacy = repository / "target" / "aws-live" / "bft-safe1"
            legacy.mkdir(parents=True)
            payload = {
                "schema_version": 1,
                "execution_id": "bft-safe1",
                "created_at": "2026-08-03T00:00:00Z",
                "qualification_deadline_at": "2026-08-03T08:00:00Z",
                "account_id": "123456789012",
                "partition": "aws",
                "region": "us-west-2",
                "project": LIVE.PROJECT,
                "managed_by": LIVE.MANAGED_BY,
                "recipe": LIVE.RECIPE,
                "stack_name": "bridgefu-bft-safe1",
                "qualification_stack_name": "bridgefu-bft-safe1-qualification",
                "bootstrap_stack_name": "bridgefu-bft-safe1-bootstrap",
                "artifact_bucket": "bridgefu-recipe-123456789012-us-west-2-bft-safe1",
                "ecr_repository": "bridgefu-test/bft-safe1",
                "connect_mode": "disposable",
                "max_usd": 200.0,
                "events": [],
            }
            (legacy / "ledger.json").write_text(json.dumps(payload))
            durable_parent = base / "durable"
            durable_parent.mkdir(mode=0o700)
            with mock.patch.dict(
                LIVE.os.environ,
                self.state_environment(durable_parent),
                clear=True,
            ), mock.patch.object(LIVE, "root_dir", return_value=repository):
                durable, _ = LIVE.load_ledger("bft-safe1")
                durable_digest = hashlib.sha256(durable.read_bytes()).hexdigest()
                tombstone = next(legacy.glob("ledger.migrated-*.json"))
                restored = legacy / "ledger.json"
                restored.write_bytes(tombstone.read_bytes() + b"\n")
                with self.assertRaisesRegex(LIVE.LiveTestError, "diverged"):
                    LIVE.load_ledger("bft-safe1")
                self.assertEqual(hashlib.sha256(durable.read_bytes()).hexdigest(), durable_digest)
                self.assertTrue(restored.exists())

    def test_legacy_mutation_at_retirement_quarantines_the_new_durable_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repository = base / "checkout"
            legacy = repository / "target" / "aws-live" / "bft-safe1"
            legacy.mkdir(parents=True)
            payload = {
                "schema_version": 1,
                "execution_id": "bft-safe1",
                "created_at": "2026-08-03T00:00:00Z",
                "qualification_deadline_at": "2026-08-03T08:00:00Z",
                "account_id": "123456789012",
                "partition": "aws",
                "region": "us-west-2",
                "project": LIVE.PROJECT,
                "managed_by": LIVE.MANAGED_BY,
                "recipe": LIVE.RECIPE,
                "stack_name": "bridgefu-bft-safe1",
                "qualification_stack_name": "bridgefu-bft-safe1-qualification",
                "bootstrap_stack_name": "bridgefu-bft-safe1-bootstrap",
                "artifact_bucket": "bridgefu-recipe-123456789012-us-west-2-bft-safe1",
                "ecr_repository": "bridgefu-test/bft-safe1",
                "connect_mode": "disposable",
                "max_usd": 200.0,
                "events": [],
            }
            legacy_path = legacy / "ledger.json"
            legacy_path.write_text(json.dumps(payload))
            durable_parent = base / "durable"
            durable_parent.mkdir(mode=0o700)
            real_retire = LIVE.retire_legacy_ledger

            def mutate_then_retire(path: Path, digest: str) -> None:
                changed = json.loads(path.read_text())
                changed["status"] = "newer-old-controller-state"
                path.write_text(json.dumps(changed))
                real_retire(path, digest)

            with mock.patch.dict(
                LIVE.os.environ,
                self.state_environment(durable_parent),
                clear=True,
            ), mock.patch.object(
                LIVE, "root_dir", return_value=repository
            ), mock.patch.object(
                LIVE, "retire_legacy_ledger", side_effect=mutate_then_retire
            ):
                with self.assertRaisesRegex(LIVE.LiveTestError, "changed"):
                    LIVE.load_ledger("bft-safe1")
                durable_execution = (
                    durable_parent / "bridgefu" / "aws-live" / "bft-safe1"
                )
                self.assertFalse(durable_execution.exists())
                self.assertTrue(legacy_path.exists())
                self.assertEqual(
                    json.loads(legacy_path.read_text())["status"],
                    "newer-old-controller-state",
                )
                self.assertEqual(
                    len(
                        list(
                            (durable_parent / "bridgefu" / "aws-live").glob(
                                ".bft-safe1-migration-quarantine-*"
                            )
                        )
                    ),
                    1,
                )

    def test_final_retirement_inode_mutation_restores_legacy_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            legacy = parent / "ledger.json"
            legacy.write_text('{"execution_id":"bft-safe1"}\n')
            digest = hashlib.sha256(legacy.read_bytes()).hexdigest()
            real_rename = LIVE.os.rename

            def mutate_after_final_rename(source, destination, *args, **kwargs):
                result = real_rename(source, destination, *args, **kwargs)
                destination_path = Path(destination)
                if destination_path.name.startswith("ledger.migrated-"):
                    with destination_path.open("ab") as handle:
                        handle.write(b" ")
                return result

            with mock.patch.object(
                LIVE.os, "rename", side_effect=mutate_after_final_rename
            ):
                with self.assertRaisesRegex(LIVE.LiveTestError, "did not converge"):
                    LIVE.retire_legacy_ledger(legacy, digest)
            self.assertTrue(legacy.is_file())
            self.assertEqual(list(parent.glob("ledger.migrated-*.json")), [])
            self.assertNotEqual(hashlib.sha256(legacy.read_bytes()).hexdigest(), digest)

    def test_every_durable_load_binds_ledger_to_immutable_authority(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            LIVE.os.environ, self.state_environment(Path(directory)), clear=True
        ):
            path = LIVE.ensure_live_state_root() / "bft-safe1" / "ledger.json"
            ledger = {
                "schema_version": 1,
                "execution_id": "bft-safe1",
                "created_at": "2026-08-03T00:00:00Z",
                "qualification_deadline_at": "2026-08-03T08:00:00Z",
                "account_id": "123456789012",
                "partition": "aws",
                "region": "us-west-2",
                "project": LIVE.PROJECT,
                "managed_by": LIVE.MANAGED_BY,
                "recipe": LIVE.RECIPE,
                "stack_name": "bridgefu-bft-safe1",
                "qualification_stack_name": "bridgefu-bft-safe1-qualification",
                "bootstrap_stack_name": "bridgefu-bft-safe1-bootstrap",
                "artifact_bucket": "bridgefu-recipe-123456789012-us-west-2-bft-safe1",
                "ecr_repository": "bridgefu-test/bft-safe1",
                "connect_mode": "disposable",
                "max_usd": 200.0,
                "events": [],
            }
            LIVE.ensure_private_directory(path.parent)
            LIVE.write_initial_recovery_authority(path, ledger)
            LIVE.record(path, ledger, "created")
            _, loaded = LIVE.load_ledger("bft-safe1")
            self.assertEqual(loaded["account_id"], "123456789012")
            loaded["account_id"] = "999999999999"
            LIVE.atomic_json(path, loaded)
            with self.assertRaisesRegex(LIVE.LiveTestError, "differs"):
                LIVE.load_ledger("bft-safe1")

    def test_snapshot_allowlist_excludes_secrets_and_rejects_unbounded_resources(self):
        ledger = {
            "execution_id": "bft-safe1",
            "created_at": "2026-08-03T00:00:00Z",
            "events": [{"at": "2026-08-03T00:01:00Z", "event": "safe"}],
            "status": "published",
            "account_id": "123456789012",
            "partition": "aws",
            "region": "us-west-2",
            "created_resources": [
                {"type": "s3_bucket", "id": "bridgefu-example"},
                {"type": "secret", "id": "bridgefu-bft-safe1-vapi-api-key"},
            ],
            "application_stack_name": "arn:aws:cloudformation:us-west-2:123456789012:stack/app/uuid",
            "vapi_stack_id": "arn:aws:cloudformation:us-west-2:123456789012:stack/vapi/uuid",
            "vapi_assistant_id": "assistant_123",
            "vapi_prepare_tool_id": "tool_123",
            "vapi_webhook_credential_id": "credential_123",
            "vapi_prepare_url": "https://example.test/prepare",
            "vapi_teardown_mode": "bound_ids",
            "vapi_api_key_secret_arn": (
                "arn:aws:secretsmanager:us-west-2:123456789012:"
                "secret:bridgefu-bft-safe1-vapi"
            ),
            "vapi_private_key_sha256": "a" * 64,
            "private_key": "do-not-copy",
            "session_token": "do-not-copy",
        }
        snapshot = LIVE.sanitized_recovery_snapshot(ledger)
        encoded = json.dumps(snapshot)
        self.assertNotIn("do-not-copy", encoded)
        self.assertNotIn("vapi_private_key_sha256", encoded)
        self.assertEqual(snapshot["scope"], "active_run_accidental_loss_recovery_only")
        self.assertEqual(
            snapshot["authority"]["vapi_assistant_id"], "assistant_123"
        )
        self.assertRegex(
            snapshot["authority"]["vapi_teardown_authority_sha256"],
            r"^[0-9a-f]{64}$",
        )
        bad = {**ledger, "created_resources": [{"type": "unknown", "id": "x"}]}
        with self.assertRaises(LIVE.LiveTestError):
            LIVE.sanitized_recovery_snapshot(bad)

    def mirror_ledger(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "execution_id": "bft-safe1",
            "created_at": "2026-08-03T00:00:00Z",
            "events": [
                {"at": "2026-08-03T00:01:00Z", "event": "bucket_ready"}
            ],
            "status": "publishing",
            "region": "us-west-2",
            "account_id": "123456789012",
            "partition": "aws",
            "artifact_bucket": "bridgefu-recovery-test",
            "created_resources": [
                {"type": "s3_bucket", "id": "bridgefu-recovery-test"}
            ],
            "state_revision": 1,
            "previous_ledger_sha256": None,
        }

    def test_remote_capsules_are_append_only_checksummed_and_chained(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.json"
            ledger = self.mirror_ledger()
            LIVE.atomic_json(path, ledger)
            objects: dict[str, dict[str, object]] = {}
            calls: list[list[str]] = []

            def exists(arguments, **_kwargs):
                key = arguments[arguments.index("--key") + 1]
                return key in objects

            def aws(arguments, **_kwargs):
                calls.append(arguments)
                operation = arguments[1]
                key = arguments[arguments.index("--key") + 1]
                if operation == "put-object":
                    raw = Path(arguments[arguments.index("--body") + 1]).read_bytes()
                    digest = hashlib.sha256(raw).hexdigest()
                    version = f"version-{len(objects) + 1}"
                    objects[key] = {
                        "raw": raw,
                        "digest": digest,
                        "version": version,
                    }
                    self.assertEqual(
                        arguments[arguments.index("--if-none-match") + 1], "*"
                    )
                    self.assertEqual(
                        arguments[arguments.index("--server-side-encryption") + 1],
                        "AES256",
                    )
                    self.assertEqual(
                        arguments[arguments.index("--checksum-sha256") + 1],
                        base64.b64encode(bytes.fromhex(digest)).decode("ascii"),
                    )
                    return {"VersionId": version}
                item = objects[key]
                snapshot = json.loads(item["raw"])
                return {
                    "VersionId": item["version"],
                    "ContentLength": len(item["raw"]),
                    "ServerSideEncryption": "AES256",
                    "ChecksumSHA256": base64.b64encode(
                        bytes.fromhex(item["digest"])
                    ).decode("ascii"),
                    "Metadata": {
                        "sha256": item["digest"],
                        "execution-id": "bft-safe1",
                        "sequence": str(snapshot["capsule_sequence"]),
                    },
                }

            with mock.patch.object(
                LIVE, "exact_probe_exists", side_effect=exists
            ), mock.patch.object(LIVE, "aws_json", side_effect=aws):
                LIVE.mirror_recovery_snapshot(path, ledger, {"SAFE": "1"})
                first_digest = ledger["recovery_snapshot_mirror"]["sha256"]
                LIVE.mirror_recovery_snapshot(path, ledger, {"SAFE": "1"})

            self.assertEqual(len(objects), 2)
            capsules = [
                json.loads(item["raw"])
                for item in objects.values()
            ]
            self.assertIsNone(capsules[0]["previous_capsule_sha256"])
            self.assertEqual(capsules[1]["previous_capsule_sha256"], first_digest)
            self.assertEqual(
                len(list((path.parent / "recovery-capsules").glob("*.json"))), 2
            )
            self.assertEqual(
                len([call for call in calls if call[1] == "put-object"]), 2
            )

    def test_remote_capsule_lost_response_retry_reuses_local_immutable_capsule(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.json"
            original = self.mirror_ledger()
            ledger = copy.deepcopy(original)
            LIVE.atomic_json(path, ledger)
            stored: dict[str, object] = {}

            def first_aws(arguments, **_kwargs):
                if arguments[1] == "put-object":
                    raw = Path(arguments[arguments.index("--body") + 1]).read_bytes()
                    stored.update(
                        {
                            "key": arguments[arguments.index("--key") + 1],
                            "raw": raw,
                            "digest": hashlib.sha256(raw).hexdigest(),
                            "version": "version-1",
                        }
                    )
                    return {"VersionId": "version-1"}
                snapshot = json.loads(stored["raw"])
                return {
                    "VersionId": "version-1",
                    "ContentLength": len(stored["raw"]),
                    "ServerSideEncryption": "AES256",
                    "ChecksumSHA256": base64.b64encode(
                        bytes.fromhex(stored["digest"])
                    ).decode("ascii"),
                    "Metadata": {
                        "sha256": stored["digest"],
                        "execution-id": "bft-safe1",
                        "sequence": str(snapshot["capsule_sequence"]),
                    },
                }

            with mock.patch.object(
                LIVE, "exact_probe_exists", return_value=False
            ), mock.patch.object(LIVE, "aws_json", side_effect=first_aws):
                LIVE.mirror_recovery_snapshot(path, ledger, {})

            retry = copy.deepcopy(original)
            LIVE.atomic_json(path, retry)
            with mock.patch.object(
                LIVE, "exact_probe_exists", return_value=True
            ), mock.patch.object(
                LIVE, "aws_json", side_effect=first_aws
            ) as aws:
                LIVE.mirror_recovery_snapshot(path, retry, {})
            self.assertFalse(any(call.args[0][1] == "put-object" for call in aws.call_args_list))
            self.assertEqual(retry["recovery_snapshot_mirror"]["sha256"], stored["digest"])
            self.assertEqual(
                len(list((path.parent / "recovery-capsules").glob("*.json"))), 1
            )

    def test_remote_capsule_readback_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.json"
            ledger = self.mirror_ledger()
            LIVE.atomic_json(path, ledger)
            raw: bytes = b""

            def aws(arguments, **_kwargs):
                nonlocal raw
                if arguments[1] == "put-object":
                    raw = Path(arguments[arguments.index("--body") + 1]).read_bytes()
                    return {"VersionId": "version-1"}
                digest = hashlib.sha256(raw).hexdigest()
                return {
                    "VersionId": "version-1",
                    "ContentLength": len(raw),
                    "ServerSideEncryption": "AES256",
                    "ChecksumSHA256": "wrong-checksum",
                    "Metadata": {
                        "sha256": digest,
                        "execution-id": "bft-safe1",
                        "sequence": "1",
                    },
                }

            with mock.patch.object(
                LIVE, "exact_probe_exists", return_value=False
            ), mock.patch.object(LIVE, "aws_json", side_effect=aws):
                with self.assertRaisesRegex(LIVE.LiveTestError, "readback"):
                    LIVE.mirror_recovery_snapshot(path, ledger, {})
            self.assertNotIn("recovery_snapshot_mirror", ledger)


if __name__ == "__main__":
    unittest.main()
