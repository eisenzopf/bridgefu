"""Reject unqualified dependency sources in retained runtime evidence."""

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "bridgefu_runtime_smoke", Path(__file__).with_name("runtime-smoke.py")
)
smoke = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = smoke
SPEC.loader.exec_module(smoke)
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


class DependencyEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "config").mkdir()
        self.source = self.root / "config/rvoip-source.txt"
        self.source.write_text(REGISTRY)
        self.lock = self.root / "Cargo.lock"
        replacement = patch.object(smoke, "ROOT", self.root)
        replacement.start()
        self.addCleanup(replacement.stop)

    def write_lock(self, overrides=None, omit=()):
        packages = [
            {
                "name": name,
                "version": smoke.RVOIP_RELEASE_VERSION,
                "source": REGISTRY,
                "checksum": "0" * 64,
            }
            for name in sorted(smoke.REQUIRED_RVOIP_PACKAGES)
        ]
        packages[0].update(overrides or {})
        for key in omit:
            packages[0].pop(key)
        self.lock.write_text("\n".join(
            "[[package]]\n" + "\n".join(f"{key} = {json.dumps(value)}" for key, value in package.items())
            for package in packages
        ))

    def test_registry_evidence_retains_checksums_and_correct_source_kind(self):
        self.write_lock()
        evidence = smoke.locked_dependency_state(self.lock)
        self.assertEqual(len(evidence["packages"]), len(smoke.REQUIRED_RVOIP_PACKAGES))
        for package in evidence["packages"]:
            self.assertEqual(package["source_kind"], "registry")
            self.assertEqual(package["checksum"], "0" * 64)

    def test_git_and_local_path_dependencies_are_rejected(self):
        for overrides, omit in (({"source": "git+https://example.invalid/rvoip"}, ()), ({}, ("source",))):
            with self.subTest(overrides=overrides, omit=omit):
                self.write_lock(overrides, omit)
                with self.assertRaises(SystemExit):
                    smoke.locked_dependency_state(self.lock)

    def test_missing_or_malformed_checksums_are_rejected(self):
        for overrides, omit in (({}, ("checksum",)), ({"checksum": "0" * 63}, ()), ({"checksum": "z" * 64}, ())):
            with self.subTest(overrides=overrides, omit=omit):
                self.write_lock(overrides, omit)
                with self.assertRaises(SystemExit):
                    smoke.locked_dependency_state(self.lock)

    def test_mixed_release_versions_are_rejected(self):
        self.write_lock({"version": "0.5.0"})
        with self.assertRaises(SystemExit):
            smoke.locked_dependency_state(self.lock)

    def test_config_cannot_reapprove_a_git_source(self):
        self.write_lock()
        self.source.write_text("git+https://example.invalid/rvoip")
        with self.assertRaisesRegex(SystemExit, "must come from crates.io"):
            smoke.locked_dependency_state(self.lock)


if __name__ == "__main__":
    unittest.main()
