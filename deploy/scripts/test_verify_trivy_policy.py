#!/usr/bin/env python3
"""Hermetic tests for the retained-image vulnerability policy."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("verify-trivy-policy.py")


def write_report(
    path: Path,
    platform: str,
    vulnerabilities: list[dict[str, str]] | None,
) -> None:
    os_name, architecture = platform.split("/", 1)
    path.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "ArtifactName": "bridgefu",
                "ArtifactType": "container_image",
                "Metadata": {
                    "ImageConfig": {"os": os_name, "architecture": architecture}
                },
                "Results": [
                    {
                        "Target": "debian",
                        "Class": "os-pkgs",
                        "Type": "debian",
                        "Vulnerabilities": vulnerabilities,
                    }
                ],
            }
        )
    )


class TrivyPolicyTests(unittest.TestCase):
    def run_policy(
        self, root: Path, amd64: Path, arm64: Path
    ) -> subprocess.CompletedProcess[str]:
        archive = root / "image.oci.tar"
        archive.write_bytes(b"exact retained OCI archive")
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--report",
                f"linux/amd64={amd64}",
                "--report",
                f"linux/arm64={arm64}",
                "--image-archive",
                str(archive),
                "--output",
                str(root / "policy.json"),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_accepts_two_platform_reports_without_denied_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            amd64 = root / "amd64.json"
            arm64 = root / "arm64.json"
            write_report(
                amd64,
                "linux/amd64",
                [{"VulnerabilityID": "CVE-LOW", "Severity": "LOW"}],
            )
            write_report(arm64, "linux/arm64", None)
            result = self.run_policy(root, amd64, arm64)
            self.assertEqual(result.returncode, 0, result.stderr)
            evidence = json.loads((root / "policy.json").read_text())
            self.assertEqual(
                [item["platform"] for item in evidence["reports"]],
                ["linux/amd64", "linux/arm64"],
            )

    def test_rejects_high_or_critical_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            amd64 = root / "amd64.json"
            arm64 = root / "arm64.json"
            write_report(
                amd64,
                "linux/amd64",
                [{"VulnerabilityID": "CVE-HIGH", "Severity": "HIGH"}],
            )
            write_report(arm64, "linux/arm64", None)
            result = self.run_policy(root, amd64, arm64)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("violates the HIGH/CRITICAL policy", result.stderr)

    def test_rejects_a_report_for_the_wrong_platform(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            amd64 = root / "amd64.json"
            arm64 = root / "arm64.json"
            write_report(amd64, "linux/arm64", None)
            write_report(arm64, "linux/arm64", None)
            result = self.run_policy(root, amd64, arm64)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("scanned linux/arm64, expected linux/amd64", result.stderr)


if __name__ == "__main__":
    unittest.main()
