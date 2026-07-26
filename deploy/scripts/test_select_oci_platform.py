#!/usr/bin/env python3
"""Hermetic tests for select-oci-platform.py."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


SCRIPT = Path(__file__).with_name("select-oci-platform.py")


def encoded(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def fixture(root: Path) -> dict[str, str]:
    blobs = root / "blobs" / "sha256"
    blobs.mkdir(parents=True)

    def retain(payload: bytes, media_type: str, **extra: Any) -> dict[str, Any]:
        digest = hashlib.sha256(payload).hexdigest()
        (blobs / digest).write_bytes(payload)
        return {
            "mediaType": media_type,
            "digest": f"sha256:{digest}",
            "size": len(payload),
            **extra,
        }

    manifests = []
    expected = {}
    for architecture in ("amd64", "arm64"):
        config = retain(
            encoded({"os": "linux", "architecture": architecture}),
            "application/vnd.oci.image.config.v1+json",
        )
        layer = retain(
            f"layer-{architecture}".encode(),
            "application/vnd.oci.image.layer.v1.tar",
        )
        manifest = retain(
            encoded({"schemaVersion": 2, "config": config, "layers": [layer]}),
            "application/vnd.oci.image.manifest.v1+json",
            platform={"os": "linux", "architecture": architecture},
        )
        manifests.append(manifest)
        expected[architecture] = manifest["digest"]
    nested = retain(
        encoded({"schemaVersion": 2, "manifests": manifests}),
        "application/vnd.oci.image.index.v1+json",
    )
    (root / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}\n')
    (root / "index.json").write_text(
        json.dumps({"schemaVersion": 2, "manifests": [nested]}) + "\n"
    )
    return expected


class SelectOciPlatformTests(unittest.TestCase):
    def test_selects_one_nested_platform_and_its_exact_blobs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            expected = fixture(source)
            output = root / "selected"
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--layout",
                    str(source),
                    "--platform",
                    "linux/arm64",
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            selected = json.loads((output / "index.json").read_text())
            self.assertEqual(len(selected["manifests"]), 1)
            self.assertEqual(selected["manifests"][0]["digest"], expected["arm64"])
            self.assertEqual(
                selected["manifests"][0]["platform"],
                {"os": "linux", "architecture": "arm64"},
            )
            self.assertEqual(len(list((output / "blobs" / "sha256").iterdir())), 3)

    def test_rejects_unknown_platform(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            fixture(source)
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--layout",
                    str(source),
                    "--platform",
                    "linux/s390x",
                    "--output",
                    str(root / "selected"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("found 0", result.stderr)


if __name__ == "__main__":
    unittest.main()
