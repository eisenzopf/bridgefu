#!/usr/bin/env python3
"""Hermetic regression tests for verify-multiarch-oci.py."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import Any


SCRIPT = Path(__file__).with_name("verify-multiarch-oci.py")
SPDX = "https://spdx.dev/Document"
SLSA = "https://slsa.dev/provenance/v1"


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def descriptor(payload: bytes, media_type: str, **extra: Any) -> dict[str, Any]:
    return {
        "mediaType": media_type,
        "digest": f"sha256:{hashlib.sha256(payload).hexdigest()}",
        "size": len(payload),
        **extra,
    }


def build_archive(
    path: Path,
    predicates: dict[str, tuple[str, ...]],
    *,
    forged_predicate: bool = False,
    nested_root: bool = False,
) -> tuple[str, list[str]]:
    blobs: dict[str, bytes] = {}

    def retain(payload: bytes, media_type: str, **extra: Any) -> dict[str, Any]:
        item = descriptor(payload, media_type, **extra)
        blobs[item["digest"].removeprefix("sha256:")] = payload
        return item

    manifests: list[dict[str, Any]] = []
    image_descriptors: list[dict[str, Any]] = []
    for architecture in ("amd64", "arm64"):
        config = retain(
            canonical_json({"architecture": architecture, "os": "linux"}),
            "application/vnd.oci.image.config.v1+json",
        )
        layer = retain(
            b"\x1f\x8b\x08\x00binary-oci-layer\x00",
            "application/vnd.oci.image.layer.v1.tar+gzip",
        )
        manifest = canonical_json(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": config,
                "layers": [layer],
            }
        )
        image_descriptor = retain(
            manifest,
            "application/vnd.oci.image.manifest.v1+json",
            platform={"os": "linux", "architecture": architecture},
        )
        manifests.append(image_descriptor)
        image_descriptors.append(image_descriptor)

    for image_descriptor in image_descriptors:
        architecture = image_descriptor["platform"]["architecture"]
        target = image_descriptor["digest"]
        statement_layers: list[dict[str, Any]] = []
        for predicate in predicates[architecture]:
            statement_predicate = SLSA if forged_predicate and predicate == SPDX else predicate
            statement = retain(
                canonical_json(
                    {
                        "_type": "https://in-toto.io/Statement/v1",
                        "subject": [
                            {
                                "name": "bridgefu",
                                "digest": {
                                    "sha256": target.removeprefix("sha256:")
                                },
                            }
                        ],
                        "predicateType": statement_predicate,
                        "predicate": {},
                    }
                ),
                "application/vnd.in-toto+json",
                annotations={"in-toto.io/predicate-type": predicate},
            )
            statement_layers.append(statement)
        attestation_manifest = canonical_json(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": retain(b"{}", "application/vnd.oci.empty.v1+json"),
                "layers": statement_layers,
            }
        )
        manifests.append(
            retain(
                attestation_manifest,
                "application/vnd.oci.image.manifest.v1+json",
                platform={"os": "unknown", "architecture": "unknown"},
                annotations={
                    "vnd.docker.reference.digest": target,
                    "vnd.docker.reference.type": "attestation-manifest",
                },
            )
        )

    image_index = canonical_json(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": manifests,
        }
    )
    if nested_root:
        image_index_descriptor = retain(
            image_index,
            "application/vnd.oci.image.index.v1+json",
            annotations={"org.opencontainers.image.ref.name": "bridgefu:test"},
        )
        root = canonical_json({"schemaVersion": 2, "manifests": [image_index_descriptor]})
        expected_digest = image_index_descriptor["digest"]
    else:
        root = image_index
        expected_digest = f"sha256:{hashlib.sha256(root).hexdigest()}"
    layout = canonical_json({"imageLayoutVersion": "1.0.0"})

    with tarfile.open(path, "w") as archive:
        for name, payload in {
            "oci-layout": layout,
            "index.json": root,
            **{f"blobs/sha256/{digest}": payload for digest, payload in blobs.items()},
        }.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))

    return expected_digest, [item["digest"] for item in image_descriptors]


class VerifyMultiarchOciTests(unittest.TestCase):
    def run_verifier(
        self,
        archive: Path,
        expected_digest: str,
        output: Path,
        source_revisions: tuple[str, ...] = (),
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--archive",
                str(archive),
                "--expected-digest",
                expected_digest,
                "--output",
                str(output),
                *[
                    argument
                    for revision in source_revisions
                    for argument in ("--source-revision", revision)
                ],
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_accepts_root_digest_exact_platforms_and_bound_attestations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "image.oci.tar"
            output = root / "descriptor.json"
            digest, _ = build_archive(
                archive, {"amd64": (SPDX, SLSA), "arm64": (SPDX, SLSA)}
            )
            result = self.run_verifier(
                archive,
                digest,
                output,
                (
                    f"bridgefu={'1' * 40}",
                    f"rvoip={'2' * 40}",
                ),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            evidence = json.loads(output.read_text())
            self.assertEqual(evidence["digest"], digest)
            self.assertEqual(evidence["digest_kind"], "oci-layout-index")
            self.assertEqual(
                evidence["source_revisions"],
                {"bridgefu": "1" * 40, "rvoip": "2" * 40},
            )
            self.assertEqual(
                [platform["name"] for platform in evidence["platforms"]],
                ["linux/amd64", "linux/arm64"],
            )
            self.assertEqual(
                evidence["archive_sha256"],
                hashlib.sha256(archive.read_bytes()).hexdigest(),
            )

    def test_accepts_one_top_level_nested_image_index_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "image.oci.tar"
            output = root / "descriptor.json"
            digest, _ = build_archive(
                archive,
                {"amd64": (SPDX, SLSA), "arm64": (SPDX, SLSA)},
                nested_root=True,
            )
            result = self.run_verifier(archive, digest, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                json.loads(output.read_text())["digest_kind"],
                "top-level-image-index",
            )

    def test_rejects_missing_provenance_on_one_platform(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "image.oci.tar"
            digest, _ = build_archive(
                archive, {"amd64": (SPDX, SLSA), "arm64": (SPDX,)}
            )
            result = self.run_verifier(archive, digest, root / "descriptor.json")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("linux/arm64 is missing provenance", result.stderr)

    def test_rejects_platform_child_digest_as_multiarch_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "image.oci.tar"
            _, platform_digests = build_archive(
                archive, {"amd64": (SPDX, SLSA), "arm64": (SPDX, SLSA)}
            )
            result = self.run_verifier(
                archive, platform_digests[0], root / "descriptor.json"
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not the OCI layout", result.stderr)

    def test_rejects_predicate_annotation_without_matching_statement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "image.oci.tar"
            digest, _ = build_archive(
                archive,
                {"amd64": (SPDX, SLSA), "arm64": (SPDX, SLSA)},
                forged_predicate=True,
            )
            result = self.run_verifier(archive, digest, root / "descriptor.json")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match its statement", result.stderr)


if __name__ == "__main__":
    unittest.main()
