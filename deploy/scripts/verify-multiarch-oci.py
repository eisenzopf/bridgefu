#!/usr/bin/env python3
"""Verify and describe a retained Bridgefu multi-platform OCI archive.

The digest emitted by this tool is deliberately restricted to the OCI layout
index itself, or to one top-level nested image index. A child platform manifest
is reachable from the layout too, but it is not a multi-architecture image
digest and must never be recorded as one.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import json
import re
import tarfile
from pathlib import Path
from typing import Any


DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
GIT_REVISION = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_PLATFORMS = {("linux", "amd64"), ("linux", "arm64")}
INDEX_MEDIA_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
ATTESTATION_MEDIA_TYPE = "application/vnd.in-toto+json"
PREDICATE_ANNOTATION = "in-toto.io/predicate-type"
REFERENCE_DIGEST_ANNOTATION = "vnd.docker.reference.digest"
REFERENCE_TYPE_ANNOTATION = "vnd.docker.reference.type"
ATTESTATION_REFERENCE_TYPE = "attestation-manifest"
IN_TOTO_TYPES = {
    "https://in-toto.io/Statement/v0.1",
    "https://in-toto.io/Statement/v1",
}


class VerificationError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--expected-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--source-revision",
        action="append",
        default=[],
        metavar="NAME=FULL_COMMIT",
    )
    return parser.parse_args()


def normalized_member_name(name: str) -> str:
    return name[2:] if name.startswith("./") else name


def digest_bytes(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise VerificationError(f"{label} is not a JSON object")
    return value


def predicate_class(predicate: str) -> str | None:
    lowered = predicate.lower()
    if "spdx" in lowered:
        return "sbom"
    if "slsa" in lowered and "provenance" in lowered:
        return "provenance"
    return None


def main() -> None:
    args = parse_args()
    if DIGEST.fullmatch(args.expected_digest) is None:
        raise VerificationError("BuildKit did not return an immutable sha256 digest")
    source_revisions: dict[str, str] = {}
    for value in args.source_revision:
        name, separator, revision = value.partition("=")
        if (
            not separator
            or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name)
            or GIT_REVISION.fullmatch(revision) is None
        ):
            raise VerificationError(f"invalid source revision: {value}")
        if name in source_revisions:
            raise VerificationError(f"duplicate source revision: {name}")
        source_revisions[name] = revision

    with tarfile.open(args.archive, mode="r:*") as archive:
        members = {
            normalized_member_name(member.name): member
            for member in archive.getmembers()
            if member.isfile()
        }

        def read_member(name: str) -> bytes:
            member = members.get(name)
            if member is None:
                raise VerificationError(f"OCI archive is missing {name}")
            stream = archive.extractfile(member)
            if stream is None:
                raise VerificationError(f"OCI archive cannot read {name}")
            return stream.read()

        layout = read_json(read_member("oci-layout"), "oci-layout")
        if layout.get("imageLayoutVersion") != "1.0.0":
            raise VerificationError("unsupported OCI image-layout version")

        root_payload = read_member("index.json")
        root = read_json(root_payload, "index.json")
        if root.get("schemaVersion") != 2:
            raise VerificationError("OCI index must use schemaVersion 2")
        root_descriptors = root.get("manifests")
        if not isinstance(root_descriptors, list) or not root_descriptors:
            raise VerificationError("OCI index contains no manifests")
        if not all(isinstance(item, dict) for item in root_descriptors):
            raise VerificationError("OCI root contains a non-object descriptor")

        layout_root_digest = digest_bytes(root_payload)
        digest_kind: str
        release_descriptors: list[dict[str, Any]]
        if args.expected_digest == layout_root_digest:
            digest_kind = "oci-layout-index"
            release_descriptors = root_descriptors
        else:
            matches = [
                descriptor
                for descriptor in root_descriptors
                if descriptor.get("digest") == args.expected_digest
                and descriptor.get("mediaType") in INDEX_MEDIA_TYPES
            ]
            if len(matches) != 1:
                raise VerificationError(
                    "BuildKit digest is not the OCI layout or one top-level "
                    "multi-platform image index"
                )
            digest_kind = "top-level-image-index"
            release_descriptors = [matches[0]]

        seen: set[str] = set()
        platforms_by_digest: dict[str, tuple[str, str]] = {}
        platform_digests: dict[tuple[str, str], str] = {}
        attestations: dict[str, set[str]] = defaultdict(set)
        attestation_targets: set[str] = set()

        def read_descriptor_blob(descriptor: dict[str, Any]) -> bytes:
            digest = descriptor.get("digest")
            match = DIGEST.fullmatch(digest) if isinstance(digest, str) else None
            if match is None:
                raise VerificationError("OCI descriptor has an invalid digest")
            payload = read_member(f"blobs/sha256/{match.group(1)}")
            if digest_bytes(payload) != digest:
                raise VerificationError(f"OCI blob digest mismatch for {digest}")
            declared_size = descriptor.get("size")
            if not isinstance(declared_size, int) or declared_size != len(payload):
                raise VerificationError(f"OCI descriptor size mismatch for {digest}")
            return payload

        def read_json_descriptor(descriptor: dict[str, Any]) -> dict[str, Any]:
            digest = descriptor.get("digest")
            return read_json(read_descriptor_blob(descriptor), str(digest))

        def validate_statement(
            layer: dict[str, Any], payload: bytes, target_digest: str
        ) -> str:
            annotations = layer.get("annotations")
            predicate = (
                annotations.get(PREDICATE_ANNOTATION)
                if isinstance(annotations, dict)
                else None
            )
            if not isinstance(predicate, str) or not predicate:
                raise VerificationError("in-toto layer has no predicate annotation")
            statement = read_json(payload, "in-toto statement")
            if statement.get("_type") not in IN_TOTO_TYPES:
                raise VerificationError("attestation has an unsupported in-toto statement type")
            if statement.get("predicateType") != predicate:
                raise VerificationError(
                    "attestation predicate annotation does not match its statement"
                )
            subjects = statement.get("subject")
            if not isinstance(subjects, list) or not subjects:
                raise VerificationError("attestation statement has no subject")
            target_hex = target_digest.removeprefix("sha256:")
            attached = False
            for subject in subjects:
                if not isinstance(subject, dict):
                    continue
                digests = subject.get("digest")
                if isinstance(digests, dict) and digests.get("sha256") == target_hex:
                    attached = True
                    break
            if not attached:
                raise VerificationError(
                    "attestation statement is not bound to its referenced image manifest"
                )
            return predicate

        def visit(descriptor: dict[str, Any]) -> None:
            digest = descriptor.get("digest")
            if not isinstance(digest, str):
                raise VerificationError("OCI descriptor has no digest")
            if digest in seen:
                return
            seen.add(digest)
            body = read_json_descriptor(descriptor)
            children = body.get("manifests")
            if isinstance(children, list):
                if descriptor.get("mediaType") not in INDEX_MEDIA_TYPES:
                    raise VerificationError("OCI index descriptor has an invalid media type")
                for child in children:
                    if not isinstance(child, dict):
                        raise VerificationError("OCI index contains a non-object descriptor")
                    visit(child)
                return

            if descriptor.get("mediaType") not in MANIFEST_MEDIA_TYPES:
                raise VerificationError("OCI manifest descriptor has an invalid media type")
            platform = descriptor.get("platform")
            if not isinstance(platform, dict):
                raise VerificationError("OCI manifest descriptor has no platform")
            os_name = platform.get("os")
            architecture = platform.get("architecture")
            if not isinstance(os_name, str) or not isinstance(architecture, str):
                raise VerificationError("OCI platform is incomplete")

            layers = body.get("layers")
            if not isinstance(layers, list):
                raise VerificationError("OCI manifest contains no layer list")
            config = body.get("config")
            if not isinstance(config, dict):
                raise VerificationError("OCI manifest contains no config descriptor")
            read_descriptor_blob(config)

            if (os_name, architecture) == ("unknown", "unknown"):
                annotations = descriptor.get("annotations")
                if not isinstance(annotations, dict):
                    raise VerificationError("attestation manifest has no reference annotations")
                if annotations.get(REFERENCE_TYPE_ANNOTATION) != ATTESTATION_REFERENCE_TYPE:
                    raise VerificationError("unknown-platform manifest is not an attestation")
                target = annotations.get(REFERENCE_DIGEST_ANNOTATION)
                if not isinstance(target, str) or DIGEST.fullmatch(target) is None:
                    raise VerificationError("attestation has no valid image reference digest")
                attestation_targets.add(target)
                for layer in layers:
                    if not isinstance(layer, dict):
                        raise VerificationError("OCI manifest contains a non-object layer")
                    payload = read_descriptor_blob(layer)
                    if layer.get("mediaType") != ATTESTATION_MEDIA_TYPE:
                        raise VerificationError(
                            "attestation manifest contains a non-in-toto layer"
                        )
                    attestations[target].add(validate_statement(layer, payload, target))
                return

            platform_key = (os_name, architecture)
            if platform_key in platform_digests:
                raise VerificationError(
                    f"OCI image contains duplicate platform {os_name}/{architecture}"
                )
            platform_digests[platform_key] = digest
            platforms_by_digest[digest] = platform_key
            for layer in layers:
                if not isinstance(layer, dict):
                    raise VerificationError("OCI manifest contains a non-object layer")
                if layer.get("mediaType") == ATTESTATION_MEDIA_TYPE:
                    raise VerificationError("runtime image manifest embeds an attestation layer")
                read_descriptor_blob(layer)

        for descriptor in release_descriptors:
            visit(descriptor)

        platforms = set(platform_digests)
        if platforms != EXPECTED_PLATFORMS:
            rendered = ", ".join(
                f"{os_name}/{arch}" for os_name, arch in sorted(platforms)
            )
            raise VerificationError(
                f"OCI archive has unexpected platform set: {rendered or 'empty'}"
            )
        dangling = attestation_targets.difference(platforms_by_digest)
        if dangling:
            raise VerificationError("attestation references a non-platform image manifest")

        required_classes = {"sbom", "provenance"}
        for platform, image_digest in sorted(platform_digests.items()):
            classes = {
                classified
                for predicate in attestations.get(image_digest, set())
                if (classified := predicate_class(predicate)) is not None
            }
            missing = required_classes.difference(classes)
            if missing:
                rendered = ", ".join(sorted(missing))
                raise VerificationError(
                    f"{platform[0]}/{platform[1]} is missing {rendered} attestation"
                )

    descriptor = {
        "schema_version": 2,
        "digest": args.expected_digest,
        "digest_kind": digest_kind,
        "oci_layout_index_digest": layout_root_digest,
        "archive": args.archive.name,
        "archive_sha256": digest_file(args.archive),
        "source_revisions": dict(sorted(source_revisions.items())),
        "platforms": [
            {
                "name": f"{os_name}/{architecture}",
                "manifest_digest": platform_digests[(os_name, architecture)],
                "attestation_predicates": sorted(
                    attestations[platform_digests[(os_name, architecture)]]
                ),
            }
            for os_name, architecture in sorted(platform_digests)
        ],
    }
    args.output.write_text(json.dumps(descriptor, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (OSError, tarfile.TarError, VerificationError) as error:
        raise SystemExit(f"multi-arch OCI verification failed: {error}") from error
