#!/usr/bin/env python3
"""Create a minimal single-platform OCI layout from a verified image layout."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from typing import Any


DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
PLATFORM = re.compile(r"^[a-z0-9]+/[a-z0-9_]+$")
INDEX_MEDIA_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}


class SelectionError(RuntimeError):
    pass


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SelectionError(f"{path} is not readable JSON") from error
    if not isinstance(value, dict):
        raise SelectionError(f"{path} is not a JSON object")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--layout", type=Path, required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if PLATFORM.fullmatch(args.platform) is None:
        raise SelectionError("platform must use the os/architecture form")
    os_name, architecture = args.platform.split("/", 1)
    source = args.layout.resolve()
    destination = args.output.resolve()
    if destination.exists():
        raise SelectionError("output layout already exists")
    layout = read_json(source / "oci-layout")
    if layout.get("imageLayoutVersion") != "1.0.0":
        raise SelectionError("unsupported OCI layout version")
    root = read_json(source / "index.json")
    descriptors = root.get("manifests")
    if not isinstance(descriptors, list):
        raise SelectionError("OCI layout index has no manifests")

    def descriptor_path(descriptor: dict[str, Any]) -> Path:
        digest = descriptor.get("digest")
        match = DIGEST.fullmatch(digest) if isinstance(digest, str) else None
        if match is None:
            raise SelectionError("OCI descriptor has an invalid digest")
        path = source / "blobs" / "sha256" / match.group(1)
        try:
            payload = path.read_bytes()
        except OSError as error:
            raise SelectionError(f"missing OCI blob {digest}") from error
        if hashlib.sha256(payload).hexdigest() != match.group(1):
            raise SelectionError(f"OCI blob digest mismatch for {digest}")
        if descriptor.get("size") != len(payload):
            raise SelectionError(f"OCI blob size mismatch for {digest}")
        return path

    matches: list[tuple[dict[str, Any], dict[str, Any]]] = []
    visited: set[str] = set()

    def visit(descriptor: dict[str, Any]) -> None:
        digest = descriptor.get("digest")
        if not isinstance(digest, str) or digest in visited:
            return
        visited.add(digest)
        body = read_json(descriptor_path(descriptor))
        children = body.get("manifests")
        if isinstance(children, list):
            if descriptor.get("mediaType") not in INDEX_MEDIA_TYPES:
                raise SelectionError("OCI index has an invalid descriptor media type")
            for child in children:
                if not isinstance(child, dict):
                    raise SelectionError("OCI index contains a malformed descriptor")
                visit(child)
            return
        platform = descriptor.get("platform")
        if (
            descriptor.get("mediaType") in MANIFEST_MEDIA_TYPES
            and isinstance(platform, dict)
            and platform.get("os") == os_name
            and platform.get("architecture") == architecture
        ):
            matches.append((descriptor, body))

    for descriptor in descriptors:
        if not isinstance(descriptor, dict):
            raise SelectionError("OCI root contains a malformed descriptor")
        visit(descriptor)
    if len(matches) != 1:
        raise SelectionError(
            f"expected one {args.platform} manifest, found {len(matches)}"
        )
    selected, manifest = matches[0]
    config = manifest.get("config")
    layers = manifest.get("layers")
    if not isinstance(config, dict) or not isinstance(layers, list):
        raise SelectionError("selected image manifest is incomplete")
    retained = [selected, config]
    for layer in layers:
        if not isinstance(layer, dict):
            raise SelectionError("selected image contains a malformed layer")
        retained.append(layer)

    destination.mkdir(parents=True)
    (destination / "blobs" / "sha256").mkdir(parents=True)
    (destination / "oci-layout").write_text(
        json.dumps(layout, separators=(",", ":"), sort_keys=True) + "\n"
    )
    selected_root = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [selected],
    }
    (destination / "index.json").write_text(
        json.dumps(selected_root, separators=(",", ":"), sort_keys=True) + "\n"
    )
    for descriptor in retained:
        source_path = descriptor_path(descriptor)
        target_path = destination / "blobs" / "sha256" / source_path.name
        if target_path.exists():
            continue
        try:
            os.link(source_path, target_path)
        except OSError:
            shutil.copyfile(source_path, target_path)


if __name__ == "__main__":
    try:
        main()
    except SelectionError as error:
        raise SystemExit(f"OCI platform selection failed: {error}") from error
