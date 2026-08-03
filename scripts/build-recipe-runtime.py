#!/usr/bin/env python3
"""Build the deterministic Starter Production bootstrap ZIP."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import zipfile
from pathlib import Path


RECIPE = "vapi-amazon-connect-screen-pop"
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
EXECUTABLES = {
    "bootstrap.sh",
    "bridgefu-cert-refresh",
    "bridgefu-cert-reload",
    "bridgefu-ha-cert-refresh",
    "bridgefu-ha-cert-reload",
    "bridgefu-ha-load-secrets.py",
    "bridgefu-ha-scale-protection",
    "bridgefu-load-secrets",
    "bridgefu-pull-image",
    "ha-host-bootstrap.sh",
    "render-ha.py",
    "render.py",
}


def zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    mode = 0o100755 if name in EXECUTABLES else 0o100644
    info.external_attr = mode << 16
    return info


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("target/recipe-runtime"),
        help="directory for the immutable runtime ZIP and manifest",
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = root / "recipes" / RECIPE / "runtime"
    output = args.output if args.output.is_absolute() else root / args.output
    output.mkdir(parents=True, exist_ok=True)
    artifact = output / "starter-runtime.zip"
    inputs = sorted(path for path in source.iterdir() if path.is_file())
    if not inputs:
        raise SystemExit("runtime assets are missing")
    with zipfile.ZipFile(artifact, "w", allowZip64=False) as archive:
        for path in inputs:
            archive.writestr(zip_info(path.name), path.read_bytes())
    payload = artifact.read_bytes()
    manifest = {
        "schema_version": 1,
        "recipe": RECIPE,
        "artifact": {
            "path": artifact.name,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload),
            "files": [path.name for path in inputs],
        },
    }
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    (output / "manifest.json").write_bytes(encoded)
    print(os.fspath(output / "manifest.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
