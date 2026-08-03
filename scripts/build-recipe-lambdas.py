#!/usr/bin/env python3
"""Build deterministic Lambda ZIPs for the canonical Bridgefu recipe."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import zipfile
from pathlib import Path


RECIPE = "vapi-amazon-connect-screen-pop"
HANDLERS = (
    "prepare_handoff",
    "transfer_destination",
    "connect_lookup",
    "vapi_provisioner",
)
COMMON = ("bridgefu_handoff.py", "aws_runtime.py", "vapi_provisioning.py")
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def _build_zip(source: Path, handler: str, output: Path) -> dict[str, object]:
    common = source / "lambda" / "common"
    handler_file = source / "lambda" / handler / "handler.py"
    inputs = [(name, common / name) for name in COMMON]
    inputs.append(("handler.py", handler_file))
    if handler == "vapi_provisioner":
        for template in sorted((source / "vapi").glob("*.json.tmpl")):
            inputs.append((f"assets/vapi/{template.name}", template))
    for _, path in inputs:
        if not path.is_file():
            raise SystemExit(f"missing Lambda source: {path}")

    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", allowZip64=False) as archive:
        for archive_name, path in sorted(inputs):
            archive.writestr(_zip_info(archive_name), path.read_bytes())

    payload = output.read_bytes()
    return {
        "handler": "handler.lambda_handler",
        "path": output.name,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size_bytes": len(payload),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("target/recipe-lambdas"),
        help="directory for immutable ZIPs and manifest",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    source = root / "recipes" / RECIPE
    output = args.output if args.output.is_absolute() else root / args.output
    artifacts: dict[str, object] = {}
    for handler in HANDLERS:
        artifacts[handler] = _build_zip(
            source,
            handler,
            output / f"{handler}.zip",
        )

    manifest = {
        "schema_version": 1,
        "recipe": RECIPE,
        "artifacts": artifacts,
    }
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    output.mkdir(parents=True, exist_ok=True)
    (output / "manifest.json").write_bytes(encoded)
    print(os.fspath(output / "manifest.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
