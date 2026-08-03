#!/usr/bin/env python3
"""Build a deterministic, checksummed release bundle for the flagship recipe."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import tomllib
from pathlib import Path


RECIPE_ID = "vapi-amazon-connect-screen-pop"
RECIPE_VERSION = 1
IMAGE_PATTERN = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
MARKER = ".bridgefu-release-build"
STAGING_MARKER = ".bridgefu-release-staging"
MAX_ARTIFACT_COUNT = 1_000
MAX_ARTIFACT_BYTES = 100 * 1024 * 1024
MAX_SINGLE_ARTIFACT_BYTES = 50 * 1024 * 1024
COPY_PATHS = (
    "CHANGELOG.md",
    "README.md",
    "deployment.example.yaml",
    "deployment.nonproduction.example.yaml",
    "handoff-contract.json",
    "parameters-starter.json",
    "parameters-ha.json",
    "parameters-nonproduction-starter.json",
    "recipe.yaml",
    "values.example.yaml",
)
COPY_DIRECTORIES = (
    "cloudformation",
    "connect",
    "demo-site",
    "runbooks",
    "qualification",
    "runtime",
    "terraform",
    "vapi",
)

IGNORED_DIRECTORY_NAMES = {
    ".mypy_cache",
    ".pytest_cache",
    ".terraform",
    ".terragrunt-cache",
    "__pycache__",
    "node_modules",
}
IGNORED_FILE_NAMES = {
    ".DS_Store",
    ".terraform.tfstate.lock.info",
    "crash.log",
    "terraform.tfstate",
    "terraform.tfstate.backup",
}
MUTABLE_SOURCE_DIGEST_PATHS = frozenset({"BRIDGEFU-RECIPE-IMPLEMENTATION-PROGRESS.md"})


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(*args: str, cwd: Path) -> str:
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def ignored_recipe_assets(_directory: str, names: list[str]) -> set[str]:
    return {
        name
        for name in names
        if name in IGNORED_DIRECTORY_NAMES
        or name in IGNORED_FILE_NAMES
        or name.endswith((".pyc", ".pyo", ".tfstate"))
        or ".tfstate." in name
    }


def copy_recipe_assets(source: Path, destination: Path) -> None:
    recipe_destination = destination / "recipe"
    recipe_destination.mkdir(parents=True)
    for relative in COPY_PATHS:
        shutil.copyfile(source / relative, recipe_destination / relative)
    for directory in COPY_DIRECTORIES:
        shutil.copytree(
            source / directory,
            recipe_destination / directory,
            ignore=ignored_recipe_assets,
        )


def working_tree_digest(root: Path) -> str:
    paths = run(
        "git",
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        cwd=root,
    ).splitlines()
    digest = hashlib.sha256()
    for relative in sorted(
        path for path in paths if path and path not in MUTABLE_SOURCE_DIGEST_PATHS
    ):
        path = root / relative
        if not path.is_file():
            continue
        encoded = relative.encode()
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(path.stat().st_size.to_bytes(8, "big"))
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def artifact_inventory(bundle: Path) -> list[dict[str, object]]:
    inventory: list[dict[str, object]] = []
    total_bytes = 0
    for path in sorted(bundle.rglob("*")):
        if not path.is_file() or path.name == MARKER:
            continue
        relative = path.relative_to(bundle).as_posix()
        size_bytes = path.stat().st_size
        if size_bytes > MAX_SINGLE_ARTIFACT_BYTES:
            raise SystemExit(
                f"release artifact exceeds {MAX_SINGLE_ARTIFACT_BYTES} bytes: "
                f"{relative}"
            )
        total_bytes += size_bytes
        inventory.append(
            {
                "path": relative,
                "sha256": sha256(path),
                "size_bytes": size_bytes,
            }
        )
        if len(inventory) > MAX_ARTIFACT_COUNT:
            raise SystemExit(
                f"release contains more than {MAX_ARTIFACT_COUNT} artifacts"
            )
        if total_bytes > MAX_ARTIFACT_BYTES:
            raise SystemExit(
                f"release artifacts exceed {MAX_ARTIFACT_BYTES} total bytes"
            )
    return inventory


def safe_replace(staging: Path, output: Path) -> None:
    if output.exists():
        if not (output / MARKER).is_file():
            raise SystemExit(f"refusing to replace unmarked output directory: {output}")
        shutil.rmtree(output)
    staging.replace(output)


def sign_manifest(output: Path, private_key: Path, public_key: Path | None) -> None:
    manifest = output / "manifest.json"
    signature = output / "manifest.sig"
    if public_key is not None:
        shutil.copyfile(public_key, output / "manifest.pub")
    subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            os.fspath(private_key),
            "-in",
            os.fspath(manifest),
            "-out",
            os.fspath(signature),
        ],
        check=True,
    )
    if public_key is not None:
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                os.fspath(public_key),
                "-in",
                os.fspath(manifest),
                "-sigfile",
                os.fspath(signature),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image-uri", required=True)
    parser.add_argument("--output", type=Path, default=Path("target/recipe-release"))
    parser.add_argument("--signing-key", type=Path)
    parser.add_argument("--signing-public-key", type=Path)
    args = parser.parse_args()
    if not IMAGE_PATTERN.fullmatch(args.image_uri):
        raise SystemExit("--image-uri must be an immutable @sha256 reference")
    if bool(args.signing_key) != bool(args.signing_public_key):
        raise SystemExit(
            "--signing-key and --signing-public-key must be supplied together"
        )

    root = Path(__file__).resolve().parents[1]
    recipe = root / "recipes" / RECIPE_ID
    output = args.output if args.output.is_absolute() else root / args.output
    if output in {root, recipe, Path.home()}:
        raise SystemExit(f"unsafe output path: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        staging_marker = staging / STAGING_MARKER
        staging_marker.write_text("bridgefu recipe release staging\n")
        source_tree_sha256 = working_tree_digest(root)
        copy_recipe_assets(recipe, staging)
        lambda_output = staging / "artifacts" / "lambda"
        runtime_output = staging / "artifacts" / "runtime"
        demo_site_output = staging / "artifacts" / "demo-site"
        qualification_output = staging / "artifacts" / "qualification"
        subprocess.run(
            [
                "python3",
                os.fspath(root / "scripts" / "build-recipe-lambdas.py"),
                "--output",
                os.fspath(lambda_output),
            ],
            cwd=root,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        try:
            subprocess.run(
                [
                    "python3",
                    os.fspath(root / "scripts" / "build-recipe-demo-site.py"),
                    "--output",
                    os.fspath(demo_site_output),
                    "--release-staging-root",
                    os.fspath(staging),
                ],
                cwd=root,
                check=True,
                stdout=subprocess.DEVNULL,
            )
        finally:
            staging_marker.unlink(missing_ok=True)
        subprocess.run(
            [
                "python3",
                os.fspath(root / "scripts" / "build-recipe-runtime.py"),
                "--output",
                os.fspath(runtime_output),
            ],
            cwd=root,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "python3",
                os.fspath(root / "scripts" / "build-recipe-qualification.py"),
                "--output",
                os.fspath(qualification_output),
                "--source-tree-sha256",
                source_tree_sha256,
            ],
            cwd=root,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        cargo = tomllib.loads((root / "Cargo.toml").read_text())
        source_revision = run("git", "rev-parse", "HEAD", cwd=root)
        source_dirty = bool(run("git", "status", "--porcelain", cwd=root))
        if working_tree_digest(root) != source_tree_sha256:
            raise SystemExit("working tree changed while building release")
        staged_recipe = staging / "recipe"
        manifest = {
            "schema_version": 1,
            "recipe": {
                "id": RECIPE_ID,
                "version": RECIPE_VERSION,
                "manifest_sha256": sha256(staged_recipe / "recipe.yaml"),
                "handoff_contract_sha256": sha256(
                    staged_recipe / "handoff-contract.json"
                ),
            },
            "bridgefu": {
                "version": cargo["package"]["version"],
                "source_revision": source_revision,
                "source_dirty": source_dirty,
                "source_tree_sha256": source_tree_sha256,
                "image_uri": args.image_uri,
            },
            "artifacts": artifact_inventory(staging),
            "signature": {
                "algorithm": "Ed25519",
                "detached_file": "manifest.sig" if args.signing_key else None,
                "public_key_file": "manifest.pub" if args.signing_public_key else None,
                "public_key_sha256": (
                    sha256(args.signing_public_key) if args.signing_public_key else None
                ),
            },
        }
        encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        (staging / "manifest.json").write_bytes(encoded)
        (staging / "manifest.sha256").write_text(
            f"{hashlib.sha256(encoded).hexdigest()}  manifest.json\n"
        )
        (staging / MARKER).write_text("bridgefu recipe release build\n")
        if args.signing_key:
            sign_manifest(staging, args.signing_key, args.signing_public_key)
        if working_tree_digest(root) != source_tree_sha256:
            raise SystemExit("working tree changed while building release")
        safe_replace(staging, output)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    print(output / "manifest.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
