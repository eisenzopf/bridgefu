#!/usr/bin/env python3
"""Build the immutable source bundle used by the AWS qualification runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path


MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_BINARY_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_BYTES = 48 * 1024 * 1024
MAX_FILES = 2_000
EPOCH = (1980, 1, 1, 0, 0, 0)

ROOT_FILES = (
    "Cargo.toml",
    "Cargo.lock",
)
ROOT_DIRECTORIES = (
    "src",
    "migrations",
)
EXPLICIT_FILES = (
    "Dockerfile",
    "deploy/Dockerfile",
    "deploy/Dockerfile.qualification",
    "examples/recipe_sip_source.rs",
    "examples/recipe_sip_negative.rs",
    "scripts/aws-recipe-live-test.py",
    "scripts/build-recipe-qualification.py",
    "scripts/collect-recipe-call-evidence.py",
    "scripts/run-recipe-qualification.py",
    "scripts/run-aws-packaged-qualification.py",
    "scripts/validate-recipe-evidence.py",
    "sdk/typescript/package.json",
    "sdk/typescript/package-lock.json",
    "sdk/typescript/tsconfig.json",
    "tools/recipe-qualification/Cargo.toml",
)
EXPLICIT_DIRECTORIES = (
    "sdk/typescript/src",
    "recipes/vapi-amazon-connect-screen-pop/qualification",
    "recipes/vapi-amazon-connect-screen-pop/demo-site",
)
IGNORED_PARTS = {
    ".DS_Store",
    ".pytest_cache",
    "__pycache__",
    "dist",
    "node_modules",
    "target",
}
QUALIFICATION_BINARIES = (
    "recipe_sip_source",
    "recipe_sip_negative",
)
QUALIFICATION_PLATFORM = "linux/amd64"
QUALIFICATION_TARGET = "x86_64-unknown-linux-gnu.2.31"
QUALIFICATION_RUST_TOOLCHAIN = "1.95.0"
QUALIFICATION_DEBIAN_SNAPSHOT = "20260202T000000Z"
MAXIMUM_GLIBC = (2, 31)
PINNED_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
DEBIAN_SNAPSHOT = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
RUST_TOOLCHAIN = re.compile(r"^[1-9][0-9]*\.[0-9]+\.[0-9]+$")
GNU_TARGET = re.compile(r"^x86_64-unknown-linux-gnu\.([0-9]+)\.([0-9]+)$")
GLIBC_VERSION = re.compile(rb"GLIBC_([0-9]+)\.([0-9]+)")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def pinned_image_argument(dockerfile: Path, name: str) -> str:
    prefix = f"ARG {name}="
    matches = [
        line.removeprefix(prefix)
        for line in dockerfile.read_text().splitlines()
        if line.startswith(prefix)
    ]
    if len(matches) != 1 or PINNED_IMAGE.fullmatch(matches[0]) is None:
        raise SystemExit(f"{dockerfile.name} has no unique pinned {name} image")
    return matches[0]


def unique_argument(
    dockerfile: Path, name: str, pattern: re.Pattern[str], label: str
) -> str:
    prefix = f"ARG {name}="
    matches = [
        line.removeprefix(prefix)
        for line in dockerfile.read_text(encoding="utf-8").splitlines()
        if line.startswith(prefix)
    ]
    if len(matches) != 1 or pattern.fullmatch(matches[0]) is None:
        raise SystemExit(f"{dockerfile.name} has no unique pinned {label}")
    return matches[0]


def qualification_builder_images(root: Path) -> dict[str, str]:
    dockerfile = root / "deploy" / "Dockerfile.qualification"
    parent = pinned_image_argument(dockerfile, "QUALIFICATION_BUILDER_IMAGE")
    amd64 = pinned_image_argument(dockerfile, "QUALIFICATION_BUILDER_AMD64_IMAGE")
    arm64 = pinned_image_argument(dockerfile, "QUALIFICATION_BUILDER_ARM64_IMAGE")
    values = (parent, amd64, arm64)
    stems = {value.rsplit("@sha256:", 1)[0] for value in values}
    digests = {value.rsplit("@sha256:", 1)[1] for value in values}
    if len(stems) != 1 or len(digests) != len(values):
        raise SystemExit("qualification builder image bindings are invalid")
    return {
        "multi_platform_index": parent,
        "linux/amd64": amd64,
        "linux/arm64": arm64,
    }


def qualification_builder_configuration(root: Path) -> dict[str, str]:
    dockerfile = root / "deploy" / "Dockerfile.qualification"
    snapshot = unique_argument(
        dockerfile,
        "QUALIFICATION_DEBIAN_SNAPSHOT",
        DEBIAN_SNAPSHOT,
        "qualification Debian snapshot",
    )
    toolchain = unique_argument(
        dockerfile,
        "QUALIFICATION_RUST_TOOLCHAIN",
        RUST_TOOLCHAIN,
        "qualification Rust toolchain",
    )
    target = unique_argument(
        dockerfile,
        "QUALIFICATION_TARGET",
        GNU_TARGET,
        "qualification target",
    )
    target_match = GNU_TARGET.fullmatch(target)
    if target_match is None:
        raise SystemExit("qualification target is invalid")
    maximum_glibc = (int(target_match.group(1)), int(target_match.group(2)))
    if (
        snapshot != QUALIFICATION_DEBIAN_SNAPSHOT
        or toolchain != QUALIFICATION_RUST_TOOLCHAIN
        or target != QUALIFICATION_TARGET
        or maximum_glibc != MAXIMUM_GLIBC
    ):
        raise SystemExit("qualification builder configuration changed unexpectedly")
    return {
        "debian_snapshot": snapshot,
        "rust_toolchain": toolchain,
        "target": target,
        "maximum_glibc": f"{maximum_glibc[0]}.{maximum_glibc[1]}",
    }


def verify_qualification_builder_index(root: Path, images: dict[str, str]) -> None:
    try:
        result = subprocess.run(
            ["docker", "manifest", "inspect", images["multi_platform_index"]],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(
            "could not verify the qualification builder image index"
        ) from error
    if not 0 < len(result.stdout) <= 2_000_000:
        raise SystemExit("qualification builder image index response is invalid")
    try:
        manifest = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise SystemExit("qualification builder image index is not JSON") from error
    if not isinstance(manifest, dict):
        raise SystemExit("qualification builder image index has an invalid shape")
    descriptors = manifest.get("manifests")
    if (
        manifest.get("schemaVersion") != 2
        or not isinstance(descriptors, list)
        or not 1 <= len(descriptors) <= 32
    ):
        raise SystemExit("qualification builder image index has an invalid shape")
    for platform in ("linux/amd64", "linux/arm64"):
        operating_system, architecture = platform.split("/", 1)
        matches = []
        for descriptor in descriptors:
            descriptor_platform = (
                descriptor.get("platform") if isinstance(descriptor, dict) else None
            )
            digest = descriptor.get("digest") if isinstance(descriptor, dict) else None
            if (
                isinstance(descriptor_platform, dict)
                and descriptor_platform.get("os") == operating_system
                and descriptor_platform.get("architecture") == architecture
            ):
                if (
                    not isinstance(digest, str)
                    or IMAGE_DIGEST.fullmatch(digest) is None
                ):
                    raise SystemExit(
                        "qualification builder image index has an invalid child digest"
                    )
                matches.append(digest)
        expected = images[platform].rsplit("@", 1)[1]
        if matches != [expected]:
            raise SystemExit(
                f"qualification builder image index does not bind {platform}"
            )


def docker_daemon_platform(root: Path) -> str:
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.OSType}}/{{.Architecture}}"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as error:
        raise SystemExit("could not inspect the Docker daemon platform") from error
    aliases = {
        "linux/amd64": "linux/amd64",
        "linux/x86_64": "linux/amd64",
        "linux/arm64": "linux/arm64",
        "linux/aarch64": "linux/arm64",
    }
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    platform = aliases.get(lines[0]) if len(lines) == 1 else None
    if platform is None:
        raise SystemExit("Docker daemon must be native linux/amd64 or linux/arm64")
    return platform


def inspect_docker_image_platform(
    root: Path, image: str, label: str, expected: str
) -> None:
    try:
        result = subprocess.run(
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Os}}/{{.Architecture}}",
                image,
            ],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"could not inspect {label} platform") from error
    actual = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if actual != [expected]:
        rendered = ",".join(actual) if actual else "invalid"
        raise SystemExit(f"{label} resolved to {rendered}, expected {expected}")


def validate_qualification_binary(binary: Path, name: str) -> str:
    details = binary.lstat()
    if (
        binary.is_symlink()
        or not stat.S_ISREG(details.st_mode)
        or not 0 < details.st_size <= MAX_BINARY_BYTES
    ):
        raise SystemExit(f"qualification binary is invalid: {name}")
    data = binary.read_bytes()
    header = data[:20]
    if (
        len(header) != 20
        or header[:6] != b"\x7fELF\x02\x01"
        or header[18:20] != b"\x3e\x00"
    ):
        raise SystemExit(f"qualification binary has the wrong platform: {name}")
    versions = {
        (int(match.group(1)), int(match.group(2)))
        for match in GLIBC_VERSION.finditer(data)
    }
    if not versions or max(versions) > MAXIMUM_GLIBC:
        raise SystemExit(f"qualification binary has an incompatible glibc: {name}")
    maximum = max(versions)
    return f"{maximum[0]}.{maximum[1]}"


def source_files(root: Path) -> list[Path]:
    candidates: list[Path] = []
    for relative in ROOT_FILES + EXPLICIT_FILES:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f"qualification source input is missing: {relative}")
        candidates.append(path)
    for relative in ROOT_DIRECTORIES + EXPLICIT_DIRECTORIES:
        directory = root / relative
        if not directory.is_dir() or directory.is_symlink():
            raise SystemExit(f"qualification source directory is missing: {relative}")
        candidates.extend(path for path in directory.rglob("*") if path.is_file())
    result = sorted(
        {
            path
            for path in candidates
            if not path.is_symlink()
            and not any(part in IGNORED_PARTS for part in path.relative_to(root).parts)
            and not path.name.endswith((".pyc", ".pyo"))
        },
        key=lambda path: path.relative_to(root).as_posix(),
    )
    if not result or len(result) + len(QUALIFICATION_BINARIES) > MAX_FILES:
        raise SystemExit("qualification source file count is outside its boundary")
    return result


def build_qualification_binaries(root: Path, destination: Path) -> dict[str, object]:
    token = f"{os.getpid()}-{os.urandom(4).hex()}"
    image = f"bridgefu-qualification-binaries:{token}"
    builder_images = qualification_builder_images(root)
    builder_configuration = qualification_builder_configuration(root)
    host_platform = docker_daemon_platform(root)
    builder_image = builder_images[host_platform]
    container_id: str | None = None
    try:
        verify_qualification_builder_index(root, builder_images)
        subprocess.run(
            [
                "docker",
                "pull",
                "--platform",
                host_platform,
                builder_image,
            ],
            cwd=root,
            check=True,
        )
        inspect_docker_image_platform(
            root, builder_image, "qualification builder", host_platform
        )
        subprocess.run(
            [
                "docker",
                "build",
                "--file",
                os.fspath(root / "deploy" / "Dockerfile.qualification"),
                "--target",
                "qualification-binaries",
                "--build-arg",
                f"QUALIFICATION_BUILDER_IMAGE={builder_image}",
                "--tag",
                image,
                os.fspath(root),
            ],
            cwd=root,
            check=True,
        )
        created = subprocess.run(
            [
                "docker",
                "create",
                image,
                "/recipe_sip_source",
                "--version",
            ],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
        container_id = created.stdout.strip()
        if len(container_id) != 64 or any(
            value not in "0123456789abcdef" for value in container_id
        ):
            raise SystemExit("qualification binary container ID is invalid")
        for name in QUALIFICATION_BINARIES:
            subprocess.run(
                [
                    "docker",
                    "cp",
                    f"{container_id}:/{name}",
                    os.fspath(destination / name),
                ],
                cwd=root,
                check=True,
            )
    finally:
        if container_id is not None:
            subprocess.run(
                ["docker", "rm", container_id],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        subprocess.run(
            ["docker", "image", "rm", image],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    actual = {path.name for path in destination.iterdir() if path.is_file()}
    if actual != set(QUALIFICATION_BINARIES):
        raise SystemExit("qualification binary output is incomplete")
    glibc = {
        name: validate_qualification_binary(destination / name, name)
        for name in QUALIFICATION_BINARIES
    }
    return {
        "host_platform": host_platform,
        "image": builder_image,
        "images": builder_images,
        **builder_configuration,
        "binary_glibc": glibc,
    }


def write_zip(
    root: Path,
    output: Path,
    tree_digest: str,
    binary_directory: Path,
    build_contract: dict[str, object],
) -> dict[str, object]:
    files = source_files(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    inventory: list[dict[str, object]] = []
    total = 0
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", dir=output.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(
            temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            for path in files:
                data = path.read_bytes()
                if not data or len(data) > MAX_FILE_BYTES:
                    raise SystemExit(
                        f"qualification source file size is invalid: {path.relative_to(root)}"
                    )
                relative = path.relative_to(root).as_posix()
                mode = 0o755 if os.access(path, os.X_OK) else 0o644
                info = zipfile.ZipInfo(relative, EPOCH)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | mode) << 16
                archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
                total += len(data)
                inventory.append(
                    {
                        "path": relative,
                        "sha256": sha256_bytes(data),
                        "size_bytes": len(data),
                    }
                )
                if total > MAX_EXPANDED_BYTES:
                    raise SystemExit(
                        "qualification source inputs exceed their expanded-byte boundary"
                    )
            for name in QUALIFICATION_BINARIES:
                path = binary_directory / name
                data = path.read_bytes()
                relative = f"target/release/examples/{name}"
                info = zipfile.ZipInfo(relative, EPOCH)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o755) << 16
                archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
                total += len(data)
                inventory.append(
                    {
                        "path": relative,
                        "sha256": sha256_bytes(data),
                        "size_bytes": len(data),
                    }
                )
                if total > MAX_EXPANDED_BYTES or len(inventory) > MAX_FILES:
                    raise SystemExit(
                        "qualification archive exceeds its expanded boundary"
                    )
            digest_info = zipfile.ZipInfo(".bridgefu-source-tree-sha256", EPOCH)
            digest_info.create_system = 3
            digest_info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(digest_info, f"{tree_digest}\n".encode())
        if temporary.stat().st_size > MAX_ARCHIVE_BYTES:
            raise SystemExit("qualification source archive exceeds its size boundary")
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "schema_version": 2,
        "source_tree_sha256": tree_digest,
        "archive": {
            "path": output.name,
            "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
            "size_bytes": output.stat().st_size,
        },
        "source_file_count": len(inventory),
        "source_bytes": total,
        "binary_platform": QUALIFICATION_PLATFORM,
        "builder": build_contract,
        "qualification_binaries": [
            f"target/release/examples/{name}" for name in QUALIFICATION_BINARIES
        ],
        "files": inventory,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-tree-sha256", required=True)
    args = parser.parse_args()
    if len(args.source_tree_sha256) != 64 or any(
        value not in "0123456789abcdef" for value in args.source_tree_sha256
    ):
        raise SystemExit("--source-tree-sha256 must be lowercase SHA-256")
    root = Path(__file__).resolve().parents[1]
    output = args.output if args.output.is_absolute() else root / args.output
    output.mkdir(parents=True, exist_ok=True)
    archive = output / "qualification-source.zip"
    with tempfile.TemporaryDirectory(
        prefix=".qualification-binaries-", dir=output
    ) as directory:
        binary_directory = Path(directory)
        build_contract = build_qualification_binaries(root, binary_directory)
        manifest = write_zip(
            root,
            archive,
            args.source_tree_sha256,
            binary_directory,
            build_contract,
        )
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(archive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
