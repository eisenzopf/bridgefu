#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
  "") mode="scan" ;;
  --self-test) mode="self-test" ;;
  *)
    echo "neutral naming check: usage: $0 [--self-test]" >&2
    exit 1
    ;;
esac

# Keep the prohibited label out of the repository, including this guard. The
# one-way fingerprint covers its lowercase form after separators are removed.
python3 - "${mode}" <<'PY'
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path


PROHIBITED_LENGTH = 15
PROHIBITED_SHA256 = bytes.fromhex(
    "25cc8558a3c67090bb542dfc06550cfa363bfcd34be36fb77e9dc0a61f7a3197"
)
SKIPPED_PARTS = frozenset({".git", "target", "node_modules"})


def normalized_with_offsets(data: bytes) -> tuple[bytes, list[int]]:
    normalized = bytearray()
    offsets: list[int] = []
    for offset, byte in enumerate(data):
        if ord("A") <= byte <= ord("Z"):
            byte += ord("a") - ord("A")
        if not (ord("a") <= byte <= ord("z") or ord("0") <= byte <= ord("9")):
            continue
        normalized.append(byte)
        offsets.append(offset)
    return bytes(normalized), offsets


def prohibited_offset(
    data: bytes,
    *,
    length: int = PROHIBITED_LENGTH,
    fingerprint: bytes = PROHIBITED_SHA256,
) -> int | None:
    normalized, offsets = normalized_with_offsets(data)
    if len(normalized) < length:
        return None
    for start in range(len(normalized) - length + 1):
        if hashlib.sha256(normalized[start : start + length]).digest() == fingerprint:
            return offsets[start]
    return None


def self_test() -> None:
    # Exercise the generic fingerprint matcher with a neutral stand-in so the
    # prohibited label never has to appear in source or test fixtures.
    sample = b"exampletenant"
    fingerprint = hashlib.sha256(sample).digest()
    length = len(sample)
    rejected = (
        sample,
        b"ExampleTenant",
        b"example tenant",
        b"example_tenant",
        b"example-tenant",
        b"example\ntenant",
        b"example/tenant",
        b"example::<tenant>",
        b"prefix-example\r\n\t_tenant-suffix",
    )
    allowed = (b"reference-tenant", b"example renter", b"tenant example")
    if any(
        prohibited_offset(value, length=length, fingerprint=fingerprint) is None
        for value in rejected
    ):
        raise SystemExit("neutral naming check: self-test failed to reject a variant")
    if any(
        prohibited_offset(value, length=length, fingerprint=fingerprint) is not None
        for value in allowed
    ):
        raise SystemExit("neutral naming check: self-test rejected a neutral value")
    print("neutral naming check: self-test passed")


def repository_paths() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        check=True,
        stdout=subprocess.PIPE,
    )
    return [
        Path(value.decode(errors="surrogateescape"))
        for value in result.stdout.split(b"\0")
        if value
    ]


def scan_repository() -> None:
    inside = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if inside.returncode != 0:
        raise SystemExit("neutral naming check: run this check from a Git worktree")

    failures: list[str] = []
    for path in repository_paths():
        if any(part in SKIPPED_PARTS for part in path.parts):
            continue
        if not path.exists() and not path.is_symlink():
            continue
        rendered = str(path)
        if prohibited_offset(rendered.encode(errors="surrogateescape")) is not None:
            failures.append(f"prohibited filename: {rendered}")
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        if b"\0" in data[:8192]:
            continue
        offset = prohibited_offset(data)
        if offset is not None:
            line = data.count(b"\n", 0, offset) + 1
            failures.append(f"prohibited content: {rendered}:{line}")

    if failures:
        for failure in failures:
            print(f"neutral naming check: {failure}", file=sys.stderr)
        raise SystemExit(1)
    print("neutral naming check: repository is clean")


if sys.argv[1] == "self-test":
    self_test()
else:
    scan_repository()
PY
