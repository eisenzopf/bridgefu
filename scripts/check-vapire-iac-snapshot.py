#!/usr/bin/env python3
"""Verify the vendored Vapire library matches the sibling canonical source."""

from __future__ import annotations

import difflib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "crates" / "vapire-iac"
UPSTREAM = ROOT.parent / "vapire" / "crates" / "vapire-iac"
FILES = ("src/lib.rs", "src/api.rs", "src/model.rs", "src/extension.rs", "src/template.rs")


def main() -> int:
    if not UPSTREAM.is_dir():
        print("Vapire sibling is absent; clean builds use the reviewed vendored snapshot")
        return 0
    failures: list[str] = []
    for relative in FILES:
        expected = (UPSTREAM / relative).read_text().rstrip() + "\n"
        actual = (SNAPSHOT / relative).read_text().rstrip() + "\n"
        if expected == actual:
            continue
        failures.append(
            "".join(
                difflib.unified_diff(
                    actual.splitlines(keepends=True),
                    expected.splitlines(keepends=True),
                    fromfile=f"snapshot/{relative}",
                    tofile=f"vapire/{relative}",
                )
            )
        )
    if failures:
        raise SystemExit("vapire-iac snapshot drifted:\n" + "\n".join(failures))
    print("vapire-iac snapshot matches the canonical sibling library")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
