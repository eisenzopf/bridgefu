#!/usr/bin/env python3
"""Apply Bridgefu's release vulnerability policy to retained Trivy reports."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any


DENIED_SEVERITIES = {"HIGH", "CRITICAL"}
EXPECTED_PLATFORMS = {"linux/amd64", "linux/arm64"}


class PolicyError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_report(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PolicyError(f"{path} is not a readable Trivy JSON report") from error
    if not isinstance(value, dict) or value.get("SchemaVersion") != 2:
        raise PolicyError(f"{path} is not a Trivy schema-version 2 report")
    if value.get("ArtifactType") not in {"container_image", "oci_image"}:
        raise PolicyError(f"{path} did not scan a container/OCI image")
    return value


def report_platform(report: dict[str, Any]) -> str:
    metadata = report.get("Metadata")
    image_config = metadata.get("ImageConfig") if isinstance(metadata, dict) else None
    if not isinstance(image_config, dict):
        raise PolicyError("Trivy report has no image configuration metadata")
    os_name = image_config.get("os")
    architecture = image_config.get("architecture")
    if not isinstance(os_name, str) or not isinstance(architecture, str):
        raise PolicyError("Trivy report has no concrete OS/architecture")
    return f"{os_name}/{architecture}"


def evaluate(path: Path, expected_platform: str) -> dict[str, Any]:
    report = load_report(path)
    observed_platform = report_platform(report)
    if observed_platform != expected_platform:
        raise PolicyError(
            f"{path} scanned {observed_platform}, expected {expected_platform}"
        )
    results = report.get("Results")
    if not isinstance(results, list) or not results:
        raise PolicyError(f"{path} contains no vulnerability scan results")

    counts: dict[str, int] = {}
    denied: list[str] = []
    for result in results:
        if not isinstance(result, dict):
            raise PolicyError(f"{path} contains a malformed result")
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is None:
            continue
        if not isinstance(vulnerabilities, list):
            raise PolicyError(f"{path} contains a malformed vulnerability list")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise PolicyError(f"{path} contains a malformed vulnerability")
            severity = vulnerability.get("Severity")
            identifier = vulnerability.get("VulnerabilityID")
            if not isinstance(severity, str) or not isinstance(identifier, str):
                raise PolicyError(f"{path} contains an unclassified vulnerability")
            normalized = severity.upper()
            counts[normalized] = counts.get(normalized, 0) + 1
            if normalized in DENIED_SEVERITIES:
                denied.append(identifier)

    if denied:
        raise PolicyError(
            f"{expected_platform} violates the HIGH/CRITICAL policy "
            f"({len(denied)} findings; first: {denied[0]})"
        )
    return {
        "platform": expected_platform,
        "report": path.name,
        "report_sha256": sha256_file(path),
        "severity_counts": dict(sorted(counts.items())),
        "denied_severities": sorted(DENIED_SEVERITIES),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--report",
        action="append",
        required=True,
        metavar="PLATFORM=PATH",
        help="Trivy JSON report for one exact platform",
    )
    parser.add_argument("--image-archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    reports: dict[str, Path] = {}
    for value in args.report:
        platform, separator, raw_path = value.partition("=")
        if not separator or platform not in EXPECTED_PLATFORMS or not raw_path:
            raise PolicyError(f"invalid --report value: {value}")
        if platform in reports:
            raise PolicyError(f"duplicate report for {platform}")
        reports[platform] = Path(raw_path)
    if set(reports) != EXPECTED_PLATFORMS:
        missing = ", ".join(sorted(EXPECTED_PLATFORMS.difference(reports)))
        raise PolicyError(f"missing vulnerability report for {missing}")
    if not args.image_archive.is_file():
        raise PolicyError("the scanned OCI archive does not exist")

    evaluated = [evaluate(reports[platform], platform) for platform in sorted(reports)]
    evidence = {
        "schema_version": 1,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "policy": "deny-high-critical",
        "image_archive": args.image_archive.name,
        "image_archive_sha256": sha256_file(args.image_archive),
        "reports": evaluated,
    }
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    try:
        main()
    except PolicyError as error:
        raise SystemExit(f"release vulnerability policy failed: {error}") from error
