#!/usr/bin/env python3
"""Run both real-protocol examples with both G.711 codecs and hangup ends."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.unlink(missing_ok=True)
    subprocess.run(
        ["cargo", "build", "--locked", "--example", "native-sip-webrtc"],
        cwd=ROOT,
        check=True,
    )
    results = []
    with tempfile.TemporaryDirectory(prefix="bridgefu-native-e2e-") as directory:
        directory = Path(directory)
        for direction in ("sip-to-webrtc", "webrtc-to-sip"):
            baseline = json.loads(
                (ROOT / "examples" / direction / "settings.example.json").read_text()
            )
            for codec in ("pcmu", "pcma"):
                for hangup in ("source", "destination"):
                    settings = dict(baseline, sip_codec=codec, hangup=hangup)
                    # Exercise customer-defined identifiers as well as the documented defaults.
                    if codec == "pcma":
                        settings.update(
                            tenant="custom-team",
                            route_id="custom-route",
                            sip_user="custom-peer",
                        )
                    config = directory / "settings.json"
                    config.write_text(json.dumps(settings))
                    report = directory / "report.json"
                    report.unlink(missing_ok=True)
                    subprocess.run(
                        [
                            str(ROOT / "target/debug/examples/native-sip-webrtc"),
                            "--settings",
                            str(config),
                            "--report",
                            str(report),
                        ],
                        cwd=ROOT,
                        check=True,
                        timeout=110,
                    )
                    result = json.loads(report.read_text())
                    assert result["passed"] and result["cleanup_verified"]
                    results.append(result)
                    print(f"PASS {direction}: {codec}, {hangup} hangup", flush=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps({"schema_version": 1, "passed": True, "cases": results}, indent=2)
        + "\n"
    )
    print(
        "All eight local end-to-end cases passed. Temporary files and endpoints were removed."
    )


if __name__ == "__main__":
    main()
