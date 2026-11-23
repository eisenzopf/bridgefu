#!/usr/bin/env python3
"""Preflight both deployment templates with temporary credentials and TLS files."""

import argparse
import os
from pathlib import Path
import secrets
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/bridgefu")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="bridgefu-native-config-") as temporary:
        directory = Path(temporary)
        certificate, key = directory / "cert.pem", directory / "key.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=bridgefu.example.com",
                "-keyout",
                str(key),
                "-out",
                str(certificate),
            ],
            check=True,
            capture_output=True,
        )
        key.chmod(0o600)
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("BRIDGEFU_", "AWS_", "VAPI_"))
        }
        env.update(
            BRIDGEFU_API_BEARER_TOKEN=secrets.token_urlsafe(32),
            BRIDGEFU_CONTROL_HMAC_KEY=secrets.token_hex(32),
            BRIDGEFU_TLS_PRIVATE_KEY_PATH=str(key),
        )
        for direction in ("sip-to-webrtc", "webrtc-to-sip"):
            text = (ROOT / "examples" / direction / "bridgefu.example.yaml").read_text()
            text = text.replace("/run/bridgefu/tls/fullchain.pem", str(certificate))
            text = text.replace(
                f"sqlite://examples/{direction}/.local/bridgefu.db",
                f"sqlite://{directory}/{direction}.db",
            )
            config = directory / f"{direction}.yaml"
            config.write_text(text)
            subprocess.run(
                [
                    str((ROOT / args.binary).resolve()),
                    "--config",
                    str(config),
                    "validate",
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            print(f"PASS {direction}: documented configuration preflight")


if __name__ == "__main__":
    main()
