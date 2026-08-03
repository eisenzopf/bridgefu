#!/usr/bin/env python3
"""Create or rotate the recipe-owned private HA mTLS bundle in Secrets Manager."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


DEPLOYMENT = re.compile(r"^[a-z][a-z0-9-]{2,23}$")
HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$"
)
REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")


def run(arguments: list[str], *, capture: bool = False) -> str:
    completed = subprocess.run(
        arguments,
        check=True,
        capture_output=capture,
        text=True,
        env={**os.environ, "AWS_PAGER": ""},
    )
    return completed.stdout if capture else ""


def openssl(arguments: list[str], root: Path) -> None:
    run(["openssl", *arguments], capture=True)
    for name in ("ca.key", "gateway.key", "worker.key"):
        path = root / name
        if path.exists():
            path.chmod(0o600)


def secret_metadata(name: str, region: str) -> dict[str, object] | None:
    completed = subprocess.run(
        [
            "aws",
            "secretsmanager",
            "describe-secret",
            "--region",
            region,
            "--secret-id",
            name,
            "--output",
            "json",
            "--no-cli-pager",
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "AWS_PAGER": ""},
    )
    if completed.returncode == 0:
        return json.loads(completed.stdout)
    if "ResourceNotFoundException" in completed.stderr:
        return None
    raise SystemExit(completed.stderr.strip() or "unable to inspect private TLS secret")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create the Bridgefu HA private CA and gateway/worker certificates."
    )
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--worker-hostname", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--secret-name")
    parser.add_argument("--kms-key-id")
    args = parser.parse_args()
    deployment = args.deployment_id.lower()
    hostname = args.worker_hostname.lower().rstrip(".")
    if not DEPLOYMENT.fullmatch(deployment):
        raise SystemExit("deployment ID must match ^[a-z][a-z0-9-]{2,23}$")
    if not HOSTNAME.fullmatch(hostname):
        raise SystemExit("worker hostname is invalid")
    if not REGION.fullmatch(args.region):
        raise SystemExit("AWS region is invalid")
    name = args.secret_name or f"bridgefu-{deployment}-ha-private-tls"
    if not re.fullmatch(r"[A-Za-z0-9/_+=.@-]{1,512}", name):
        raise SystemExit("secret name is invalid")

    existing = secret_metadata(name, args.region)
    if existing is not None:
        tags = {item["Key"]: item["Value"] for item in existing.get("Tags", [])}
        expected = {
            "ManagedBy": "bridgefu-ha-tls-helper",
            "BridgefuExecutionId": deployment,
        }
        if any(tags.get(key) != value for key, value in expected.items()):
            raise SystemExit(
                "refusing to rotate an existing secret not owned by this deployment"
            )

    with tempfile.TemporaryDirectory(prefix="bridgefu-ha-tls-") as temporary:
        root = Path(temporary)
        ca_key, ca_cert = root / "ca.key", root / "ca.crt"
        openssl(
            [
                "req",
                "-x509",
                "-newkey",
                "rsa:3072",
                "-sha256",
                "-nodes",
                "-days",
                "825",
                "-subj",
                f"/CN=bridgefu-{deployment}-private-ca",
                "-keyout",
                os.fspath(ca_key),
                "-out",
                os.fspath(ca_cert),
            ],
            root,
        )
        serial = root / "ca.srl"
        for role, common_name, usages, san in (
            (
                "gateway",
                f"bridgefu-{deployment}-gateway",
                "clientAuth,serverAuth",
                f"DNS:gateway.{hostname}",
            ),
            ("worker", hostname, "serverAuth,clientAuth", f"DNS:{hostname}"),
        ):
            key, request, certificate = (
                root / f"{role}.key",
                root / f"{role}.csr",
                root / f"{role}.crt",
            )
            extensions = root / f"{role}.ext"
            extensions.write_text(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\n"
                f"extendedKeyUsage={usages}\nsubjectAltName={san}\n"
            )
            extensions.chmod(0o600)
            openssl(
                [
                    "req",
                    "-new",
                    "-newkey",
                    "rsa:3072",
                    "-sha256",
                    "-nodes",
                    "-subj",
                    f"/CN={common_name}",
                    "-keyout",
                    os.fspath(key),
                    "-out",
                    os.fspath(request),
                ],
                root,
            )
            openssl(
                [
                    "x509",
                    "-req",
                    "-in",
                    os.fspath(request),
                    "-CA",
                    os.fspath(ca_cert),
                    "-CAkey",
                    os.fspath(ca_key),
                    "-CAserial",
                    os.fspath(serial),
                    "-CAcreateserial",
                    "-days",
                    "397",
                    "-sha256",
                    "-extfile",
                    os.fspath(extensions),
                    "-out",
                    os.fspath(certificate),
                ],
                root,
            )
            run(
                [
                    "openssl",
                    "verify",
                    "-CAfile",
                    os.fspath(ca_cert),
                    os.fspath(certificate),
                ],
                capture=True,
            )
        run(
            [
                "openssl",
                "verify",
                "-purpose",
                "sslserver",
                "-verify_hostname",
                hostname,
                "-CAfile",
                os.fspath(ca_cert),
                os.fspath(root / "worker.crt"),
            ],
            capture=True,
        )
        bundle = {
            "ca_crt": ca_cert.read_text(),
            "gateway_crt": (root / "gateway.crt").read_text(),
            "gateway_key": (root / "gateway.key").read_text(),
            "worker_crt": (root / "worker.crt").read_text(),
            "worker_key": (root / "worker.key").read_text(),
        }
        bundle_file = root / "bundle.json"
        bundle_file.write_text(json.dumps(bundle, separators=(",", ":")))
        bundle_file.chmod(0o600)
        if existing is None:
            command = [
                "aws",
                "secretsmanager",
                "create-secret",
                "--region",
                args.region,
                "--name",
                name,
                "--description",
                "Bridgefu HA private mTLS bundle; rotate slot by slot",
                "--secret-string",
                f"file://{bundle_file}",
                "--tags",
                "Key=Project,Value=bridgefu-recipe",
                "Key=ManagedBy,Value=bridgefu-ha-tls-helper",
                f"Key=BridgefuExecutionId,Value={deployment}",
                "Key=BridgefuRecipe,Value=vapi-amazon-connect-screen-pop@1",
                "--query",
                "ARN",
                "--output",
                "text",
                "--no-cli-pager",
            ]
            if args.kms_key_id:
                command[command.index("--tags"):command.index("--tags")] = [
                    "--kms-key-id",
                    args.kms_key_id,
                ]
            arn = run(command, capture=True).strip()
        else:
            run(
                [
                    "aws",
                    "secretsmanager",
                    "put-secret-value",
                    "--region",
                    args.region,
                    "--secret-id",
                    name,
                    "--secret-string",
                    f"file://{bundle_file}",
                    "--no-cli-pager",
                ],
                capture=True,
            )
            arn = str(existing["ARN"])
    print(arn)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
