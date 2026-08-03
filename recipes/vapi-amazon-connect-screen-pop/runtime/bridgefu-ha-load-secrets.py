#!/usr/bin/env python3
"""Load HA runtime secrets into bounded root-owned host files."""

from __future__ import annotations

import grp
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import quote


SECRET_ROOT = Path(os.environ.get("BRIDGEFU_SECRET_ROOT", "/run/bridgefu/secrets"))
PRIVATE_ROOT = Path(os.environ.get("BRIDGEFU_PRIVATE_TLS_ROOT", "/etc/bridgefu/private"))
PUBLIC_ROOT = Path(os.environ.get("BRIDGEFU_PUBLIC_TLS_ROOT", "/etc/bridgefu/tls"))
MAX_SECRET = 16 * 1024
HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
ARN = re.compile(r"^arn:aws[-a-z0-9]*:secretsmanager:[-a-z0-9]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$")


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value or len(value) > 4096 or any(char in value for char in "\r\n\0"):
        raise SystemExit(f"invalid {name}")
    return value


def secret(arn_name: str, region: str) -> str:
    arn = required(arn_name)
    if not ARN.fullmatch(arn):
        raise SystemExit(f"invalid {arn_name}")
    completed = subprocess.run(
        [
            "aws",
            "secretsmanager",
            "get-secret-value",
            "--region",
            region,
            "--secret-id",
            arn,
            "--query",
            "SecretString",
            "--output",
            "text",
            "--no-cli-pager",
        ],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "AWS_PAGER": ""},
    )
    value = completed.stdout
    if value.endswith("\n"):
        value = value[:-1]
    if not value or len(value.encode()) > MAX_SECRET or "\0" in value:
        raise SystemExit(f"invalid secret material for {arn_name}")
    return value


def atomic(path: Path, value: str, group: int) -> None:
    encoded = value.encode()
    if not encoded or len(encoded) > MAX_SECRET or b"\0" in encoded:
        raise SystemExit("invalid bounded secret material")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, 0, group)
        os.chmod(temporary, 0o640)
        temporary.replace(path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def bounded_plain(name: str, value: str) -> str:
    if not 32 <= len(value) <= 4096 or any(char in value for char in "\r\n\0"):
        raise SystemExit(f"invalid {name}")
    return value


def database_url(raw: str) -> str:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise SystemExit("invalid database secret") from error
    if not isinstance(value, dict):
        raise SystemExit("invalid database secret")
    required_keys = {"username", "password", "host", "port"}
    if not required_keys.issubset(value):
        raise SystemExit("invalid database secret")
    username, password, host = (value[key] for key in ("username", "password", "host"))
    port = value["port"]
    database = value.get("dbname", "bridgefu")
    if not all(isinstance(item, str) and item for item in (username, password, host, database)):
        raise SystemExit("invalid database secret")
    if not HOST.fullmatch(host) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise SystemExit("invalid database secret")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,62}", database):
        raise SystemExit("invalid database secret")
    return (
        f"postgres://{quote(username, safe='')}:{quote(password, safe='')}@"
        f"{host}:{port}/{database}?sslmode=require"
    )


def tls_bundle(raw: str, role: str) -> tuple[str, str, str]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise SystemExit("invalid private TLS secret") from error
    expected = {"ca_crt", "gateway_crt", "gateway_key", "worker_crt", "worker_key"}
    if not isinstance(value, dict) or set(value) != expected:
        raise SystemExit("invalid private TLS secret")
    for key in expected:
        material = value[key]
        if not isinstance(material, str) or not material.endswith("\n") or len(material) > MAX_SECRET:
            raise SystemExit("invalid private TLS secret")
    return value["ca_crt"], value[f"{role}_crt"], value[f"{role}_key"]


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("Bridgefu HA secret loader must run as root")
    region = required("AWS_REGION")
    role = required("BRIDGEFU_ROLE")
    if role not in {"gateway", "worker"}:
        raise SystemExit("invalid BRIDGEFU_ROLE")
    group = grp.getgrnam("bridgefu").gr_gid

    values = {
        "api-bearer": bounded_plain(
            "API bearer secret", secret("BRIDGEFU_API_BEARER_SECRET_ARN", region)
        ),
        "control-hmac": bounded_plain(
            "control HMAC secret", secret("BRIDGEFU_CONTROL_HMAC_SECRET_ARN", region)
        ),
        "private-forwarding": bounded_plain(
            "private forwarding secret",
            secret("BRIDGEFU_PRIVATE_FORWARDING_SECRET_ARN", region),
        ),
        "broadcast-token": bounded_plain(
            "broadcast token secret", secret("BRIDGEFU_BROADCAST_SECRET_ARN", region)
        ),
        "database-url": database_url(secret("BRIDGEFU_DATABASE_SECRET_ARN", region)),
    }
    redis_password = bounded_plain(
        "Redis password", secret("BRIDGEFU_REDIS_PASSWORD_SECRET_ARN", region)
    )
    redis_host = required("BRIDGEFU_REDIS_ENDPOINT")
    if not HOST.fullmatch(redis_host):
        raise SystemExit("invalid BRIDGEFU_REDIS_ENDPOINT")
    values["redis-url"] = (
        f"rediss://bridgefu:{quote(redis_password, safe='')}@{redis_host}:6379"
    )
    for name, value in values.items():
        atomic(SECRET_ROOT / name, value, group)

    ca, certificate, private_key = tls_bundle(
        secret("BRIDGEFU_PRIVATE_TLS_SECRET_ARN", region), role
    )
    atomic(PRIVATE_ROOT / "ca.crt", ca, group)
    atomic(PRIVATE_ROOT / f"{role}.crt", certificate, group)
    atomic(PRIVATE_ROOT / f"{role}.key", private_key, group)
    if role == "worker":
        # The catalog-only recipe projection fingerprints the same public TLS
        # paths as the gateway. Workers never bind these files; keeping a valid
        # identity at the same paths preserves exact profile parity without
        # granting workers ACM export permission.
        atomic(PUBLIC_ROOT / "fullchain.pem", certificate, group)
        atomic(PUBLIC_ROOT / "private-key.pem", private_key, group)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
