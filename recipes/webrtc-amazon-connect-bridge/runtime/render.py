#!/usr/bin/env python3
"""Render the non-secret and origin-gate runtime files with strict inputs."""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent
OUTPUT_ROOT = Path(os.environ.get("BRIDGEFU_RENDER_ROOT", "/"))
DEPLOYMENT = re.compile(r"^[a-z][a-z0-9-]{2,31}$")
HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$"
)
CONNECT_ARN = re.compile(
    r"^arn:aws[-a-z0-9]*:connect:[-a-z0-9]+:[0-9]{12}:instance/[A-Za-z0-9-]+$"
)
FLOW_ID = re.compile(r"^[A-Za-z0-9-]{1,128}$")
SECRET = re.compile(r"^[A-Za-z0-9]{32,128}$")


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value or len(value) > 2048 or any(char in "\r\n\x00" for char in value):
        raise SystemExit(f"invalid {name}")
    return value


def render(source: str, destination: Path, replacements: dict[str, str], mode: int) -> None:
    value = (ROOT / source).read_text()
    for key, replacement in replacements.items():
        value = value.replace(f"__{key}__", replacement)
    if re.search(r"__[A-Z0-9_]+__", value):
        raise SystemExit(f"unresolved placeholder in {source}")
    temporary = destination.with_suffix(destination.suffix + ".new")
    temporary.write_text(value)
    os.chmod(temporary, mode)
    temporary.replace(destination)


def destination(value: str) -> Path:
    output = OUTPUT_ROOT / value.lstrip("/")
    output.parent.mkdir(parents=True, exist_ok=True)
    return output


def bounded_integer(name: str, minimum: int, maximum: int) -> int:
    try:
        value = int(required(name))
    except ValueError as error:
        raise SystemExit(f"invalid {name}") from error
    if value < minimum or value > maximum:
        raise SystemExit(f"invalid {name}")
    return value


def main() -> int:
    deployment = required("BRIDGEFU_DEPLOYMENT_ID")
    region = required("AWS_REGION")
    signaling_host = required("BRIDGEFU_SIGNALING_HOST").lower()
    public_ip = str(ipaddress.ip_address(required("BRIDGEFU_PUBLIC_IP")))
    instance_arn = required("CONNECT_INSTANCE_ARN")
    flow_id = required("CONNECT_ENTRY_FLOW_ID")
    origin_verify = required("BRIDGEFU_ORIGIN_VERIFY")
    maximum = bounded_integer("BRIDGEFU_MAX_CONCURRENT_CALLS", 1, 8)
    port_start = bounded_integer("BRIDGEFU_MEDIA_PORT_START", 1024, 65535)
    port_end = bounded_integer("BRIDGEFU_MEDIA_PORT_END", 1024, 65535)

    if not DEPLOYMENT.fullmatch(deployment):
        raise SystemExit("invalid BRIDGEFU_DEPLOYMENT_ID")
    if not re.fullmatch(r"[a-z]{2}-[a-z]+-[1-9]", region):
        raise SystemExit("invalid AWS_REGION")
    if not HOSTNAME.fullmatch(signaling_host):
        raise SystemExit("invalid BRIDGEFU_SIGNALING_HOST")
    if not isinstance(ipaddress.ip_address(public_ip), ipaddress.IPv4Address):
        raise SystemExit("BRIDGEFU_PUBLIC_IP must be IPv4")
    if not CONNECT_ARN.fullmatch(instance_arn):
        raise SystemExit("invalid CONNECT_INSTANCE_ARN")
    if not FLOW_ID.fullmatch(flow_id):
        raise SystemExit("invalid CONNECT_ENTRY_FLOW_ID")
    if not SECRET.fullmatch(origin_verify):
        raise SystemExit("invalid BRIDGEFU_ORIGIN_VERIFY")
    if port_start > port_end or (port_end - port_start + 1) < maximum * 2:
        raise SystemExit("media range requires at least two ports per concurrent call")

    render(
        "bridgefu.yaml.tmpl",
        destination("/etc/bridgefu/bridgefu.yaml"),
        {
            "AWS_REGION": region,
            "SIGNALING_HOST": signaling_host,
            "PUBLIC_IP": public_ip,
            "CONNECT_INSTANCE_ARN": instance_arn,
            "CONNECT_ENTRY_FLOW_ID": flow_id,
            "DEPLOYMENT_ID": deployment,
            "MEDIA_PORT_START": str(port_start),
            "MEDIA_PORT_END": str(port_end),
            "MAX_CONCURRENT_CALLS": str(maximum),
        },
        0o640,
    )
    render(
        "nginx.conf.tmpl",
        destination("/etc/nginx/nginx.conf"),
        {"ORIGIN_VERIFY": origin_verify},
        0o600,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
