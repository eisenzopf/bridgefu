#!/usr/bin/env python3
"""Render strict, non-secret HA gateway or worker host assets."""

from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent
OUTPUT_ROOT = Path(os.environ.get("BRIDGEFU_RENDER_ROOT", "/"))
DEPLOYMENT = re.compile(r"^[a-z][a-z0-9-]{2,23}$")
SLOT = re.compile(r"^(?:gateway|worker)-[a-d]$")
GATEWAY_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
HOSTNAME = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$"
)
UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
FLOW_ID = re.compile(r"^[A-Za-z0-9-]{1,128}$")
CONNECT_ARN = re.compile(
    r"^arn:aws[-a-z0-9]*:connect:[-a-z0-9]+:[0-9]{12}:instance/[A-Za-z0-9-]+$"
)


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value or len(value) > 8192 or "\0" in value:
        raise SystemExit(f"invalid {name}")
    return value


def token(name: str) -> str:
    value = required(name)
    if any(char.isspace() for char in value):
        raise SystemExit(f"invalid {name}")
    return value


def destination(value: str) -> Path:
    return OUTPUT_ROOT / value.lstrip("/")


def render(name: str, output: Path, replacements: dict[str, str], mode: int) -> None:
    value = (ROOT / name).read_text()
    for key, replacement in replacements.items():
        value = value.replace(f"__{key}__", replacement)
    if re.search(r"__[A-Z0-9_]+__", value):
        raise SystemExit(f"unresolved placeholder in {name}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".new")
    temporary.write_text(value)
    os.chmod(temporary, mode)
    temporary.replace(output)


def hostname(name: str) -> str:
    value = token(name).rstrip(".").lower()
    if not HOSTNAME.fullmatch(value):
        raise SystemExit(f"invalid {name}")
    return value


def positive_integer(name: str, minimum: int, maximum: int) -> int:
    try:
        value = int(token(name))
    except ValueError as error:
        raise SystemExit(f"invalid {name}") from error
    if not minimum <= value <= maximum:
        raise SystemExit(f"invalid {name}")
    return value


def worker_targets(raw: str) -> str:
    try:
        values = json.loads(raw)
    except json.JSONDecodeError as error:
        raise SystemExit("invalid BRIDGEFU_WORKER_TARGETS_JSON") from error
    if not isinstance(values, list) or not 2 <= len(values) <= 4:
        raise SystemExit("invalid BRIDGEFU_WORKER_TARGETS_JSON")
    lines: list[str] = []
    seen_ids: set[str] = set()
    seen_endpoints: set[str] = set()
    for value in values:
        if not isinstance(value, dict) or set(value) != {
            "worker_id",
            "endpoint",
            "server_name",
        }:
            raise SystemExit("invalid BRIDGEFU_WORKER_TARGETS_JSON")
        worker_id = value["worker_id"]
        endpoint = value["endpoint"]
        server_name = value["server_name"]
        if not isinstance(worker_id, str) or not UUID.fullmatch(worker_id):
            raise SystemExit("invalid worker target ID")
        if not isinstance(endpoint, str) or endpoint.count(":") != 1:
            raise SystemExit("invalid worker target endpoint")
        endpoint_host, endpoint_port = endpoint.rsplit(":", 1)
        if not HOSTNAME.fullmatch(endpoint_host) or not endpoint_port.isdigit():
            raise SystemExit("invalid worker target endpoint")
        if not 1 <= int(endpoint_port) <= 65535:
            raise SystemExit("invalid worker target endpoint")
        if not isinstance(server_name, str) or not HOSTNAME.fullmatch(server_name):
            raise SystemExit("invalid worker target server name")
        if worker_id in seen_ids or endpoint in seen_endpoints:
            raise SystemExit("duplicate worker target")
        seen_ids.add(worker_id)
        seen_endpoints.add(endpoint)
        lines.extend(
            [
                f"      - worker_id: {worker_id}",
                f"        endpoint: {endpoint}",
                f"        server_name: {server_name}",
            ]
        )
    return "\n".join(lines)


def main() -> int:
    role = token("BRIDGEFU_ROLE")
    if role not in {"gateway", "worker"}:
        raise SystemExit("invalid BRIDGEFU_ROLE")
    slot = token("BRIDGEFU_SLOT")
    if not SLOT.fullmatch(slot) or not slot.startswith(f"{role}-"):
        raise SystemExit("invalid BRIDGEFU_SLOT")
    deployment = token("BRIDGEFU_DEPLOYMENT_ID")
    if not DEPLOYMENT.fullmatch(deployment):
        raise SystemExit("invalid BRIDGEFU_DEPLOYMENT_ID")
    region = token("AWS_REGION")
    sip_hostname = hostname("BRIDGEFU_SIP_HOSTNAME")
    uctp_hostname = hostname("BRIDGEFU_UCTP_HOSTNAME")
    public_ip = str(ipaddress.ip_address(token("BRIDGEFU_PUBLIC_IP")))
    if ipaddress.ip_address(public_ip).is_unspecified:
        raise SystemExit("invalid BRIDGEFU_PUBLIC_IP")
    instance_arn = token("CONNECT_INSTANCE_ARN")
    if not CONNECT_ARN.fullmatch(instance_arn):
        raise SystemExit("invalid CONNECT_INSTANCE_ARN")
    flow_id = token("CONNECT_ENTRY_FLOW_ID")
    if not FLOW_ID.fullmatch(flow_id):
        raise SystemExit("invalid CONNECT_ENTRY_FLOW_ID")
    security = token("BRIDGEFU_SIP_SECURITY")
    if security not in {"sips_srtp", "sip_rtp"}:
        raise SystemExit("invalid BRIDGEFU_SIP_SECURITY")
    maximum = positive_integer("BRIDGEFU_MAX_CONCURRENT_CALLS", 1, 1000)

    cidrs = token("VAPI_SIGNALING_CIDRS").split(",")
    if not 1 <= len(cidrs) <= 32:
        raise SystemExit("invalid VAPI_SIGNALING_CIDRS")
    normalized_cidrs = [str(ipaddress.ip_network(value, strict=True)) for value in cidrs]
    cidr_yaml = "\n".join(f"        - {value}" for value in normalized_cidrs)
    if security == "sips_srtp":
        edge = f"""  sip_tls:
    bind: 0.0.0.0:5061
    advertised_addr: {public_ip}:5061
    certificate_chain: /etc/bridgefu/tls/fullchain.pem
    private_key: /etc/bridgefu/tls/private-key.pem"""
    else:
        edge = f"""  sip_rtp:
    bind: 0.0.0.0:5060
    advertised_addr: {public_ip}:5060"""

    common = {
        "AWS_REGION": region,
        "SIP_HOSTNAME": sip_hostname,
        "UCTP_HOSTNAME": uctp_hostname,
        "PUBLIC_IP": public_ip,
        "SIP_EDGE_CONFIG": edge,
        "VAPI_SIGNALING_CIDRS": cidr_yaml,
        "CONNECT_INSTANCE_ARN": instance_arn,
        "CONNECT_ENTRY_FLOW_ID": flow_id,
        "SIP_SECURITY": security,
        "DEPLOYMENT_ID": deployment,
        "MAX_CONCURRENT_CALLS": str(maximum),
    }
    if role == "gateway":
        gateway_id = token("BRIDGEFU_GATEWAY_ID")
        if not GATEWAY_ID.fullmatch(gateway_id):
            raise SystemExit("invalid BRIDGEFU_GATEWAY_ID")
        common.update(
            {
                "GATEWAY_ID": gateway_id,
                "WORKER_TARGETS": worker_targets(required("BRIDGEFU_WORKER_TARGETS_JSON")),
                "FORWARDING_CAPACITY": str(min(2000, maximum * 2)),
                "PUBLIC_UCTP_CAPACITY": str(min(2000, maximum * 2)),
            }
        )
        template = "bridgefu-ha-gateway.yaml.tmpl"
    else:
        worker_id = token("BRIDGEFU_WORKER_ID")
        if not UUID.fullmatch(worker_id):
            raise SystemExit("invalid BRIDGEFU_WORKER_ID")
        common["WORKER_ID"] = worker_id
        template = "bridgefu-ha-worker.yaml.tmpl"

    render(template, destination("/etc/bridgefu/bridgefu.yaml"), common, 0o640)
    render(
        "prometheus-ha.yaml.tmpl",
        destination("/opt/aws/amazon-cloudwatch-agent/var/bridgefu-prometheus.yaml"),
        {"DEPLOYMENT_ID": deployment, "ROLE": role, "SLOT": slot},
        0o640,
    )
    render(
        "cloudwatch-agent-ha.json.tmpl",
        destination("/opt/aws/amazon-cloudwatch-agent/etc/bridgefu.json"),
        {
            "AWS_REGION": region,
            "DEPLOYMENT_ID": deployment,
            "ROLE": role,
            "SLOT": slot,
        },
        0o640,
    )
    json.loads(destination("/opt/aws/amazon-cloudwatch-agent/etc/bridgefu.json").read_text())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
