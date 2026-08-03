#!/usr/bin/env python3
"""Render bounded, non-secret Starter Production configuration assets."""

from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent
OUTPUT_ROOT = Path(os.environ.get("BRIDGEFU_RENDER_ROOT", "/"))
DEPLOYMENT = re.compile(r"^[a-z][a-z0-9-]{2,23}$")
HOSTNAME = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$"
)
FLOW_ID = re.compile(r"^[A-Za-z0-9-]{1,128}$")
CONNECT_ARN = re.compile(
    r"^arn:aws[-a-z0-9]*:connect:[-a-z0-9]+:[0-9]{12}:instance/[A-Za-z0-9-]+$"
)


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value or len(value) > 2048 or any(char.isspace() for char in value):
        raise SystemExit(f"invalid {name}")
    return value


def render(name: str, output: Path, replacements: dict[str, str], mode: int) -> None:
    value = (ROOT / name).read_text()
    for key, replacement in replacements.items():
        value = value.replace(f"__{key}__", replacement)
    if re.search(r"__[A-Z0-9_]+__", value):
        raise SystemExit(f"unresolved placeholder in {name}")
    temporary = output.with_suffix(output.suffix + ".new")
    temporary.write_text(value)
    os.chmod(temporary, mode)
    temporary.replace(output)


def destination(value: str) -> Path:
    return OUTPUT_ROOT / value.lstrip("/")


def main() -> int:
    deployment = required("BRIDGEFU_DEPLOYMENT_ID")
    if not DEPLOYMENT.fullmatch(deployment):
        raise SystemExit("invalid BRIDGEFU_DEPLOYMENT_ID")
    region = required("AWS_REGION")
    sip_hostname = required("BRIDGEFU_SIP_HOSTNAME").rstrip(".").lower()
    control_hostname = required("BRIDGEFU_CONTROL_HOSTNAME").rstrip(".").lower()
    try:
        sip_address = ipaddress.ip_address(sip_hostname)
    except ValueError:
        sip_address = None
    if (
        not HOSTNAME.fullmatch(sip_hostname)
        and not isinstance(sip_address, ipaddress.IPv4Address)
    ) or not HOSTNAME.fullmatch(control_hostname):
        raise SystemExit("invalid Bridgefu hostname or public IPv4 address")
    public_ip = str(ipaddress.ip_address(required("BRIDGEFU_PUBLIC_IP")))
    private_ip = str(ipaddress.ip_address(required("BRIDGEFU_PRIVATE_IP")))
    if not ipaddress.ip_address(private_ip).is_private:
        raise SystemExit("BRIDGEFU_PRIVATE_IP must be private")
    instance_arn = required("CONNECT_INSTANCE_ARN")
    if not CONNECT_ARN.fullmatch(instance_arn):
        raise SystemExit("invalid CONNECT_INSTANCE_ARN")
    flow_id = required("CONNECT_ENTRY_FLOW_ID")
    if not FLOW_ID.fullmatch(flow_id):
        raise SystemExit("invalid CONNECT_ENTRY_FLOW_ID")
    security = required("BRIDGEFU_SIP_SECURITY")
    if security not in {"sips_srtp", "sip_rtp"}:
        raise SystemExit("invalid BRIDGEFU_SIP_SECURITY")
    try:
        maximum = int(required("BRIDGEFU_MAX_CONCURRENT_CALLS"))
    except ValueError as error:
        raise SystemExit("invalid BRIDGEFU_MAX_CONCURRENT_CALLS") from error
    if maximum < 1 or maximum > 1000:
        raise SystemExit("invalid BRIDGEFU_MAX_CONCURRENT_CALLS")

    cidrs = required("VAPI_SIGNALING_CIDRS").split(",")
    if not 1 <= len(cidrs) <= 32:
        raise SystemExit("invalid VAPI_SIGNALING_CIDRS")
    normalized_cidrs = [str(ipaddress.ip_network(value, strict=True)) for value in cidrs]
    cidr_yaml = "\n".join(f"        - {value}" for value in normalized_cidrs)
    if security == "sips_srtp":
        edge = """  sip_tls:
    bind: 0.0.0.0:5061
    advertised_addr: __PUBLIC_IP__:5061
    certificate_chain: /etc/bridgefu/tls/fullchain.pem
    private_key: /etc/bridgefu/tls/private-key.pem""".replace(
            "__PUBLIC_IP__", public_ip
        )
    else:
        edge = """  sip_rtp:
    bind: 0.0.0.0:5060
    advertised_addr: __PUBLIC_IP__:5060""".replace("__PUBLIC_IP__", public_ip)

    config_replacements = {
        "AWS_REGION": region,
        "SIP_HOSTNAME": sip_hostname,
        "PUBLIC_IP": public_ip,
        "SIP_EDGE_CONFIG": edge,
        "VAPI_SIGNALING_CIDRS": cidr_yaml,
        "CONNECT_INSTANCE_ARN": instance_arn,
        "CONNECT_ENTRY_FLOW_ID": flow_id,
        "SIP_SECURITY": security,
        "DEPLOYMENT_ID": deployment,
        "MAX_CONCURRENT_CALLS": str(maximum),
    }
    render(
        "bridgefu.yaml.tmpl",
        destination("/etc/bridgefu/bridgefu.yaml"),
        config_replacements,
        0o640,
    )
    render(
        "haproxy.cfg.tmpl",
        destination("/etc/haproxy/haproxy.cfg"),
        {
            "CONTROL_BIND": (
                f"{private_ip}:443 ssl crt /etc/haproxy/bridgefu.pem alpn h2,http/1.1"
                if security == "sips_srtp"
                else f"{private_ip}:443"
            )
        },
        0o640,
    )
    render(
        "prometheus.yaml",
        destination("/opt/aws/amazon-cloudwatch-agent/var/bridgefu-prometheus.yaml"),
        {"DEPLOYMENT_ID": deployment},
        0o640,
    )
    render(
        "cloudwatch-agent.json.tmpl",
        destination("/opt/aws/amazon-cloudwatch-agent/etc/bridgefu.json"),
        {
            "AWS_REGION": region,
            "DEPLOYMENT_ID": deployment,
            "RUNTIME_LOG_GROUP": required("BRIDGEFU_RUNTIME_LOG_GROUP"),
            "PROMETHEUS_LOG_GROUP": required("BRIDGEFU_PROMETHEUS_LOG_GROUP"),
        },
        0o640,
    )
    json.loads(destination("/opt/aws/amazon-cloudwatch-agent/etc/bridgefu.json").read_text())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
