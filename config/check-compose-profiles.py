#!/usr/bin/env python3
"""Exercise rendered Compose environments through Bridgefu's own preflight."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "bridgefu.example.yaml"

# These values are deliberately non-secret and are used only to prove that
# every required env: reference resolves during local/CI configuration checks.
PLACEHOLDERS = {
    "BRIDGEFU_API_TOKEN": "compose-validation-only-api-token",
    "BRIDGEFU_CONTROL_HMAC_KEY": "compose-validation-only-control-key-32-bytes",
    "BRIDGEFU_BROADCAST_TOKEN_SECRET": "compose-validation-only-broadcast-token",
    "BRIDGEFU_MOQ_DIAGNOSTICS_TOKEN": "compose-validation-only-moq-diagnostics-token",
    "BRIDGEFU_PRIVATE_FORWARDING_SECRET": "compose-validation-private-forwarding-key",
    "BRIDGEFU_ADVERTISED_IP": "127.0.0.1",
    "BRIDGEFU_MEDIA_PUBLIC_IP": "127.0.0.1",
    "TELNYX_ACCOUNT_PROFILE": "telnyx-compose-validation",
    "TELNYX_API_KEY": "compose-validation-only-telnyx-key",
    "TELNYX_CONNECTION_ID": "compose-validation-connection",
    "TELNYX_WEBHOOK_PUBLIC_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "TELNYX_FROM": "+14155550100",
    "TELNYX_MEDIA_SIP_AUTHORITY": "bridgefu.invalid:5060",
    "TELNYX_MEDIA_SIP_USERNAME": "telnyx-media",
    "TELNYX_MEDIA_SIP_PASSWORD": "compose-validation-only-media-password",
    "TELNYX_MEDIA_SIP_REALM": "bridgefu",
    "TELNYX_MEDIA_SIP_TRANSPORT": "UDP",
}

SUCCESS_CASES = (
    ("reference-tenant", "reference-tenant"),
    ("generic", "generic"),
    ("telnyx", "telnyx"),
    ("uctp", "uctp"),
    ("moqt", "moqt"),
    ("cluster", "gateway"),
    ("cluster", "worker"),
    ("cluster", "moq-relay"),
)

EXPECTED_FAILURES = ()


def render_profile(profile: str, interpolation_env: dict[str, str]) -> dict[str, object]:
    result = subprocess.run(
        ["docker", "compose", "--profile", profile, "config", "--format", "json"],
        cwd=ROOT,
        env=interpolation_env,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def service_environment(rendered: dict[str, object], service: str) -> dict[str, str]:
    services = rendered.get("services", {})
    if service not in services:
        raise AssertionError(f"profile did not render expected service {service!r}")
    values = services[service].get("environment", {})
    if not isinstance(values, dict):
        raise AssertionError(f"service {service!r} environment is not a mapping")
    return {str(key): str(value) for key, value in values.items() if value is not None}


def validate(
    binary: Path,
    rendered: dict[str, object],
    service: str,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update(service_environment(rendered, service))
    environment["RUST_BACKTRACE"] = "0"
    return subprocess.run(
        [str(binary), "--config", str(CONFIG), "validate"],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def assert_profile_contracts(rendered: dict[str, dict[str, object]]) -> None:
    telnyx_environment = service_environment(rendered["telnyx"], "telnyx")
    telnyx = json.loads(telnyx_environment["BRIDGEFU__PROVIDERS__TELNYX"])
    expected_secret_refs = {
        "api_key": "env:TELNYX_API_KEY",
        "webhook_public_key": "env:TELNYX_WEBHOOK_PUBLIC_KEY",
        "media_sip_password": "env:TELNYX_MEDIA_SIP_PASSWORD",
    }
    for field, expected in expected_secret_refs.items():
        if telnyx.get(field) != expected:
            raise AssertionError(f"Telnyx {field} must remain the secret reference {expected}")
    for field in ("from", "media_sip_authority", "media_sip_username"):
        if not telnyx.get(field):
            raise AssertionError(f"Telnyx Compose configuration is missing {field}")

    worker_environment = service_environment(rendered["cluster"], "worker")
    if worker_environment.get("BRIDGEFU__API__ENABLED", "").lower() != "false":
        raise AssertionError("cluster worker must disable the public control API")
    expected_public_uctp_endpoint = "uctp+quic://gateway.invalid:4433"
    if (
        worker_environment.get("BRIDGEFU__BROADCAST__PUBLIC_ENDPOINT")
        != expected_public_uctp_endpoint
    ):
        raise AssertionError(
            "cluster worker must use the gateway's canonical public UCTP/QUIC endpoint"
        )

    gateway_environment = service_environment(rendered["cluster"], "gateway")
    if gateway_environment.get("BRIDGEFU__API__ENABLED", "").lower() != "true":
        raise AssertionError("cluster gateway must own the public control API")
    if gateway_environment.get("BRIDGEFU__API__HTTP_BIND") != "0.0.0.0:9080":
        raise AssertionError("cluster gateway must isolate the public API on port 9080")
    if gateway_environment.get("BRIDGEFU__API__TLS__CERTIFICATE_CHAIN") != "/run/tls/public-api.crt":
        raise AssertionError("cluster gateway must terminate API TLS with the mounted certificate")
    if gateway_environment.get("BRIDGEFU__API__TLS__PRIVATE_KEY") != "/run/tls/public-api.key":
        raise AssertionError("cluster gateway must terminate API TLS with the mounted private key")
    if gateway_environment.get("BRIDGEFU__GENERIC_BRIDGE__ENABLED", "").lower() != "true":
        raise AssertionError("cluster gateway must enable native SIP/WebRTC ingress")
    if (
        gateway_environment.get("BRIDGEFU__BROADCAST__PUBLIC_ENDPOINT")
        != expected_public_uctp_endpoint
    ):
        raise AssertionError(
            "cluster gateway must advertise the canonical public UCTP/QUIC endpoint"
        )
    expected_native_binds = {
        "BRIDGEFU__GENERIC_BRIDGE__SIP_BIND": "0.0.0.0:5070",
        "BRIDGEFU__GENERIC_BRIDGE__WEBRTC_WS_BIND": "0.0.0.0:8080",
        "BRIDGEFU__GENERIC_BRIDGE__WEBRTC_WHIP_BIND": "0.0.0.0:8081",
        "BRIDGEFU__GENERIC_BRIDGE__WEBRTC__UDP_BIND": "0.0.0.0:40000",
    }
    for field, expected in expected_native_binds.items():
        if gateway_environment.get(field) != expected:
            raise AssertionError(f"cluster gateway {field} must equal {expected}")
    if gateway_environment.get("BRIDGEFU__PERSISTENCE__WORKER_ID"):
        raise AssertionError("cluster gateway must not advertise a durable worker identity")
    gateway_forwarding = json.loads(
        gateway_environment["BRIDGEFU__PRIVATE_FORWARDING"]
    )
    worker_forwarding = json.loads(worker_environment["BRIDGEFU__PRIVATE_FORWARDING"])
    expected_secret = "env:BRIDGEFU_PRIVATE_FORWARDING_SECRET"
    minimum_direct_listeners = 1_000
    public_uctp = gateway_forwarding["gateway"].get("public_uctp", {})
    if public_uctp.get("max_concurrent_connections", 0) < minimum_direct_listeners:
        raise AssertionError(
            "cluster gateway must admit at least 1,000 direct public UCTP listeners"
        )
    for role, forwarding in (
        ("gateway", gateway_forwarding),
        ("worker", worker_forwarding),
    ):
        if forwarding.get("token_signing_secret") != expected_secret:
            raise AssertionError(
                f"cluster {role} private-forwarding token must remain {expected_secret}"
            )
        if not forwarding.get("enabled") or role not in forwarding:
            raise AssertionError(
                f"cluster {role} must enable its role-specific private forwarding"
            )
        limits = forwarding.get("limits", {})
        for field in ("max_active_routes", "max_routes_per_peer"):
            if limits.get(field, 0) < minimum_direct_listeners:
                raise AssertionError(
                    f"cluster {role} {field} must support at least 1,000 direct UCTP listeners"
                )
    target = gateway_forwarding["gateway"]["workers"][0]
    if target.get("worker_id") != worker_environment.get(
        "BRIDGEFU__PERSISTENCE__WORKER_ID"
    ):
        raise AssertionError(
            "cluster gateway target must match the durable worker identity"
        )


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: check-compose-profiles.py /path/to/bridgefu")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit(f"Bridgefu binary does not exist: {binary}")

    interpolation_env = os.environ.copy()
    # Never inherit provider credentials into this deterministic check.
    interpolation_env.update(PLACEHOLDERS)
    rendered = {
        profile: render_profile(profile, interpolation_env)
        for profile in {case[0] for case in SUCCESS_CASES + EXPECTED_FAILURES}
    }
    assert_profile_contracts(rendered)

    for profile, service in SUCCESS_CASES:
        result = validate(binary, rendered[profile], service)
        if result.returncode != 0:
            raise AssertionError(
                f"{profile}/{service} failed Bridgefu validation:\n{result.stderr}"
            )
        print(f"validated executable Compose service: {profile}/{service}")

    for profile, service, expected in EXPECTED_FAILURES:
        result = validate(binary, rendered[profile], service)
        output = result.stdout + result.stderr
        if result.returncode == 0 or expected not in output:
            raise AssertionError(
                f"{profile}/{service} did not fail with its expected preflight:\n{output}"
            )
        print(f"validated fail-closed Compose service: {profile}/{service}")


if __name__ == "__main__":
    main()
