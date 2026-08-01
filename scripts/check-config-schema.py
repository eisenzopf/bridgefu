#!/usr/bin/env python3
"""Validate Bridgefu's versioned configuration contract without secrets."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "config" / "schema.json"
EXAMPLE_PATH = ROOT / "config" / "bridgefu.example.yaml"
COMPATIBILITY_FIXTURES = sorted((ROOT / "config" / "fixtures").glob("config-v*.yaml"))
STANDARDCHARTER_CONFIG = (
    ROOT / "config" / "fixtures" / "standardcharter-managed-routes.yaml"
)
STANDARDCHARTER_ENV = (
    ROOT / "config" / "fixtures" / "standardcharter-managed-routes.env"
)
EXPECTED_STANDARDCHARTER_ROUTES = (
    "amazon-connect",
    "generic-sip",
    "telnyx",
    "generic-wss",
)


def assert_rejected(
    validator: Draft202012Validator,
    instance: dict[str, object],
    expected_path: tuple[object, ...],
) -> None:
    errors = list(validator.iter_errors(instance))
    if not errors:
        raise AssertionError(f"schema accepted invalid field at {expected_path!r}")
    if not any(tuple(error.absolute_path) == expected_path for error in errors):
        rendered = "; ".join(
            f"{tuple(error.absolute_path)!r}: {error.message}" for error in errors
        )
        raise AssertionError(
            f"schema did not reject expected path {expected_path!r}: {rendered}"
        )


def parse_env_fixture(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise AssertionError(f"{path}:{line_number} is not KEY=VALUE")
        key, value = line.split("=", 1)
        if not key or key in values:
            raise AssertionError(f"{path}:{line_number} has an invalid/duplicate key")
        values[key] = value
    return values


def nested(instance: dict[str, object], *path: object) -> object:
    value: object = instance
    for component in path:
        if isinstance(component, int):
            if not isinstance(value, list):
                raise AssertionError(f"expected list at {path!r}")
            value = value[component]
        else:
            if not isinstance(value, dict) or component not in value:
                raise AssertionError(f"missing paired-fixture field {path!r}")
            value = value[component]
    return value


def assert_env_secret(instance: dict[str, object], *path: object) -> None:
    value = nested(instance, *path)
    if not isinstance(value, str) or not value.startswith("env:"):
        raise AssertionError(f"paired fixture secret {path!r} must use env:VARIABLE")


def validate_standardcharter_pair(
    validator: Draft202012Validator,
) -> None:
    bridgefu = yaml.safe_load(STANDARDCHARTER_CONFIG.read_text(encoding="utf-8"))
    validator.validate(bridgefu)
    standardcharter = parse_env_fixture(STANDARDCHARTER_ENV)

    routes = nested(bridgefu, "api", "routes")
    if not isinstance(routes, dict):
        raise AssertionError("paired Bridgefu fixture has no named-route catalog")
    if tuple(routes) != EXPECTED_STANDARDCHARTER_ROUTES:
        raise AssertionError(
            "paired Bridgefu fixture route order/IDs do not match the product contract"
        )
    configured_routes = tuple(
        route.strip()
        for route in standardcharter.get("BRIDGEFU_ROUTE_IDS", "").split(",")
        if route.strip()
    )
    if configured_routes != EXPECTED_STANDARDCHARTER_ROUTES:
        raise AssertionError("paired StandardCharter route IDs do not match Bridgefu")
    if standardcharter.get("BRIDGEFU_DEFAULT_ROUTE_ID") != "amazon-connect":
        raise AssertionError("paired default route must remain amazon-connect")
    if standardcharter.get("BRIDGEFU_LEGACY_AMAZON_ROLLBACK_ENABLED") != "true":
        raise AssertionError("paired migration fixture must explicitly scope Amazon rollback")
    if not standardcharter.get("CONNECT_TRANSFER_SIP_URI", "").startswith("sips:"):
        raise AssertionError("paired Amazon rollback fixture must use SIPS")
    bearer_ref = standardcharter.get("BRIDGEFU_API_BEARER_TOKEN_REF", "")
    if not bearer_ref.startswith("env:"):
        raise AssertionError("StandardCharter control bearer must remain a secret reference")

    expected_destination_types = {
        "amazon-connect": ("amazon_connect", "amazon_connect"),
        "generic-sip": ("sip", "sip"),
        "telnyx": ("telnyx", "provider"),
        "generic-wss": ("webrtc", "webrtc"),
    }
    for route_id, (profile_type, endpoint_type) in expected_destination_types.items():
        route = routes[route_id]
        if set(route.get("ingress", [])) != {"sip", "webrtc"}:
            raise AssertionError(f"{route_id} must support both approved ingress modes")
        if not route.get("vapi_ingress_profile") or not route.get(
            "webrtc_ingress_profile"
        ):
            raise AssertionError(f"{route_id} is missing an ingress profile")
        if route.get("destination_profile", {}).get("type") != profile_type:
            raise AssertionError(f"{route_id} has the wrong destination profile")
        if route.get("destination", {}).get("endpoint", {}).get("type") != endpoint_type:
            raise AssertionError(f"{route_id} has the wrong destination endpoint")

    for path in (
        ("api", "bearer_token"),
        ("api", "control_hmac_key"),
        ("api", "route_attachments", "webrtc", "ice_servers", 0, "credential"),
        ("vapi_ingress_profiles", "vapi-production", "tls", "private_key"),
        ("sip_profiles", "call-center-sip", "auth", "password"),
        ("webrtc_profiles", "browser-public", "ice_servers", 0, "credential"),
        ("webrtc_profiles", "call-center-wss", "bearer_token"),
        ("generic_bridge", "sip", "secure_listener", "private_key"),
        ("generic_bridge", "webrtc", "ice_servers", 0, "credential"),
        ("providers", "telnyx", "api_key"),
        ("providers", "telnyx", "webhook_public_key"),
        ("providers", "telnyx", "media_sip_password"),
    ):
        assert_env_secret(bridgefu, *path)

    # A coordinated local checkout additionally catches accidental drift in
    # StandardCharter's operator-facing example. Isolated Bridgefu CI still
    # validates the complete canonical pair above.
    sibling = ROOT.parent / "standardcharter" / "config" / "bridgefu-managed-ingress.env.example"
    if sibling.is_file():
        deployed = parse_env_fixture(sibling)
        for key in (
            "BRIDGEFU_ROUTE_IDS",
            "BRIDGEFU_DEFAULT_ROUTE_ID",
            "BRIDGEFU_LEGACY_AMAZON_ROLLBACK_ENABLED",
        ):
            if deployed.get(key) != standardcharter.get(key):
                raise AssertionError(
                    f"StandardCharter example drifted from paired fixture key {key}"
                )


def main() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    example = yaml.safe_load(EXAMPLE_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate(example)
    if not COMPATIBILITY_FIXTURES:
        raise AssertionError("no versioned configuration compatibility fixtures found")
    for fixture_path in COMPATIBILITY_FIXTURES:
        fixture = yaml.safe_load(fixture_path.read_text(encoding="utf-8"))
        validator.validate(fixture)
    validate_standardcharter_pair(validator)

    unknown_top = copy.deepcopy(example)
    unknown_top["unknown_top_level"] = True
    assert_rejected(validator, unknown_top, ())

    unknown_runtime = copy.deepcopy(example)
    unknown_runtime["runtime"]["setup_timeout_secondz"] = 30
    assert_rejected(validator, unknown_runtime, ("runtime",))

    unknown_tenant = copy.deepcopy(example)
    unknown_tenant["tenants"]["banking"]["contact_flow"] = "typo"
    assert_rejected(validator, unknown_tenant, ("tenants", "banking"))

    unknown_context = copy.deepcopy(example)
    unknown_context["context"]["allow_all_headers"] = True
    assert_rejected(validator, unknown_context, ("context",))

    secret_otlp_headers = copy.deepcopy(example)
    secret_otlp_headers["observability"]["otlp"]["headers"] = {
        "authorization": "secret"
    }
    assert_rejected(
        validator,
        secret_otlp_headers,
        ("observability", "otlp"),
    )

    enabled_otlp_without_endpoint = copy.deepcopy(example)
    enabled_otlp_without_endpoint["observability"]["otlp"]["enabled"] = True
    assert_rejected(
        validator,
        enabled_otlp_without_endpoint,
        ("observability", "otlp"),
    )

    unsafe_otlp_batching = copy.deepcopy(example)
    unsafe_otlp_batching["observability"]["otlp"]["max_queue_size"] = 65537
    assert_rejected(
        validator,
        unsafe_otlp_batching,
        ("observability", "otlp", "max_queue_size"),
    )

    excessive_broadcast_ttl = copy.deepcopy(example)
    excessive_broadcast_ttl["broadcast"]["token_ttl_secs"] = 901
    assert_rejected(
        validator,
        excessive_broadcast_ttl,
        ("broadcast", "token_ttl_secs"),
    )

    short_broadcast_secret = copy.deepcopy(example)
    short_broadcast_secret["broadcast"]["token_secret"] = "too-short"
    assert_rejected(
        validator,
        short_broadcast_secret,
        ("broadcast", "token_secret"),
    )

    telnyx = copy.deepcopy(example)
    telnyx["providers"] = {
        "telnyx": {
            "api_key": "env:TELNYX_API_KEY",
            "connection_id": "test-connection",
            "webhook_public_key": "env:TELNYX_WEBHOOK_PUBLIC_KEY",
            "from": "+14155550100",
            "media_sip_authority": "bridgefu.example:5060",
            "media_sip_username": "telnyx",
            "media_sip_password": "env:TELNYX_MEDIA_SIP_PASSWORD",
        }
    }
    validator.validate(telnyx)
    telnyx["providers"]["telnyx"]["api_kei"] = "typo"
    assert_rejected(validator, telnyx, ("providers", "telnyx"))

    print(
        "Bridgefu config schema, compatibility/deployment fixtures, paired "
        "StandardCharter routes, and strict negative fixtures are valid"
    )


if __name__ == "__main__":
    main()
