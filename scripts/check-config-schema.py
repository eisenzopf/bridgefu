#!/usr/bin/env python3
"""Validate Bridgefu's versioned configuration contract without secrets."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "config" / "schema.json"
EXAMPLE_PATH = ROOT / "config" / "bridgefu.example.yaml"
RECIPE_SCHEMA_PATH = ROOT / "recipes" / "schema" / "recipe-v1.schema.json"
RECIPE_VALUES_SCHEMA_PATH = ROOT / "recipes" / "schema" / "values-v1.schema.json"
RECIPE_ROOT = ROOT / "recipes" / "vapi-amazon-connect-screen-pop"
RECIPE_PACKAGES = sorted(
    path for path in (ROOT / "recipes").iterdir() if (path / "recipe.yaml").is_file()
)
RECIPE_CONFIG_EXAMPLE = ROOT / "config" / "recipe-vapi-amazon-connect.example.yaml"
COMPATIBILITY_FIXTURES = sorted((ROOT / "config" / "fixtures").glob("config-v*.yaml"))
REFERENCE_TENANT_CONFIG = (
    ROOT / "config" / "fixtures" / "reference-tenant-managed-routes.yaml"
)
REFERENCE_TENANT_ENV = (
    ROOT / "config" / "fixtures" / "reference-tenant-managed-routes.env"
)
EXPECTED_REFERENCE_TENANT_ROUTES = (
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


def validate_reference_tenant_pair(
    validator: Draft202012Validator,
) -> None:
    bridgefu = yaml.safe_load(REFERENCE_TENANT_CONFIG.read_text(encoding="utf-8"))
    validator.validate(bridgefu)
    reference_tenant = parse_env_fixture(REFERENCE_TENANT_ENV)

    routes = nested(bridgefu, "api", "routes")
    if not isinstance(routes, dict):
        raise AssertionError("paired Bridgefu fixture has no named-route catalog")
    if tuple(routes) != EXPECTED_REFERENCE_TENANT_ROUTES:
        raise AssertionError(
            "paired Bridgefu fixture route order/IDs do not match the product contract"
        )
    configured_routes = tuple(
        route.strip()
        for route in reference_tenant.get("BRIDGEFU_ROUTE_IDS", "").split(",")
        if route.strip()
    )
    if configured_routes != EXPECTED_REFERENCE_TENANT_ROUTES:
        raise AssertionError("paired ReferenceTenant route IDs do not match Bridgefu")
    if reference_tenant.get("BRIDGEFU_DEFAULT_ROUTE_ID") != "amazon-connect":
        raise AssertionError("paired default route must remain amazon-connect")
    if reference_tenant.get("BRIDGEFU_LEGACY_AMAZON_ROLLBACK_ENABLED") != "true":
        raise AssertionError("paired migration fixture must explicitly scope Amazon rollback")
    if not reference_tenant.get("CONNECT_TRANSFER_SIP_URI", "").startswith("sips:"):
        raise AssertionError("paired Amazon rollback fixture must use SIPS")
    bearer_ref = reference_tenant.get("BRIDGEFU_API_BEARER_TOKEN_REF", "")
    if not bearer_ref.startswith("env:"):
        raise AssertionError("ReferenceTenant control bearer must remain a secret reference")

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

    # A caller may additionally check a coordinated operator-facing fixture.
    # Isolated Bridgefu CI validates the complete canonical pair above without
    # depending on a specifically named sibling checkout.
    paired_fixture = os.environ.get("BRIDGEFU_PAIRED_OPERATOR_FIXTURE")
    if paired_fixture:
        deployed_path = Path(paired_fixture).expanduser()
        if not deployed_path.is_file():
            raise AssertionError(
                "BRIDGEFU_PAIRED_OPERATOR_FIXTURE must name an existing file"
            )
        deployed = parse_env_fixture(deployed_path)
        for key in (
            "BRIDGEFU_ROUTE_IDS",
            "BRIDGEFU_DEFAULT_ROUTE_ID",
            "BRIDGEFU_LEGACY_AMAZON_ROLLBACK_ENABLED",
        ):
            if deployed.get(key) != reference_tenant.get(key):
                raise AssertionError(
                    f"ReferenceTenant example drifted from paired fixture key {key}"
                )


def collect_recipe_input_references(value: object) -> list[str]:
    references: list[str] = []
    if isinstance(value, dict):
        if "$input" in value:
            if set(value) != {"$input"} or not isinstance(value["$input"], str):
                raise AssertionError("$input must replace one complete YAML node")
            references.append(value["$input"])
        else:
            for child in value.values():
                references.extend(collect_recipe_input_references(child))
    elif isinstance(value, list):
        for child in value:
            references.extend(collect_recipe_input_references(child))
    return references


def validate_canonical_recipe() -> None:
    recipe_schema = json.loads(RECIPE_SCHEMA_PATH.read_text(encoding="utf-8"))
    values_schema = json.loads(
        RECIPE_VALUES_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(recipe_schema)
    Draft202012Validator.check_schema(values_schema)
    recipe_validator = Draft202012Validator(recipe_schema)
    values_validator = Draft202012Validator(values_schema)

    for package_root in RECIPE_PACKAGES:
        package_manifest = yaml.safe_load(
            (package_root / "recipe.yaml").read_text(encoding="utf-8")
        )
        package_values = yaml.safe_load(
            (package_root / "values.example.yaml").read_text(encoding="utf-8")
        )
        recipe_validator.validate(package_manifest)
        values_validator.validate(package_values)
        declared_inputs = package_manifest.get("inputs", {})
        supplied_inputs = set(package_values)
        unknown_inputs = supplied_inputs - set(declared_inputs)
        missing_required = {
            name
            for name, definition in declared_inputs.items()
            if definition.get("required", False)
            and "default" not in definition
            and name not in supplied_inputs
        }
        references = collect_recipe_input_references(package_manifest["spec"])
        unknown_references = set(references) - set(declared_inputs)
        unused_inputs = set(declared_inputs) - set(references)
        if unknown_inputs or missing_required or unknown_references or unused_inputs:
            raise AssertionError(
                f"recipe package {package_root.name} input contract drifted: "
                f"unknown_values={sorted(unknown_inputs)!r} "
                f"missing_required={sorted(missing_required)!r} "
                f"unknown_references={sorted(unknown_references)!r} "
                f"unused={sorted(unused_inputs)!r}"
            )
        for asset_path in list(package_manifest.get("assets", {}).values()) + [
            asset_path
            for profiles in package_manifest.get("deployments", {}).values()
            for asset_path in profiles.values()
        ]:
            resolved = (package_root / asset_path).resolve()
            if package_root.resolve() not in resolved.parents or not resolved.is_file():
                raise AssertionError(
                    f"recipe asset is missing or escapes {package_root.name}: {asset_path}"
                )

    manifest_path = RECIPE_ROOT / "recipe.yaml"
    values_path = RECIPE_ROOT / "values.example.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    values = yaml.safe_load(values_path.read_text(encoding="utf-8"))
    recipe_validator.validate(manifest)
    values_validator.validate(values)

    declared = set(manifest.get("inputs", {}))
    supplied = set(values)
    if declared != supplied:
        raise AssertionError(
            f"canonical recipe example values differ from declared inputs: "
            f"declared={sorted(declared)!r} supplied={sorted(supplied)!r}"
        )
    referenced = collect_recipe_input_references(manifest["spec"])
    unknown = set(referenced) - declared
    unused = declared - set(referenced)
    if unknown or unused:
        raise AssertionError(
            f"canonical recipe input references drifted: "
            f"unknown={sorted(unknown)!r} unused={sorted(unused)!r}"
        )

    for path in list(manifest.get("assets", {}).values()) + [
        path
        for profiles in manifest.get("deployments", {}).values()
        for path in profiles.values()
    ]:
        resolved = (RECIPE_ROOT / path).resolve()
        if RECIPE_ROOT.resolve() not in resolved.parents or not resolved.is_file():
            raise AssertionError(f"canonical recipe asset is missing or escapes root: {path}")

    handoff_contract = json.loads(
        (RECIPE_ROOT / "handoff-contract.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(handoff_contract)

    unknown_top = copy.deepcopy(manifest)
    unknown_top["executable_plugin"] = "forbidden"
    assert_rejected(recipe_validator, unknown_top, ())

    unknown_metadata = copy.deepcopy(manifest)
    unknown_metadata["metadata"]["download_url"] = "https://example.invalid/recipe"
    assert_rejected(recipe_validator, unknown_metadata, ("metadata",))

    unknown_endpoint = copy.deepcopy(manifest)
    unknown_endpoint["spec"]["bridges"]["transfer"]["source"][
        "forward_all_headers"
    ] = True
    if not list(recipe_validator.iter_errors(unknown_endpoint)):
        raise AssertionError("recipe schema accepted an unknown endpoint policy")


def main() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    example = yaml.safe_load(EXAMPLE_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate(example)
    validator.validate(yaml.safe_load(RECIPE_CONFIG_EXAMPLE.read_text(encoding="utf-8")))
    if not COMPATIBILITY_FIXTURES:
        raise AssertionError("no versioned configuration compatibility fixtures found")
    for fixture_path in COMPATIBILITY_FIXTURES:
        fixture = yaml.safe_load(fixture_path.read_text(encoding="utf-8"))
        validator.validate(fixture)
    validate_reference_tenant_pair(validator)
    validate_canonical_recipe()

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
        "Bridgefu config and recipe schemas, compatibility/deployment fixtures, "
        "paired ReferenceTenant routes, canonical recipe assets, and strict "
        "negative fixtures are valid"
    )


if __name__ == "__main__":
    main()
