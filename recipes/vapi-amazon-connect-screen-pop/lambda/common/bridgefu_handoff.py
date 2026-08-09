"""Security boundary for the Bridgefu Vapi/Amazon Connect handoff recipe.

This module deliberately contains no framework and logs no request bodies. The
three Lambda entrypoints inject AWS clients and fixed deployment settings into
these pure contract functions.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from screen_pop import (
    DEFAULT_FIELDS,
    ScreenPopConfigError,
    ScreenPopField,
    connect_rows,
    schema_hash,
    validate_values,
)


SCHEMA_VERSION = 1
CORRELATION_VERSION = "bf1"
CORRELATION_HEADER = "X-Correlation-Id"
PREPARE_TOOL_NAME = "prepare_handoff"
TEMPLATE_PREPARE_TOOL_NAME = "prepare_bridgefu_amazon_connect_transfer"
DIRECT_TRANSFER_TOOL_NAME = "bridgefu_transfer_to_amazon_connect"
DISPLAY_FIELDS = (
    "customer_name",
    "issue_summary",
    "intent",
    "verification_status",
)
RETURN_FIELDS = DISPLAY_FIELDS + ("vapi_call_reference",)
FIELD_LIMITS = {
    "customer_name": 256,
    "issue_summary": 1024,
    "intent": 128,
    "verification_status": 128,
}
MAX_BODY_BYTES = 16_384
MAX_CONTEXT_BYTES = 8_192
IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
CORRELATION = re.compile(r"^bf1_[A-Za-z0-9_-]{43}$")


class HandoffError(Exception):
    """Safe, low-cardinality application error."""

    def __init__(self, code: str, status_code: int = 400) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


class HandoffStore(Protocol):
    def put_prepared(self, record: Mapping[str, Any]) -> str: ...

    def get(self, correlation_id: str) -> Mapping[str, Any] | None: ...

    def mark_reserved(
        self,
        correlation_id: str,
        updated_at: int,
        bridgefu_call_id: str,
        attachment_expires_at: int,
    ) -> None: ...


@dataclass(frozen=True)
class VapiIdentity:
    org_id: str
    call_id: str


@dataclass(frozen=True)
class PreparedHandoff:
    correlation_id: str
    tool_call_id: str
    replayed: bool


@dataclass(frozen=True)
class SipReservation:
    uri: str
    call_id: str
    expires_at: int


def _bounded_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise HandoffError(f"invalid_{field}")
    return value


def _bounded_display(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise HandoffError(f"invalid_{field}")
    if len(value.encode("utf-8")) > FIELD_LIMITS[field]:
        raise HandoffError(f"invalid_{field}")
    if any(ord(character) < 0x20 and character not in ("\t",) for character in value):
        raise HandoffError(f"invalid_{field}")
    return value


def _message(event: Mapping[str, Any], expected_type: str) -> Mapping[str, Any]:
    message = event.get("message")
    if not isinstance(message, Mapping) or message.get("type") != expected_type:
        raise HandoffError("invalid_vapi_event")
    return message


def _vapi_identity(message: Mapping[str, Any]) -> VapiIdentity:
    call = message.get("call")
    if not isinstance(call, Mapping):
        raise HandoffError("invalid_vapi_call")
    return VapiIdentity(
        org_id=_bounded_identifier(call.get("orgId"), "vapi_org_id"),
        call_id=_bounded_identifier(call.get("id"), "vapi_call_id"),
    )


def verify_vapi_binding(event: Mapping[str, Any], binding: Mapping[str, Any]) -> None:
    """Bind authenticated requests to the exact setup-created assistant."""
    if binding == {"status": "unbound"}:
        return
    if (
        not isinstance(binding, Mapping)
        or set(binding)
        != {"status", "organization_id", "assistant_id"}
        or binding.get("status") != "bound"
    ):
        raise HandoffError("vapi_identity_binding_invalid", 500)
    expected_org = _bounded_identifier(
        binding.get("organization_id"), "vapi_org_id"
    )
    expected_assistant = _bounded_identifier(
        binding.get("assistant_id"), "vapi_assistant_id"
    )
    message = event.get("message")
    call = message.get("call") if isinstance(message, Mapping) else None
    assistant = message.get("assistant") if isinstance(message, Mapping) else None
    actual_org = call.get("orgId") if isinstance(call, Mapping) else None
    actual_assistant = call.get("assistantId") if isinstance(call, Mapping) else None
    if actual_assistant is None and isinstance(assistant, Mapping):
        actual_assistant = assistant.get("id")
    if actual_org != expected_org or actual_assistant != expected_assistant:
        raise HandoffError("vapi_identity_mismatch", 403)


def derive_correlation_id(
    correlation_key: bytes,
    deployment_id: str,
    identity: VapiIdentity,
) -> str:
    if len(correlation_key) < 32:
        raise HandoffError("invalid_correlation_key", 500)
    deployment_id = _bounded_identifier(deployment_id, "deployment_id")
    material = (
        f"bridgefu|{deployment_id}|{identity.org_id}|{identity.call_id}"
    ).encode("utf-8")
    digest = hmac.new(correlation_key, material, hashlib.sha256).digest()
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    correlation_id = f"{CORRELATION_VERSION}_{encoded}"
    if not CORRELATION.fullmatch(correlation_id):
        raise HandoffError("correlation_derivation_failed", 500)
    return correlation_id


def call_fingerprint(deployment_id: str, identity: VapiIdentity) -> str:
    material = (
        f"bridgefu-call|{deployment_id}|{identity.org_id}|{identity.call_id}"
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _content_hash(fields: Mapping[str, str]) -> str:
    encoded = json.dumps(
        dict(fields), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _tool_arguments(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_CONTEXT_BYTES:
        raise HandoffError("invalid_tool_arguments")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise HandoffError("invalid_tool_arguments")
            result[key] = item
        return result

    try:
        decoded = json.loads(value, object_pairs_hook=unique_object)
    except json.JSONDecodeError:
        raise HandoffError("invalid_tool_arguments") from None
    if not isinstance(decoded, Mapping):
        raise HandoffError("invalid_tool_arguments")
    return decoded


def _tool_call(
    message: Mapping[str, Any],
    configured_fields: tuple[ScreenPopField, ...] | None = None,
) -> tuple[str, Mapping[str, Any]]:
    calls = message.get("toolCallList")
    if not isinstance(calls, list) or len(calls) != 1 or not isinstance(calls[0], Mapping):
        raise HandoffError("invalid_tool_call")
    call = calls[0]
    function = call.get("function")
    if function is None:
        name = call.get("name")
        arguments = call.get("arguments")
        parameters = call.get("parameters")
    elif isinstance(function, Mapping):
        if any(key in call for key in ("name", "arguments", "parameters")):
            raise HandoffError("conflicting_tool_arguments")
        if call.get("type") not in (None, "function"):
            raise HandoffError("invalid_tool_call")
        name = function.get("name")
        arguments = function.get("arguments")
        parameters = function.get("parameters")
    else:
        raise HandoffError("invalid_tool_call")
    if name not in (
        PREPARE_TOOL_NAME,
        TEMPLATE_PREPARE_TOOL_NAME,
        DIRECT_TRANSFER_TOOL_NAME,
    ):
        raise HandoffError("invalid_tool_name")
    tool_call_id = _bounded_identifier(call.get("id"), "tool_call_id")
    if arguments is not None and parameters is not None and arguments != parameters:
        raise HandoffError("conflicting_tool_arguments")
    values = _tool_arguments(arguments if arguments is not None else parameters)
    if configured_fields is None:
        if set(values) != set(DISPLAY_FIELDS):
            raise HandoffError("invalid_tool_arguments")
        return tool_call_id, values
    try:
        return tool_call_id, validate_values(values, configured_fields)
    except ScreenPopConfigError as error:
        raise HandoffError(str(error)) from None


def tool_name(event: Mapping[str, Any]) -> str:
    """Return the single validated tool name without exposing its arguments."""
    message = _message(event, "tool-calls")
    calls = message.get("toolCallList")
    if not isinstance(calls, list) or len(calls) != 1 or not isinstance(calls[0], Mapping):
        raise HandoffError("invalid_tool_call")
    call = calls[0]
    function = call.get("function")
    name = function.get("name") if isinstance(function, Mapping) else call.get("name")
    if name not in (
        PREPARE_TOOL_NAME,
        TEMPLATE_PREPARE_TOOL_NAME,
        DIRECT_TRANSFER_TOOL_NAME,
    ):
        raise HandoffError("invalid_tool_name")
    return name


def prepare_handoff(
    event: Mapping[str, Any],
    store: HandoffStore,
    correlation_key: bytes,
    deployment_id: str,
    ttl_seconds: int,
    now: int | None = None,
    configured_fields: tuple[ScreenPopField, ...] | None = None,
) -> PreparedHandoff:
    message = _message(event, "tool-calls")
    identity = _vapi_identity(message)
    tool_call_id, arguments = _tool_call(message, configured_fields)
    fields = (
        {
            field: _bounded_display(arguments.get(field), field)
            for field in DISPLAY_FIELDS
        }
        if configured_fields is None
        else dict(arguments)
    )
    fields["vapi_call_reference"] = identity.call_id
    if len(
        json.dumps(fields, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ) > MAX_CONTEXT_BYTES:
        raise HandoffError("context_too_large")
    if not isinstance(ttl_seconds, int) or not 300 <= ttl_seconds <= 604_800:
        raise HandoffError("invalid_context_ttl", 500)
    now = int(time.time()) if now is None else now
    correlation_id = derive_correlation_id(correlation_key, deployment_id, identity)
    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION if configured_fields is None else 2,
        "correlation_id": correlation_id,
        **fields,
        **(
            {
                "screen_pop_values": {key: value for key, value in fields.items() if key != "vapi_call_reference"},
                "screen_pop_schema_hash": schema_hash(configured_fields),
            }
            if configured_fields is not None
            else {}
        ),
        "vapi_call_fingerprint": call_fingerprint(deployment_id, identity),
        "content_hash": _content_hash(fields),
        "created_at": now,
        "updated_at": now,
        "expires_at": now + ttl_seconds,
        "handoff_status": "PREPARED",
    }
    disposition = store.put_prepared(record)
    if disposition not in ("created", "replayed"):
        raise HandoffError("handoff_store_invalid", 500)
    return PreparedHandoff(
        correlation_id=correlation_id,
        tool_call_id=tool_call_id,
        replayed=disposition == "replayed",
    )


def prepare_vapi_response(prepared: PreparedHandoff) -> dict[str, Any]:
    return {
        "results": [
            {
                "toolCallId": prepared.tool_call_id,
                "result": "prepared",
            }
        ]
    }


def vapi_control_url(event: Mapping[str, Any]) -> str:
    """Return a bounded Vapi live-control URL or fail closed before transfer."""
    message = _message(event, "tool-calls")
    call = message.get("call")
    monitor = call.get("monitor") if isinstance(call, Mapping) else None
    value = monitor.get("controlUrl") if isinstance(monitor, Mapping) else None
    if not isinstance(value, str) or len(value) > 2_048:
        raise HandoffError("vapi_control_url_invalid")
    parsed = urllib.parse.urlsplit(value)
    hostname = parsed.hostname or ""
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not (hostname == "api.vapi.ai" or hostname.endswith(".vapi.ai"))
        or not parsed.path.startswith("/")
        or ".." in parsed.path
    ):
        raise HandoffError("vapi_control_url_invalid")
    return value


def direct_transfer_response(prepared: PreparedHandoff) -> dict[str, Any]:
    """Acknowledge the tool without returning routing or correlation material."""
    return {
        "results": [
            {
                "toolCallId": prepared.tool_call_id,
                "result": "transfer_started",
            }
        ]
    }


def transfer_destination(
    event: Mapping[str, Any],
    store: HandoffStore,
    correlation_key: bytes,
    deployment_id: str,
    reserve: Callable[[str, str], SipReservation],
    expected_scheme: str,
    now: int | None = None,
) -> dict[str, Any]:
    message = _message(event, "transfer-destination-request")
    identity = _vapi_identity(message)
    correlation_id = derive_correlation_id(correlation_key, deployment_id, identity)
    record = store.get(correlation_id)
    now = int(time.time()) if now is None else now
    if record is None:
        raise HandoffError("handoff_not_prepared", 409)
    if record.get("vapi_call_fingerprint") != call_fingerprint(deployment_id, identity):
        raise HandoffError("handoff_identity_conflict", 409)
    if not isinstance(record.get("expires_at"), int) or record["expires_at"] <= now:
        raise HandoffError("handoff_expired", 409)
    if record.get("handoff_status") not in ("PREPARED", "RESERVED"):
        raise HandoffError("handoff_not_prepared", 409)
    idempotency_key = "vapi-transfer-" + hashlib.sha256(
        correlation_id.encode("ascii")
    ).hexdigest()[:48]
    reservation = reserve(correlation_id, idempotency_key)
    if expected_scheme not in ("sips", "sip") or not reservation.uri.startswith(
        f"{expected_scheme}:"
    ):
        raise HandoffError("bridgefu_destination_invalid", 502)
    _bounded_identifier(reservation.call_id, "bridgefu_call_id")
    if reservation.expires_at <= now:
        raise HandoffError("bridgefu_destination_expired", 502)
    store.mark_reserved(
        correlation_id,
        now,
        reservation.call_id,
        reservation.expires_at,
    )
    return {
        "destination": {
            "type": "sip",
            "sipUri": reservation.uri,
            "sipHeaders": {CORRELATION_HEADER: correlation_id},
            "message": "Okay, connecting you to a support specialist now. Please stay on the line.",
        }
    }


def connect_lookup(
    event: Mapping[str, Any],
    store: HandoffStore,
    now: int | None = None,
    configured_fields: tuple[ScreenPopField, ...] | None = None,
    routing_field_key: str | None = None,
) -> dict[str, str]:
    if configured_fields is not None:
        unavailable = {
            "context_available": "false",
            "vapi_call_reference": "",
            "routing_value": "",
            **connect_rows(configured_fields, None),
        }
    else:
        unavailable = {
            "context_available": "false",
            "routing_value": "",
            **{field: "" for field in RETURN_FIELDS},
        }
    correlation_id = connect_correlation_id(event)
    if correlation_id is None:
        return unavailable
    record = store.get(correlation_id)
    now = int(time.time()) if now is None else now
    if (
        record is None
        or not isinstance(record.get("expires_at"), int)
        or record["expires_at"] <= now
        or record.get("handoff_status") not in ("PREPARED", "RESERVED", "CONSUMED")
    ):
        return unavailable
    if configured_fields is not None:
        values = record.get("screen_pop_values")
        schema_v2 = (
            record.get("schema_version") == 2
            and record.get("screen_pop_schema_hash") == schema_hash(configured_fields)
            and isinstance(values, Mapping)
        )
        if (
            not schema_v2
        ):
            # Schema-v1 compatibility: read the four historical flat values
            # only when the configured keys are that exact released set.
            if tuple(field.key for field in configured_fields) != tuple(DISPLAY_FIELDS):
                return unavailable
            values = {field: record.get(field, "") for field in DISPLAY_FIELDS}
        try:
            validated = validate_values(values, configured_fields)
        except ScreenPopConfigError:
            return unavailable
        reference = record.get("vapi_call_reference", "")
        if not isinstance(reference, str) or len(reference.encode("utf-8")) > 128:
            return unavailable
        routing_value = ""
        if routing_field_key:
            routing_field = next(
                (field for field in configured_fields if field.key == routing_field_key),
                None,
            )
            # Routing is available only for a current schema-v2 choice field.
            # The returned value has already passed that field's enum validation.
            if (
                not schema_v2
                or routing_field is None
                or routing_field.field_type != "choice"
            ):
                return unavailable
            routing_value = validated[routing_field_key]
        return {
            "context_available": "true",
            "vapi_call_reference": reference,
            "routing_value": routing_value,
            **connect_rows(configured_fields, validated),
        }
    result = {"context_available": "true", "routing_value": ""}
    for field in RETURN_FIELDS:
        value = record.get(field, "")
        if not isinstance(value, str) or len(value.encode("utf-8")) > max(
            FIELD_LIMITS.get(field, 256), 1
        ):
            return unavailable
        result[field] = value
    return result


def connect_correlation_id(event: Mapping[str, Any]) -> str | None:
    """Return only a validated Connect correlation identifier, or fail open."""
    details = event.get("Details")
    if not isinstance(details, Mapping):
        return None
    contact = details.get("ContactData")
    if not isinstance(contact, Mapping):
        return None
    attributes = contact.get("Attributes")
    if not isinstance(attributes, Mapping):
        return None
    correlation_id = attributes.get("correlation_id")
    if not isinstance(correlation_id, str) or not CORRELATION.fullmatch(correlation_id):
        return None
    return correlation_id


def verify_bearer(headers: Mapping[str, Any], expected: str) -> None:
    if not isinstance(expected, str) or len(expected) < 32:
        raise HandoffError("authentication_unavailable", 500)
    presented = None
    for name, value in headers.items():
        if isinstance(name, str) and name.lower() == "authorization":
            if presented is not None or not isinstance(value, str):
                raise HandoffError("unauthorized", 401)
            presented = value
    prefix = "Bearer "
    if presented is None or not presented.startswith(prefix) or not hmac.compare_digest(
        presented[len(prefix) :], expected
    ):
        raise HandoffError("unauthorized", 401)


def decode_http_json(event: Mapping[str, Any]) -> tuple[dict[str, Any], Mapping[str, Any]]:
    headers = event.get("headers")
    if not isinstance(headers, Mapping):
        raise HandoffError("invalid_http_request")
    body = event.get("body")
    if not isinstance(body, str):
        raise HandoffError("invalid_http_request")
    try:
        raw = base64.b64decode(body, validate=True) if event.get("isBase64Encoded") else body.encode()
    except (ValueError, TypeError):
        raise HandoffError("invalid_http_request") from None
    if len(raw) > MAX_BODY_BYTES:
        raise HandoffError("request_too_large", 413)
    content_type = next(
        (
            value
            for name, value in headers.items()
            if isinstance(name, str) and name.lower() == "content-type"
        ),
        None,
    )
    if not isinstance(content_type, str) or content_type.split(";", 1)[0].strip().lower() != "application/json":
        raise HandoffError("unsupported_content_type", 415)
    try:
        decoded = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HandoffError("invalid_json") from None
    if not isinstance(decoded, dict):
        raise HandoffError("invalid_json")
    return decoded, headers


def http_response(status_code: int, payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "content-type": "application/json",
            "cache-control": "no-store",
            "x-content-type-options": "nosniff",
        },
        "body": json.dumps(payload, separators=(",", ":")),
        "isBase64Encoded": False,
    }


def error_response(error: HandoffError) -> dict[str, Any]:
    return http_response(error.status_code, {"error": error.code})
