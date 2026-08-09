"""Authenticated Vapi context-preparation Lambda entrypoint.

The production template stores validated context here, then Vapi asks the
separate transfer-destination endpoint for a one-use SIP route. The historical
direct live-control tool remains compatibility-only.
"""

from __future__ import annotations

import os
import time
import json
import urllib.error
import urllib.request

from aws_runtime import DynamoHandoffStore, emit_operation, load_secret
from bridgefu_handoff import (
    HandoffError,
    decode_http_json,
    error_response,
    http_response,
    direct_transfer_response,
    prepare_handoff,
    prepare_vapi_response,
    DIRECT_TRANSFER_TOOL_NAME,
    TEMPLATE_PREPARE_TOOL_NAME,
    tool_name,
    vapi_control_url,
    verify_vapi_binding,
    verify_bearer,
)
from screen_pop import parse_fields


_STORE = None
_LAMBDA = None


def _store():
    global _STORE
    if _STORE is None:
        _STORE = DynamoHandoffStore(os.environ["HANDOFF_TABLE_NAME"])
    return _STORE


def _lambda_client():
    global _LAMBDA
    if _LAMBDA is None:
        import boto3

        _LAMBDA = boto3.client("lambda")
    return _LAMBDA


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _reserve(payload):
    call = payload["message"]["call"]
    response = _lambda_client().invoke(
        FunctionName=os.environ["TRANSFER_FUNCTION_NAME"],
        InvocationType="RequestResponse",
        Payload=json.dumps(
            {
                "bridgefuInternalReserveV1": {
                    "call": {
                        "id": call["id"],
                        "orgId": call["orgId"],
                        "assistantId": call.get("assistantId"),
                    }
                }
            },
            separators=(",", ":"),
        ).encode("utf-8"),
    )
    if response.get("FunctionError"):
        raise HandoffError("bridgefu_reservation_failed", 502)
    raw = response.get("Payload").read(65_537)
    if len(raw) > 65_536:
        raise HandoffError("bridgefu_reservation_failed", 502)
    try:
        decoded = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HandoffError("bridgefu_reservation_failed", 502) from None
    destination = decoded.get("destination") if isinstance(decoded, dict) else None
    if not isinstance(destination, dict):
        raise HandoffError("bridgefu_reservation_failed", 502)
    return destination


def _start_vapi_transfer(control_url, destination):
    body = json.dumps(
        {"type": "transfer", "destination": destination},
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        control_url,
        data=body,
        method="POST",
        headers={
            "content-type": "application/json",
            "accept": "application/json",
            "user-agent": "bridgefu-vapi-handoff/1",
        },
    )
    try:
        with urllib.request.build_opener(_NoRedirect()).open(
            request, timeout=8
        ) as response:
            response.read(65_537)
            status = response.status
    except urllib.error.HTTPError as error:
        if error.code in (401, 403):
            raise HandoffError("vapi_control_unauthorized", 502) from None
        raise HandoffError("vapi_control_failed", 502) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise HandoffError("vapi_control_unavailable", 502) from None
    if status < 200 or status >= 300:
        raise HandoffError("vapi_control_failed", 502)


def lambda_handler(event, _context):
    started_at = time.monotonic()
    try:
        payload, headers = decode_http_json(event)
        verify_bearer(
            headers,
            load_secret(os.environ["VAPI_WEBHOOK_SECRET_ARN"]),
        )
        verify_vapi_binding(
            payload,
            json.loads(load_secret(os.environ["VAPI_IDENTITY_BINDING_ARN"])),
        )
        name = tool_name(payload)
        configured_fields = (
            parse_fields(os.environ["SCREEN_POP_FIELDS_JSON"])
            if name in (TEMPLATE_PREPARE_TOOL_NAME, DIRECT_TRANSFER_TOOL_NAME)
            else None
        )
        control_url = (
            vapi_control_url(payload)
            if name == DIRECT_TRANSFER_TOOL_NAME
            else None
        )
        prepared = prepare_handoff(
            payload,
            _store(),
            load_secret(os.environ["CORRELATION_KEY_SECRET_ARN"]).encode("utf-8"),
            os.environ["DEPLOYMENT_ID"],
            int(os.environ.get("CONTEXT_TTL_SECONDS", "3600")),
            configured_fields=configured_fields,
        )
        result = "replayed" if prepared.replayed else "created"
        if name == DIRECT_TRANSFER_TOOL_NAME:
            destination = _reserve(payload)
            _start_vapi_transfer(control_url, destination)
            result = "transfer_replayed" if prepared.replayed else "transfer_started"
            response = http_response(200, direct_transfer_response(prepared))
        else:
            response = http_response(200, prepare_vapi_response(prepared))
    except HandoffError as error:
        result = error.code
        response = error_response(error)
    except Exception:
        result = "internal_error"
        response = error_response(HandoffError("internal_error", 500))
    emit_operation("prepare_handoff", result, started_at)
    return response
