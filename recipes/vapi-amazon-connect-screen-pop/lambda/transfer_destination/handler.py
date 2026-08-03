"""Authenticated Vapi transfer-destination Lambda entrypoint."""

from __future__ import annotations

import os
import time

from aws_runtime import BridgefuRouteClient, DynamoHandoffStore, emit_operation, load_secret
from bridgefu_handoff import (
    HandoffError,
    decode_http_json,
    error_response,
    http_response,
    transfer_destination,
    verify_bearer,
)


_STORE = None
_BRIDGEFU = None


def _store():
    global _STORE
    if _STORE is None:
        _STORE = DynamoHandoffStore(os.environ["HANDOFF_TABLE_NAME"])
    return _STORE


def _bridgefu():
    global _BRIDGEFU
    if _BRIDGEFU is None:
        sip_scheme = os.environ.get("SIP_SECURITY_SCHEME", "sips")
        deployment_id = os.environ["DEPLOYMENT_ID"]
        _BRIDGEFU = BridgefuRouteClient(
            os.environ["BRIDGEFU_CONTROL_BASE_URL"],
            os.environ["BRIDGEFU_ROUTE_ID"],
            load_secret(os.environ["BRIDGEFU_API_BEARER_SECRET_ARN"]),
            private_http_hostname=(
                f"control.{deployment_id}.bridgefu.internal"
                if sip_scheme == "sip"
                else None
            ),
        )
    return _BRIDGEFU


def lambda_handler(event, _context):
    started_at = time.monotonic()
    try:
        payload, headers = decode_http_json(event)
        verify_bearer(
            headers,
            load_secret(os.environ["VAPI_WEBHOOK_SECRET_ARN"]),
        )
        response = transfer_destination(
            payload,
            _store(),
            load_secret(os.environ["CORRELATION_KEY_SECRET_ARN"]).encode("utf-8"),
            os.environ["DEPLOYMENT_ID"],
            _bridgefu().reserve,
            os.environ.get("SIP_SECURITY_SCHEME", "sips"),
        )
        result = "reserved"
        output = http_response(200, response)
    except HandoffError as error:
        result = error.code
        output = error_response(error)
    except Exception:
        result = "internal_error"
        output = error_response(HandoffError("internal_error", 500))
    emit_operation("transfer_destination", result, started_at)
    return output
