"""Authenticated Vapi prepare_handoff Lambda entrypoint."""

from __future__ import annotations

import os
import time

from aws_runtime import DynamoHandoffStore, emit_operation, load_secret
from bridgefu_handoff import (
    HandoffError,
    decode_http_json,
    error_response,
    http_response,
    prepare_handoff,
    prepare_vapi_response,
    verify_bearer,
)


_STORE = None


def _store():
    global _STORE
    if _STORE is None:
        _STORE = DynamoHandoffStore(os.environ["HANDOFF_TABLE_NAME"])
    return _STORE


def lambda_handler(event, _context):
    started_at = time.monotonic()
    try:
        payload, headers = decode_http_json(event)
        verify_bearer(
            headers,
            load_secret(os.environ["VAPI_WEBHOOK_SECRET_ARN"]),
        )
        prepared = prepare_handoff(
            payload,
            _store(),
            load_secret(os.environ["CORRELATION_KEY_SECRET_ARN"]).encode("utf-8"),
            os.environ["DEPLOYMENT_ID"],
            int(os.environ.get("CONTEXT_TTL_SECONDS", "86400")),
        )
        result = "replayed" if prepared.replayed else "created"
        response = http_response(200, prepare_vapi_response(prepared))
    except HandoffError as error:
        result = error.code
        response = error_response(error)
    except Exception:
        result = "internal_error"
        response = error_response(HandoffError("internal_error", 500))
    emit_operation("prepare_handoff", result, started_at)
    return response
