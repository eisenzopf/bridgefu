"""Private Amazon Connect context lookup Lambda entrypoint."""

from __future__ import annotations

import os
import time

from aws_runtime import DynamoHandoffStore, emit_correlation_evidence, emit_operation
from bridgefu_handoff import RETURN_FIELDS, connect_correlation_id, connect_lookup


_STORE = None


def _store():
    global _STORE
    if _STORE is None:
        _STORE = DynamoHandoffStore(os.environ["HANDOFF_TABLE_NAME"])
    return _STORE


def _unavailable():
    return {"context_available": "false", **{field: "" for field in RETURN_FIELDS}}


def lambda_handler(event, _context):
    started_at = time.monotonic()
    correlation_id = connect_correlation_id(event)
    try:
        response = connect_lookup(event, _store())
        result = (
            "available"
            if response["context_available"] == "true"
            else "unavailable"
        )
    except Exception:
        # Missing screen-pop context must never prevent the voice contact from
        # continuing into the customer's target flow.
        result = "internal_error"
        response = _unavailable()
    emit_operation("connect_lookup", result, started_at)
    if correlation_id is not None:
        emit_correlation_evidence("connect_lookup", result, correlation_id)
    return response
