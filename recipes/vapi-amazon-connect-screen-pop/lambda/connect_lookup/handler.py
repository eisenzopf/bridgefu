"""Private Amazon Connect context lookup Lambda entrypoint."""

from __future__ import annotations

import os
import time

from aws_runtime import DynamoHandoffStore, emit_correlation_evidence, emit_operation
from bridgefu_handoff import RETURN_FIELDS, connect_correlation_id, connect_lookup
from screen_pop import connect_rows, parse_fields


_STORE = None


def _store():
    global _STORE
    if _STORE is None:
        _STORE = DynamoHandoffStore(os.environ["HANDOFF_TABLE_NAME"])
    return _STORE


def _unavailable():
    configured = os.environ.get("SCREEN_POP_FIELDS_JSON")
    if configured:
        fields = parse_fields(configured)
        return {
            "context_available": "false",
            "vapi_call_reference": "",
            "routing_value": "",
            **connect_rows(fields, None),
        }
    return {
        "context_available": "false",
        "routing_value": "",
        **{field: "" for field in RETURN_FIELDS},
    }


def lambda_handler(event, _context):
    started_at = time.monotonic()
    correlation_id = connect_correlation_id(event)
    try:
        configured = os.environ.get("SCREEN_POP_FIELDS_JSON")
        response = connect_lookup(
            event,
            _store(),
            configured_fields=parse_fields(configured) if configured else None,
            routing_field_key=os.environ.get("ROUTING_FIELD_KEY") or None,
        )
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
