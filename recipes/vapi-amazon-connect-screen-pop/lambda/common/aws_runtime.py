"""AWS adapters for the handoff contract.

Only resource identifiers and low-cardinality result codes may be logged by
entrypoints. This module never logs secret strings, handoff rows, or payloads.
"""

from __future__ import annotations

import hashlib
import json
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping

from bridgefu_handoff import CORRELATION, HandoffError, SipReservation


_SECRET_CACHE: dict[str, tuple[str, float]] = {}
_SECRET_LOCK = threading.Lock()
SECRET_CACHE_TTL_SECONDS = 300.0
SAFE_EVENTS = {
    "prepare_handoff",
    "transfer_destination",
    "connect_lookup",
    "vapi_provisioner",
}
SAFE_RESULTS = {
    "created",
    "replayed",
    "reserved",
    "available",
    "unavailable",
    "create_success",
    "update_success",
    "delete_success",
    "delete_retained",
    "provisioning_failed",
    "authentication_unavailable",
    "bridgefu_configuration_invalid",
    "bridgefu_destination_expired",
    "bridgefu_destination_invalid",
    "bridgefu_reservation_failed",
    "bridgefu_reservation_unavailable",
    "bridgefu_response_invalid",
    "conflicting_tool_arguments",
    "context_too_large",
    "correlation_derivation_failed",
    "handoff_expired",
    "handoff_identity_conflict",
    "handoff_not_prepared",
    "handoff_replay_conflict",
    "handoff_state_conflict",
    "handoff_store_invalid",
    "invalid_context_ttl",
    "invalid_correlation_key",
    "invalid_http_request",
    "invalid_json",
    "invalid_tool_arguments",
    "invalid_tool_call",
    "invalid_tool_name",
    "invalid_vapi_call",
    "invalid_vapi_event",
    "request_too_large",
    "secret_configuration_invalid",
    "unauthorized",
    "unsupported_content_type",
    "internal_error",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _boto3_client(service: str):
    import boto3  # AWS Lambda runtime dependency; intentionally not vendored.

    return boto3.client(service)


def load_secret(secret_arn: str, client=None, now=None) -> str:
    if not isinstance(secret_arn, str) or not secret_arn.startswith("arn:"):
        raise HandoffError("secret_configuration_invalid", 500)
    current = time.monotonic() if now is None else float(now)
    with _SECRET_LOCK:
        cached = _SECRET_CACHE.get(secret_arn)
    if cached is not None and current - cached[1] < SECRET_CACHE_TTL_SECONDS:
        return cached[0]
    client = client or _boto3_client("secretsmanager")
    response = client.get_secret_value(SecretId=secret_arn)
    value = response.get("SecretString")
    if not isinstance(value, str) or len(value) < 32:
        raise HandoffError("secret_configuration_invalid", 500)
    with _SECRET_LOCK:
        _SECRET_CACHE[secret_arn] = (value, current)
    return value


def emit_operation(event: str, result: str, started_at: float) -> None:
    """Emit one bounded EMF record with no request body or identifiers."""
    safe_event = event if event in SAFE_EVENTS else "internal"
    safe_result = result if result in SAFE_RESULTS else "internal_error"
    duration = max(0.0, min(120_000.0, (time.monotonic() - started_at) * 1000.0))
    print(
        json.dumps(
            {
                "_aws": {
                    "Timestamp": int(time.time() * 1000),
                    "CloudWatchMetrics": [
                        {
                            "Namespace": "Bridgefu/Recipe",
                            "Dimensions": [["operation", "result"]],
                            "Metrics": [
                                {"Name": "Requests", "Unit": "Count"},
                                {"Name": "Duration", "Unit": "Milliseconds"},
                            ],
                        }
                    ],
                },
                "event": safe_event,
                "operation": safe_event,
                "result": safe_result,
                "Requests": 1,
                "Duration": round(duration, 3),
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def emit_correlation_evidence(
    operation: str,
    result: str,
    correlation_id: str,
) -> None:
    """Emit one bounded lookup audit event without the correlation identifier."""
    if (
        operation not in SAFE_EVENTS
        or result not in SAFE_RESULTS
        or not isinstance(correlation_id, str)
        or CORRELATION.fullmatch(correlation_id) is None
    ):
        return
    print(
        json.dumps(
            {
                "event": "bridgefu_correlation_evidence",
                "operation": operation,
                "result": result,
                "correlation_fingerprint": hashlib.sha256(
                    correlation_id.encode("ascii")
                ).hexdigest()[:12],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def _decode_item(item: Mapping[str, Any]) -> dict[str, Any]:
    decoded: dict[str, Any] = {}
    for key, value in item.items():
        if not isinstance(value, Mapping) or len(value) != 1:
            raise HandoffError("handoff_store_invalid", 500)
        kind, raw = next(iter(value.items()))
        if kind == "S" and isinstance(raw, str):
            decoded[key] = raw
        elif kind == "N" and isinstance(raw, str):
            try:
                decoded[key] = int(raw)
            except ValueError:
                raise HandoffError("handoff_store_invalid", 500) from None
        else:
            raise HandoffError("handoff_store_invalid", 500)
    return decoded


def _encode_item(record: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    encoded: dict[str, dict[str, str]] = {}
    for key, value in record.items():
        if isinstance(value, bool):
            raise HandoffError("handoff_store_invalid", 500)
        if isinstance(value, int):
            encoded[key] = {"N": str(value)}
        elif isinstance(value, str):
            encoded[key] = {"S": value}
        else:
            raise HandoffError("handoff_store_invalid", 500)
    return encoded


def _conditional_failure(error: Exception) -> bool:
    response = getattr(error, "response", None)
    return (
        isinstance(response, Mapping)
        and response.get("Error", {}).get("Code")
        == "ConditionalCheckFailedException"
    )


class DynamoHandoffStore:
    def __init__(self, table_name: str, client=None) -> None:
        if not isinstance(table_name, str) or not table_name:
            raise HandoffError("handoff_store_invalid", 500)
        self._table_name = table_name
        self._client = client or _boto3_client("dynamodb")

    def get(self, correlation_id: str) -> Mapping[str, Any] | None:
        response = self._client.get_item(
            TableName=self._table_name,
            Key={"correlation_id": {"S": correlation_id}},
            ConsistentRead=True,
            ProjectionExpression=(
                "schema_version,correlation_id,customer_name,issue_summary,intent,"
                "verification_status,vapi_call_reference,vapi_call_fingerprint,"
                "content_hash,created_at,updated_at,expires_at,handoff_status,"
                "bridgefu_call_id,attachment_expires_at"
            ),
        )
        item = response.get("Item")
        return _decode_item(item) if isinstance(item, Mapping) else None

    def put_prepared(self, record: Mapping[str, Any]) -> str:
        try:
            self._client.put_item(
                TableName=self._table_name,
                Item=_encode_item(record),
                ConditionExpression="attribute_not_exists(correlation_id)",
            )
            return "created"
        except Exception as error:
            if not _conditional_failure(error):
                raise
        existing = self.get(str(record["correlation_id"]))
        exact = (
            existing is not None
            and existing.get("schema_version") == record.get("schema_version")
            and existing.get("vapi_call_fingerprint")
            == record.get("vapi_call_fingerprint")
            and existing.get("content_hash") == record.get("content_hash")
            and existing.get("handoff_status") in ("PREPARED", "RESERVED")
        )
        if not exact:
            raise HandoffError("handoff_replay_conflict", 409)
        return "replayed"

    def mark_reserved(
        self,
        correlation_id: str,
        updated_at: int,
        bridgefu_call_id: str,
        attachment_expires_at: int,
    ) -> None:
        try:
            self._client.update_item(
                TableName=self._table_name,
                Key={"correlation_id": {"S": correlation_id}},
                UpdateExpression=(
                    "SET #status = :reserved, updated_at = :updated, "
                    "bridgefu_call_id = :call, attachment_expires_at = :attachment_expiry"
                ),
                ConditionExpression="#status IN (:prepared, :reserved)",
                ExpressionAttributeNames={"#status": "handoff_status"},
                ExpressionAttributeValues={
                    ":prepared": {"S": "PREPARED"},
                    ":reserved": {"S": "RESERVED"},
                    ":updated": {"N": str(updated_at)},
                    ":call": {"S": bridgefu_call_id},
                    ":attachment_expiry": {"N": str(attachment_expires_at)},
                },
            )
        except Exception as error:
            if _conditional_failure(error):
                raise HandoffError("handoff_state_conflict", 409) from None
            raise


class BridgefuRouteClient:
    def __init__(
        self,
        base_url: str,
        route_id: str,
        bearer_token: str,
        timeout_seconds: float = 8.0,
        private_http_hostname: str | None = None,
    ) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        secure_origin = parsed.scheme == "https" and parsed.port in {None, 443}
        private_test_origin = (
            parsed.scheme == "http"
            and private_http_hostname is not None
            and parsed.hostname == private_http_hostname
            and parsed.port == 443
            and re.fullmatch(
                r"control\.bft-[a-z0-9-]{4,20}\.bridgefu\.internal",
                private_http_hostname,
            )
            is not None
        )
        if (
            not (secure_origin or private_test_origin)
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise HandoffError("bridgefu_configuration_invalid", 500)
        if parsed.query or parsed.fragment:
            raise HandoffError("bridgefu_configuration_invalid", 500)
        if parsed.path not in ("", "/"):
            raise HandoffError("bridgefu_configuration_invalid", 500)
        if not route_id or not route_id.replace("-", "").replace("_", "").isalnum():
            raise HandoffError("bridgefu_configuration_invalid", 500)
        if len(bearer_token) < 32:
            raise HandoffError("bridgefu_configuration_invalid", 500)
        self._base_url = base_url.rstrip("/")
        self._route_id = route_id
        self._bearer_token = bearer_token
        self._timeout_seconds = timeout_seconds
        transport = (
            urllib.request.HTTPSHandler(context=ssl.create_default_context())
            if secure_origin
            else urllib.request.HTTPHandler()
        )
        self._opener = urllib.request.build_opener(_NoRedirect(), transport)

    def reserve(self, correlation_id: str, idempotency_key: str) -> SipReservation:
        url = (
            f"{self._base_url}/v1/routes/"
            f"{urllib.parse.quote(self._route_id, safe='')}/calls"
        )
        body = json.dumps(
            {
                "ingress": "sip",
                "context": {"correlation_id": correlation_id, "metadata": {}},
            },
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "authorization": f"Bearer {self._bearer_token}",
                "content-type": "application/json",
                "idempotency-key": idempotency_key,
                "user-agent": "bridgefu-recipe-handoff/1",
            },
        )
        try:
            with self._opener.open(
                request,
                timeout=self._timeout_seconds,
            ) as response:
                if response.status != 201:
                    raise HandoffError("bridgefu_reservation_failed", 502)
                raw = response.read(16_385)
        except HandoffError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError):
            raise HandoffError("bridgefu_reservation_unavailable", 503) from None
        if len(raw) > 16_384:
            raise HandoffError("bridgefu_response_invalid", 502)
        try:
            payload = json.loads(raw)
            attachment = payload["attachment"]
            uri = attachment["uri"]
            expires_at_raw = attachment["expires_at"]
            call_id = payload["call_id"]
        except (KeyError, TypeError, json.JSONDecodeError):
            raise HandoffError("bridgefu_response_invalid", 502) from None
        if not isinstance(uri, str) or not isinstance(call_id, str) or not isinstance(
            expires_at_raw, str
        ):
            raise HandoffError("bridgefu_response_invalid", 502)
        try:
            from datetime import datetime

            expires_at = int(
                datetime.fromisoformat(
                    expires_at_raw.replace("Z", "+00:00")
                ).timestamp()
            )
        except ValueError:
            raise HandoffError("bridgefu_response_invalid", 502) from None
        return SipReservation(uri=uri, call_id=call_id, expires_at=expires_at)
