"""CloudFormation custom-resource entrypoint for recipe-owned Vapi objects."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

from aws_runtime import emit_operation, load_secret
from vapi_provisioning import (
    PENDING_PHYSICAL_ID,
    ProvisioningConfig,
    VapiHttpClient,
    VapiProvisioningError,
    provision_create,
    provision_delete,
    provision_update,
)


VAPI_REQUEST_TIMEOUT_SECONDS = 15.0
CLOUDFORMATION_RESPONSE_RESERVE_SECONDS = 15.0
MIN_VAPI_REQUEST_TIMEOUT_SECONDS = 1.0
CLOUDFORMATION_RESPONSE_TIMEOUT_SECONDS = 6.0
CLOUDFORMATION_RESPONSE_ATTEMPTS = 2
CLOUDFORMATION_RESPONSE_MARGIN_SECONDS = 2.0


def _remaining_seconds(context):
    if context is None or not callable(
        getattr(context, "get_remaining_time_in_millis", None)
    ):
        return None
    return max(0.0, context.get_remaining_time_in_millis() / 1000.0)


def _vapi_request_timeout(context):
    remaining = _remaining_seconds(context)
    if remaining is None:
        return VAPI_REQUEST_TIMEOUT_SECONDS
    available = remaining - CLOUDFORMATION_RESPONSE_RESERVE_SECONDS
    if available < MIN_VAPI_REQUEST_TIMEOUT_SECONDS:
        raise VapiProvisioningError("vapi_operation_budget_exhausted")
    return min(VAPI_REQUEST_TIMEOUT_SECONDS, available)


def _response_request_timeout(context):
    remaining = _remaining_seconds(context)
    if remaining is None:
        return CLOUDFORMATION_RESPONSE_TIMEOUT_SECONDS
    available = remaining - CLOUDFORMATION_RESPONSE_MARGIN_SECONDS
    if available <= 0:
        return 0.25
    return max(0.25, min(CLOUDFORMATION_RESPONSE_TIMEOUT_SECONDS, available))


def _boolean(value, field):
    if value in (True, "true", "True"):
        return True
    if value in (False, "false", "False", None):
        return False
    raise VapiProvisioningError(f"{field}_invalid")


def _config(event, properties, *, load_webhook_token=True):
    return ProvisioningConfig(
        stack_id=event["StackId"],
        deployment_id=properties["DeploymentId"],
        prepare_url=properties["PrepareUrl"],
        transfer_url=properties["TransferUrl"],
        model=properties.get("Model", "gpt-4.1-mini"),
        voice_id=properties.get("VoiceId", "Elliot"),
        webhook_token=(
            load_secret(properties["WebhookSecretArn"])
            if load_webhook_token
            else None
        ),
        asset_root=Path(os.environ.get("VAPI_ASSET_ROOT", "assets/vapi")),
    )


def _send(event, status, physical_id, data, reason, *, context=None):
    body = json.dumps(
        {
            "Status": status,
            "Reason": reason[:512],
            "PhysicalResourceId": physical_id,
            "StackId": event["StackId"],
            "RequestId": event["RequestId"],
            "LogicalResourceId": event["LogicalResourceId"],
            "NoEcho": False,
            "Data": data,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        event["ResponseURL"],
        data=body,
        method="PUT",
        headers={"content-type": "", "content-length": str(len(body))},
    )
    for attempt in range(CLOUDFORMATION_RESPONSE_ATTEMPTS):
        try:
            with urllib.request.urlopen(
                request, timeout=_response_request_timeout(context)
            ) as response:
                response.read(1024)
            return
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt + 1 == CLOUDFORMATION_RESPONSE_ATTEMPTS:
                raise


def lambda_handler(event, _context):
    started_at = time.monotonic()
    result_code = "internal_error"
    request_type = event.get("RequestType")
    fallback_id = event.get("PhysicalResourceId", PENDING_PHYSICAL_ID)
    try:
        properties = event.get("ResourceProperties")
        if not isinstance(properties, dict):
            raise VapiProvisioningError("resource_properties_invalid")
        retain = _boolean(
            properties.get("RetainVapiResourcesOnDelete"),
            "retain_vapi_resources",
        )
        if request_type == "Delete" and retain:
            result_code = "delete_retained"
            _send(
                event,
                "SUCCESS",
                fallback_id,
                {},
                "resources retained by policy",
                context=_context,
            )
            return

        api_key = load_secret(properties["VapiApiKeySecretArn"])
        client = VapiHttpClient(
            api_key,
            request_timeout=lambda: _vapi_request_timeout(_context),
        )
        config = _config(
            event,
            properties,
            load_webhook_token=request_type != "Delete",
        )
        if request_type == "Create":
            result = provision_create(client, config)
        elif request_type == "Update":
            old_properties = event.get("OldResourceProperties")
            if not isinstance(old_properties, dict):
                raise VapiProvisioningError("old_resource_properties_invalid")
            old_config = _config(event, old_properties)
            result = provision_update(client, old_config, config, fallback_id)
        elif request_type == "Delete":
            provision_delete(client, config, fallback_id)
            result_code = "delete_success"
            _send(
                event,
                "SUCCESS",
                fallback_id,
                {},
                "recipe-owned resources deleted",
                context=_context,
            )
            return
        else:
            raise VapiProvisioningError("request_type_invalid")

        result_code = f"{request_type.lower()}_success"
        _send(
            event,
            "SUCCESS",
            result.physical_id,
            {
                "AssistantId": result.assistant_id,
                "PrepareToolId": result.prepare_tool_id,
                "TransferToolMode": "inline",
                "WebhookCredentialId": result.webhook_credential_id,
            },
            "recipe-owned Vapi resources are ready",
            context=_context,
        )
    except VapiProvisioningError as error:
        result_code = "provisioning_failed"
        _send(event, "FAILED", fallback_id, {}, str(error), context=_context)
    except Exception:
        result_code = "internal_error"
        _send(event, "FAILED", fallback_id, {}, "internal_error", context=_context)
    finally:
        emit_operation("vapi_provisioner", result_code, started_at)
