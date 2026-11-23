"""Example Lambda runtime. Customer data is defined entirely by FIELD_CONFIG.

The deploy script inlines this file into CloudFormation. Never log events,
provider responses, SIP values, control URLs, or credentials.
"""

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

import boto3

_SECRET_CACHE = {}


def configuration():
    return json.loads(os.environ["FIELD_CONFIG"])


def secret(arn):
    if arn not in _SECRET_CACHE:
        _SECRET_CACHE[arn] = boto3.client("secretsmanager").get_secret_value(
            SecretId=arn
        )["SecretString"]
    return _SECRET_CACHE[arn]


def api(method, path, body=None):
    request = urllib.request.Request(
        "https://api.vapi.ai" + path,
        data=None if body is None else json.dumps(body).encode(),
        method=method,
        headers={
            "Authorization": "Bearer " + secret(os.environ["VAPI_SECRET_ARN"]),
            "Content-Type": "application/json",
            "User-Agent": "bridgefu-examples/1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


def value_at(data, path):
    for key in path.split("."):
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def values_for(config, call, arguments):
    variables = call.get("assistantOverrides", {}).get("variableValues", {})
    values = {}
    for field in config["fields"]:
        source, path = field["source"].split(".", 1)
        value = value_at(
            {"call": call, "variables": variables, "arguments": arguments}[source], path
        )
        if value is None and not field.get("required", True):
            continue
        if (
            not isinstance(value, str)
            or not value.strip()
            or len(value.encode("utf-8")) > field["max_bytes"]
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or "{{" in value
            or "}}" in value
        ):
            raise ValueError("invalid_field")
        values[field["attribute"]] = value
    return values


def destination(config, values, call_id, tool_id, webhook_secret):
    if config["mode"] == "sip-headers":
        headers = {
            f["header"]: values[f["attribute"]]
            for f in config["fields"]
            if f["attribute"] in values
        }
    else:
        # Stable, unguessable for retries of the same tool invocation; no model involvement.
        token = hmac.new(
            webhook_secret.encode(), (call_id + ":" + tool_id).encode(), hashlib.sha256
        ).hexdigest()[:32]
        table = boto3.resource("dynamodb").Table(os.environ["CONTEXT_TABLE"])
        item = {
            "id": token,
            "values": values,
            "expires_at": int(time.time()) + config["correlation"]["ttl_seconds"],
        }
        try:
            table.put_item(Item=item, ConditionExpression="attribute_not_exists(id)")
        except table.meta.client.exceptions.ConditionalCheckFailedException:
            previous = table.get_item(Key={"id": token}, ConsistentRead=True).get(
                "Item", {}
            )
            if previous.get("values") != values or int(
                previous.get("expires_at", 0)
            ) <= int(time.time()):
                raise ValueError("conflicting_or_expired_retry") from None
        headers = {config["correlation"]["header"]: token}
    return {
        "type": "sip",
        "sipUri": os.environ["GATEWAY_SIP_URI"],
        "sipHeaders": headers,
        "transferPlan": {"mode": "blind-transfer", "sipVerb": "dial"},
    }


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def control(call, dest):
    # URL is obtained from the authenticated Vapi GET /call, not tool arguments
    # or a caller-supplied callback. It may itself contain a bearer capability.
    url = call.get("monitor", {}).get("controlUrl")
    parsed = urllib.parse.urlparse(url or "")
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
    ):
        raise ValueError("missing_control_url")
    request = urllib.request.Request(
        url,
        method="POST",
        data=json.dumps({"type": "transfer", "destination": dest}).encode(),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "bridgefu-examples/1.0",
        },
    )
    with urllib.request.build_opener(NoRedirect).open(request, timeout=5) as response:
        if not 200 <= response.status < 300:
            raise ValueError("transfer_not_accepted")


def transfer(event, _context):
    headers = {k.lower(): v for k, v in event.get("headers", {}).items()}
    expected = secret(os.environ["WEBHOOK_SECRET_ARN"])
    supplied = headers.get("x-bridgefu-webhook-secret", "")
    if not isinstance(supplied, str) or not hmac.compare_digest(
        supplied.encode(), expected.encode()
    ):
        return {"statusCode": 401, "body": "{}"}
    tool_id = None
    stage = "validate_request"
    try:
        body = event.get("body", "")
        if event.get("isBase64Encoded"):
            body = base64.b64decode(body).decode()
        if len(body.encode()) > 1024 * 1024:
            raise ValueError("request_too_large")
        message = json.loads(body)["message"]
        tools = message.get("toolCallList") or [
            x["toolCall"] for x in message.get("toolWithToolCallList", [])
        ]
        config = configuration()
        if message.get("type") != "tool-calls" or len(tools) != 1:
            raise ValueError("unexpected_message")
        tool = tools[0]
        tool_id = tool["id"]
        if not isinstance(tool_id, str) or not 1 <= len(tool_id) <= 128:
            raise ValueError("invalid_tool_id")
        if tool["function"]["name"] != config["tool_name"]:
            raise ValueError("unexpected_tool")
        call_id = message["call"]["id"]
        import re

        if not isinstance(call_id, str) or not re.fullmatch(
            r"[0-9a-fA-F-]{36}", call_id
        ):
            raise ValueError("invalid_call_id")
        stage = "fetch_call"
        call = api("GET", "/call/" + call_id)
        if call.get("id") != call_id or call.get("status") != "in-progress":
            raise ValueError("call_not_in_progress")
        arguments = tool["function"]["arguments"]
        if isinstance(arguments, str):
            arguments = json.loads(arguments)
        if not isinstance(arguments, dict):
            raise ValueError("invalid_arguments")
        stage = "validate_fields"
        values = values_for(config, call, arguments)
        stage = "prepare_destination"
        dest = destination(config, values, call_id, tool_id, expected)
        stage = "request_transfer"
        control(call, dest)
        result = "Transfer requested."
    except Exception as error:
        # Static stage and exception class only; never include provider bodies or IDs.
        print(
            json.dumps(
                {
                    "event": "handoff_failed",
                    "stage": stage,
                    "error_type": type(error).__name__,
                }
            )
        )
        # A timeout is ambiguous. No automatic retry is configured in the tool.
        result = "Transfer not confirmed. Do not retry automatically; continue assisting the caller."
        if tool_id is None:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "invalid_handoff_request"}),
            }
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json"},
        "body": json.dumps({"results": [{"toolCallId": tool_id, "result": result}]}),
    }


def lookup(event, _context):
    config = configuration()
    status = config["status_attribute"]
    try:
        contact = event["Details"]["ContactData"]
        if contact.get("InstanceARN") != os.environ["CONNECT_INSTANCE_ARN"]:
            return {status: "invalid_instance"}
        token = contact["Attributes"].get(config["correlation"]["attribute"], "")
        import re

        if not re.fullmatch(r"[0-9a-f]{32}", token):
            return {status: "missing"}
        item = (
            boto3.resource("dynamodb")
            .Table(os.environ["CONTEXT_TABLE"])
            .get_item(Key={"id": token}, ConsistentRead=True)
            .get("Item", {})
        )
        if int(item.get("expires_at", 0)) <= int(time.time()):
            return {status: "expired_or_missing"}
        allowed = {
            field["attribute"]: item.get("values", {}).get(field["attribute"], "")
            for field in config["fields"]
        }
        # Connect Lambda STRING_MAP results must remain under 4 KiB.
        response = {**allowed, status: "found"}
        if len(json.dumps(response).encode()) > 4000:
            return {status: "too_large"}
        return response
    except Exception:
        return {status: "unavailable"}
