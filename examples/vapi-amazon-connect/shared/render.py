#!/usr/bin/env python3
"""Render both runnable examples from one customer-owned settings file."""

import argparse
import copy
import json
from pathlib import Path
import re
import yaml


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


ROOT = Path(__file__).resolve().parents[1]
RESERVED = {
    "correlation_id",
    "handoff_token",
    "tenant_id",
    "call_id",
    "source_leg_id",
    "version",
    "bridgefu_recipe",
    "bridgefu_recipe_version",
}


def validate(c):
    if c["mode"] not in ("sip-headers", "correlation-id"):
        raise ValueError("Unknown mode")
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,39}", c["sip_user"]):
        raise ValueError("Invalid SIP user")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,39}", c["tool_name"]):
        raise ValueError("Invalid tool name")
    if c["sip_security"] not in ("sips_srtp", "sips_optional_srtp"):
        raise ValueError("Select a TLS SIP security posture")
    if not 1 <= len(c["fields"]) <= 12:
        raise ValueError("Configure 1-12 fields")
    names, headers, attrs = set(), set(), set()
    for f in c["fields"]:
        if (
            not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,39}", f["name"])
            or f["name"] in names
        ):
            raise ValueError("Field names must be unique identifiers")
        if (
            not re.fullmatch(r"X-[A-Za-z0-9_-]+", f["header"], re.I)
            or f["header"].lower() in headers
            or f["header"].lower().startswith(("x-bridgefu", "x-rvoip"))
        ):
            raise ValueError("Headers must be unique application X- headers")
        if (
            not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", f["attribute"])
            or f["attribute"] in attrs
            or f["attribute"] in RESERVED
        ):
            raise ValueError("Invalid, reserved, or duplicate Connect attribute")
        if not re.fullmatch(r"(call|variables|arguments)\.[A-Za-z0-9_.]+", f["source"]):
            raise ValueError("Source must be call.*, variables.*, or arguments.*")
        if (
            f["source"].startswith("arguments.")
            and f["source"] != "arguments." + f["name"]
        ):
            raise ValueError("Argument sources must match the field name")
        if not isinstance(f["max_bytes"], int) or not 1 <= f["max_bytes"] <= 2048:
            raise ValueError("Invalid field bound")
        if (
            not isinstance(f["description"], str)
            or not 1 <= len(f["description"]) <= 256
        ):
            raise ValueError("Supply a short field description")
        names.add(f["name"])
        headers.add(f["header"].lower())
        attrs.add(f["attribute"])
    if sum(f["max_bytes"] for f in c["fields"]) > 2500:
        raise ValueError("Total field bounds must fit the 4 KiB Connect Lambda result")
    corr = c["correlation"]
    if (
        not re.fullmatch(r"X-[A-Za-z0-9_-]+", corr["header"], re.I)
        or corr["header"].lower().startswith(("x-bridgefu", "x-rvoip"))
        or corr["header"].lower() in headers
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", corr["attribute"])
        or corr["attribute"] in attrs | RESERVED
        or not 60 <= corr["ttl_seconds"] <= 86400
    ):
        raise ValueError("Invalid correlation configuration")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", c["status_attribute"]) or c[
        "status_attribute"
    ] in attrs | RESERVED | {corr["attribute"]}:
        raise ValueError("Status attribute must be a distinct application key")
    runtime = {
        k: c[k]
        for k in ("mode", "fields", "correlation", "tool_name", "status_attribute")
    }
    # Leave room for ARN and URI environment variables below Lambda's 4 KiB cap.
    if len(json.dumps(runtime, separators=(",", ":")).encode()) > 2800:
        raise ValueError(
            "Field configuration exceeds the example Lambda environment budget"
        )
    return runtime


def flow(c):
    err = [{"ErrorType": "NoMatchingError", "NextAction": "target"}]
    actions = []
    if c["mode"] == "correlation-id":
        actions += [
            {
                "Identifier": "lookup",
                "Type": "InvokeLambdaFunction",
                "Parameters": {
                    "LambdaFunctionARN": "${LookupFunction.Arn}",
                    "InvocationTimeLimitSeconds": "8",
                    "ResponseValidation": {"ResponseType": "STRING_MAP"},
                },
                "Transitions": {
                    "NextAction": "check-result",
                    "Errors": [
                        {"ErrorType": "NoMatchingError", "NextAction": "missing"}
                    ],
                },
            },
            {
                "Identifier": "check-result",
                "Type": "Compare",
                "Parameters": {
                    "ComparisonValue": "$.External." + c["status_attribute"]
                },
                "Transitions": {
                    "NextAction": "missing",
                    "Conditions": [
                        {
                            "NextAction": "attributes",
                            "Condition": {"Operator": "Equals", "Operands": ["found"]},
                        }
                    ],
                    "Errors": [
                        {"ErrorType": "NoMatchingCondition", "NextAction": "missing"}
                    ],
                },
            },
            {
                "Identifier": "attributes",
                "Type": "UpdateContactAttributes",
                "Parameters": {
                    "TargetContact": "Current",
                    "Attributes": {
                        **{
                            f["attribute"]: "$.External." + f["attribute"]
                            for f in c["fields"]
                        },
                        c["status_attribute"]: "found",
                    },
                },
                "Transitions": {"NextAction": "target", "Errors": err},
            },
            {
                "Identifier": "missing",
                "Type": "UpdateContactAttributes",
                "Parameters": {
                    "TargetContact": "Current",
                    "Attributes": {c["status_attribute"]: "unavailable"},
                },
                "Transitions": {"NextAction": "target", "Errors": err},
            },
        ]
    actions += [
        {
            "Identifier": "target",
            "Type": "TransferToFlow",
            "Parameters": {"ContactFlowId": "${TargetContactFlowArn}"},
            "Transitions": {
                "NextAction": "disconnect",
                "Errors": [
                    {"ErrorType": "NoMatchingError", "NextAction": "disconnect"}
                ],
            },
        },
        {
            "Identifier": "disconnect",
            "Type": "DisconnectParticipant",
            "Parameters": {},
            "Transitions": {},
        },
    ]
    return {
        "Version": "2019-10-30",
        "StartAction": actions[0]["Identifier"],
        "Metadata": {"entryPointPosition": {"x": 40, "y": 40}, "ActionMetadata": {}},
        "Actions": actions,
    }


def template(c, runtime):
    ref = lambda name: {"Ref": name}
    sub = lambda value: {"Fn::Sub": value}
    arn = lambda name: {"Fn::GetAtt": [name, "Arn"]}
    r = {}
    r["WebhookSecret"] = {
        "Type": "AWS::SecretsManager::Secret",
        "Properties": {
            "Description": "Authentication for this example Vapi webhook",
            "GenerateSecretString": {"PasswordLength": 48, "ExcludePunctuation": True},
        },
    }
    policy = [
        {
            "Effect": "Allow",
            "Action": "secretsmanager:GetSecretValue",
            "Resource": [ref("VapiApiKeySecretArn"), ref("WebhookSecret")],
        },
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": sub(
                "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/${AWS::StackName}-*:*"
            ),
        },
    ]
    if c["mode"] == "correlation-id":
        r["ContextTable"] = {
            "Type": "AWS::DynamoDB::Table",
            "DeletionPolicy": "Delete",
            "Properties": {
                "BillingMode": "PAY_PER_REQUEST",
                "AttributeDefinitions": [{"AttributeName": "id", "AttributeType": "S"}],
                "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
                "SSESpecification": {"SSEEnabled": True},
                "TimeToLiveSpecification": {
                    "AttributeName": "expires_at",
                    "Enabled": True,
                },
            },
        }
        policy += [
            {
                "Effect": "Allow",
                "Action": ["dynamodb:PutItem", "dynamodb:GetItem"],
                "Resource": arn("ContextTable"),
            }
        ]
    r["TransferRole"] = {
        "Type": "AWS::IAM::Role",
        "Properties": {
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
            "Policies": [
                {
                    "PolicyName": "example-transfer",
                    "PolicyDocument": {"Version": "2012-10-17", "Statement": policy},
                }
            ],
        },
    }
    variables = {
        "FIELD_CONFIG": json.dumps(runtime, separators=(",", ":")),
        "VAPI_SECRET_ARN": ref("VapiApiKeySecretArn"),
        "WEBHOOK_SECRET_ARN": ref("WebhookSecret"),
        "GATEWAY_SIP_URI": ref("GatewaySipUri"),
        "CONNECT_INSTANCE_ARN": ref("ConnectInstanceArn"),
    }
    if c["mode"] == "correlation-id":
        variables["CONTEXT_TABLE"] = ref("ContextTable")
    for name, entry in [("TransferFunction", "transfer")] + (
        [("LookupFunction", "lookup")] if c["mode"] == "correlation-id" else []
    ):
        r[name + "Logs"] = {
            "Type": "AWS::Logs::LogGroup",
            "Properties": {
                "LogGroupName": sub("/aws/lambda/${AWS::StackName}-" + entry),
                "RetentionInDays": 7,
            },
        }
        role = "TransferRole"
        env = variables
        if entry == "lookup":
            role = "LookupRole"
            r[role] = copy.deepcopy(r["TransferRole"])
            r[role]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"] = [
                policy[1],
                {
                    "Effect": "Allow",
                    "Action": "dynamodb:GetItem",
                    "Resource": arn("ContextTable"),
                },
            ]
            env = {
                k: variables[k]
                for k in ("FIELD_CONFIG", "CONTEXT_TABLE", "CONNECT_INSTANCE_ARN")
            }
        r[name] = {
            "Type": "AWS::Lambda::Function",
            "DependsOn": name + "Logs",
            "Properties": {
                "FunctionName": sub("${AWS::StackName}-" + entry),
                "Runtime": "python3.12",
                "Handler": "index." + entry,
                "Role": arn(role),
                "Timeout": 25 if entry == "transfer" else 8,
                "MemorySize": 256,
                "Environment": {"Variables": env},
                "Code": {"ZipFile": (ROOT / "shared/handler.py").read_text()},
            },
        }
    r["WebhookApi"] = {
        "Type": "AWS::ApiGatewayV2::Api",
        "Properties": {
            "Name": sub("${AWS::StackName}-webhook"),
            "ProtocolType": "HTTP",
        },
    }
    r["WebhookIntegration"] = {
        "Type": "AWS::ApiGatewayV2::Integration",
        "Properties": {
            "ApiId": ref("WebhookApi"),
            "IntegrationType": "AWS_PROXY",
            "IntegrationUri": arn("TransferFunction"),
            "PayloadFormatVersion": "2.0",
            "TimeoutInMillis": 29000,
        },
    }
    r["WebhookRoute"] = {
        "Type": "AWS::ApiGatewayV2::Route",
        "Properties": {
            "ApiId": ref("WebhookApi"),
            "RouteKey": "POST /transfer",
            "Target": {"Fn::Join": ["/", ["integrations", ref("WebhookIntegration")]]},
        },
    }
    r["WebhookStage"] = {
        "Type": "AWS::ApiGatewayV2::Stage",
        "Properties": {
            "ApiId": ref("WebhookApi"),
            "StageName": "$default",
            "AutoDeploy": True,
            "DefaultRouteSettings": {
                "ThrottlingBurstLimit": 10,
                "ThrottlingRateLimit": 5,
            },
        },
    }
    r["WebhookPermission"] = {
        "Type": "AWS::Lambda::Permission",
        "Properties": {
            "Action": "lambda:InvokeFunction",
            "FunctionName": ref("TransferFunction"),
            "Principal": "apigateway.amazonaws.com",
            "SourceArn": sub(
                "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${WebhookApi}/*/POST/transfer"
            ),
        },
    }
    if c["mode"] == "correlation-id":
        r["LookupAssociation"] = {
            "Type": "AWS::Connect::IntegrationAssociation",
            "Properties": {
                "InstanceId": ref("ConnectInstanceArn"),
                "IntegrationType": "LAMBDA_FUNCTION",
                "IntegrationArn": arn("LookupFunction"),
            },
        }
        r["LookupPermission"] = {
            "Type": "AWS::Lambda::Permission",
            "Properties": {
                "Action": "lambda:InvokeFunction",
                "FunctionName": ref("LookupFunction"),
                "Principal": "connect.amazonaws.com",
                "SourceAccount": ref("AWS::AccountId"),
                "SourceArn": ref("ConnectInstanceArn"),
            },
        }
    r["EntryFlow"] = {
        "Type": "AWS::Connect::ContactFlow",
        "Properties": {
            "InstanceArn": ref("ConnectInstanceArn"),
            "Name": sub("${AWS::StackName}-entry"),
            "Type": "CONTACT_FLOW",
            "State": "ACTIVE",
            "Content": sub(json.dumps(flow(c), separators=(",", ":"))),
        },
    }
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Disposable Bridgefu "
        + c["mode"]
        + " example; customer field contract generated from settings.",
        "Parameters": {
            name: {"Type": "String", "Description": desc}
            for name, desc in {
                "ConnectInstanceArn": "Existing Connect instance ARN in this stack region.",
                "TargetContactFlowArn": "Published flow in that same instance to receive the handoff.",
                "VapiApiKeySecretArn": "Secrets Manager ARN whose plaintext value is the Vapi private key.",
                "GatewaySipUri": "Fixed Bridgefu SIP address, including TLS transport.",
            }.items()
        },
        "Resources": r,
        "Outputs": {
            "WebhookUrl": {
                "Value": sub(
                    "https://${WebhookApi}.execute-api.${AWS::Region}.${AWS::URLSuffix}/transfer"
                )
            },
            "WebhookSecretArn": {"Value": ref("WebhookSecret")},
            "EntryContactFlowArn": {"Value": ref("EntryFlow")},
            "TransferFunctionName": {"Value": ref("TransferFunction")},
            **(
                {
                    "LookupFunctionName": {"Value": ref("LookupFunction")},
                    "ContextTableName": {"Value": ref("ContextTable")},
                }
                if c["mode"] == "correlation-id"
                else {}
            ),
        },
    }


def variable_examples(config):
    """Use the same nested paths in call input that values_for reads at transfer."""
    result = {}
    for field in config["fields"]:
        if not field["source"].startswith("variables."):
            continue
        parts = field["source"].split(".")[1:]
        target = result
        for part in parts[:-1]:
            target = target.setdefault(part, {})
            if not isinstance(target, dict):
                raise ValueError("Conflicting variable paths")
        value = field.get("example", "synthetic-example")
        if parts[-1] in target and target[parts[-1]] != value:
            raise ValueError("Conflicting variable examples")
        target[parts[-1]] = value
    return result


def render(c, out):
    runtime = validate(c)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    write_json = lambda path, data: write(out / path, json.dumps(data, indent=2) + "\n")
    fields = c["fields"] if c["mode"] == "sip-headers" else [c["correlation"]]
    mapping = {f["header"]: f["attribute"] for f in fields}
    recipe_name = "vapi-connect-" + c["mode"]
    recipe = {
        "api_version": "bridgefu.dev/recipe/v1",
        "kind": "bridge_recipe",
        "metadata": {
            "name": recipe_name,
            "version": 1,
            "title": "Vapi to Connect: " + c["mode"],
            "support": "custom",
        },
        "inputs": {
            "signaling_cidrs": {"type": "cidr_list", "required": True},
            "connect_instance_arn": {"type": "aws_arn", "required": True},
            "contact_flow_id": {"type": "aws_connect_resource_id", "required": True},
            "sip_security": {
                "type": "enum",
                "values": ["sips_srtp", "sips_optional_srtp"],
                "default": "sips_srtp",
            },
        },
        "spec": {
            "bridges": {
                "handoff": {
                    "source": {
                        "type": "sip",
                        "security": {"$input": "sip_security"},
                        "admission": {
                            "mode": "stable_uri",
                            "uri_user": c["sip_user"],
                            "trusted_cidrs": {"$input": "signaling_cidrs"},
                        },
                    },
                    "destination": {
                        "type": "amazon_connect",
                        "media": "webrtc",
                        "instance_arn": {"$input": "connect_instance_arn"},
                        "contact_flow_id": {"$input": "contact_flow_id"},
                        "context_metadata_keys": list(mapping.values()),
                    },
                }
            }
        },
    }
    write(out / "recipe/recipe.yaml", yaml.safe_dump(recipe, sort_keys=False))
    gateway = {
        "config_version": 1,
        "aws": {"region": c["region"]},
        "edge": {
            "public_host": c["sip_host"],
            "media_public_addr": c["media_public_ip"] + ":0",
            "sip_tls": {
                "bind": "0.0.0.0:5061",
                "advertised_addr": c["media_public_ip"] + ":5061",
                "certificate_chain": "/run/bridgefu/tls/fullchain.pem",
                "private_key": "env:BRIDGEFU_SIP_TLS_PRIVATE_KEY_PATH",
            },
        },
        "api": {
            "enabled": True,
            "bearer_token": "env:BRIDGEFU_API_BEARER_TOKEN",
            "control_hmac_key": "env:BRIDGEFU_CONTROL_HMAC_KEY",
        },
        "recipe_catalog": {"paths": [str(out / "recipe")]},
        "recipes": {
            "support": {
                "use": "external:" + recipe_name + "@1",
                "with": {
                    "signaling_cidrs": c["signaling_cidrs"],
                    "connect_instance_arn": c["connect_instance_arn"],
                    "contact_flow_id": c["entry_contact_flow_id"],
                    "sip_security": c["sip_security"],
                },
            }
        },
        "context": {"allow_headers": mapping},
        "persistence": {
            "backend": "sqlite",
            "database_url": "sqlite:///var/lib/bridgefu/bridgefu.db",
        },
        "observability": {
            "log_level": "info",
            "log_format": "json",
            "http_bind": "127.0.0.1:9090",
        },
        "runtime": {
            "mode": "all-in-one",
            "max_concurrent_calls": 10,
            "setup_timeout_secs": 30,
            "media_idle_timeout_secs": 120,
            "drain_timeout_secs": 30,
        },
    }
    write(out / "bridgefu.example.yaml", yaml.safe_dump(gateway, sort_keys=False))
    args = [f for f in c["fields"] if f["source"].startswith("arguments.")]
    tool = {
        "type": "function",
        "async": False,
        "function": {
            "name": c["tool_name"],
            "description": "Transfer this caller to a human with the configured handoff context.",
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    f["name"]: {
                        "type": "string",
                        "maxLength": f["max_bytes"],
                        "description": f["description"],
                    }
                    for f in args
                },
                "required": [f["name"] for f in args if f.get("required", True)],
            },
        },
        "server": {
            "url": "https://WEBHOOK_HOST/transfer",
            "timeoutSeconds": 25,
            "headers": {"X-Bridgefu-Webhook-Secret": "REPLACE_FROM_STACK_SECRET"},
        },
    }
    assistant = {
        "name": "Bridgefu " + c["mode"] + " example",
        "firstMessage": "Hello. How can I help you today?",
        "model": {
            "provider": c["model_provider"],
            "model": c["model"],
            "messages": [
                {
                    "role": "system",
                    "content": c["system_prompt"]
                    + " When transferring, call "
                    + c["tool_name"]
                    + " once. Supply only its declared conversation fields, using short, factual, single-line text. IDs and input variables are supplied by the server. Never invent them. A successful tool result means transfer requested, not agent answered. If it fails, continue helping; do not retry automatically.",
                }
            ],
            "tools": [tool],
        },
        "voice": {"provider": c["voice_provider"], "voiceId": c["voice_id"]},
        "artifactPlan": {"recordingEnabled": False},
        "keypadInputPlan": {"enabled": False},
    }
    write_json("vapi/assistant.json", assistant)
    write_json("vapi/transfer-tool.json", tool)
    variables = variable_examples(c)
    write_json(
        "vapi/call.example.json",
        {
            "assistantId": "REPLACE_WITH_NEW_ASSISTANT_ID",
            "phoneNumberId": "REPLACE_WITH_NONPRODUCTION_PHONE_NUMBER_ID",
            "customer": {"number": "+12025550123"},
            "assistantOverrides": {"variableValues": variables},
        },
    )
    write_json("amazon-connect/contact-flow.json", flow(c))
    write(
        out / "amazon-connect/cloudformation.yaml",
        yaml.dump(
            template(c, runtime), Dumper=NoAliasDumper, sort_keys=False, width=110
        ),
    )
    subdirs = (
        ["transfer"]
        if c["mode"] == "sip-headers"
        else ["prepare-transfer", "resolve-context"]
    )
    for subdir in subdirs:
        write(
            out / ("lambda/" + subdir + "/handler.py"),
            (ROOT / "shared/handler.py").read_text(),
        )
    return gateway


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--settings", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    render(json.loads(a.settings.read_text()), a.output)
    print("Rendered example. Keep filled-in settings and outputs private.")
