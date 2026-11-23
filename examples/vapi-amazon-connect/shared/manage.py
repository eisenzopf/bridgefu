#!/usr/bin/env python3
"""Deploy or remove only the resources journaled by this example invocation."""

import argparse
import json
import os
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request
import boto3
from render import render, validate


def vapi(method, path, body=None):
    req = urllib.request.Request(
        "https://api.vapi.ai" + path,
        method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={
            "Authorization": "Bearer " + os.environ["VAPI_PRIVATE_KEY"],
            "Content-Type": "application/json",
            "User-Agent": "bridgefu-examples/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        payload = response.read()
        return json.loads(payload) if payload else {}


def save(path, state):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(state, indent=2) + "\n")
    path.chmod(0o600)


def wait_stack(cf, name, deleting=False):
    previous = None
    while True:
        try:
            stack = cf.describe_stacks(StackName=name)["Stacks"][0]
        except cf.exceptions.ClientError as e:
            if deleting and "does not exist" in e.response["Error"].get("Message", ""):
                return {}
            raise
        status = stack["StackStatus"]
        if status != previous:
            print("CloudFormation:", status, flush=True)
            previous = status
        if status in ("CREATE_COMPLETE", "UPDATE_COMPLETE") and not deleting:
            return {x["OutputKey"]: x["OutputValue"] for x in stack.get("Outputs", [])}
        if status.endswith("_FAILED") or status.startswith("ROLLBACK"):
            raise RuntimeError("stack_failed_check_private_aws_console")
        time.sleep(5)


def deploy(a):
    if a.state.exists():
        raise ValueError(
            "State file exists; use a new name or clean up its deployment first"
        )
    c = json.loads(a.settings.read_text())
    validate(c)
    session = boto3.Session(profile_name=a.profile, region_name=c["region"])
    identity = session.client("sts").get_caller_identity()
    if (
        ":connect:" + c["region"] + ":" + identity["Account"] + ":instance/"
        not in a.instance_arn
    ):
        raise ValueError(
            "Connect instance must belong to the selected account and region"
        )
    if not a.target_flow_arn.startswith(a.instance_arn + "/contact-flow/"):
        raise ValueError("Target flow must belong to the selected instance")
    connect = session.client("connect")
    target = connect.describe_contact_flow(
        InstanceId=a.instance_arn, ContactFlowId=a.target_flow_arn
    )["ContactFlow"]
    if target.get("Status") != "PUBLISHED" or target.get("State") != "ACTIVE":
        raise ValueError("Target flow must be active and published")
    c["connect_instance_arn"] = a.instance_arn
    output = a.state.parent / (a.name + "-rendered")
    render(c, output)
    state = {
        "schema": 1,
        "name": a.name,
        "profile": a.profile,
        "region": c["region"],
        "account_id": identity["Account"],
        "mode": c["mode"],
        "rendered": str(output),
        "resources": {},
    }
    save(a.state, state)
    sm = session.client("secretsmanager")
    secret = sm.create_secret(
        Name=a.name + "-vapi",
        SecretString=os.environ["VAPI_PRIVATE_KEY"],
        Tags=[{"Key": "Project", "Value": "bridgefu-examples"}],
    )["ARN"]
    state["resources"]["vapi_secret_arn"] = secret
    save(a.state, state)
    uri = "sips:" + c["sip_user"] + "@" + c["sip_host"] + ":5061;transport=tls"
    cf = session.client("cloudformation")
    # Save ownership intent before mutation so interrupted creates can be removed.
    state["resources"]["stack_name"] = a.name
    save(a.state, state)
    cf.create_stack(
        StackName=a.name,
        TemplateBody=(output / "amazon-connect/cloudformation.yaml").read_text(),
        Capabilities=["CAPABILITY_IAM"],
        Parameters=[
            {"ParameterKey": k, "ParameterValue": v}
            for k, v in {
                "ConnectInstanceArn": a.instance_arn,
                "TargetContactFlowArn": a.target_flow_arn,
                "VapiApiKeySecretArn": secret,
                "GatewaySipUri": uri,
            }.items()
        ],
        Tags=[{"Key": "Project", "Value": "bridgefu-examples"}],
    )
    outputs = wait_stack(cf, a.name)
    state["outputs"] = outputs
    save(a.state, state)
    c["entry_contact_flow_id"] = outputs["EntryContactFlowArn"].rsplit("/", 1)[-1]
    render(c, output)
    assistant = json.loads((output / "vapi/assistant.json").read_text())
    assistant["name"] = a.name
    assistant["model"]["tools"][0]["server"]["url"] = outputs["WebhookUrl"]
    assistant["model"]["tools"][0]["server"]["headers"]["X-Bridgefu-Webhook-Secret"] = (
        sm.get_secret_value(SecretId=outputs["WebhookSecretArn"])["SecretString"]
    )
    # Never write the expanded assistant definition (it contains the webhook secret).
    created = vapi("POST", "/assistant", assistant)
    state["resources"]["assistant_id"] = created["id"]
    save(a.state, state)
    print(
        "Deployment and new Vapi assistant created. Private state saved; no existing assistant was changed."
    )
    print(
        "Install the rendered bridgefu.example.yaml and recipe/ on your gateway; see the README."
    )


def cleanup(a):
    state = json.loads(a.state.read_text())
    session = boto3.Session(profile_name=state["profile"], region_name=state["region"])
    if session.client("sts").get_caller_identity()["Account"] != state["account_id"]:
        raise ValueError("Cleanup account does not match the recorded deployment")
    resources = state["resources"]
    # The optional temporary SIP entry is owned only if recorded by the test runner.
    for key, endpoint in [("phone_id", "phone-number"), ("assistant_id", "assistant")]:
        if key in resources:
            try:
                vapi("DELETE", "/" + endpoint + "/" + resources[key])
            except urllib.error.HTTPError as e:
                if e.code != 404:
                    raise
            del resources[key]
            save(a.state, state)
    if "stack_name" in resources:
        cf = session.client("cloudformation")
        cf.delete_stack(StackName=resources["stack_name"])
        wait_stack(cf, resources["stack_name"], deleting=True)
        del resources["stack_name"]
        save(a.state, state)
    if "vapi_secret_arn" in resources:
        session.client("secretsmanager").delete_secret(
            SecretId=resources["vapi_secret_arn"], ForceDeleteWithoutRecovery=True
        )
        del resources["vapi_secret_arn"]
        save(a.state, state)
    print(
        "Recorded example resources removed. Existing Connect instance, target flow, and gateway were retained."
    )


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    d = sub.add_parser("deploy")
    d.add_argument("--settings", type=Path, required=True)
    d.add_argument("--profile", required=True)
    d.add_argument("--name", required=True)
    d.add_argument("--instance-arn", required=True)
    d.add_argument("--target-flow-arn", required=True)
    d.add_argument("--state", type=Path, required=True)
    cl = sub.add_parser("cleanup")
    cl.add_argument("--state", type=Path, required=True)
    a = p.parse_args()
    try:
        if not os.environ.get("VAPI_PRIVATE_KEY"):
            raise ValueError("Set VAPI_PRIVATE_KEY in your environment")
        deploy(a) if a.command == "deploy" else cleanup(a)
    except Exception as e:
        # Do not print arbitrary API response bodies, which may contain identifiers or credentials.
        print(
            "Operation failed:",
            type(e).__name__,
            "; keep the private state file for recovery.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
