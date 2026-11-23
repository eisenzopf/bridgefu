#!/usr/bin/env python3
"""Disposable live test. State contains private IDs and secrets; never publish it."""

import argparse
import json
import math
import os
from pathlib import Path
import secrets
import shlex
import struct
import subprocess
import sys
import tarfile
import time
import wave
import boto3
import yaml

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
sys.path.insert(0, str(ROOT / "shared"))
from manage import save, vapi, wait_stack
from render import variable_examples

MODES = [("sip-headers", "headers"), ("correlation-id", "lookup")]


def session(s):
    return boto3.Session(profile_name=s["profile"], region_name=s["region"])


def stack(b, name, template, parameters):
    cf = b.client("cloudformation")
    cf.create_stack(
        StackName=name,
        TemplateBody=template.read_text(),
        Capabilities=["CAPABILITY_IAM"],
        Parameters=[
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ],
        Tags=[{"Key": "Project", "Value": "bridgefu-examples"}],
    )
    return wait_stack(cf, name)


def command(s, script, timeout=60, wait=True):
    client = session(s).client("ssm")
    host = s["gateway_outputs"]["InstanceId"]
    key = client.send_command(
        InstanceIds=[host],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": [script], "executionTimeout": [str(timeout)]},
    )["Command"]["CommandId"]
    if not wait:
        return key
    end = time.monotonic() + timeout + 60
    while time.monotonic() < end:
        time.sleep(2)
        try:
            r = client.get_command_invocation(CommandId=key, InstanceId=host)
        except client.exceptions.InvocationDoesNotExist:
            continue
        if r["Status"] not in ("Pending", "InProgress", "Delayed"):
            if r["Status"] != "Success":
                raise RuntimeError("remote_command_failed_" + key)
            return r["StandardOutputContent"]
    raise TimeoutError("remote_command_timeout")


def upload(s, local, key):
    session(s).client("s3").upload_file(str(local), s["artifact_bucket"], key)


def download_command(s, key, target):
    code = (
        "import boto3; boto3.client('s3').download_file("
        + repr(s["artifact_bucket"])
        + ","
        + repr(key)
        + ","
        + repr(target)
        + ")"
    )
    return "python3 -c " + shlex.quote(code)


def provision(a):
    if a.state.exists():
        raise ValueError("Use a new state path; existing state is never overwritten")
    p = a.state.parent
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    s = {
        "name": a.name,
        "profile": a.profile,
        "region": a.region,
        "stacks": [],
        "vapi": [],
    }
    b = session(s)
    s["account_id"] = b.client("sts").get_caller_identity()["Account"]
    save(a.state, s)
    for suffix, template, params, output in [
        ("connect", "aws-sandbox.yaml", {"DeploymentId": a.name}, "sandbox_outputs"),
        ("gateway", "gateway.yaml", None, "gateway_outputs"),
    ]:
        if params is None:
            s["gateway_hostname"] = a.name + "." + a.zone_name.rstrip(".")
            params = {
                "HostedZoneId": a.zone_id,
                "SipHostname": s["gateway_hostname"],
                "ConnectInstanceArn": s["sandbox_outputs"]["ConnectInstanceArn"],
                "SignalingCidr1": a.signaling_cidr[0],
                "SignalingCidr2": a.signaling_cidr[1],
            }
        name = a.name + "-" + suffix
        s["stacks"].append(name)
        save(a.state, s)
        s[output] = stack(b, name, ROOT / "tests" / template, params)
        save(a.state, s)
    s["artifact_bucket"] = s["gateway_outputs"]["ArtifactBucket"]
    save(a.state, s)
    # Only repository files plus the new public examples; never include .local or ignored credentials.
    tracked = (
        subprocess.check_output(["git", "ls-files", "-z"], cwd=REPO)
        .decode()
        .split("\0")
    )
    examples = (
        subprocess.check_output(
            ["rg", "--files", "examples/vapi-amazon-connect"], cwd=REPO
        )
        .decode()
        .splitlines()
    )
    with tarfile.open(p / "source.tar.gz", "w:gz") as archive:
        for name in sorted(set(tracked + examples)):
            f = REPO / name
            if (
                name
                and f.is_file()
                and ".local" not in f.parts
                and not name.endswith("settings.local.json")
            ):
                archive.add(f, arcname=name)
    upload(s, p / "source.tar.gz", "source.tar.gz")
    print(
        "Sandbox provisioned. The gateway builds this checkout in the background.",
        flush=True,
    )
    # Build readiness is bounded and emits only a stage; remote logs remain private.
    for _ in range(180):
        try:
            if "ready" in command(
                s, "test -f /var/lib/bridgefu/build-ready && echo ready || true"
            ):
                break
        except Exception:
            pass
        time.sleep(10)
    else:
        raise TimeoutError("gateway_build_not_ready_check_private_bootstrap_log")
    for mode, suffix in MODES:
        cfg = json.loads((ROOT / mode / "settings.example.json").read_text())
        cfg.update(
            region=a.region,
            sip_host=s["gateway_hostname"],
            media_public_ip=s["gateway_outputs"]["PublicIp"],
            signaling_cidrs=a.signaling_cidr,
            connect_instance_arn=s["sandbox_outputs"]["ConnectInstanceArn"],
            sip_security=a.sip_security,
        )
        save(p / (mode + "-settings.json"), cfg)
        args = [
            sys.executable,
            str(ROOT / "shared/manage.py"),
            "deploy",
            "--settings",
            str(p / (mode + "-settings.json")),
            "--profile",
            a.profile,
            "--name",
            a.name + "-" + suffix,
            "--instance-arn",
            s["sandbox_outputs"]["ConnectInstanceArn"],
            "--target-flow-arn",
            s["sandbox_outputs"]["TargetContactFlowArn"],
            "--state",
            str(p / (mode + "-state.json")),
        ]
        subprocess.run(args, check=True)
    prepare(a)


def prepare(a):
    s = json.loads(a.state.read_text())
    p = a.state.parent
    b = session(s)
    # Polly produces only synthetic speech and returns raw 8 kHz signed PCM.
    response = b.client("polly").synthesize_speech(
        Text="My doorbell is offline. I already restarted it. Please transfer me to a person for technical support.",
        VoiceId="Joanna",
        OutputFormat="pcm",
        SampleRate="8000",
    )
    (p / "prompt.pcm").write_bytes(response["AudioStream"].read())
    with wave.open(str(p / "agent.wav"), "wb") as w:
        w.setparams((1, 2, 48000, 0, "NONE", "not compressed"))
        w.writeframes(
            b"".join(
                struct.pack(
                    "<h",
                    int(10000 * math.sin(2 * math.pi * 880 * i / 48000))
                    if i % 480000 < 240000
                    else 0,
                )
                for i in range(48000 * 120)
            )
        )
    with tarfile.open(p / "fixtures.tar.gz", "w:gz") as t:
        t.add(
            ROOT / "tests/sip-client",
            arcname="sip-client",
            filter=lambda m: None if "/target/" in m.name else m,
        )
        t.add(p / "prompt.pcm", arcname="prompt.pcm")
    upload(s, p / "fixtures.tar.gz", "fixtures.tar.gz")
    command(
        s,
        download_command(s, "fixtures.tar.gz", "/tmp/fixtures.tar.gz")
        + """
mkdir -p /opt/bridgefu-test
tar -xzf /tmp/fixtures.tar.gz -C /opt/bridgefu-test
cd /opt/bridgefu-test/sip-client
CARGO_TARGET_DIR=/opt/bridgefu-src/target /root/.cargo/bin/cargo build --locked --release -j2 >/var/log/peer-build.log 2>&1
install -m755 /opt/bridgefu-src/target/release/bridgefu-vapi-sip-smoke /usr/local/bin/bridgefu-vapi-sip-smoke
""",
        timeout=1800,
    )
    for mode, _ in MODES:
        f = p / (mode + "-state.json")
        st = json.loads(f.read_text())
        if st.get("test"):
            continue
        cfg = json.loads((p / (mode + "-settings.json")).read_text())
        variables = variable_examples(cfg)
        name = st["name"] + "-input"
        s["stacks"].append(name)
        save(a.state, s)
        out = stack(
            b,
            name,
            ROOT / "tests/inbound.yaml",
            {
                "AssistantId": st["resources"]["assistant_id"],
                "VariablesJson": json.dumps(variables),
            },
        )
        auth = {
            "realm": "sip.vapi.ai",
            "username": secrets.token_hex(12),
            "password": secrets.token_urlsafe(24),
        }
        key = b.client("secretsmanager").get_secret_value(SecretId=out["SecretArn"])[
            "SecretString"
        ]
        phone = vapi(
            "POST",
            "/phone-number",
            {
                "provider": "vapi",
                "name": st["name"],
                "sipUri": "sip:" + st["name"] + "@sip.vapi.ai",
                "authentication": auth,
                "server": {"url": out["Url"], "headers": {"X-Test-Secret": key}},
            },
        )
        st["resources"]["phone_id"] = phone["id"]
        st["test"] = {"sip_uri": phone["sipUri"], "auth": auth}
        save(f, st)
    print("Synthetic speech, SIP peer, and inbound selectors ready.", flush=True)


def install(s, st, p):
    out = Path(st["rendered"])
    work = p / "install"
    work.mkdir(exist_ok=True)
    cfg = yaml.safe_load((out / "bridgefu.example.yaml").read_text())
    cfg["recipe_catalog"]["paths"] = ["/etc/bridgefu/recipe"]
    (work / "bridgefu.yaml").write_text(yaml.safe_dump(cfg))
    (work / "env").write_text(
        "BRIDGEFU_API_BEARER_TOKEN="
        + secrets.token_urlsafe(32)
        + "\nBRIDGEFU_CONTROL_HMAC_KEY="
        + secrets.token_urlsafe(32)
        + "\nBRIDGEFU_SIP_TLS_PRIVATE_KEY_PATH=/run/bridgefu/tls/private-key.pem\nAWS_REGION="
        + s["region"]
        + "\n"
    )
    with tarfile.open(p / "config.tar.gz", "w:gz") as t:
        t.add(work / "bridgefu.yaml", arcname="bridgefu.yaml")
        t.add(work / "env", arcname="env")
        t.add(out / "recipe", arcname="recipe")
    upload(s, p / "config.tar.gz", "config.tar.gz")
    command(
        s,
        download_command(s, "config.tar.gz", "/tmp/config.tar.gz")
        + """
set -eu
mkdir -p /etc/bridgefu
tar -xzf /tmp/config.tar.gz -C /etc/bridgefu
chmod 600 /etc/bridgefu/env
set -a
. /etc/bridgefu/env
set +a
/usr/local/bin/bridgefu --config /etc/bridgefu/bridgefu.yaml validate
cat >/etc/systemd/system/bridgefu.service <<'UNIT'
[Unit]
After=network-online.target
[Service]
EnvironmentFile=/etc/bridgefu/env
ExecStart=/usr/local/bin/bridgefu --config /etc/bridgefu/bridgefu.yaml run
WorkingDirectory=/etc/bridgefu
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl restart bridgefu
sleep 3
systemctl is-active bridgefu
""",
    )


def cleanup(a):
    s = json.loads(a.state.read_text())
    b = session(s)
    if (
        s.get("account_id")
        and b.client("sts").get_caller_identity()["Account"] != s["account_id"]
    ):
        raise ValueError("Cleanup account mismatch")
    for mode, _ in MODES:
        f = a.state.parent / (mode + "-state.json")
        if f.exists():
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "shared/manage.py"),
                    "cleanup",
                    "--state",
                    str(f),
                ],
                check=True,
            )
    # Selectors reference assistants only by strings, so can follow example removal.
    cf = b.client("cloudformation")
    for name in reversed(list(dict.fromkeys(s["stacks"]))):
        if name.endswith("-gateway"):
            client = b.client("s3")
            bucket = s.get("artifact_bucket")
            if bucket:
                for page in client.get_paginator("list_objects_v2").paginate(
                    Bucket=bucket
                ):
                    if page.get("Contents"):
                        client.delete_objects(
                            Bucket=bucket,
                            Delete={
                                "Objects": [{"Key": v["Key"]} for v in page["Contents"]]
                            },
                        )
        cf.delete_stack(StackName=name)
        wait_stack(cf, name, deleting=True)
    s["cleaned_up"] = True
    save(a.state, s)
    print("Disposable resources removed.")


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["provision", "prepare", "run", "cleanup"])
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--profile")
    parser.add_argument("--region", default="us-west-2")
    parser.add_argument("--name")
    parser.add_argument("--zone-id")
    parser.add_argument("--zone-name")
    parser.add_argument("--signaling-cidr", action="append", default=[])
    parser.add_argument(
        "--sip-security",
        choices=["sips_srtp", "sips_optional_srtp"],
        default="sips_optional_srtp",
    )
    parser.add_argument("--mode", choices=[x[0] for x in MODES])
    a = parser.parse_args()
    a.state = a.state.resolve()
    if a.action == "provision" and (
        not all([a.profile, a.name, a.zone_id, a.zone_name])
        or len(a.signaling_cidr) != 2
    ):
        parser.error(
            "provision requires profile, unique name (3-24 characters), public zone ID/name, and two signaling CIDRs"
        )
    if a.action == "run":
        from run_case import run

        run(a)
    else:
        globals()[a.action](a)
