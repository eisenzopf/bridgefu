"""One live scenario, retaining raw evidence privately and publishing only assertions."""

import datetime as dt
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time
import urllib.request
import urllib.parse
from live import ROOT, command, download_command, install, save, session, upload, vapi


def run(a):
    if not a.mode:
        raise ValueError("run requires --mode")
    s = json.loads(a.state.read_text())
    p = a.state.parent
    st = json.loads((p / (a.mode + "-state.json")).read_text())
    cfg = json.loads((p / (a.mode + "-settings.json")).read_text())
    b = session(s)
    connect = b.client("connect")
    instance = s["sandbox_outputs"]["ConnectInstanceArn"]
    case = p / (a.mode + "-run-" + str(int(time.time())))
    case.mkdir(mode=0o700)
    install(s, st, p)
    credential = json.loads(
        b.client("secretsmanager").get_secret_value(
            SecretId=s["sandbox_outputs"]["AgentCredentialSecretArn"]
        )["SecretString"]
    )
    result_path = case / "agent.json"
    credential.update(
        url=s["sandbox_outputs"]["ConnectLoginUrl"],
        audio=str(p / "agent.wav"),
        output=str(result_path),
    )
    agent_log = (case / "agent.log").open("w")
    agent = subprocess.Popen(
        ["node", str(ROOT / "tests/agent.mjs")],
        stdin=subprocess.PIPE,
        stdout=agent_log,
        stderr=agent_log,
        text=True,
        env=dict(os.environ, PLAYWRIGHT_BROWSERS_PATH="0"),
    )
    agent.stdin.write(json.dumps(credential))
    agent.stdin.close()
    call = None
    contact_id = None
    report = {
        "mode": a.mode,
        "date": dt.date.today().isoformat(),
        "passed": False,
        "sip_security_configured": cfg["sip_security"],
    }
    try:
        for _ in range(180):
            if Path(str(result_path) + ".ready").exists():
                break
            if agent.poll() is not None:
                raise RuntimeError("agent_login_failed_check_private_log")
            time.sleep(1)
        else:
            raise TimeoutError("agent_login_timeout")
        users = connect.list_users(InstanceId=instance)["UserSummaryList"]
        user = next(x for x in users if x["Username"] == credential["username"])["Id"]
        statuses = connect.list_agent_statuses(InstanceId=instance)[
            "AgentStatusSummaryList"
        ]
        available = next(x for x in statuses if x["Type"] == "ROUTABLE")["Id"]
        try:
            connect.put_user_status(
                InstanceId=instance, UserId=user, AgentStatusId=available
            )
        except connect.exceptions.InvalidRequestException as error:
            if "already in requested status" not in error.response["Error"].get(
                "Message", ""
            ):
                raise
        print(a.mode + ": agent ready; starting synthetic SIP call", flush=True)
        auth = case / "sip-auth.json"
        save(auth, st["test"]["auth"])
        upload(s, auth, "sip-auth.json")
        remote = "/opt/bridgefu-test/result-" + a.mode + ".json"
        script = (
            download_command(s, "sip-auth.json", "/opt/bridgefu-test/auth.json")
            + "\nchmod 600 /opt/bridgefu-test/auth.json\n"
        )
        script += "rm -f " + shlex.quote(remote) + "\n"
        args = [
            "/usr/local/bin/bridgefu-vapi-sip-smoke",
            "--sip-uri",
            st["test"]["sip_uri"],
            "--prompt-pcm",
            "/opt/bridgefu-test/prompt.pcm",
            "--public-ip",
            s["gateway_outputs"]["PublicIp"],
            "--execution-id",
            "bfq-example-" + str(int(time.time())),
            "--output",
            remote,
            "--timeout-seconds",
            "150",
            "--auth-stdin",
        ]
        script += (
            " ".join(shlex.quote(x) for x in args)
            + " < /opt/bridgefu-test/auth.json > /opt/bridgefu-test/peer.log 2>&1"
        )
        started = time.time()
        key = command(s, script, timeout=200, wait=False)
        ssm = b.client("ssm")
        contact_id = None
        for _ in range(110):
            time.sleep(2)
            # Record the actual routed contact while the source is still connected.
            data = connect.get_current_user_data(
                InstanceId=instance, Filters={"Agents": [user]}
            )
            for item in data.get("UserDataList", []):
                for contact in item.get("Contacts", []):
                    contact_id = contact["ContactId"]
            try:
                r = ssm.get_command_invocation(
                    CommandId=key, InstanceId=s["gateway_outputs"]["InstanceId"]
                )
            except ssm.exceptions.InvocationDoesNotExist:
                continue
            if r["Status"] not in ("Pending", "InProgress", "Delayed"):
                break
        save(case / "ssm-result.json", r)
        raw = command(
            s,
            "cat /opt/bridgefu-test/peer.log; echo '\n---RESULT---'; cat "
            + shlex.quote(remote)
            + " 2>/dev/null || true",
        )
        (case / "peer.txt").write_text(raw)
        if "---RESULT---" in raw and raw.split("---RESULT---", 1)[1].strip():
            peer = json.loads(raw.split("---RESULT---", 1)[1])
            save(case / "peer.json", peer)
        else:
            peer = {}
        # Vapi call records and argument values stay in private evidence.
        calls = vapi(
            "GET", "/call?assistantId=" + st["resources"]["assistant_id"] + "&limit=10"
        )
        if isinstance(calls, dict):
            calls = calls.get("results", calls.get("data", []))
        call = next(
            (
                c
                for c in calls
                if c.get("assistantId") == st["resources"]["assistant_id"]
            ),
            None,
        )
        if call:
            call = vapi("GET", "/call/" + call["id"])
            save(case / "vapi-call.json", call)
        if not contact_id:
            # Terminal contacts may leave the agent before the poll. Read this disposable
            # gateway's durable provider bindings; never use fuzzy account-wide search.
            code = "import sqlite3,json; c=sqlite3.connect('/var/lib/bridgefu/bridgefu.db'); print(json.dumps(c.execute('select reference_kind,reference_value from external_references order by bound_at desc limit 5').fetchall()))"
            refs = json.loads(command(s, "python3 -c " + shlex.quote(code)))
            save(case / "references.json", refs)
            for kind, value in refs:
                try:
                    d = connect.describe_contact(InstanceId=instance, ContactId=value)[
                        "Contact"
                    ]
                    if d["InitiationTimestamp"].timestamp() >= started - 5:
                        contact_id = value
                        break
                except connect.exceptions.ClientError:
                    pass
        if not call or not contact_id:
            raise RuntimeError("call_did_not_reach_connect_check_private_evidence")
        contact = connect.describe_contact(InstanceId=instance, ContactId=contact_id)[
            "Contact"
        ]
        if contact["InitiationTimestamp"].timestamp() < started - 5:
            raise RuntimeError("contact_does_not_belong_to_current_attempt")
        for _ in range(15):
            if contact.get("DisconnectTimestamp"):
                break
            time.sleep(2)
            contact = connect.describe_contact(
                InstanceId=instance, ContactId=contact_id
            )["Contact"]
        save(case / "contact.json", json.loads(json.dumps(contact, default=str)))
        attrs = connect.get_contact_attributes(
            InstanceId=instance,
            InitialContactId=contact.get("InitialContactId", contact_id),
        )["Attributes"]
        save(case / "attributes.json", attrs)
        sql = "select p.body from call_execution_plans p join external_references r on r.call_id=p.call_id where r.reference_value=?"
        code = (
            "import sqlite3,json; c=sqlite3.connect('/var/lib/bridgefu/bridgefu.db'); print(json.dumps(c.execute("
            + repr(sql)
            + ",("
            + repr(contact_id)
            + ",)).fetchall()))"
        )
        plan_rows = json.loads(command(s, "python3 -c " + shlex.quote(code)))
        if len(plan_rows) != 1:
            raise RuntimeError("missing_exact_durable_start_evidence")
        plan = json.loads(plan_rows[0][0])
        save(case / "execution-plan.json", plan)
        initial = plan["plan"]["amazon_connect_starts"][0]["spec"]["attributes"]

        messages = call.get("messages") or call.get("artifact", {}).get("messages", [])
        args = None
        for message in messages:
            for tool in message.get("toolCalls", []):
                f = tool.get("function", {})
                if f.get("name") == cfg["tool_name"]:
                    args = f.get("arguments", {})
                    args = json.loads(args) if isinstance(args, str) else args
        if args is None:
            raise RuntimeError("tool_arguments_not_in_call_evidence")
        sys.path.insert(0, str(ROOT / "shared"))
        from handler import values_for

        expected = values_for(cfg, call, args)
        report["attributes"] = {k: attrs.get(k) == v for k, v in expected.items()}
        report["input_variables"] = {
            field["attribute"]: expected.get(field["attribute"]) == field["example"]
            for field in cfg["fields"]
            if field["source"].startswith("variables.")
        }
        report["input_variables_match"] = all(report["input_variables"].values())

        report["agent_connected"] = bool(
            contact.get("AgentInfo", {}).get("ConnectedToAgentTimestamp")
        )
        report["contact_disconnected"] = bool(contact.get("DisconnectTimestamp"))
        report["source_peer_passed"] = r["Status"] == "Success" and bool(
            peer.get("hangup", {}).get("cleanup_observed")
        )
        audio = json.loads(result_path.read_text())
        report["agent_audio"] = {
            k: audio[k] for k in ("incoming", "outgoing", "dtmfFrames")
        }
        report["source_audio"] = {
            "agent_marker_frames_received": peer.get("media", {}).get(
                "agent_to_source_marker_frames", 0
            ),
            "caller_probe_frames_sent": peer.get("media", {}).get(
                "dtmf_source_to_agent_frames_sent", 0
            ),
        }
        report["bidirectional_audio"] = (
            report["source_peer_passed"]
            and audio["incoming"] > 0
            and audio["outgoing"] > 0
            and audio["dtmfFrames"] >= 3
        )
        if a.mode == "correlation-id":
            report["lookup_found"] = attrs.get(cfg["status_attribute"]) == "found"
            report["token_only_ingress"] = cfg["correlation"][
                "attribute"
            ] in initial and not any(f["attribute"] in initial for f in cfg["fields"])
            # Invoke real deployed lookup for absent and expired context; no raw token in report.
            fn = st["outputs"]["LookupFunctionName"]
            lam = b.client("lambda")

            def lookup(token):
                event = {
                    "Details": {
                        "ContactData": {
                            "InstanceARN": instance,
                            "Attributes": {cfg["correlation"]["attribute"]: token},
                        }
                    }
                }
                response = lam.invoke(
                    FunctionName=fn, Payload=json.dumps(event).encode()
                )
                return json.load(response["Payload"])

            report["missing_token_rejected"] = lookup("") == {
                cfg["status_attribute"]: "missing"
            }
            table = b.resource("dynamodb").Table(st["outputs"]["ContextTableName"])
            token = "0" * 32
            table.put_item(
                Item={
                    "id": token,
                    "expires_at": int(time.time()) - 10,
                    "values": expected,
                }
            )
            report["expired_token_rejected"] = lookup(token) == {
                cfg["status_attribute"]: "expired_or_missing"
            }
            table.delete_item(Key={"id": token})
        else:
            report["no_correlation_attribute"] = (
                cfg["correlation"]["attribute"] not in initial
                and "correlation_id" not in initial
            )
            report["all_fields_in_initial_contact"] = all(
                initial.get(k) == v for k, v in expected.items()
            )
        code = "import sqlite3,json; c=sqlite3.connect('/var/lib/bridgefu/bridgefu.db'); print(json.dumps({'active_calls':c.execute(\"select count(*) from calls where call_state not in ('ended','failed')\").fetchone()[0],'reserved_calls':c.execute('select coalesce(sum(reserved_calls),0) from workers').fetchone()[0],'unreleased_assignments':c.execute('select count(*) from worker_assignments where released_at is null').fetchone()[0]}))"
        cleanup = json.loads(command(s, "python3 -c " + shlex.quote(code)))
        report["gateway_cleanup"] = cleanup
        report["gateway_drained"] = all(value == 0 for value in cleanup.values())
        report["duration_seconds"] = round(time.time() - started, 1)
        gates = [
            "input_variables_match",
            "agent_connected",
            "contact_disconnected",
            "source_peer_passed",
            "bidirectional_audio",
            "gateway_drained",
        ]
        gates += (
            [
                "lookup_found",
                "token_only_ingress",
                "missing_token_rejected",
                "expired_token_rejected",
            ]
            if a.mode == "correlation-id"
            else ["no_correlation_attribute", "all_fields_in_initial_contact"]
        )
        report["passed"] = all(report[k] for k in gates) and all(
            report["attributes"].values()
        )
    finally:
        # A failed media assertion must not leave this owned test call running.
        if not report["passed"]:
            if contact_id:
                try:
                    connect.stop_contact(InstanceId=instance, ContactId=contact_id)
                except Exception:
                    pass
            if call and call.get("status") != "ended":
                url = call.get("monitor", {}).get("controlUrl", "")
                if urllib.parse.urlparse(url).scheme == "https":
                    try:
                        request = urllib.request.Request(
                            url,
                            data=b'{"type":"end-call"}',
                            headers={"Content-Type": "application/json"},
                            method="POST",
                        )
                        urllib.request.urlopen(request, timeout=5).close()
                    except Exception:
                        pass
        Path(str(result_path) + ".stop").touch()
        try:
            agent.wait(timeout=15)
        except subprocess.TimeoutExpired:
            agent.terminate()
            agent.wait(timeout=10)
        save(case / "report.json", report)
        save(p / (a.mode + "-report.json"), report)
        print(
            a.mode
            + ": "
            + ("PASS" if report["passed"] else "FAIL")
            + "; private evidence retained",
            flush=True,
        )
    if not report["passed"]:
        raise RuntimeError("live_assertion_failed")
