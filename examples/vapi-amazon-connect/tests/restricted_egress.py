#!/usr/bin/env python3
"""Reproduce Connect TURN with direct media denied. Uses only a journaled test host."""
import argparse
import copy
import ipaddress
import json
from pathlib import Path
import shlex
import time
from types import SimpleNamespace
import yaml

from live import command, save, session
import run_case

CHAIN = "BRIDGEFU_CONNECT_TEST"


def validate(settings):
    if not settings["relay_cidrs"] or len(settings["relay_cidrs"]) > 32:
        raise ValueError("Configure 1-32 relay CIDRs")
    for cidr in settings["relay_cidrs"]:
        network = ipaddress.ip_network(cidr, strict=True)
        if network.version != 4 or network.prefixlen == 0:
            raise ValueError("Use specific IPv4 relay CIDRs")
    for key in ("relay_port", "udp_port_start", "udp_port_end"):
        if type(settings[key]) is not int or not 1 <= settings[key] <= 65535:
            raise ValueError("Invalid UDP port")
    if settings["udp_port_start"] > settings["udp_port_end"]:
        raise ValueError("Reversed UDP range")
    if settings["udp_port_start"] < 32768:
        raise ValueError("Keep test Connect ports separate from the SIP media range")
    if settings["udp_port_start"] <= 40031 and settings["udp_port_end"] >= 40000:
        raise ValueError("Connect ports must not overlap the synthetic SIP caller's 40000-40031 range")
    for key in ("gather_timeout_secs", "connection_timeout_secs", "turn_attempt_timeout_secs", "turn_send_timeout_secs", "turn_close_timeout_secs", "request_timeout_secs"):
        if type(settings[key]) is not int or not 1 <= settings[key] <= 60:
            raise ValueError("Invalid timeout")
    if settings["connection_timeout_secs"] < settings["gather_timeout_secs"]:
        raise ValueError("Connection timeout must cover gathering")
    return settings


def firewall_script(settings, action):
    """Only the configured Connect UDP source ports enter this fail-closed chain."""
    ports = f'{settings["udp_port_start"]}:{settings["udp_port_end"]}'
    hook = f"-p udp --sport {ports} -j {CHAIN}"
    # Also cover a future IPv6 socket; this fixture uses IPv4 TURN only.
    remove = f"""iptables -D OUTPUT {hook} 2>/dev/null || true
iptables -F {CHAIN} 2>/dev/null || true
iptables -X {CHAIN} 2>/dev/null || true
ip6tables -D OUTPUT {hook} 2>/dev/null || true
ip6tables -F {CHAIN} 2>/dev/null || true
ip6tables -X {CHAIN} 2>/dev/null || true
"""
    if action == "remove":
        return remove
    rules = ["set -eu", remove, f"iptables -N {CHAIN}"]
    for cidr in settings["relay_cidrs"]:
        rules.append(f'iptables -A {CHAIN} -d {shlex.quote(cidr)} -p udp --dport {settings["relay_port"]} -j ACCEPT')
    rules += [f"iptables -A {CHAIN} -j REJECT", f"iptables -I OUTPUT 1 {hook}", f"ip6tables -N {CHAIN}", f"ip6tables -A {CHAIN} -j REJECT", f"ip6tables -I OUTPUT 1 {hook}"]
    return "\n".join(rules)


def apply_config(config, settings, source):
    config = copy.deepcopy(config)
    config.setdefault("aws", {})["turn"] = {
        "credential_source": source,
        "relay_only": source != "disabled",
        "request_timeout_secs": settings["request_timeout_secs"],
        "control_allowed_hosts": settings["control_allowed_hosts"],
    }
    webrtc = config.setdefault("generic_bridge", {}).setdefault("webrtc", {})
    webrtc.update({
        "ice_servers": [],
        "ice_transport_policy": "all",
        "udp_port_range": {"bind_ip": "0.0.0.0", "port_start": settings["udp_port_start"], "port_end": settings["udp_port_end"]},
        "trickle_ice": False,
    })
    for key in ("gather_timeout_secs", "connection_timeout_secs", "turn_attempt_timeout_secs", "turn_send_timeout_secs", "turn_close_timeout_secs"):
        webrtc[key] = settings[key]
    # This is a test installation setting; it does not alter an application's
    # route fields or the assistant/customer context mapping.
    return config


def counters(state):
    output = command(state, f"iptables -L {CHAIN} -n -v -x")
    totals = {"accepted": 0, "rejected": 0}
    for line in output.splitlines():
        columns = line.split()
        if len(columns) >= 3 and columns[0].isdigit():
            if columns[2] == "ACCEPT":
                totals["accepted"] += int(columns[0])
            if columns[2] == "REJECT":
                totals["rejected"] += int(columns[0])
    return totals


def run(args):
    state = json.loads(args.state.read_text())
    if state.get("cleaned_up"):
        raise ValueError("This sandbox has already been removed")
    if session(state).client("sts").get_caller_identity()["Account"] != state["account_id"]:
        raise ValueError("AWS account differs from the sandbox journal")
    settings = validate(json.loads(args.network_settings.read_text()))
    mode_state = json.loads((args.state.parent / (args.mode + "-state.json")).read_text())
    rendered = Path(mode_state["rendered"]) / "bridgefu.example.yaml"
    original = rendered.read_text()
    configured = apply_config(yaml.safe_load(original), settings, args.source)
    report = {
        "schema": "bridgefu.connect-turn.restricted.v1",
        "credential_source": args.source,
        "ice_servers_empty": True,
        "relay_only": args.source != "disabled",
        "firewall_scope": "Connect UDP source port range; SIP and HTTPS control unchanged",
        "passed": False,
    }
    error = None
    started = int(time.time())
    try:
        rendered.write_text(yaml.safe_dump(configured, sort_keys=False))
        command(state, firewall_script(settings, "apply"))
        try:
            run_case.run(SimpleNamespace(state=args.state, mode=args.mode))
            call_passed = True
        except Exception as exc:
            # Raw logs and IDs remain in the private run directory.
            error = type(exc).__name__
            call_passed = False
        report["firewall"] = counters(state)
        # SSM caps command output. Filter on the host so startup/call logging
        # cannot truncate the later relay-selection evidence.
        journal = command(
            state,
            f"journalctl -u bridgefu --since @{started} --no-pager -o cat "
            "| grep -E 'TURN UDP allocation established|Connect ICE selected candidate pair' || true",
            timeout=30,
        )
        report["selected_relay"] = 'local_candidate_type="relay"' in journal or '"local_candidate_type":"relay"' in journal
        report["turn_allocated"] = "TURN UDP allocation established" in journal
        report["call_passed"] = call_passed
        if args.source == "disabled":
            report["passed"] = not call_passed and report["firewall"]["rejected"] > 0 and not report["selected_relay"] and not report["turn_allocated"]
        else:
            report["passed"] = call_passed and report["selected_relay"] and report["turn_allocated"] and report["firewall"]["accepted"] > 0 and report["firewall"]["rejected"] == 0
        if error:
            report["runner_error_class"] = error
    finally:
        rendered.write_text(original)
        # Stop only this disposable test service and remove only our own chain.
        command(state, "systemctl stop bridgefu\n" + firewall_script(settings, "remove"))
        report["test_service_stopped"] = True
        report["firewall_restored"] = True
        save(args.state.parent / ("restricted-" + args.source + "-report.json"), report)
    print(json.dumps(report, indent=2), flush=True)
    if not report["passed"]:
        raise SystemExit("Restricted-egress assertions failed; inspect private evidence")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--network-settings", type=Path, required=True)
    parser.add_argument("--mode", choices=["sip-headers", "correlation-id"], default="sip-headers")
    parser.add_argument("--source", choices=["turn_control_url", "join_ack", "auto", "disabled"], required=True)
    run(parser.parse_args())
