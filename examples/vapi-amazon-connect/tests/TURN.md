# Test Connect TURN with direct media blocked

This test uses the same real Vapi assistant, SIP caller, header mappings and
Connect browser agent as [the existing end-to-end test](E2E.md). It adds a
firewall and requires `ice_servers: []` on Bridgefu.

The firewall applies to the **Connect UDP socket range** on the disposable
Linux gateway. It permits only the configured relay CIDRs and destination
port, rejects every other IPv4 destination from those sockets, and rejects
IPv6 from that range. SIP traffic and HTTPS/WSS control traffic are unchanged.
This isolates the customer's media-egress constraint; it is not a claim that
the whole host has a destination allowlist. The bootstrap security group alone
is deliberately not used as proof of restricted egress.

## 1. Provision the test environment

Follow steps 1 and 2 of [E2E.md](E2E.md) from this candidate checkout. Use a new,
private state directory. Wait until provisioning reports that the synthetic
speech, SIP peer and inbound selectors are ready.

## 2. Choose the allowed relay network

Copy the example and review it against
[AWS's current published network requirements](https://docs.aws.amazon.com/chime-sdk/latest/dg/network-config.html):

```sh
cp examples/vapi-amazon-connect/tests/restricted-egress.example.json \
  examples/vapi-amazon-connect/.local/live/network.json
```

The CIDRs, relay port, local Connect port range and timeouts are editable. The
example uses Connect ports 42000–42031, separate from the test caller's
40000–40031 ports. Do not overlap the two ranges.

## 3. Run the three cases sequentially

Run from the repository root:

```sh
for SOURCE in auto join_ack disabled; do
  python3 examples/vapi-amazon-connect/tests/restricted_egress.py \
    --state examples/vapi-amazon-connect/.local/live/state.json \
    --network-settings examples/vapi-amazon-connect/.local/live/network.json \
    --mode sip-headers --source "$SOURCE" || break
done
```

Each case temporarily installs the chosen credential-source mode, explicit
empty static ICE servers, and the firewall before making the call. The first
case exercises automatic selection; the second requires credentials from
Chime `JOIN_ACK`, matching the current SDK. The last disables Connect relay provisioning and **must fail to
connect while the firewall rejects direct ICE packets**. A failed call alone
is insufficient to pass the negative control.

Successful positive cases must also show:

- Actual context/attribute equality and audio markers in both directions,
  checked by the existing runner.
- A selected local `relay` candidate and an allocated TURN transport.
- Packets accepted by the relay firewall rules and zero packets rejected.
- Normal contact teardown and the existing zero-active-call cleanup checks.

The helper restores the generated configuration, stops this test service, and
removes only its own firewall chains after each case. It does not change
customer resources outside the recorded disposable test host.

### Optional legacy URL diagnostic

`TurnControlUrl` is unused by the current Chime SDK. To check an older endpoint,
run the same command once with `--source turn_control_url`. This forces HTTP
credential retrieval; it never silently switches to JOIN_ACK. Our sandbox
rejected the legacy request with HTTP 400 `UnknownOperationException`. Treat
that result as a failed diagnostic, not a passed relay/media test. The current
Connect recipe uses the two signaling-based modes above.

## 4. Keep only the safe report

`restricted-auto-report.json`, `restricted-join_ack-report.json`, and
`restricted-disabled-report.json` contain booleans, counters, and the test
scope. Inspect them before sharing. Resource IDs, credentials, raw signaling,
contact records and browser logs remain in the private state/run directories.
Never upload that entire directory.

## 5. Clean up

```sh
python3 examples/vapi-amazon-connect/tests/live.py cleanup \
  --state examples/vapi-amazon-connect/.local/live/state.json
```

Run cleanup even if qualification fails. Keep the private journal until it
reports success. No live result is implied merely by the presence of this
runbook; the candidate's result report records what actually ran.

## Recorded qualification: November 25, 2026 — merged main

A fresh disposable environment built merged main
`85527e2313776886e53dba606384945c9074271d`, with merged rvoip
`529293064953c94c0b021c43e46d03d878922d0c`. Every uploaded source file was
tracked and matched that commit. The installed binary's SHA-256 and the
[redacted machine-readable results](turn-results.json) identify this run.

This main revision still reports version `0.9.1`; it contains the merged TURN
implementation. The 0.9.2 release preparation changes version metadata,
documentation, and evidence, with no production-code or dependency-pin change.
It does not represent a second live run of the version-bumped binary.

Every case used `ice_servers: []` with direct Connect UDP blocked. The first
three commands are exactly the sequence above. The fourth also validated the
optional correlation-ID recipe using the same runner with
`--mode correlation-id --source auto`. Preserve each case's report before
reusing a source mode, because its `restricted-<source>-report.json` filename
is reused. The committed report combines the per-case assertion snapshots.

| Recipe / credential source | Result | Allowed relay packets | Blocked direct packets |
| --- | --- | ---: | ---: |
| SIP headers / `auto` | Two-way audio and exact context passed | 538 | 0 |
| SIP headers / `join_ack` | Two-way audio and exact context passed | 638 | 0 |
| SIP headers / `disabled` | Failed as required; negative control passed | 0 | 16 |
| Correlation ID / `auto` | Two-way audio and exact context passed | 844 | 0 |

All three successful calls selected a relay, preserved the configured
customer fields, passed generated audio probes in both directions, and ended
with zero active calls, reserved capacity, or unreleased assignments. The
correlation-ID case also passed deployed missing-token and expired-token checks.
The disabled case allocated no relay and failed with observed firewall rejects.

Each case stopped its test service and removed its firewall rules. The final
cleanup audit confirmed deletion of the six disposable stacks, Connect instance,
gateway volumes, public address, DNS records, artifact bucket, secrets, Vapi
assistants and SIP entries, and recording/transcript/analysis data for the ended
test calls. It also verified that no test Lambda log groups remained and the
gateway was terminated. Vapi retains historical operational call metadata;
this audit does not claim to erase all provider history. See the
[complete cleanup steps](E2E.md#5-remove-the-disposable-environment).

This run did not repeat the forced legacy URL diagnostic. Its earlier failed
result remains documented below. The scope remains one Linux ARM64 gateway,
Connect UDP media egress, and one AWS region; SIP and HTTPS/WSS control traffic
were available throughout.

## Historical qualification: November 24, 2026

The sandbox was provisioned during implementation; the committed candidate
was then built with `cargo build --locked --release` and installed before
these calls. Normal reproduction builds your candidate checkout during
provisioning.

Both successful cases used real Vapi and Amazon Connect calls, with
`ice_servers: []` and direct Connect UDP blocked. See the
[historical machine-readable results](turn-results-2026-11-24.json).

| Credential source | Call result | Allowed relay packets | Blocked direct packets | Qualification |
| --- | --- | ---: | ---: | --- |
| `auto` | Two-way audio and context checks passed | 604 | 0 | Passed |
| `join_ack` | Two-way audio and context checks passed | 645 | 0 | Passed |
| `disabled` | Failed to connect, as required | 0 | 16 | Negative control passed |

Both successful calls selected a relay candidate, preserved all configured
customer attributes, disconnected normally, and left zero active calls,
reserved capacity, or unreleased assignments. Each case stopped the test
service and restored its firewall rules. The disposable AWS and Vapi resources
were removed after qualification.

The forced `turn_control_url` call failed and allocated no relay. Separate
HTTP probes, including the old SDK version parameters, received HTTP 400
`UnknownOperationException`; their contacts were stopped. This legacy option
is not qualified for this deployment. The current SDK's JOIN_ACK path is the
validated recipe.

This is a Connect-media egress test on one disposable Linux ARM64 gateway.
It does not qualify TURN over TCP/TLS, a whole-host HTTPS destination allowlist,
long-duration credential replacement, or every AWS region. Packet counts and
call durations will vary on another run.
