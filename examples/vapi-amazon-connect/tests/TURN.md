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
for SOURCE in turn_control_url auto disabled; do
  python3 examples/vapi-amazon-connect/tests/restricted_egress.py \
    --state examples/vapi-amazon-connect/.local/live/state.json \
    --network-settings examples/vapi-amazon-connect/.local/live/network.json \
    --mode sip-headers --source "$SOURCE" || break
done
```

Each case temporarily installs the chosen credential-source mode, explicit
empty static ICE servers, and the firewall before making the call. The first
case exercises `TurnControlUrl`; the second exercises normal automatic
selection. The last disables Connect relay provisioning and **must fail to
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

## 4. Keep only the safe report

`restricted-turn_control_url-report.json`, `restricted-auto-report.json`, and
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
