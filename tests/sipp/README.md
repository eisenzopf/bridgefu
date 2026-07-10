# Testing the gateway with SIPp

A [SIPp](https://sipp.sourceforge.net/) scenario that stands in for Vapi: it
sends an `INVITE` carrying the custom `X-` headers, negotiates G.711 audio,
streams a canned clip, holds the call, then hangs up. Use it to validate the
gateway end-to-end **without** waiting on Vapi.

What this proves vs. doesn't:

- ✅ **FR2/FR3/FR4/FR5** — header→attribute mapping, `StartWebRTCContact`, Chime
  media join + audio bridge, and teardown. Plus the agent **screen pop** and
  **two-way audio** (with an agent answering).
- ❌ **FR6 (carrier header preservation)** — inherently Vapi-specific. *We* set
  the headers here, so this can't tell you whether Vapi's carrier preserves them
  across the REFER. Only a real Vapi call answers that.

`bridgefu_invite.xml` — the scenario. The `X-` header **values** in it are
samples; edit them freely.

---

## Multi-tenant routing scenarios (no media, no AWS needed)

Three signaling-only scenarios validate the CONTRACTS B.4 routing semantics
(R-URI user part → `To:` user part → `default_tenant` → 404). They run anywhere
(laptop included — no RTP round-trip needed) against a config with two tenants,
e.g. `banking` and `retail` on distinct contact flows:

```bash
# Routed by R-URI user part → expect 200; gateway log shows route="banking".
sipp -sf bridgefu_route.xml 127.0.0.1:5060 -s banking -m 1 -d 2000

# Second tenant, distinct flow → route="retail".
sipp -sf bridgefu_route.xml 127.0.0.1:5060 -s retail -m 1 -d 2000

# R-URI user is unknown, To: user matches → still routed (To fallback).
sipp -sf bridgefu_to_fallback.xml 127.0.0.1:5060 -s retail -m 1

# No tenant matches, default_tenant: null → 404 Not Found.
sipp -sf bridgefu_unknown_tenant.xml 127.0.0.1:5060 -s ghost -m 1
```

Then check:

- `curl -s localhost:9090/healthz` → `{"ok":true,"tenants":["banking","retail"]}`
- `curl -s localhost:9090/metrics | grep bridgefu` → per-tenant labels:
  `bridgefu_calls_routed_total{tenant="banking"}`,
  `bridgefu_unknown_tenant_total`, plus `bridgefu_active_sessions` /
  `bridgefu_contacts_started_total` / `bridgefu_failures_total` per tenant.

Without real AWS credentials the routed calls still answer (200) and then fail
at `StartWebRTCContact` — that failure is *expected* off-EC2 and shows up in
`bridgefu_failures_total{tenant=…}`, which is itself part of what the test
validates. On the real bridge host the same runs place real contacts.

---

## Where to run it: ON the EC2 instance (not your laptop)

Run SIPp **on the gateway instance itself**. From your laptop (behind home NAT)
the `INVITE` would arrive fine, but the gateway sends RTP back to the IP your
client advertises in its SDP — a private/NAT address — so audio won't return.
Running on the instance removes NAT entirely.

```bash
ssh -i ~/.ssh/bridgefu ec2-user@35.80.105.73
```

---

## Install SIPp on the instance (Amazon Linux 2023)

`dnf` doesn't ship SIPp, so build it from source (a couple of minutes):

```bash
sudo dnf install -y git gcc-c++ make cmake ncurses-devel libpcap-devel \
                    openssl-devel automake autoconf libtool
# --recurse-submodules is REQUIRED — SIPp vendors pugixml etc. as submodules,
# and a plain/shallow clone omits them (cmake fails with "pugixml is required").
git clone --recurse-submodules https://github.com/SIPp/sipp /opt/sipp
cd /opt/sipp
cmake . -DUSE_PCAP=1 -DUSE_SSL=1
make -j"$(nproc)"
sudo install -m0755 sipp /usr/local/bin/sipp
sipp -v
```

(If you already did a shallow clone and hit the pugixml error, just run
`git -C /opt/sipp submodule update --init --recursive` and re-run cmake/make.)

The bundled audio clip (`pcap/g711a.pcap`) lives in the source tree at
`/opt/sipp/pcap/g711a.pcap` — run SIPp from `/opt/sipp` (or pass an absolute
path) so `play_pcap_audio="pcap/g711a.pcap"` resolves.

Get the scenario onto the box (from the instance):

```bash
# It was already rsynced with the source by deploy.sh:
cp /opt/build/bridgefu/tests/sipp/bridgefu_invite.xml /opt/sipp/
```

---

## Run a single test call

From `/opt/sipp` on the instance:

```bash
cd /opt/sipp
sipp -sf bridgefu_invite.xml 127.0.0.1:5060 \
     -s bridgefu \
     -m 1 \
     -trace_msg -trace_err
```

- `127.0.0.1:5060` — the gateway is on the same host (`--network host`).
- `-s bridgefu` — request-URI user part (the gateway auto-answers regardless).
- `-m 1` — place exactly one call, then exit.
- `-trace_msg` / `-trace_err` — write the SIP exchange + any errors to files.

To change the hold time (default 30 s in the scenario) add `-d 30000`.

---

## What to watch — tail the gateway logs in a second SSH session

```bash
ssh -i ~/.ssh/bridgefu ec2-user@35.80.105.73 'sudo journalctl -u bridgefu -f'
```

A successful run should show, in order (PRD §9.3):

1. `INVITE received` with the inbound headers, **including the `X-` set**
2. `attributes=N` with **N > 0** (the mapped Connect attributes)
3. `StartWebRTCContact` returning a real `contact_id`
4. Chime meeting connected → `bridged`
5. On BYE: clean teardown of both legs (no leaked contacts) — PRD §9.5

`mapping.unmapped: drop` is set, so only the three renamed headers map; you
should see ~3 attributes (`HostedWidget-customerId`, `-vapiCallId`,
`-accountTier`). Debug logging is already on (`info,rvoip_amazon_connect=debug`).

---

## Two tiers of test

**Tier A — gateway logic (no agent needed).** Just run the call and read the
logs. Confirms steps 1–4 above: our headers map correctly and a real contact is
placed with media joining Chime. The agent leg simply won't have anyone on it.

**Tier B — full screen pop + two-way audio (agent required).** First make sure a
Connect agent is **logged in and Available** with the CCP open, on the queue the
`Sample queue customer` flow routes to. Then run the call: the CCP should ring,
the **screen pop should show** `HostedWidget-customerId=CUST-12345` etc., and the
agent should hear the streamed clip (and their audio bridges back). Hang up
(scenario auto-BYEs after the pause) and confirm clean teardown.

---

## Codec note

The scenario offers **PCMA (G.711 A-law, payload 8)** to match the bundled
`g711a.pcap`. Vapi typically uses **PCMU (µ-law)**; the gateway transcodes both
G.711 variants to Opus, so A-law is fine for this bridge test. To mimic PCMU
instead, change the SDP to `m=audio ... RTP/AVP 0 101` / `a=rtpmap:0 PCMU/8000`
and supply a µ-law pcap to `play_pcap_audio`.

---

## Quick reachability pre-check (optional)

The gateway answers `OPTIONS` (auto_options). A fast "is it alive on the wire"
check from the instance:

```bash
sipp -sn uac 127.0.0.1:5060 -m 1 -timeout 5s -trace_err   # expect it to reach INVITE/200 or time out cleanly
```

(For the real test use the `-sf bridgefu_invite.xml` command above — `-sn uac`
does not carry the `X-` headers.)
