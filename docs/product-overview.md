# Bridgefu product overview

Bridgefu is an audio-first call controller and media bridge. It terminates the
protocol on both sides of a call, joins the two media streams, converts audio
when their codecs differ, and owns the lifecycle of both endpoints.

The simplest accurate model is **exactly two logical call legs**:

```text
source leg  <---- audio, DTMF, and allowed context ---->  destination leg
     \_____________________ Bridgefu _______________________/
```

The physical connection behind a logical leg may change. During a handoff,
Bridgefu prepares a new destination connection while retaining the old one as
the resumable current generation. It then either promotes the new connection
and retires the old one, or rejects the attempt and resumes the old connection.
It does not create a three-party audio conference.

This document concentrates on Bridgefu's two intended product workflows:

1. a Vapi call transfers by SIP to Bridgefu and Bridgefu connects it to Amazon
   Connect; and
2. a browser connects directly to Bridgefu by WebRTC, Bridgefu initially calls
   a Vapi SIP assistant, and a trusted backend later replaces that assistant
   with Amazon Connect.

Bridgefu also contains generic SIP/WebRTC routing, Telnyx control, UCTP and
MOQT broadcasts, clustered process roles, and deployment work. Those are real
capabilities, but they are not prerequisites for understanding these two
workflows.

## The actors and their responsibilities

| Actor | Responsibility |
|---|---|
| Browser application | Captures microphone audio, plays remote audio, and presents call and handoff state. |
| Bridgefu browser SDK | Owns one browser `RTCPeerConnection`, WSS signaling, short-lived attachment credentials, DataChannels, DTMF, and client-side cleanup. |
| Application backend | Holds the Bridgefu API credential, creates named-route calls, maps any application handoff token to the correct call and leg, and requests replacement. |
| Vapi | Runs the voice assistant and either transfers a Vapi-managed call to Bridgefu or receives a SIP call from Bridgefu in direct-browser mode. A Vapi tool can notify the application backend that escalation is required. |
| Bridgefu | Authenticates and binds call attachments, owns the two-leg call state, translates media and allowed context, controls replacement, and reconciles teardown. |
| Amazon Connect | Creates the inbound WebRTC contact, runs the configured contact flow, rings the agent, and renders the screen pop from contact attributes. |
| rvoip | Supplies Bridgefu's SIP, RTP, WebRTC, media graph, authentication, and transport implementations through exact crates.io 0.3.7 component packages recorded in `Cargo.lock`. |

## Workflow 1: Vapi SIP transfer to Amazon Connect

In this workflow, Bridgefu is the **target of the transfer**. Vapi or its
carrier performs the transfer and sends Bridgefu a new SIP `INVITE`; Bridgefu
does not need to process the original `REFER` transaction.

```text
caller -> Vapi app -> new SIP INVITE -> Bridgefu -> StartWebRTCContact
                                                    |
                                                    v
                                             Amazon Connect flow
                                                    |
                                                    v
                                               available agent
```

Bridgefu currently offers two forms of this workflow.

### Preserved fixed SIP listener

The original reference-tenant-compatible gateway remains the default
all-in-one path. Its SIP listener uses `sip.port`, which defaults to port 5060.

For each inbound `INVITE`, it:

1. selects a tenant by Request-URI user, then `To` user, then
   `default_tenant`, otherwise rejects the call with `404`;
2. extracts custom SIP headers and applies the configured header-to-contact-
   attribute mapping;
3. answers the inbound SIP call;
4. invokes Amazon Connect `StartWebRTCContact` using the selected instance,
   contact flow, display name, and mapped attributes;
5. joins the returned Amazon Chime WebRTC session;
6. bridges the SIP and Amazon audio, including G.711/Opus conversion; and
7. tears down the peer when either side ends.

The answer-before-originate ordering is intentional compatibility behavior.
It also means the caller can receive a successful SIP answer followed by a
quick hangup if `StartWebRTCContact`, Chime signaling, or Amazon media setup
fails.

The SIP side of this preserved path is plain SIP/RTP. It does not provide SIP
Digest authentication, TLS, or SRTP. Production exposure therefore depends on
carrier/Vapi source restrictions at the firewall or load-balancer boundary.
The legacy Terraform configuration supports source CIDR restrictions, but the
listener itself is not an authentication boundary.

The current implementation logs header and mapped-attribute **counts**, not
raw names or values. This protects credentials and customer context, but it
also means carrier header preservation must be proven with controlled test
evidence rather than by expecting sensitive headers in normal logs.

The relevant implementation starts in
[`src/main.rs`](../src/main.rs),
[`src/config.rs`](../src/config.rs), and the crates.io
`rvoip-amazon-connect` 0.3.7 server implementation pinned by `Cargo.lock`.
Amazon setup is described in
[`amazon-connect.md`](amazon-connect.md).

### Secure named-route SIP attachment

The v1 call engine exposes a safer server-owned route catalog. The application
backend first calls:

```http
POST /v1/routes/{route_id}/calls
Authorization: Bearer <server-side credential>
Idempotency-Key: <unique operation key>
Content-Type: application/json

{
  "ingress": "sip",
  "context": {
    "correlation_id": "application-owned-correlation",
    "metadata": {}
  }
}
```

Bridgefu returns a two-minute, single-use SIPS attachment URI. The application
gives that exact URI to Vapi as the transfer destination. The request cannot
choose an arbitrary SIP target, Amazon instance, contact flow, tenant, call ID,
leg ID, or credential; those all come from the named route and its profiles.

The secure path then:

1. authenticates Vapi using the named ingress profile's trusted CIDR and,
   where configured, Digest or mTLS identity;
2. requires the listener and profile to agree on SIP TLS and mandatory SRTP;
3. consumes the exact attachment once and binds it to the durable inbound leg;
4. starts the server-owned Amazon Connect destination; and
5. answers and promotes the inbound call only when the destination is ready.

This is the preferred public integration when the application can request a
fresh transfer destination before asking Vapi to transfer.

### Choosing between the two SIP paths

| Concern | Fixed listener | Named-route attachment |
|---|---|---|
| Transfer target | Stable SIP address, normally port 5060 | Fresh, two-minute, single-use SIPS URI |
| SIP security | Plain SIP/RTP; network restriction required | TLS plus mandatory SRTP; profile-bound CIDR, Digest, and/or mTLS policy |
| Destination selection | Tenant routing chooses configured Connect target | Server-owned named route and destination profile |
| Call state | Preserved screen-pop server lifecycle | Durable transactional two-leg aggregate |
| Answer timing | Answers before Amazon setup | Attach-then-dial; waits for destination readiness |
| Context source | Mapped headers from the transferred `INVITE` | Sanitized call context plus configured profile policy |
| Intended role | Compatibility and simple fixed-target deployment | Intended v1 production architecture; not yet fully qualified |

### Amazon Connect's role

Bridgefu supplies media and the initial contact attributes. Amazon Connect's
configured contact flow remains responsible for selecting a queue, ringing an
agent, and making those attributes visible in CCP or Agent Workspace. If a
contact starts but the screen pop is empty, the first contract to check is the
mapping between Bridgefu's attribute keys and the keys read by the contact
flow.

Amazon Connect is **initial-context-only** in Bridgefu. It does not receive
later arbitrary WebRTC DataChannel messages. The contact is stopped when the
call ends; Bridgefu retains cleanup authority in a durable journal and retries
unresolved `StopContact` work during reconciliation.

## Workflow 2: browser to Vapi assistant, then Amazon Connect

This mode makes Bridgefu the browser's WebRTC server and keeps the browser
connection stable while the remote endpoint changes.

```text
initial conversation

browser == WSS/WebRTC ==> Bridgefu == SIPS/SRTP ==> Vapi assistant

successful handoff

browser == same WebRTC ==> Bridgefu == Amazon Chime WebRTC ==> Connect agent
                                  \\-- old Vapi connection retired

failed handoff

browser == same WebRTC ==> Bridgefu == SIPS/SRTP ==> Vapi assistant resumed
```

### Phase A: create and attach the browser call

The browser must not call Bridgefu's protected REST API directly. A trusted,
normally same-origin backend calls a named route such as
`vapi-direct-assistant`:

```http
POST /v1/routes/vapi-direct-assistant/calls
Authorization: Bearer <server-side credential>
Idempotency-Key: <unique operation key>
Content-Type: application/json

{
  "ingress": "webrtc",
  "context": {
    "correlation_id": "application-owned-correlation",
    "metadata": {
      "handoff_token": "opaque-server-issued-value"
    }
  }
}
```

The response contains the call and leg IDs plus a browser attachment
descriptor with:

- a WSS signaling URI;
- a two-minute, single-use attachment token;
- a separate attachment-bound signaling bearer with only
  `webrtc:connect` authority;
- the exact WebSocket subprotocol values; and
- ICE/TURN configuration.

The backend returns that descriptor to the browser. The TypeScript SDK
normalizes it, opens authenticated WSS signaling, obtains microphone media,
creates one `RTCPeerConnection`, and attaches the inbound WebRTC leg. Bridgefu
then dials the Vapi assistant endpoint selected by the named route, normally
using SIPS, SRTP, and an outbound SIP profile.

When the Vapi route declares `initial_context: required`, Bridgefu does not send
the first SIP `INVITE` until safe context is available. Server-owned context in
the backend's named-route request can supply it after the browser attachment is
authenticated; this is the path used by the example above. If the backend
omits route context, Bridgefu instead waits for and durably validates one exact
`bridgefu.context.v1` envelope from the authenticated browser binding. Only
configured metadata keys become SIP headers. Later allowed context can use
in-dialog SIP `MESSAGE`.

### Phase B: request the handoff

The SDK does not choose or invoke Amazon Connect. The application backend
requests replacement through the protected control API:

```http
POST /v1/calls/{call_id}/legs/{vapi_leg_id}/replace
Authorization: Bearer <server-side credential>
Idempotency-Key: <unique operation key>
Content-Type: application/json

{
  "route_id": "amazon-connect"
}
```

Only an allowlisted route ID is accepted. Bridgefu resolves the Amazon profile,
instance, contact flow, credentials, and endpoint from server-owned
configuration. An HTTP `202 Accepted` means the durable replacement command
was recorded; it does not mean the agent is already connected.

A common application pattern is:

1. the backend creates a signed or opaque, short-lived handoff token that maps
   to the Bridgefu call and Vapi logical leg;
2. Bridgefu passes it to the configured Vapi SIP assistant as an allowlisted
   context header;
3. Vapi exposes it as a fixed template value to a non-LLM-generated escalation
   tool request;
4. the backend validates the token and calls Bridgefu's replacement endpoint.

The handoff token is application correlation authority. It is not a Bridgefu
API credential and must not be allowed to select an arbitrary route.

### Replacement behavior

Replacement is generation-fenced and make-before-break:

1. Bridgefu records a pending generation for the existing logical Vapi leg.
2. The old Vapi binding remains the resumable current generation while the new
   Amazon connection is prepared.
3. Media policy prevents the pending destination from becoming a third audio
   participant.
4. Bridgefu starts Amazon Connect with safe retained initial context and waits
   for the new media path to become ready.
5. On success, it atomically promotes the Amazon generation and retires the
   exact old Vapi binding.
6. On rejection, timeout, cancellation, or setup failure, it retires only the
   failed generation and resumes Vapi.

Stale completion events cannot promote an older attempt over a newer retry.
The browser's logical leg and `RTCPeerConnection` remain stable throughout a
normal replacement.

Bridgefu reports the server-authenticated lifecycle over the reserved
`bridgefu.handoff.v1` DataChannel. The browser can observe `preparing`,
`ringing`, `attaching`, `connected`, `resumed`, `failed`, and `ended`. Peer
DataChannels cannot spoof this reserved label.

### Browser SDK boundary

The alpha `@bridgefu/webrtc-browser` package owns:

- WSS signaling and one `RTCPeerConnection`;
- microphone acquisition and remote-audio playback;
- ICE/TURN configuration;
- `bridgefu.context.v1` and application DataChannels;
- WebRTC DTMF when the negotiated audio sender supports it;
- ringback and authenticated handoff-status events; and
- deterministic disconnect and fresh-attachment reconnect behavior.

It deliberately does not:

- store or send the long-lived Bridgefu REST bearer;
- call Vapi's API or Amazon's API;
- select a destination route;
- expose a `replaceLeg` or handoff control method;
- turn Bridgefu into a conference; or
- replay an attachment after signaling loss.

If the signaling socket or peer connection is lost, the application must ask
its backend for a newly created attachment. The two-minute, single-use token is
never reused.

See [`sdk/typescript/README.md`](../sdk/typescript/README.md) for the browser
wire contract and API.

## Common media and control capabilities

| Capability | Behavior |
|---|---|
| Audio | Full-duplex audio through rvoip's `MediaGraph`; no video track. |
| Codecs | G.711 PCMU/PCMA and Opus on the supported paths, with transcoding when needed. |
| DTMF | RFC 4733 or the negotiated WebRTC DTMF path where both endpoint policies support it. |
| SIP early media | Supported by the generic engine; destination media can be heard during a valid `183` without prematurely promoting the final call state. |
| Initial context | Allowlisted browser context or SIP headers can become initial SIP headers or Amazon contact attributes. |
| Live context | Generic interactive WebRTC can use DataChannels; generic SIP can use later SIP `MESSAGE` when enabled. Amazon remains initial-only. |
| Hangup | Either terminal leg converges the other leg and owned external resources toward cleanup. |
| SIP transfer | Authoritative SIP `REFER`/`NOTIFY` semantics are separate from server-controlled leg replacement. |
| Replacement | One stable logical destination leg is rebound to a new server-owned endpoint generation. |
| Persistence | SQLite is the normal all-in-one backend; PostgreSQL plus Redis supports role separation and clustered coordination. Memory is explicit dev/test-only state. |

## Runtime components

### All-in-one

`runtime.mode: all-in-one` is the default and the most complete composition for
these two workflows. One process owns:

- the preserved Vapi-to-Amazon SIP listener;
- the protected HTTP control API;
- the optional generic SIP and WebRTC listeners;
- the durable call service and worker execution;
- Amazon Connect control and media; and
- health, metrics, drain, and cleanup reconciliation.

The preserved listener and generic call engine are independent even when they
share a process. Generic routing changes do not take over the fixed legacy SIP
listener.

### Gateway and worker

Role-separated operation moves public HTTP, SIP, and WebRTC termination to a
gateway and durable execution/media ownership to a pinned worker. Their private
route uses authenticated mTLS UCTP with generation and worker fencing. Local
SIP/WSS split-path implementation exists, but split Amazon handoff is not yet a
release-qualified substitute for the all-in-one workflow.

### MOQT relay

`runtime.mode: moq-relay` is for broadcast distribution. It is unrelated to the
Vapi-to-Amazon and browser-handoff call path and can be ignored while reviewing
those products.

## Security boundaries

- The REST bearer and control HMAC key belong only on a trusted backend.
- Every mutating call API request requires a unique `Idempotency-Key`; exact
  retries return the original receipt and conflicting reuse is rejected.
- Public clients choose a named route, not a raw destination. Routes and
  profiles keep SIP targets, Amazon identifiers, credentials, TLS policy, and
  TURN secrets server-owned.
- Browser attachment and signaling credentials are short-lived,
  attachment-bound, and single-purpose. WSS is mandatory outside explicit
  localhost development.
- Named Vapi SIP ingress requires a profile-bound principal and matching TLS,
  SRTP, CIDR, Digest, and/or mTLS policy. A CA certificate alone does not assign
  a Bridgefu principal; an mTLS deployment also binds accepted leaf
  fingerprints.
- Context mapping is allowlisted and bounded. It rejects hop-by-hop and auth
  headers, reserved ownership keys, control characters, oversized values, and
  unknown fields.
- Amazon and provider credentials come from secret references, the AWS default
  credential chain, or an instance/task role. They are not returned in route
  discovery or call plans.
- Effective configuration output redacts secrets. Public route discovery,
  call responses, and diagnostics do not expose credentials or attachment
  material; route discovery also withholds destination details and TURN
  secrets.
- The fixed port-5060 compatibility listener is not a secure signaling
  boundary; restrict it at the network edge.

See [`security.md`](security.md) for the full model.

## Explicit non-capabilities

Bridgefu is not currently:

- a three-way mixer or conferencing server;
- a video or screen-sharing bridge;
- an Amazon Connect contact-flow designer or agent UI;
- a replacement for the application backend that authorizes handoff;
- a browser-side Vapi or Amazon API client;
- a guarantee that a carrier preserves custom SIP headers across a transfer;
- a guarantee that stock Vapi `webCall` can perform the required SIP transfer;
- a hot-reloadable configuration service; or
- a generally available, fully qualified 1.0 release.

Twilio and Vonage provider control are deferred. Telnyx and broadcast features
exist but are outside the two workflows in this guide.

## Implementation and readiness

The repository distinguishes implemented behavior from release evidence.

### Implemented and hermetically exercised

- the preserved SIP-to-Amazon header mapping, `StartWebRTCContact`, Chime media,
  bidirectional teardown, and durable Amazon cleanup path;
- secure, single-use named SIP and WebRTC attachments;
- durable exactly-two-leg call state and server-owned route profiles;
- browser WebRTC to a Vapi-like SIPS/SRTP assistant;
- generation-fenced assistant replacement with success promotion, failure
  compensation, no-mix behavior, and stable browser binding;
- replacement to the Amazon adapter with initial context, media, DTMF,
  teardown, and exactly owned cleanup; and
- the TypeScript SDK's signaling, media, context, DTMF, handoff-status,
  reconnect, and cleanup behavior.

### Still open before an end-to-end support claim

- a current, externally credentialed stock Vapi browser `webCall` to SIP
  transfer, including preservation of the required headers;
- live Amazon Connect and agent-screen-pop qualification for the current
  release candidate;
- a clean rerun of the exact-Chromium handoff matrix against the published,
  locked rvoip 0.3.7 WebRTC/RTC packages;
- TURN-only and public-NAT qualification;
- built-SDK split gateway/worker Amazon execution;
- process-restart recovery during the handoff matrix;
- deployed cloud smoke, live provider/PBX checks, and sustained load/chaos
  qualification; and
- publication of the alpha browser SDK and a generally available Bridgefu
  release.

The exact-Chromium direct-browser matrix recorded in the roadmap used a
temporary local RTC path override before the coordinated rvoip 0.3.1 packages
were published. Those runs remain useful historical local-composite evidence,
but they do not qualify the current crates.io package graph until the matrix is
rerun with the committed `Cargo.lock`.

The canonical status and remaining gates are in
[`roadmap.md`](roadmap.md). Test counts elsewhere in the roadmap are historical
evidence for particular revisions, not a promise about an arbitrary working
tree.

Where older documentation disagrees with the implementation and current
roadmap, this overview follows the latter. In particular, the older statement
in `amazon-connect.md` that full inbound headers are logged is stale, and some
split-mode availability notes in `api.md` predate the local split SIP/WSS
execution now present in the tree. Neither correction turns local split work
into deployed release evidence.

## Configuration map for the two workflows

The existing example configuration contains the relevant pieces, but not one
active, production-complete browser-to-Vapi-to-Amazon topology:

- `sip`, `tenants`, `aws`, `contact`, and `mapping` configure the preserved
  fixed-listener workflow;
- `api.route_attachments` configures the generated SIPS and WSS attachment
  descriptors;
- `vapi_ingress_profiles` authenticates named Vapi-managed SIP ingress;
- `webrtc_profiles` describes browser WebRTC policy;
- `sip_profiles` constrains outbound Vapi and PBX SIP destinations;
- `api.routes.vapi-direct-assistant` creates the initial browser-to-Vapi call;
- `api.routes.amazon-connect` provides the replacement destination; and
- `context.allow_headers` determines which browser/SIP metadata can cross the
  protocol boundary.

The `vapi-direct-assistant` example is commented in
[`config/bridgefu.example.yaml`](../config/bridgefu.example.yaml), while the
active Amazon route is demonstrated in
[`config/fixtures/reference-tenant-managed-routes.yaml`](../config/fixtures/reference-tenant-managed-routes.yaml).
They should be read as complementary examples, not as a single ready-to-deploy
configuration.

[`config/browser-vapi-amazon-handoff.example.yaml`](../config/browser-vapi-amazon-handoff.example.yaml)
composes those pieces into one complete all-in-one template for the fixed
transfer, secure named transfer, and browser-to-Vapi-to-Amazon handoff. It was
manually cross-checked against the current configuration model but intentionally
was not executed or passed to Bridgefu's validation command. Its placeholder
hosts, certificates, secret references, IDs, CIDRs, and application
handoff-token integration must be replaced and reviewed before use.

## Where to read next

For a review centered on the product rather than the entire platform, use this
order:

1. [`CHANGELOG.md`](../CHANGELOG.md) for the inventory of work since the
   original gateway.
2. [`src/main.rs`](../src/main.rs) and
   [`src/amazon_cleanup.rs`](../src/amazon_cleanup.rs) for the preserved
   Vapi-to-Amazon lifecycle.
3. [`api.md`](api.md) and [`src/api/calls.rs`](../src/api/calls.rs) for named
   routes and protected replacement control.
4. [`sdk/typescript/README.md`](../sdk/typescript/README.md) and
   [`sdk/typescript/src/client.ts`](../sdk/typescript/src/client.ts) for the
   browser boundary.
5. [`src/call_engine/domain.rs`](../src/call_engine/domain.rs) and the
   replacement code in
   [`src/call_service/execution.rs`](../src/call_service/execution.rs) for the
   exactly-two-leg and generation-fencing guarantees.
6. [`roadmap.md`](roadmap.md) for evidence and remaining release gates.
7. [`architecture.md`](architecture.md) only when reviewing split execution,
   broadcasts, or scaling.
