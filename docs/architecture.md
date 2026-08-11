# Bridgefu architecture

Bridgefu is an audio-first policy and operations layer over rvoip. Protocol
state machines, authentication primitives, media streams, transcoding,
WebRTC, UCTP/QUIC, and MOQT live in rvoip; Bridgefu owns tenant routing,
provider APIs, safe metadata policy, admission, HTTP control, and deployment.

The current runtime has two independent SIP listeners so the reference tenant is
never put at risk by generic routing changes:

- Port 5060 (default) is the preserved Vapi → Amazon Connect screen-pop path.
- Port 5070 (when `generic_bridge.enabled`) is an rvoip Orchestrator with the
  first-party SIP and WebRTC servers. Each inbound route consumes its own
  hashed, single-use durable attachment token; there is no process-global FIFO
  pairing. The call actor then uses the shared `MediaGraph` for G.711/Opus
  conversion.

The generic listener has one deliberately narrow exception for migration
testing. `generic_bridge.reference_tenant_canary` is disabled by default and may
name exactly one configured/static-auth tenant. Only that tenant's exact
authenticated subject and issuer, `sip:connect` plus `calls:create` scopes, and
one allowlisted `X-Correlation-Id` can atomically create/replay a durable
SIP-to-Amazon call. Bridgefu then derives and immediately consumes the normal
two-minute single-use attachment token; the tenant name never becomes a
general token bypass. Replays after attachment, duplicates, changed metadata,
cross-tenant principals, and unavailable durable authority fail closed.

In role-separated mode the gateway owns native SIP/RTP, WSS, and WHIP/WHEP
termination but not durable call execution. A transport-only Orchestrator
consumes the Request-URI, WebSocket subprotocol, or WHIP/WHEP path attachment
hint, resolves the exact principal-bound token through Redis, and forwards the
route to its pinned worker over private mTLS UCTP 0.2. RTP, DataMessages, and
typed DTMF cross that boundary with bounded queues. Bridgefu 1.0 terminates
RTCP hop-by-hop because transcoding/repacketization can rewrite packet identity;
a future rvoip translated-feedback/diagnostic seam may expose raw packets only
when SSRC, sequence, and timestamp identity is preserved.

That private route remains an **ingress media** seam in production, while its
reusable egress proxy seam is now hermetically executable. Its control
substrate recognizes authenticated,
versioned `prepare`, `activate`, `abort`, `end`, DTMF, DataMessage, response,
and lifecycle messages. The physical source route is authoritative: every
command must match its worker fence, tenant, call, source leg, and source
binding generation, and it names one exact destination leg generation.
Commands are bounded, short-lived, digest-replay protected, serialized per
destination, and automatically ended when the source route closes. Reserved
labels are rejected at public DataChannel and SIP mappings.

The egress seam derives a one-use stream admission from Prepare and opens a
second authenticated UCTP Session/Connection/MediaStream, independently
bounded and keyed by the exact source and destination generations. Gateway
proxy handlers wrap staged SIP/WebRTC `ConnectionAdapter`s: Prepare allocates
without peer-visible signaling, Activate starts native signaling and
full-duplex media/control pumps, and Abort/End own both halves' teardown.
Remote terminal events are journaled before delivery; their proxy and private
media route remain alive until the worker's exact generation-bound ACK is
durable. Source loss provides the fallback cleanup when that ACK can no longer
arrive.

Gateway and worker process roles now install this protocol for configured SIP
and WebRTC egress. The durable call supervisor uses it for initial destinations
and generation-fenced make-before-break replacement, while clustered gateway
state, replay, and lifecycle journals use Redis. Hermetic real-network tests
cover authenticated WHIP ingress, SIP and WSS egress, full-duplex media and
control, failed and successful replacement generations, remote terminal
reconciliation, drain, and exact cleanup. This remains local implementation
evidence rather than deployed qualification: process-restart recovery with a
real Redis peer, non-loopback signaling peers, TURN/NAT traversal, cloud smoke,
and sustained load/chaos gates remain open. Configuration or local seam
availability alone is never treated as deployed evidence.

Every media source is consumed once by `MediaGraph`. Call peers, recorders,
observers, UCTP publishers, and MOQT origins are sinks. Each sink receives a
bounded ten-frame drop-oldest queue; codec-equivalent sinks share immutable
payloads and transcode work is shared by codec group.

## Call state

Provider-controlled calls have a Bridgefu call ID plus the provider's call ID.
Webhooks are signature-verified, normalized, and deduplicated before changing
state. Amazon screen-pop calls retain their SIP session ID as the call ID so the
legacy operational contract remains intact.

Active media stays worker-local. Draining refuses new work, allows the bounded
drain interval, and ends remaining legs; 1.0 does not migrate sessions.

The immutable execution plan carries the redacted authorization fingerprint
needed to prepare outbound rvoip routes after restart. Transfers identify one
existing leg and its exact binding generation in the durable effect payload.
Once authoritative rvoip media activity begins, each exact route advances a
durable activity generation and atomically refreshes `DeadlineKind::Media`
using `runtime.media_idle_timeout_secs`. Duplicate, skipped, retired-route, and
post-teardown observations cannot resurrect that deadline.

For WebRTC→SIP calls that require first-INVITE metadata, the execution plan
persists `initial_context: required`. The call actor accepts only a
`bridgefu.context.v1` message whose tenant, call, source leg, connection, and
both binding generations match durable state. It records the envelope and
typed allowlisted SIP headers atomically before SIP route preparation. Inbound
SIP metadata follows the reverse path to the peer DataChannel; later context
and arbitrary labeled DataChannels use the active graph route.

## Broadcast state

`POST /v1/calls/{id}/broadcasts` selects exactly one source graph and adds an
Opus sink. `moqt` produces LOC audio objects plus an MSF catalog;
`uctp-quic` uses the corrected UCTP-header + complete-RTP-packet datagram.
Subscriber JWTs are receive-only, tenant-bound, broadcast-bound, and short
lived. MOQT call context is not published.

## Scaling boundaries

- Call and UCTP broadcast affinity is one worker for the life of the session.
- MOQT origins can publish through raw QUIC or WebTransport to an external
  relay tier. Origin-to-relay client certificates enable mTLS.
- Call IDs belong in logs and traces, never Prometheus labels.
- Cluster coordination is intentionally outside media packet paths.
