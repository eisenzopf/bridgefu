# Bridgefu architecture

Bridgefu is an audio-first policy and operations layer over rvoip. Protocol
state machines, authentication primitives, media streams, transcoding,
WebRTC, UCTP/QUIC, and MOQT live in rvoip; Bridgefu owns tenant routing,
provider APIs, safe metadata policy, admission, HTTP control, and deployment.

The current runtime has two independent SIP listeners so StandardCharter is
never put at risk by generic routing changes:

- Port 5060 (default) is the preserved Vapi → Amazon Connect screen-pop path.
- Port 5070 (when `generic_bridge.enabled`) is an rvoip Orchestrator with the
  first-party SIP and WebRTC servers. It pairs inbound heterogeneous legs and
  uses the shared `MediaGraph` for G.711/Opus conversion.

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
