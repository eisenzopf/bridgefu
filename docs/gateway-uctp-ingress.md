# Split gateway public edge

The role-separated `gateway` process exposes four production-shaped public
edge families:

- the authenticated, versioned HTTP call-control/provider-webhook API on
  `api.http_bind`;
- authenticated UCTP 0.2 attachments over raw QUIC;
- authenticated native SIP/RTP on `generic_bridge.sip_bind`; and
- authenticated WSS plus WHIP/WHEP over HTTPS on the two generic WebRTC binds.

Gateway preflight requires `api.enabled: true` and
`generic_bridge.enabled: true`. The gateway constructs a transport-only rvoip
Orchestrator to terminate native protocols and supervise ephemeral adapter
routes. It does not construct `CallService`, register a durable worker, select
legs locally, or use FIFO pairing. Every native route must resolve one exact
principal-bound attachment and forward it to the call-pinned worker over
private mTLS UCTP 0.2 before signaling succeeds.

The public router never mounts `/metrics`, `/livez`, `/readyz`, or `/healthz`;
those remain exclusively on `observability.http_bind`. Non-loopback
`api.http_bind` values require `api.tls`. The same reviewed certificate and key
terminate HTTPS, WSS, and WHIP/WHEP HTTPS when WebRTC signaling is non-loopback.
Plaintext WebRTC signaling is accepted only on loopback development binds.

## HTTP control contract

The gateway opens the same PostgreSQL call repository, tenant principal,
24-hour idempotency, attachment-token, provider-signature, and state-machine
contracts as all-in-one mode. It does not register a worker, advertise worker
media capabilities, or consume worker work. Call creation selects an existing
live worker atomically in PostgreSQL. Effects and controls are stored there and
announced through the ordered Redis projection/worker stream; workers retain
their mandatory PostgreSQL polling fallback.

The projector owns a bounded supervised task. Three consecutive projection
failures make readiness non-healthy and pause authenticated API admission; a
successful cycle restores it. Provider webhooks remain protected by each
provider's native signature verification and are durably deduplicated.
Clustered broadcast commands use the durable worker command path; they never
create a local gateway media runtime or silently fall back to all-in-one.

## Native attachment contract

Native edges carry the generated single-use two-minute attachment proof in a
transport-specific routing field:

- SIP uses the Request-URI user part;
- WebSocket signaling uses the private `bridgefu.attach.<token>` subprotocol;
- WHIP/WHEP uses the resource path tag.

The same auth-core principal used by the API/UCTP boundary is retained through
WebRTC admission. SIP accepts the configured Bridgefu Bearer authority and,
when configured, either a first-party `generic_bridge.sip.digest` identity or
the Telnyx account's Digest username/password/realm. Generic and Telnyx Digest
may coexist only with one exact realm and distinct usernames.
Cleartext SIP UDP/TCP rejects Bearer credentials by default. A generic peer
without generic or Telnyx Digest can use the shared Bearer authority only after explicitly
setting `generic_bridge.sip.allow_cleartext_bearer: true`; because that exposes
a reusable credential to on-path observers, the listener must also be limited
to a private or CIDR-restricted carrier path. Bridgefu does not yet expose
rvoip's trusted-CIDR or SIP-mTLS listener policies as YAML and does not claim
them here.

After the pinned worker consumes the proof, the gateway creates only the
ephemeral local conversation needed to activate rvoip's adapter media stream.
It resolves that stream's exact codec before consuming the proof, offers only
that codec on the private route, reconstructs complete RTP packets for private
forwarding, and parses worker RTP back into transport media. The supported
private profiles are mono Opus at 48 kHz, PCMU at 8 kHz, and PCMA at 8 kHz.
Public dynamic Opus payload types are normalized to the private profile's PT
111; PCMU and PCMA use PT 0 and PT 8. A packet whose payload type does not match
the route's negotiated codec fails the route instead of falling back to a
different codec. DataMessages and typed DTMF commands traverse the private
route in both directions with bounded queues.

## Private outbound egress control

The same mTLS UCTP 0.2 connection now reserves three reliable internal labels
for worker-to-gateway commands, gateway responses, and asynchronous lifecycle
events. Public SIP MESSAGE and WebRTC DataChannel input cannot use those
labels. The gateway authorizes a command from the consumed source attachment,
not from command JSON: worker fence, tenant, call, source leg, and attachment
generation must match, while the command names one exact destination leg and
generation. Prepare remains peer-dormant until Activate; Abort, End, DTMF, and
DataMessage transitions are state checked. Queues, active routes, replay
entries, command lifetime, and handler deadlines are bounded, and closing the
source ends every matching prepared or active destination.

The reusable media seam now reserves a one-use descriptor derived from the
exact Prepare command and opens a second authenticated UCTP
Session/Connection/Stream for the destination generation. The worker registry
binds worker fence, tenant, call, source attachment generation, target leg
generation, codec, expiry, and admission ID; the connection remains
reauthorizable but the admission cannot be consumed twice. A gateway proxy
can wrap staged SIP or WebRTC `ConnectionAdapter`s, keep Prepare dormant, and
start bounded full-duplex media plus DTMF/DataMessage forwarding on Activate.
Terminal lifecycle events remain journaled on the gateway until the worker's
exact ACK is durable; only then does the proxy retire its native/private route.
If the source disappears before that ACK, generation-bound source cleanup owns
the fallback End.

Gateway and worker process roles now install the proxy, registry, and durable
Redis-backed command/lifecycle authority for configured SIP and WSS egress.
The durable call supervisor owns both initial destination admission and
generation-fenced replacement. The focused real-network topology test drives
authenticated WHIP ingress through SIP and WSS destinations, failed and
successful replacement attempts, full-duplex media/control, remote terminal
reconciliation, drain, and exact cleanup. This is still hermetic local
evidence, not production qualification: real Redis process-restart recovery,
non-loopback SIP/WSS peers, TURN/NAT, deployed cloud smoke, and sustained
load/chaos suites remain open.

Bridgefu 1.0 deliberately terminates native RTCP hop-by-hop. SIP↔WebRTC routes
may transcode, repacketize, and rewrite SSRC/timestamps, so blindly forwarding
raw feedback would be incorrect. Worker RTCP arriving at a native edge is
counted and discarded. A future rvoip seam should expose translated feedback
and aggregate diagnostics, with raw observation/sending only where packet
identity is explicitly preserved.

## Public UCTP attachment contract

The peer authenticates with `api.bearer_token`, using the ordinary UCTP bearer
handshake, and opens a Session with:

- intent `bridgefu-public-attachment`;
- Session ID `bf-public-attach-v1:<transport>:<attachment-token>`;
- transport `sip` or `webrtc` matching the call API attachment;
- one audio stream using UCTP 0.2's complete-RTP datagram format.

The attachment token is canonical unpadded URL-safe Base64 for 32 bytes. It is
never logged or used as a metric label. The gateway validates its shape,
resolves only its keyed owner/digest projection through clustered Redis, and
opens one provisional mTLS UCTP route to the projected worker. Only that worker
consumes the proof and returns the exact call/leg binding. As with native
SIP/WebRTC, the gateway resolves the public stream codec first and offers one
exact canonical codec to the private worker; it does not use an ordered codec
list as an implicit fallback.

Complete RTCP packets use the reserved reliable `bridgefu.rtcp.v1` /
`application/rtcp` DataMessage. Other reliable DataMessages and typed DTMF
commands are forwarded in both directions without inspecting application
payloads.

## Required gateway configuration

`private_forwarding.gateway.public_uctp` supplies the public QUIC bind and
server certificate. The gateway additionally requires:

- `api.enabled: true`;
- a dedicated `api.http_bind` different from `observability.http_bind`;
- `api.tls.certificate_chain` and `api.tls.private_key` whenever the API or
  WebRTC signaling binds are non-loopback;
- `generic_bridge.enabled: true`, with explicit SIP, RTP, WSS, WHIP/WHEP, and
  ICE/DTLS binds suitable for the deployment's advertised addresses;
- at least one usable SIP authentication mechanism: generic Digest, Telnyx
  Digest, or the explicit cleartext-Bearer opt-in;
- `api.bearer_token`, `api.control_hmac_key`, and an unambiguous static tenant;
- PostgreSQL plus clustered `rediss://` coordination; a gateway deliberately
  omits `persistence.worker_id`;
- private forwarding mTLS, token-signing, worker targets, limits, and timeouts.

Readiness is healthy only when call control, native SIP/WebRTC, public UCTP,
their correctness streams, and every configured private worker dependency are
healthy. Drain stops HTTP and all attachment admission first, drains native
signaling/media and public UCTP routes within the shared deadline, then closes
private worker peers and joins the control projector.
