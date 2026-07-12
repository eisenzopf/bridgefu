# Protocol compatibility

| Surface | Release contract |
|---|---|
| SIP/RTP | Audio, G.711 µ-law/A-law, RFC 4733 DTMF |
| WebRTC | Opus, WHIP/WHEP, WS/WSS signaling, arbitrary labeled DataChannels |
| Context | `bridgefu.control.v1`, JSON, allowlisted `X-Bridgefu-*`/configured `X-*` only |
| UCTP | `uctp/0.2`; 8-byte UCTP header followed by a complete RTP packet |
| MOQT wire library | Private `eisenzopf/moq-rs` draft-19 port pinned at `f6159d2daf4e7aa6caccefbaf225070ff55bd869`; control/data/PUBLISH/session hardening complete, Gate 5 interoperability in progress |
| Bridgefu MOQT target | MOQT draft-19, MSF-01, LOC-03 |

MOQT draft churn is isolated in `rvoip-moq`. The reviewed private fork now
implements the draft-19 control and data codecs plus hardened PUBLISH and
session lifecycles, including bounded admission, cancellation, cleanup, and
same-alias fanout. Its reviewed matrix passes 264 transport tests, 42 relay
library tests, two relay binary tests, strict clippy, and a workspace check.

The matching rvoip revision is
`6492ec1d4638323aeb52cfc66fa7feea0b180e0f`. It exposes rvoip-owned
authorization, catalog, LOC, compatibility, health, and lifecycle types without
leaking moq-rs types. Managed publication/relay lifecycles use production mTLS,
bounded reconnect, health reporting, graceful drain, and deterministic cleanup.
The scoped `rvoip-moq` matrix passes 53 default unit tests plus its public API
test, 54 `insecure-development` unit tests plus its public API test, and strict
clippy and rustdoc in both configurations.

Gate 5 remains in progress. The remaining wire and interoperability work is:

- confine every request to its request stream instead of accepting or emitting
  requests on the control stream;
- emit subgroup `END_OF_GROUP` and use one stream per MSF Object;
- implement Joining FETCH backed by the bounded retention cache;
- complete URI handling, WebTransport, and end-to-end relay traversal; and
- pass the recorded matrix against an independent draft-19 implementation.

Bridgefu must not be called GA for draft-19 until those checks pass. No upstream
issue, pull request, or maintainer contact has been made; any proposed upstream
submission remains subject to project-owner review.

The reviewed inputs are recorded in `docs/moq-compatibility.json`. A scheduled,
report-only CI workflow compares those pins with IETF Datatracker and moq-rs
upstream. It never updates a dependency or contacts an upstream maintainer.

Bridgefu's production MSF-01 profile maps each audio Object to a new MOQT
stream, as required by MSF-01 section 6. LOC datagrams are retained only as an
explicit experimental non-MSF profile.

RoQ remains an adapter seam. It is point-to-point RTP/RTCP carriage and is not
used as a broadcast fanout protocol.
