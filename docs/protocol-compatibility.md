# Protocol compatibility

| Surface | Release contract |
|---|---|
| SIP/RTP | Audio, G.711 µ-law/A-law, RFC 4733 DTMF |
| WebRTC | Opus, WHIP/WHEP, WS/WSS signaling, arbitrary labeled DataChannels |
| Context | `bridgefu.control.v1`, JSON, allowlisted `X-Bridgefu-*`/configured `X-*` only |
| UCTP | `uctp/0.2`; 8-byte UCTP header followed by a complete RTP packet |
| MOQT wire library | Private `eisenzopf/moq-rs` draft-19 port pinned at `612cc6fe4550a02092c932c3bdfbe4da8fed8694`; request placement, data/PUBLISH codecs, canonical targets, explicit acceptance, and secure relay admission are implemented; Gate 5 remains in progress |
| Bridgefu MOQT target | MOQT draft-19, MSF-01, LOC-03 |

MOQT draft churn is isolated in `rvoip-moq`. The reviewed private fork now
implements draft-19 request-stream placement, data and PUBLISH codecs,
canonical raw-QUIC/WebTransport session targets, and explicit session and
namespace acceptance. It also has the bounded retention-cache foundation,
Joining subscription state and typed options, and subgroup `END_OF_GROUP`
handling. The relay path verifies mTLS identities, enforces scoped admission,
uses stateless retry, redacts secrets from diagnostics, and defaults to a
production-safe posture.

The fork's full workspace passed 431 tests before the final user-information
hardening change. The final affected-package rerun passed 347 transport tests,
20 native-IETF tests, and 67 relay-IETF tests. These are checkpoint counts, not
the Gate 5 interoperability exit evidence.

The matching rvoip revision is
`a3eed0d730502093384a90680d15f0e64665f9f6`. It exposes rvoip-owned
authorization, catalog, LOC, compatibility, health, and lifecycle types without
leaking moq-rs types. The integration accepts an opaque, credential-free relay
peer identity from the transport, requires explicit publication acceptance,
and retains production mTLS, bounded reconnect, health reporting, graceful
drain, and deterministic cleanup. The scoped `rvoip-moq` matrix passes 68
default unit tests plus one public API test and 69 `insecure-development` unit
tests plus one public API test.

Gate 5 remains in progress. The remaining wire and interoperability work is:

- complete enforced logical retained-state bounds, cleanup, and eviction or
  backpressure;
- complete the FETCH state machine and cache-to-request handoff;
- emit one stream per MSF Object and complete catalog publication semantics;
- add rvoip `SessionAdmission` and await replay-tombstone persistence before
  reporting admission success;
- authorize production token subscribers and pass a real-browser WebTransport
  end-to-end test; and
- complete relay traversal and pass the recorded matrix against an independent
  draft-19 implementation.

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
