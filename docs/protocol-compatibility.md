# Protocol compatibility

| Surface | Release contract |
|---|---|
| SIP/RTP | Audio, G.711 µ-law/A-law, RFC 4733 DTMF |
| WebRTC | Opus, WHIP/WHEP, WS/WSS signaling, arbitrary labeled DataChannels |
| Context | `bridgefu.control.v1`, JSON, allowlisted `X-Bridgefu-*`/configured `X-*` only |
| UCTP | `uctp/0.2`; 8-byte UCTP header followed by a complete RTP packet |
| MOQT wire library | Private `eisenzopf/moq-rs` draft-19 port pinned at `f3c29d319766061b013ed683552a26ff8b7e5a2f`; control-plane port in progress |
| Bridgefu MOQT target | MOQT draft-19, MSF-01, LOC-03 |

MOQT draft churn is isolated in `rvoip-moq`. The first immutable fork checkpoint
implements draft-19 ALPN/version rejection and the changed control-request wire
surface; PUBLISH, FETCH, production MSF object streams, and relay lifecycle
remain release-gated. The diagnostics endpoint reports
the negotiated transport draft and the configured MSF/LOC profile separately.
Bridgefu must not be called GA for draft-19 until the pinned moq-rs commit
passes independent interop; the current crate makes this gap explicit rather
than misreporting compatibility.

The reviewed inputs are recorded in `docs/moq-compatibility.json`. A scheduled,
report-only CI workflow compares those pins with IETF Datatracker and moq-rs
upstream. It never updates a dependency or contacts an upstream maintainer.

Bridgefu's production MSF-01 profile maps each audio Object to a new MOQT
stream, as required by MSF-01 section 6. LOC datagrams are retained only as an
explicit experimental non-MSF profile.

RoQ remains an adapter seam. It is point-to-point RTP/RTCP carriage and is not
used as a broadcast fanout protocol.
