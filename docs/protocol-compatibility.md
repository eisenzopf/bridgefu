# Protocol compatibility

| Surface | Release contract |
|---|---|
| SIP/RTP | Audio, G.711 µ-law/A-law, RFC 4733 DTMF |
| WebRTC | Opus, WHIP/WHEP, WS/WSS signaling, arbitrary labeled DataChannels |
| Context | `bridgefu.control.v1`, JSON, allowlisted `X-Bridgefu-*`/configured `X-*` only |
| UCTP | `uctp/0.2`; 8-byte UCTP header followed by a complete RTP packet |
| MOQT wire library | `moq-transport` 0.15 currently advertises draft-16 |
| Bridgefu MOQT target | MOQT draft-19, MSF-01, LOC-03 |

MOQT draft churn is isolated in `rvoip-moq`. The diagnostics endpoint reports
both the linked wire draft and the target. Bridgefu must not be called GA for
draft-19 until the pinned moq-rs commit passes independent interop; the current
crate makes this gap explicit rather than misreporting compatibility.

RoQ remains an adapter seam. It is point-to-point RTP/RTCP carriage and is not
used as a broadcast fanout protocol.
