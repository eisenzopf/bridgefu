# Protocol compatibility

| Surface | Release contract |
|---|---|
| SIP/RTP | Audio, G.711 µ-law/A-law, RFC 4733 DTMF |
| WebRTC | Opus, WHIP/WHEP, WS/WSS signaling, arbitrary labeled DataChannels |
| Context | `bridgefu.control.v1`, JSON, allowlisted `X-Bridgefu-*`/configured `X-*` only |
| UCTP | `uctp/0.2`; 8-byte UCTP header followed by a complete RTP packet |
| MOQT wire library | Private `eisenzopf/moq-rs` draft-19 port pinned at `ef52ac8656513bb3b07b4b9b80152ac24bb2467e`; Gate 5 wire, retention, discovery, and least-privilege relay qualification is complete |
| Bridgefu MOQT target | MOQT draft-19, MSF-01, LOC-03 |

MOQT draft churn is isolated in `rvoip-moq`. The reviewed private fork
implements draft-19 request-stream placement, control/data/PUBLISH/FETCH
codecs, canonical raw-QUIC/WebTransport session targets, explicit session and
namespace acceptance, bounded retention, warm Joining FETCH, cold live
fallback, and subgroup `END_OF_GROUP` handling. Namespace discovery has a
bounded initial snapshot plus live Added/Removed updates and fails closed on
overflow or prefix overlap.

The relay path verifies mTLS identities, enforces exact scopes, uses stateless
retry, redacts secrets, and defaults to a production-safe posture. Publisher
certificates are publish-only. External relay certificates are subscribe-only
and cannot announce or publish a namespace.

The reviewed fork passes 429 transport tests. Its relay package passes 111
library, 25 binary, one admission-contract, and five feature-policy tests with
all features, plus strict Clippy and warning-free rustdoc. Golden vectors cover
draft-19 setup, request/response, subgroup, datagram, FETCH, object, status,
padding, and authorization encodings.

The matching rvoip revision is
`7d83b66545789d55471c13a7c68eb54a9493cc0a`. It exposes only rvoip-owned
authorization, catalog, LOC, events, compatibility, health, topology, and
lifecycle types. Its final Gate 5 matrix passes 134 unit, three managed relay
E2E, two public API, and seven admission tests. The E2E matrix includes warm
Relative Joining FETCH, cold live fallback, raw QUIC, WebTransport, a real
two-topology external mTLS relay chain, route replacement/reconnect, publish
denial for relay credentials, and drain cleanup.

The real-browser run negotiates draft 19, authenticates through a structured
receive-only SETUP token, traverses WebTransport, and parses the MSF-01 catalog.
The packet-capture suite records both `moqt-19` and `h3` ALPN handshakes without
enabling a TLS key log. Unmodified `moq-dev/moq` independently passes draft-19
WebTransport namespace discovery, subscription, and live Objects. Its current
native client omits mandatory PATH/AUTHORITY and its high-level subscriber does
not expose retained FETCH; rvoip rejects those unsupported paths explicitly
rather than downgrading.

Gate 5 is complete. Dynamic route registrations for standalone relays are
runtime-safe, bounded, exact-namespace, generation-safe, and drain-owned. They
remain local to one process until Gate 10's PostgreSQL/Redis control plane
distributes route changes across relay replicas.

No upstream issue, pull request, or maintainer contact has been made. The
private fork review packet is in `moq-fork-review.md`; any submission remains
subject to project-owner review.

The reviewed inputs are recorded in `moq-compatibility.json`. A scheduled,
report-only CI workflow compares those pins with IETF Datatracker and moq-rs
upstream. It never updates a dependency or contacts an upstream maintainer.

Bridgefu's production MSF-01 profile maps each audio Object to a new MOQT
stream, as required by MSF-01 section 6. LOC datagrams remain an explicit
experimental non-MSF profile and are not enabled by Bridgefu 1.0.

RoQ remains an adapter seam. It is point-to-point RTP/RTCP carriage and is not
used as a broadcast fanout protocol.
