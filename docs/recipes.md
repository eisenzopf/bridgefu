# Bridgefu recipes and support matrix

Bridgefu connects one support signaling/media transport to another. A recipe is
the supported unit of configuration, infrastructure, documentation, tests, and
operational evidence. Administrators normally select a recipe; experts may
still use the full low-level configuration model.

## Support tiers

| Tier | Meaning |
|---|---|
| `supported` | Exact matrix has retained hermetic and live evidence plus runbooks. |
| `preview` | Intended production path; at least one external/release gate remains. |
| `development` | Executable implementation for experimentation; no production claim. |
| `custom` | User-authored data-only recipe; structural validation only. |
| `roadmap` | Planned, not delivered. |

Only an embedded recipe can be promoted to `supported`. A working proof is
important evidence, but support also requires the exact released artifacts,
failure cases, operations, teardown, latency, capacity, and retained test gate.

## Catalog

| Recipe or capability | Source | Destination | Tier |
|---|---|---|---|
| [`vapi-amazon-connect-screen-pop@1`](../recipes/vapi-amazon-connect-screen-pop/README.md) | Vapi SIP/RTP or SIPS/SRTP | Amazon Connect WebRTC | Preview (Starter pilot and HA) |
| [`webrtc-amazon-connect-bridge@1`](../recipes/webrtc-amazon-connect-bridge/README.md) | Interactive WebRTC/WSS | Amazon Connect WebRTC | Preview |
| `browser-vapi-to-contact-center` | Vapi-managed browser WebRTC | SIP/RTP, SIPS/SRTP, or Amazon Connect WebRTC | Development recipe work |
| [`sip-webrtc-bridge@1`](../recipes/sip-webrtc-bridge/README.md) | SIP/RTP or SIPS/SRTP | Interactive WebRTC/WSS | Preview |
| [`webrtc-sip-bridge@1`](../recipes/webrtc-sip-bridge/README.md) | Interactive WebRTC/WSS | SIP/RTP or SIPS/SRTP | Preview |
| `genesys-webrtc-bridge` | SIP/RTP or SIPS/SRTP | Genesys WebRTC | Roadmap |

Telnyx, WHIP/WHEP, UCTP, MOQT, and generic WSS capabilities remain available
through expert configuration at their published development/preview status.
They are not part of the first promoted recipe matrix.

## Why the first recipe matters

The flagship use case solves a common contact-center failure: a voice AI system
collects context, but a SIP transfer moves only audio and the agent asks the
customer to repeat everything. The recipe stores bounded fields in DynamoDB,
puts only an opaque ID in SIP, maps that ID to an Amazon Connect attribute,
retrieves the fields with Lambda, and shows them in Agent Workspace before
entering the customer's existing flow.

## Product boundary

- SIP and WebRTC are first-class sources or destinations in the Bridgefu call
  engine.
- Amazon Connect is currently a destination, not a recipe ingress source.
- A bridge has exactly two full-duplex logical legs. Transfer replaces a leg;
  it does not create an accidental conference.
- Telemetry and context services stay outside the packet path.
- SIPS/SRTP is the production default. Clear SIP/RTP is explicit compatibility.
- Support claims are per exact direction, security posture, codec, DTMF path,
  deployment profile, and evidence revision.

Use `bridgefu recipe available`, `show`, `validate`, `init`, and `explain` to
inspect or configure the embedded catalog without exposing secrets. Released
AWS packages also support guarded `deploy`, `status`, `doctor`, `test`, and
`preflight` commands through one strict schema-2 deployment descriptor.
Change-set execution requires exact stack-name confirmation; production
destruction is blocked behind the separate break-glass runbook.
