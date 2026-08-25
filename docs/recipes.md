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

Every built-in is compiled, fingerprinted, and negative-tested on each CI run by
[`tests/recipe_matrix.rs`](../tests/recipe_matrix.rs). That gate proves a recipe
still *compiles* to the bridge graph it claims. It does not prove a live call
works, which is what the promotion blocker column below tracks.

| Recipe or capability | Source | Destination | Tier | What blocks promotion to `supported` |
|---|---|---|---|---|
| [`vapi-amazon-connect-screen-pop@1`](https://github.com/eisenzopf/bridgefu-vapi-awsconnect) | Vapi SIP transfer | Amazon Connect WebRTC | Preview | Nothing technical. Dual-region live evidence exists; customer CloudFormation and qualification are maintained externally, so promotion is a release-process step, not an engineering one. |
| [`webrtc-amazon-connect-bridge@1`](../recipes/webrtc-amazon-connect-bridge/recipe.yaml) | Interactive WebRTC/WSS | Amazon Connect WebRTC | Preview | Needs a live browser-to-Connect call: a Connect instance, a published entry flow, and a browser client driving the Bridgefu Web SDK. No live evidence retained yet. |
| [`sip-webrtc-bridge@1`](../recipes/sip-webrtc-bridge/README.md) | SIP/RTP or SIPS/SRTP | Interactive WebRTC/WSS | Preview | Needs a live SIP peer that will originate into Bridgefu, plus a browser answering over WSS. Testable locally with the `generic` Compose profile and the SDK; no retained evidence yet. |
| [`webrtc-sip-bridge@1`](../recipes/webrtc-sip-bridge/README.md) | Interactive WebRTC/WSS | SIP/RTP or SIPS/SRTP | Preview | Needs a fixed SIP destination that accepts Bridgefu's From URI, plus TLS roots for `sips_srtp`. The `generic` Compose profile plus coturn covers the browser half; the SIP half needs a real contact-center endpoint. |
| `browser-vapi-to-contact-center` | Vapi-managed browser WebRTC | SIP/RTP, SIPS/SRTP, or Amazon Connect WebRTC | Development | Not yet an embedded recipe. Needs a manifest before it can be compiled or tested at all. |
| `genesys-webrtc-bridge` | SIP/RTP or SIPS/SRTP | Genesys WebRTC | Roadmap | Not implemented. Needs a Genesys destination adapter in the call engine first. |

Telnyx, WHIP/WHEP, UCTP, MOQT, and generic WSS capabilities remain available
through expert configuration at their published development/preview status.
They are not part of the first promoted recipe matrix.

### Testing a recipe locally

The three non-Vapi recipes all have a browser leg, and
[`sdk/typescript`](../sdk/typescript) is the reference client for it — a generic
rvoip WebRTC signaling client with no deployment-specific coupling. Pair it with
the `generic` Compose profile (which also starts coturn) to exercise the
WebRTC half of a bridge without any cloud account:

```bash
make recipes                  # what is embedded in this build
make recipe-matrix            # compile + fingerprint + negative cases
docker compose --profile generic up
```

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
- SIPS/SRTP is the secure default. `sips_optional_srtp` preserves TLS signaling
  and accepts RTP only when the peer does not offer SRTP. Clear SIP/RTP is a
  separate explicit diagnostic compatibility posture.
- Support claims are per exact direction, security posture, codec, DTMF path,
  deployment profile, and evidence revision.

Use `bridgefu recipe available`, `show`, `validate`, `init`, and `explain` to
inspect or configure the embedded catalog without exposing secrets. Provider
deployment, lifecycle, and live qualification tooling belongs in the
provider-specific distribution repository rather than the Bridgefu runtime.
