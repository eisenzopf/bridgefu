<div align="center">
  <img src="bridgefu-banner.png" alt="Bridgefu — Connect anything." width="70%" />

# Bridgefu

**Connect anything.**

</div>

Bridgefu is a Rust media gateway that terminates two call legs and bridges
audio, DTMF, and explicitly allowed context between them. It is built on
[rvoip](https://github.com/eisenzopf/rvoip) and is designed to connect voice AI,
SIP, WebRTC, provider call control, and contact-center systems without making
either side understand the other.

[![Watch the 51-second Bridgefu explainer](media/explainer/scene-2.png)](media/explainer/bridgefu-explainer.mp4)

[Watch the explainer (MP4)](media/explainer/bridgefu-explainer.mp4) · [English captions](media/explainer/captions.srt)

The first product-qualified deployment target is a Vapi SIP transfer into
Amazon Connect with a correlated agent screen pop:

```mermaid
flowchart LR
    V["Vapi assistant"] -->|"SIP transfer + opaque correlation ID"| B["Bridgefu"]
    B -->|"WebRTC audio + contact attribute"| C["Amazon Connect"]
    L["AWS Lambda"] --> D["DynamoDB context"]
    C --> L
    L --> A["Agent screen pop"]
```

## Deploy Vapi transfers to Amazon Connect

The customer CloudFormation template, AMI build, Lambdas, Vapi provisioning,
and full live qualification harness live in the dedicated
[bridgefu-vapi-awsconnect](https://github.com/eisenzopf/bridgefu-vapi-awsconnect)
repository. That is the canonical place to deploy and operate this integration.

This repository owns the Bridgefu runtime and its built-in declarative recipe
contract. The deployment repository pins an immutable Bridgefu commit and
builds the customer AMIs from it.

## SIP security modes

- `sips_srtp` — TLS signaling and SDES-SRTP are required. This is the secure
  default.
- `sips_optional_srtp` — TLS signaling is required; Bridgefu negotiates SRTP
  when the peer offers it and accepts RTP/AVP otherwise. Use this deliberately
  for peers such as the currently observed Vapi transfer path that do not offer
  SRTP in SDP.
- `sip_rtp` — clear SIP and RTP. This is an explicit diagnostic compatibility
  posture, not the production default.

Managed SIPS recipes use one-use attachment URIs. Explicit external recipes can
use a trusted-source fixed URI with configurable context headers. Both advertise
a DNS `sips:` Contact; Bridgefu does not silently downgrade signaling from TLS.

For complete configurable Vapi → Amazon Connect setups, see the
[SIP-header and optional correlation-ID examples](examples/vapi-amazon-connect/README.md).

For networks that block direct Connect media, use the
[Connect TURN setup](docs/connect-turn.md) and
[restricted-egress test](examples/vapi-amazon-connect/tests/TURN.md).
Bridgefu 0.9.2 supports Connect's UDP relay with `ice_servers: []`.


## Try SIP ↔ WebRTC locally

With [Rust 1.95+, a C/C++ toolchain, and protobuf installed](examples/native-sip-webrtc/README.md#start-with-the-local-demo), run this **one line from the repository root**:

```sh
cargo run --locked --example native-sip-webrtc -- --settings examples/sip-to-webrtc/settings.example.json
```

It makes a real encrypted SIP → WebRTC call, verifies audio both ways, prints
**PASS**, and stops all demo endpoints. No cloud account or credentials are needed.
The first build can take several minutes. Change settings or try the reverse direction:

- [SIP caller → WebRTC service](examples/sip-to-webrtc/README.md)
- [WebRTC caller → SIP destination](examples/webrtc-to-sip/README.md)

Each guide includes a one-command demo, editable endpoint configuration, and
step-by-step setup. The [eight-case end-to-end matrix](examples/native-sip-webrtc/README.md#repeat-the-end-to-end-tests)
checks both codecs, both hangup directions, audio, and cleanup.

## Tested recipes and how to repeat them

Choose a recipe below for step-by-step setup. The test guides explain the
prerequisites, commands, expected results, and cleanup; the reports record
what actually passed.

| Recipe or scenario | What was tested | Repeat the test | Recorded results |
| --- | --- | --- | --- |
| [Vapi → Connect: SIP headers](examples/vapi-amazon-connect/sip-headers/README.md) | Live calls with exact header-to-contact attribute mapping and audio both ways; Connect UDP relay with `auto` and `join_ack`, direct media blocked, and `ice_servers: []`. | [Live environment setup](examples/vapi-amazon-connect/tests/E2E.md) → [restricted-egress steps](examples/vapi-amazon-connect/tests/TURN.md) | [November 25 live results](examples/vapi-amazon-connect/tests/TURN.md#recorded-qualification-november-25-2026--merged-main) · [JSON](examples/vapi-amazon-connect/tests/turn-results.json) |
| [Vapi → Connect: optional correlation ID](examples/vapi-amazon-connect/correlation-id/README.md) | Live context storage and Lambda lookup, exact attributes, two-way audio, missing/expired lookup-token checks, and `auto` relay with direct media blocked and `ice_servers: []`. | [Live environment setup](examples/vapi-amazon-connect/tests/E2E.md) → [correlation-ID relay test](examples/vapi-amazon-connect/tests/TURN.md) | [November 25 live results](examples/vapi-amazon-connect/tests/turn-results.json) |
| [Connect TURN negative control](docs/connect-turn.md) | Disabling the relay makes the call fail with actual firewall rejects and no relay allocation. This checks that the successful calls depended on TURN. | [Three-case TURN test](examples/vapi-amazon-connect/tests/TURN.md#3-run-the-three-cases-sequentially) | [November 25 live results](examples/vapi-amazon-connect/tests/turn-results.json) |
| [SIP → WebRTC](examples/sip-to-webrtc/README.md) | Local real-protocol calls with PCMU/PCMA, audio both ways, caller/destination hangup, and cleanup. | [One-command demo and eight-case matrix](examples/native-sip-webrtc/README.md) | [November 23 recorded matrix](examples/native-sip-webrtc/results.json) |
| [WebRTC → SIP](examples/webrtc-to-sip/README.md) | The reverse direction in the same local matrix, with both codecs and both hangup directions. | [One-command demo and eight-case matrix](examples/native-sip-webrtc/README.md) | [November 23 recorded matrix](examples/native-sip-webrtc/results.json) |

The November 25 live tests ran merged main `85527e2`, before the 0.9.2
version-only runtime metadata bump. The [0.9.2 release report](docs/release-0.9.2.md)
records the exact source, dependency pin, cleanup audit, and release checks.
The native matrix's checked-in report is historical 0.9.1 evidence; CI reruns
that matrix and retains fresh results with each [CI run](https://github.com/eisenzopf/bridgefu/actions/workflows/ci.yml).

The Connect tests restrict **Connect UDP media sockets**, while leaving SIP
and HTTPS/WSS control available. They qualify UDP TURN, not whole-host egress
allowlisting or TURN over TCP/TLS. The native examples use automated local
WebRTC peers; they do not qualify a browser, public NAT, or your carrier.
See [qualification scope](docs/qualification.md) for older evidence and limits.

## Local development

Bridgefu 0.9.2 pins every rvoip component to one immutable revision based
on `0.5.0`, recorded in `config/rvoip-source.txt` and `Cargo.lock`. No sibling
checkout is needed. See [Connect TURN setup and validation](docs/connect-turn.md).

```bash
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Inspect the embedded, credential-free recipe catalog with:

```bash
cargo run -- recipe available
cargo run -- recipe show builtin:vapi-amazon-connect-screen-pop@1
cargo run -- recipe validate builtin:vapi-amazon-connect-screen-pop@1 \
  --values recipes/vapi-amazon-connect-screen-pop/values.example.yaml
```

Low-level configuration remains available for custom integrations. Start with
[the product overview](docs/product-overview.md), [architecture](docs/architecture.md),
[configuration schema](config/schema.json), and [security model](docs/security.md).

Bridgefu is MIT licensed. See [CONTRIBUTING.md](CONTRIBUTING.md) for development
and security-reporting expectations.
