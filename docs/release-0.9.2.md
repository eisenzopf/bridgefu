# Bridgefu 0.9.2 release checks

Bridgefu 0.9.2 adds configurable Amazon Connect UDP TURN support on the merged
rvoip 0.5.0 implementation. This is a source release, with a Git tag and
GitHub-generated source archives. It does not publish a container image or
an rvoip release. The TypeScript SDK version is unchanged.

## What changed

- The Connect leg obtains temporary TURN credentials per contact. `auto`
  prefers Chime `JOIN_ACK`; `join_ack` requires that signaling source.
- `aws.turn.relay_only: true` requires an allocated UDP relay and avoids
  falling back to blocked direct media destinations.
- `generic_bridge.webrtc.ice_servers: []` disables public STUN while retaining
  per-contact Connect TURN provisioning.
- Header names, context fields, Connect attributes, credential sources,
  timeouts, and local port ranges remain customer configurable.
- All 27 rvoip components use merged revision
  `529293064953c94c0b021c43e46d03d878922d0c`. The upgrade and TURN changes remain
  separately reviewable in [PR #8](https://github.com/eisenzopf/bridgefu/pull/8)
  and [PR #9](https://github.com/eisenzopf/bridgefu/pull/9).
- A test-only setup-budget adjustment in
  [PR #10](https://github.com/eisenzopf/bridgefu/pull/10) lets the deferred SIP
  destination be reached before the cancellation/cleanup assertions run.

## Live test provenance

The fresh qualification uses merged main
`85527e2313776886e53dba606384945c9074271d`, built with
`cargo build --locked --release` on a disposable Linux ARM64 gateway.
The 0.9.2 release preparation changes version metadata, documentation, and
redacted evidence; it does not change the tested production implementation or
rvoip pin. See the exact revisions and results in the
[live report](../examples/vapi-amazon-connect/tests/turn-results.json).

The [runbook](../examples/vapi-amazon-connect/tests/TURN.md) reproduces real
Vapi → Bridgefu → Connect browser-agent calls with empty static ICE servers.
Its firewall allows only the configured relay destinations for Connect UDP
sockets, rejects other destinations and IPv6 on those sockets, and leaves
SIP and HTTPS/WSS control available. A relay-disabled call must fail with
actual firewall rejects; a failed call alone is not sufficient evidence.

On November 25, all four live cases passed: SIP headers with `auto` and
`join_ack`, the relay-disabled negative control, and correlation ID with
`auto`. Successful calls passed generated audio probes in both directions,
exact context comparison, relay selection, and zero-active-call cleanup.
The disabled case failed with firewall rejects and no relay allocation.
The correlation case also passed the deployed missing/expired-token checks.

A separate cleanup audit confirmed removal of the six disposable stacks,
Connect instance, gateway storage and public address, DNS, artifact bucket,
secrets, Vapi assistants/SIP entries, and recording/transcript/analysis data for
the ended test calls. No test Lambda log groups remained and the gateway was
verified terminated. Vapi retains historical operational call metadata; that
retained history is not an active test resource.

## Release checks

The release requires passing test, infrastructure, AMD64 image, and ARM64
image CI jobs. Those jobs check formatting, strict Clippy, the locked rvoip
graph, the full Rust suite, PostgreSQL/Redis coordination, runtime smoke,
native SIP/WebRTC examples, image execution, SBOMs, and vulnerability policy.
The release tag must point to the checked main commit.

Local release checks passed: CLI reports `bridgefu 0.9.2`, locked metadata
matches the package version and merged dependency pin, 11 example tests pass,
and formatting, configuration-schema, image-policy, and whitespace checks pass.
The final source release notes link to its passing protected CI run.

Gitleaks 8.30.1 findings were reviewed: 40 occurrences of the known synthetic
test key and eight `YOUR_TOKEN` documentation placeholders. No live secrets
were found. Known private test identifiers, addresses, and credentials were
checked against the publishable tree. Customer-branded references were absent.
Raw state, credentials, and call evidence remain outside the repository.

## Reproduce and deploy

Start with the [Connect TURN setup](connect-turn.md). Preserve your existing
routes and header mappings, select `auto` or `join_ack`, require a relay for a
restricted-egress deployment, and set the static ICE list to `[]`. Allow the
current AWS relay network and UDP port while retaining required control and
SIP traffic. All network values are deployment configuration.

Run the [three live cases](../examples/vapi-amazon-connect/tests/TURN.md), then
remove the disposable environment using that runbook's cleanup command.
[The previous release report](release-0.9.1.md#repeat-the-checks) lists the
local validation commands; current CI is the final release check.

## Scope

This release supports TURN over UDP. It does not add TURN over TCP/TLS,
replace credentials during an established contact, or extend the ICE retry
budget. The candidate-check retry budget and overall connection deadline
remain separate; the fix supplies a reachable relay candidate.

Forced legacy `turn_control_url` mode was not qualified by the earlier live
sandbox, which rejected its HTTP request. The supported recipe uses `auto`
or `join_ack`. This qualification does not establish whole-host egress
allowlisting, every region, long-duration or load behavior, or customer QA
acceptance. [Historical evidence](../examples/vapi-amazon-connect/tests/E2E.md)
remains identified by its original date and source.
