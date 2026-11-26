# Bridgefu 0.9.3 release checks

This release moves Bridgefu and the Vapi/Connect SIP test client to exact
crates.io `=0.5.1` rvoip dependencies. It preserves the published 0.9.2 tag.
Customer configuration remains unchanged, including header mappings, TURN
credential sources, relay-only policy, timeouts, and static ICE servers.

## Dependency checks

Both Cargo lockfiles must be resolved against the published registry packages.
CI checks both lockfiles for registry checksums and exact rvoip 0.5.1
components, and compiles the SIP test client with `--locked`. Runtime
smoke and image checks enforce the same rvoip source/version contract.

The application resolves 27 rvoip components and the standalone SIP client
resolves 16. Their checksums match the rvoip release archives. Compared with
0.9.2, all non-rvoip versions and checksums are unchanged in both lockfiles.
The resolved dependency links and enabled features are also unchanged, apart
from the application/rvoip version and source changes.

The rvoip release commit, `673b3e29af9e270309fb7d17c5fd767179086f49`, has the
same production Rust sources as the live-tested TURN revision below. Its
changed Cargo manifests contain only the coordinated version bump. Release
packaging built all 48 archives, and the source audit matched all 2,538
packaged Rust files to that release commit.

Before publication, run the full Bridgefu CI suite against the resolved graph:
formatting, Clippy, Rust tests, coordination tests, runtime smoke, the native
SIP/WebRTC example matrix, and both image platforms. The release notes link to
the final passing main run. The source release does not publish an OCI image.

The [0.9.3 release page](https://github.com/eisenzopf/bridgefu/releases/tag/v0.9.3)
links the passing final-main CI run and retains these redacted result files:

- `release-results.json`: the exact release commit, CI run, registry/source
  verification summary, and the native report's checksum.
- `bridgefu-native-results.json`: all eight SIP/WebRTC call results, including
  bidirectional audio and endpoint cleanup.

The [rvoip 0.5.1 release](https://github.com/eisenzopf/rvoip/releases/tag/v0.5.1)
retains its signed qualification reports and `SHA256SUMS` for all 48 crates.

## Live evidence and reproduction

The [November 25 live report](../examples/vapi-amazon-connect/tests/turn-results.json)
records restricted Connect UDP egress with `ice_servers: []`, exact contact
attributes, bidirectional audio, and the relay-disabled negative control.
Those calls used Bridgefu commit `85527e2313776886e53dba606384945c9074271d` and
rvoip commit `529293064953c94c0b021c43e46d03d878922d0c`, before the 0.9.2 version
bump. They are not a new live run of the 0.9.3 registry build. The
[0.9.2 report](release-0.9.2.md) records the environment and completed cleanup.

Start with [Connect TURN configuration](connect-turn.md), choose the
[SIP-header recipe](../examples/vapi-amazon-connect/sip-headers/README.md) or
[correlation-ID recipe](../examples/vapi-amazon-connect/correlation-id/README.md),
and follow the [live setup](../examples/vapi-amazon-connect/tests/E2E.md) and
[restricted-egress test steps](../examples/vapi-amazon-connect/tests/TURN.md).
Use your own account, credentials, destinations, headers, and context values.
The runbook includes cleanup.

For native SIP/WebRTC calls, use the recipes and repeatable test commands in
the [tested-scenarios table](../README.md#tested-recipes-and-how-to-repeat-them).

## Scope

Connect TURN support remains UDP-only. The earlier live firewall constrained
Connect media sockets, not whole-host egress. The ICE candidate retry budget
is unchanged. Benchmarks, long-running load/soak tests, arbitrary NATs, and
every AWS region are outside this release's evidence.
