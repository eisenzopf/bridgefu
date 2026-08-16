# MOQT packet-capture conformance

The managed relay suite has reproducible packet-level evidence for both raw
QUIC and WebTransport. Captures are written outside the repository, contain no
TLS key log, and are never treated as application-semantic evidence on their
own. The paired Rust tests verify authentication, exact protocol compatibility,
Joining FETCH/live fallback, catalog parsing, lifecycle, and cleanup.

Run:

```bash
RVOIP_REVIEWED_REVISION=8dab9d14a49178fa5f9a3e48ed6c1388272bfe58 \
  ./scripts/capture-moq-managed-relay.sh
```

This command is a source-level rvoip protocol-qualification tool, not a
Bridgefu build input. Bridgefu resolves the published `rvoip-moq = 0.3.8`
package from crates.io through Cargo.lock. Release-quality capture is the
default and requires `RVOIP_REVIEWED_REVISION` to be an exact 40-character
commit matching `HEAD`. The rvoip worktree must be clean and remain at the same
revision and tree state for the entire run. Choose the revision only after
review; do not derive it from `HEAD` in the capture command.

Set `RVOIP_DIR`, `ARTIFACT_DIR`, or `CAPTURE_INTERFACE` when the repositories or
loopback interface differ. The script requires permission to capture the
loopback interface and fails rather than silently skipping packet evidence. It
always stops `tcpdump`, validates a non-empty QUIC capture with `tshark`, and
requires both the `moqt-19` raw-QUIC ALPN and the `h3` WebTransport substrate.
The JSON report records the reviewed and observed revisions, clean/stable tree
checks, and test counts parsed from the Cargo result rather than assumed.

For local investigation of unreviewed or dirty source, opt in explicitly:

```bash
RVOIP_CAPTURE_MODE=diagnostic ./scripts/capture-moq-managed-relay.sh
```

Diagnostic reports always set `releaseQualified` to `false`, even when the
checkout happens to be clean. They cannot be promoted into release evidence
after the fact.

## Recorded run

The 2026-07-12 run used rvoip
`8dab9d14a49178fa5f9a3e48ed6c1388272bfe58` and private wire revision
`ef52ac8656513bb3b07b4b9b80152ac24bb2467e`.
This historical run predates the clean/stable source checks and
`releaseQualified` report field. It remains packet-path evidence, but must be
recaptured under the current release mode before it is used as release-quality
source evidence.

- Both managed relay tests passed: one raw QUIC and one WebTransport.
- The loopback capture contained 166 QUIC packets, 45,441 captured packet
  bytes, a 48,121-byte PCAP file, and zero kernel drops over 29.639 ms.
- `tshark` decoded four `moqt-19` ALPN handshakes and two `h3` ALPN handshakes.
- The ephemeral capture's SHA-256 was
  `7ba99e6088ee56c14a9b493348cdeceba4181739abf43a3db3bca102c762f4da`.

The capture was intentionally left at
`/tmp/bridgefu-moq-capture-script-test-3/managed-relay.pcap` rather than checked
in. QUIC payloads remain encrypted; this evidence confirms the packet path and
negotiated substrates while the executable protocol tests confirm MOQT, MSF,
LOC, authorization, and retained-object semantics. TLS key logging is neither
needed nor enabled.
