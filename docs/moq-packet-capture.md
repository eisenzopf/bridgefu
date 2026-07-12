# MOQT packet-capture conformance

The managed relay suite has reproducible packet-level evidence for both raw
QUIC and WebTransport. Captures are written outside the repository, contain no
TLS key log, and are never treated as application-semantic evidence on their
own. The paired Rust tests verify authentication, exact protocol compatibility,
Joining FETCH/live fallback, catalog parsing, lifecycle, and cleanup.

Run:

```bash
./scripts/capture-moq-managed-relay.sh
```

Set `RVOIP_DIR`, `ARTIFACT_DIR`, or `CAPTURE_INTERFACE` when the repositories or
loopback interface differ. The script requires permission to capture the
loopback interface and fails rather than silently skipping packet evidence. It
always stops `tcpdump`, validates a non-empty QUIC capture with `tshark`, and
requires both the `moqt-19` raw-QUIC ALPN and the `h3` WebTransport substrate.

## Recorded run

The 2026-07-12 run used rvoip
`8dab9d14a49178fa5f9a3e48ed6c1388272bfe58` and private wire revision
`ef52ac8656513bb3b07b4b9b80152ac24bb2467e`.

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
