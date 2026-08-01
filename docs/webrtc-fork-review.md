# Private WebRTC/RTC alpha fork review packet

This packet records the local TURN candidate and the separate six-file
DTMF/codec/supplemental-encoding RTC candidate for project-owner review. It does
not authorize a push, dependency change, upstream issue, pull request, or
maintainer contact.

## Authoritative release inputs

Bridgefu now consumes exact crates.io
`rvoip-webrtc`/`rvoip-webrtc-stack`/`rvoip-rtc` 0.3.5 packages. The committed
Cargo.lock records their registry checksums and contains no Git or path package
source. The validation runs below predate that package migration and were
performed while both manifests temporarily used
`rtc = { path = "../rtc/rtc" }` and Bridgefu's generated lock entry was
path-resolved. Those overrides have been removed. Because the restored base
and candidate worktrees were not the current published graph, the recorded
RTC-dependent results remain local-composite validation rather than evidence
for the authoritative release build. The local TURN and DTMF candidates
described below must not be represented as qualified in 0.3.5 until their
behavior is rerun against the locked package set.

## Local candidate provenance

- WebRTC branch: `codex/udp-turn-relay-alpha`.
- WebRTC head: `4a2f64c4a10562bfbcf6e406afb197642e72c442`.
- RTC submodule branch: `codex/udp-turn-relay-hardening`.
- RTC submodule head: `4aa775a2c7d308b15075b544eaf667eba8584a6f`.
- The local WebRTC checkout has its push URL disabled.
- Neither candidate revision has been pushed or submitted upstream.

The validation worktree was not a clean two-revision checkout. Its RTC
submodule also contained an uncommitted four-file NACK/statistics candidate:

- `rtc/src/peer_connection/configuration/interceptor_registry.rs`
- `rtc/src/peer_connection/handler/endpoint.rs`
- `rtc/src/peer_connection/handler/interceptor.rs`
- `rtc/src/statistics/accumulator/rtp_stream/outbound.rs`

Those files negotiate generic NACK for Opus, bind a declared SSRC after
first-packet codec resolution, account for inbound RTCP feedback, and count
same-SSRC retransmissions. They were pre-existing shared work and were not
modified during the final rvoip WebRTC qualification. Until they are reviewed,
committed or removed, and the suite is rerun, the current 4/4 result belongs to
the composite worktree state—not solely to the two clean heads above.

## Candidate scope

The committed WebRTC fork adds UDP TURN allocation, permission, refresh,
release, relay-only gathering and routing, credential/configuration updates,
and cancellation-safe PeerConnection cleanup. Its candidate commit sequence is
currently local and awaits owner review:

- `56ed73d1` — UDP TURN relay transport.
- `c73afb86` — relay lifecycle and configuration hardening.
- `74009c95` — verified shutdown and allocation recovery.
- `4a2f64c4` — cancellation-safe TURN cleanup.

The RTC submodule contains the late-DataChannel/reliability base plus committed
TURN authentication, refresh, recovery, diagnostics, SCTP invalidation, and
tuple-validation changes through `4aa775a2`.

## Validation evidence

On 2026-07-14, the private WebRTC checkout's `turn_relay_e2e` suite passed 4/4
against an in-process UDP TURN server and observing proxy. It proves:

- relay-only DataChannel traffic crosses the TURN proxy in both directions;
- allocation, permission, relayed payload, and zero-lifetime release traffic
  are observed;
- dropping a peer releases its allocation;
- a configuration update changes TURN policy and credentials before gathering;
- invalid relay-only configuration is rejected without a partial core update.

The same downstream rvoip relay qualification does not pass with the
authoritative crates.io WebRTC alpha. Its fixture/construction case passes, but
the real two-peer media case selects a host local candidate instead of a relay
candidate. Inspection confirms the alpha wrapper ignores `gather_policy` and
implements host/STUN gathering only even though the underlying RTC core maps
`Relay` correctly. This is an engine-wrapper dependency gap, not an rvoip
statistics-label issue.

Separate rvoip-owned WebRTC qualification is green for all-feature
compilation, strict all-target no-dependency Clippy, 96 library tests, 10
principal-bound admission tests, five WHEP-04 tests, five secure
HTTP(S)/WS(S) target-contacting tests, seven outbound WHIP/WHEP/WS tests,
stalled-task supervision, and local ICE lifecycle. Those results complete the
signaling/admission/supervision work; they do not claim relay-only TURN on the
current dependency.

## RTC DTMF/codec/supplemental-encoding owner-review candidate

This is a separate, uncommitted candidate in the local RTC checkout. It is not
part of either TURN candidate revision above and does not change the
authoritative immutable RTC pin.

- Local branch: `codex/dtmf-codec-identity`.
- Base and current committed head: `1e5b7d4be6d94850694f2519f4c235d16c871d53`.
- Candidate state: six modified files in the working tree, with no candidate
  commit or immutable revision yet; 807 insertions and 130 deletions.
- Stable working-tree patch ID:
  `478b7da63ea6d195f446a9abce4c56e62129a86e`.
- Remote state: unpushed. No fork push, upstream issue, pull request, or
  maintainer contact is authorized.

The exact candidate files are:

- `rtc/src/peer_connection/handler/endpoint.rs`
- `rtc/src/peer_connection/internal.rs`
- `rtc/src/peer_connection/sdp/mod.rs`
- `rtc/src/rtp_transceiver/rtp_sender/internal.rs`
- `rtc/src/rtp_transceiver/rtp_sender/mod.rs`
- `rtc/src/rtp_transceiver/rtp_sender/rtp_codec.rs`

The candidate makes codec selection include MIME type, RTP clock rate, and
channel count, preventing `telephone-event/48000` from collapsing onto the
first registered 8 kHz telephone-event payload. It represents primary audio and
supplemental RFC 4733 encodings on one negotiated sender, but advertises only
the primary audio SSRC in SDP so the supplemental coding does not masquerade as
a second Unified Plan track. Only same-codec, non-empty-RID layers are treated
as RID simulcast, and no empty RID/simulcast lines are emitted.

On receive, SDP-declared SSRCs with the same MID, stream ID, and track ID are
grouped into one receiver track. An un-signaled supplemental SSRC is admitted
only when an authoritative MID selects a receiver that negotiated its payload
type, or when that payload type uniquely identifies one receiver; ambiguous or
unknown ownership fails closed. Existing primary coding is retained rather
than overwritten. On send, an explicitly requested payload type is preserved
only when the sender track represents it and it shares the selected encoding's
RTP clock; unnegotiated, unrepresented, or different-clock payloads retain the
legacy primary-payload rewrite.

The full RTC library is green in the local working tree:

```text
cargo test -p rtc --lib
# 180 passed, including all 13 candidate tests
```

Downstream rvoip evidence is also green only while resolving RTC through the
local path override:

```text
cargo test -p rvoip-webrtc --lib media::outbound::tests -- --nocapture
# 4 passed

cargo test -p rvoip-webrtc --test dtmf_wire -- --nocapture
# 3 passed

cargo test -p rvoip-webrtc --features signaling-whip --test browser_sdp_interop -- --nocapture
# 13 passed
```

For same-clock PT 110/48 kHz, rvoip's serialized outbound writer uses the
primary Opus SSRC and one monotonic sequence/timestamp state for audio and DTMF,
and includes the exactly negotiated SDES MID. Different-clock telephone-event
retains a supplemental encoding. The exact built-SDK Chromium handoffs to
generic SIP, generic WSS, Amazon Connect, and Telnyx all pass against this local
composite; the TypeScript SDK passes 20/20. Bridgefu library 328/328,
`private_forwarding` 7/7, `call_directionality` 3/3,
`call_execution_supervisor` 39/39, and StandardCharter's 48 core, 11 web, and
16 Python tests plus production web build are also green.

Those results prove only the recorded composite local checkouts. They do not
prove that the current published rvoip 0.3.5 package graph has equivalent
behavior.

Qualification now requires rerunning the focused suites, full WebRTC
regressions, all four exact Chromium destinations, and the StandardCharter
regression gate against Bridgefu's committed Cargo.lock. If that exposes a
missing engine fix, the project owner must review the minimal fork diff and
approve a clean rvoip package update before Bridgefu changes versions. No fork
push or upstream contact is authorized by this packet.

## Owner-review and adoption sequence

1. Review the committed WebRTC and RTC TURN deltas, the separate four-file
   NACK/statistics worktree delta, and the six-file
   `codex/dtmf-codec-identity` candidate.
2. Decide which deltas belong in the same coordinated revision, then produce a
   clean candidate pair without mixing unreviewed working-tree state.
3. Rerun the RTC suite, the private WebRTC 4/4 TURN suite, rvoip's real
   relay-only media suite, and the DTMF wire/browser-SDP suites against that
   exact clean pair. The downstream rvoip
   assertions are explicitly opt-in with `--features turn-fork-candidate`;
   without the reviewed fork, default CI lists them as ignored instead of
   falsely claiming that the crates.io alpha supports relay-only gathering.
4. Only after explicit project-owner approval, create immutable revisions on an
   owner-approved private remote.
5. Update rvoip and Bridgefu pins and lockfiles together, verify the fetched
   source, and rerun the full WebRTC, all four exact Chromium destinations, and
   StandardCharter regressions.
6. Retain the exact commands, revisions, dirty flags, and packet-level evidence
   in release qualification.

No step above authorizes upstream contact. Any future upstream proposal needs a
separate explicit project-owner review after the private integration is stable.
Stock Vapi `webCall`→SIP feasibility, protected Vapi/AWS canaries, live
PBX/Amazon/Telnyx accounts, TURN-only/public-NAT, built-SDK split execution,
process restart, AWS/GCP apply-smoke-destroy, and one-hour load/chaos campaigns
remain separate owner-authorized or external release blockers.
