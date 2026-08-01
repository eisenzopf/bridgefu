# Release qualification

Bridgefu keeps short correctness checks separate from release evidence. A
passing smoke run proves only that the harness and the current media graph work
on the local machine; it does not satisfy a one-hour roadmap item.

## Bridgefu 0.9.0 customer-preview boundary

Bridgefu 0.9.0 is the first customer-preview release toward the 1.0 roadmap.
Its Rust package, CLI, and OCI metadata use `0.9.0`; the TypeScript SDK remains
independently versioned at `0.1.0`. The preview retains the exact crates.io
rvoip 0.3.5 graph and discloses the generic-WSS outbound-DTMF limitation tracked
as rvoip #54. It does not claim the still-open 1.0 TURN/public-NAT, fourth
exact-Chromium destination, live-provider, cloud, or one-hour load gates.

An exact clean Bridgefu commit and the protected, non-published
`linux/amd64,linux/arm64` OCI qualification artifact are the remaining 0.9.0
candidate gates. Repository publication, public images, and production changes
remain separately owner-authorized actions.

## Historical stable-tree correctness matrix

The following 2026-07-14 matrix was recorded before the later Vapi
full-duplex (`VF-*`) working-tree changes. It remains useful baseline evidence,
but its counts must not be represented as the current tree's final matrix:

- Bridgefu locked all-target tests: 546 passed, 0 failed, 12 ignored.
- The seven ignored datastore cases pass when explicitly enabled against the
  isolated disposable PostgreSQL and Redis services; together with repository
  conformance, the live-store matrix is 28/28.
- The remaining five Bridgefu ignores are the explicit manual Gate 11 media,
  UCTP-direct, UCTP-network, MOQT, and chaos harnesses.
- Bridgefu strict all-target no-dependency Clippy, formatting, and whitespace
  checks pass.
- The selected rvoip auth/core/UCTP/QUIC/WebTransport/MOQT all-target and
  strict-Clippy matrices pass. Rvoip WebRTC passes 114 tests with exactly two
  ignored owner-gated TURN candidate tests.

These counts prove only the recorded baseline tree. The subsequent dirty
coordinated trees, short smokes, ignored release harnesses, and credential-free
infrastructure checks do not constitute a release candidate or any external
qualification. A new exact all-target count must be retained after every
`VF-*` local blocker is resolved.

## Transcoded worker-media harness

The ignored `qualification_media_graph` test creates two media graphs per call:
PCMU to Opus and Opus to PCMU. Every source emits a canonical 20 ms frame. The
harness retains the exact Bridgefu revision and dirty-worktree state, every
locked rvoip 0.3.5 package plus its crates.io checksum, host data,
frame/drop/transcode counts, a fixed-bucket p95 latency bound, and post-warmup
RSS in a versioned JSON report.

Run a short local smoke:

```sh
BRIDGEFU_QUALIFICATION_MODE=smoke \
  cargo test --locked --test qualification_media_graph -- \
  --ignored --exact qualifies_bidirectional_transcoded_worker_media --nocapture
```

Smoke duration and call count may be bounded explicitly with
`BRIDGEFU_QUALIFICATION_SMOKE_SECONDS` (3–60) and
`BRIDGEFU_QUALIFICATION_SMOKE_CALLS` (1–100).

Run the release profile only on the intended Linux qualification host:

```sh
BRIDGEFU_QUALIFICATION_MODE=release \
BRIDGEFU_QUALIFICATION_ACKNOWLEDGE_ONE_HOUR=1 \
BRIDGEFU_QUALIFICATION_OUTPUT=/retained-evidence/media.json \
  cargo test --release --locked --test qualification_media_graph -- \
  --ignored --exact qualifies_bidirectional_transcoded_worker_media --nocapture
```

Release parameters cannot be overridden: 100 bidirectional transcoded calls,
a 10-call-attempt/s ramp, five minutes of warm-up, and one hour with all calls
active. The run fails for source or graph drops, sink eviction, transcode
errors, delivery below 99%, p95 bridge latency above 100 ms, RSS growth of 10%
or more, an incomplete hour, or a ramp longer than 12 seconds. The JSON report
is written before the final assertion so failed evidence is retained too.

This harness qualifies the worker MediaGraph/transcoder path. It does not by
itself qualify real SIP/WebRTC signaling, RTP network behavior, UCTP fanout,
MOQT relay fanout, provider control, or cloud topology; those remain separate
roadmap scenarios.

A final 2026-07-14 one-call, three-second macOS smoke delivered 302/302 frames
and completed 302 transcodes with no source/graph drops, sink evictions, or
transcode errors. Its p95 upper bound was 1.1 ms and post-warmup RSS growth was
0.71%. This is current-tree harness evidence, not the immutable one-hour result.

## UCTP direct-fanout harness

The ignored `qualification_uctp_fanout` test drives the public
`UctpBroadcastPublisher` at the canonical 20 ms cadence. Each listener owns a
bounded receive queue and an independent consumer task. The report contains no
listener identifiers: it retains only aggregate deliveries, the minimum and
maximum per-listener delivery counts, publisher drops, p95 queue latency, RSS,
the exact revisions, and the configured capacity rejection result.

Run a short local smoke:

```sh
BRIDGEFU_QUALIFICATION_MODE=smoke \
  cargo test --locked --test qualification_uctp_fanout -- \
  --ignored --exact qualifies_uctp_direct_fanout --nocapture
```

Smoke duration and listener count may be bounded with
`BRIDGEFU_UCTP_SMOKE_SECONDS` (3–60) and
`BRIDGEFU_UCTP_SMOKE_LISTENERS` (1–1,000). A transport-specific output path may
be supplied as `BRIDGEFU_UCTP_QUALIFICATION_OUTPUT`; otherwise the report is
written beneath `target/qualification`.

Run the fixed release profile only on the intended Linux qualification host:

```sh
BRIDGEFU_QUALIFICATION_MODE=release \
BRIDGEFU_QUALIFICATION_ACKNOWLEDGE_ONE_HOUR=1 \
BRIDGEFU_UCTP_QUALIFICATION_OUTPUT=/retained-evidence/uctp-fanout.json \
  cargo test --release --locked --test qualification_uctp_fanout -- \
  --ignored --exact qualifies_uctp_direct_fanout --nocapture
```

Release parameters cannot be overridden: 1,000 listeners, one hour active,
five minutes before the RSS baseline, at least 99% delivery, no source-queue
drops, a 100 ms p95 queue-latency ceiling, and less than 10% post-warmup RSS
growth. The run also proves that the 1,001st target is rejected.

This is a real qualification of rvoip's bounded nonblocking publisher fanout
to the already-authenticated target queues installed for network subscribers.
It does not create 1,000 QUIC handshakes or validate 1,000 RTP datagram paths;
the smaller authenticated public-listener and UCTP 0.2 packet-conformance tests
cover those boundaries. A release claim about 1,000 simultaneous network peers
therefore needs the retained load report together with those conformance tests
and the deployment smoke.

A final 2026-07-14 16-listener, three-second macOS smoke delivered all 154
source frames to every listener (2,464/2,464 deliveries), with no source or
publisher drops. It verified rejection beyond the configured 1,000-listener
capacity, measured a 0.4 ms p95 upper bound, and observed 0.64% post-warmup RSS
growth. This qualifies the local bounded-fanout harness only.

## Authenticated UCTP network harness

The separate ignored `qualification_uctp_network` test exercises the complete
localhost raw-QUIC path instead of replacing the bounded publisher harness. It
creates one independently authenticated, receive-only UCTP Session and
Connection per listener through `PublicUctpBroadcastListener`, resolves the
Bridgefu broadcast grant, subscribes through the real rvoip Orchestrator, and
receives media from a MediaGraph-backed virtual publisher. Every received
datagram is parsed as the UCTP 0.2 eight-byte header followed by one complete
RTP packet. The report records aggregate and per-listener delivery, setup and
media latency, token refreshes, protocol errors, unsubscribe acknowledgements,
and exact route, connection, permit, and publisher cleanup.

Run a short local smoke:

```sh
BRIDGEFU_QUALIFICATION_MODE=smoke \
  cargo test --locked --test qualification_uctp_network -- \
  --ignored --exact qualifies_authenticated_uctp_network_fanout --nocapture
```

Smoke duration, listener count, and setup rate may be bounded with
`BRIDGEFU_UCTP_NETWORK_SMOKE_SECONDS` (3–60),
`BRIDGEFU_UCTP_NETWORK_SMOKE_LISTENERS` (1–32), and
`BRIDGEFU_UCTP_NETWORK_SMOKE_ATTEMPTS_PER_SECOND` (1–100). Use
`BRIDGEFU_UCTP_NETWORK_QUALIFICATION_OUTPUT` for a retained report path. Smoke
credentials deliberately start with a three-second lifetime, rotate to
six-second credentials every second, and delay the refreshed-token replay probe
until after the initial credential expires. This lets a short run prove real
`auth.refresh`, stable ownership, replay-ID rotation, and rejection of second
peers using either the original or refreshed credential.

Run the fixed release profile only on an appropriately sized Linux host:

```sh
BRIDGEFU_QUALIFICATION_MODE=release \
BRIDGEFU_QUALIFICATION_ACKNOWLEDGE_ONE_HOUR=1 \
BRIDGEFU_UCTP_NETWORK_QUALIFICATION_OUTPUT=/retained-evidence/uctp-network.json \
  cargo test --release --locked --test qualification_uctp_network -- \
  --ignored --exact qualifies_authenticated_uctp_network_fanout --nocapture
```

Release parameters cannot be overridden: 1,000 real listeners, 100 connection
attempts per second, a ten-minute setup deadline, five minutes before the RSS
baseline, and one hour active. Listener credentials have a ten-minute lifetime
and refresh every five minutes using a stable credential owner with a rotating
replay ID. The run requires at least 99% delivery, complete valid RTP datagrams,
no unmatched timestamps or protocol errors, a 100 ms p95 media-latency ceiling,
less than 10% post-warmup RSS growth, and zero retained connections, routes,
listener permits, or publisher registrations after graceful shutdown.

A final 2026-07-14 four-listener, three-second macOS smoke delivered 612/612
complete RTP datagrams from 153 source frames after 20 successful wire
refreshes. The
original-token replay was rejected, and a current refreshed-token replay was
still rejected after the initial reservation would have expired. The original
peers remained active and received the measured media. The run observed no
invalid packets, sequence discontinuities, unmatched timestamps, protocol
errors, or cleanup leaks and a 7.3 ms aggregate p95 latency upper bound. It
retained zero routes, connections, direct-listener permits, or publisher
registrations after shutdown. This
proves the local end-to-end harness executes; it is not the immutable one-hour
result and does not qualify a deployed gateway, worker, load balancer, or
adverse network.

## Canonical broadcast-codec acceptance

The managed UCTP broadcast path requests canonical Opus 48 kHz mono from the
rvoip MediaGraph instead of inheriting a SIP source codec. rvoip consumes the
source receiver once, reuses one transcode group for same-codec sinks, publishes
payload type 111, and advances 20 ms Opus timestamps by 960 across wraparound.
The Bridgefu shape checks cover both PCMU and PCMA sources and verify that the
registry descriptor and emitted packet agree on canonical Opus.

Run the reusable rvoip and Bridgefu checks from their respective repositories:

```sh
CARGO_INCREMENTAL=0 cargo test -p rvoip-core --test virtual_publisher
```

```sh
CARGO_INCREMENTAL=0 cargo test --locked --lib \
  broadcast::managed::shape_tests -- --nocapture
```

The current local results are 5/5 rvoip virtual-publisher tests and 9/9
Bridgefu managed-broadcast shape tests. These are functional codec and graph-
ownership checks. They do not substitute for a receive-only split-gateway wire
test, either one-hour UCTP load profile, or deployed-network evidence.

## MOQT relay-session harness

The ignored `qualification_moq_relay` test starts separate publisher-mTLS and
subscriber raw-QUIC listeners over a shared embedded rvoip relay topology. Each
simulated listener is a real MOQT draft-19 QUIC connection with an independently
issued credential and an rvoip-managed MSF/LOC audio subscription. Each handle
uses one authenticated session for the catalog compatibility gate and the
`audio/main` subscription, with the same reconnect and drain supervisor. The
origin concurrently publishes canonical 20 ms Opus frames. The report compares
publisher queue admission with both rvoip's origin counter and every listener's
bounded received-object stream while retaining relay health, setup p95, source
admission-to-receiver latency, and RSS.

Run a short local smoke:

```sh
BRIDGEFU_QUALIFICATION_MODE=smoke \
  cargo test --locked --test qualification_moq_relay -- \
  --ignored --exact qualifies_moqt_origin_through_relay --nocapture
```

Smoke duration, listener count, and connection ramp may be bounded with
`BRIDGEFU_MOQT_SMOKE_SECONDS` (3–60),
`BRIDGEFU_MOQT_SMOKE_LISTENERS` (1–10,000), and
`BRIDGEFU_MOQT_SMOKE_ATTEMPTS_PER_SECOND` (1–500). Use
`BRIDGEFU_MOQT_QUALIFICATION_OUTPUT` for a retained report path.

Run the fixed release profile only on a Linux host with sufficient UDP sockets,
file descriptors, memory, and CPU for 10,000 concurrent QUIC clients:

```sh
BRIDGEFU_QUALIFICATION_MODE=release \
BRIDGEFU_QUALIFICATION_ACKNOWLEDGE_ONE_HOUR=1 \
BRIDGEFU_MOQT_QUALIFICATION_OUTPUT=/retained-evidence/moqt-relay.json \
  cargo test --release --locked --test qualification_moq_relay -- \
  --ignored --exact qualifies_moqt_origin_through_relay --nocapture
```

Release parameters cannot be overridden: 10,000 listeners ramped at 500
attempts/s, a ten-minute setup deadline, one hour with every subscriber live,
zero reconnects or source drops, exact admitted-frame/audio-object agreement,
exact per-listener receipt with no bounded-receiver lag, under 100 ms p95
source-admission-to-receiver latency, healthy publisher and relay lifecycles,
clean subscriber shutdown, and less than 10% post-warmup RSS growth.

The rvoip-owned `MoqAudioSubscriber` exposes only validated `LocAudioObject`
events and safe snapshots; draft-specific moq-rs types remain private. Its
catalog, audio, authorization, reconnect, and drain paths run over raw QUIC and
WebTransport in focused real-relay tests without requiring a moq-rs fork
change. A final four-listener, three-second raw-QUIC smoke on 2026-07-14
delivered 151/151 objects to every listener (604 samples), with zero lag,
unmatched timestamps, reconnects, or cleanup errors, 10 ms p95, 16 ms maximum
measured latency, and 0.66% post-warmup RSS growth. The release checkbox
still remains open until the immutable 10,000-listener one-hour run and a
separately deployed relay-tier/cloud smoke are retained.

## Hermetic SIP/WebRTC wire acceptance

The rvoip-owned `sip_webrtc_acceptance` integration test exercises the
production adapters and runtime rather than fake adapters or direct graph-only
fixtures. It prepares and commits real `SipAdapter` and `WebRtcAdapter` legs
through `Orchestrator`, bridges them with the production `MediaGraph`, uses a
raw peer only at the external SIP/RTP boundary, and reaches a second production
rvoip WebRTC server over WHIP or persistent WebSocket signaling.

Run the sequential localhost matrix from the rvoip repository:

```sh
cargo test -p rvoip-webrtc --test sip_webrtc_acceptance \
  --features tls-rustls,signaling-whip,signaling-ws -- --nocapture
```

The single integration test runs three independent bidirectional cases:
PCMU↔Opus over WHIP, PCMA↔Opus over WS, and PCMU↔Opus over WSS with a scoped
test trust bundle. It then runs canonical secure WHEP-04 PCMA→Opus playback as
a separate one-way role. The bidirectional cases verify actual RTP across the
SIP and WebRTC boundaries, negotiated payload types, 160-byte 20 ms G.711
frames, non-empty Opus, graph transcoding, and zero graph drops or evictions.
They verify RFC 4733 in both directions, arbitrary labeled binary
DataChannel→in-dialog SIP MESSAGE, subsequent `bridgefu.context.v1` SIP
MESSAGE→the exact DataChannel, exact allowlisted initial INVITE headers, remote
SIP BYE, no media after teardown, terminal source graphs, and zero retained
bridges, routes, signaling resources, media pumps, peer sessions, SIP tasks,
or Orchestrator lifecycle tasks. The WSS case additionally declares an SDP RTP
port different from its actual source and proves the production symmetric-RTP
path returns media to the learned tuple.

The focused reusable checks are:

```sh
cargo test -p rvoip-webrtc --lib \
  opus_rtp_channels_are_normalized_to_the_negotiated_signal_shape \
  --features signaling-whip,signaling-ws

cargo check -p rvoip-core -p rvoip-sip -p rvoip-webrtc \
  --features rvoip-webrtc/tls-rustls,rvoip-webrtc/signaling-whip,rvoip-webrtc/signaling-ws

cargo clippy -p rvoip-webrtc --features tls-rustls,signaling-whip,signaling-ws \
  --lib --test sip_webrtc_acceptance --no-deps -- -D warnings

cargo test -p rvoip-webrtc --test outbound_whip_originating \
  --features signaling-whip -- --nocapture

cargo test -p rvoip-sip --test nat_advertisement_network

cargo test -p rvoip-sip --test resilience_rfc3581_rport_nat_recovery \
  rport_response_routing_survives_source_port_rewrite

cargo test -p rvoip-rtp-core \
  symmetric_rtp_latches_valid_source_and_bounds_rebinding
```

The outbound WHIP target runs four cases; two retain normal resource lifecycle
coverage, while candidate-less ICE and a mismatched answer fingerprint prove
bounded ICE/DTLS failure and exact two-route cleanup. The focused SIP/RTP tests
prove advertised public signaling/media addresses, RFC 3581 `rport` recovery
after a source-port rewrite, and bounded symmetric-RTP learning/rebinding.

Run the Bridgefu durable-actor attachment and initial-context ownership checks
from the Bridgefu repository:

```sh
cargo test --locked --test call_execution_supervisor \
  authenticated_real_sip_request_uri_attachment_reaches_the_durable_call_actor \
  -- --nocapture

cargo test --locked --test call_execution_supervisor \
  required_context_is_owned_persisted_and_applied_before_the_first_sip_invite \
  -- --nocapture
```

The first case uses a production tenant-authenticated `SipAdapter`, a real SIP
caller, and Bridgefu's hashed single-use two-minute request-URI token. The SIP
leg becomes durably connected only after the real ACK, the peer attaches with
its own explicit token rather than FIFO pairing, one bridge becomes active,
and remote BYE releases both legs and all lifecycle tasks on the normal stack.
The second case proves the actor owns and persists required initial context
before originate; the production rvoip wire case above independently proves
those allowlisted initial headers exactly. This split is intentional and is
not described as one monolithic edge-to-edge DataChannel test.

The reusable local adapter and durable-actor matrix is complemented by
Bridgefu's split-role composition test
`native_whip_edge_reaches_call_pinned_worker_over_mtls_uctp_and_drains_cleanly`.
It runs a real native WHIP peer through exact bearer/attachment routing, mTLS
UCTP 0.2, the call-pinned durable worker and MediaGraph, bidirectional Opus,
context DataMessages, RFC 4733 DTMF, terminal teardown, and zero retained
native/private routes, bridges, or worker lifecycle tasks. WSS and WHEP retain
their separate first-party rvoip boundary tests. RTCP is intentionally
hop-by-hop when transcoding changes packet identity; the native termination
behavior and byte-exact private RTCP path are tested separately.

The complete `private_forwarding` target passes 7/7. Its exact durable
replacement case
`durable_actor_routes_whip_to_split_sip_and_wss_egress_with_authoritative_lifecycle`
also passes three consecutive post-fix runs. It proves a failed destination
generation compensates before a later generation promotes, the old generation
receives exact cleanup, remote terminal delivery remains journaled until its
durable acknowledgement, and gateway drain releases every private admission,
proxy route, graph bridge, and native route. This is hermetic loopback evidence
with adapter fixtures and in-memory call authority, not a separate-process
Redis restart, non-loopback peer, built-SDK split, or deployed result.

Separately, the named Vapi SIP attachment boundary has focused non-media
regressions for the control-principal/listener-principal split. They require an
exact tenant/profile/revision match, reject missing, stale, cross-tenant, and
multiple ingress bindings, prove the API route owner cannot consume the SIP
token, prove the configured Vapi identity can consume it only once, and verify
that configuration builds the same principal for listener projection and
attachment authorization. Run them with:

```sh
cargo test -p bridgefu --lib --no-default-features \
  configured_attachment_resolver_requires_exact_vapi_snapshot_and_preserves_generic_policy \
  -- --nocapture
cargo test -p bridgefu --lib --no-default-features \
  named_vapi_sip_token_rejects_api_owner_and_accepts_configured_listener_identity_once \
  -- --nocapture
cargo test -p bridgefu --bin bridgefu --no-default-features \
  referenced_vapi_profile_projects_one_identity_into_listener_and_attachment_resolver \
  -- --nocapture
```

All three focused tests pass. This proves local identity selection and token
ownership, not stock Vapi `webCall` transfer feasibility, media flow, or any
live Vapi/provider topology.

The all-in-one interactive-WSS qualification is
`tests/qualification_generic_wss.rs`. It composes the named Bridgefu call
engine with real rvoip adapters for both direct WebRTC ingress and a
trusted-CIDR-authenticated, one-use Vapi-like SIPS/SRTP attachment. The test
proves authenticated WSS/TLS, Opus full-duplex media, PCMU↔Opus transcoding,
arbitrary DataMessages, allowlisted initial SIP context, later SIP MESSAGE↔
DataChannel translation, RFC 4733 in both directions, both hangup directions,
and complete route/bridge cleanup. Run it with:

```sh
cargo test -p bridgefu --test qualification_generic_wss -- --nocapture
```

The same file contains the exact direct-mode handoff qualification. It keeps
one authenticated browser WSS/WebRTC connection stable while a real
Digest-authenticated SIPS/TLS+SRTP Vapi-like assistant is held and replaced by
an authenticated generic interactive-WSS destination. The destination must
publish its explicit, request-bound application-ready outcome before the
pending generation can become active. The success phase proves zero media
leakage during hold, atomic route replacement, exact assistant retirement,
full-duplex Opus, arbitrary labeled DataChannels, RFC 4733 in both directions,
browser hangup, and zero retained routes/tasks/capacity. The rejection phase
proves that no premature promotion occurs and that the original assistant and
its full-duplex media resume on the same browser binding. Run that case alone
with:

```sh
cargo test -p bridgefu --test qualification_generic_wss \
  direct_browser_vapi_sip_to_generic_wss_handoff_is_connected_gated_and_resumable \
  -- --exact --nocapture
```

This nonignored file passes 4/4 and is hermetic adapter/call-engine evidence.
The separate ignored exact-browser case runs both terminal variants through the
built SDK:

```sh
cargo test -p bridgefu --test qualification_generic_wss \
  built_typescript_sdk_hands_off_to_generic_wss_and_cleans_both_terminal_directions \
  -- --exact --ignored --nocapture
```

That case passes 1/1 against the temporary RTC path override used for
validation. It proves
the built TypeScript SDK keeps one browser peer stable through assistant hold,
application-ready WSS promotion, full-duplex Opus, arbitrary DataChannels, RFC
4733, both terminal directions, and exact cleanup. It is local-composite
validation only, not evidence for the current locked rvoip 0.3.5 graph, stock
Vapi `webCall`→SIP feasibility, real TURN traversal, split gateway/worker
execution, or live infrastructure.

### Built browser SDK in Chromium

The ignored `tests/qualification_browser_sdk.rs` test builds the actual
`sdk/typescript` package, imports its generated `dist` module in Playwright's
pinned Chromium, and uses a fake microphone against a real authenticated,
one-use Bridgefu WSS/WebRTC attachment. The named call engine first dials a
hermetic Digest-authenticated SIPS/TLS+SRTP Vapi-like assistant, then performs
two make-before-break replacements to a separately profiled SIPS/TLS+SRTP
call-center destination. Run it explicitly from the Bridgefu repository:

```sh
cargo test -p bridgefu --test qualification_browser_sdk -- \
  --ignored --nocapture
```

The test is ignored in the default Cargo suite because it depends on the
pinned Playwright 1.61.1 dependency and Chromium installation under
`sdk/typescript`. Prepare that self-contained browser runtime with
`npm ci && npm run browser:install` in `sdk/typescript`; an explicit run fails
rather than silently skipping when it is absent.

The browser qualification proves full-duplex media between the fake
microphone and the initial assistant, a remote audio track, initial allowlisted
context in the SIP INVITE, later `bridgefu.context.v1` through SIP MESSAGE,
an arbitrary labeled binary DataMessage reaching the authenticated rvoip core,
and mandatory browser DTMF reaching the SIP RFC 4733 endpoint. A rejected
generation-2 replacement holds the assistant with no active graph bridge and
zero inbound RTP-byte or browser-microphone leakage, then resumes full-duplex
assistant media. A generation-3 retry holds the same stable browser peer,
promotes the call center only after answer/media readiness, retires the
assistant, and passes full-duplex agent media without a three-party interval.
The browser observes the exact authenticated `preparing`→`ringing`→`attaching`
→`resumed` and `preparing`→`ringing`→`attaching`→`connected` sequences. One
initial-attachment and two replacement ringback intervals stop exactly on
`connected`, `resumed`, and `connected`. The test also proves browser hangup,
terminal call cleanup, zero retained routes/tasks/capacity, and rejection of a
replayed attachment while retaining the same `RTCPeerConnection` object and
server connection ID throughout both replacements. Arbitrary DataChannel
labels are deliberately not mapped to SIP MESSAGE; only the managed context
contract crosses that policy boundary.

Chromium offers telephone-event at dynamic PT 110/48 kHz and PT 126/8 kHz.
rvoip derives the exact negotiated payload type, clock, SDES MID binding, and
direction from the final SDP pair instead of assuming PT 101/8 kHz. For the
same-clock PT 110/48 kHz case, audio and DTMF use the primary Opus SSRC and one
serialized sequence/timestamp writer; different-clock telephone-event retains
a supplemental encoding. Pending, remapped, missing-MID, or ambiguous state
fails closed. The local RTC candidate advertises only the primary audio SSRC,
preserves an explicit represented same-clock payload type, and accepts an
un-signaled supplemental SSRC only through authoritative MID/payload ownership
or a uniquely negotiated payload type.

The browser test requires `RTCDTMFSender.canInsertDTMF`, waits for the empty
`tonechange`, and keeps the peer alive for a bounded one-second flush so
Chromium can send its three final end-of-event retransmissions. Historical
local-candidate RTC validation passed 180/180, including all 13 six-file
candidate tests; rvoip's outbound-writer tests passed 4/4, `dtmf_wire` passed
3/3, and `browser_sdp_interop` passed 13/13. Those counts describe the earlier
candidate and do not substitute for the current published-package browser
results below.

Bridgefu's production generic-WebRTC profile defaults to Opus only (plus the
negotiated supplemental telephone-event payload), while rvoip retains its
multi-codec compatibility mode for callers that do not select a deterministic
profile. Both Chromium answers advertised Opus PT 111 and telephone-event PT
110; the server observed browser media on PT 111. The test also snapshots the
real MediaGraph and requires an Opus/PT111 source, at least one Opus-to-PCMU
transcode operation, and zero transcode errors, so a mislabeled PCMA payload
cannot satisfy this qualification.

The published-graph rerun on 2026-07-31 uses only the exact checksummed rvoip
0.3.5 packages in `Cargo.lock`, Playwright 1.61.1, and its Bridgefu-local
Chromium installation. No StandardCharter browser installation or Cargo path,
Git, or patch override is used.

| Destination | Exact built-SDK Chromium evidence |
|---|---|
| Generic SIP | `tests/qualification_browser_sdk.rs`: `built_typescript_sdk_reaches_named_sips_destination_in_real_chromium` passes 1/1. |
| Generic WSS | **Blocked by rvoip #54.** Chromium-to-WSS DTMF works, the reverse event reaches the exact Bridgefu/rvoip-core destination binding, and rvoip reports a successful outbound send, but Chromium receives no new RTP packet before the deadline. The isolated result reproduces 3/3. |
| Amazon Connect | `direct_assistant_handoff::built_typescript_sdk_hands_off_to_amazon_and_cleans_both_terminal_directions` passes 1/1 and internally runs both terminal variants. |
| Telnyx | `direct_assistant_handoff::built_typescript_sdk_hands_off_to_telnyx_and_cleans_both_terminal_directions` passes 1/1 and internally runs both terminal variants. |

Supporting current published-graph evidence passes as follows:
`cargo test --locked --all-targets`, including Bridgefu library 341/341,
binary 128/128, `call_execution_supervisor` 41/41, generic SIP 6/6,
`private_forwarding` 7/7, and StandardCharter 82/82. Strict
all-target/all-feature Clippy passes with warnings denied. The TypeScript SDK
passes 20/20 tests and its typecheck. The generic-WSS test continuously drains
the real destination media receiver and independently asserts the DTMF event
at Bridgefu's core boundary, so bounded receiver backpressure cannot explain
the browser-side failure.

The Bridgefu library suite was previously rerun after restoring the then-exact
dependency and lock provenance: `cargo test --locked -p bridgefu --lib` passed
328/328 against `1e5b7d4...`. This is historical evidence for that graph, not
the current crates.io rvoip 0.3.5 package set.

The earlier four-pass exact Chromium matrix was run through the temporary local
`../rtc/rtc` override. The candidate is six uncommitted files at base
`1e5b7d4be6d94850694f2519f4c235d16c871d53`, with stable patch ID
`478b7da63ea6d195f446a9abce4c56e62129a86e`. The temporary manifest overrides
have since been removed: Bridgefu's current manifest and lockfile now resolve
exact checksummed rvoip 0.3.5 packages from crates.io with no Git or path
source. The historical results are therefore local-composite validation only,
not release evidence for the published graph.

This is substantial local all-in-one evidence, not Gate 7 completion. Three of
the four exact Chromium destinations now pass against the published graph; the
generic-WSS case remains blocked on
[rvoip issue #54](https://github.com/eisenzopf/rvoip/issues/54) and must be
rerun after an owner-reviewed published rvoip fix. Bridgefu does not carry a
local dependency patch. TURN-only/public-NAT, built-SDK split gateway/worker,
stock Vapi transfer, live PBX/Amazon/Telnyx, process-restart, cloud, one-hour
load, and deployed chaos evidence remain open.

Release-image evidence recorded on the same worktree:

- `deploy/scripts/check-release-image.sh` and all ten OCI helper unit tests
  pass.
- All eight rendered Compose services pass executable configuration/role
  preflight.
- The credential-free runtime smoke passes all nine role, lifecycle, private
  forwarding, durable call/media/context, and broadcast checks while recording
  the exact 25-package registry-only rvoip 0.3.5 graph.
- An earlier cold canonical `linux/arm64` image build succeeded. The resulting
  301 MB pre-retarget image reported Bridgefu 1.0.0 and rvoip 0.3.5, ran as
  `65532:65532`, retained SIGTERM and the `/livez` healthcheck, validated the
  example configuration, and executed with a read-only root filesystem, no
  capabilities, and `no-new-privileges`. This proves the native build and
  hardening path, not the final 0.9.0 artifact identity.
- The retained `linux/amd64` + `linux/arm64` OCI archive, per-platform Trivy
  policy, embedded SBOMs, provenance, and exact 0.9.0 labels remain the
  protected post-commit workflow gate; the local Docker client does not have
  Buildx installed.

## Finite chaos matrix

The ignored `qualification_chaos` runner composes exact existing Bridgefu and
rvoip tests rather than duplicating their fault-injection logic. Its local
matrix covers media queue loss/backpressure, RTP jitter-buffer packet loss,
malformed SIP and WHEP signaling, Telnyx retry exhaustion and circuit recovery,
lease/repository unavailability, worker drain, MOQT relay-session loss,
attachment expiry/replay, call-capacity exhaustion, and broadcast-authority
loss. Every child command selects one exact test, and a zero-test command is a
failure rather than a false pass.

Run the local matrix manually:

```sh
BRIDGEFU_CHAOS_ACKNOWLEDGE_MANUAL=1 \
  cargo test --locked --test qualification_chaos -- \
  --ignored --exact qualifies_deterministic_chaos_matrix --nocapture
```

The runner uses `target/qualification/chaos-cargo-target` for nested Cargo
commands so it cannot deadlock on the invoking Cargo process's build lock. Set
`BRIDGEFU_CHAOS_CHILD_TARGET_DIR` to another dedicated directory when the
default is unsuitable. Set `BRIDGEFU_CHAOS_QUALIFICATION_OUTPUT` for a retained
report path; otherwise a timestamped
`bridgefu.qualification.chaos.v3` JSON report is written under
`target/qualification`.

The v3 report deliberately separates two dependency scopes. Bridgefu child
tests run with Bridgefu's committed `Cargo.lock`, and
`bridgefu_locked_rvoip_graph` records the exact rvoip 0.3.5 packages and
crates.io checksums in that application graph. rvoip child tests are selected
from that locked metadata, but execute the published registry package source
with `cargo test --locked --manifest-path ...`; that command uses the selected
package's packaged `Cargo.lock`, not Bridgefu's lockfile.
`rvoip_package_source_execution` and each scenario's
`dependency_resolution` make this independent package-source test graph
explicit. Those upstream unit-test results validate the exact published source
package, but their independently locked transitive dependency graph is not
evidence that the same test ran under Bridgefu's application lock.

Two additional cases are external and destructive only to disposable test
services:

- `BRIDGEFU_TEST_REDIS_URL` enables a Redis 7.2 connection-kill, state-loss,
  database-fallback, and reconnect scenario.
- `BRIDGEFU_TEST_POSTGRES_URL` enables a PostgreSQL two-projector crash/reclaim
  scenario.

Missing external configuration is recorded as `skipped_external`, never
`passed`. The report retains only static scenario/test names, aggregate test
counts, timings, exit status, host metadata, and revisions. Child stdout and
stderr are parsed in bounded memory for the test count, then discarded; no
credential, URL, provider payload, call identifier, or child diagnostic is
written to evidence. Failed scenarios are rerun by their static exact test name
for detailed local diagnosis.

The recorded pre-`VF-*` run on 2026-07-14 passed all 16 scenarios: 14 local
deterministic cases and both disposable-service cases against isolated Redis
and PostgreSQL. No scenario failed or was skipped. The retained redacted report
still sets `release_criterion_satisfied` to `false`, because this finite run is
neither an hour-long load profile nor a deployed-cloud chaos campaign.

This runner is a finite correctness smoke. It does not run for one hour, apply
network impairment at release scale, contact a live Telnyx account, interrupt a
PostgreSQL server process, or fail a separately deployed relay tier. Its report
therefore hard-codes `release_criterion_satisfied: false`, even when every local
and external scenario passes. The Gate 11 chaos checkbox remains open until an
owner-authorized deployed campaign retains those missing results alongside the
one-hour load evidence.
