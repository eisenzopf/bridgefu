# Bridgefu 1.0 and rvoip Dual-QUIC Roadmap

This is the canonical implementation and release-gate plan for Bridgefu 1.0.
Every gate remains incomplete until its exit criteria have executable evidence.
Documentation, Terraform, or API scaffolding alone does not complete a gate.

## Baseline

- Bridgefu starting revision: `5ed676c3f51d1b3af5bdabe504032b26a59225e0`
- rvoip starting revision: `239efa5649dcf330f90ed63a84c1b082a8f4916b`
- StandardCharter starting revision: `0143eac46d737ac532405371224d1a4f8c676ffb`
- Bridgefu branch: `codex/bridgefu-1.0`
- rvoip branch: `codex/bridgefu-1.0-rvoip`
- Production StandardCharter deployment and public artifact publication are not
  authorized by this roadmap.
- Reproducible defects in the published rvoip dependency are reported in
  `eisenzopf/rvoip` with Bridgefu evidence for the rvoip maintainer to repair.
  Bridgefu does not carry an unpublished rvoip patch, fork push, remote
  candidate pin, or maintainer pull request as part of its release.

Baseline evidence recorded on 2026-07-10:

- Bridgefu: `cargo test` — 13 passed.
- rvoip: auth-core 35, core 25, UCTP 8, QUIC 1, and MOQT 1 unit tests passed.
- rvoip WebRTC: WHIP, WS, and rustls feature compilation passed.
- StandardCharter core: 31 tests passed; web: 3 tests passed.

Dependency checkpoint recorded on 2026-07-26:

- Bridgefu then consumed the coordinated rvoip 0.3.1 component release from
  crates.io using exact `=0.3.1` requirements.
- `Cargo.lock` is the authoritative, checksummed transitive dependency record.
  The locked graph contained 24 rvoip packages, all at 0.3.1 and all sourced
  from crates.io; it contains no Git or sibling-path package sources.
- Docker, Compose, CI, the release-candidate workflow, deployment tooling, and
  qualification provenance no longer require or accept a sibling rvoip build
  context or revision.
- Locked compilation and the focused migration/qualification suites pass. The
  pre-answer inbound SIP CANCEL regression identified at this checkpoint is
  now corrected by BP-1: Bridgefu durably transitions the exact source
  generation and immediately tears down the independently originated peer.
  The strict propagation test now requires destination CANCEL within one
  second rather than relying on the ten-second setup recovery fence.
- This closes the fetchable-dependency input gap. It does not retroactively
  qualify exact-Chromium, TURN-only, live-provider, cloud, or load results
  recorded against earlier local candidates; those tests must be rerun against
  the published locked graph before their release gates can close. The B2BUA
  cancellation fix could be qualified against published rvoip 0.3.1. A later
  exact-generation admission terminal signal is an additive rvoip hardening
  improvement, not the root-cause fix.

Registry integration checkpoint recorded on 2026-07-29:

- rvoip `0.3.4` is published as a coordinated 44-crate release at
  `7581b61cf74b6c692a05664668ae7d0dc03246a9`. Bridgefu resolves 25 rvoip
  packages at exactly `0.3.4`, all from crates.io, with no Git/path override or
  temporary Cargo patch.
- Bridgefu now consumes the exact-generation admission terminal signal and has
  removed its 25 ms pending-admission liveness poll. Signal outcomes map to the
  durable, generation-fenced `SourceTerminatedBeforeAnswer` transition; the
  one-time principal check remains only as a fail-closed activation-error
  fallback for older adapters.
- The real SIP cancellation reference passes the one-second destination-CANCEL
  bound. The complete generic SIP suite passes 6/6, the call execution
  supervisor passes 40/40, the StandardCharter contract passes 82/82, and the
  non-browser Amazon qualification passes 2/2 against the registry-only graph.
- rvoip `0.3.4` used the disclosed owner-approved carry-forward release mode;
  its full beta, external interoperability matrix, and long soaks were not
  rerun. Bridgefu does not reinterpret that inherited evidence as a current
  full-beta pass. Its remaining browser, TURN, live-provider, split/cloud, and
  long-run gates remain open.

Registry integration checkpoint recorded on 2026-07-31:

- rvoip `0.3.5` is published as a coordinated 44-crate release at
  `c4f95e0c696a11e2e6e15183fbaa9b3dc6f94fec` and tagged `v0.3.5`.
  Bridgefu resolves 25 rvoip packages at exactly `0.3.5`, all from crates.io
  with registry checksums and no Git or path overrides.
- The locked application graph contains neither Smol nor async-std. Bridgefu
  uses Tokio throughout its runtime integration.
- The 0.3.5 package graph is the authoritative Bridgefu 0.9.0 preview and 1.0
  development dependency input.
  Historical local-candidate and 0.3.4 results remain historical; downstream
  Rust, browser, TURN, provider, cloud, and long-run gates qualify only the
  committed 0.3.5 lockfile when rerun.

## B2BUA cancellation and stateful-proxy conformance overlay

This overlay was approved on 2026-07-26 and supersedes older roadmap text that
attributes the pending-source cancellation timeout to rvoip admission
retirement or treats `rvoip-sip-proxy` as broadly RFC 3261 §16 compliant.

Overlay provenance:

- Bridgefu was preserved in place on `codex/bridgefu-1.0` at
  `83443e39bfb4974eaa3e6b25fcd82b6f0fd277fe` (tree
  `853dbbf53072a539bd0e8df9aba950ac0b409323`). It was already dirty; no
  reset, cleanup, or unrelated rewrite was performed. The tracked-tree
  manifest SHA-256 is
  `5fc5886b563e4bd3cb908881d36a2baabcbe267a40a4546497638c016d28ccc4`.
- The original rvoip worktree was preserved on `main` at
  `f2f29d0e110bc9b3d6f83aa5e8f131398a2dce0a`. Proxy work uses the clean
  isolated worktree `/Users/jonathan/Developer/rvoip-sip-proxy-conformance`
  on `codex/sip-proxy-conformance`; its exact manifest and evolving evidence
  are recorded in `crates/sip/sip-proxy/docs/CONFORMANCE_STATUS.md`.

The work has two independent tracks:

1. **Bridgefu B2BUA teardown.** Instrumented execution of
   `provisional_source_cancel_reaches_the_real_destination_and_releases_routes`
   observed rvoip SIP cancellation, adapter terminal delivery, and core route
   retirement in approximately 39 ms. Bridgefu subsequently rejected the
   pending admission but did not immediately terminate the correlated outbound
   leg. This result was qualified at the 2026-07-29 checkpoint on exact
   crates.io rvoip 0.3.4; the current release dependency is the superseding
   exact 0.3.5 registry graph recorded above.
2. **rvoip transaction-stateful proxy conformance.** The original proxy's
   primary event stream received `TransactionEvent::CancelRequest`, while the
   proxy listened for a different cancellation event. The response-context,
   multiple-2xx, ACK, Timer C, Via, routing, and cleanup corrections were
   integrated into coordinated rvoip 0.3.4.

   RFC 6026 is normative for this profile. It replaces RFC 3261's former
   stateless fallback for an INVITE response whose upstream server transaction
   is no longer available: that response is discarded. It also requires the
   INVITE client/server Accepted lifecycles and Timer M/L behavior. The
   former 0.3.1 transaction layer had useful retained-2xx caches and
   authenticated tombstones, but transitioned its INVITE state machines
   directly to `Terminated`. The 0.3.4 implementation adds the explicit RFC
   6026 Accepted/Timer-M/Timer-L behavior rather than treating caches alone as
   conformance.

Bridgefu remains a media-terminating B2BUA and does not use the stateful proxy
to coordinate its two call legs.

| Gate | Status | Exit evidence |
|---|---|---|
| BP-0 — baseline and claims | In progress | Dirty worktrees preserved; exact SHAs recorded; failing Bridgefu and proxy tests captured; proxy documentation says Partial. |
| BP-1 — Bridgefu pending-source teardown | Implemented; focused qualification green | The exact-generation durable source terminal transition is committed before admission rejection and also wins the final-answer race; in-flight SIP, WebRTC, Amazon, and private-egress setup is cancelled before it can publish a late binding. The real SIP regression observes destination CANCEL within one second, the six-scenario generic SIP suite, 41-scenario call supervisor suite, seven-scenario private-forwarding suite, 341 library tests, and repository conformance for memory, SQLite, and PostgreSQL pass. Full release qualification remains in BP-7. |
| BP-2 — rvoip admission terminal signal | Complete in published rvoip 0.3.4 and adopted by Bridgefu | Exact-generation terminal watch, retained response-before-wait result, late-accept rejection, Drop safety, generation reuse, and saturated-observer tests pass. Bridgefu selects directly on the terminal receiver and no longer performs the 25 ms liveness poll. |
| BP-3 — proxy CANCEL processing | Implemented; focused qualification green | Matched/unmatched, pre-provisional latch, duplicate/retransmitted CANCEL after INVITE retirement, fork, generated-CANCEL ownership, exact UDP/TCP/TLS routing, authenticated peer/flow isolation, listener-auth no-challenge behavior, and CANCEL/2xx race tests pass. The full external and beta gates remain BP-6/BP-7. |
| BP-4 — RFC 6026 and proxy response contexts | Released in rvoip 0.3.4; focused qualification green | The former distinct-To-tag failure is corrected with live INVITE client/server `Accepted` states, centralized Timer M/L at exactly `64*T1`, proxy-mode cache isolation, duplicate/distinct 2xx delivery, retransmitted-INVITE absorption, ACK-to-TU, transport-error retention, RFC 4320 non-INVITE response handling, and post-Timer-L discard. The focused proxy suite passed; the full 0.3.4 external matrix and beta suite were explicitly not rerun under the carry-forward release disposition. |
| BP-5 — ACK, Timer C, and routing | In progress | Focused tests now distinguish transaction-owned non-2xx ACK from stateless 2xx ACK. Per-branch Timer C, actual-transport Via stamping, Route/SIPS/RFC 3263, bounded state, UDP/TCP/TLS packet evidence, and cleanup remain open. |
| BP-6 — independent conformance | Active | Mock and real UDP/TCP/TLS loopback coverage is in progress. On the current stable development source, a bounded Kamailio/rvoip-first UDP row and a bounded OpenSIPS/peer-first UDP row each pass all 10 counted core-and-cleanup scenarios with real external traversal, packet-bound Via evidence, unchanged proxy binaries, and clean process/port convergence. Earlier diagnostic runs exposed and led to corrections for SIPp CANCEL branch/duplicate-response modeling, an INVITE-487 Via fixture error, provisional-response timing, body-length evidence, and shell fail-open/stale-artifact risks. These short dirty-source rows deliberately omit the 130-second retention assertion and advanced scenarios, so they are development evidence rather than release evidence. The `0.3.2` release gate requires pinned real Kamailio and OpenSIPS peers in both adjacency orders (`UAC → rvoip → peer → UAS` and `UAC → peer → rvoip → UAS`), SIPp/raw-wire scenario traffic, verified TLS identities, packet captures proving both Via hops, a full protocol-retention drain, and machine-readable zero-retained-state evidence. Each peer must independently exercise the full required scenario inventory across its six rows; one peer cannot substitute for the other, and an in-process Rust test may supplement but cannot satisfy external interoperability coverage. The harness follows the existing Asterisk/FreeSWITCH lifecycle and provenance pattern while remaining self-contained in rvoip. A skipped peer, topology, required transport, scenario, capture, or cleanup assertion is a release failure. |
| BP-7 — beta qualification | Pending | Full beta report, three canonical 2,000-CPS passes, PBX audio/teardown, 30-minute monolithic soak, and one-hour split soak pass. |
| BP-8 — registry integration | Historical 0.3.4 checkpoint complete; superseded by 0.3.5 | At the 2026-07-29 checkpoint, rvoip 0.3.4 was published and Bridgefu's exact registry-only 0.3.4 graph passed its all-target compile/test matrix plus SIP cancellation, generic SIP, call-actor, StandardCharter, and hermetic Amazon suites. The 2026-07-31 checkpoint above makes exact registry-only 0.3.5 the current release graph. Owner-gated TURN/public-NAT, live-provider, split/cloud, and long-run evidence remain later product-release gates rather than registry-integration claims. |

## Vapi Widget to Call Center full-duplex release gap

This section is the canonical product-level release overlay approved on
2026-07-14. It takes precedence over any older statement below that calls a
component, localhost adapter path, or legacy StandardCharter fixture locally
complete. Those results remain useful implementation evidence, but they do not
make a Vapi website-widget topology supported.

For this matrix, **supported** means that browser-to-destination audio works in
both directions, DTMF and hangup behave exactly as advertised, failure cleanup
is deterministic, and the exact topology passes both automated and required
live acceptance tests. Having the constituent adapters or a mock topology is
not sufficient.

| Vapi widget path | Current status | Release verdict |
|---|---|---|
| Stock Vapi Web SDK → Bridgefu → Amazon Connect | Bridgefu's downstream Vapi SIP/RTP → Amazon Chime WebRTC bridge is implemented and hermetically tested. The stock browser `webCall` → SIP transfer has not been proven. | Partial; not yet supported end-to-end |
| Stock Vapi Web SDK → Bridgefu → generic SIP | The downstream one-use Vapi-like SIPS/SRTP attachment → named SIPS/SRTP destination composition is hermetically green, including Digest, media, DTMF, teardown, and context policy. Stock Vapi browser `webCall` → SIP transfer and live standards-PBX behavior remain unproven. | Partial; not yet supported end-to-end |
| Stock Vapi Web SDK → Bridgefu → Telnyx | A Vapi-like trusted-CIDR SIPS/SRTP attachment is hermetically qualified through the production Telnyx executor and a distinct authenticated Telnyx media attachment, including linked dials, full-duplex audio, RFC 4733, signed callbacks, retries, both terminal directions, and exact cleanup. Stock Vapi browser `webCall` → SIP transfer and a restricted live Telnyx account remain unproven. | Partial; not yet supported end-to-end |
| Stock Vapi Web SDK → Bridgefu → generic WebRTC/WSS | The downstream authenticated Vapi-like SIPS/SRTP attachment → interactive WSS route is hermetically qualified with real protocol adapters. Stock Vapi browser `webCall` → SIP transfer is still unproven, so this is not live Vapi evidence. | Partial; not yet supported end-to-end |
| Direct Bridgefu browser WebRTC → generic SIP | The all-in-one named-route composition is hermetically green for authenticated browser WSS/TLS to a context-gated named SIPS/TLS+SRTP destination, Opus↔PCMU and Opus↔PCMA, bidirectional DataChannel↔SIP MESSAGE, RFC 4733, both hangup directions, and exact cleanup. The exact built TypeScript SDK/Chromium handoff now passes against the published registry-only rvoip 0.3.5 graph through a real one-use attachment, Digest SIPS/TLS+SRTP assistant, rejected-generation compensation, and successful retry to a separately profiled call center. Local split WHIP→SIP execution and SIP→WSS replacement are also hermetically green. TURN-only, built-SDK split, and live standards-PBX evidence remain open. | Partial; not yet supported end-to-end |
| Direct Bridgefu browser WebRTC → Amazon Connect | The exact all-in-one named-route composition is hermetically green for a real authenticated, one-use browser WSS/WebRTC attachment through the production Amazon adapter seams: Opus full duplex, DTMF both ways, allowlisted initial StartWebRTCContact attributes/screen pop, both terminal directions, exactly one StopContact, and exact cleanup. The exact built-SDK Chromium→Connect handoff passes both terminal variants against the published registry-only rvoip 0.3.5 graph. Amazon remains initial-context-only. TURN-only, split execution, and live Connect evidence remain open. | Partial; not yet supported end-to-end |
| Direct Bridgefu browser WebRTC → Telnyx | The production one-use authenticated WSS/WebRTC ingress and real-adapter Vapi-assistant handoff are hermetically composed with the Telnyx executor and distinct authenticated media attachment, including linked dials, full-duplex audio, RFC 4733, signed callbacks, retry behavior, both terminal directions, compensation, and cleanup. The exact built-SDK Chromium→Telnyx test passes both terminal variants against the published registry-only rvoip 0.3.5 graph. Split execution and a restricted live-account run remain open. | Partial; not yet supported end-to-end |
| Direct Bridgefu browser WebRTC → generic WebRTC/WSS | The all-in-one named-route composition and real-adapter direct-mode handoff are hermetically green for authenticated WSS/TLS, Opus full duplex, arbitrary DataChannels, RFC 4733, hold/no-mix, application-ready promotion, rejection compensation, both hangup directions, and exact cleanup. The earlier local RTC composite passed both terminal variants. Against published rvoip 0.3.5, Chromium-to-WSS DTMF reaches Bridgefu correctly but outbound RFC 4733 returns success without reaching Chromium; this reproduces 3/3 and is tracked as rvoip #54. Local split WHIP→WSS execution and SIP→WSS replacement remain green. TURN-only, built-SDK split, live qualification, and a published dependency fix/rerun remain open. | Blocked on rvoip #54; not yet supported end-to-end |

The original four-pass exact-Chromium results were produced against a temporary
local RTC path override containing an uncommitted six-file candidate. The
published-graph rerun now passes generic SIP, Amazon Connect, and Telnyx using
the fetchable, checksummed rvoip 0.3.5 package family with no Git or path
overrides. Generic WSS remains a real failing published-graph result, not a
missing run; rvoip issue #54 records its exact boundary evidence.

Two ingress modes are required:

1. **Vapi-managed widget.** Browser WebRTC terminates at Vapi. Vapi transfers
   the call over SIPS/SRTP to a unique, single-use Bridgefu attachment, and
   Bridgefu bridges that SIP leg to Amazon Connect, generic SIP, Telnyx, or
   interactive WebRTC/WSS. Bridgefu does not claim access to Vapi's browser
   peer connection or DataChannel.
2. **Direct Bridgefu widget.** A reusable Bridgefu TypeScript client terminates
   browser WSS/WebRTC at Bridgefu. Bridgefu initially connects the other leg to
   a Vapi SIP assistant, then uses make-before-break leg replacement to move
   that stable browser leg to the selected call-center destination. Failure
   resumes the Vapi leg; success never creates a three-party mix.

Both modes require full-duplex caller-to-agent and agent-to-caller media. They
do not include later reverse origination to a browser that is offline.

### Vapi full-duplex gap gates

The `VF-*` prefix preserves the historical Gate 0–11 numbering below while
recording the newly approved ordered Gates 0–7. A `VF-*` gate can close only
with its listed executable evidence.

| Gap gate | Status | Required evidence |
|---|---|---|
| VF-0 — roadmap and Vapi feasibility | In progress — owner-gated harness implemented; live evidence absent | StandardCharter now has a manual-only, dry-run-by-default Chromium harness for both Vapi transfer mechanisms, a controlled SIP echo, and a generated Bridgefu SIPS attachment. Offline contract/redaction tests are executable, but they are not qualification evidence and no live browser run has occurred. Closure still requires owner-authorized, externally credentialed evidence for full-duplex audio, DTMF, allowlisted header names, both hangup directions, callbacks, final reason, and cleanup. Automation may only flag a vendor-blocked candidate after all four echo attempts explicitly report capability unsupported; only owner review may mark Vapi-managed ingress `vendor-blocked`, and direct ingress remains release-capable. |
| VF-1 — rvoip edge foundations | In progress — local split initial, replacement, terminal, and drain paths are green; outbound browser DTMF is upstream-blocked | Staged inbound SIP answer, listener policy exposure, outbound SIPS/SRTP and authentication profiles, and WSS/HTTPS/ICE/TURN/DataMessage lifecycle pass their focused suites. Authenticated `offer-ready` provides two-phase WSS admission: it requires a leased `rvoip.webrtc.v1` route and a non-anonymous, unexpired principal; stages SDP and DataChannels before core publication; emits neither media nor `Connected` before exact request-bound acceptance; preserves legacy `offer`; and performs owner-bound rejection, timeout, disconnect, and expired-principal cleanup. Its focused suite passes 11/11. The private UCTP seam has versioned, bounded `prepare`, `activate`, `abort`, `end`, DTMF, DataMessage, response, and lifecycle envelopes; exact worker fence plus tenant/call/source-leg/source-generation/target-generation checks; command expiry/digest replay rejection; source cleanup; worker/gateway client dispatch; one-use generation-bound destination-stream admission; and distinct authenticated UCTP Session/Connection/MediaStream ownership. Gateway and worker roles install the SIP/WSS proxy lifecycle, Redis-backed state/replay, durable initial and replacement bindings, DTMF/DataMessage forwarding, terminal lifecycle journaling with exact durable ACKs, and awaited End/Abort cleanup during drain. Process-level Redis restart and non-loopback real-peer qualification remain open. The coordinated WebRTC/RTC implementation is supplied by the locked rvoip 0.3.5 crates.io graph. Three exact Chromium destinations pass; generic WSS exposes rvoip #54 after the DTMF event reaches Bridgefu's core boundary. Reproducible dependency defects are reported to `eisenzopf/rvoip`; Bridgefu carries no local rvoip patch. |
| VF-2 — secure routes and attachment lifecycle | In progress — local API, repository, and split-adapter ownership evidence is green | Named route/profile APIs, complete redacted one-use SIP and WebRTC attachment descriptors, `attach_then_dial`, durable 24-hour idempotency, atomic token consumption, tenant isolation, fail-closed split capability selection, and generation-bound split destination ownership pass focused suites. Closure still requires the final all-target regression and deployed topology evidence. |
| VF-3 — generic SIP reference destination | In progress — secure SIP, true early media, all-in-one, cancellation, and local split execution are hermetically green; live qualification remains | `tests/generic_sip_reference.rs` composes the durable named-route actor with real rvoip source, Bridgefu B2BUA, and destination peers. All six exact local tests pass for authenticated SIPS/SRTP, non-silent destination-to-source media during 183 while both legs remain signaling, final-answer promotion onto the same source graph, full-duplex media, RFC 4733, proxy and origin Digest challenges, rejection, source CANCEL propagation within one second, and cleanup. The call-supervisor race suite additionally proves that source termination while the final answer is in flight commits the same exact-generation durable transition and immediately retires a connected peer. `tests/qualification_generic_wss.rs` separately covers authenticated browser WSS/TLS to named SIPS/TLS+SRTP with media, context translation, DTMF, hangup, and cleanup. The split topology test adds real authenticated WHIP ingress over loopback, private mTLS UCTP, staged SIP/WSS adapter fixtures, failed-generation compensation, successful replacement, and exact terminal/drain cleanup. Non-loopback/live standards-PBX and built-SDK split qualification remain open; this does not prove stock Vapi browser transfer. |
| VF-4 — Vapi-managed ingress | In progress — local Vapi-like edges and StandardCharter control integration are green; VF-0/live evidence remains | `tests/qualification_generic_wss.rs` proves that a trusted-CIDR-authenticated, one-use named-route SIPS attachment with mandatory SRTP reaches configured WSS and generic-SIP destinations with the advertised media, context, DTMF, terminal, and cleanup behavior. StandardCharter locally creates only allowlisted managed route calls, preserves the Amazon default and rollback flag, and keeps URI/call/tenant/credential authority off the model. This is hermetic Vapi-like SIP and local control evidence, not proof that stock Vapi `webCall` can transfer. Closure still requires VF-0, owner-authorized canary evidence, and every claimed destination. |
| VF-5 — direct browser ingress and handoff | In progress — SDK, server-owned mapping, assistant configuration, durable lifecycle, all-in-one handoffs, local split replacement, and three published-graph Chromium destinations are green | The reusable TypeScript client, StandardCharter widget integration, signed server-owned session mapping, dedicated Vapi SIP assistant/tool configuration, generation-fenced make-before-break replacement, monotonic authenticated handoff status, success compensation, timeout/cancellation, replay, glare, and no-spoof/no-mix tests are implemented. Exact built-SDK Chromium handoffs to generic SIP, Amazon Connect, and Telnyx pass against published rvoip 0.3.5. Generic WSS reaches Bridgefu's core but is blocked by rvoip #54 on outbound RFC 4733. Real-adapter suites cover application/media-ready promotion, rejection compensation, no-mix holds, stable browser binding, exact profile revisions, terminal variants, and cleanup. The local split topology proves one failed replacement generation followed by a successful generation without cross-connect or leaked prior media, but remains an adapter-fixture/WHIP test rather than a built-SDK Chromium split matrix. Closure still requires the upstream fix/rerun, TURN-only and public-NAT evidence, built-SDK split execution, process-restart recovery, and deployed canary qualification. |
| VF-6 — destination qualification | In progress — all-in-one paths and three published-graph exact built-SDK destinations are green; generic WSS is upstream-blocked | The published rvoip 0.3.5 Chromium rerun qualifies direct-browser → Vapi-like SIPS/SRTP assistant → generic SIP, Amazon Connect, and Telnyx. Generic WSS has a strict failing result recorded in rvoip #54. Real-adapter suites cover full-duplex media, DTMF, signed readiness, compensation, both terminal variants, and exact cleanup; Amazon remains initial-context-only. The local split test qualifies SIP/WSS adapter-fixture routing and replacement, not split Amazon/Telnyx, stock Vapi transfer, real TURN traversal, live provider/PBX behavior, or cloud infrastructure. |
| VF-7 — clustered and release qualification | In progress — local split execution, route-catalog fencing, runtime smoke, and native image are green; deployed qualification remains | Split workers advertise only concrete configured capabilities. The canonical SHA-256 route/capability fingerprint includes provider, Amazon, generic destination/profile, codec, and effective capability policy; ordering is stable, configuration changes alter the digest, workers advertise it, assignments retain it, gateways reject mismatched/legacy workers and fresh dispatch or attachment consumption after catalog change, and reconnect refresh is tested. A worker cannot advance to a changed catalog while either an active assignment or a released terminal assignment with unfinished recovery work still requires the previous catalog. Gateway and worker roles install the authenticated private egress command service, Redis-backed epoch/replay state, SIP/WSS staged adapters, separate target-generation media admission, durable initial/replacement supervision, DTMF/DataMessage carriage, progress/terminal reconciliation, exact lifecycle ACKs, source-loss fallback, and awaited drain cleanup. The nine-check runtime smoke and hardened native Linux ARM image pass. Closure still requires a real process-role Redis restart test, non-loopback gateway/worker peer qualification, the protected multi-architecture OCI candidate, AWS/GCP smoke, one-hour load, latency/memory, deployed chaos, and provider/StandardCharter evidence. |

VF-2 named-Vapi attachment-identity evidence recorded on 2026-07-15: route
creation remains authorized by the control-API principal, while a named SIP
ingress attachment is bound to the exact configured Vapi
`tenant/profile_id/non-secret-revision` identity projected into the SIP
listener. Missing, stale, wrong-tenant, and multiple ingress bindings fail
closed; the API principal cannot consume the resulting SIP token. Direct named
WebRTC signaling and privileged unnamed SIP retain their existing API-principal
ownership. Three focused library/config tests pass; this is local identity and
token evidence only, not a stock Vapi `webCall` transfer, media, or live-provider
qualification.

VF-1 private-egress evidence recorded on 2026-07-14: three focused protocol,
authority, replay, transition, lifecycle, capacity, and drain tests pass. The
existing real mTLS UCTP forwarding test now also sends a reserved command from
the authenticated worker, proves that public-route injection is rejected, and
receives the gateway's explicit ownership response on the same Connection.
This verifies interception and response carriage; it does not satisfy the
gateway-restart requirement.

VF-1 private-egress media evidence recorded on 2026-07-14: the focused
`split_egress_uses_a_second_generation_bound_connection_full_duplex` test uses
real mutually authenticated UCTP 0.2 to admit a second Session, Connection,
and audio stream for one exact destination generation. It drives dormant
Prepare, Activate, caller-to-agent and agent-to-caller media, DTMF,
DataMessage, End, and exact zero-leak cleanup through the gateway's staged
SIP `ConnectionAdapter` proxy seam. The admission descriptor is one-use,
bounded, tenant/call/source-generation/target-generation/worker-fence bound,
and retained for connection reauthorization. This is hermetic seam evidence,
not complete production split support. Gateway/worker role installation,
durable initial-leg ownership, remote lifecycle reconciliation, and Redis
state/replay are source-complete; the later evidence below closes the local
replacement and awaited-drain gaps. Process-level restart recovery and
non-loopback real-peer qualification remain open.

VF-1/VF-3/VF-5/VF-7 split replacement and terminal-lifecycle evidence
recorded on 2026-07-15: the exact
`durable_actor_routes_whip_to_split_sip_and_wss_egress_with_authoritative_lifecycle`
test passes three consecutive post-fix runs. It uses a real authenticated WHIP
source and mutually authenticated private UCTP on loopback, drives SIP 183
progress before final source answer, verifies full-duplex Opus media,
DataMessages and RFC 4733, then injects a failed second-generation replacement
and proves compensation before promoting a successful third generation. The
old generation receives exact StopLeg cleanup, the MediaGraph bridge is
restored only to the winner, and a later remote terminal event is journaled,
delivered, durably ACKed, and retired without closing its private route early.
The focused lifecycle unit proves wrong-sequence ACK rejection, no cleanup
before the exact ACK, and replayed-ACK idempotence; the focused source-loss unit
proves terminal-but-unacked proxy cleanup when no ACK can arrive. Gateway drain
finishes with zero lifecycle deliveries, proxy routes, private admissions,
bridges, and native routes. This is hermetic in-process/loopback evidence with
adapter fixtures and an in-memory call/coordination authority. It is not a
separate-process Redis restart, non-loopback SIP/WSS interoperability, built
TypeScript SDK/Chromium split run, TURN/NAT traversal, cloud smoke, provider
split path, sustained load, or chaos result.

VF-3 focused evidence recorded on 2026-07-14: `cargo test -p bridgefu
--test generic_sip_reference -- --nocapture` passes all three hermetic
packet-path cases. The scenarios use test-only 8 MiB debug-task stacks because
the combined SIP/TLS/SRTP/MediaGraph futures overflow Rust's 2 MiB test-thread
default; production task and thread configuration is unchanged.

VF-3 completion-gap evidence recorded on 2026-07-15: `cargo test -p
bridgefu --test generic_sip_reference -- --nocapture` passes all six hermetic
packet-path cases. The added exact named-route proxy case proves that the
configured proxy receives the request even when the Request-URI target is
unreachable, challenges it with 407, cryptographically verifies the resulting
`Proxy-Authorization`, and observes no origin `Authorization`. It also proves
the source receives local 180 and Bridgefu observes destination 183 with SRTP
SDP before final answer. No RTP is sent in that proxy case, so it remains
signaling-order evidence rather than the separate early-media proof below.
Other real-adapter cases prove
486 rejection and setup-deadline cancellation with outbound CANCEL, terminal
call/leg state, and zero retained connections, bridges, admission, routes, or
tasks.

VF-3 true-early-media evidence recorded on 2026-07-15 is green for three exact
tests. rvoip-core's
`pending_admission_routes_early_media_without_answer_or_target_source_consumption`
passes 1/1; rvoip-sip's
`ringing_then_183_installs_and_publishes_srtp_before_final_answer` passes 1/1;
and Bridgefu's
`named_sip_route_crosses_real_srtp_transcoding_dtmf_and_bye` passes 1/1. The
Bridgefu acceptance sends non-silent SRTP after 183 SDP, receives and decrypts
it at the source while both durable legs remain signaling, then proves final
200 removes the provisional sink before the same single-source MediaGraph
installs its full-duplex route. This is hermetic all-in-one evidence; split
execution and non-loopback/live standards-PBX qualification remain open.

VF-4/VF-6 focused evidence recorded on 2026-07-14: `cargo test -p bridgefu
--test qualification_generic_wss -- --nocapture` passes the all-in-one named-
route qualification for both direct WebRTC ingress and a trusted-CIDR-
authenticated, one-use Vapi-like SIPS/SRTP attachment. The real rvoip peers
prove authenticated WSS/TLS, Opus full-duplex media, PCMU↔Opus transcoding,
arbitrary DataMessages, allowlisted initial SIP context, later SIP MESSAGE↔
DataChannel translation, RFC 4733 in both directions, both hangup directions,
and zero retained routes or bridges. This local result is not evidence for a
stock Vapi browser transfer, a real TURN traversal, split execution, or live
infrastructure.

VF-3/VF-6 generic-SIP evidence recorded on 2026-07-15: `cargo test -p
bridgefu --test qualification_generic_wss
direct_browser_to_named_generic_sips_qualifies_pcmu_pcma_context_and_cleanup
-- --nocapture` passes its single qualification test, which internally runs
both PCMU and PCMA destination cases. The real adapters prove authenticated
browser WSS/TLS, context-gated named SIPS/TLS with mandatory SRTP, Opus codec
translation, bidirectional DataChannel↔SIP MESSAGE context, RFC 4733 in both
directions, browser-originated and SIP-originated hangup, and exact route,
bridge, and retained-task cleanup. Supporting `cargo test -p rvoip-sip --test
adapter_data_message_network -- --nocapture` passes five real-network tests
covering the baseline round trip, origin 401 and proxy 407 stale-nonce refresh,
configured-realm rejection, cross-dialog credential non-reuse, and retained
authenticated BYE. This is hermetic all-in-one loopback evidence, not evidence
for the actual browser SDK process, TURN, split execution, a live standards
PBX, cloud infrastructure, or stock Vapi browser transfer.

VF-5/VF-6 generic-WSS handoff evidence recorded on 2026-07-15:
`cargo test -p bridgefu --test qualification_generic_wss
direct_browser_vapi_sip_to_generic_wss_handoff_is_connected_gated_and_resumable
-- --exact --nocapture` passes 1/1 in 15.99 seconds. One authenticated browser
WSS/WebRTC binding first exchanges full-duplex media with a real
Digest-authenticated SIPS/TLS+SRTP Vapi-like assistant. During replacement the
assistant and browser are muted in both directions with zero active graph
bridges. An authenticated interactive-WSS call center cannot promote from its
SDP answer alone: the durable call stays `Transferring` until the destination
application accepts and emits the exact request/connection-bound ready
outcome. Success atomically installs generation 2, emits `connected`, preserves
the browser binding, retires the assistant, and passes full-duplex Opus,
arbitrary binary/JSON DataMessages, RFC 4733 in both directions, browser
hangup, and exact cleanup. A second call receives an explicit destination
rejection, restores the original assistant generation and full-duplex media,
emits `resumed`, and never mixes the rejected destination.

That qualification exposed an rvoip SIP eager-media race in which inbound
publication could precede `CreateMediaSession` commit. The media driver now
waits, cancellation-aware and within one shared setup deadline, for the exact
media owner while failing promptly for missing or terminal sessions. `cargo
test -p rvoip-sip media_owner_wait_tests --lib` passes 3/3 for delayed owner
commit, terminal/missing fail-closed behavior, and cancellation. This is
hermetic all-in-one evidence; it is not an exact built-SDK Chromium→WSS,
TURN-only, split, live destination, stock Vapi transfer, or cloud result.

The separate ignored exact Chromium case
`built_typescript_sdk_hands_off_to_generic_wss_and_cleans_both_terminal_directions`
passes 1/1 and internally runs browser-terminal and destination-terminal
variants through the built TypeScript SDK, real one-use browser attachment,
assistant hold, application-ready WSS promotion, Opus/DataChannel/RFC 4733
traffic, and exact cleanup. The full nonignored generic-WSS file passes 4/4.
The exact-browser result is local-composite validation through the temporary
RTC path override, not immutable dependency, TURN-only, split, live destination,
stock Vapi transfer, or cloud evidence.

Current VF-3/VF-5/VF-6 built-browser local-composite evidence recorded on
2026-07-15: `cargo test -p bridgefu --test qualification_browser_sdk --
--ignored --nocapture` passes its exact-handoff form 1/1. The
ignored test builds and imports
the actual TypeScript `dist` module in BridgeFu's pinned Playwright Chromium,
authenticates a one-use WSS attachment, and first reaches a
Digest-authenticated SIPS/TLS+SRTP assistant. An authenticated generation-2
attempt is rejected and resumes the assistant; an authenticated generation-3
retry promotes a
separately profiled SIPS/TLS+SRTP call center. The same `RTCPeerConnection` and
server connection ID remain connected throughout. Both hold intervals report
zero inbound RTP-byte delta and no browser-microphone leakage, so the assistant
and agent are never mixed. The test proves full-duplex assistant recovery and
agent media after promotion, exact authenticated handoff status generations,
initial plus replacement ringback lifecycle, fake-microphone and remote audio,
initial allowlisted SIP context, later `bridgefu.context.v1` through SIP
MESSAGE, arbitrary labeled binary data at the authenticated rvoip core without
arbitrary SIP injection, mandatory browser DTMF reaching the RFC 4733
destination, hangup, exact cleanup, and attachment-replay rejection. The
production browser profile and fixture are Opus-only for primary audio; the
server observes actual inbound RTP PT 111, the MediaGraph reports Opus/PT111
with a real Opus-to-PCMU transcode, and `transcode_errors` remains zero. The SDK
suite passes 20/20.

The Chromium offer uses telephone-event PT 110/48 kHz and PT 126/8 kHz. rvoip
derives the exact telephone-event PT, clock, SDES MID binding, and direction
from the final offer/answer pair. PT 101/8 kHz, PT 110/48 kHz, and PT 126/8 kHz
are covered; no implicit PT 101 fallback remains. For the negotiated same-clock
PT 110/48 kHz case, audio and DTMF use the primary Opus SSRC and one serialized
outbound RTP sequence/timestamp writer. A different-clock telephone-event uses
the separate supplemental encoding. Pending or ambiguous negotiation fails
closed, and renegotiation clears the previous MID binding until a new final
pair is accepted.

The six-file RTC candidate preserves an explicit negotiated payload type only
when that codec is represented by the sender track and shares the selected RTP
clock. It otherwise retains the legacy primary-payload rewrite. Its SDP
advertises only the primary audio SSRC, avoiding a duplicate Unified Plan track;
the receiver accepts an un-signaled supplemental SSRC only through an
authoritative MID plus negotiated payload type, or a payload type unique to one
receiver, and fails closed on ambiguity. Full local RTC library validation
passes 180/180, including all 13 candidate tests. rvoip's outbound-writer suite
passes 4/4, `dtmf_wire` passes 3/3, and `browser_sdp_interop` passes 13/13. A
bounded one-second post-`tonechange` grace remains required for Chromium's
final three end-of-event retransmissions. The default Bridgefu public browser
edge is explicitly Opus-only.

These RTC, rvoip, and exact Chromium results were produced through the temporary
`../rtc/rtc` path override. The candidate is uncommitted, so the results are
local-composite validation only. Bridgefu now resolves the coordinated
checksummed rvoip 0.3.5 crates.io graph with no Git or path override. That
fetchable package graph is the authoritative release input, but it does not
inherit the historical candidate evidence: downstream browser, DTMF, codec,
and TURN reruns remain mandatory.
TURN-only/public-NAT, split built-SDK execution, and live destinations remain
release blockers and are not claimed by this evidence.

VF-5/VF-6 Amazon Connect evidence recorded on 2026-07-15: `cargo test -p
bridgefu --test qualification_amazon_connect -- --nocapture` passes both
qualification tests. The original test contains browser-originated and
Amazon-originated terminal cases. It
uses a real authenticated one-use WSS attachment, WebRTC/ICE/DTLS, Opus RTP,
DataChannels, the durable named-route actor, MediaGraph, and the production
Amazon adapter lifecycle; only AWS control and Chime network I/O use public
test seams. It proves Opus full-duplex media, DTMF in both directions,
allowlisted `bridgefu.context.v1` projection into initial
StartWebRTCContact attributes with server-owned collision precedence, no live
DataChannel mutation claim, exactly one StopContact, and zero retained graph
routes, adapter routes, lifecycle tasks, sessions, or capacity. Supporting
`cargo test -p bridgefu --test initial_context_repository_conformance --
--nocapture` passes memory and SQLite/restart coverage and defines the same
conditional PostgreSQL conformance path for duplicate/conflict, source and
target generation fencing, and an empty Amazon SIP-header projection.

The added exact handoff test runs three independent all-in-one environments:
browser terminal after success, Amazon terminal after success, and permanent
StartWebRTCContact rejection. Each begins with the same authenticated browser
binding talking full duplex to a real Digest SIPS/TLS+SRTP Vapi-like assistant.
A gated Chime connector proves zero graph bridges and no media leakage in
either direction while the assistant is held, then allows atomic promotion
only when Amazon media is ready. The selected non-default Amazon profile
receives the exact persisted server-owned start attributes; the default
profile remains unused. Success preserves the browser binding, retires the
assistant, passes full-duplex Opus and DTMF, keeps context initial-only, handles
both terminal directions, calls StopContact exactly once, and drains every
route/task/capacity owner. Permanent start rejection acquires no Chime stream
and resumes full-duplex assistant media. The nonignored qualification file
passes 2/2. The separate ignored exact Chromium test
`direct_assistant_handoff::built_typescript_sdk_hands_off_to_amazon_and_cleans_both_terminal_directions`
passes 1/1 and internally runs both browser-terminal and Amazon-terminal
variants. Both results remain hermetic all-in-one evidence. The Chromium result
is local-composite validation through the temporary RTC path override, not
immutable dependency, TURN-only, split, live Amazon Connect, stock Vapi
transfer, or cloud evidence.

VF-5/VF-6 Telnyx evidence recorded on 2026-07-15: `cargo test -p bridgefu
--test qualification_telnyx -- --nocapture` passes both exact network
qualification tests in 22.34 seconds. The original test contains both direct
authenticated one-use WSS/WebRTC ingress and Vapi-like trusted-CIDR SIPS/SRTP
ingress. It uses the crates.io `telnyx = "=0.1.0"`
client through Bridgefu's production provider executor, creates two linked
provider calls plus a distinct Digest-authenticated media attachment, and
proves full-duplex audio, RFC 4733 in both directions, signed `call.bridged`
gating, bounded 429 retry, invalid-signature rejection, webhook deduplication,
both terminal directions, exact hangup, cleanup, and attachment replay
rejection. Supporting Telnyx and lifecycle suites pass 13/13 plus the focused
admission, cache-convergence, terminal-cleanup, and durable-command-ID
regressions.

The added handoff test starts with an authenticated WSS/WebRTC browser talking
full duplex to a real Digest SIPS/TLS+SRTP Vapi-like assistant. It holds that
assistant with zero graph bridges and no media leakage while the production
Telnyx executor creates a distinct, generation-bound Digest SIP/SRTP media
attachment and destination call. The destination HTTP response is explicitly
insufficient to promote. An invalid signature, a validly signed stale provider
reference, and a duplicate exact event cannot switch the call; only the first
valid signed destination-role `call.bridged` event for the exact persisted
reference promotes the pending generation. The browser connection/binding
remains stable, the assistant retires exactly, and Opus↔PCMU full-duplex media
plus RFC 4733 pass after promotion. A second attempt receives a permanent
destination rejection, hangs up the exact provider media call once, resumes
the original assistant and full-duplex media, then drains all routes, tasks,
and capacity. The nonignored qualification file passes 2/2. The separate
ignored exact Chromium test
`direct_assistant_handoff::built_typescript_sdk_hands_off_to_telnyx_and_cleans_both_terminal_directions`
passes 1/1 in 35.38 seconds and internally runs both browser-terminal and
Telnyx-terminal variants. This remains deterministic all-in-one evidence. The
Chromium result is local-composite validation through the temporary RTC path
override, not a stock Vapi browser transfer, split execution, an immutable
dependency result, or a restricted live-account qualification.

Current post-change Bridgefu regression evidence recorded on 2026-07-15:
`cargo test -p bridgefu --lib` passes 328/328; `private_forwarding` passes 7/7;
`call_directionality` passes 3/3; and `call_execution_supervisor` passes 39/39.
The generic-WSS file passes all four nonignored tests and its exact Chromium
test passes 1/1; Amazon passes 2/2 plus its exact Chromium 1/1; Telnyx passes
2/2 plus its exact Chromium 1/1; and the generic-SIP exact Chromium test passes
1/1. StandardCharter passes 48 core, 11 web, and 16 Python tests, and its
production web build succeeds. These are local library, loopback, and
local-composite browser results. They do not replace owner-authorized Vapi/AWS
canaries, a restricted live-provider run, TURN/public-NAT qualification,
built-SDK split execution, cloud smoke, or the release load/chaos campaign.

At that time, after restoring the exact `1e5b7d4...` Git source and lock
provenance,
`cargo test --locked -p bridgefu --lib` independently passes the same 328/328
library suite. This is historical evidence for the former graph; it does not
qualify the current crates.io rvoip 0.3.5 packages or reproduce the four exact
Chromium results.

VF-1 local-candidate WebRTC signaling evidence recorded on 2026-07-15:
`cargo test -p rvoip-webrtc --features signaling-ws --test
outbound_ws_originating -- --nocapture` passes 11/11 authenticated
`offer-ready` cases, and `cargo test -p rvoip-webrtc --test dtmf_wire --
--nocapture` passes 3/3. The outbound RTP-writer suite passes 4/4 and
`browser_sdp_interop` passes 13/13. The full local RTC library passes 180/180,
including all 13 tests added with the six-file candidate. These results resolve
through the uncommitted local RTC path override and remain owner-review
evidence rather than a result for the current published graph. A clean
qualification rerun against the locked rvoip 0.3.5 packages and
TURN-only/public-NAT qualification therefore remain open.

Required public product interfaces for these gates are named, server-controlled
routes (`GET /v1/routes`, `POST /v1/routes/{route_id}/calls`) and append-only,
generation-fenced leg replacement
(`POST /v1/calls/{call_id}/legs/{leg_id}/replace`). Route creation returns a
complete two-minute, one-use SIPS or WSS attachment descriptor rather than a
bare token. The existing low-level call API remains privileged. Amazon Connect
advertises initial StartWebRTCContact context only; generic WSS may advertise
live DataChannels; SIP advertises only its configured initial-header and SIP
MESSAGE capabilities.

## Architecture decisions

### Library ownership

MOQT is implemented in three layers:

1. A qualified, exact-revision moq-rs dependency implements the wire protocol;
   project-owner review is still required before release approval.
2. `rvoip-moq` owns the stable rvoip-facing compatibility and lifecycle API.
3. Bridgefu consumes only rvoip broadcast traits and never moq-rs types.

`rvoip-moq` supports one production protocol tuple in Bridgefu 1.0:
MOQT draft-19, MSF draft-01, and LOC draft-03. Incompatible peers are rejected
explicitly. Draft changes are never adopted automatically; scheduled CI only
reports changes in the IETF drafts or upstream implementation.

Bridgefu consumes WebRTC through the exact crates.io
`rvoip-webrtc`/`rvoip-webrtc-stack`/`rvoip-rtc` 0.3.5 package graph and its
Cargo.lock checksums. Future alpha-engine fixes may still be developed on an
owner-controlled fork, but Bridgefu does not adopt a floating branch or
unpublished path override, and no upstream contact occurs without owner
review. A historical local, uncommitted
`codex/dtmf-codec-identity` candidate at base
`1e5b7d4be6d94850694f2519f4c235d16c871d53` makes codec identity include MIME,
clock, and channel count; advertises only the primary audio SSRC; routes valid
un-signaled supplemental SSRCs by authoritative MID/payload identity; preserves
only represented same-clock payload types on write; and fails closed on
ambiguous ownership. Its six-file diff, current stable patch ID
`478b7da63ea6d195f446a9abce4c56e62129a86e`, and local-path evidence are
recorded in `docs/webrtc-fork-review.md`. The validation runs used temporary
`../rtc/rtc` manifest overrides and a path-resolved generated lock entry. Those
overrides are removed. The candidate remains historical validation-only
evidence until equivalent downstream qualification is rerun against the
published, locked 0.3.5 graph. Reproducible defects are reported to
`eisenzopf/rvoip`; Bridgefu does not carry or publish a dependency patch.

### Provider scope

Bridgefu 1.0 has one first-class external provider-control integration:
Telnyx. It uses the published `telnyx` crate pinned as `telnyx = "=0.1.0"`
with only the Call Control, webhook, and selected rustls features. The SDK's
optional tracing feature is deliberately disabled for 1.0 because its current
debug request event includes the full URL, whose action path contains the
provider call identifier. Bridgefu emits its own metadata-only provider spans
and metrics instead; the SDK feature can be enabled after that URL is safely
classified or redacted.

The published 0.1.0 `rustls-ring` feature selects reqwest's no-provider mode.
Bridgefu therefore installs ring's rustls crypto provider before constructing
the SDK client and verifies that a process-global provider exists. This is a
local compatibility shim, not an upstream submission; any crate patch or
maintainer contact remains owner-review-gated.

Bridgefu owns call/leg policy, durable idempotency, SIP attachment routing, and
normalized events; the SDK owns Telnyx request models, command dispatch,
command-ID behavior, response errors, and Ed25519 webhook verification. The
companion `telnyx-axum` crate may be adopted if its extractor fits the final
HTTP boundary, but it is not required because `telnyx::webhooks::Verifier`
already accepts the exact raw body and headers retained by Bridgefu.

Twilio and Vonage are deferred beyond 1.0 and are not release blockers. Their
existing enums, persistence compatibility, and experimental adapter scaffolds
may remain while stored data is migrated safely, but the 1.0 API, capability
matrix, examples, live qualification, and production claims must expose only
Telnyx. A deferred provider request returns an explicit unsupported-capability
error; it never silently falls back to Telnyx or generic SIP semantics.

### Transport roles

- UCTP 0.2 over QUIC or WebTransport carries authenticated interactive
  sessions, messages, internal gateway-to-worker media, and direct fanout.
- MOQT is the default relay-capable one-to-many broadcast transport.
- WebTransport is a substrate rather than a fanout protocol.
- RTP over QUIC retains an adapter seam but is not a Bridgefu 1.0 feature.

### Runtime roles

- `all-in-one`: API, providers, public transports, worker, SQLite, and an
  optional embedded MOQT relay.
- `gateway`: API/webhooks and public SIP, RTP, WebRTC, and UCTP termination;
  authenticated forwarding to a pinned worker.
- `worker`: call state machine, rvoip Orchestrator, MediaGraph, transcoding,
  Amazon Connect, and broadcast origins.
- `moq-relay`: independently scalable authenticated MOQT relay.

PostgreSQL is the clustered source of truth. Redis provides leases, capacity,
replay protection, rate limits, short-lived routing, and worker commands.
Active calls remain pinned and are drained rather than migrated.

## Public contract decisions

- `POST /v1/calls` creates exactly two explicitly bridged logical legs.
- Leg kinds are SIP, interactive WebRTC, WHIP/WHEP, Amazon Connect, and
  provider-controlled Telnyx. Persisted Twilio/Vonage discriminants remain
  readable for compatibility but are not accepted as new 1.0 provider legs.
- Tenant identity is derived from the authenticated principal.
- `Idempotency-Key` is retained durably for 24 hours.
- Inbound legs use hashed, single-use, two-minute attachment tokens; global
  FIFO pairing is forbidden.
- Calls use `pending`, `connecting`, `active`, `transferring`, `ending`,
  `ended`, and `failed` states.
- Legs use `pending`, `awaiting_attach`, `signaling`, `connected`, `held`,
  `ending`, `ended`, and `failed` states.
- `bridgefu.context.v1` is the allowlisted SIP-header/DataChannel envelope.
- Broadcasts reference a real connected `source_leg_id` and inherit its tenant.
- MOQT responses include protocol versions and relay path; UCTP responses
  include protocol version, session, and stream.
- Bridgefu 1.0 transfer is authoritative SIP REFER or Telnyx Call Control.
  Protocol-native WebRTC transfer is not standardized by the selected stack
  and returns an explicit capability error. The newly required API-level leg
  replacement is a Bridgefu call-engine operation, not a claim that WebRTC has
  a protocol-native transfer method; its completion is tracked by VF-5.

## Gates

Current component status after the 2026-07-14 stable-tree qualification follows.
This historical table does not override the product support matrix or `VF-*`
release gates above:

| Gate | Status | Remaining release evidence or authority |
|---|---|---|
| 0–6 | Complete | None in the local implementation scope. |
| 7 | Local adapter/component evidence substantial; Vapi widget and outbound-WSS-DTMF gaps open | VF-0 through VF-7, including the protected Vapi browser transfer feasibility run, API-level leg replacement, the rvoip #54 fix and generic-WSS Chromium rerun, exact destination compositions, and deployed public-NAT/TURN runs. Generic SIP, Amazon Connect, and Telnyx already pass against locked rvoip 0.3.5. |
| 8 | Local Telnyx implementation complete; live qualification pending | Restricted live Telnyx test-account control/media workflow. |
| 9 | Direct UCTP and local/static MOQT complete; clustered dynamic MOQT pending | Owner review, immutable pin, enablement, and requalification of the private dynamic publisher-policy candidate. |
| 10 | Local modes/config/observability/Compose preflight/Terraform validation complete | Protected multi-architecture artifact plus disposable AWS/GCP apply-smoke-destroy. |
| 11 | Finite local qualification complete; release campaign pending | Exact one-hour loads, deployed chaos, protected provider/StandardCharter runs, and coordinated release-candidate revisions. |

An unchecked item below is not implied by a green local smoke. Production
deployment, public publication, fork push/adoption, cloud apply, and live
provider calls remain outside automatic authority.

### Gate 0 — Plan and baseline (`complete`)

- [x] Record the canonical roadmap before implementation edits.
- [x] Preserve the existing dirty worktrees on coordinated branches.
- [x] Record exact starting revisions.
- [x] Run and record the baseline test matrix.
- [x] Separate existing scaffolding from new functional changes.
- [x] Pin Bridgefu CI to the exact checksummed rvoip 0.3.5 crates.io graph
  rather than a floating branch or sibling checkout.

Exit: all existing work is accounted for and the baseline is reproducible.

### Gate 1 — Freeze StandardCharter (`complete`)

- [x] Add hermetic Connect and Chime test doubles and golden Vapi SIP fixtures.
- [x] Assert `X-Correlation-Id` to Amazon `correlation_id` mapping and exact
  StartWebRTCContact attributes.
- [x] Assert G.711 to/from Opus media, screen-pop events, and bidirectional
  teardown.
- [x] Add a protected non-production Vapi-to-Connect smoke workflow and a
  drain/rollback runbook.
- [x] Keep the existing production path isolated.

The Gate 7 Amazon audit reopened this gate at Bridgefu revision `6e30708`.
Bridgefu revision `eb9932c` and rvoip revisions `84f84fbf`, `869e20d6`, and
`a18df977` close the hermetic media and lifecycle gap without changing the
production connector default. `tests/standardcharter_contract.rs` now enters
through the real localhost SIP listener, completes INVITE/180/200/ACK, sends
real PCMU RTP through the production MediaGraph to a credential-free fake
Connect Opus session, loops Opus back to real PCMU RTP, and proves ordered
screen-pop stages, exactly-once StopContact, and both Vapi- and
Connect-originated teardown. The end-to-end test exposed and now guards two
reusable rvoip defects: bridge handles must retain transport-owning media
streams, and decoded audio callbacks must preserve source RTP timestamps.

Focused evidence passes 247 media-core tests, 62 Amazon Connect library tests,
3 Amazon media-bridge tests, and all 34 locked StandardCharter contract tests.
Bridgefu revision `84d760e` adds the manual-only workflow, its fixed
`standardcharter-nonproduction` GitHub environment boundary, exact confirmation
and owner-authorization gates, secret-only targets, offline-default validation,
redacted lifecycle evidence, and the executable drain/rollback runbook. The CI
artifact check parses the workflow and scripts, executes synthetic offline
preflight/plan paths, and proves that production-marked targets, option-looking
targets, and unauthorized execution are rejected. The locked 34-test
StandardCharter contract remains green after the artifact change.

No AWS, Vapi, SSH, deployment, or rollback operation was executed to close this
gate. An owner-authorized run of the protected non-production workflow remains
explicitly unchecked Gate 11 release-qualification evidence; checking in a safe
and locally verifiable workflow does not claim that external result.

This gate freezes the legacy Vapi SIP-to-Amazon contract only. It does not
prove that a stock Vapi browser `webCall` can transfer to SIP; that externally
credentialed feasibility result remains pending in VF-0.

Exit: current StandardCharter behavior is reproducibly protected without a
production change.

### Gate 2 — Complete rvoip foundations (`complete`)

- [x] Move `AuthenticatedPrincipal` to core traits and preserve issuer, tenant,
  subject, scopes, expiry, method, and assurance through every validator/event.
- [x] Add transport-neutral DataMessage adapter, Orchestrator, and client APIs.
- [x] Complete MediaGraph IDs, snapshots, codec grouping, bounded fanout,
  queue/transcoder diagnostics, and aggregate-safe metrics.
- [x] Preserve compatibility through re-exports and legacy wrappers.

Gate 2 evidence recorded on 2026-07-10:

- rvoip revision `b8c1f25b5e797c00012cca1fe66d252ba3f8bd5d` was pushed on
  `codex/bridgefu-1.0-rvoip`; Bridgefu CI pinned that exact revision at the
  time. This historical source pin is superseded by the crates.io 0.3.4
  dependency checkpoint above.
- The complete rvoip workspace passes `cargo check --workspace --all-targets`.
- Focused foundation, identity, UCTP, client, WebRTC, and Amazon suites pass
  441 tests with zero failures; QUIC, WebTransport, and WebSocket adapters
  compile together.
- The reviewed rtc alpha fork revision
  `1e5b7d4be6d94850694f2519f4c235d16c871d53` passes 167 library tests and is
  exact-pinned by both rvoip and the top-level Bridgefu build. Bridgefu's
  locked consumer graph passes all 34 tests.
- The current rtc-line port remains review-only on the `eisenzopf/rtc` fork at
  revision `a26e9b080a68cdf4210d7f34e227006625c89668`; no upstream submission is
  open.
- Migration and compatibility guidance is recorded in rvoip's
  `docs/BRIDGEFU_FOUNDATIONS_MIGRATION.md`.

Exit: validator parity, ownership isolation, DataMessage round trips, and
MediaGraph stress tests pass.

### Gate 3 — Harden rvoip authentication and lifecycle (`complete`)

- [x] Authenticate WS/WSS before upgrade and enforce full route ownership.
- [x] Enforce SIP Digest, Bearer, trusted-CIDR, and server-verified mTLS at the
  listener before application events.
- [x] Verify UCTP version, replay, signature, principal, scopes, and ownership
  before delivering replies or commands.
- [x] Enforce caps and deterministic peer cleanup on QUIC, WebTransport, and
  WebSocket substrates.
- [x] Treat a denied SIP authentication reservation as a terminal admission
  decision. A denied initial challenge must not mint or persist a Digest nonce,
  call a credential/challenge/audit provider, or return another 401/407.
  Preserve the released exhaustive auth-decision enums through an additive
  richer evaluation path; the listener returns a bounded `503` with a typed
  `Retry-After` clamped to 1–3,600 seconds and no auth challenge. Prove the
  legacy empty-rejection projection plus real-wire absent, subsecond, and huge
  retry hints with counting providers and replay stores.
- [x] Close the release-wide credential diagnostic boundary found by the final
  SIP integration audit. Every direct and enclosing auth container in
  auth-core, core/core-traits, client, UCTP, WebRTC, IMS-AKA, LDAP, and
  users-core must preserve live/serialized values while exposing only
  scheme/stage, presence/length/count, and fixed classes in `Debug`/`Display`.
  This includes bearer/access/refresh/ID/DPoP tokens, passwords/hashes, Digest
  challenge/nonce/response/cnonce/HA1, AKA vectors, bind/TURN credentials,
  signed credentials, signature headers, step-up payloads, WebSocket query auth,
  and mapped principals.
- [x] Replace production registrar and UCTP auth log relays with metadata-only
  fields. Boxed/erased auth errors must enter the same typed stage classifier as
  direct conversions; no `Other(err.to_string())` or provider error can bypass
  the boundary. Add source guards and malicious first-party canaries.
- [x] Make all UCTP/core/client outer event, envelope, payload, and state Debug
  implementations metadata-only while retaining serde and routing behavior.
  Re-run negative auth, transport, and lifecycle suites before Gate 3 is closed
  again.

Gate 3 evidence recorded on 2026-07-11:

- rvoip revision `a0335daf81ba5e18bddf960c61d4f5bc01c6079e` was pushed on
  `codex/bridgefu-1.0-rvoip`; Bridgefu CI pinned that exact revision at the
  time. This historical source pin is superseded by the crates.io 0.3.4
  dependency checkpoint above.
- Auth-core passes 89 tests; rvoip-core passes 163 tests, including saturated
  lifecycle fallback, idempotent terminal delivery, stale-event rejection,
  subscription cleanup, and MediaGraph lifecycle stress.
- SIP dialog passes 325 tests, rvoip-sip passes 198 library tests, and SIP
  transport passes all 115 all-feature tests, including 12 TLS/WSS mTLS modes
  plus negative listener-auth, source-binding, CANCEL, ACK, and replay cases.
- UCTP passes 115 tests; QUIC, WebTransport, and all-feature WebSocket suites
  pass 8, 3, and 11 tests respectively. A real WebSocket saturation test with
  capacity one proves terminal fallback releases the first peer and admits an
  authenticated second peer.
- The feature-correct WHIP/WS/WSS ownership and pre-upgrade authentication
  matrix passes 18 tests. The full WebRTC suite passes 96 tests; its two known
  baseline media-stat assertions remain isolated from signaling auth and are
  tracked as rtc/media test-environment debt rather than Gate 3 regressions.
- Strict clippy is clean for core/auth/UCTP and every substrate across all
  targets/features, for SIP transport/dialog/proxy, and for the focused WebRTC
  signaling library/tests. Migration guidance is in rvoip's
  `docs/BRIDGEFU_FOUNDATIONS_MIGRATION.md`.
- Final closure is at local rvoip revision
  `85b932e46267e59fbdb16864f47a37bdac9ae2f5`. Revisions `2238c70d` and
  `9dacd544` close the remaining WebRTC DataChannel/packet and UCTP correlation
  diagnostic surfaces. An independent combined-revision audit closes all three
  reopened diagnostic items; 194 credential, registrar, erased-error,
  core/client, and UCTP source-guard/canary tests pass.
- QUIC, WebTransport, and WebSocket all-feature suites pass after the final
  UCTP change. The WebSocket saturation test now fills the atomic source queue,
  forces critical-event pump shutdown, proves lifecycle fallback and exact
  permit release, and admits a second authenticated peer.
- The final `cargo test -p rvoip-sip --no-fail-fast` run exits zero at the exact
  revision above: 337 library tests and every executable integration target
  pass, including default-stack Endpoint auth, redirect and 422 retry,
  listener mTLS/tenant binding, CANCEL, PRACK, session timers, real audio and
  three-peer bridge media, admission hysteresis, and secure wire diagnostics.
  Doctests pass 213/213 with seven explicitly documented examples ignored.
  No `RUST_MIN_STACK` override is used.
- The exact closure revision is intentionally local pending owner review. It
  has not been pushed, submitted upstream, or substituted into Bridgefu CI;
  the existing remotely available exact CI pin remains unchanged.
- The final 2026-07-14 UCTP reauthorization audit found and fixed a scope-
  dropping refresh race. The regression
  `scope_dropping_refresh_is_rejected_before_existing_media_authority_changes`
  and its wire-level counterpart
  `auth_refresh_rejects_scope_drop_before_existing_session_authority_changes`
  pass: every bound Session is reauthorized under the mutation lock before a
  replacement principal becomes visible, and a rejected refresh leaves the
  previous principal and media authority intact. The broader UCTP, QUIC, and
  WebTransport library matrix passes 53/53. This is local negative-security
  evidence, not a deployed qualification result.

Exit: auth-negative, cross-tenant, replay, expiry, cap, and leak tests pass on
every supported substrate.

### Gate 4 — Release UCTP 0.2 (`complete`)

The audited implementation order is deliberate; a crate-version change is the
last step rather than evidence that the wire path is complete.

1. [x] Define one `UctpCompatibility` descriptor for the crate release,
   envelope version, RTP-datagram version, and ALPN; use it in negotiation,
   diagnostics, and `auth.challenge` capabilities.
2. [x] Enforce the eight-byte UCTP header followed by one complete RTP packet
   through typed pack/unpack APIs, retaining any raw helpers only as explicitly
   unchecked compatibility surfaces; add an authoritative full-byte vector.
3. [x] Replace per-Session allocators and first-route lookup with one
   peer-scoped, non-reusing media router shared by QUIC and WebTransport. Bind
   every negotiated wire Stream ID to its real adapter Stream before emitting
   `stream.opened`; route each datagram with that binding's Session,
   Connection, Stream, and fanout context.
4. [x] Replace random-only subscription namespaces with authenticated,
   resolver-backed wire-to-core Session/Connection bindings. Tie subscriber
   route handles to peer cancellation and remove exactly the owning route on
   unsubscribe, disconnect, expiry, or drain.
5. [x] Register managed MediaGraph virtual publishers through the existing
   Orchestrator publisher/subscriber path, with one source receiver and atomic
   graph-route/registry cleanup.
6. [x] Prove same-peer multi-Session isolation and real wire-driven subscribe,
   fanout, disconnect, reconnect, scope/tenant denial, and token-expiry behavior
   on QUIC and WebTransport; add key-log-enabled packet-capture conformance.
7. [x] Version UCTP, QUIC, and WebTransport crates as 0.2, update locks and the
   breaking-wire migration guide, only after every preceding compatibility,
   routing, listener, and conformance suite passes.

Exit: authenticated QUIC and WebTransport listeners receive media and the 0.2
wire suite passes.

Gate 4 evidence recorded on 2026-07-11:

- rvoip revision `ef74512967e26f994c4593ed2187517e2c0307b4` was pushed on
  `codex/bridgefu-1.0-rvoip`; Bridgefu CI pinned that exact revision at the
  time. This historical source pin is superseded by the crates.io 0.3.4
  dependency checkpoint above.
- `rvoip-uctp`, `rvoip-quic`, and `rvoip-webtransport` are versioned 0.2.0
  with coordinated changelogs. The serializable compatibility descriptor is
  advertised in `auth.challenge` and keeps crate, envelope, datagram, ALPN,
  and RTP-profile versions distinct.
- The full post-bump core/UCTP/QUIC/WebTransport/all-feature WebSocket matrix
  passes 333 tests (165 + 143 + 9 + 5 + 11). All-target/all-feature strict
  clippy is clean for the same packages.
- The checked media API rejects payload-only bodies and passes an exact
  24-byte UCTP+RTP vector plus a checked-in PCAP fixture. TLS key logging is an
  explicit conformance-only opt-in and is never enabled from environment alone.
- QUIC and WebTransport each prove several Sessions on one physical peer have
  non-reused, non-aliasing media IDs; failed batches roll back; ending one
  Session preserves its siblings; both transports receive real RTP media.
- Real authenticated `stream.subscribe` and `stream.unsubscribe` envelopes on
  both QUIC and WebTransport resolve through an explicit canonical Session,
  deliver media, remove the exact subscriber row, and stop post-unsubscribe
  delivery. Resolver rejection happens before Session state or events exist.
- `Orchestrator::register_virtual_publisher` attaches a bounded ten-frame sink
  to the reusable MediaGraph, fans canonical Stream IDs through the existing
  registry, and uses generation-scoped cleanup that cannot delete a
  replacement publisher.
- Bridgefu's locked consumer graph passes 34 tests against the 0.2.0 crates;
  StandardCharter remains unchanged and passes all 35 core and 3 web tests.
  CI now runs the all-target Gate 4 matrix and the same strict clippy set.
- The current rvoip revision packages `rvoip-uctp` 0.2.0 successfully. Dry
  packaging the dependent QUIC/WebTransport crates correctly waits for a
  separately authorized publication of `rvoip-uctp` 0.2.0; no artifacts were
  published.

### Gate 5 — Finish rvoip-moq draft-19 (`complete`)

The implementation pins the published MOQT-19/MSF-01/LOC-03 tuple.

1. [x] Fork `cloudflare/moq-rs` under `eisenzopf` and record upstream main
   `5295993480c3d19f6057d0bb3c8b0b394ad1df62` plus the draft-18 port base.
   Keep every patch private to the fork until user review; do not open upstream
   issues or pull requests.
2. [x] Add serializable `MoqProtocolVersion` and `MoqCompatibility` types and
   make the published MOQT-19/MSF-01/LOC-03 tuple authoritative across ALPN,
   negotiation, descriptors, diagnostics, logs, and metrics. Reject mismatches
   explicitly and remove the current runtime/target split.
3. [x] Base the port on Cloudflare's draft-18 work at exact revision
   `c7e80e49f4189efd1e55e2533eab36adf0e8f4b4`, reconcile it with the current
   upstream mainline, and port the resulting wire engine to draft-19. Add
   golden control/data vectors plus raw-QUIC and WebTransport coverage.
4. [x] Pin `moq-transport`, `moq-native-ietf`, and `moq-relay-ietf` to the same
   qualified 40-character fork revision, pending project-owner review. Permit
   that exact Git source in supply-chain policy without allowing branches or
   floating revisions, and prove no moq-rs type appears in the public
   `rvoip-moq` API.
5. [x] Implement the rvoip-owned LOC Opus object and MSF catalog model,
   including canonical 48 kHz mono 20 ms audio, collision-free namespace tuple
   validation, catalog authorization, Joining FETCH retention, and an optional
   sanitized events track. Production MSF-01 uses one new MOQT stream per
   Object as required by MSF-01 section 6; LOC datagrams remain an explicitly
   experimental non-MSF profile and are not enabled by Bridgefu 1.0.
6. [x] Implement managed origin, publication, subscriber, embedded-relay, and
   external-relay lifecycles with mTLS, scoped authorization, reconnect,
   health, graceful drain, exact cleanup, and bounded task/queue behavior.
7. [x] Prove publication and subscription through a relay over raw QUIC and
   WebTransport, then test against one independent implementation at the exact
   same draft. Record packet captures, negotiated versions, and relay paths.
8. [x] Add scheduled CI that compares the pinned tuple and fork base with IETF
   Datatracker and moq-rs upstream, emits a report or tracking issue, and never
   edits dependencies or contacts upstream automatically.
9. [x] Prepare the fork delta, interoperability report, and proposed upstream
   patch for user review. Submission remains a separately authorized action.

Gate 5 completion evidence recorded on 2026-07-12:

- The private `eisenzopf/moq-rs` fork is exact-pinned at
  `ef52ac8656513bb3b07b4b9b80152ac24bb2467e`. The draft-18 base is an ancestor
  of this revision. It implements the authoritative draft-19 request, data,
  PUBLISH, FETCH, target, acceptance, bounded retention, Joining FETCH, live
  fallback, namespace discovery/update, and least-privilege relay-admission
  behavior. It passes 429 transport tests; relay passes 111 library, 25 binary,
  one admission-contract, and five feature-policy tests plus strict Clippy and
  warning-free rustdoc.
- rvoip revision `7d83b66545789d55471c13a7c68eb54a9493cc0a` is pushed on
  `codex/bridgefu-1.0-rvoip` and exact-pins that fork. The final `rvoip-moq`
  matrix passes 134 unit, three managed E2E, two public API, and seven admission
  tests. Public types are rvoip-owned.
- Raw QUIC and WebTransport both traverse managed role-separated relays with
  warm Relative Joining FETCH and cold live fallback. A separate two-topology
  test sends a catalog Object from an mTLS publisher through a subscribe-only
  mTLS upstream hop to a token subscriber, covers route replacement/reconnect,
  denies publishing with the relay certificate, and proves drain cleanup.
- A real in-app Chromium WebTransport client used a one-day hash-pinned
  certificate and two-minute receive-only token, negotiated draft 19, and
  parsed an MSF-01 catalog. The browser implementation is pinned and the token
  is carried in structured SETUP rather than the URL.
- The reproducible packet-capture script records both `moqt-19` and `h3` ALPN
  handshakes. Its recorded run captured 166 QUIC packets with zero drops and no
  TLS key log while both managed relay tests passed.
- Unmodified `moq-dev/moq` at
  `ea97ce44470e35a49f5f18acf8ad96daa37aabea` independently passes draft-19
  WebTransport namespace discovery, subscription, and live Objects. Its native
  client currently omits mandatory PATH/AUTHORITY and its high-level subscriber
  does not expose retained FETCH; those limits remain explicit and never cause
  a silent downgrade.
- Exact dynamic external routes are bounded, installable after startup,
  generation-safe, and drain-owned. Durable distribution of those registrations
  to every relay replica remains a Gate 10 PostgreSQL/Redis control-plane task.
- The fork review packet and interoperability reports are checked in. No
  upstream issue, pull request, or maintainer message has been created; any
  submission remains pending project-owner review.

Exit: both substrates traverse a relay and version, packet-capture, and
interoperability suites pass.

### Gate 6 — Build Bridgefu's durable call engine (`complete`)

The implementation order is deliberate. In particular, FIFO pairing cannot be
removed safely until rvoip preserves a single-take, redacted inbound routing
hint for SIP and WebRTC connections.

1. [x] Add an additive rvoip inbound-context seam before the normalized
   `ConnectionInbound` event. Preserve the SIP Request-URI routing hint and the
   WHIP/WS path or authenticated session hint, expose it through Orchestrator as
   a single-take value, and erase it on terminal cleanup. Prove once-only,
   redacted, transport-bound, and cross-tenant-safe behavior.
2. [x] Add Bridgefu's pure typed two-leg aggregate with strong call/leg/tenant
   IDs, exact call and leg states, directions, typed leg kinds, UTC deadlines,
   binding generations, sanitized failures, transition invariants, and
   serializable effect intents. Keep the frozen Amazon runtime untouched.
3. [x] Add high-level atomic repository contracts and a memory implementation
   covering capacity reservation, tenant-scoped load, optimistic command/outbox
   commit, attachment consumption, provider-event deduplication, deadlines,
   and restart claims. Use one lock across all memory indexes so tests exercise
   real atomic semantics.
4. [x] Add SQLite and PostgreSQL migrations and implementations for calls,
   legs, commands, 24-hour idempotency, attachments, provider events, outbox,
   worker capacity, and assignments. Run one repository conformance suite
   against all three backends; use cancellation-safe `BEGIN IMMEDIATE` or
   conditional capacity updates rather than count-based admission. Read paths
   must not mutate storage, SQL mutations write only changed rows, normalized
   call/leg ownership must be database-enforced, and mandatory CI must exercise
   a real disposable PostgreSQL service plus two-instance races.
5. [x] Add a transactional call service and authenticated API principal. Read
   `Idempotency-Key` from the header, bind it to tenant plus canonical request
   hash, persist state/command/effect intents before external I/O, and reconcile
   provider or rvoip outcomes afterward. Tenant override requires a dedicated
   administrative scope.
   - Require durable 24-hour idempotency for create and non-naturally-idempotent
     mutating call operations such as transfer and DTMF. Persist a typed
     operation receipt atomically with each service/control command so a retry
     returns the original result even when wall time, aggregate version, or a
     newly generated Command ID would differ; reject reuse for another
     canonical request or receipt kind.
   - Persist a versioned execution plan alongside the aggregate so each leg's
     endpoint/configuration survives replay and restart without putting secrets
     in domain state.
   - Add durable payloads for transfer targets, a fenced DTMF/control outbox,
     and outbound connection binding with permanent connection-ID uniqueness.
   - Add one atomic effect-result reconciliation transaction that verifies the
     outbox claim, records provider/rvoip references, releases callback-before-
     reference events, commits the follow-up state transition, completes the
     effect, and retains an exact replay result.
   - Keep service-managed mutations behind the service repository boundary.
     Raw compatibility methods must not create state transitions or complete
     effects for a service-managed call in a way that bypasses execution-plan,
     payload, reference, or reconciliation invariants.
   - Bind every returned provider reference to the exact provider endpoint and
     account profile in the persisted execution plan before releasing queued
     callbacks. Validate effect follow-ups against the claimed intent, leg,
     binding generation, and success/failure result.
   - Give control effects a database-safe per-binding sequence, claim only the
     oldest unfinished command, and invalidate claimed DTMF as soon as its leg
     leaves `connected` or `held`, including teardown races.
   - Return the original creation snapshot on an idempotent replay, enforce one
     Command ID namespace across core and service operations, and redact endpoint
     URIs, transfer destinations, phone numbers, and credential-bearing URL
     components from durable-model diagnostics.
   - Preserve service ownership independently from the execution-plan row.
     A normalized, one-way `service_managed` marker on the call must agree with
     exact plan coverage, and every raw compatibility mutation checks that
     marker so deleting or corrupting a plan cannot downgrade a managed call to
     a legacy call.
   - Retire expired service/control idempotency receipts into immutable,
     cross-linked claim tombstones before allowing active-key reuse. Historical
     command requests must be backed by either their exact active receipt or an
     expiry-eligible tombstone; premature receipt deletion remains a fail-closed
     storage error.
   - Reconstruct durable evidence bidirectionally: every successful or externally
     failed managed effect has exactly one reconciliation receipt, every active
     outbound binding has its original bind receipt, and every receipt points
     back to the same immutable command/effect identity. Locally invalidated
     control work carries an explicit, command-backed retirement failure.
   - Inject rvoip `AuthenticatedPrincipal` validation into Axum, inherit tenant
     from the principal, require operation scopes, and allow tenant override
     only with `calls:tenant-override`.
   - Keep `ConnectScreenPopServer` and the existing StandardCharter listener
     untouched; the new API and effect executor do not call its active-call or
     teardown helpers during this item.
6. [x] Add memory and Redis worker coordination with fenced leases, capability
   and capacity-aware selection, reservations, routing, replay markers, drain,
   and Redis Streams notification. PostgreSQL remains authoritative and a
   transactional outbox avoids PostgreSQL/Redis dual writes.
   - Reuse authoritative `workers.reserved_calls` and `worker_assignments`;
     select and reserve an active, non-draining, capability-compatible worker
     inside the same call-creation transaction after idempotency replay lookup.
     Do not create a second Redis or lease-table capacity authority.
   - Add expiring, non-resurrectable worker leases, exact-fence renewal, and a
     one-way drain transition. PostgreSQL lease decisions use database time;
     standalone backends use an injected clock for deterministic parity tests.
     A delayed projector evaluates renewal eligibility against the durable
     event's recorded database time, not Redis recovery time, so an ordered
     backlog can always converge after an outage.
   - Persist a separate, ordered coordination outbox for worker snapshots, call
     routes, and work-available notifications. A projector applies each event
     idempotently to memory or Redis, then acknowledges PostgreSQL; it never
     writes PostgreSQL and Redis as one request-path operation.
     PostgreSQL sequence allocation and claims share a deployment-scoped
     transactional lock so visible sequence order is commit order; a paused
     lower-sequence producer cannot be overtaken by a later commit.
   - Treat Redis route/replay entries and per-worker Streams as short-lived
     sequence-checked hints only. Consumers still claim authoritative database
     work before external I/O, use bounded database fallback polling, and
     tolerate duplicate, missing, trimmed, stale, flushed, or reordered Redis
     messages.
   - Run Redis Stream consumers with dedicated blocking connections,
     `XREADGROUP`/`XACK`/`XAUTOCLAIM`, bounded streams, deployment-prefixed keys,
     `rediss://` in clustered modes, and no raw tokens, secrets, provider
     payloads, or tenant authorization decisions in Redis.
     Blocking response deadlines must exceed the configured interval;
     disconnect, restart, `NOGROUP`, flush, and stream expiry reconnect and
     recreate state with bounded backoff. Persist the `XAUTOCLAIM` cursor,
     bound both stream length and pending-entry cleanup, and force a paced
     authoritative-database poll after every timeout or coordination error.
   - Retain sequence tombstones beyond route/replay payload expiry so delayed
     older projections cannot resurrect stale hints. Apply equivalent expiry,
     tombstone, blocking-poll, and cleanup behavior in the standalone memory
     coordinator, and bound Redis worker candidate scans/pipelining before
     falling back to authoritative placement.
   - Wire coordination into real transactions and process supervision: worker
     register/renew/drain, capacity reservation/release, call assignment/route,
     replay markers, and work creation append events atomically; projectors and
     wakeup consumers run as bounded supervised tasks. Redis supplies hints
     only, and every placement/work claim is revalidated in the repository.
   - Make disposable PostgreSQL and digest-pinned Redis 7.2 coordination tests
     mandatory in CI and local backend scripts, including delayed recovery,
     commit reordering, restart/flush/group recreation, v3-to-v4 migration, and
     values above `2^53`; ignored external tests alone are not evidence.
7. [x] Replace global FIFO pairing with at least 256-bit, two-minute,
   single-use attachment tokens. Persist only a digest bound to tenant, call,
   leg, expected transport, and worker fence; atomically bind the exact rvoip
   Connection ID and reject expiry, replay, wrong transport, and cross-call or
   cross-tenant use.
   - Do not authorize inbound attachments from rvoip's lossy public event
     broadcast. Add an opt-in, bounded single-consumer admission queue before
     adapter registration; queue saturation, receiver loss, or an admission
     timeout must reject and forget the route, erase its inbound context, and
     close the transport. Emit the compatibility `ConnectionInbound` event
     only after the admission owner accepts the connection.
   - Require principal-bearing rvoip authentication in the generic runtime.
     WebRTC uses the auth-core hook with a separately retained session hint;
     SIP uses an enforceable listener policy. Anonymous or identity-only
     compatibility modes that cannot supply the complete principal and routing
     hint are not valid for durable attachment admission.
   - Parse presented tokens as exactly one canonical, unpadded URL-safe Base64
     encoding of 32 bytes, hash the decoded bytes with SHA-256, zeroize every
     raw buffer, and return one indistinguishable proof failure for malformed,
     missing, expired, replayed, or mismatched material.
   - Keep proof consumption inside `CallService`: validate the complete
     principal and owner-bound context, derive the existing issuer/tenant/
     subject fingerprint, inspect using the current worker fence, re-observe
     principal/token expiry after the database await, then atomically consume
     and bind the exact Connection ID. The API and signaling runtime share one
     repository, worker lease, validator, cryptographic policy, and service
     bundle; they must never construct independent in-memory authorities.
   - Treat signaling authentication and attachment proof as separate checks.
     The attachment token never substitutes for the authenticated rvoip
     principal, and an inbound provider leg resolves its expected transport
     principal from the configured account/authentication profile rather than
     blindly inheriting the control-API caller.
   - Present the token as the SIP Request-URI user, the WHIP/WHEP resource tag,
     or a dedicated `bridgefu.attach.<token>` WebSocket subprotocol value.
     Keep the WebSocket authentication bearer in its existing independent
     subprotocol/header path; do not put attachment tokens in query strings.
     rvoip's auth hook retains only a redacted, single-take session hint.
   - Model WHIP and WHEP according to their signaling role instead of forcing
     both through the unsolicited-inbound event shape. WHIP publication enters
     the reliable inbound-admission path. Current WHEP resource creation is a
     server-offer/outbound rvoip operation and is completed in Gate 7 through
     the explicit attachable-outbound path below; it must not emit a synthetic
     `ConnectionInbound` event.
   - On every inbound connection, obtain the complete authenticated principal,
     consume its owner-bound rvoip inbound context once, hash the routing hint,
     inspect and consume the durable attachment atomically, and reject/close
     the connection on any mismatch. Never log or serialize the raw hint.
   - Replace FIFO tasks with a bounded supervisor-owned `JoinSet`/semaphore and
     per-connection attachment state. Duplicate notices must not close an
     already admitted winner, and no protocol acceptance, media work, or other
     external I/O may occur before the durable bind commits.
   - Register the exact durable connection-to-tenant/call/leg/generation index
     before calling `InboundAdmission::accept()`. The unresolved admission is
     handed to the owning call actor only after that index is visible, so an
     immediate `Connected` or terminal event cannot outrun durable ownership.
   - In clustered topology, a public gateway resolves only a token digest to
     the authoritative pinned worker through PostgreSQL or a sequence-checked
     coordination projection, then forwards over private authenticated UCTP.
     It never guesses a worker or consumes a worker-owned attachment locally.
8. [x] Add a bounded lifecycle supervisor for setup/media/transfer/cleanup
   deadlines, cancellation and compensation, hangup-versus-transfer glare,
   peer teardown, stale generation rejection, worker drain, and fenced restart
   recovery. Active media is ended and cleaned after worker loss, never
   migrated.
   - Add an rvoip-owned bounded, single-consumer operational lifecycle stream
     for connected, terminal, DTMF, and `DataMessage` events. The existing
     broadcast event bus remains observability-only; lag on it must never lose
     a durable state transition or cleanup decision.
   - Make every rvoip correctness task owned and drainable before Bridgefu
     relies on the stream. `Orchestrator::register` must retain and join adapter
     normalizer tasks, authoritative mode must not use detached DTMF forwarding,
     and prepared-outbound plus terminal publication must remain lossless across
     cancellation, activation failure, receiver loss, and drain races.
   - Add an opaque two-phase `PreparedOutboundConnection` seam in rvoip. The
     adapter creates an event-dormant route, Bridgefu transactionally binds its
     exact Connection ID, and only then may core activate signaling/events.
     Abort, drop, timeout, or durable-bind failure closes the provisional route
     and permanently retires the ID.
   - Construct one `CallExecutionSupervisor` after the durable worker runtime
     and before opening public signaling listeners. It owns bounded claim loops
     for call effects, controls, deadlines, provider events, and restart work,
     plus capacity-bounded per-call actors and all adapter/bridge child tasks.
   - Add a service-managed provider-event reconciliation transaction before the
     supervisor claims provider callbacks. The raw compatibility completion
     path intentionally rejects service-managed calls and must never be used as
     a bypass.
   - Persist every input needed to recover external work before enabling the
     corresponding claim: the call/outbound authorization fingerprint, the
     explicit transfer target leg, and a media-idle timeout/activity generation.
     `DeadlineKind::Media` is not operational evidence until rvoip supplies an
     authoritative activity signal that can refresh it.
   - Treat lease validity as a monotonic local safety deadline as well as a
     repository state. A store outage may report `Degraded` only until the last
     confirmed lease TTL expires; at that instant the runtime becomes
     `LeaseLost`, stops admission/claims, and ends local media without attempting
     stale-fence durable writes.
   - Each call actor serializes attachment, originate, connect, media-bridge,
     DTMF, transfer, terminal, and compensation work against the exact worker
     fence and connection binding generation. It owns the conversation,
     session, connections, managed media-graph routes, cancellation, and child
     `JoinSet`; no correctness task is detached.
   - Give operational events a reserved bounded mailbox and prioritize them over
     ordinary work so an external operation cannot deadlock waiting for the
     event it emitted. Retry ambiguous repository failures with the identical
     command request; reload and reclassify only after an explicit version
     conflict. Retain completed external-I/O results until reconciliation is
     durable so an outage never repeats a non-idempotent operation.
   - Run fenced restart recovery before public listeners become usable. Old
     process-local routes cannot migrate: fail their nonterminal bindings with
     `worker_restarted`, fail unbound legs through the internal service command
     path, and execute the resulting teardown work before admitting new calls.
   - Drain in dependency order: stop admission/listeners, stop new claims,
     drain or end call actors, close graphs/connections/adapters, join core
     lifecycle tasks, then stop coordination and lease renewal.

Gate 6 progress evidence recorded on 2026-07-12:

- Bridgefu revision `6e8bc0a2534b9cb962d0e613e4715e3aea30a525`
  adds the pure, fixed-size two-leg aggregate without changing the API,
  generic runtime, or frozen Amazon runtime. It includes strong IDs,
  database-safe generations, exact call/leg states and leg kinds, UTC
  generation-bound deadlines, sanitized failures, and serializable commands,
  decisions, and ordered effect intents.
- The domain suite passes 19 transition, stale-generation, serialization,
  invariant, and property-like tests. The complete Bridgefu all-target suite
  passes 20 binary tests plus 14 StandardCharter contract tests; strict library
  Clippy and warning-free library rustdoc pass.
- rvoip revision `87b213b33f26ca6f178c899b8b91a18ba30ebedf`
  completed the inbound-context seam and was pushed on
  `codex/bridgefu-1.0-rvoip`; Bridgefu CI pinned that exact revision at the
  time. This historical source pin is superseded by the crates.io 0.3.4
  dependency checkpoint above. SIP and
  WebRTC preserve redacted transport-bound hints through a single atomic
  authenticated handoff, while the public adapter event API remains source
  compatible. Context is owner-bound, single-take, bounded, expiry-checked at
  publication, and erased on every terminal path.
- The final focused qualification passes 9 core dispatch tests, 14 SIP inbound
  context tests, 3 WebRTC inbound-hardening tests, and 3 signaling ownership
  tests. It covers interleaving, queue saturation, fast-auto-accept cleanup,
  principal expiry, tenantless principals, reserved-header denial, and
  cross-principal update/delete isolation.
- rvoip revision `1ec7b370e82ed3ba646e795b343a117466667e48`
  extends the first-party WebRTC auth-core hook with an opt-in, separately
  prefixed WebSocket session hint for attachment routing. Authentication and
  attachment material remain independent; missing, duplicate, oversized, or
  prefix-ambiguous values fail closed, and neither bearer nor attachment
  subprotocols are echoed during upgrade. `AuthContext` diagnostics redact the
  subject, principal, and hint. Ten auth tests, two handshake-selection tests,
  five real WebSocket-auth tests, three signaling-ownership tests, strict
  Clippy, and warning-free rustdoc passed. Bridgefu CI pinned this revision at
  the time; the historical source pin is superseded by the crates.io 0.3.4
  dependency checkpoint above.
- Bridgefu revisions `952a01adcf41a2bc2c73a4999521876533bfb87d`,
  `c758981fd4726810fdec3135eb730c9bf082c471`, and
  `ad3dbec819335d5afb82425125af94769a009384` add the backend-neutral atomic
  repository contract and one-lock memory backend, then close all independent
  review findings. Durable intents cover worker capacity and fencing,
  tenant-scoped idempotency, optimistic commands, ordered outbox work,
  attachment consumption, provider receipt/claim/completion, deadlines, and
  restart recovery.
- Repository qualification passes 28 focused tests, including 64-way
  idempotency, N+1 admission, concurrent CAS and outbox races, interleaved
  attachments, wrong-leg provider rollback, callback-before-reference ordering,
  exact lost-response replay, terminal callback recovery, permanent connection
  ID tombstones, and capacity-safe terminal cleanup. The complete locked suite
  passes 49 library, 20 binary, and 14 StandardCharter tests; strict library
  Clippy and warning-free library rustdoc pass.
- Bridgefu revision `5b746cf12bd50c645492d05213167a1c6283950b`
  adds authoritative SQLite and PostgreSQL implementations with one versioned
  initial schema per backend. SQLite uses cancellation-safe `BEGIN IMMEDIATE`;
  PostgreSQL serializes mutation decisions with a fenced epoch row. Read-only
  snapshots do not advance the epoch, and mutations write targeted row deltas
  rather than rewriting unchanged history.
- Database constraints enforce composite call/leg ownership, provider
  completion replay, and permanent connection-ID tombstones. Both loaders
  compare every normalized worker, call, leg, assignment, binding, command,
  idempotency, attachment, provider, outbox, and deadline column against its
  serialized body and fail closed on drift. Unsafe automatic history deletion
  is absent; only fully settled terminal histories can be reported as retention
  candidates.
- The digest-pinned PostgreSQL 17.5 Docker runner passes all 10 shared schema,
  migration reconnect/checksum, row-delta, rollback/cancellation, 13-row-family
  drift, lifecycle, and two-independent-instance race tests. The main locked
  suite passes 49 library, 20 binary, 10 repository, and 14 StandardCharter
  tests; strict library/repository Clippy and warning-free rustdoc pass. CI
  provisions PostgreSQL and cannot silently use the local skip path.
- Bridgefu revision `fb24b7a` upgrades both SQL backends to integrity schema
  version 3. Service ownership is now an independent one-way call marker;
  expired service/control idempotency claims leave immutable cross-linked
  tombstones; locally retired control work has an exact causal-command receipt;
  and terminal reconciliation plus outbound binding evidence is validated in
  both directions. The standalone and disposable PostgreSQL suites pass 16
  repository and 3 call-service backend tests, including v2 upgrades, exact
  key reuse after 24 hours, ignored-command tampering, and direct deletion of
  every required evidence row. The full locked suite passes 136 tests with
  strict Clippy, rustdoc, formatting, and checksum validation.
- Bridgefu revisions
  `e0e45f2`, `3ddb0d0`, and `daa7723` complete the authenticated
  transactional call boundary: tenant/scoped principals, canonical HMAC
  idempotency, immutable execution plans, exact original create snapshots and
  attachment-token replay, durable transfer/DTMF/control receipts, bounded
  dependency setup, explicit capability/transition errors, and tenant-scoped
  legacy API isolation. The frozen StandardCharter runtime is not called or
  replaced by this path.
- Bridgefu revision `dda3288`
  makes Gate 6 item 5 durable at process startup. A public shared construction
  seam opens the exact Memory, SQLite, or PostgreSQL repository used by the API
  and future worker runtime. SQLite is the standalone default only when the
  transactional API has complete authentication; PostgreSQL requires a stable
  explicit worker UUID; memory requires a dev/test acknowledgement. Requested
  SQL failures abort startup without an in-memory fallback. URLs and control
  keys are redacted and zeroized, invalid keys are rejected before repository
  mutation, and the non-root read-only Compose profile mounts writable SQLite
  state explicitly.
- SQL create-replay lookup is now a read-only snapshot operation that never
  advances the repository epoch. `StoredServiceCall.attachments` is rebuilt
  from the immutable original create command, and snapshot reconstruction
  cross-links every descriptor, attachment row, digest, row ID, owner, leg,
  generation, transport, principal, worker fence, and expiry. Missing, orphan,
  duplicate, or mismatched evidence fails closed without weakening schema-v3
  service markers, tombstones, or reverse reconciliation evidence.
- The final locked all-target/all-feature suite passes 178 tests, including 20
  unchanged StandardCharter contract tests. The digest-pinned disposable
  PostgreSQL runner executes 16 repository, 3 service-repository, and 5 runtime
  tests. Memory, SQLite, and real PostgreSQL cover dependency outage, exhausted
  capacity, restart fencing, retained reservations, and exact replay after an
  attachment is consumed and expired. Strict changed-surface Clippy,
  warning-free rustdoc, rustfmt, schema parsing, Compose validation, and diff
  checks pass.
- Bridgefu revision `4196625` completes Gate 6 item 6. Worker placement and
  reservation are database-authoritative and capability/capacity-aware;
  PostgreSQL uses database time for leases and one deployment-scoped ordering
  lock for state plus coordination-outbox commits. Redis and the standalone
  memory projection carry only bounded, sequence-checked hints with
  non-resurrectable tombstones, fenced renewal, one-way drain, replay markers,
  and recoverable Streams wakeups. SQLite runs the same local projector and
  supervised wakeup path, while PostgreSQL without `rediss://` requires an
  explicit all-in-one dev/test acknowledgement.
- The integrated locked suite passes 206 tests with three credentialed backend
  cases intentionally skipped. The digest-pinned PostgreSQL 17.5 and Redis 7.2
  runner adds 32 PostgreSQL-backed passes and one Redis conformance pass,
  including delayed projection recovery, commit-order locking, restart/flush/
  group recreation, v3-to-v4 migration, values above `2^53`, startup failure,
  expired/replaced fences, acknowledgement outages, bounded fallback polling,
  and clean shutdown. Formatting, JSON Schema parsing, and diff checks pass.
- Bridgefu revisions `5fda49c` and `8816cdb` add the fail-closed attachment
  service transaction and close its independent security-audit finding.
  Canonical 256-bit hints are parsed and zeroized, issuer/tenant/subject
  ownership and the exact worker fence/Connection ID are checked, and token
  plus principal expiry are enforced inside the final atomic transaction using
  authoritative database time after lock acquisition. Blocked-consume,
  in-memory authority injection, SQLite clock-skew, and PostgreSQL clock-skew
  tests prove expiry cannot be bypassed by transaction contention.
- rvoip revisions `b90d4cc8` through `fc8a2fe3`, `0a56978f`, and `df1a5dc1`
  add bounded inbound admission, process-lifetime connection-ID retirement,
  adapter lifecycle capabilities, generation-scoped protocol confirmation,
  first-party SIP/WebRTC/UCTP handoff and cleanup, and enforceable SIP Bearer
  scopes. Admission is single-consumer and precedes the compatibility event;
  saturation, timeout, receiver loss, stale generations, terminal races, and
  cross-tenant ownership all fail closed. Outbound UCTP route creation remains
  explicitly unsupported rather than being represented as operational.
- Bridgefu revision `f474408` removes global FIFO authorization. The generic
  runtime now shares the API's exact validator, service, repository, crypto,
  and worker fence; installs the admission gate before adapter registration;
  consumes owner-bound SIP Request-URI or WHIP/WS routing hints once; commits
  the exact durable connection binding before accepting; and uses a bounded,
  supervisor-owned `JoinSet`. Crossed-call and duplicate-leg tests prove that
  arrival order cannot cross-connect calls. At that revision, Gate 6 item 7
  remained open until the WebRTC listener consumed protocol confirmation and
  terminal compensation was driven by the strong lifecycle supervisor.
- Bridgefu revision `c72bed3` adds exact, fenced connection-lifecycle commits
  across the memory, SQLite, and PostgreSQL repositories. Durable connection
  ownership, binding generation, worker fence, state mutation, replay, and
  snapshot cross-links are validated atomically; adversarial tamper tests fail
  closed. This is an item-7 prerequisite, not the lifecycle supervisor itself.
- Bridgefu revision `e244275` adds bounded optimistic retry for simultaneous
  attachments to different legs of one call. Retries retain the original
  token digest and command ID and recheck expiry after every database await;
  a deterministic two-inspection barrier test proves the calls cannot
  cross-bind through a shared aggregate-version race.
- Bridgefu revision `a2c20e6` makes the worker lease a monotonic local safety
  deadline measured from the last confirmed registration or renewal attempt.
  A coordination outage can report `Degraded` only until that deadline, then
  becomes `LeaseLost` and cancels the existing runtime supervisor. Full
  admission, claim, and local-media behavior after lease loss remains item 8
  work.
- Bridgefu revision `03ddce7` adds the service-owned provider-event
  reconciliation transaction required before item 8 can claim callbacks. It
  validates the execution plan, account, target, external reference, binding
  generation, follow-up, terminal acknowledgement, exact replay, and snapshot
  cross-links, while the raw managed-call completion path remains rejected.
  Schema version 5 and memory, SQLite, and PostgreSQL tamper tests cover the
  transaction; the supervisor claim/normalization loop remains open.
- Bridgefu revision `a455717` persists execution-plan version 2 authorization
  fingerprints, explicit transfer target leg and binding generation, and the
  configured media-idle policy with exact consecutive activity generations.
  Migrated version-1 plans deliberately have no inferred authority and cannot
  start new outbound work. Provider reconciliation remains schema version 5;
  execution authority is the ordered schema-version-6 migration. The isolated
  locked suite passes 114 library, 40 binary, all repository/runtime suites,
  and 24 unchanged StandardCharter contract tests.
- Bridgefu revision `09d92fa` adds explicit SQLite and PostgreSQL schema-5 to
  schema-6 fixtures containing a legacy version-1 execution plan, historical
  outbound binding, and service-reconciliation receipt. Upgrade preserves
  inspect/terminate/replay history while every new outbound bind still fails
  closed. The digest-pinned disposable PostgreSQL run passes 21 repository,
  5 service-repository, 8 runtime, and 2 coordination tests; the focused
  SQLite boundary, 114 library tests, and strict repository Clippy also pass.
- rvoip revisions `c353b4d6`, `c04737c6`, `78b0b370`, and `53fa66cb` add
  admission confirmation before WHIP/WS protocol success, two-phase prepared
  outbound connections, the bounded authoritative operational stream, and
  owned lifecycle activation/normalizer/DTMF tasks with exact terminal,
  cancellation, timeout, and drain behavior. These local revisions are item-7
  and item-8 prerequisites. Bridgefu CI remains on the last reviewed pushed
  rvoip revision until the remaining local rvoip work is qualified and its
  exact final revision is reviewed.

- rvoip revisions `7d8eb259`, `2df927f6`, and `b25785c0` complete the
  remaining correctness signals used by the supervisor. MediaGraph activity
  is coalesced into consecutive, monotonic per-connection generations, and a
  task-free sticky health subscription reports receiver loss, cancelled
  delivery, sequence exhaustion, or send failure without delaying core
  lifecycle drain. The full core and orchestrator qualification passes 153
  tests with strict Clippy, rustdoc, formatting, and no upstream contact.
- Bridgefu revisions `9f46120`, `4ba929e`, and `e680146` move verified
  Twilio, Telnyx, and Vonage callbacks into the shared durable repository,
  bind them to exact provider/account profiles, reject ambiguous identities,
  and make duplicate/conflicting delivery deterministic before the execution
  supervisor claims provider work.
- Bridgefu revisions `8216d13` through `8b3e1be` complete Gate 6 items 7 and
  8. One process-owned `CallExecutionSupervisor` installs admission and the
  authoritative operational stream before listeners, runs fenced recovery,
  owns bounded proof/claim/actor tasks, and serializes each call's signaling,
  media, control, provider, deadline, compensation, and cleanup work. Exact
  durable connection ownership is installed before protocol acceptance;
  simultaneous same-call legs and interleaved unrelated calls cannot race or
  cross-connect. Immediate `Connected` then terminal events are reconciled in
  order, remote termination boundedly tears down its peer, and retiring actors
  release active capacity without making total task count unbounded.
- Lease or operational-stream authority loss is a hard local boundary. The
  supervisor cancels proof, claim, actor, and external-operation work, retains
  every indexed or not-yet-joined proof Connection ID, performs no stale-fence
  durable compensation, and boundedly ends all local routes. Startup recovery
  has an explicit old-fence bound-leg fixture. Process shutdown applies one
  absolute deadline across HTTP, signaling/media, the worker drain write, and
  coordination tasks; stalled writes time out and stalled tasks are aborted.
- Final Gate 6 qualification passes 280 executable tests: 133 library, 53
  binary, 6 real fake-adapter supervisor integrations, 20 memory-service, 5
  service-repository, 8 runtime, 1 standalone SQL coordination, 21 repository
  conformance, and 33 unchanged StandardCharter tests. Three credentialed
  Redis/PostgreSQL cases remain intentionally environment-gated in the normal
  suite. The digest-pinned disposable PostgreSQL run passes 21 repository, 5
  service-repository, 8 runtime, and 2 coordination tests; the companion
  PostgreSQL/Redis runner passes both SQL ordering tests and the Redis 7.2
  Streams/fallback conformance test. Strict changed-surface Clippy, warning-
  free rustdoc, rustfmt, and diff checks pass; an independent P0/P1 audit found
  no release blocker.

Gate 6 qualification covers interleaved unrelated attachments, repository
parity, concurrent capacity/idempotency races, callback-before-originate-result,
outbox crash points, token replay/expiry/isolation, remote teardown, transfer
glare, restart, authority loss, and bounded drain. The existing
`ConnectScreenPopServer` remains the default StandardCharter path until Gate 7
moves Amazon behind the common engine.

Exit: state/repository tests pass and unrelated concurrent calls cannot
cross-connect.

### Gate 7 — Complete SIP/WebRTC and Amazon paths (`in progress`)

The 2026-07-12 interface audit established the following implementation order.
These prerequisites are intentionally sequential: later call-engine work must
not hide an earlier adapter side effect behind a nominally staged API.

1. [x] Extend rvoip origination with an opaque, typed, and redaction-safe
   adapter context plus stable activation and external-connection references.
   Concrete transport-owned `SipOriginateContext`, `WebRtcOriginateContext`,
   and `AmazonConnectOriginateContext` values are delivered by items 2, 3, and
   5 behind this core seam, without exposing transport types through
   Bridgefu's durable domain. Context secrets must never appear in logs,
   diagnostics, equality output, or metrics.
2. [x] Make SIP origination genuinely dormant. `prepare_outbound` may reserve
   bounded in-process identifiers, routes, and capacity, but it must perform no
   coordinator call, DNS lookup, socket connection, RTP allocation, timer
   creation, INVITE, or other peer-visible signaling. A retained single-flight
   activation driver must send at most one INVITE only after Bridgefu has
   durably bound the exact Connection ID and installed its operational-event
   owner. Concurrent or cancelled activation waiters must observe the same
   result without retransmitting. Cancellation before activation must release
   every reservation without a network side effect; cancellation after a
   possible send must boundedly compensate with CANCEL/BYE and forced local
   cleanup. Activation must return the actual SIP Call-ID only after staged
   events have been flushed without losing a fast terminal response.
   `SipOriginateContext` must provide redacted typed authentication and
   ordered, bounded initial headers; reject controls, CR/LF, stack-managed or
   internal headers, and untyped authorization before any packet. Add
   byte-preserving in-dialog SIP MESSAGE mapping for reliable ordered
   `DataMessage`, typed asynchronous REFER progress/completion/failure, and
   validated RFC 4733 duration and inter-digit spacing.
   - [x] 2a — Add `SipOriginateContext`, ordered bounded initial headers,
     typed/redacted credentials, wrong-context rejection, and packet-silence
     tests for every validation failure. Bound and control-check Digest,
     Basic, Bearer, and non-nested composite auth before reserving a route;
     redact every retaining diagnostic container. SIP tracing must be
     credential/context-safe by default across headers and SIP bodies, and
     folded continuation lines must inherit the preceding header's
     keep/redact/drop decision. Verbatim header or body trace output requires
     an explicit development opt-in. Before this slice can close, the combined
     security audit must also prove that every generated or precomputed raw
     authentication value is bounded and control-free at its final insertion
     point and at every public typed transport `send_message` boundary; the
     explicitly raw transport escape hatch remains the only verbatim bypass.
     Typed sends also validate every extension header name as an exact SIP
     token and the final serialized value of every header variant as a bounded,
     single-line field. This includes structured values and non-`Other` typed
     headers, not only `HeaderValue::Raw`, so whitespace-before-colon,
     embedded-colon, CR/LF, malicious nested parameters, and malformed `Other`
     spellings cannot create a new header downstream. Response reason phrases
     are bounded and reject line/control injection before any typed transport
     performs I/O. Request methods must be exact SIP tokens, and every rendered
     Request-URI/version start-line component is bounded and single-line before
     route lookup or I/O. Outer diagnostics classify extension methods without
     formatting their caller-controlled spelling. Transaction-layer diagnostics
     must likewise be metadata-only: no derived `Debug` of a command or complete
     SIP message, no peer-controlled Via branch or extension-method spelling in
     transaction-key logs, and no raw expected/received branch comparison. Use
     log-only safe wrappers so functional transaction identity, wire formatting,
     parsing, and protocol correlation remain byte-for-byte compatible. Apply
     those wrappers to transaction commands, events, messages, errors, client
     and server data, request-authorization decisions, and rejection details;
     arbitrary error strings and challenge headers are presence/length metadata
     only. Validate typed requests at transaction-manager entry before route
     selection, then retain full wire validation after stack normalization;
     route/Via diagnostics remain metadata-only even for valid messages. A
     static scan plus secret-bearing canaries must cover every transaction-key,
     method, branch, message, event, error, and route log sink. Parser
     failures expose only offsets, error classes, and remaining byte counts;
     they never log the unparsed remainder because it may contain credentials,
     malformed headers, or a body. Typed-header conversion errors and successful
     parser diagnostics are included: they expose header class and extent only,
     never owned nom input, Content-Disposition, Authorization, or arbitrary
     extension-header values.
     Legacy dialog/API/manager/protocol logs follow the same rule: From, To,
     target, resolver, Contact, REFER, Route, and Via URIs; arbitrary response
     reasons; transaction identifiers; complete messages; and lower parser or
     validation errors are represented only by fixed class, status,
     presence/length/count, and safe standard-method metadata. Source sockets
     may remain for network diagnostics; caller/peer signaling values may not.
     Authorization-bearing raw values, their enclosing typed headers, and
     complete requests must also redact secrets from diagnostics regardless of
     whether the header name uses a canonical variant or a case-insensitive
     `Other` alias. Transport/session event diagnostics retain raw bytes only
     functionally; their `Debug` and default log surfaces expose presence/size,
     never raw signaling or body content. Request start lines redact the
     complete Request-URI and
     response start lines redact untrusted reason text in both the raw trace and
     the separate event field. A custom Call-ID decision must also govern the
     separately retained `sip_call_id`; no parallel event field may bypass the
     policy. Malformed or orphan trace lines fail closed instead of passing
     verbatim. The public lower-level trace API uses
     a continuation-aware, body-safe default when no application policy is
     installed; and the default typed-header policy is a deliberate safe
     allowlist rather than an `_ => Keep` fallback.
     SIP option materialization errors expose only field presence/length and
     validation class; they never include P-Asserted-Identity, proxy URI, From,
     target, credential, or application-header values.
     The same boundary covers every initial, extra-header, structured-options,
     and authenticated-retry INVITE wrapper: no wrapper may relay a lower
     builder/parser error string, and pre-dispatch CreateDialog actions expose
     only endpoint presence/length before calling the lower dialog manager.
     Registration diagnostics apply the same rule to From URI, username, AoR,
     and registrar-auth errors. `HeaderPolicyViolation`, method-bearing session
     errors, and authentication challenge/decision containers have manual,
     metadata-only diagnostics; no `Method::Extension`, realm, nonce, challenge,
     or rejected header value appears in `Debug`/`Display`.
     Redaction must not collapse the public typed-header conversion error enum:
     callers retain the pre-hardening `InvalidHeader`, `Utf8Error`, `ParseError`,
     and incomplete-input variant semantics while every attached string is
     replaced by fixed class and bounded extent metadata. Direct authentication
     configuration and service containers are also in scope: `AuthIdentity`,
     extension schemes, client headers, configured realms/scopes, and lower
     validator/provider/store errors expose only fixed stage/class and
     presence/length metadata through `Debug`, `Display`, and `SessionError`.
     Their live values remain available only through the functional API.
     This applies transitively to every cross-crate and public application
     event: SIP headers, bodies, SDP, principals, REGISTER identities,
     authentication challenges, REFER targets/transactions, and raw requests
     remain functional/serializable but custom `Debug` exposes only event kind,
     safe status, and bounded presence/length/count metadata. Core principal,
     credential, listener-mapping, URI, SIP request, policy, and service
     containers follow the same rule; bearer/access/ID tokens, Digest nonce or
     response, signed material, deprecated URI passwords, raw URI/header/body,
     tenant/subject/issuer/scope, and extension-scheme spelling never appear in
     default diagnostics.
     No runtime parser may depend on a value-bearing `Debug` string. Retire the
     dialog event-hub fallback that formats `SessionToDialogEvent` and reparses
     `StoreDialogMapping`/`ReferResponse`; match the typed variants directly,
     preserve the functional identifiers and application reason in memory, and
     make their direct and `RvoipCrossCrateEvent` diagnostics metadata-only.
     Compatibility tests assert typed delivery behavior rather than exact raw
     `Debug` text.
     Lower SDP/parser errors are classified at their source and again at the
     media-adapter/executor/log boundary. A malformed inbound offer can never
     reach a normal log through `SDPNegotiationFailed` or a generic string
     session error. Outbound REGISTER/refresh logs likewise expose only URI and
     Contact presence/length and fixed stage metadata, including authenticated
     retries and NAT rewrites.
     TLS and WSS handshake failures are also fixed stage/class diagnostics:
     rustls errors are never string-flattened because name-mismatch errors can
     contain both the requested SNI and presented certificate SANs. Socket
     addresses may remain; expected/presented DNS values may not.
     Header-policy identity is canonical and case-insensitive: an `Other`
     spelling equal to Authorization, Proxy-Authorization, or any other
     reserved/stack-managed name receives the same classification as its typed
     variant. Generic header staging cannot become an untyped credential path.
     Inbound stream framing and the core parser share one strict
     `Content-Length` decision. Long-form and compact `l:` names are
     case-insensitive aliases; conflicting or repeated singleton values,
     non-numeric values, overflow, invalid bytes, and framing/parser disagreement
     reject and close the message/connection before a following request can be
     consumed. TCP and TLS tests cover both duplicate orders and prove no
     request-smuggling/desynchronization; WS/WSS use the same core singleton
     rule even though their message frame supplies an outer boundary.
     The shared scanner enforces bounded header bytes, line/header counts, body
     bytes, and total message bytes with checked arithmetic. TLS must not grow an
     unbounded `BytesMut` while waiting for a terminator or attacker-declared
     body; endless headers and huge/overflow lengths close the connection under
     deterministic tests.
     History snapshots sanitize every payload-bearing state-machine event before
     insertion, not only `AuthRequired`. SDP, SIP identities, targets, contacts,
     reasons, custom strings, media paths, transaction identifiers, and other
     peer/application values become fixed event kind plus bounded metadata in
     retained `TransitionRecord`, JSON, and CSV output. Live events remain
     unchanged, and CSV output must quote/escape all diagnostic fields safely.
     The public diagnostic boundary is safe before insertion as well:
     directly constructed/deserialized `EventType`, `TransitionRecord`,
     `GuardResult`, and `ActionRecord` cannot expose raw payloads through
     `Debug` or diagnostic serialization. Lifecycle, callback, prepared/live
     call, endpoint trace/registration, and parallel legacy wrappers receive
     the same metadata-only diagnostics as the primary application `Event`.
     Direct SIP auth challenge/authentication-info headers, Digest models,
     typed SDP/ICE/SRTP keying, URI, Request, Response, and Message diagnostics
     never render nonce/realm/proof, ICE password, crypto key, fingerprint,
     header, reason, or body values. Every `TypedHeader` diagnostic delegates to
     a safe structural view rather than wire `Display`.
     All remaining `RvoipCrossCrateEvent` families, including media/RTP,
     orchestration, and core events, provide metadata-only inner Debug so the
     outer wrapper cannot reopen arbitrary errors, file paths, transcript text,
     targets, or details. Serde and live routing fields remain unchanged.
     Opt-in transport/dialog timing diagnostics correlate calls through a
     bounded opaque identifier derived after the configured Call-ID keep/redact/
     drop decision; their maps and snapshots never store or return raw peer
     Call-ID values.
   - [x] 2b — Replace eager originate with a dormant route, deferred media,
     retained single-flight activation, actual Call-ID receipt, FIFO event
     flush, cancellation compensation, exact cleanup, and capture-UAS tests.
     Initial and authenticated-retry INVITEs must use one defense-in-depth
     validated append path so allowed duplicate headers preserve exact order
     and multiplicity while singleton duplicates fail. Validate generated
     auth values, including AKA-provider output, before wire serialization.
     Implement this as one per-connection `SipOutboundRoute`, not independent
     context and event maps. Its retained driver owns `Dormant`, `Activating`,
     `Flushing`, `Activated`, `Terminating`, and `Terminal` phases, a bounded
     operational FIFO, a separately reserved first-terminal slot, a cloneable
     redacted result, cancellation, and exact task/route reclamation. The first
     activation spawns the driver; caller-future cancellation must not cancel
     or re-enter the initializer, and every concurrent waiter observes the
     same receipt or failure. Split protocol-map retirement from route
     reclamation so a fast terminal is delivered once but can never resurrect
     a tombstoned Session ID or retain a permanent stage.

     `SipMediaStream` gains a local-only dormant constructor plus single-flight
     bind/close states. Prepare may allocate its bounded channels and stable
     stream ID, but no coordinator subscription, media session, pump, timer,
     socket, DNS, or packet exists until activation. Existing inbound/new
     construction remains a compatibility wrapper over dormant-plus-bind.
     Non-terminal controls fail with a typed pre-activation state error; end is
     always allowed. Once a session may have been created, a bounded
     coordinator compensation helper sends the one legal CANCEL or BYE and
     then forces idempotent local cleanup if the peer never completes teardown.

     Land 2b in independently green slices: shared initial/retry append and
     singleton policy; dormant-bind media; retained route supervisor; zero-wire
     prepare plus context/receipt; cancellation compensation; then the complete
     capture-UAS, concurrency, backpressure, leak, and migration suite. Existing
     core receipt and prepared-commit interfaces are sufficient; do not make a
     breaking core API change. A generic adapter drain hook remains optional,
     while SIP exposes a concrete drain method for Bridgefu worker shutdown.
     Before 2b closes, remediate the exact-revision lifecycle re-audit:
     failed route/media compensation during drain remains sticky or is truly
     retried; a route that has entered termination can never return its cached
     successful activation receipt; and cancellation of the sole
     `SipMediaStream::new`/bind owner after driver spawn must synchronously
     signal or abort that driver instead of leaking its subscription/callback.
     Barriered failure, delayed-terminal activation, and constructor-cancel
     churn tests are mandatory.

     The post-implementation cancellation audit adds one canonical lifetime
     prerequisite before those tests may qualify 2b. `SessionStore` must own a
     unique generation and an operation/resource supervisor for every live SIP
     session. Inbound setup, the complete state-machine action loop, outbound
     dialog creation, media/SRTP/callback creation, adapter activation/bind,
     timers/retries, and every spawned task acquire that exact generation before
     side effects. Retirement atomically changes `Active` to `Quiescing`, rejects
     new leases and commits, signals cancellation, and waits without holding a
     synchronous lock. A creator lease is released only after an atomic
     current-generation commit or rollback of the exact dialog, transaction,
     media, callback, or task handle it created. Caller cancellation cannot drop
     owned work between those outcomes. Long-lived resources remain registered
     to the generation until exact unregister, cancellation, and join complete.

     Quiesce timeout must not become false reclamation. It moves the lifetime to
     a bounded, non-expiring `PendingCleanup`/quarantine class, preserves the
     identifier, generation, exact handles, cancellation authority, and retained
     continuation, returns a sticky cleanup failure, and remains charged against
     an explicit lifecycle/resource limit. Admission uses two independent hard
     bounds: active permits remain charged through active, quiescing, and
     quarantined cleanup and are released only by the exact transition to
     retired; a separately bounded retained-fence capacity owns anti-reuse
     records after cleanup. Retired fences do not consume active permits, but
     exhausting either bound rejects new work. Diagnostics expose active permit
     use, retained capacity and count, phase counts, oldest age, and fixed reason
     class. Same-ID reuse is allowed only after all creator/resource leases are
     zero, exact cleanup is complete, and the SIP anti-reuse horizon expires.
     Queued dialog/media/bus
     events and callbacks carry the generation or another unique route identity;
     deterministic Call-ID and media identifiers include that identity, or their
     cleanup uses an exact generation-bound handle. Remove-by-Session-ID alone is
     not completion evidence.

     Replace `SessionRegistry`'s single global current/pending slots with keyed
     per-session-and-generation entries plus exact dialog/media secondary
     indexes. Modern pending request, transport, principal, and call accessors
     require the lifecycle key; legacy current-session accessors may remain only
     as explicit compatibility wrappers. Two simultaneously interleaved inbound
     calls must retain independent dialog, media, request, transport, principal,
     and attachment context, and teardown of either call must not clear the
     other. Repeat the barriers with a late old-generation completion after
     same-ID reuse.

     Teardown qualification records independent facts for peer signaling and
     local resource release. Zero-wire and observed-remote-terminal paths may be
     successful without a local teardown request; otherwise only a confirmed
     `hangup` dispatch can satisfy the wire result. Timeout or error remains a
     failure even when local reclamation succeeds. Cancellation-safe dialog
     cleanup must retain the exact lower descriptor across every await. The
     capture UAS must establish a legal dialog with a stable To tag, UAS Contact,
     SDP answer, ACK, and teardown delivered to the advertised UAS target. A
     blocked-before-wire teardown and a sent-but-no-terminal teardown are both
     deterministic acceptance cases. TTS playback started by the shared
     orchestrator also requires a cooperative owned supervisor: output rejection,
     output closure, detach, or the competing input loop ending must invoke the
     provider cancellation path before the playback future is released.
   - [x] 2c — Add byte-preserving reliable-ordered SIP MESSAGE/DataMessage in
     both directions, with validated internal label/message-ID headers and
     explicit reliability capability errors.
   - [x] 2d — Publish typed REFER progress/completion/failure and implement
     all-or-nothing bounded RFC 4733 digit validation, requested duration, and
     inter-digit pacing.
   - [x] 2e — Run SIP library/dialog/adapter, packet, lifecycle, strict lint,
     documentation, and real localhost interoperability qualification; obtain
     an independent P0/P1 audit before item 2 is complete. Property/fuzz
     evidence must show that no accepted header or auth value can serialize an
     additional SIP header line.
     The retained INVITE planner must also pass the exact-revision ownership
     audit: separate active-plan admission from 90-second tombstone capacity;
     make `stop` a latched joinable drain; release the plan mutex around every
     signer/send/hook await and race each attempt against deadline/cancel/drain;
     make prune, registration, and event advancement generation-atomic; and
     expose every live-plan, attempt, tombstone, and retired-transaction count
     in qualification snapshots. Transaction retirement must atomically move
     the exact request route from Active to Retired and authenticate one
     ingress decision against that retained UDP tuple or stream flow. Tests run
     at the real capacity=100/10-CPS configuration for longer than the 90-second
     retention window and include blocked awaits, concurrent stop/prune/setup,
     same-address distinct-flow late 2xx, and normal-stack auth/redirect chains.

   Focused 2026-07-14 SIP evidence closes 2c. A real two-dialog UDP test sends
   binary-safe `DataMessage` content as in-dialog SIP MESSAGE in both
   directions and proves byte, label, message-ID, route, and terminal cleanup
   behavior. The dialog layer now acknowledges and forwards MESSAGE instead of
   silently consuming it. The same slice adds typed REFER accepted/progress/
   completed/failed outcomes: real REFER/NOTIFY success and failure cases,
   exact-route ordering, redacted diagnostics, and core normalized/
   operational mapping pass. RFC 4733 validation rejects an invalid suffix
   before emitting a prefix, honors requested duration, and applies bounded
   inter-digit pacing; the exact 95 ms non-tick duration case also passes.
   At that checkpoint, items 2a, 2b, and 2e retained broader security,
   lifetime, soak, fuzz/property, and independent-audit gates; the final local
   evidence below closes the implementation portions of 2a and 2b.

   Final local 2026-07-14 SIP evidence completes 2a and 2b. Strict all-target
   Clippy, strict rustdoc, all-target checks, formatting, and diff checks pass
   for `rvoip-sip` and `rvoip-sip-dialog`; their complete library suites pass
   413/413 and 419/419. The active Section-10 suite passes 14/14, the real
   localhost capture UAS proves one Digest 401 retry followed by stable-dialog
   180/200/ACK/BYE, and real DataMessage and REFER network cases pass. Three
   512-case injection property suites cover accepted ordered headers, generated
   authentication, and arbitrary accepted precomputed authentication.
   Dormant prepare, cancellation, late terminal, retained single-flight,
   generation-bound route retirement, and final drain snapshots prove zero
   retained routes, tasks, observers, session mappings, media streams, and
   retired transaction routes.

   Final 2026-07-14 Gate 7 item 2e evidence closes the independent P0/P1 audit
   and greater-than-90-second planner/capacity qualification. The audit found
   and fixed options-path redirect ownership and cleanup, unresolved
   pre-callback install reservations, default-stack cleanup overflow, CANCEL
   teardown incorrectly sharing the expired INVITE setup deadline, and retained
   anti-reuse fences consuming active session capacity. No unresolved P0/P1
   SIP finding remains. Active permits and retained-fence capacity are now
   independently bounded; retiring a session immediately releases its active
   permit while the exact same identifier remains blocked through the 64-second
   anti-reuse horizon. Manual-clock churn proves both bounds and generation-safe
   reuse.

   At the release configuration of 100 active sessions and 10 call attempts per
   second, the real localhost stack completed 920/920 INVITE/486/ACK exchanges
   in 91.903 seconds (10.0105 CPS), observed 901 retained plans/attempts and 900
   retired exact routes, and drained every asserted live count to zero. A
   normal-stack redirect to a fresh origin proves that stale Bearer credentials
   are not forwarded and that the new-origin Digest retry preserves Route and
   SDP. The three 512-case properties prove every accepted initial header,
   generated auth value, and accepted precomputed Authorization or
   Proxy-Authorization value serializes as exactly one SIP header line. The
   complete SIP library suites pass 413/413 and 419/419, all 21 RFC 3263
   failover integrations pass, focused redirect/auth/property tests pass 8/8,
   strict default-feature all-target Clippy with dependency linting excluded is
   clean for both SIP packages, and warning-denied rustdoc, targeted formatting,
   and diff checks pass. Dependency-wide all-feature Clippy remains separately
   blocked by pre-existing codec-core lint debt and an unrelated media-core
   cfg-specific compile error; neither is in the SIP-owned Gate 7 item 2e
   surface.

3. [x] Implement real target-contacting WebRTC clients for WS, WSS, WHIP, and
   WHEP, while retaining the corresponding authenticated server roles. Local
   SDP offer construction is not an outbound client. Pin WHIP to
   [RFC 9725](https://datatracker.ietf.org/doc/rfc9725/) and WHEP to
   [draft-ietf-wish-whep-04](https://datatracker.ietf.org/doc/html/draft-ietf-wish-whep-04)
   (published 2026-06-22, expiring 2026-12-24). Implement canonical WHEP-04
   offer/answer and `406` counter-offer handling; any prior empty-POST/server-
   offer behavior is legacy-only behind explicit configuration. HTTP clients
   must retain `Location`/`ETag`, use conditional PATCH/DELETE, constrain
   redirects and credential forwarding, and buffer trickle candidates until a
   resource exists. Persistent WS/WSS sessions must carry signaling,
   candidates, and BYE over one authenticated `rvoip.webrtc.v1` connection.
   For attachable WHEP, authenticate and validate the resource tag, allocate a
   provisional connection, bind its exact Connection ID transactionally, and
   install its owner before returning `201` and emitting the operational event.
   Rejection, expiry, replay, disconnect, or abandonment must close the
   provisional connection and erase its context.
   - [x] 3a — Add redacted `WebRtcOriginateContext`, an explicit signaling
     protocol, per-exchange ICE policy, async bearer credential provider, and
     bounded target/redirect policy. Reject userinfo, query credentials,
     fragments, disallowed schemes/ports/resolved addresses, TLS downgrade,
     ambiguous create retries, and cross-origin credential forwarding before
     DNS or network I/O. Keep released exhaustive `WebRtcConfig` source-
     compatible through additive types/builders.
   - [x] 3b — Replace the separate outbound stage with one private retained
     `WebRtcOutboundRoute` modeled on `SipOutboundRoute`. Preparation is local-
     only; one activation driver owns signaling, candidate pumps, FIFO plus
     reserved terminal, exact receipt, cancellation compensation, cleanup,
     setup deadline, health, and drain. `accept` never initiates outbound
     signaling, and cancelled waiters cannot cancel or re-enter the driver.
   - [x] 3c — Replace per-operation `WsSignaler` sockets with one persistent,
     authenticated WS/WSS connection carrying request-correlated logical
     sessions, scoped candidates, and BYE. Require and echo exactly
     `rvoip.webrtc.v1`; never echo private auth/attachment subprotocol values.
     Track socket-leased routes so one BYE affects one route while disconnect,
     pong expiry, or drain closes and joins every owned route/task. Keep legacy
     `Signaler` APIs only as truthful compatibility wrappers and key any pool
     by sanitized origin, TLS profile, and opaque credential partition.
   - [x] 3d — Add production rustls WHIP HTTP clients with automatic redirects
     disabled. Own canonical endpoint, bounded relative/absolute `Location`,
     strong rotating `ETag`, conditional serialized PATCH/DELETE, response
     bounds, ordered pre-resource candidate buffering/completion, and no retry
     after an ambiguous POST. Harden the server to require content type and
     preconditions and rotate ETags on mutation/restart.
   - [x] 3e — Add the minimal alpha-engine
     offer→rollback→counter-offer→answer conformance test before implementing
     canonical WHEP-04 and typed `406`. Use an owner-reviewed private exact-
     revision fork only if that test fails; create no upstream issue or PR.
     Make draft-04 the default and place empty-POST/server-offer behavior
     behind explicit legacy configuration and a warning/metric.
   - [x] 3f — Route attachable WHEP through authenticated provisional inbound
     admission. Convert the tag to a bounded routing hint, consume a hashed
     single-use attachment token, bind the exact generated Connection ID and
     owner transactionally before `201`, and clean every replay loser,
     rejection, expiry, timeout, disconnect, or abandonment.
   - [x] 3g — Add tracked HTTP/WS/peer-session supervisors, actual abort after
     drain deadline, route-owned `LocalIceEvent::{Candidate, Complete,
     Overflow}`, bounded task/resource counters, redacted diagnostics, and
     churn/soak leak tests. Global `WebRtcConfig.trickle_ice` must not choose
     policy for all exchanges.
   - [x] 3h — Qualify real HTTP/HTTPS and WS/WSS client-to-rvoip loopbacks with
     ICE/DTLS/media/teardown; redirect and credential isolation; ETag races;
     WHEP-04 success and exact 406 fixtures; concurrent attachment replay;
     stalled-peer shutdown; and zero leaked routes, contexts, tasks, socket
     leases, or candidate pumps. Server-role and local-offer tests alone do not
     satisfy item 3.
     Partial evidence recorded 2026-07-14: hermetic target-contacting WHIPS and
     WSS adapter loopbacks use a bounded per-context rustls trust bundle (with
     normal certificate and hostname verification), complete ICE/DTLS and
     bidirectional Opus, then reach zero routes and outbound signaling tasks;
     WSS also reaches zero retained hub drivers and enforces exact
     `rvoip.webrtc.v1` selection. An HTTPS 307 fixture proves the authenticated
     origin receives exactly one POST while the cross-origin redirect target
     receives no request or credential. The focused secure suite passes 3/3,
     trust/redaction unit tests pass 6/6, combined-feature check and scoped
     no-dependency strict Clippy pass, and formatting/diff checks pass. Item 3h
     remains open for canonical secure WHEP-04/typed `406`, item 3f attachment
     replay, ETag concurrency, and the required churn/soak leak run. The current
     rvoip WHEP listener is still the legacy server-offer role, so it is not
     represented as canonical client-to-rvoip evidence.

     Additional 2026-07-14 evidence closes 3a–3e. The canonical WHEP-04
     listener now passes five end-to-end cases covering `201` send-only media,
     typed `406` counter-offer, one-winner strong-ETag mutation, malformed
     offer rejection, explicit legacy-mode metrics, non-HTTP teardown, and
     sixteen-cycle route churn. Authenticated provisional admission passes 9/9
     tests, including exact principal/routing-hint binding and a concurrent
     replay race with one `201`, one `403`, and exact loser cleanup. Combined
     outbound WHEP, ownership, alpha rollback, connected signaling, and
     observability tests pass; the complete WebRTC library passes 89/89 with
     WS, WHIP/WHEP, and rustls enabled, plus strict no-unwrap/no-expect Clippy.
     At that checkpoint item 3f remained open until Bridgefu exercised its real durable hashed
     token through this provisional path. Items 3g and 3h remain open for the
     required tracked peer-session soak, canonical HTTPS WHEP loopback, and
     complete cross-task/socket/candidate-pump zero-leak qualification.

     Final local 2026-07-14 WebRTC evidence completes 3f–3h and item 3. The
     Bridgefu execution suite exercises the canonical WHEP provisional route
     with its real hashed, two-minute, single-use durable attachment token.
     rvoip now owns bounded per-route peer, media, HTTP, WS, and candidate
     tasks through one shared drain deadline, including final post-listener
     cleanup of the in-flight publication race. Real verified HTTPS/WSS tests
     cover ICE, DTLS, bidirectional Opus, late arbitrary DataChannels,
     canonical WHEP `201`, exact typed `406`, strong ETag behavior, redirect
     credential isolation, and zero route/task/resource leakage. Evidence is
     green for all-feature compilation, strict all-target Clippy, 96 library
     tests, 10 admission tests, 5 WHEP-04 tests, 5 secure target-contacting
     tests, 7 outbound WHIP/WHEP/WS tests, stalled-task supervision, and local
     ICE lifecycle. Relay-only TURN remains separately gated by item 9 and the
     owner-reviewed private WebRTC/RTC fork decision; it does not reopen the
     target-contacting signaling implementation completed here.
4. [x] Persist signaling role independently from media direction using
   `SignalingInitiator` and `MediaFlow` (`send_only`, `receive_only`, or
   `send_recv`). Derive offerer/answerer behavior from the protocol and
   signaling role, never from media direction, and construct directional
   MediaGraph routes so one-way legs do not accidentally transmit. Make source
   and sink halves independently optional, negotiate Opus/PCMU/PCMA from the
   actual SDP/transceiver rather than configuration guesses, and validate the
   complete directional bridge plan before consuming any one-shot receiver.

   The pre-item-4 media-contract audit at rvoip revision `41649dbb` confirms
   that both current inbound pumps emit codec payload bytes; the contrary
   `SipMediaStream` module comment is stale and must be corrected. Two real
   release blockers remain. The SIP stream reports and decodes PCMU
   unconditionally instead of the codec negotiated for the exact SDP leg, and
   the WebRTC outbound pump guesses whether arbitrary codec bytes are a legacy
   complete RTP packet by attempting to parse them. That heuristic makes the
   payload representation ambiguous and can misclassify valid codec data.
   Enforce one transport-neutral `MediaFrame` invariant, remove the heuristic
   or place legacy wire images behind an explicit representation, packetize
   only at adapter boundaries, and derive PCMU/PCMA/Opus stream codecs from
   negotiated media. Add adversarial packet vectors and real loopback tests so
   RTP-looking Opus/G.711 payload remains payload and no leg is decoded with a
   configured guess. Existing adapter lifecycle tests do not prove generic
   SIP/WebRTC audio interoperability.

   The 2026-07-14 working tree closes the two representation/codec defects
   from that audit without completing item 4. `MediaFrame.payload` is now
   normatively codec payload only; the WebRTC pump no longer attempts to
   reinterpret RTP-looking codec bytes as a serialized RTP packet and an
   adversarial Opus-shaped vector locks that boundary. SIP media streams retain
   the exact SDP-negotiated PCMU, PCMA, or feature-gated Opus descriptor,
   payload type, clock, and channel shape, use the matching codec in both
   directions, and fail closed for unsupported or application-supplied
   unanchored SDP instead of guessing PCMU or waiting without a setup deadline.
   The focused rvoip suites pass 21 SIP media-stream tests, the WebRTC
   adversarial pump test, and all three explicit two-MiB fast-auto-accept
   regressions. Bridgefu's durable execution-supervisor suite passes 8/8 and
   now proves two managed directional MediaGraph routes for PCMU↔Opus and
   PCMA↔Opus, 8 kHz↔48 kHz RTP timestamp translation, opaque RTP-looking
   same-codec payload, single receiver acquisition, and exact remote-teardown
   route/source release. The new durable one-way case executes both
   SIP→WebRTC and WebRTC→SIP plans, acquires the enabled source exactly once,
   never acquires the disabled source, rejects reverse media, and releases the
   active route/source on terminal teardown. Plan schema version 3 persists
   `SignalingInitiator` independently from `MediaFlow`; the 3/3 directionality
   suite proves signaling-role and business-direction independence and rejects
   incomplete source/sink pairings before execution. rvoip's 28/28 focused
   bridge-pump suite additionally proves independently optional graph halves,
   atomic receiver reservation/rollback, and one-way codec replacement.
   A 2026-07-14 rvoip-owned production-path acceptance test closes the wire
   evidence for item 4. It prepares and
   commits real `SipAdapter` and `WebRtcAdapter` legs through `Orchestrator`,
   bridges their production `MediaGraph` routes, uses a raw peer only at the
   external SIP/RTP boundary, and reaches a second production rvoip WebRTC
   server over WHIP or persistent WebSocket signaling. Its sequential matrix
   proves PCMU↔Opus over WHIP and PCMA↔Opus over WS with actual RTP on
   both external boundaries, negotiated payload types and 20 ms G.711 frames,
   and zero graph drops or evictions. It also proves WebRTC→SIP RFC 4733,
   arbitrary binary DataChannel→in-dialog SIP MESSAGE, subsequent
   `bridgefu.context.v1` SIP MESSAGE→DataChannel, authoritative remote SIP
   BYE, no post-BYE media, terminal graph state, and zero retained bridge,
   route, media, signaling, peer-session, and lifecycle tasks. The test is
   `rvoip-webrtc/tests/sip_webrtc_acceptance.rs`; its focused command is
   `cargo test -p rvoip-webrtc --test sip_webrtc_acceptance --features
   tls-rustls,signaling-whip,signaling-ws -- --nocapture`.

   Item 4 is locally complete. Bridgefu's plan-v3 directionality and durable
   actor tests cover independent signaling/media roles, one-way receiver
   ownership, reverse RFC 4733, initial context before INVITE, and inbound
   attachment. The rvoip acceptance matrix covers WHIP, WSS, WHEP, negotiated
   codecs, and exact resource cleanup. The split-role composition and deployed
   TURN/public-NAT qualifications remain separately tracked by items 7 and 9;
   they no longer keep this transport-neutral media-plan contract open.
5. [x] Give the Amazon adapter the same prepare/bind/activate/terminal/drain
   lifecycle. Its typed per-call context must contain the actual Connect
   target, attributes, display name, and a stable client token reused during
   reconciliation; default targets, empty attributes, or a newly generated
   retry token are not compatible evidence. Operational events must cover
   liveness, remote termination, activation failure, and drain cleanup.
   - [x] 5a — Add redacted validated `ConnectProfileId`, exact
     `AmazonConnectTarget`, `ConnectClientToken`, and
     `AmazonConnectOriginateContext` containing target, attributes, display
     name, optional description, and stable token. Generic originate requires
     that exact context before I/O. Preserve legacy `ConnectConfig`,
     `ContactTarget`, and `client_token=None` wrapper semantics for the frozen
     path.
   - [x] 5b — Add one adapter-owned non-secret profile resolver so the selected
     AWS account/region starter also owns StopContact. Validate request bounds
     and every required AWS response field, redact/zeroize sensitive request,
     connection, mapping, and error diagnostics, and replace rendered-SDK
     string matching with typed retry/already-ended classes. Reconcile an
     ambiguous Start only with the byte-equivalent request and stable token.
   - [x] 5c — Add an injectable `ConnectMediaConnector`/session lifecycle seam
     backed in production by Chime plus rvoip WebRTC. Own PONG/activity,
     distinct remote terminal/error causes, joined task, absolute-deadline
     close, streams, hold/resume/DTMF, and secret-free logs. Use the existing
     hermetic Chime server to test the adapter without another media library.
   - [x] 5d — Implement a retained `AmazonOutboundRoute` with local-only
     prepare, immutable context, single-flight activation/cleanup, bounded FIFO
     plus first terminal, authoritative liveness/fallback, stable deferred
     stream, owned tasks, and `amazon-connect.contact-id` receipt. A known
     contact is stopped exactly once on every post-Start failure, cancellation,
     remote end, peer failure, PONG expiry, or repeated local end; route becomes
     non-live before terminal delivery.
   - [x] 5e — Add bounded adapter and `ConnectScreenPopServer` admission,
     `begin_drain`/absolute-deadline drain, owned JoinSets, terminal fallback,
     cancellation/join for the metrics updater, and explicit pending-cleanup
     records after hard local abort. Bridgefu shuts this path down by draining,
     never by merely aborting `serve`.
     - [x] The adapter rejects new generic and legacy setup after an atomic
       drain boundary, waits for admitted setup to quiesce, retires prepared
       and active routes once, and drains to one absolute deadline. Cleanup
       past that deadline is detached with its exact StopContact authority
       rather than aborted in an ambiguous post-Start window.
     - [x] `ConnectScreenPopServer` now has a linearizable, fail-closed drain
       boundary and a bounded 256-setup admission budget. Its SIP/Connect
       watchers, admitted per-call setup tasks, and exact registry cleanup
       tasks are owned and joined through one shutdown signal. Server drain
       rejects new calls, cancels each setup/active owner by exact SIP session,
       stops `serve`, delegates to the adapter, and shuts down the coordinator
       against one absolute deadline. Work crossing that deadline is detached,
       never aborted in an ambiguous post-Start window.
     - [x] Bridgefu owns the `serve`, lifecycle-ingest, metrics-updater, and
       durable-cleanup reconciliation tasks, invokes this server drain during
       process shutdown, and persists exact pending-cleanup records after a
       hard local deadline. The outer listener task is retained and joined;
       abort is only a bounded fallback after cleanup authority has moved to a
       retained owner.
   - [x] 5f — Persist a redaction-safe Bridgefu Amazon start spec containing
     profile, exact instance/flow, attributes, display, and optional
     description. Callers never supply a token, and durable state contains
     neither a derived client token nor credentials. Migrate plan schema
     explicitly rather than defaulting legacy records into runnable work.
   - [x] 5g — Execute Amazon StartLeg through exact durable effect authority:
     derive the token deterministically from immutable effect ID with a
     versioned domain prefix, build context, prepare, transactionally bind the
     exact Connection ID, then activate and reconcile its contact reference.
     Bind failure produces zero Start. Restart never migrates old media; an
     ambiguous Start repeats the identical token/request only to recover and
     stop the same contact, then fails the old leg. Register one
     profile-resolving adapter only after rvoip lifecycle tests pass.
   - [x] 5h — Keep the legacy listener/default runtime byte- and behavior-
     compatible while adding a separate false-by-default authenticated canary
     listener/tenant allowlist. Require trusted Vapi principal, matching
     tenant/correlation, and atomic durable create/attach/dedup. Add full fake-
     Connect/fake-Chime PCMU↔Opus golden teardown/drain tests, repository crash-
     barrier tests, and canary replay/cross-tenant negatives. The manually
     protected non-production workflow is separate Gate 11 release evidence,
     not a prerequisite for completing this local adapter/canary implementation.
     - [x] The local generic-engine slice uses the real durable supervisor,
       `MediaGraph`, transcoder, and rvoip Amazon adapter with injected Connect
       control/Chime-media doubles. It proves exact correlation mapping, one
       stable Start token/contact, PCMU↔Opus, teardown/drain, exact replay,
       mapped-metadata conflict, cross-tenant rejection, and SQLite
       pre-attachment restart fail-closed behavior without AWS I/O.
     - [x] Exercise the authenticated production `SipAdapter` listener rather
       than the adapter-bound SIP fixture with a real localhost SIP/RTP peer.
     The owner-authorized protected Vapi/AWS non-production run remains an
     unchecked Gate 11 item. Local evidence does not represent that
     credentialed workflow as complete.

   The pre-item-5 audit at rvoip revision `7c1902eb` confirms that current
   generic `originate` eagerly performs StartWebRTCContact, Chime signaling,
   and ICE/DTLS using a default target, empty attributes, and no client token
   before durable ownership. The adapter advertises no lifecycle capabilities;
   remote terminal/failure can leave routes, media, contact, and detached tasks
   alive; configured idle TTL is unused; event saturation loses terminal
   cleanup; and neither adapter nor screen-pop server drains active work.
   Bridgefu persists only instance/flow and cannot yet execute Amazon StartLeg
   through its durable actor. Sensitive attributes, tokens, URLs, SDP, and raw
   AWS/Chime errors also remain in several default diagnostics. The reusable
   control starter, started-contact cleanup guard, Chime test server,
   ContactRegistry races, core prepared-commit seam, and frozen listener stay
   in place while 5a–5h replace these behaviors.

   rvoip revision `5ad5ffe1` completes 5a and 5b. New generic calls carry an
   opaque validated/redacted profile, exact target, stable token, attributes,
   display, and description; a bounded exact profile resolver retains the same
   starter for Start, Stop, and pending cleanup. Missing/wrong/unknown context
   fails before I/O, critical request/response fields are bounded, SDK retry/
   already-ended decisions are typed, and diagnostics are metadata-only.
   Legacy screen-pop wrappers preserve defaults, empty attributes, and
   `client_token=None`. Fifty-nine all-feature Amazon unit/integration/source-
   compatibility tests pass with strict all-target/all-feature Clippy and
   default/AWS-control checks. Generic originate remains intentionally dormant
   and returns a typed unsupported result until 5d; malformed-response cleanup
   whose compensating Stop also fails remains owned by 5d/5e retained cleanup.

   rvoip revision `bbdef330` completes 5c. A public injectable
   `ConnectMediaConnector`/`ConnectMediaSession` is backed in production by the
   existing Chime plus rvoip WebRTC stack and exposes streams, negotiated
   codecs, DTMF, hold/resume, typed terminal/health state, and close to one
   absolute deadline. Chime now owns and joins its loop, classifies remote
   leave/error/transport causes, tracks activity/PONG, responds to server PING,
   and aborts on Drop/deadline without logging wire payloads, SDP, or ICE.
   Sixty-nine all-feature tests include a local Chime WebSocket with two real
   rvoip WebRTC peers and an injected non-cooperative connector; strict all-
   target/all-feature Clippy, rustdoc, and diff checks pass. Route-level
   non-live/Stop/terminal authority, PONG-expiry policy, and adapter drain
   remain explicitly in 5d/5e.

   The 2026-07-13 rvoip working tree completes 5d plus the adapter and server
   lifecycle slices of 5e.
   Generic prepare is I/O-dormant; activation is retained and single-flight,
   uses the stable Connect token for bounded ambiguous-Start reconciliation,
   publishes the redacted contact reference only after route ownership, and
   supervises terminal, DTMF, PONG/health, media, and StopContact through one
   exact route. Local end, remote end, setup failure, repeated end, and drain
   cannot duplicate StopContact. Fifty-two Amazon library tests pass, including
   hard Start/media deadlines and a drain-deadline proof that exact cleanup
   continues after the caller's deadline. The focused server qualification adds
   21 passing tests for bounded permanent drain admission, tracked watcher and
   call-task shutdown, exact setup/active registry cleanup, live `serve` exit,
   adapter delegation, and deadline detachment without aborting ambiguous work;
   server-feature all-target check and strict no-dependency Clippy pass. The
   Bridgefu outer-task/metrics ownership and durable hard-deadline cleanup record
   remain under 5e, so the parent item is intentionally still open.

   The 2026-07-14 Bridgefu working tree completes 5f. Execution-plan schema
   version 3 persists an exact, validated `AmazonConnectStartSpec` keyed by the
   outbound Amazon leg. Its profile, instance/flow, attributes, display name,
   and optional description use the same byte, cardinality, charset, and
   control-character bounds as rvoip; duplicate attribute keys and unknown
   credential/token-shaped fields fail during deserialization. Debug output is
   metadata-only. New Amazon plans fail closed without an exact target-matching
   spec, while plan versions 1 and 2 remain readable for inspection and
   teardown but cannot be inserted as new runnable calls. SQLite and PostgreSQL
   migration 0008 advance repository metadata without rewriting historical
   plan bodies or inventing start authority. Model, memory, SQLite restart,
   corrupt-body, migration non-rewrite, and shared repository suites pass. The
   equivalent PostgreSQL round-trip and migration cases are executable when
   `BRIDGEFU_TEST_POSTGRES_URL` is supplied and was skipped locally because the
   variable was unset.

   The 2026-07-14 Bridgefu working tree completes 5g. Amazon execution accepts
   only a persisted outbound, Bridgefu-initiated Amazon leg and builds its
   rvoip context from that leg's exact start spec plus the claimed immutable
   effect UUID. The client token is SHA-256 over a versioned domain and that
   UUID only. Execution prepares locally, transactionally binds the exact
   effect/claim, tenant, call, leg, generation, worker, and generated
   Connection ID, commits signaling state, and registers the route owner before
   activation can perform StartWebRTCContact; any bind failure aborts with zero
   Start. Restart reuses the byte-identical context/token, recovers and
   role-binds the exact contact reference, eagerly stops it, and atomically
   fails the non-migratable old leg. `StopLeg` reloads only that exact persisted
   media-role reference and uses the original profile and instance. Disabled
   generic execution creates no fork. The focused evidence passes 5/5 Amazon
   start-spec tests, 21/21 memory service tests, 5/5 shared service-repository
   tests, 8/8 runtime tests, 21/21 repository tests, and the exact restart/
   reference/stop execution test in the 176/176 library suite.

   Additional 2026-07-14 Bridgefu working-tree evidence completes 5e. The
   all-in-one compatibility process retains the legacy `serve` task, closes
   public admission, calls `begin_drain` and `drain_until` against one absolute
   deadline, records aggregate drain diagnostics, and joins lifecycle,
   metrics, cleanup-reconciliation, HTTP, UCTP, and generic-runtime owners in
   dependency order. A hard Amazon cleanup deadline no longer discards a
   known contact: rvoip transfers the exact profile/instance/contact Stop
   authority to a redaction-safe observer, and Bridgefu journals it in memory,
   SQLite, or PostgreSQL until StopContact succeeds or reports already ended.
   Startup reconciles the journal before new admission and a retained periodic
   owner retries it thereafter. `cargo test --locked --lib
   amazon_cleanup::tests -- --nocapture` passes 3/3 restart, tamper,
   idempotency, redaction, and joined-reconciler cases; `cargo test --locked
   --bin bridgefu
   observability::tests::metrics_updater_is_owned_and_joins_on_shutdown --
   --exact --nocapture` passes. Item 5 remains open only for the protected
   canary work in 5h; this evidence does not claim that owner-authorized
   non-production workflow.

   The 2026-07-14 working tree now implements the local protected-canary
   admission slice without changing that external gate. A new false-by-default
   policy lives only on the separate generic SIP listener and binds one
   configured tenant to an exact authenticated subject/issuer, `sip:connect`
   plus `calls:create`, one duplicate-rejecting allowlisted correlation header,
   and the tenant's exact Amazon target/mapping. It atomically creates or
   byte-identically replays the durable SIP-to-Amazon call, derives the normal
   two-minute SIP attachment bearer, and immediately returns to the ordinary
   single-use consume path. Changed metadata, cross-tenant/expired identities,
   attachment replay, mapping drift, or unavailable durable authority fail
   closed; diagnostics redact the principal, route, target, and bearer. The
   focused library suite passes 3/3 durable replay, single-use, expiry,
   cross-tenant, duplicate-header, and redaction tests; the binary config suite
   passes 2/2 false-default, exact-tenant/mapping, and unsafe-configuration
   tests; the schema checker remains green.

   The follow-up local golden closes the durable call-engine, fake-Connect,
   fake-Chime, media, and repository-crash portions of 5h. The
   `standardcharter_canary_replays_into_generic_engine_bridges_media_and_drains`
   test enters with only the configured `sip:<tenant>` routing hint and Vapi
   headers, replays/consumes the hidden bearer inside normal admission, sends
   the exact two allowlisted Connect attributes, starts one contact, runs a
   bidirectional PCMU↔Opus graph, rejects exact attachment replay, changed
   mapped metadata, and a foreign tenant, then observes one StopContact, one
   media close, zero aborts, zero graph routes, and zero retained Amazon
   sessions. `standardcharter_canary_sqlite_restart_fails_closed_without_connect_io`
   crashes after durable creation but before attachment, advances the worker
   fence on SQLite restart, fails both old legs with `worker_restarted`, and
   rejects correlation replay with zero Start/Stop/media routes. The focused
   commands pass 2/2 integration tests and the original 3/3 policy tests; the
   unchanged real-SIP frozen `standardcharter_contract` suite now passes 72/72.

   This run exposed a production rvoip integration defect rather than masking
   it in the fixture: the outbound-only Amazon adapter advertised
   `atomic_inbound_handoff=false`, so an Orchestrator with Bridgefu's
   fail-closed inbound gate rejected Amazon registration. The adapter now
   advertises that invariant as vacuously true for its outbound-only surface,
   with a direct registration regression in `rvoip-amazon-connect`. At that
   checkpoint, item 5h and item 8 still required the authenticated generic SIP
   wire boundary and the owner-authorized non-production Vapi/AWS workflow.

   The later 2026-07-14 localhost wire qualification closes the remaining
   local half of 5h through rvoip's production `UnifiedCoordinator` and
   `SipAdapter`, not an adapter-bound SIP fixture. The canary is enabled
   explicitly on a separate tenant-bound listener whose trusted loopback Vapi
   mapping supplies the exact subject, issuer, tenant, and scopes; only the
   configured correlation and Vapi call headers enter the inbound context.
   A real SIP INVITE creates and single-use-attaches the durable call, reaches
   the fake Connect/Chime boundary with exactly two screen-pop attributes,
   and carries PCMU RTP through the owned `MediaGraph` to Opus and back.
   Byte-identical attachment replay, mapped-metadata drift, and a foreign
   tenant route fail closed with zero additional Connect I/O. Remote BYE
   produces exactly one StopContact and media close, zero aborts, zero active
   graph bridges, zero Amazon sessions or pending cleanup, and zero retained
   SIP/orchestrator lifecycle tasks after drain. The exact test
   `authenticated_standardcharter_canary_crosses_real_sip_rtp_and_drains_exactly`
   passes 1/1. This does not run Vapi, AWS, or authorize a production switch.
6. [x] Add an initial-context readiness barrier. Durable
   `bridgefu.context.v1` metadata must be validated and available before an
   outbound SIP activation so allowlisted values are present on the first
   INVITE. Later context uses SIP MESSAGE where negotiated. Reject CR/LF,
   reserved or hop-by-hop headers, oversized values, identifier overrides, and
   envelopes whose tenant/call/leg fields do not match the exact durable
   connection binding.

   The 2026-07-14 Bridgefu working tree completes this barrier. Call requests
   persist an explicit backward-compatible SIP policy (`none` or `required`),
   and idempotency transcripts bind that choice. A required outbound SIP leg
   polls only the exact tenant/call/leg generation and cannot prepare a route
   or INVITE until one context message is atomically durable. Memory, SQLite,
   and PostgreSQL repository implementations bind the exact current source
   connection and both leg generations, enforce per-call message-ID replay,
   permit only byte-identical replay, and revalidate the 16 KiB envelope plus
   typed SIP-header boundary. Actor tests prove a foreign envelope sends zero
   INVITEs, a valid envelope is durable before activation and preserves its
   allowlisted headers, and timeout sends zero INVITEs. Inbound SIP metadata is
   translated once to the peer DataChannel, while later valid context and
   arbitrary application DataChannels cross the owned media graph to SIP's
   MESSAGE boundary. The complete execution-supervisor suite passes 18/18.
7. [x] Drive inbound and outbound SIP and WebRTC through the durable call
   engine using the staged interfaces above. Support G.711, Opus, RFC 4733
   DTMF, arbitrary DataChannels, context translation, supported SIP REFER and
   Telnyx transfers, remote hangup, timeout, and teardown in both directions
   without bypassing the actor or MediaGraph ownership model. Protocol-native
   WebRTC transfer has no interoperable standard in this stack and returns an
   explicit capability error. This checked historical item covers protocol
   transfer only; it does not cover the API-level make-before-break leg
   replacement now required by VF-5. Each SIP and WebRTC route must have one owned
   supervisor for negotiation, candidate, media-pump, disconnect-grace, and
   terminal tasks; teardown must cancel and join them, remove exact mappings,
   close transport resources, and emit exactly one authoritative terminal
   event. Transfer completion is established by typed protocol outcome, not by
   successful command dispatch alone.

   The 2026-07-14 working tree completes the authoritative transfer slice of
   this item without claiming the wider SIP/WebRTC item complete. rvoip now
   carries an application-owned, redaction-safe `TransferAttemptId` through
   `ConnectionAdapter`, Orchestrator submission, and the authoritative
   transfer-status stream. SIP binds that ID to one exact live route, echoes it
   on typed REFER accepted/progress/completed/failed events, discards duplicate
   or late events after exact route cleanup, and conservatively permits only
   one transfer attempt per route lifetime because the lower raw REFER event
   API does not expose a transaction identifier. Bridgefu persists
   `transferring` plus its deadline before dispatch, treats dispatch success as
   submission only, and finishes only after an exact call, target leg, binding
   generation, deadline generation, connection, and attempt match. Missing,
   stale, duplicate, cross-leg, and cross-generation status cannot settle the
   call. Submission failure and authoritative rejection compensate back to an
   active call and cancel the transfer deadline without disturbing the live
   MediaGraph.

   Telnyx uses the same terminal rule: Bridgefu puts a versioned ownership
   envelope in both `client_state` and `target_leg_client_state`, reuses the
   durable effect ID as `command_id`, and only a verified Media-role
   `call.bridged` or `call.failed` callback matching the exact tenant, call,
   leg, binding, and deadline generation may finish the transfer. The accepted
   1.0 capability matrix is deliberately narrow: a SIP leg can transfer to a
   SIP URI, and a Telnyx leg can transfer to SIP or the same Telnyx account
   profile. WebRTC, WHIP/WHEP, Amazon Connect, mismatched provider profiles,
   and deferred Twilio/Vonage transfer requests return explicit
   `unsupported_capability`/`409` before durable state changes rather than
   inferring completion from command acknowledgement.

   Focused evidence is green: Bridgefu's three-test SIP transfer suite covers
   accepted/progress, success, failure, terminal-before-submit-return, missing
   correlation, stale generation, cross-leg injection, duplicate terminal
   events, deadline cancellation, and media cleanup; the Telnyx callback,
   Telnyx SDK payload, service capability, and API conflict tests pass. rvoip's
   orchestrator correlation test and SIP exact-route REFER test also pass. The
   commands are `cargo test --test call_execution_supervisor sip_transfer --
   --nocapture`, `cargo test --lib
   telnyx_transfer_callbacks_require_exact_live_correlation -- --nocapture`,
   `cargo test --bin bridgefu
   telnyx_sdk_uses_bridgefu_owned_command_ids_for_every_mutation --
   --nocapture`, `cargo test --bin bridgefu
   unsupported_transfer_capability_maps_to_explicit_conflict -- --nocapture`,
   `cargo test -p rvoip-core --test orchestrator_dispatch
   operational_stream_orders_dtmf_data_and_transfer_outcomes -- --nocapture`,
   and `cargo test -p rvoip-sip --lib
   refer_updates_are_typed_ordered_and_bound_to_the_exact_live_route --
   --nocapture`.

   The same 2026-07-14 rvoip wire harness records a narrower production-adapter
   slice for this item. It uses actual prepared/committed SIP and WebRTC routes,
   the common Orchestrator bridge and MediaGraph, real G.711/Opus RTP,
   WebRTC→SIP RFC 4733, bidirectional DataMessage/SIP MESSAGE translation,
   remote SIP hangup, post-teardown silence, and exact resource cleanup. The
   reusable fixes exposed by that run landed in rvoip first: `rvoip-core`
   enables the Opus media feature in its production dependency graph; WebRTC
   retains RFC 7587 `opus/48000/2` SDP while normalizing the default media
   signal to mono; one WebRTC audio stream can attach both Opus and
   telephone-event tracks without duplicate pumps; and exact outbound SIP
   release treats a peer-removed dialog as authoritative terminal state. The
   focused three-package `cargo check` and strict `rvoip-webrtc --no-deps`
   Clippy pass. This evidence does not complete item 7 because the Bridgefu
   durable actor, inbound attachment paths, reverse-direction DTMF, WSS/WHEP,
   and deployed NAT traversal are not exercised.

   The later split-gateway slice closes the local inbound protocol-termination
   gap. A real authenticated WHIP offer retains the
   exact auth-core subject/issuer/tenant and WebRTC attachment token through
   admission; a real SIP dialog retains its exact SIP token; both use the
   transport-only gateway Orchestrator and drain to zero. Pump tests cover
   complete RTP, arbitrary DataMessages, and typed DTMF over the private route.
   Final local composition evidence uses a real native WHIP peer, exact
   principal/attachment routing, mTLS UCTP 0.2, an authoritative single-use
   worker consume, the durable call actor and MediaGraph, bidirectional Opus,
   bound context DataMessages, RFC 4733 DTMF, terminal teardown, and zero
   native/private routes, worker bridges, or lifecycle tasks. It is
   `native_whip_edge_reaches_call_pinned_worker_over_mtls_uctp_and_drains_cleanly`;
   the complete private-forwarding target passes 7/7. WSS and WHEP semantics
   remain covered at their first-party rvoip listener boundaries rather than
   by duplicating this topology test. RTCP is intentionally terminated
   hop-by-hop when transcoding changes packet identity; the native termination
   metric and byte-exact private RTCP conformance are tested separately.
   Deployed NAT/TURN remains the owner-gated item 9 qualification and does not
   keep the local call-engine implementation open.
8. [x] Preserve the frozen StandardCharter path while adding a protected
   canary compatibility route for its trusted Vapi contract: `sip:<tenant>`
   plus `X-Correlation-Id`, without a public attachment token. The canary may
   auto-create or attach only after source authentication, explicit tenant
   enablement, correlation validation, and durable idempotency/deduplication;
   unrelated or replayed requests must fail closed. The existing runtime stays
   the default until this path passes every frozen regression and the
   non-production canary workflow.
   - [x] Local durable-engine compatibility evidence: authenticated principal,
     exact tenant/correlation mapping, hidden attachment derivation, stable
     idempotency, replay/metadata-drift/cross-tenant negatives, real
     MediaGraph PCMU↔Opus, bidirectional teardown/drain, and SQLite crash
     fencing through the production Amazon adapter seams.
   - [x] Real authenticated generic SIP listener packet and RTP path with
     durable create/attach, replay and tenant negatives, fake Connect/Chime,
     screen-pop attributes, PCMU↔Opus, teardown, and exact drain cleanup.
   The manually protected Vapi→AWS non-production workflow remains an
   unchecked Gate 11 item. The legacy runtime remains the default and no
   production switch is authorized.
9. [ ] Add configurable STUN/TURN, symmetric RTP, advertised addresses, SIP
   `rport`, ICE/DTLS timeout handling, and NAT-aware media-port allocation. ICE
   candidate policy is per exchange: HTTP answers full-gather as required by
   WHIP/WHEP, while trickle-capable clients buffer until `Location`/`ETag` and
   WS/WSS exchanges negotiate trickle independently. Do not use one global
   trickle setting across these substrates.
   Prove real PCMU and PCMA SIP/RTP to Opus WebRTC media in both directions,
   real RFC 4733 DTMF, WS/WSS and WHIP/WHEP signaling, initial and subsequent
   context translation, terminal cleanup, and no media after teardown across
   representative NAT topologies. Mock-adapter bridge tests alone do not
   satisfy this prerequisite or the gate.
   - [x] 9a — Prove the hermetic localhost production-path slice: PCMU↔Opus
     over WHIP and WSS plus PCMA↔Opus over WS, actual SIP and WebRTC RTP,
     RFC 4733 in both directions, arbitrary binary DataChannel→SIP MESSAGE,
     subsequent SIP MESSAGE→`bridgefu.context.v1` DataChannel, exact
     allowlisted initial SIP INVITE headers, symmetric-RTP tuple learning,
     remote SIP BYE, post-teardown silence, and exact graph/route/task cleanup.
     Prove canonical secure WHEP-04 one-way playback separately because WHEP
     is a playback role rather than a bidirectional interactive leg.
   - [x] 9b — Qualify the remaining local failure and durable-attachment
     boundary: candidate-less ICE and mismatched DTLS fingerprint fail within
     the configured deadline and release both routes; advertised signaling and
     media addresses, RFC 3581 `rport`, and bounded symmetric-RTP rebinding
     pass focused network tests; a real tenant-authenticated SIP listener
     consumes Bridgefu's hashed single-use two-minute request-URI token,
     reaches the durable call actor only after ACK, binds an explicitly
     token-selected peer without FIFO pairing, creates one active bridge, and
     tears both legs and all lifecycle tasks down on remote BYE. The initial
     context proof is deliberately split: the durable actor owns and persists
     `bridgefu.context.v1` before originate, while the production SIP wire test
     proves the resulting allowlisted headers exactly; it is not represented
     as one monolithic edge-to-edge test.
   - [ ] 9c — Use the published, checksummed rvoip 0.3.5 WebRTC/RTC package
     graph as the clean fetchable input. That dependency migration is
     complete; generic SIP, Amazon Connect, and Telnyx exact Chromium reruns
     pass, while generic WSS is blocked by the reproducible outbound RFC 4733
     defect in rvoip #54. Reconcile any behavior demonstrated only by the
     historical TURN, NACK/statistics, or `codex/dtmf-codec-identity`
     candidates in the rvoip repository before a
     future package update; do not add a Bridgefu path or floating-Git
     override.
     Run Bridgefu through representative deployed public-NAT and TURN-only
     topologies, including explicit media-port allocation/forwarding behavior,
     and rerun the RTC, rvoip WebRTC, exact Chromium destination, and
     StandardCharter regression matrices against the committed lockfile.
     Reproducible rvoip defects are filed in `eisenzopf/rvoip`; Bridgefu does
     not carry a local dependency patch.

Focused local evidence for 9a and 9b is green on 2026-07-14. The rvoip
production-adapter matrix runs three bidirectional cases (WHIP/PCMU,
WS/PCMA, and trust-bundle-scoped WSS/PCMU) plus secure WHEP-04 playback. The
WSS peer advertises an SDP RTP tuple different from its actual source and
proves media returns to the learned tuple. Two additional target-contacting
WHIP cases prove bounded ICE and DTLS failure cleanup. Focused SIP/RTP tests
prove advertised public addresses, `rport` source-port recovery, and symmetric
RTP rebinding policy. Bridgefu's real authenticated attachment case completes
the durable actor boundary and also exposed two reusable rvoip fixes: inbound
`SipAdapter::accept` now waits for the UAS ACK/Active boundary before emitting
`Connected`, and inbound BYE cleanup dispatches from a fresh owned task so the
normal Tokio test stack is not exhausted. Scoped rvoip strict Clippy passes.
Bridgefu's current strict all-target/all-feature Clippy passes. Item 9 remains
open for the rvoip #54 fix and exact generic-WSS rerun plus deployed
public-NAT/TURN proof; it is no longer waiting for the other three exact
Chromium destinations to execute.

The current Bridgefu release declaration uses exact crates.io rvoip 0.3.5
packages, and Cargo.lock records their registry checksums; the graph contains
no Git or path package source. The earlier validation runs used temporary
`../rtc/rtc` manifest overrides and a path-resolved generated lock entry, but
that historical state is not current release provenance. Bridgefu does not
carry a private dependency patch for the current failing browser behavior;
rvoip issue #54 is the maintainer handoff. Any future private fork still
requires a minimal failing engine conformance test and separate owner review.

The private TURN hardening work is complete locally at WebRTC revision
`4a2f64c4a10562bfbcf6e406afb197642e72c442` with `rtc` submodule revision
`4aa775a2c7d308b15075b544eaf667eba8584a6f`. The candidate scope includes real
UDP relay-only gathering and routing, allocation/permission/refresh/release,
authenticated responses, stale-nonce and ICE-restart recovery, exact inbound
TURN tuple enforcement, bounded peer state, IPv6 related-address handling,
and cancellation-safe coalesced PeerConnection shutdown. Its focused unit,
TURN end-to-end, strict library Clippy, formatting, and independent P0/P1/P2
audit evidence is green. These revisions have not been pushed, submitted
upstream, or pinned into rvoip: owner review and an owner-approved private
remote are prerequisites for changing the fetchable dependency. The existing
tracked rvoip `rtc` revision therefore remains authoritative until that review;
the earlier temporary local path override produced validation-only evidence,
and no roadmap item may claim the local TURN fork is integrated before the exact
pin and downstream WebRTC qualification pass.

The recorded 4/4 private WebRTC TURN run used those two heads plus the RTC
submodule's separate uncommitted four-file NACK/statistics delta. It is valid
evidence for that composite local worktree, not yet for a clean immutable
revision pair. `docs/webrtc-fork-review.md` records the files, commands, scope,
and owner-review sequence required before adoption.

Downstream qualification now uses a hermetic in-process TURN server rather
than the former Docker fixture, so an unavailable container network cannot
silently skip relay evidence. Against the current crates.io WebRTC alpha pin,
the real two-peer Opus test fails because `IceTransportPolicy::Relay` is not
enforced and no relay pair is selected. The same test passes against the two
private revisions above. That run also exposed and fixed rvoip's candidate
diagnostic lookup: alpha stats prefix candidate entry IDs while candidate-pair
references use the unprefixed ID.

The subsequent private RTC delta at base revision
`4aa775a2c7d308b15075b544eaf667eba8584a6f` closes the lossy-audio feedback
path: generic NACK is negotiated for Opus, declared SDP SSRCs bind to inbound
interceptors after first-packet codec resolution, inbound RTCP feedback updates
statistics, and same-SSRC audio retransmissions are counted. The hermetic
lossy-TURN test deterministically drops 31 relay packets, recovers all 200
frames, observes 20 NACKs and 23 retransmissions, and passes. The RTC library
passes 180/180 tests, four focused regressions pass, and the top-level private
WebRTC TURN suite passes 4/4. The scoped four-file fork diff is uncommitted and
unpushed. The remaining release blocker under item 9 is owner review plus an
immutable fetchable private WebRTC/RTC revision and downstream qualification
against that exact pin; no upstream contact is authorized.

A second local RTC candidate on branch `codex/dtmf-codec-identity`, based on
the currently authoritative `1e5b7d4be6d94850694f2519f4c235d16c871d53`,
addresses final-SDP telephone-event interoperability independently of the TURN
and NACK work. Its six modified files cover sender codec identity/binding,
same-clock payload preservation, primary-only supplemental SDP, grouped and
un-signaled supplemental receive ownership, and their tests. The current diff
is 807 insertions and 130 deletions with stable patch ID
`478b7da63ea6d195f446a9abce4c56e62129a86e`. The full local RTC library passes
180/180, including all 13 candidate tests; rvoip's outbound-writer suite passes
4/4, DTMF wire 3/3, and browser SDP 13/13. Exact built-SDK Chromium handoffs to
generic SIP, generic WSS, Amazon Connect, and Telnyx are also green against this
local composite. The candidate is uncommitted and unpushed; those path-override
results do not change the authoritative tracked pin or constitute release
integration. Owner review, a clean immutable revision, restored exact pins and
lockfile provenance, and the downstream reruns in 9c remain mandatory.

The pre-item-3 client audit at committed rvoip revision `e982e36b` confirms
that the authenticated WS/WSS and WHIP/WHEP server roles are present, but the
outbound adapter is still local-only. `WebRtcAdapter::originate` creates a peer,
offer, and route without contacting `OriginateRequest::target`.
`WsSignaler` opens a separate socket for offer, answer, and each candidate,
while `SignalingPool` only caches the object and therefore does not provide the
documented persistent multiplexed connection. There is no WHIP or WHEP HTTP
client retaining `Location`/`ETag`, applying conditional PATCH/DELETE, or
constraining redirects and credential forwarding. The current WHEP server is
the legacy empty-POST/server-offer flow, and the base `Signaler::send_ice`
method cannot scope a candidate to a resource. Item 3 must replace these seams
with target-contacting, resource-owning client sessions. It also finds that the
current server accepts/echoes an inexact WS subprotocol, does not own all routes
or child tasks by socket, does not actually abort every task at drain deadline,
uses one global trickle policy, and lacks route-versioned ETag/If-Match on all
WHIP/WHEP mutations. Direct WHEP activation bypasses Orchestrator durable
binding, and generic targets currently have no SSRF or redirect credential
boundary. The reusable pre-upgrade auth, route ownership, provisional inbound
context, SDP/ICE primitives, and core prepared-commit seam remain the base for
the ordered 3a–3h work. Existing loopback and server-role tests are not
completion evidence for outbound interoperability.

Gate 7 progress evidence recorded on 2026-07-12:

- rvoip revision `ff248a243dfa9c6db0a79e09e9505f4dc8b1a685` completes
  item 1. `OriginateContext`, bounded redacted external references, activation
  receipts, request builders, and the compatibility activation hook are owned
  by core. Provisional receipts are cleared and the final receipt is exposed
  only after activation, route/lifecycle/session liveness, authoritative-event
  health, and prepared-supervisor completion. Both prepared and legacy paths
  fail closed and compensate if authority is lost while activation is awaited.
- rvoip-core-traits passes 16 tests; rvoip-core passes 77 library and 79
  orchestrator-dispatch tests plus its remaining integration and doctest
  suites. Split all-target workspace checks, the comprehensive WebRTC feature
  check, strict core Clippy and rustdoc, rustfmt, and diff checks pass. An
  independent P0/P1 audit found and verified the legacy event-health race fix,
  then reported no remaining release blocker. The two unsplit workspace check
  failures are pre-existing feature-configuration defects outside this change
  and are recorded for Gate 7 cleanup rather than represented as new evidence.
- rvoip revision `52c2d78eb71eb62c20920dcf94881a31afe16c21`
  implements the first 2a admission and diagnostic-redaction pass. Its combined
  qualification passes 2,050 sip-core tests (one ignored), 328 sip-dialog
  tests, 232 rvoip-sip library tests, and 12 trace integration tests, together
  with package checks, strict sip-core/sip-dialog Clippy, rustdoc, rustfmt, and
  diff checks. The retained originate context is intentionally not applied to
  a packet yet. An independent P0/P1 audit found no P0 but rejected completion
  because final raw auth insertion, start-line redaction, the lower-level
  no-policy trace path, and the typed-header default still have P1 disclosure
  or header-smuggling gaps. It also confirmed that true dormant activation and
  terminal-stage reclamation remain item 2b blockers. These findings are
  release gates, not deferred cleanup.
- The subsequent item 2a audit at rvoip revision
  `36f7d59e5dfc8398e7c6725fec998955dcb94c13` confirms the authorization,
  trace-event, orphan-fold, typed raw-field, response-reason, and outer-event
  closures already landed, but keeps 2a open. Exact serializer validation for
  structured typed headers and request start lines is in qualification, and a
  further P1 diagnostic audit found transaction commands, complete SIP
  messages, Via branches, extension methods, arbitrary errors, original
  requests/responses, authorization decisions, and pre-validation route/Via
  values reflected by transaction-layer logs, plus a parser failure path that
  reflects the unparsed peer-controlled remainder. The 2b dependency audit also
  found raw P-Asserted-Identity/proxy URI values in SIP option-materialization
  errors. A final source-wide scan also found the same caller-controlled URI,
  Contact, REFER target, reason, transaction identifier, and lower-error values
  in legacy dialog/API/manager/protocol logs outside the transaction tree.
  Those diagnostic surfaces
  must be closed with log-only wrappers before 2a may be represented as
  complete. `TransactionKey`'s public `Display`/`Debug` formats remain unchanged
  because legacy event/API round trips parse them functionally; only log sinks
  may use the safe wrapper.
- rvoip revision `10e239bd5adf4fdf3c47aad2d3acdbcd13bef5ae`
  closes the exact typed serializer boundary. It validates every rendered
  header variant and nested value through an early-stopping bounded formatter,
  validates exact header names plus method/URI/version start-line fields, fixes
  `Call-Info` serialization, and rejects unsafe fields before manager,
  UDP/TCP/TLS/WS/WSS, direct-connection, or multiplexed transport I/O while
  preserving explicit raw sends. The five-crate qualification executes 2,768
  tests with one ignored, and passes checks, strict lower-crate Clippy,
  warning-free rustdoc, formatting, and diff checks. Item 2a remains open only
  for the separately enumerated transaction/parser/option diagnostic closure
  and its final independent audit.
- An independent audit of rvoip revision
  `fa173e7c9bd875ea143a0894415c5826448c09c0` confirms the new PAI/proxy option
  errors and structured-options wrapper are value-free and preserve absent-From
  and header-order behavior, but keeps 2a open. The earlier CreateDialog action
  and lower dialog manager still log raw endpoints, while legacy, extra-header,
  and authenticated-retry adapter wrappers still relay lower builder/parser
  source text. Those two P1 paths are part of the active diagnostic closure.
- The independent transaction audit at rvoip revision
  `a3e44a5a97a7dae54a7d91c43519e58e431c2ad7` keeps 2a open after finding two
  source-scan false negatives: a raw transaction key named `tx_key` and a raw
  lower error named `err`. Malformed `TransactionKey` parse errors also echo the
  complete key or invalid side before a legacy event-hub path relays them.
  Identifier spelling is not a security boundary; scans and canaries must cover
  typed operands and the complete parse/error path rather than a short variable
  name list. Diagnostic return values are included: retention/capacity
  breakdowns may expose only the safe standard-method class or `extension`,
  never `Method::Extension` text or an unbounded method label. Static scans must
  be field/type-aware enough to reject `tx_key`, positional events, lower errors,
  and arbitrary dialog identifiers without treating every unrelated numeric
  variable named `id` as a transaction secret.
- The parallel INVITE-wrapper audit at the same revision confirms endpoint
  logs, all eight dialog dispatch wrappers, absent-From behavior, header order,
  and wire behavior are correct, but finds one earlier P1: Digest challenge
  algorithm text or an arbitrary AKA-provider error can cross the authorization
  construction boundary, become a terminal failure reason, and then reach logs
  and application events before the safe resend wrapper. Authorization
  construction must map every lower error to a fixed auth class at the action
  boundary, and terminal event/log diagnostics must expose only that class.
  Sanitization occurs before normal-path `TransitionRecord`/`ActionRecord`
  construction: in-memory history and JSON/CSV export may retain only the fixed
  `AuthRequired` class, status, presence/length metadata, and safe standard
  method or `extension`. Raw challenges, authorization values, arbitrary AKA
  errors, and peer or public-API CSeq extension spellings may never enter a
  history record. Functional cross-crate delivery may retain the challenge only
  for authentication computation, but its `Debug` view and every history/export
  projection are metadata-only; diagnostic serialization is never the runtime
  payload type.
- The outer-dialog audit at rvoip revision
  `7e5a185e2de2a0627f32056c9ab7e776cab1e412` keeps 2a open for four additional
  legacy shapes: an INVITE-handler transaction key, extension methods embedded
  in outward dialog errors, STIR/SHAKEN verification outcomes whose derived
  `Debug` contains arbitrary reasons, and event-hub transaction parse/operation
  errors relayed verbatim. Safe source scans must cover typed derived values and
  outward error constructors, not only obvious tracing field names.
- The outbound-auth audit at rvoip revision
  `6effbbe1b6757201c53af9ce22de1e0cdcfe5d53` confirms construction mapping and
  terminal CallFailed reasons are fixed-class, but finds two normal-path P1
  retention gaps: serialized transition history still clones the complete
  `AuthRequired` event, and extension CSeq methods still enter auth
  retry/missing-credential errors and action history. History is enabled by
  default, so both values must be classified before the record is created.
- The complete item 2a security audit at rvoip revision
  `a7da8b59e8f529b0ece1a02a0ececd167eb69bf9` finds no remaining typed-wire
  injection and confirms raw sends are the sole intentional bypass, but keeps
  2a open for six diagnostic groups: parser/header conversion values;
  REFER/transaction legacy logs; resolver/TLS plus registration identities;
  transport/header-policy/method/action errors; raw Call-ID timing snapshots;
  and value-bearing auth challenge containers. These are release blockers,
  not deferred observability cleanup.
- The independent public-diagnostic audit at rvoip revision
  `3ab1e1b58e9051367ca24842726dc49ffe1b95e9` adds six P1 groups to item 2a
  before closure: consolidated public session/CDR types retaining From, To,
  Call-ID, SDP, MESSAGE/NOTIFY bodies, transfer/registration targets, reasons,
  and asserted identities; state-machine helper/executor events retaining
  caller, error, custom-event, and media-address payloads; negotiated media
  configuration retaining RTP addresses and codec values; public TCP
  `ReceivedFrame` retaining byte-exact SIP credentials/body; `ViaRewrite`
  retaining arbitrary pushed bytes; and direct infra support enum diagnostics
  retaining termination/registration error strings. The outer cross-crate
  wrapper is already safe, but every public/direct diagnostic container must
  be safe independently. These findings are recorded before remediation and
  keep 2a open.
  The same audit also finds three P1 control/error paths: boxed lower errors
  can bypass dedicated authentication redaction when flattened into
  `SessionError::Other`; the public TLS certificate-error class is dead while
  certificate parse/config/verification failures collapse into the generic
  handshake class; and SIP WS/WSS subprotocol negotiation is fail-open on both
  server and client when the peer omits or refuses `sip`/`sips`. Preserve lower
  errors only for typed matching, route certificate failures to their declared
  class without rendering rustls detail, and fail the WebSocket upgrade/dial
  with a typed protocol error unless the peer explicitly negotiates the exact
  required subprotocol.
  User callback and coordinator-shutdown failures are also in this P1 closure:
  production logs currently render raw `SessionError` values at each callback
  stage, so arbitrary application/provider strings can escape even after the
  enclosing callback types are safe. Log only a fixed callback operation and
  typed error class; retain the original error solely in the live return path.
- The independent SIP-core/framing audit at rvoip revision
  `c0cc324151819394e3c107d48f018b64854e91d7` confirms the compact-alias,
  duplicate, bounds, checked-arithmetic, and TCP/TLS smuggling defenses, but
  adds six P1 compatibility/diagnostic findings before 2a can close: direct
  Digest/authentication-info parameter and extension-scheme diagnostics still
  expose credential values; low-level `Header`/`HeaderValue`/`HeaderName`
  diagnostics bypass the safe `TypedHeader` view; SDP simulcast diagnostics
  expose RID identifiers; remaining registrar API/presence/registry logs expose
  subscriber/contact identities or arbitrary event errors; the shared scanner
  rejects valid SIP HCOLON whitespace before `:`; and the transport-neutral
  complete-message parser incorrectly applies the stream-only requirement for
  an explicit Content-Length instead of accepting an absent length as a
  zero-byte body. Keep strict explicit-length framing for TCP/TLS while adding
  a complete-message policy for UDP/direct parsing, and cover both modes with
  regression tests.
- The final exact-combined SIP audit at rvoip revision
  `a327bfb2` remains nonzero and records two additional P1 public-diagnostic
  boundaries before remediation: `EndpointCall` and `EndpointIncomingCall`
  directly render raw Call-ID and From/To values, and the registrar's public
  `UserCredentials` diagnostic renders its plaintext password. The same audit
  is continuing across registrar events, public types, and errors; every
  consolidated finding must be recorded here and independently re-audited at
  the remediated exact revision before Gate 3 or item 2a can close.
  It also records P1 authentication/lifecycle defects: the legacy registrar
  validates Digest response arithmetic without proving server nonce issuance,
  expiry, or nonce-count freshness, so a captured REGISTER authorization can be
  replayed. Its `UserStore` retains and clones plaintext passwords. The primary
  SIP Digest services keep unbounded local issued-nonce and nonce-count maps and
  remove an expired nonce only when that exact value is later presented,
  allowing unauthenticated challenge traffic to grow memory indefinitely.
  Registrar authentication must use issued, expiring, replay-protected nonces
  and verifier/HA1-backed secrets; all local replay stores need hard capacity,
  periodic expiry, and coupled nonce-count cleanup.
  Responses that omit an offered Digest `qop` currently bypass nonce-count
  enforcement, and response comparison uses ordinary early-exit string
  equality. Require the negotiated `qop` contract, enforce monotonic nonce
  counts whenever offered, and compare response digests in constant time.
  The audit additionally finds the WebSocket frame cap is declared but not
  supplied to either server or client tungstenite configuration; already-large
  frames are then copied during processing, leaving an allocation/double-copy
  DoS path. Configure bounded message/frame/write limits before the handshake
  on WS and WSS and reject oversize frames without another full-size copy.
  RFC 7118 also requires exactly one SIP message per WebSocket message, but the
  WS/WSS boundary uses the lenient complete parser and accepts the first request
  from a frame containing a second SIP message while retaining both in raw
  bytes. Use strict full-frame parsing with zero trailing bytes and add a
  packet-capture request-smuggling regression canary.
  The complete-message framing policy also incorrectly treats an absent
  Content-Length as a zero-byte body. RFC 3261 message-oriented transports and
  RFC 7118 WebSockets define the packet/frame remainder as the body when the
  length is absent. Preserve that remainder for CL-less SDP/MESSAGE bodies;
  when UDP has an explicit shorter length, retain only the consumed message in
  `raw_bytes` and discard datagram excess so the advertised raw SBC path cannot
  forward a smuggled second request. WS/WSS must reject, rather than discard,
  any bytes beyond one complete message.
  UDP currently declares the legal 65,507-byte packet maximum but receives into
  only 8,192 bytes on both awaited and nonblocking paths, allowing the OS to
  silently truncate a datagram that can then be parsed as valid. Receive the
  complete supported datagram size or detect `MSG_TRUNC` and drop it before SIP
  parsing; add oversized-body and truncated-request regressions for both paths.
  Typed WS/WSS outbound sends also use lossy UTF-8 conversion unconditionally,
  mutating binary SIP bodies and potentially invalidating Content-Length. Per
  RFC 7118, send Text only when the complete serialized SIP message is valid
  UTF-8; otherwise send the exact bytes in a Binary WebSocket message.
  `TlsPeerIdentity`, `TransportConnectionMetadata`, and the enclosing SIP
  ingress context still derive diagnostics over the complete client-certificate
  fingerprint. Retain the fingerprint for mTLS policy matching, but expose only
  presence, length, verification state, and certificate-chain count.
  TLS failure classification must include certificate revocation failures and
  certificate-related peer alerts, not only `InvalidCertificate` and
  `NoCertificatesPresented`; preserve a fixed certificate-vs-handshake class
  without rendering rustls details.
  Remaining public diagnostic P1s include sip-core `CallId`, `Address`,
  `Error`, and `LocationAwareError`; sip-dialog `DialogError`, `RecoveryError`,
  and `ApiError`; and registrar errors, events, and public registration/presence
  types. Each currently derives or displays retained caller IDs, addresses,
  parameters, reasons, messages, or arbitrary details. Preserve live typed
  fields for matching and wire behavior, but make all direct `Debug`, `Display`,
  error-source, and diagnostic serialization projections metadata-only.
  A production adapter warning also logs the authenticated principal subject;
  it must use only fixed principal-presence and ownership metadata.
- The exact-combined compatibility audit at rvoip revision `a327bfb2` records
  four P1 regressions before remediation. Legacy incoming-call standard header
  keys and staged REGISTER response header names incorrectly use the newly safe
  `HeaderName` `Debug` view as functional wire data; both must use a canonical
  header-name API while retaining extension names only in the live value.
  Bearer fallback subjects similarly use the safe `IdentityAssurance` `Debug`
  view, collapsing distinct pseudonymous keys and same-length DTLS fingerprints
  into one ownership subject; identity derivation needs a typed stable digest.
  Follow-up at the compatibility patch boundary finds the centralized default
  `BearerValidator::validate_principal` path still uses
  `AuthenticatedPrincipal::from_assurance`: it collapses every anonymous and
  keyless pseudonymous assurance to a shared owner, derives identified fallback
  identity from diagnostics, and exposes raw DTLS material. Reject a successful
  Bearer result that provides no credential-derived owner, and centralize a
  typed, stable, credential-free digest for assurance variants with real binding
  material so all transports inherit the same collision-resistant ownership.
  Finally, WSS now requires the nonstandard WebSocket subprotocol token `sips`,
  while RFC 7118 requires `sip` for both WS and WSS. Keep the secure URL and
  transport classification, but advertise and require the exact `sip` token on
  both substrates. The remaining compatibility surfaces inspected by this
  audit had no additional P0/P1 findings.
- The final exact-combined credential/ownership audit at rvoip revision
  `a327bfb2` records two P0 users-core authorization failures before
  remediation. A non-admin `PUT /users/{id}` may update the caller's own
  `roles` and `active` fields, allowing self-promotion or bypass of account
  lifecycle policy. Separately, API-key authentication loads the owning user's
  roles but handler authorization never enforces the key's own permission set,
  so a least-privilege key owned by an administrator receives administrator
  authority. Split self-service profile updates from administrative role/state
  mutations and propagate/enforce the credential's effective permissions at
  every protected handler before Gate 3 can close. The audit is continuing and
  all consolidated findings must be closed and re-audited at an exact revision.
  The same audit records three P1 ownership failures. AAuth unions actor scopes
  into a subject principal without requiring compatible issuer, tenant, or an
  explicit delegation relationship, allowing cross-tenant scope elevation when
  a validator spans tenants. Orchestrator `complete_step_up` accepts an
  arbitrary connection ID, authenticates a credential, and emits an assurance
  event without verifying the route owner or updating the connection principal.
  The users REST JWT extractor also bypasses users-core token revocation and
  active-user checks, leaving revoked or deactivated sessions authorized until
  token expiry. Delegation must be explicit and tenant/issuer constrained;
  step-up must be an atomic owner-bound principal transition; and every JWT API
  path must enforce revocation plus current user state.
  A third P0 in the users API lets an authorized caller create a key through
  their own `/users/{id}` path while supplying a different `user_id` in the
  request body. Combined with the ignored key-permission defect, a normal user
  can mint an administrator-owned key and exercise administrator authority.
  The path identity must be authoritative (or the body identity removed), and
  ownership plus requested permissions must be validated transactionally.
  The completed credential audit also finds unrestricted authenticated user
  enumeration of emails, roles, and status. It records remaining P1 diagnostic
  boundaries across auth-core (Bearer/DPoP/HTTP-signature errors and payloads,
  user/actor contexts, and JWKS logs), core traits/runtime (erased adapter
  errors, arbitrary `DataMessage` bytes/labels, reachability and fingerprint
  identities), UCTP (custom scope maps, required scopes, participant identities,
  lower transport/TLS errors), the unified client (arbitrary URI/protocol/server
  error JSON), users-core (enclosing database/JWT/validation/internal errors,
  public identity/passkey/update/auth contexts, and background task errors), and
  WebRTC (SDP/ICE/signaling events, lower errors returned by WHIP, TLS logs,
  route-owner legacy subjects, and DTLS fingerprints). IMS-AKA and LDAP have no
  remaining P0/P1 in this audit, and UCTP's issuer+tenant+subject binding
  comparisons are sound. All listed public diagnostics and remote error bodies
  must become fixed class/shape metadata while functional values remain
  available only to their authorized live paths.
- The post-remediation cross-audit at rvoip production revision
  `d46fd91a993129d312d95849d3046525398812b2` (unchanged by test-only descendant
  `ac9d75549f6f78cab0e87fc918075c02b17bc0da`) reports zero P0 but three new P1
  lifecycle/admission gaps before Gate 3 or item 2a can close. WS/WSS performs
  TLS and HTTP upgrade inline in the sole accept loop without a deadline, so
  one slow peer blocks every later connection; direct TLS spawns every accepted
  handshake without a deadline or admission bound, allowing task/FD/memory
  exhaustion. `TlsTransport::close` only flips a flag while its detached accept
  loop and live readers continue accepting and emitting events, defeating
  drain, reconfiguration, and port rebinding. Finally, unauthenticated Digest
  challenge churn can fill the 4,096-entry stateful nonce sets and evict active
  challenges in both registrar and local rvoip-sip fallbacks, indefinitely
  starving legitimate clients when rate limiting is absent. Add bounded
  concurrent handshake supervision with deadlines, owned listener/connection
  cancellation and joined close/drain semantics, and nonce admission that never
  evicts an active challenge (plus pre-challenge source limiting or stateless
  signed nonces for exposed listeners). Re-audit the exact remediated revision.
  The parallel compatibility audit records two additional P1 public-contract
  breaks at the same revision. Users-core added required public fields to
  `api::AuthContext`, breaking every downstream struct literal; keep token
  revocation metadata behind an internal extractor/session context or provide
  an explicit versioned constructor/migration. Registrar `UserStore` retained
  `get_password`/`get_credentials` signatures but now silently returns
  `None`/an empty password for existing users. HA1-only storage is required,
  but false legacy success semantics can make downstream authentication fail as
  though the user vanished; remove or explicitly version the incompatible
  secret-retrieval contract with a migration to `get_digest_secret` rather than
  silently lying through the old API.
  A second cross-audit records three further P1 ownership/escalation defects at
  the same production revision. API-key creation checks only caller `write`
  permission plus owner/admin status while accepting any requested permission,
  so an administrator-owned write-only key can mint `*` and regain full admin
  authority; requested grants must be a subset of the calling key and wildcard
  or administrative grants require explicit non-key administrator authority.
  Core step-up authenticates only `(IdentityId, IdentityAssurance)` and then
  grafts the result onto the connection's existing issuer/tenant/subject after
  string matching, so a same-name credential from another provider—or an AAuth
  actor identity—can acquire the subject connection's authority. Step-up
  providers must return a complete `AuthenticatedPrincipal`, and the atomic
  transition must compare issuer+tenant+subject ownership before updating.
  Finally, TaskScoped/UserAuthorized compatibility subjects concatenate
  unconstrained IDs with delimiters, allowing distinct attacker-chosen field
  tuples to collide on one ownership key. Use domain-separated,
  length-prefixed hashing (or a typed ownership key) for every composite
  fallback subject and add adversarial delimiter-collision tests.
  The same audit finds a separate API-key exchange P1: public
  `AuthenticationService::authenticate_api_key` discards the validated key and
  its permissions, issues ordinary role-derived access and refresh JWTs, fails
  to store the refresh JTI, and reports a five-minute expiry while the token
  uses the configured access TTL (fifteen minutes by default). Because missing
  refresh rows are treated as active and REST JWTs receive full permissions, a
  read-only key can exchange itself into unrestricted user/admin authority and
  an untracked thirty-day refresh token that survives key revocation, logout,
  and password revocation. API-key authentication must either remain a
  non-upgradeable restricted context or issue permission-constrained,
  key-bound, accurately expired tokens whose refresh lineage is durably stored
  and revoked with the originating key/user.
  Users-core also fails open when the public `AuthenticationService::new`
  constructor is used without its optional security store: password changes,
  logout, access/refresh revocation, and JTI checks silently succeed or treat
  absent state as active. `create_router` accepts that service, so custom or
  PostgreSQL construction can expose credential-retirement endpoints that
  return success while old passwords and tokens remain valid. Make the security
  store a required constructor dependency for any API-capable service, or make
  every retirement/validation path return a typed unavailable error rather than
  silently weakening policy; add non-SQLite fail-closed tests.
- The third exact cross-audit at rvoip revision
  `98b87099029d9fd6ac6fe1ef6bc718f706e994ea` remains nonzero after the second
  remediation. Outbound TLS and WSS TCP/TLS/HTTP handshakes still have no
  deadline, global/per-destination admission, task ownership, or close/drain
  cancellation. Concurrent pool misses also dial the same destination in
  parallel; WS overwrites the map and an older reader unconditionally removes
  the newer route, while TLS teardown removes every duplicate for the address.
  Add managed outbound admission/deadlines, per-destination single-flight, and
  generation/identity-checked eviction so close joins dials and a stale reader
  cannot erase its replacement. The publicly exported `WebSocketListener`
  likewise retains a sequential `accept()` that performs the full unbounded
  TLS/HTTP upgrade outside the hardened transport supervisor; make the low-level
  API explicitly configured and bounded or move it behind a breaking migration.
  Digest saturation now preserves active state, but nonce-count replay keys use
  only `(username, nonce)`. When saturated clients share the reused nonce, a
  first legitimate proof with `nc=1` locks out later clients with different
  `cnonce` values until expiry. Key replay state by username, nonce, and cnonce
  (with the same aggregate cap/cleanup), and test multiple new legitimate
  clients after saturation rather than only one preexisting unused proof.
  Users-core still lets a write-only API key owned by an administrator use
  `PUT /users/{id}` to mutate any user's roles/active state because owner roles
  satisfy `is_admin` without explicit key `admin` permission. All cross-user and
  role/state mutations must require non-key admin authority or an explicit key
  admin grant. Its default Axum server omits real peer `ConnectInfo`; rate
  limiting therefore trusts spoofable `x-real-ip` or places every client in one
  `unknown` bucket, while IP and failed-login maps are unbounded by
  attacker-controlled addresses/usernames. Wire socket peer identity, trust
  forwarding headers only from configured proxies, and cap/expire every limiter
  keyspace. Finally, users-core access JWTs carry no tenant claim, so the
  first-party auth-core bridge creates a tenantless principal that secure
  WebRTC correctly rejects. Add an issuer-controlled tenant model/claim or an
  explicit configured single-tenant binding adapter; never derive tenant from
  untrusted client input.
- The fourth exact cross-audit at clean rvoip revision
  `82d414235c1020a59664cc6bf45d6ebb961a3554` remains nonzero after the third
  remediation. The combined selected library suite is green at that revision
  (including 300 rvoip-sip, 2,114 sip-core plus one ignored, 364 dialog, 120
  transport, 54 WebRTC, 34 UCTP, 24 registrar, 79 core, 39 auth-core, 24
  core-traits, and 6 client tests), but the independent audit found further
  release-blocking boundary and resource failures that those suites do not yet
  model.

  Outbound TLS and WSS pools/single-flight keys use only `SocketAddr`, so two
  authorities resolving to one address can reuse a connection authenticated
  for the wrong SNI; WSS also sends the socket address as `Host`. Key every
  route, pool, in-flight dial, and eviction by normalized authority, address,
  trust context, and direction, and derive the HTTP authority from the same
  authenticated identity. Extend one end-to-end deadline through connection
  registration, never await a writer/channel while holding the connection-map
  lock, and make failure single-flight share a bounded result/backoff rather
  than serialize a retry storm. Bound pending dial waiters/tasks before task
  creation and bound established inbound and outbound sockets/tasks/maps with
  authentication/idle deadlines and deterministic permit release. WebSocket
  sends and close still hold a shared writer lock across unbounded network
  writes, so a non-reading peer can prevent drain; move writes to an owned
  bounded/cancellable writer or enforce repeatable send/close deadlines. The
  public listener's sequential `accept()` still lets one slow upgrade consume
  each timeout interval; move concurrent upgrade supervision inside the public
  surface or deprecate it in favor of the bounded transport supervisor with an
  explicit migration.

  Clustered Digest remains unbounded: even rate-limit denial records a fresh
  Redis nonce, Redis admits unlimited nonce/cnonce keys, and nonce-count TTL is
  independent of the issued nonce lifetime, so captured proofs can become
  replayable while their nonce remains valid. Extend the shared replay-store
  contract with atomic bounded/fair nonce admission/reuse and an atomic
  active-nonce-plus-count update whose TTL covers the nonce's remaining valid
  and stale-retention window. Enforce tenant, user, nonce, and aggregate
  quotas. Local and registrar replay maps likewise need fair per-principal and
  per-nonce caps: one valid user must not fill the global 16,384-entry cnonce
  budget and deny every other identity. Preserve exact replay rejection within
  `(username, nonce, cnonce)`.

  Users-core API-key attenuation still has a logout hole: a read-only or empty
  key can revoke all interactive refresh sessions for its owner. Require an
  explicit revocation permission or reject API keys for that endpoint.
  Configured tenant identity must be checked by direct access-token validation,
  carried and checked through refresh tokens, and enforced before a token from
  another deployment sharing issuer/key can be exchanged into the local
  tenant. Public router embedding must require real peer metadata or expose a
  peer-aware make-service; it may not collapse missing `ConnectInfo` into one
  attacker-exhaustible `unknown` bucket. Limiter cleanup tasks must terminate
  when their owner is dropped. IPv6 identities must be normalized to a safe
  prefix, and capacity pressure must use bounded hashed/overflow buckets or
  safe low-volume eviction rather than globally rejecting every unseen real
  client after 16,384 rotating addresses.

  Finally, do not hide source breaks in patch releases. The new cnonce-aware
  replay contract needs an additive legacy adapter that fails closed until a
  store opts into client-aware replay, or an explicitly versioned breaking
  release and migration. Public users-core `UserClaims`, `JwtConfig`, and
  exhaustive rate-limit error changes likewise need compatible constructors/
  non-exhaustive boundaries or a coordinated semver-breaking version with
  migration evidence. These compatibility decisions must be executable and
  documented before the next exact-revision audit.
- The fifth exact audit at clean rvoip revision
  `c626879057066e6c043e511e639a8e19a64175e4` confirms that bounded connection
  internals are no longer sufficient while the layers above them collapse a
  secure flow back to one socket address. `WebSocketTransport` does not expose
  live-flow lookup to the standard multiplexer, so structured and cached raw
  WS/WSS responses can fall through to UDP instead of the inbound WebSocket.
  The resolver retains address and transport but discards the authenticated
  next-hop authority selected from Route/outbound-proxy/SRV, causing TLS/WSS
  SNI, HTTP Host, pool identity, and single-flight identity to be derived from
  the Request-URI callee rather than the actual proxy authority. Ingress,
  response/raw-send, pong, and close events likewise carry no opaque flow ID;
  their address-only fallback can select another authority/direction at the
  same address or fail every dialog sharing that address. Carry a normalized
  authority-bearing route and opaque flow ID end-to-end through resolver,
  transport events, transactions, cached responses, and lifecycle indexes.
  Require the exact flow for responses; reject ambiguous raw routing. Give
  lifecycle/control events reserved bounded delivery so media/message
  backpressure cannot erase teardown.

  Public WebSocket supervision has three remaining boundary defects. A peer
  Close changes writer state before `close()` can enqueue its close command,
  retaining admission until the write timeout; complete peer-initiated close
  promptly and prove permit release. One recoverable accept error currently
  returns from `serve_concurrent` and drops every active session; retry with
  bounded backoff while preserving children, and terminate only on shutdown or
  a fatal listener error. Finally, making the formerly functional public
  `accept()` always fail at runtime is not a patch-compatible migration. Either
  retain a supervised compatibility path or publish an explicit coordinated
  sip-transport 0.3 migration with release notes and replacement examples.
  Multiplexer-level WS/WSS request-to-structured-response, cached-response,
  multi-authority, close-event, and accept-recovery tests are required before
  another exact audit.
- The independent users-core and Digest replay cross-audit at the same clean
  rvoip revision (`c626879057066e6c043e511e639a8e19a64175e4`) is also nonzero:
  zero P0 and three P1 findings remain. `UsersCoreAuthProvider` compares the
  access-token tenant only when the bridge is configured with a tenant, so an
  unbound bridge accepts a tenant-bearing token even though the native JWT
  issuer enforces exact `Option` equality. Compare the tenant options
  unconditionally so tenant-bound and tenantless issuers cannot cross that
  boundary.

  The claimed additive `DigestReplayStore` compatibility layer changed the
  original `accept_nonce_count(username, nonce, cnonce, nonce_count)` method by
  removing `cnonce`; existing downstream implementations therefore stop
  compiling. Restore the exact legacy signature and make only the secure
  client-nonce-aware extensions additive and fail-closed until implemented.
  The Redis replay implementation also advertises clustered deployment and
  uses cluster-safe hash tags, but it owns a single-node `redis::Client` and
  lacks the async cluster feature. Hash-slot compatibility alone does not
  process `MOVED`, topology changes, or failover. Add a seed-based
  `ClusterClient` mode and exercise the replay Lua scripts against a real
  multi-node Redis Cluster before the next exact-revision audit.
- rvoip revision `388652d0fe51a2c4d9b7add067c6c81a0e2d124f` implements
  exact transport-flow routing and an explicit coordinated SIP transport and
  dialog 0.3 migration. Authority and opaque flow identity now cross RFC 3263
  resolution, request/response routing, transaction caches, and lifecycle
  teardown; TCP/TLS/WS/WSS connection supervision is bounded and flow-aware.
  At that revision, the full SIP transport suite (144 library tests plus all
  integrations), SIP dialog suite (372 library tests plus integrations and 172
  passing documentation tests), strict Clippy for both crates, proxy,
  registrar, SIP examples/binaries, formatting, and diff checks pass. A fresh
  exact-revision independent flow audit is still required before this evidence
  closes the fifth-audit findings.
- That independent flow audit at `388652d0` reports zero P0 and four remaining
  P1 code defects. Legacy multiplexer APIs still make address-only first-match
  choices and use synchronous `try_lock` flow probes; contention can fall
  through to UDP, and co-addressed TCP/TLS/WS flows can be selected by fixed
  priority instead of identity. Make flowless connection-oriented response and
  raw routing fail closed, remove `try_lock` from correctness decisions, and
  migrate every production caller to an explicit `TransportRoute`.

  The rvoip-sip symmetric REGISTER keepalive path still resolves only a socket
  address, starts an address-only ping, and later probes for a flow
  synchronously. It can miss the flow or ping another authority at the same
  address; retain the exact route returned by the REGISTER transaction and use
  it for keepalive, pong, and close correlation. Transport messages, pong, and
  close also share one bounded event lane. A saturated payload lane can delay
  teardown and retain sockets/permits indefinitely, so add independently
  reserved lifecycle/control capacity through transport and transaction
  dispatch and prove prompt delivery under saturation. Finally, TLS listener
  accept errors immediately reiterate; add bounded retry/backoff while keeping
  active sessions alive.

  Required evidence now includes live TLS and WSS exact structured/cached-raw
  response tests, end-to-end NAPTR/SRV/A authority-to-SNI/Host failover,
  adapter-level exact-flow REGISTER keepalive, saturated payload/control
  delivery, TLS accept-fault recovery, and co-addressed/lock-contention
  fail-closed routing. Address-only server-transaction facades remain a lower
  severity migration risk and should be removed from production call sites.
- The independent credential/replay audit of `07f387ff` (whose changes are
  included in `388652d0`) reports zero P0 and six P1 findings. First, the
  released 0.2 `DigestReplayStore::accept_nonce_count` signature was actually
  `(username, nonce, nonce_count)`; adding `cnonce` is still a patch-level
  source break, and the compatibility test merely reimplements the new shape.
  Restore the exact released method and keep the client-nonce-aware secure path
  in the additive default-fail-closed method already used by production SIP.
  Second, adding variants to the public exhaustive `RedisAuthError` in
  rvoip-redis 0.1.3 is also a source break; preserve exhaustiveness or perform
  an explicit semver migration.

  Third, listener Digest authentication and static CIDR/mTLS principals can
  remain tenantless even though `SipAdapter` requires a tenant, making the
  authenticated Bridgefu ingress unusable and leaving ownership ambiguous.
  Bind every listener policy to an explicit validated tenant and require that
  tenant on every admitted principal. Fourth, rvoip-redis enables asynchronous
  cluster support without a Redis TLS runtime feature, so `rediss://` cannot be
  used. Fifth, each auth operation constructs a new single-node socket or full
  cluster topology and has no bounded command deadline; cache the production
  connection/manager and configure finite connect, response, and retry bounds.
  Sixth, Redis rate limiting separates its read admission from later failure
  recording and keys only one attacker-controlled subject/realm/peer tuple, so
  concurrent or rotating guesses bypass it and create unbounded TTL keys. Use
  one atomic admission/reservation operation, a peer-level aggregate limit,
  bounded subject cohorts, and deterministic expiry/cardinality tests. Cluster
  qualification must fail rather than silently skip construction errors and
  must exercise redirection/topology change plus TLS/authenticated deployments.
- The remediation sequence through clean rvoip revision
  `caf1ac933c45c3ede26c65a96dfb05cb01e7b380` closes the previously recorded
  credential, Redis, and exact-flow implementation findings, adds a unified
  initial/auth-retry header append path, and introduces dormant retained SIP
  media binding. Live evidence includes 11 single-node Redis tests, six
  authenticated mTLS three-node cluster tests with untrusted-CA and real
  `MOVED` recovery, five auth provider contracts, 13 Redis unit tests, four
  tenant-bound SIP adapter tests, and the locked 3,216-test cross-crate suite
  (one ignored) spanning auth, client, core, SIP, UCTP, and WebRTC. This is
  regression evidence, not completion evidence: two independent audits at the
  same revision report zero P0 and 15 remaining P1 findings.

  One exact-flow/control-lane P1 also remains: every UDP parse error is routed
  onto the reserved control lane, but 100 ms of control backpressure causes the
  transport bridge loop to terminate permanently. A malformed-datagram flood
  can therefore stop all later valid UDP SIP until restart. Treat malformed
  packet diagnostics as bounded/drop-safe data, reserve the control lane for
  lifecycle correctness, and never terminate a healthy listener merely
  because an error notification cannot be delivered.

  The INVITE planner/retry audit reports eight P1s. A configured global
  outbound proxy is transient and disappears on authenticated retry, so a 407
  response can cause `Proxy-Authorization` to be sent toward the callee and can
  reuse a secure-hop credential decision on a plaintext reconstructed route.
  Top-Route resolution failure also falls back to the Request-URI address;
  this leaks callee DNS, fails proxy-only domains, and can bypass a failed
  security perimeter. REGISTER-learned Service-Route currently precedes the
  documented first outbound proxy. Preserve one authoritative ordered route
  plan through every retry and fail closed when its selected next hop cannot be
  resolved.

  Caller-provided SDP is replaced by regenerated local SDP after a challenge.
  RFC 3263 candidate failover clones one Via branch into multiple client
  transactions, allowing a late failed-candidate event to collide with the
  replacement. Rejected final headers occur after session/media/dialog/mapping
  allocation and have no rollback or setup timer. Sequential 407 then 401
  authentication has one global retry budget and drops the earlier protection
  space. Finally, a `sips:` Request-URI can be downgraded by a plaintext
  `sip:` Route because only the first Route drives transport security. Retain
  the exact original body, generate a fresh branch per candidate, validate
  before allocation with compensating rollback after any possible side
  effect, retain authorization per protection space/header kind, and require a
  TLS/WSS first hop for every SIPS request.

  The independent review of that remediation found five additional P1s before
  commit. Redirect handling could replay origin or precomputed credentials to
  a new Contact; credentials must retain an exact protection target and a 3xx
  target change must invalidate old-origin material while preserving only an
  unchanged proxy protection space. Candidate failover and the initial INVITE
  path also classified an error string containing `Transaction terminated` as
  success; only typed success or verified response state may suppress failover.
  Add redirect-to-new-origin credential canaries and a transport failure with
  that exact phrase followed by a successful second candidate.

  The 3xx and 422 paths bypassed the authoritative INVITE plan, losing proxy,
  body, From/Contact, 100rel, extras, or accumulated authorization across
  redirect/auth/session-timer chains. Every initial, 401/407, 3xx, and 422
  attempt must derive from one immutable snapshot; a redirect creates a new
  origin-scoped plan and a timer retry changes only timer fields. Several
  in-dialog INFO/NOTIFY/PRACK/BYE paths also resolved an exact top Route and
  then fell back to the remote target. They must fail closed or perform
  candidate failover only within that exact Route. Finally, persist a secure-
  dialog requirement from a dialog-forming SIPS request and reject plaintext
  Contact or Record-Route downgrade before mutating dialog state. Acceptance
  covers auth-to-422 and 422-to-auth through global/per-leg proxies, zero
  remote-target packets after an unreachable mandatory Route, unique branches
  with exact-route candidate failover, and TLS/WSS-only ACK/BYE/INFO/PRACK for
  SIPS dialogs.

  The review then found two more candidate-lifecycle P1s. The current helper
  exhausts only synchronous send failures and commits to the first enqueued
  transaction, so a pre-provisional Timer B/F timeout or retry-eligible `503`
  cannot advance to the next RFC 3263 candidate. Retain the candidate plan
  until a typed terminal outcome; retry only before any provisional response,
  within the overall deadline, and never during cancellation, drain, semantic
  auth/redirect/422 retry, or terminal dialog state. Each attempt gets a fresh
  branch and transaction, atomically replaces the canonical mapping, and
  retires late events. Transaction core currently discards or swallows a late
  2xx after Timer B and retains no authenticated route tombstone; therefore do
  not enable timeout failover until each superseded attempt retains bounded
  route/security/CSeq/branch state, a late 2xx is validated against that state,
  and the stack sends the required ACK followed by BYE without promoting the
  superseded dialog. Race this cleanup against CANCEL, drain, a winning
  candidate, and tombstone expiry. An eligible 503 retry may land first while
  retaining its old transaction for ACK, but it does not substitute for the
  Timer-B safety work. Test a black-holed first candidate and an eligible 503
  followed by a successful second candidate, delayed 2xx from every losing
  attempt, plus the provisional, cancellation, terminal, and expiry no-retry
  boundaries.

  Implement this with one bounded `InviteFailoverPlan` per logical dialog and
  INVITE CSeq plus a transaction-key attempt index. The plan retains the
  immutable unsigned request, remaining candidates, current attempt, exact
  signed request/route for every attempt, provisional state, monotonic outcome,
  and expiry; authentication, redirect, and 422 semantic retries start a new
  plan. Intercept typed transaction events before normal dialog delivery,
  serialize candidate advancement with CANCEL, and ensure an old terminated
  attempt can never remove the current mapping. Bounded transaction-core
  tombstones retain exact source/flow/authority and request route after timeout
  or supersession. A matching late 2xx is ACKed; a superseded, failed, or
  cancelled attempt also creates a response-derived fork only long enough to
  send BYE and never emits `CallAnswered`. A winning duplicate 2xx is re-ACKed
  only. Cap and expire live plans, attempt indexes, and late-response archives,
  expose their counts, and drain them without launching another candidate.

  The transaction-core implementation audit also confirmed that the old
  post-retirement path accepted a response carrying a forgeable transaction
  key after its route state had been removed, without revalidating the UDP
  tuple or exact stream flow; its ACK then used an address-only/default
  transport. Retired-attempt admission must authenticate the exact retained
  `TransportRoute` and every ACK must use that same route. Add correct/wrong
  UDP source, TLS/WS flow/authority, expiry, and exact-route ACK tests.

  rvoip revision `80a4b41d` lands that transaction-core prerequisite. Bounded
  90-second, 65,536-entry tombstones retain only the immutable INVITE request
  and exact route after a successfully sent client transaction retires;
  late-response admission revalidates the UDP tuple or exact stream flow, a
  valid late 2xx reaches the transaction user, and ACK uses the retained route.
  Expiry/prune, wrong-route rejection, success delivery, and exact ACK tests
  pass within the 387-test sip-dialog suite, with strict Clippy and rvoip-sip
  library check clean. This is not Timer-B failover: dialog-level attempt
  planning, 503 advancement, orphan ACK/BYE cleanup, and CANCEL races remain
  required before timeout retry can be enabled.

  rvoip revision `915bce0d` completes the retained dialog-level failover
  implementation. One capped/expiring plan and exact attempt index serialize
  503 and Timer-B advancement, current-attempt CANCEL, provisional/no-retry
  policy, duplicate selected 2xx re-ACK, and superseded late-2xx ACK-then-BYE
  cleanup. ACK failure blocks BYE and a retransmitted 2xx serially retries the
  cleanup; old terminal events cannot unlink the winner. Candidate and plan
  caps are atomic, maintenance is nonblocking, prune/drain reaches zero, and
  every attempt shares one immutable logical setup deadline. The 393-test
  sip-dialog library suite, 21 RFC 3263 tests, exact wrong-route tests, strict
  all-target/all-feature Clippy, concurrent CANCEL/timeout orders, and default-
  stack Digest reproduction pass. Timeout failover was enabled only after
  tombstone validation and orphan cleanup gates passed. An independent exact-
  revision cross-audit remains required before the P1 is closed.

  Candidate selection also changes the socket transport without stamping that
  transport and advertised sent-by into the request: a TCP candidate can carry
  a UDP Via and a stack-default UDP Contact. Materialize the selected route
  before lifecycle signing, regenerate stack-owned Via and default Contact per
  attempt, and preserve only a caller-explicit validated Contact. Packet tests
  must assert that actual transport, Via transport/sent-by, and default Contact
  agree for every UDP/TCP/TLS/WS/WSS candidate.

  rvoip revision `05091c8b` lands the safe planner checkpoint: one immutable
  initial INVITE plan across proxy/auth/redirect/422 paths, exact SDP/options,
  per-protection-space credentials, fresh candidate branches, pre-allocation
  validation/compensation, fail-closed exact next hops, persisted SIPS
  confidentiality, and candidate-specific Via/sent-by/default-Contact wire
  materialization. It passes 2,115 sip-core tests (one ignored), 385 dialog
  tests, 325 rvoip-sip tests, 11 RFC 3263 tests, and focused redirect,
  per-leg-proxy, 100rel, and chained 407→401→422→200 suites. The additive
  `CandidateWirePlan` API keeps the legacy failover wrapper; requiring a
  structured Via at finalization is retained as an explicit compatibility
  audit point. This checkpoint does not claim asynchronous 503/Timer-B or
  late-2xx safety; the retained-plan/tombstone work above remains open.

  Qualification exposed a default-stack failure: the retained initial-INVITE
  diff enlarged the finite `execute_action` poll frame to about 1.34 MiB and
  overflowed Tokio's default 2 MiB debug worker stack after the authenticated
  second INVITE. Revision `915bce0d` heap-pins the heavy state machine at the
  candidate-plan boundary. The exact tenant-bound Digest reproducer now passes
  on the default stack both locally and under independent revalidation with the
  adapter lifecycle diff. Keep default/release/long-churn stack evidence in the
  final combined qualification; no release candidate may regress to a hidden
  `RUST_MIN_STACK` dependency.

  The dormant-media/adapter audit reports six P1s. `SipAdapter::originate`
  still sends INVITE before durable activation, and its current activation
  starts media before event-stage admission can fail. `run_bind` can overwrite
  `Closing` with `Bound` or publish `Closed` before pumps are joined. Cache
  insertion races route retirement, bind singleflight does not verify that
  concurrent callers name the same coordinator/session, and a failed bind or
  later pump exit is only logged while signaling remains connected. Replace
  the separate context/stage maps with one retained `SipOutboundRoute`; make
  cache insertion/retirement atomic; bind to one immutable target; make close
  ownership and terminal state monotonic; and convert bind/pump failure into
  authoritative teardown. Add deterministic bind/close, mismatched-target,
  activation-failure, cache-retirement, pump-exit, and bounded-drain tests.

  rvoip revisions `884a27ad`, `a1a41fb8`, and `41649dbb` implement that
  retained-route/media-lifecycle remediation. They introduce one retained
  outbound route, dormant single-flight activation, actual wire Call-ID
  receipts, bounded FIFO staging, cancellation compensation, immutable bind
  targets, atomic cache retirement, and authoritative teardown on bind or pump
  failure. Incomplete driver shutdown remains truthfully `Closing` instead of
  publishing a false `Closed`. The rvoip-sip library suite passes 325 tests,
  including zero-wire prepare/end, 100 concurrent activators with one INVITE,
  cancelled waiters, backpressure, bind/close races, 100 bind callers, target
  mismatch, cache retirement, and media-failure teardown. Item 2b remains open
  until the shared INVITE planner work, complete capture-UAS qualification, and
  an independent exact-revision audit also pass.

  That independent retained-route review confirms two additional P1s. API
  translation resolves a Session ID and then terminal delivery re-looks up the
  route without holding one atomic mapping decision while cleanup can retire
  it concurrently. This can deliver a second terminal or forward Connected/
  progress after terminal. Make resolution, terminal claim, and retirement
  generation-aware and monotonic; add barriered CallEnded/CallAnswered versus
  local-end/media-cleanup races proving exactly one terminal and no later
  public event. Also replace permanent `retired_sessions` accumulation: at the
  default 262,144 entries it permanently poisons admission after about 7.3
  hours at 10 calls per second. Use bounded expiring/generation tombstones that
  still reject delayed events for the retired route, reclaim safely under
  steady churn, expose capacity/expiry metrics, and test delayed replay across
  reuse plus multi-hour equivalent churn without poisoning the worker.

  Fast terminal activation is also currently reported as success: after the
  staged FIFO observes a retained terminal, `run_outbound_activation` wakes
  waiters with a Call-ID receipt before cleanup makes the route non-live. A
  caller can therefore pass the core liveness check for a route already known
  terminal. Mark the route sticky non-live and complete activation as failure
  before waking any waiter. A barriered test with 100 concurrent activators
  must expose no receipt, deliver exactly one terminal, and retire every map,
  stream, and task.

  Adapter shutdown currently closes local streams but does not hang up or
  finalize active outbound SIP sessions when another owner retains the public
  coordinator. The media monitor treats `Closing` as normal and no cleanup
  supervisor takes network authority, leaving an orphaned dialog/session.
  Make the optional drain hook required for SIP: freeze admission, compensate
  each prepared/possible/sent route with the phase-appropriate no-wire/CANCEL/
  BYE action, join route/media/translator tasks, and report incomplete drain.
  `Drop` remains best-effort only. A retained-coordinator capture-UAS test must
  drop/drain the adapter and observe required CANCEL/BYE plus zero sessions,
  audio receivers, transactions, routes, and tasks.

  rvoip revision `3ca4644d` remediates the independent retained-route findings.
  Paired maps carry exact generations and terminal enqueue/retirement is
  linearized; a fast terminal marks the route non-live and fails every
  activation waiter before any receipt; bounded TTL/order tombstones replace
  permanent admission poisoning; and retained production tasks participate in
  public async drain/shutdown with phase-aware compensation. The rvoip-sip
  library suite passes 328 tests, including 100-waiter fast terminal, stale-
  generation churn, explicit drain/join/zero-wire cases, lifecycle/auth/audio,
  and the default-stack Digest reproducer. Full-package mTLS timeout,
  auto-emit redaction, and two B2BUA carry-through failures reproduce at clean
  pre-change revision `5ad5ffe1`; they remain baseline qualification debt, not
  evidence against this slice. Item 2b still needs capture-UAS coverage and an
  independent audit on the exact combined revision.

  The clean-baseline failures are now precisely classified. Verified mTLS
  reaches the TLS listener but times out waiting for the authenticated adapter
  handoff after the anonymous/untrusted negatives complete; diagnose the
  principal/observation race and add a bounded positive handoff test. The
  legacy BYE auto-emit and one B2BUA carry-through test assert secret values by
  reading the intentionally redacted trace (`X-AutoEmit`, History-Info,
  Diversion, PAI, and X-Customer-ID). Preserve redaction and replace those
  assertions with a capture socket/UAS that inspects actual wire bytes. The
  other B2BUA case produces no staged PAI where exactly one is expected and
  requires a product-path diagnosis rather than an observation rewrite. These
  four exact tests must pass honestly before item 2e or Gate 3 closes.

  Lower findings to close with these P1s include dialog-layer rejection of
  stack-owned Via/Route/Record-Route extras, semantic routing for structured
  `Other` Route values, singleton `Session-Expires`/`Min-SE`, lossless Contact
  handling, validation before CSeq/tag/DNS mutation, honoring
  `with_supported_100rel`, and eliminating the remaining address-only
  server-transaction facade call sites.
- The independent credential/replay re-audit at committed rvoip baseline
  `8baa81f3` reports zero P0 and one remaining P1. Rate admission happens
  before SIP credential parsing, and every normal unauthenticated Digest
  challenge has no subject. Redis maps that absent dimension to one shared
  `subject=_` cohort and retains `MissingCredential` as a failure, so ten
  ordinary initial challenges exhaust a tenant-wide cohort for the default
  60-second window. Bind an unknown subject to the known peer (and an unknown
  peer to a bounded subject cohort), or omit that aggregate until the dimension
  is known; give protocol-normal challenge issuance an explicit per-peer
  budget. Add missing-subject, missing-peer, distributed-concurrency, and
  recovery tests. The re-audit otherwise confirms released Digest trait source
  compatibility, Redis error-enum compatibility, tenant-bound listener
  principals, verified Redis TLS/cluster behavior, cached bounded connections,
  and atomic/cardinality-bounded admission.
- rvoip revision `ea77dde5` remediates that P1 with a distinct
  `SipChallenge` admission kind, a configurable per-peer challenge budget,
  missing-subject cohorts bound to the known peer, missing-peer cohorts bound
  to the known subject, fail-closed handling when both are absent, realm-
  independent grouping, and versioned stable Redis key/kind tags. Auth-core
  passes 115 tests, rvoip-redis passes 13 unit and 12 live Redis 7.2 tests, SIP
  auth passes 48 tests, and strict auth-core/rvoip-redis all-target Clippy is
  clean. Its first implementation added the challenge budget as a new public
  `RedisAuthConfig` field, which breaks released exhaustive struct literals;
  move that setting to private provider state with an additive builder before
  qualification.
- rvoip revision `e982e36b` completes that compatibility follow-up. The public
  `RedisAuthConfig` field set is restored exactly, an external-crate exhaustive
  struct-literal sentinel compiles, and the challenge setting is private
  provider state with an additive builder/getter. Redis passes 13 unit, 12 live
  single-node, and seven password-authenticated mTLS three-primary cluster
  tests, including distributed missing-dimension isolation, real MOVED
  handling, recovery, and wrong-CA rejection. Strict rvoip-redis all-target
  Clippy and the enterprise example are clean. Only the independent combined-
  revision audit remains before this finding can close.
- Exact combined-revision qualification at rvoip `3ca4644d` passes 2,115
  sip-core tests (one ignored), 393 sip-dialog tests, 21 retained failover
  tests, 328 rvoip-sip library tests, the default-stack tenant-bound Digest
  handoff, and 69 all-feature Amazon Connect tests. A workspace-wide strict
  all-feature Clippy invocation remains unusable as release evidence because
  it enters the unrelated legacy G.729 implementation and fails on 993
  pre-existing pedantic lints; qualification uses scoped `--no-deps` strict
  linting and records that workspace debt separately rather than weakening the
  lint boundary.
- The independent auth/adapter re-audit at `3ca4644d` reports zero P0 and four
  P1s. Challenge-budget denial still calls `rejected_async`, minting and
  persisting a fresh nonce while discarding `retry_after`; this is now the
  explicit Gate 3 checklist item above. A failed adapter drain removes route
  ownership before reporting compensation failure, allowing a second drain to
  return a false success. A post-terminal activation can fall through to a
  previously cached successful receipt. Cancellation of the sole public media
  constructor/bind owner after its detached driver is spawned can leak the
  driver and subscription. These three adapter/media findings are mandatory
  2b closures with deterministic failure/race tests.
- The independent retained-planner audit at the same revision reports zero P0
  and six P1s. Its 90-second retained plans share the active-dialog capacity,
  so the real capacity=100 configuration can reject healthy 10-CPS traffic
  after roughly 51 seconds. Manager stop is a sleep-and-clear operation rather
  than a latched joined drain. External pre-send/send/post-send awaits hold the
  plan mutex and can starve deadline, CANCEL, and shutdown. Prune, registration,
  and event advancement do not share one generation-atomic ownership decision.
  Client retirement briefly removes its route before publishing a tombstone,
  authenticates the response twice, and can lose an exact stream flow. Finally,
  performance/soak snapshots omit planner and retired-transaction ownership and
  can report a false zero before the 90-second TTL expires. Item 2e now lists
  the ordered remediation and acceptance races. No Gate 3 or SIP item is closed
  solely from the green pre-audit suite.
- rvoip revision `0eaebd68` closes the challenge-budget P1 without changing
  the released exhaustive auth-decision enums. A crate-private richer
  evaluation retains the limiter hint, performs no nonce, credential,
  challenge, audit, or completion-provider work after denial, and projects an
  empty rejection for legacy callers. The listener emits `503` with a typed,
  ceiling-rounded `Retry-After` clamped to 1–3,600 seconds and no auth header.
  Counting-provider unit tests, normal challenge regressions, tenant-bound
  Digest, and a real UDP wire test pass.
- rvoip revision `3d6b321e` removes redacted trace output from the three
  header-propagation baseline assertions. A raw UDP capture UAS now verifies
  the legacy BYE auto-emit value and both synthetic and real B2BUA INVITE
  carry-through values on actual datagrams; semantic PAI lookup accepts its
  canonical typed header name. All three exact tests pass while production
  trace redaction remains unchanged. The verified-mTLS adapter handoff is the
  sole remaining test in the original four-test baseline failure set.
- rvoip revision `4118681f` closes retained-planner findings A–D. Active plan
  reservations are independent from bounded tombstone retention; manager
  lifecycle is latched and joins its dispatch workers; attempt I/O no longer
  holds the plan mutex and is generation/deadline/cancel/drain guarded; and
  registration, prune, and captured-event advancement use one atomic ownership
  decision. Deterministic blocked pre/send/post-send, concurrent registration,
  prune, abort, and stop tests pass, followed by 400/400 sip-dialog library
  tests and the full package unit/integration/documentation suite.
- rvoip revision `f5ff5c1a` closes planner diagnostic finding F. All five
  planner counters and retired client transactions are present in runtime/perf
  snapshots, live ownership is separated from expected tombstones, and soak
  drain evidence spans the 90-second retention horizon. The exact snapshot and
  two retention performance tests pass.
- rvoip revision `e3b596b6` closes the three adapter/media re-audit findings.
  The first destructive drain failure is sticky, terminal/draining routes
  return a typed activation error instead of replaying a cached receipt, and
  dropping the final public `SipMediaStream` owner signals and aborts an
  in-flight driver. Focused real cleanup plus 100-caller/100-driver churn tests
  pass. The retired-client exact-route transition P1 remains open before
  combined qualification; the verified-SIPS stack finding is closed below.
- rvoip revision `e8d99a5a` closes the last original baseline failure and its
  masked product defect. The verified mTLS fixture now advertises a SIPS
  Contact and retains rejected-client transport receivers deterministically.
  LLDB localized the subsequent default-stack abort to a 79-frame nested async
  response path, not recursion or the INVITE planner. `SendSIPResponse` now
  owns and awaits a fresh-stack task, aborts that task if its parent is
  cancelled, and maps join/panic failure to one fixed error class. The exact
  default 2 MiB and 16 MiB mTLS/SIPS tests, trusted-CIDR, Digest, all five
  listener fixtures, 335 rvoip-sip library tests, and the combined 403-test
  sip-dialog library tree pass. All four clean-baseline qualification failures
  are therefore closed without weakening trace redaction or requiring a hidden
  `RUST_MIN_STACK` setting.
- Follow-up default-stack qualification on 2026-07-14 found one separate
  inbound entrypoint that still awaited the first signaling state-machine
  transition inside the transport/dialog/session poll chain. The inbound
  handler now awaits the existing cancellation-safe fresh-task seam, preserving
  per-shard ordering and exact state-machine error propagation while allowing
  the parent poll chain to unwind. A raw-UDP fast-auto-accept regression runs
  the complete inbound listener path on an explicitly configured 2 MiB Tokio
  worker stack and passes with `RUST_MIN_STACK` absent. Both hermetic
  StandardCharter teardown directions now use the same explicit 2 MiB runtime;
  their exact tests pass independently, the full locked
  `standardcharter_contract` binary passes 59/59 tests, and the focused SIP
  teardown/header/state-table matrix passes 23/23 tests. The raw peer in the
  rvoip regression deliberately excludes the separate UAC response path so the
  evidence measures the corrected inbound boundary directly.

Historical local exit: the generic SIP/WebRTC adapter directions pass the
listed real localhost media tests and the frozen StandardCharter SIP contract
remains unchanged. This is not evidence for a stock Vapi browser transfer, a
direct Bridgefu widget, API-level leg replacement, or the complete destination
matrix. Product release status is governed by VF-0 through VF-7 in addition to
the protected Vapi/AWS run and owner-reviewed deployed NAT/TURN evidence.

### Gate 8 — Complete provider control and media (`pending`)

- [x] Replace Bridgefu's hand-written Telnyx HTTP models and Ed25519 verifier
  with exact crates.io dependency `telnyx = "=0.1.0"`; keep Bridgefu-owned tenant,
  call, leg, idempotency, deadline, redaction, and reconciliation policy.
- [x] Replace provider methods that rely on SDK-generated command IDs with
  Bridgefu-owned command envelopes. Originate, bridge, transfer, hangup, and
  DTMF each receive the exact durable outbox/effect ID as their Telnyx
  `command_id`; retries reuse that ID and a different logical operation can
  never reuse it.
- [x] Complete Telnyx originate, native bridge, transfer, hangup, DTMF,
  capability discovery, webhook verification, and typed event normalization.
- [x] Build the SDK client with the configured base URL, explicit request
  timeout, reviewed retry policy, and webhook public key. Verify the exact raw
  request body with `telnyx::webhooks::Verifier`, retain unknown event payloads
  for forward compatibility, and never log credentials or raw call metadata.
- [x] Connect Telnyx media to unique, hidden, two-minute Bridgefu SIP attachment
  URIs authenticated with the configured tenant-bound Digest principal. Issue
  the linked destination Dial only after the primary media reference is
  durably bound, with a distinct effect ID, `link_to`, and
  `bridge_on_answer=true`.
- [x] Persist webhook deduplication, provider references, exact command IDs,
  callback reconciliation, and request idempotency; enforce deadlines,
  bounded SDK retries, redacted diagnostics, and safe retry classification.
- [x] Add the runtime circuit breaker and prove its open/half-open/recovery
  behavior against deterministic outage injection.
- [x] Reject new Twilio/Vonage provider legs with an explicit deferred
  capability error while preserving safe reads of existing persisted enums.
- [x] Pass deterministic SDK-backed Telnyx mock contracts for all mutations,
  exact retry bodies, timeouts, 429/5xx exhaustion, invalid signatures,
  connection binding, duplicate events, and role-aware repository restart
  behavior.
- [ ] Pass the restricted Telnyx live test-account control/media workflow.

Gate 8 implementation evidence recorded on 2026-07-13:

- `ProviderLegExecutor` is additive and defaults to a fail-closed disabled
  implementation. The Telnyx registry implementation reconstructs the hidden
  media token only inside the owned `StartLeg` effect and sends the token to
  Telnyx as the SIP user; no raw token is persisted or returned by the API.
- The durable call engine emits `ConnectProviderDestination` only after the
  media Dial reference commits. Media and destination references use explicit
  roles and coexist under schema version 7; SQLite and PostgreSQL migrations
  preserve legacy references as `media`.
- Transfer, hangup, and DTMF target the primary media reference. A Telnyx
  logical leg cannot become connected from SIP signaling or `call.answered`;
  it requires both the exact current SIP attachment binding and the verified
  `call.bridged` callback.
- `cargo test --test repository_conformance` passes 21 tests and
  `cargo test --test call_service_repository_conformance` passes 5 tests,
  including memory/SQLite/PostgreSQL role-aware restart and migration coverage.
- `cargo test --lib` passes 148 tests and `cargo test --bin bridgefu` passes 68
  tests, including the two-Dial executor, webhook profile isolation, retry,
  redaction, attachment-purpose, bridged-state, and circuit-breaker contracts.
- The Telnyx circuit breaker opens after bounded retryable failures, rejects
  without touching the network, admits exactly one half-open probe, ignores
  stale completions by generation, and exports transition/rejection metrics.
  Its deterministic 503/open/half-open/recovery test passes.
- The production `worker` role now constructs the configured tenant-bound
  attachment-principal resolver and `ProviderRegistry`, then installs the call
  execution supervisor with that provider executor. The compatibility helper
  used by isolated worker tests remains fail-closed with the disabled executor;
  all four `process_role::tests` pass after the production wiring change.
- The restricted live workflow remains release-blocking. No provider call was
  placed and no credential was read as part of this implementation pass.

Exit: Telnyx passes control, media, security, retry, and outage scenarios using
the published SDK; Twilio and Vonage are represented consistently as deferred.

### Gate 9 — Make broadcasts operational (`pending`)

- [x] Attach UCTP and MOQT to any connected source without competing for its
  receiver.
  - [x] Add `ManagedBroadcastService`, which accepts a real rvoip
    `ConnectionId`, reuses `Orchestrator::media_graph_for_connection`, exposes
    UCTP through `register_virtual_publisher_with_codec` using canonical Opus
    48 kHz mono, and adds MOQT as a managed graph sink. The legacy virtual-
    publisher API remains a compatibility wrapper. Focused tests prove PCMU
    and PCMA sources produce payload type 111 Opus with wrap-safe 960-tick
    timestamps, same-codec sinks share one transcode group, UCTP and MOQT share
    one source graph, and both close their exact routes/registrations.
  - [x] Resolve a durable API `source_leg_id` through `CallService` to its
    tenant-owned, call-pinned, currently connected binding and exact fenced
    worker. The opaque `ConnectionId` is passed only to the colocated managed
    media runtime; the durable API has no legacy Amazon-media fallback.
- [x] Expose real authenticated subscriber endpoints and enforce token expiry.
  - [x] Replace ad-hoc API JWT creation with a strict shared
    `BroadcastTokenService`: fixed HS256, issuer, audience, contract version,
    bounded size/TTL, exact tenant/broadcast scope, active-grant revocation,
    credential ID, and expiry metadata.
  - [x] Add a single-use UCTP `SessionBindingResolver` and a transport-level
    receive-only scope. The coordinator rejects `sendonly`/`sendrecv` offers
    before connection state or media allocation and rechecks principal expiry
    on every command.
  - [x] Install the shared validator plus the Redis-projected active-grant and
    durable session-lease authorities into both standalone
    `RvoipMoqRelayAdmission` subscriber listeners. Raw QUIC and WebTransport
    use the same fail-closed token, replay, ownership, quota, expiry, and
    revocation policy.
  - [x] Install the shared validator/resolver into a real public UCTP/QUIC
    listener. `all-in-one` binds an explicit TLS/UDP endpoint on the exact
    managed-media Orchestrator and drains it on shutdown. The later Gate 10
    implementation adds the authenticated split gateway-to-pinned-worker edge;
    this checkpoint describes only the earlier standalone listener evidence.
- [x] Publish audio/catalog and optional sanitized event tracks.
  - [x] Attach the existing rvoip-moq LOC Opus audio and MSF catalog publisher
    through the managed source path, with optional external-relay publication.
  - [x] Surface opt-in sanitized-event configuration and event submission from
    the durable call engine.
- [x] Track publication, negotiated version, relay path, reconnect, listener,
  drop, and cleanup state.
  - [x] Add a serializable managed diagnostic snapshot containing endpoint,
    protocol tuple, relay path, lifecycle, health, active listeners, graph and
    route state, queue depth/capacity, drops, evictions, transcodes, and expiry.
    Exact-generation grants and managed routes are revoked on explicit close,
    expiry, and Drop fallback.
  - [x] Retain managed handles in the durable API, build GET responses from
    their current descriptors, merge sanitized managed snapshots into the
    authenticated diagnostics response, and await exact close/revocation on
    DELETE.
- [x] Enforce 1,000 direct UCTP listeners per worker.
  - [x] Bound the managed UCTP profile and diagnostics to a maximum configured
    capacity of 1,000.
  - [x] Make subscription admission atomic at the shared Orchestrator handler
    and reject listener 1,001. One physical Connection holds one permit across
    all its routes and every ingress handler sharing that Orchestrator.
  - [x] Configure the clustered public gateway and worker path for at least
    1,000 direct listeners. The shipped profile permits 2,000 active routes,
    1,200 routes on one gateway-to-worker peer, and 2,000 public UCTP
    connections; rendered-profile validation prevents regression below the
    1,000-listener floor.
- [ ] Route fanout above the direct-listener ceiling through the production
  MOQT relay topology. The relay runtime is present, but arbitrary dynamic
  namespace activation remains owner-review-gated on the pinned moq-rs fork.

Gate 9 canonical broadcast-codec evidence recorded on 2026-07-14:

- The explicit-target-codec rvoip virtual-publisher suite passes 5/5. It proves
  PCMU and PCMA to canonical Opus publication, one source receiver, codec-group
  reuse, one group transcode per source frame, and wrap-safe 20 ms RTP timestamp
  continuity. Bridgefu's managed-broadcast shape suite passes 9/9 and proves
  the production UCTP descriptors and packets advertise Opus payload type 111
  for both G.711 source codecs. The exact rvoip command is
  `cargo test -p rvoip-core --test virtual_publisher`; Bridgefu uses
  `cargo test --lib broadcast::managed::shape_tests -- --nocapture`.

Gate 9 implementation evidence recorded on 2026-07-13:

- `cargo test -p rvoip-uctp --test coordinator receive_only_credential`
  passes both rejection-before-state and valid `recvonly` setup cases.
- Focused rvoip-quic and rvoip-webtransport tests prove an outbound-only
  (`recvonly` on the wire) binding drops peer-supplied datagrams before ingress
  delivery or publisher fanout.
- `cargo test --lib broadcast::token::tests` passes five strict algorithm,
  TTL/ownership, revocation, exact-session, single-use replay, and
  cross-transport tests.
- The focused `uctp_and_moq_share_one_real_source_and_cleanup_exactly` test
  passes, including concurrent idempotent close and exact publisher/route/grant
  cleanup.
- The focused `managed_expiry_revokes_grant_and_closes_route` test proves an
  expired publication revokes admission and removes its exact media route
  without requiring an API cleanup request.
- `cargo check --bin bridgefu` passes after the API token/grant integration.

Gate 9 durable API integration evidence recorded on 2026-07-14:

- `broadcast_source_resolution_requires_exact_owned_connected_binding_and_worker`
  proves exact tenant, call, leg, current binding, connection redaction, and
  worker-fence enforcement at the authoritative service boundary.
- `durable_broadcast_rejects_invalid_foreign_disconnected_and_stale_sources`
  proves malformed identifiers, foreign legs, disconnected legs, missing
  runtimes, and stale process-local routes fail closed without a grant or
  retained publication.
- `durable_broadcasts_share_real_source_and_cleanup_managed_state` proves two
  durable API publications consume one real Orchestrator source graph, expose
  live sanitized diagnostics, never serialize the source `ConnectionId`, and
  remove exact publisher registrations and grants on DELETE.
- `broadcast_crud_and_tokens_are_hidden_from_other_tenants` proves GET, token,
  and DELETE ownership isolation plus immediate token revocation. At this dated
  checkpoint the rvoip virtual-publisher suite passed 3/3, including a
  compile-time regression proving its setup future is `Send`; no blocking-thread
  shim is used. The later canonical-codec additions bring the current suite to
  5/5 as recorded below.

Gate 9 public UCTP and admission evidence recorded on 2026-07-14:

- `PublicUctpBroadcastListener` now owns a real raw-QUIC endpoint, PEM TLS
  loading, ALPN dispatch, bounded connection admission, drain, and shutdown.
  Installation forcibly replaces caller-supplied bearer, Session resolver,
  subscription handler, and Orchestrator authority so a permissive prebuilt
  transport configuration cannot bypass Bridgefu policy.
- The listener's two real-network tests prove that an invalid credential is
  rejected despite a permissive injected stub, a valid short-lived Bridgefu
  token binds once, replay is rejected, active-grant revocation closes the
  bound peer, and a dedicated ephemeral PEM endpoint drains cleanly. The token
  authority suite passes 6/6, including non-consuming authorization checks for
  an already-bound Session after the single-use attachment is consumed.
- rvoip reauthorizes bound Sessions on every command and with a 250 ms raw-QUIC
  and WebTransport lifetime guard. Principal expiry, tenant/broadcast mismatch,
  inactive grants, and revocation fail closed; the common peer supervisor then
  releases tasks, routes, streams, and direct-listener capacity.
- Direct-listener permits are atomic and Orchestrator-wide. An eight-test
  handler suite proves full-batch rollback, concurrency across handler
  instances, one permit across multiple routes, exact unsubscribe/session/
  connection/publisher cleanup, publisher-close versus in-flight-admission
  serialization, and an explicit 1,001st-listener `429` without route
  insertion. The complete UCTP state suite passes its focused matrix, and the
  current rvoip virtual-publisher suite passes 5/5 with exact route/permit
  cleanup on close plus canonical codec grouping.
- `broadcast.uctp_listener` is schema-validated and explicit about bind address,
  TLS certificate chain/private key, connection cap, token authority, and
  advertised `uctp+quic` endpoint. Its two config tests, the configuration
  schema checker, and `cargo check --bin bridgefu` pass. This paragraph records
  the standalone wiring checkpoint; Gate 10 subsequently completes clustered
  authenticated forwarding and independent listener ownership.

Gate 9 sanitized-event evidence recorded on 2026-07-14:

- MOQT event tracks are disabled unless both the tenant policy and the
  individual broadcast request opt in. UCTP rejects event-track requests, and
  the default catalog remains audio-only.
- Event admission resolves the exact live source Connection, tenant, call,
  leg, and worker fence before accepting a `bridgefu.context.v1` message. It
  rejects identifier overrides, replay, NUL/control/CRLF content, oversized
  fields, unsupported reliability, and rate/queue overflow; only fixed event
  kinds plus a trusted receive timestamp are published.
- Publication state, queue depth, drops, authorization, and exact route cleanup
  are included in managed diagnostics without retaining raw context. The
  sanitizer passes 3/3 tests, managed broadcasts 6/6, context boundaries 9/9,
  configuration policy 1/1, the API security/lifecycle path 1/1, and the
  rvoip-moq sanitized-event suite 9/9. Schema validation and scoped strict
  Clippy also pass.

Gate 9/11 broadcast-load harness evidence recorded on 2026-07-14:

- `tests/qualification_uctp_fanout.rs` is an ignored, opt-in harness for the
  real bounded `UctpBroadcastPublisher` target fanout. Its immutable release
  profile is 1,000 direct targets for one hour; it records aggregate delivery,
  drops, p95 queue latency, capacity rejection, and post-warmup RSS without
  retaining subscriber identifiers. A 16-listener, three-second local smoke
  delivered 2,464/2,464 frames with zero source or publisher drops, a
  400-microsecond p95 upper bound, verified rejection beyond the configured
  1,000-listener capacity, and 0.64 percent post-warmup RSS growth. This
  validates the harness and publisher
  fanout only, not 1,000 QUIC handshakes or RTP datagram paths.
- `tests/qualification_uctp_network.rs` is the complementary ignored,
  end-to-end raw-QUIC harness. It creates one unique Bridgefu token and
  receive-only UCTP Session/Connection per listener through the real
  `PublicUctpBroadcastListener`, resolves the exact broadcast grant, subscribes
  through the Orchestrator, and consumes a MediaGraph-backed virtual publisher.
  It parses every received datagram as an eight-byte UCTP 0.2 header plus a
  complete RTP packet, refreshes expiring credentials during release runs, and
  verifies unsubscribe, ConnectionEnd, route, registration, permit, and peer
  cleanup. Its immutable release profile is 1,000 real QUIC listeners for one
  hour at a 100-attempt/s setup rate. A four-listener, three-second local smoke
  delivered 612/612 complete RTP datagrams from 153 source frames with no
  invalid packets, discontinuities, unmatched timestamps, protocol errors, or
  retained resources and a 7.3 ms aggregate p95 latency upper bound. The smoke
  used a three-second initial credential, six-second replacements, and
  one-second refreshes; completed 20 real wire refreshes; rotated replay IDs
  without changing ownership; and rejected second-peer attachment first with
  the original credential and then with a current refreshed credential after
  the initial reservation expired. The original peers remained active for the
  measured media. This validates the local authenticated network harness only;
  the one-hour and deployed-network evidence remain open.
- Broadcast token refresh now rotates the JWT replay ID while retaining a
  stable credential lineage for UCTP Session ownership. Refresh also extends
  only the already-consumed exact Session reservation, preventing the refreshed
  token from attaching a second peer when the original token expires. A focused
  unit test covers owner continuity, replay-ID rotation, and post-expiry replay
  rejection.
- `tests/qualification_moq_relay.rs` is an ignored, opt-in real-network
  draft-19 harness. It uses distinct publisher-mTLS and subscriber raw-QUIC
  listeners over a role-separated embedded relay topology; every simulated
  listener is a real authenticated `MoqAudioSubscriber` session. rvoip now
  validates the MSF catalog before subscribing `audio/main` on that same
  session, exposes bounded rvoip-owned LOC events/snapshots, and shares the
  existing credential, reconnect, and drain lifecycle. Focused real-relay tests
  pass over raw QUIC and WebTransport without a moq-rs fork change. Its
  immutable release profile remains 10,000 listeners for one hour. A
  four-listener, three-second local raw-QUIC smoke brought all four sessions
  live with no reconnects, admitted and produced 151/151 origin audio objects,
  delivered all 151 to every listener (604 receipt/latency samples), observed
  zero receiver lag or unmatched timestamps, measured 10 ms p95 and 16 ms
  maximum source-admission-to-receiver latency, observed zero reconnect or
  cleanup errors and 0.66 percent post-warmup RSS growth, retained healthy relay
  snapshots, and shut down cleanly. A separately deployed relay-tier smoke also
  remains open. Neither local smoke completes a Gate 11 checkbox.

Local exit: a normal call, UCTP, and MOQT consume one source simultaneously and
their lifecycle/security tests pass. Production fanout above the direct UCTP
ceiling remains open until the dynamic MOQT publisher-policy candidate is
owner-reviewed, pinned, enabled, and requalified.

### Gate 10 — Operations, containers, and clouds (`pending`)

- [x] Make all process modes executable with dependency-aware health and drain.
  - [x] Type `runtime.mode`, preserve `all-in-one` as the compatibility default,
    and make the split durable worker own a real call-service runtime, rvoip
    execution supervisor, dependency-aware readiness, and bounded drain without
    binding public signaling or control routes.
  - [x] Add an executable `gateway` lifecycle shell and explicit concrete-edge
    dependency seam. The shell owns operational health, pauses bounded
    admission whenever the dependency is not healthy, permanently closes
    admission before drain, waits for admitted setup work, and drains the edge
    plus health server against one deadline. Main dispatch cannot fall back to
    `all-in-one`.
  - [x] Make the split gateway own the authenticated/versioned HTTP call API,
    provider capabilities, and signature-verified provider webhooks through a
    transport-free `CallControlRuntime`. It opens the shared PostgreSQL/Redis
    authority, selects already-registered workers, and projects existing
    durable commands without registering a worker, constructing an
    Orchestrator, or consuming worker work. Its supervised projector pauses
    readiness after persistent failures and joins during drain. Broadcast
    CRUD and token requests now use the durable worker-command path described
    below; transports without a safe public subscriber topology still return
    an explicit capability error. Public
    `/v1` and provider-webhook routes bind only `api.http_bind`; health and
    metrics remain isolated on `observability.http_bind`. Non-loopback public
    binds fail closed without `api.tls`; the runtime terminates HTTPS with
    rustls and drains admitted requests against the configured shared deadline.
  - [x] Add the private authenticated UCTP gateway-to-worker forwarding adapter
    and install it as the concrete gateway edge and worker listener. The edge
    uses mutually authenticated QUIC plus short-lived tenant- and
    worker-bound JWTs, exact call/leg routes, complete UCTP 0.2 RTP datagrams,
    reliable byte-exact RTCP carriage, bounded queues and admissions, immutable
    call-to-worker pinning, dependency health, and drain/cleanup semantics.
  - [x] Add the fail-closed private egress command protocol over that existing
    mTLS UCTP 0.2 route. It defines bounded reliable prepare/activate/abort/end,
    DTMF, DataMessage, response, and lifecycle envelopes; checks the physical
    route's exact worker fence, tenant, call, source leg, and attachment
    generation plus the requested destination generation; rejects expired or
    digest-conflicting command IDs; serializes transitions per destination;
    ends matching egress state on source cleanup; and blocks its reserved
    labels at every public data boundary. Focused state-machine tests and a
    real authenticated UCTP interception round trip are required evidence.
  - [x] Complete executable local split SIP/WSS egress. Initial and replacement
    execution add destination-owned worker Connections/MediaStreams over
    additional authenticated UCTP streams with exact private-egress session
    admission, worker SIP/WebRTC proxy adapters, gateway signaling/media
    handlers, durable progress/terminal reconciliation, and Redis-backed
    production state/replay seams. The generation-bound
    `StartLegReplacement`/abort/compensation path, exact terminal ACK ordering,
    source-loss fallback, and awaited private End/Abort drain cleanup pass the
    hermetic full-topology test. Process-level Redis restart, non-loopback
    real-peer, TURN/NAT, cloud, load, and chaos qualification remain required
    before advertising split `sip_egress` or `webrtc_egress` as release-ready.
  - [x] Wire authenticated native SIP/RTP, WSS, and WHIP/WHEP production
    listeners on the split gateway without constructing a durable worker. A transport-only
    rvoip Orchestrator resolves the exact principal-bound Request-URI,
    WebSocket-subprotocol, or WHIP/WHEP-path attachment, lets only the pinned
    worker consume it over private mTLS UCTP 0.2, and forwards complete RTP,
    DataMessages, and typed DTMF through bounded routes. Native listeners share
    gateway admission, readiness, and ordered drain. WSS/WHIPS reuse the
    reviewed `api.tls` identity; non-loopback plaintext WebRTC fails preflight.
    Bridgefu exposes optional generic and Telnyx Digest credentials to the SIP
    listener; they can merge only under one realm with distinct usernames.
    The configured API Bearer principal is rejected on cleartext SIP UDP/TCP by
    default and requires the explicit
    `generic_bridge.sip.allow_cleartext_bearer` opt-in. Bridgefu now projects
    referenced Vapi-profile CIDRs and transport-verified mTLS leaf
    fingerprints into rvoip's tenant-bound listener policy in both all-in-one
    and gateway modes. Cross-tenant, overlapping-CIDR, duplicate-fingerprint,
    and CA-without-leaf-identity configurations fail closed.
    Focused configuration and role tests prove the false default, explicit
    opt-in, generic/Telnyx realm and username disambiguation, cleartext Bearer
    rejection, and preflight rejection when no usable SIP mechanism exists.
    RTCP is deliberately hop-by-hop: transcoding/repacketization may rewrite
    packet identity, so raw forwarding is not generally correct. A future
    rvoip translated-feedback/diagnostic seam may expose raw packets only when
    SSRC/sequence/timestamp identity is preserved.
    The native and public-UCTP attachment paths now resolve the public audio
    stream before consuming the single-use worker proof and offer exactly one
    canonical private codec. Opus dynamic PTs normalize to 111; PCMU and PCMA
    use PT 0 and PT 8, and mismatched private RTP is rejected. Focused evidence
    passes six native-edge tests, five public-UCTP tests, four real mTLS
    gateway-to-worker tests with encoded/decoded Opus and PCMU, plus rvoip
    descriptor and real-QUIC PCMA tests. The supervisors retain
    generation-specific cleanup through panic or forced abort; unexpected
    supervisor-stream termination now marks health degraded, while an explicit
    drain remains a normal shutdown.
  - [x] Represent role-separated publisher mTLS, WebTransport and raw-QUIC
    subscriber admission, Redis active-grant/session leases, bounded limits,
    readiness, aggregate diagnostics, and drain; dispatch `moq-relay` through
    three shared-topology `rvoip_moq::MoqRelayRuntime` listeners without an
    all-in-one fallback.
- [ ] Replace the current exact publisher certificate-to-namespace bindings
  with an rvoip-owned active-grant admission policy for dynamically generated
  `{tenant}/{broadcast}` namespaces. Exact preconfigured namespaces are secure
  and executable, but are not sufficient for the production dynamic broadcast
  API.
  - [x] Add an rvoip-owned publisher authority contract with no moq-rs types,
    exact or component-safe tenant-prefix certificate ceilings, exact
    generation-fenced publication grants, bounded per-certificate capacity,
    pre-authority certificate checks, and fail-closed bounded lookups.
  - [x] Implement the Bridgefu authority against the existing Redis active
    grant projection. It requires exact tenant and broadcast identity, MOQT
    transport, a live expiry, and the current Redis generation as its fence;
    missing, malformed, revoked, expired, or unavailable state denies.
  - [x] Expose the policy through `MoqRelayRuntime` while retaining the static
    exact-binding variant. The dynamic variant deliberately refuses startup
    against the current dependency pin because that relay revision does not
    continuously revalidate expiring mTLS publisher leases.
  - [x] Prepare an uncommitted private moq-rs candidate which generalizes
    production expiry-lease supervision to token and mTLS decisions and proves
    both pre-activation and active-session publisher revocation over a real
    raw-QUIC connection. The candidate is recorded in
    `docs/moq-fork-review.md`; it has not been pushed or consumed.
  - [ ] After owner review, commit and push the private candidate, pin its
    immutable revision in rvoip, flip the guarded compatibility marker, wire
    Bridgefu's relay role to the dynamic policy, and rerun the complete relay
    integration suite. No upstream contact is authorized by this item.
- [x] Enforce versioned schema-backed configuration and redacted secret refs.
  - [x] Apply `BRIDGEFU__SECTION__KEY` overrides before strict typed parsing,
    reject unknown keys at every depth, and keep the version-1 JSON Schema
    closed over every documented section. CI validates the example plus
    negative top-level, runtime, tenant, context, and Telnyx typo fixtures.
  - [x] Provide `validate` and `print-effective-config`; the latter validates
    shape and redacts credentials without resolving not-yet-provisioned secret
    references, while `validate` performs secret resolution and role preflight.
  - [x] Close the remaining semantic-parity checks between JSON Schema bounds
    and runtime validation. Startup now enforces the schema's nonzero SIP,
    contact, runtime, and broadcast limits, nonempty region/log filter, exact
    log format, valid operational bind, and the bounded safe context allowlist;
    27 configuration and 9 context tests pass.
  - [x] Add an immutable `config-v1.yaml` schema/model compatibility fixture;
    CI validates every versioned fixture and Rust asserts v1's typed defaults.
    Future versions add sibling fixtures rather than rewriting v1.
  - [x] Model the role-specific private-forwarding TLS, worker targets, token
    secret, queue/admission bounds, and timeouts in YAML and JSON Schema. The
    token secret is resolved only for startup, zeroized in intermediate
    storage, redacted from effective configuration, and rejected outside the
    gateway/worker roles.
  - [x] Add schema-backed `api.rate_limit` settings with bounded positive
    rates, bursts, identity capacity, and idle reclamation. Version-1 configs
    retain explicit safe defaults and environment overrides remain available
    through the existing typed configuration path.
- [x] Add OTLP tracing, complete Prometheus metrics, diagnostics, admission,
  bounded work, rate limits, and circuit breakers.
  - [x] Add opt-in OTLP/gRPC trace export using OpenTelemetry Rust 0.32 and
    `tracing-opentelemetry` 0.33 while preserving JSON/pretty stdout logs and
    the existing Prometheus recorder. Startup validates the collector origin,
    service name, parent-based sampling ratio, and bounded batch queue; W3C
    Trace Context propagation is installed, secret header configuration is
    rejected, and every post-tracing process result uses the SDK's combined
    flush-and-shutdown operation within the configured timeout. Disabled
    remains the collector-free default.
  - [x] Enforce independent token buckets for authenticated control and
    diagnostics principals plus a pre-verification, gateway-wide provider
    webhook budget. Principal keys are process-salted one-way
    issuer/tenant/subject digests;
    untrusted paths cannot create buckets, the cache is hard-bounded and
    idle-reclaimed, capacity fails closed, and every denial returns `429` with
    integer `Retry-After`.
  - [x] Publish `docs/observability.md` as the Bridgefu-owned release metric and
    diagnostic inventory. Its executable inventory test requires every listed
    metric to have an emitter and rejects call, leg, connection, broadcast,
    message, subject, issuer, correlation, token, or remote-address labels.
- [ ] Produce one digest-pinned multi-architecture non-root/read-only image and
  scenario-specific Compose profiles.
  - [x] Keep provider credentials as `env:` references, include every required
    Telnyx control/media field, and give the clustered worker a private-role
    configuration that passes its real preflight.
  - [x] Render every Compose profile in CI, then run the Bridgefu binary's
    strict `validate`/role preflight against the StandardCharter, generic,
    Telnyx, UCTP, MOQT, clustered-gateway, clustered-worker, and
    clustered-MOQT-relay service environments. This is executable configuration
    validation, not a claim that the checker starts the Compose services. The
    clustered gateway projection enables its native SIP/RTP, WSS, WHIPS,
    HTTPS API, and public UCTP listeners with distinct media/signaling ports.
    The relay profile passes its strict private-role preflight with
    three distinct UDP listeners, TLS material, Redis coordination, bounded
    limits, and no public control/signaling surface.
  - [ ] Assemble and retain one multi-architecture image digest rather than
    only independent per-architecture local images.
    - [x] Add a manually dispatched, protected-environment release-candidate
      workflow with read-only repository permission, exact full Bridgefu and
      rvoip revisions, pinned executable Actions, `push: false`, one retained
      OCI layout, and no registry/OIDC publication authority. Its verifier
      rejects platform-child digests, requires exactly linux/amd64 and
      linux/arm64, and requires statement-bound SPDX and SLSA predicates for
      each exact platform manifest. Trivy scans single-platform layouts derived
      from that same archive and a retained policy rejects HIGH/CRITICAL
      findings.
    - [ ] Land the owner-reviewed workflow and exact candidate on `main`,
      configure required reviewers on the named GitHub environment, dispatch
      the workflow with that exact 40-character commit, and retain its
      successful root digest and reports. GitHub does not dispatch a
      `workflow_dispatch` definition that exists only on a candidate branch;
      adding the workflow locally is not evidence that it has run.
- [ ] Complete runnable AWS ECS/EC2 and GKE gateway, worker, relay, database,
  cache, identity, secret, networking, autoscaling, and telemetry stacks.
  - [x] Define credential-free, digest-pinned AWS ECS/EC2 and GCP GKE roots
    for the gateway, worker, and relay roles, including role-separated compute,
    networking and load balancing, PostgreSQL, Redis, workload identity/IAM,
    secret injection, telemetry, and bounded autoscaling. Both roots pass
    formatting, provider initialization without a backend, and static
    validation.
  - [ ] Apply each root in an owner-authorized disposable account/project,
    retain the complete call/context/broadcast/drain smoke evidence, and prove
    that destroy leaves no billable resources. Static validation alone does
    not satisfy this item.
- [ ] Validate code, schemas, Compose, Terraform, runtime smoke, SBOM,
  provenance, and vulnerability policy in CI.
  - [x] Validate configuration schema fixtures, Compose rendering and runtime
    preflight, Terraform formatting/static validity, hardened image policy,
    per-architecture SBOMs, and high/critical vulnerability policy.
  - [x] Add and execute a credential-free local/CI process/configuration/health
    smoke covering all eight Compose service preflights, all four exact process
    runners, dependency-aware `/livez` and `/readyz`, split-role admission and
    drain, relay diagnostics authentication, and real loopback mTLS UCTP
    private forwarding. Its evidence explicitly sets
    `release_criterion_satisfied: false`.
  - [x] Add call/media/context/broadcast coverage to the credential-free
    runtime smoke. It executes durable bidirectional codec media, initial and
    later context/DataMessage flow, shared-source broadcast media, token,
    diagnostic, and cleanup checks, and retains bounded output hashes in the
    existing evidence report without claiming a deployment release criterion.
  - [ ] Retain registry-compatible provenance evidence from the protected
    multi-architecture candidate workflow.

Gate 10 API admission and observability evidence recorded on 2026-07-14:

- `api.rate_limit` defaults to 50 control requests/s with a 100-request burst,
  2 diagnostics requests/s with a four-request burst, and 100 provider
  webhooks/s with a 200-request burst. At most 10,000 one-way identity keys are
  retained for five minutes by default; all values have matching schema and
  runtime upper bounds.
- `api_rate_limit::tests` proves independent surfaces, deterministic token
  refill/denial, strict identity-capacity behavior, idle reclamation, and zero
  state when disabled. `api::tests::api_rate_policy_returns_429_with_retry_after_per_surface`
  proves the Axum boundary returns `429` plus `Retry-After`, does not let a
  diagnostics budget consume control capacity, and rejects a second webhook
  before signature verification/persistence. A separate Axum regression proves
  the 256 KiB webhook body ceiling rejects before either operation.
- `observability::tests::release_metric_inventory_is_documented_and_bounded`
  ties the release inventory to concrete emitters and enforces the forbidden
  high-cardinality label list. The authenticated diagnostics inventory test
  fixes the exact top-level contract and asserts private material is absent.
  `deploy/scripts/runtime-smoke.py --list` exposes
  nine credential-free checks, including the new durable call/media, context,
  and broadcast runtime checks. The three-check developer form passes 3/3 for
  codec-exact bidirectional media/cleanup, initial and later context flow, and
  shared-source broadcast media/token/diagnostic/cleanup. These local checks
  do not replace live carrier, cloud apply/destroy, release-load, or protected
  image-candidate evidence.
  The retained smoke source record includes Bridgefu's tracked and untracked
  state plus every exact lockfile-resolved rvoip 0.3.5 package and registry
  checksum; a sibling checkout is not consulted. Child tests
  strip inherited `BRIDGEFU_*`, `RVOIP_*`, `OTEL_*`, cloud, provider, and
  external-store variables so operator credentials/configuration cannot alter
  the hermetic result or enter a failure tail.

Gate 10 gateway-lifecycle evidence recorded on 2026-07-14:

- `gateway_mode_dispatches_to_the_gateway_runner_without_fallback` proves the
  binary selects the gateway runner and never the all-in-one compatibility
  path. Static gateway preflight now succeeds so dispatch is reachable. A
  fully configured static MOQT relay also passes preflight and starts; only an
  incomplete relay configuration or the deliberately disabled dynamic
  publisher policy fails closed.
- `production_gateway_fails_on_missing_dependency_before_binding_any_socket`
  holds the configured operational address open and proves the missing
  authenticated edge error wins before any bind attempt or readiness state.
- `gateway_readiness_tracks_dependency_and_drain_closes_admission_before_shutdown`
  proves `/readyz` follows healthy/degraded dependency state, `/livez` remains
  available while draining, admission closes before dependency shutdown, and
  an admitted operation is joined before bounded cleanup completes.
- The original lifecycle shell evidence covered bounded-capacity,
  pause/resume, permanent drain closure, terminal dependency failure, and the
  existing worker isolation/drain regressions. The later public-UCTP evidence
  below supersedes its original statement that no public edge existed.
- `control_runtime_*` passes 3/3 and proves the split API authority selects an
  existing worker without registering or draining one, rejects local stores,
  and degrades after persistent projection failure. The gateway suite passes
  7/7, and `tls_public_api_drain_waits_for_an_admitted_request` proves an HTTPS
  request admitted before shutdown completes before the shared drain deadline.

Gate 10 role-separated MOQT relay evidence recorded on 2026-07-14:

- `runtime.mode: moq-relay` now starts three production-role listeners sharing
  one `MoqRelayTopology`: publisher mTLS, token-authenticated WebTransport, and
  token-authenticated raw QUIC. Startup verifies Redis grant and session-lease
  dependencies before any relay bind; dependency loss removes readiness, an
  unexpected listener stop is terminal, and shutdown drains all listeners
  concurrently against one bounded deadline.
- The API-side managed publisher projects an independently generation-fenced
  active grant into Redis. Standalone subscriber admission validates the same
  signed token against that projection, then uses the Redis MOQT session lease
  as the cluster-wide replay tombstone and tenant quota. Backend errors fail
  closed; explicit broadcast close awaits exact-generation Redis revocation.
- `cargo test -p rvoip-moq --features relay-runtime --test
  managed_relay_e2e` passes 3/3 real network paths: external mTLS topology,
  publisher-to-relay-to-subscriber over raw QUIC, and the same path over
  WebTransport. `relay_admission` passes 7/7 expiry, replay, quota,
  wrong-transport, ownership, timeout, revocation, revalidation, and close
  cases.
- The focused Bridgefu process-role, relay-configuration, and exact/bounded
  diagnostics-bearer tests pass. The public
  `broadcast_shared_authority` integration test proves a standalone validator
  accepts the projected active grant and rejects both missing and unavailable
  authorities. The schema/compatibility checker, binary build, all eight
  executable Compose service preflights, formatting, diff checks, and targeted
  Clippy run pass. Exact historical per-module counts are superseded by the
  final stable-tree all-target result recorded below.

- The rvoip dynamic publisher policy rejects wrong certificates, cross-tenant
  prefixes, path-confusion targets, missing/revoked/expired/unavailable grants,
  generation replacement, and certificate-cap exhaustion; its focused policy
  tests pass 5/5. Bridgefu's
  focused Redis authority tests pass 2/2 for exact live MOQT grants and
  fail-closed variants. A local, uncommitted moq-rs candidate passes 2/2 real
  network tests for pre-activation and active-session mTLS grant revocation.
  Against the qualified dependency pin, which is still pending project-owner
  release review, the complete rvoip-moq suite
  passes 138 library, 3 managed-relay, 2 external public-contract, and 7
  subscriber-admission tests, plus strict Clippy for every rvoip-moq target.
  rvoip still pins the qualified `ef52ac8` revision. The separate uncommitted
  dynamic-lease candidate remains unconsumed, and the dynamic runtime refuses
  startup until that candidate passes project-owner review and is adopted at an
  immutable fork revision.
  This evidence therefore does not claim a complete production relay path for
  arbitrary new broadcasts.

Gate 9/10 clustered durable broadcast-command evidence recorded on 2026-07-14:

- Schema version 11 adds authoritative `broadcasts`, `broadcast_commands`, and
  `broadcast_operation_receipts` tables to SQLite and PostgreSQL. Gateway
  create/delete operations persist the broadcast aggregate, exact worker
  generation, tenant-bound idempotency receipt, command, transactional
  outbox event, and `Broadcasts` wakeup in one transaction. GET and subscriber
  token issuance read that same tenant-scoped aggregate; no process-local
  registry is treated as clustered truth.
- Admission locks the authoritative, live, non-draining worker row across the
  active-count check and insert. PostgreSQL also takes a transaction-scoped
  advisory lock for each tenant/idempotency digest, so concurrent gateway
  instances cannot exceed the per-worker cap or race start/stop receipts. The
  create request digest includes the call ID as well as the canonical request,
  preventing one reused key and identical body from aliasing broadcasts on two
  calls.
- The worker owns a bounded command executor. It claims only its exact worker
  ID and fence, revalidates the connected source leg and current assignment,
  then starts the existing MediaGraph-backed managed publisher. One-second
  reconciliation ends publications on expiry, terminal call/leg state, source
  rebinding, assignment change, or managed-runtime failure. Startup first
  closes stale-fence resources and revokes their exact Redis grant generation;
  shutdown retains unresolved generation metadata for the replacement worker
  rather than losing cleanup authority. Active broadcasts never migrate.
- Start/stop completion uses exact worker-, fence-, runtime-, and grant-
  generation compare-and-set checks. A failed DELETE cannot leave an obsolete
  worker command behind; a failed broadcast with completed cleanup transitions
  directly to deleted. All-in-one mode prunes terminal process-local handles
  before CRUD/diagnostics and explicitly closes the remainder during process
  shutdown.
- Clustered UCTP broadcast creation now terminates on the authenticated public
  gateway and forwards receive-only media from the exact call-pinned worker
  over private mTLS UCTP 0.2. MOQT configuration separately identifies the
  private publisher-mTLS and public subscriber endpoints, but arbitrary
  generated namespaces remain fail-closed until the dynamic publisher-policy
  dependency is pinned after owner review. No transport silently advertises
  its publisher listener to subscribers or downgrades authorization.
- Disposable backend evidence passes: the complete SQLite/PostgreSQL
  repository suite is 21/21; broadcast-command conformance is 2/2 for memory
  and SQLite plus 1/1 against live PostgreSQL; Redis 7.2 coordination is 1/1;
  and the live shared-grant test proves registration, duplicate rejection,
  cross-process issue/validation, exact-generation revocation, and fail-closed
  post-revocation validation. The focused broadcast library suite passes
  22/22, and the six API regressions cover cross-call idempotency isolation,
  topology capability errors, local pruning, ownership, and cleanup. Strict
  no-dependency Clippy passes for the library, binary, broadcast conformance,
  shared-authority, and full repository-conformance targets.

Final local broadcast authority/reconciliation audit evidence recorded on
2026-07-14:

- The ignored live-Redis regression
  `redis_uctp_listener_ownership_uses_complete_principal_tuple` passes against
  the disposable Redis authority. Listener keys use the principal's complete
  issuer, tenant, and subject ownership tuple through a length-prefixed,
  domain-separated digest. Two otherwise identical principals from different
  issuers acquire, revalidate, close, and rebind independently.
- `committed_but_ambiguous_start_completion_is_reconciled_as_active` and
  `stale_start_never_adopts_a_different_authoritative_generation` pass. A
  post-commit unavailable response is reconciled from durable truth, while an
  older Start claim cannot adopt or overwrite a successor runtime/grant
  generation. The executor cleans only the uncommitted runtime it created and
  preserves the authoritative generation.

This closes the durable control-plane, worker-execution, and local clustered
UCTP subscriber-edge gaps. It does not complete owner-reviewed dynamic MOQT
namespace activation, a deployed relay campaign, or Gate 11 load evidence.

Gate 10 private gateway-to-worker forwarding evidence recorded on 2026-07-14:

- `cargo test --test private_forwarding` passes 6/6 hermetic real-network
  tests. A trusted gateway establishes mTLS and authenticated UCTP 0.2,
  preserves complete RTP in both directions, carries byte-exact RTCP and
  transport-neutral DataMessages, rejects an untrusted gateway certificate,
  enforces exact worker pinning and race-free per-peer capacity, surfaces
  queue backpressure, rejects reserved-label and non-RTCP confusion, drains
  without admitting new routes, and releases exact routes and permits when a
  worker disconnects. Its fifth test composes a real native WHIP edge, exact
  attachment authority, mTLS UCTP, the pinned durable worker and MediaGraph,
  bidirectional Opus/context, RFC 4733 DTMF, and exact terminal cleanup.
  The sixth test reserves an exact destination generation, admits a distinct
  authenticated target UCTP Session/Connection/MediaStream, and drives a
  staged SIP adapter proxy through Prepare, Activate, full-duplex media,
  DTMF, DataMessage, and End with exact cleanup.
- The concrete gateway factory now creates `GatewayForwarder`; the worker role
  registers `WorkerForwardingRuntime` with the worker's existing rvoip
  Orchestrator. Gateway readiness follows authenticated worker reachability,
  worker drain stops new UCTP sessions before closing the endpoint, and both
  roles complete against the process drain deadline.
- The current `process_role::tests` lifecycle/isolation suite passes. The
  focused private-forwarding configuration test proves
  valid gateway and worker projections, role isolation, route-limit parity,
  and token/key redaction. Worker readiness now requires both durable worker
  authority and the private forwarding listener to be healthy; a healthy
  update from either dependency cannot mask degradation in the other. The
  complete configuration suite passes. The configuration schema checker and
  every Compose profile render and pass the binary's strict preflight with
  explicit private TLS and secret inputs. The disposable local TLS helper
  generates verified Redis, gateway-client, and worker-server certificates
  with the required Compose DNS identities and extended-key usages.

- Attachment routing is now fail-closed and exact rather than a worker scan.
  The durable call transaction projects only the attachment-token digest plus
  tenant/call/leg, transport, keyed owner identity, expiry, and current worker
  generation fence. Redis lookup verifies that same live, non-draining worker
  lease before the gateway dials exactly one worker; stale projection
  replacement and removal are sequence-fenced.
- rvoip UCTP exposes a deliberately opt-in, authenticated pre-admission
  routing-hint resolver. Its default ignores all capabilities. Bridgefu enables
  it only for the private gateway intent, required scopes, bounded capability,
  matching request/session UUID, and peer-principal tenant. The worker then
  consumes the real two-minute, single-use attachment token against the
  projected worker fence before activating the rvoip route, and emits the
  admission receipt only after activation succeeds. The gateway validates the
  returned exact worker lease before promoting that same QUIC connection; the
  private capability itself remains unreachable to public peers.
- Focused evidence passes for the opt-in UCTP resolver, gateway attachment
  validation, exact Redis projection, SQLite restart/race conformance, and the
  private QUIC lifecycle. The lifecycle test proves activation precedes the
  receipt and replay produces neither a second binding nor a response. The
  complete 4/4 real-network private-forwarding mTLS/UCTP suite remains green.

Gate 10 authenticated split-gateway public UCTP evidence recorded on 2026-07-14:

- `GatewayUctpIngress` binds a dedicated TLS/raw-QUIC UCTP 0.2 listener, uses
  the same complete principal as the configured Bridgefu bearer validator,
  installs rvoip's bounded fail-closed inbound-admission gate and authoritative
  operational stream before adapter registration, and admits only the
  `bridgefu-public-attachment` intent.
- The typed Session contract
  `bf-public-attach-v1:<sip|webrtc>:<attachment-token>` validates canonical
  token shape without logging the bearer, binds the untrusted wire Session to
  its digest, resolves its keyed tenant-owner Redis projection, and lets only
  the pinned worker consume the original single-use token. The shared
  `GatewayAdmission` closes on dependency degradation, capacity, and drain.
- The media pumps reconstruct complete RTP packets from public rvoip
  `MediaFrame`s, parse complete worker RTP packets on the reverse path, carry
  byte-exact RTCP through the reserved reliable DataMessage, and forward other
  reliable DataMessages bidirectionally. Both directions use bounded queues,
  count overload drops without call IDs in labels, and evict a persistently
  slow route. Session, conversation, public connection, private route, process
  permit, and task ownership converge during terminal teardown.
- `RolePlan` now describes the actual split surface: authenticated HTTP call
  control/provider webhooks, UCTP, native SIP/RTP, WSS, and WHIP/WHEP are
  enabled. Preflight requires `api.enabled`, `generic_bridge.enabled`,
  PostgreSQL, clustered Redis, public TLS for every non-loopback HTTP/WebRTC
  bind, and bearer/fingerprint authority. The executable limits, native
  attachment contract, SIP auth limitations, and hop-by-hop RTCP boundary are
  documented in `docs/gateway-uctp-ingress.md`.
- The focused public-ingress suite covers typed/secret-safe Session parsing,
  scope/intent/digest authorization, RTP framing, typed DTMF, and concurrent
  RTP/RTCP/reliable-DataMessage pumps. Native-edge tests add a real
  authenticated SIP dialog plus an authorized WHIP offer whose exact token,
  WebRTC transport, subject, issuer, and tenant reach the opener before 201;
  owner DELETE and SIP BYE return active routes to zero. These are local
  executable checks, not a credentialed cloud/NAT/TURN smoke.

Final split-gateway broadcast network evidence recorded on 2026-07-14:

- The public gateway now opens one listener-unique private Session, waits for
  its exact worker `SessionAccept` before `ConnectionReady`, and authorizes the
  exact wire Connection on every subscribe/unsubscribe mutation. A sibling
  Connection cannot consume or revoke another listener, and an authority
  generation change fails synchronously before registry mutation.
- QUIC DATAGRAM media that overtakes the reliable dynamic `StreamOpened`
  announcement is retained in a per-peer buffer bounded to 1,000 stream IDs,
  one complete RTP packet and 4 KiB per ID, with a non-extendable one-second
  expiry. Known streams remain lock-free. Dynamic registration is one-shot and
  serialized with retirement, preventing stale local-ID routes or capacity
  bypass.
- `real_network_two_listener_broadcast_is_receive_only_and_independently_owned`
  uses two public raw-QUIC clients on one broadcast and one gateway-to-worker
  peer. Both receive canonical Opus payload type 111; malicious public RTP and
  control produce zero worker input. Ending listener one converges every
  public/private route, direct-listener permit, authority binding, gateway
  admission, and listener lease from two to one while listener two continues;
  ending listener two converges every count to zero.
- Peer-visible acceptance followed by setup timeout sends `SessionEnd` for the
  exact unique Session. Private-route failure awaits exact listener-lease
  cleanup. Proof panic/cancellation, lifecycle failure, graceful drain, and
  worker lease loss release authority, capacity, Sessions, Connections, and
  routes. The gateway ingress suite passes 13/13, gateway forwarding 7/7,
  worker broadcast cleanup/guard tests 3/3, and rvoip's exact-Connection
  subscribe/unsubscribe mutation regression passes.
- Worker startup after execution/listener creation now has one bounded cleanup
  funnel for forwarding, secret, PostgreSQL, Redis, endpoint, MOQT, policy, and
  executor errors. Its real-mTLS-listener regression proves the original error
  is preserved while tasks, health owners, lease admission, and the UDP port
  are released. The four focused worker role tests pass.

Gate 10 native SIP/WebRTC gateway evidence recorded on 2026-07-14:

- `GatewayNativeIngress` installs bounded admission and the operational stream
  before registering SIP/WebRTC adapters. SIP Request-URI, WebSocket private
  subprotocol, and WHIP/WHEP path hints resolve through the same exact Redis
  attachment authority as public UCTP; no local `CallService`, durable worker,
  or FIFO exists on the gateway.
- A focused media-pump test proves complete RTP reconstruction/parsing,
  bidirectional arbitrary DataMessages, typed DTMF, bounded cleanup, and the
  explicit worker-to-native RTCP termination metric. The real-loopback test
  proves missing WHIP auth opens no route, valid Bearer plus SDP opens exactly
  a WebRTC attachment with the retained principal, and authenticated SIP opens
  only the requested SIP attachment. The exposed SIP policies are optional
  generic/Telnyx Digest and an API Bearer that is cleartext-denied unless
  explicitly opted in. Referenced Vapi ingress profiles add explicit
  CIDR-to-principal and verified-mTLS-leaf-to-principal mappings through the
  same policy constructor used by all-in-one mode; unreferenced profiles add no
  trust. Gateway preflight rejects a dead SIP listener with none of those
  mechanisms. Both transports converge to zero active routes.
- Gateway health now combines private worker forwarding, public UCTP, and the
  native correctness stream. Drain freezes all shared admission, closes
  WSS/WHIPS and SIP signaling, drains native/public routes, and only then
  closes private peers against one deadline.

Gate 10 cloud-stack evidence recorded on 2026-07-14:

- `deploy/terraform/check.sh` passes formatting, backend-free provider
  initialization, and `terraform validate` for both the AWS and GCP roots.
  The schema compatibility check and all eight executable Compose profiles
  also pass against the Bridgefu binary.
- Both cloud roots expose the implemented network shape. AWS uses a
  CIDR-restricted NLB for SIP/UDP, WSS, WHIP/WHEP HTTPS, and the HTTPS API; a
  separate QUIC NLB; and exact per-instance EIP associations for RTP plus the
  fixed WebRTC media mux. GCP uses one source-preserving all-ports UDP
  passthrough rule with protocol-specific SIP/RTP/WebRTC/QUIC firewalls and a
  TCP rule containing only API/WSS/WHIPS ports. Health and metrics remain on
  the distinct non-public operations port. Static validation does not prove
  the advertised media addresses, NAT/TURN behavior, certificate chain, or
  carrier/client CIDRs in a deployed environment.
- The local cluster profile publishes native SIP/RTP, WSS, WHIPS, public UCTP,
  the rustls HTTPS API, and a separate operations port. Its disposable TLS
  helper creates distinct serverAuth identities for `public-uctp` and
  `public-api`; the latter is shared with WSS/WHIPS instead of reusing the
  private-forwarding clientAuth-only gateway certificate.
- The roots intentionally contain no production credentials, public DNS,
  public certificates, carrier allowlists, or remote state backend. No cloud
  apply, runtime smoke, or destroy was attempted; those owner-authorized
  credentialed runs remain the release-blocking evidence for this gate.

Gate 10 local container/CI evidence recorded on 2026-07-14:

- Both canonical base references resolve to manifest lists containing
  linux/amd64 and linux/arm64. The former runtime reference was invalid and is
  replaced by the resolvable Debian bookworm-slim manifest digest
  `sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818`.
  Builder and runtime APT inputs now use immutable 2026-05-18 and 2026-07-13
  Debian snapshots plus explicit top-level package versions; this is a
  reproducible-input claim, not a byte-identical-rustc claim.
- `deploy/scripts/check-release-image.sh` passes. The multi-architecture OCI
  verifier passes 5/5 root/digest/platform/attestation regressions, the
  exact-platform selector passes 2/2 nested-index regressions, and the retained
  Trivy policy passes 3/3 platform and severity regressions. No image was pushed
  or published, and the manually authorized combined candidate workflow was
  not run.
- `deploy/scripts/runtime-smoke.py` passes 9/9 checks against the dirty
  coordinated working tree at baseline `0ea0e177`: eight service preflights,
  exact runner dispatch, role lifecycle, operational health, relay diagnostics
  authorization, seven concrete private-forwarding loopback tests, durable
  call/media, context, and broadcast lifecycles. The
  report is schema-version 1, records only output hashes/byte counts, strips
  external credentials, and truthfully leaves the complete deployment release
  criterion false.

Exit: disposable AWS and GCP deployments pass complete smoke tests and destroy
cleanly.

### Gate 11 — Qualification and release candidate (`pending`)

The manual worker-media qualification harness is executable at
`tests/qualification_media_graph.rs` and documented in
`docs/qualification.md`. Its `release` mode fixes the acceptance parameters at
100 bidirectional PCMU↔Opus calls, a 10-call/s ramp, one hour of active load,
100 ms p95 latency, and less than 10 percent post-warmup RSS growth, and writes
versioned JSON evidence before asserting. A final 2026-07-14 one-call,
three-second local smoke passed with 302/302 frames delivered, 302 transcodes,
no source or graph drops, no eviction or transcode error, a 1.1 ms p95 upper
bound, and 0.71 percent post-warmup RSS growth. That
smoke validates the harness only; the release checkboxes remain open until the
exact Linux release run is retained.

The corresponding ignored UCTP and MOQT load harnesses are executable at
`tests/qualification_uctp_fanout.rs`,
`tests/qualification_uctp_network.rs`, and
`tests/qualification_moq_relay.rs`, with exact smoke/release commands and
scope limits in `docs/qualification.md`. The UCTP queue harness measures the
bounded nonblocking fanout primitive, while the network harness creates an
authenticated raw-QUIC peer and complete RTP datagram path for every listener.
Their local smoke reports validate that the harnesses execute, but the
1,000/10,000-listener one-hour checkboxes remain open. MOQT now has a managed
rvoip-owned LOC audio-receive surface and the local harness measures every
listener, but the immutable 10,000-listener one-hour run and deployed relay-tier
evidence are still required before representing the MOQT media-fanout criterion
as complete.

The ignored finite chaos orchestrator is executable at
`tests/qualification_chaos.rs`. It composes exact existing Bridgefu and rvoip
tests for deterministic media loss/backpressure, malformed signaling, Telnyx
outage handling, storage-authority loss, worker drain, relay-session loss,
token expiry/replay, and quota exhaustion. Optional disposable Redis and
PostgreSQL cases are reported as `skipped_external` when their named test URLs
are absent; they never become implicit passes. Its versioned redacted report
hard-codes `release_criterion_satisfied: false`: this finite local matrix does
not replace live Telnyx, actual PostgreSQL-process interruption, a deployed
relay-tier failure, network impairment at release load, or any one-hour run.
The v3 report separately records Bridgefu's locked rvoip application graph and
the rvoip registry-package source tests. The latter are selected at exact
crates.io 0.3.5 name/version/source/checksum from Bridgefu's locked metadata,
then run with each published package's own packaged Cargo.lock; they do not
misrepresent that independent test graph as Bridgefu-lock execution.
The recorded pre-`VF-*` finite run passed all 16 scenarios: 14 local cases and
both isolated Redis/PostgreSQL cases, with no failures or skipped cases. Its
report still correctly leaves `release_criterion_satisfied` false. The chaos
checkbox below remains open until the hour-long and owner-authorized deployed
results are retained.

Historical stable-tree verification recorded earlier on 2026-07-14 after the
split-role composition test was green. Bridgefu's then-current locked
all-target matrix passed 546 tests with zero
failures and 12 intentional ignores. The seven ignored PostgreSQL/Redis cases
were then executed against the isolated disposable services and pass alongside
the 21-test repository conformance suite (28 live-store tests total); the five
remaining ignores are the explicit manual Gate 11 harnesses. Strict all-target
no-dependency Clippy, formatting, and whitespace checks pass. The selected
rvoip foundation/auth/UCTP/QUIC/WebTransport/MOQT all-target matrix and strict
Clippy passed; rvoip WebRTC passed 114 tests with only the two owner-gated TURN
candidate tests ignored. Those counts predate the later Vapi full-duplex
working-tree changes and must not be cited as a final current-tree run. They do
not substitute for any unchecked credentialed, cloud, or one-hour item below.

- [ ] Run the owner-authorized protected non-production Vapi-to-Connect smoke
  and retain only the redacted workflow, revision, approval, account, and
  artifact evidence required by the runbook.
- [ ] Sustain 100 transcoded calls at 10 attempts/second for one hour.
- [ ] Sustain one UCTP publisher to 1,000 listeners for one hour.
- [ ] Sustain one MOQT origin through relays to 10,000 listeners for one hour.
- [ ] Assert less than 100 ms p95 bridge-added latency and less than 10 percent
  post-warmup steady-state memory growth.
- [ ] Chaos-test media, signaling, providers, stores, drain, relay loss, token
  expiry/replay, and quota exhaustion.
- [ ] Publish measured architecture, security, protocol, provider, benchmark,
  migration, and deployment documentation.

Exit: every completed checkbox links to executable evidence and the coordinated
rvoip and Bridgefu revisions are release-candidate quality.

## Release defaults

- Bridgefu 1.0 is audio-only with required G.711 and Opus support.
- Broadcast audio is Opus 48 kHz mono in 20 ms frames.
- Proprietary provider WebSocket media, video, conferencing mixes, listener
  backchannels, and active-call migration are deferred.
- Twilio and Vonage provider control are deferred beyond Bridgefu 1.0; Telnyx
  is the only external provider-control release gate.
- StandardCharter compatibility is release-blocking.
- External provider/cloud evidence requires test credentials supplied through
  secret references; absence of credentials never converts a pending gate into
  a completed one.
