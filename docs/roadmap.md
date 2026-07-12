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
- Upstream pull requests, issues, or other maintainer outreach require explicit
  user review and approval. Dependency fixes may be developed and pinned on the
  `eisenzopf` forks before that review.

Baseline evidence recorded on 2026-07-10:

- Bridgefu: `cargo test` — 13 passed.
- rvoip: auth-core 35, core 25, UCTP 8, QUIC 1, and MOQT 1 unit tests passed.
- rvoip WebRTC: WHIP, WS, and rustls feature compilation passed.
- StandardCharter core: 31 tests passed; web: 3 tests passed.

## Architecture decisions

### Library ownership

MOQT is implemented in three layers:

1. A reviewed, exact-revision moq-rs dependency implements the wire protocol.
2. `rvoip-moq` owns the stable rvoip-facing compatibility and lifecycle API.
3. Bridgefu consumes only rvoip broadcast traits and never moq-rs types.

`rvoip-moq` supports one production protocol tuple in Bridgefu 1.0:
MOQT draft-19, MSF draft-01, and LOC draft-03. Incompatible peers are rejected
explicitly. Draft changes are never adopted automatically; scheduled CI only
reports changes in the IETF drafts or upstream implementation.

The WebRTC alpha dependency follows the same reviewed-fork rule. rvoip pins an
exact `eisenzopf/rtc` revision for post-handshake DataChannel creation and DCEP
partial-reliability fixes. A port to the current upstream branch may be kept on
the fork for review, but it is not submitted upstream without explicit approval.

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
  provider-controlled Twilio, Telnyx, or Vonage.
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

## Gates

### Gate 0 — Plan and baseline (`complete`)

- [x] Record the canonical roadmap before implementation edits.
- [x] Preserve the existing dirty worktrees on coordinated branches.
- [x] Record exact starting revisions.
- [x] Run and record the baseline test matrix.
- [x] Separate existing scaffolding from new functional changes.
- [x] Pin Bridgefu CI to an exact rvoip revision rather than floating `main`.

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

- rvoip revision `b8c1f25b5e797c00012cca1fe66d252ba3f8bd5d` is pushed on
  `codex/bridgefu-1.0-rvoip`; Bridgefu CI pins that exact revision.
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

Gate 3 evidence recorded on 2026-07-11:

- rvoip revision `a0335daf81ba5e18bddf960c61d4f5bc01c6079e` is pushed on
  `codex/bridgefu-1.0-rvoip`; Bridgefu CI pins that exact revision.
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

- rvoip revision `ef74512967e26f994c4593ed2187517e2c0307b4` is pushed on
  `codex/bridgefu-1.0-rvoip`; Bridgefu CI pins that exact revision.
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
   reviewed 40-character fork revision. Permit that exact Git source in supply
   chain policy without allowing branches or floating revisions, and prove no
   moq-rs type appears in the public `rvoip-moq` API.
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

### Gate 6 — Build Bridgefu's durable call engine (`pending`)

The implementation order is deliberate. In particular, FIFO pairing cannot be
removed safely until rvoip preserves a single-take, redacted inbound routing
hint for SIP and WebRTC connections.

1. [ ] Add an additive rvoip inbound-context seam before the normalized
   `ConnectionInbound` event. Preserve the SIP Request-URI routing hint and the
   WHIP/WS path or authenticated session hint, expose it through Orchestrator as
   a single-take value, and erase it on terminal cleanup. Prove once-only,
   redacted, transport-bound, and cross-tenant-safe behavior.
2. [x] Add Bridgefu's pure typed two-leg aggregate with strong call/leg/tenant
   IDs, exact call and leg states, directions, typed leg kinds, UTC deadlines,
   binding generations, sanitized failures, transition invariants, and
   serializable effect intents. Keep the frozen Amazon runtime untouched.
3. [ ] Add high-level atomic repository contracts and a memory implementation
   covering capacity reservation, tenant-scoped load, optimistic command/outbox
   commit, attachment consumption, provider-event deduplication, deadlines,
   and restart claims. Use one lock across all memory indexes so tests exercise
   real atomic semantics.
4. [ ] Add SQLite and PostgreSQL migrations and implementations for calls,
   legs, commands, 24-hour idempotency, attachments, provider events, outbox,
   worker capacity, and assignments. Run one repository conformance suite
   against all three backends; use `BEGIN IMMEDIATE` or conditional capacity
   updates rather than count-based admission.
5. [ ] Add a transactional call service and authenticated API principal. Read
   `Idempotency-Key` from the header, bind it to tenant plus canonical request
   hash, persist state/command/effect intents before external I/O, and reconcile
   provider or rvoip outcomes afterward. Tenant override requires a dedicated
   administrative scope.
6. [ ] Add memory and Redis worker coordination with fenced leases, capability
   and capacity-aware selection, reservations, routing, replay markers, drain,
   and Redis Streams notification. PostgreSQL remains authoritative and a
   transactional outbox avoids PostgreSQL/Redis dual writes.
7. [ ] Replace global FIFO pairing with at least 256-bit, two-minute,
   single-use attachment tokens. Persist only a digest bound to tenant, call,
   leg, expected transport, and worker fence; atomically bind the exact rvoip
   Connection ID and reject expiry, replay, wrong transport, and cross-call or
   cross-tenant use.
8. [ ] Add a bounded lifecycle supervisor for setup/media/transfer/cleanup
   deadlines, cancellation and compensation, hangup-versus-transfer glare,
   peer teardown, stale generation rejection, worker drain, and fenced restart
   recovery. Active media is ended and cleaned after worker loss, never
   migrated.

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
- The rvoip inbound-context seam is implemented but remains unchecked here
  until its independent review findings on saturated terminal delivery,
  post-gather principal expiry, SIP metadata policy, pending-context bounds,
  and atomic authenticated-inbound delivery are fixed and requalified.

Gate 6 qualification must include interleaved unrelated attachments, repository
parity, concurrent capacity/idempotency races, callback-before-originate-result,
outbox crash points, token replay/expiry/isolation, remote teardown, transfer
glare, restart, and drain. The existing `ConnectScreenPopServer` remains the
default StandardCharter path until Gate 7 moves Amazon behind the common engine.

Exit: state/repository tests pass and unrelated concurrent calls cannot
cross-connect.

### Gate 7 — Complete SIP/WebRTC and Amazon paths (`pending`)

- [ ] Support inbound and outbound SIP and WebRTC through one call engine.
- [ ] Support G.711, Opus, DTMF, arbitrary DataChannels, context translation,
  transfer, and teardown in both directions.
- [ ] Integrate Amazon through reusable rvoip interfaces while preserving the
  frozen StandardCharter contract.
- [ ] Add STUN/TURN, symmetric RTP, advertised-address, `rport`, and NAT
  traversal configuration.

Exit: both bridge directions pass real media tests and StandardCharter remains
unchanged.

### Gate 8 — Complete provider control and media (`pending`)

- [ ] Complete originate, native bridge, transfer, hangup, DTMF, capability,
  webhook verification, and event normalization for all three providers.
- [ ] Connect provider media to unique Bridgefu SIP attachment URIs.
- [ ] Persist deduplication, command IDs, callback reconciliation, and
  idempotency; add deadlines, circuit breakers, redaction, and safe retries.
- [ ] Pass deterministic mock contracts and restricted live test-account flows.

Exit: Twilio, Telnyx, and Vonage pass control, media, security, retry, and
outage scenarios.

### Gate 9 — Make broadcasts operational (`pending`)

- [ ] Attach UCTP and MOQT to any connected source without competing for its
  receiver.
- [ ] Expose real authenticated subscriber endpoints and enforce token expiry.
- [ ] Publish audio/catalog and optional sanitized event tracks.
- [ ] Track publication, negotiated version, relay path, reconnect, listener,
  drop, and cleanup state.
- [ ] Enforce 1,000 direct UCTP listeners per worker; use MOQT relays above it.

Exit: a normal call, UCTP, and MOQT consume one source simultaneously and all
lifecycle/security tests pass.

### Gate 10 — Operations, containers, and clouds (`pending`)

- [ ] Make all process modes executable with dependency-aware health and drain.
- [ ] Enforce versioned schema-backed configuration and redacted secret refs.
- [ ] Add OTLP tracing, complete Prometheus metrics, diagnostics, admission,
  bounded work, rate limits, and circuit breakers.
- [ ] Produce one digest-pinned multi-architecture non-root/read-only image and
  scenario-specific Compose profiles.
- [ ] Complete runnable AWS ECS/EC2 and GKE gateway, worker, relay, database,
  cache, identity, secret, networking, autoscaling, and telemetry stacks.
- [ ] Validate code, schemas, Compose, Terraform, runtime smoke, SBOM,
  provenance, and vulnerability policy in CI.

Exit: disposable AWS and GCP deployments pass complete smoke tests and destroy
cleanly.

### Gate 11 — Qualification and release candidate (`pending`)

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
- StandardCharter compatibility is release-blocking.
- External provider/cloud evidence requires test credentials supplied through
  secret references; absence of credentials never converts a pending gate into
  a completed one.
