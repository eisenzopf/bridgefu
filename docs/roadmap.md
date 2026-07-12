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

The WebRTC alpha dependency follows a private, owner-reviewed fork rule. When an
alpha-engine defect blocks a gate, rvoip may patch an owner-controlled fork and
must pin its exact commit in the dependency declaration and lockfile; floating
branches are forbidden. CI records that revision as dependency provenance.
The current `eisenzopf/rtc` patch covers post-handshake DataChannel creation and
DCEP partial-reliability fixes. No upstream issue, discussion, maintainer
contact, or pull request may be opened without the owner's explicit review and
approval. A port to a newer upstream revision may remain private on the fork
until that review.

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

### Gate 6 — Build Bridgefu's durable call engine (`in progress`)

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
7. [ ] Replace global FIFO pairing with at least 256-bit, two-minute,
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
8. [ ] Add a bounded lifecycle supervisor for setup/media/transfer/cleanup
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
  completes the inbound-context seam and is pushed on
  `codex/bridgefu-1.0-rvoip`; Bridgefu CI pins that exact revision. SIP and
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
  Clippy, and warning-free rustdoc pass. Bridgefu CI now pins this revision.
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
  arrival order cannot cross-connect calls. Gate 6 item 7 remains open until
  the WebRTC listener consumes protocol confirmation and terminal compensation
  is driven by the strong lifecycle supervisor.
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

Gate 6 qualification must include interleaved unrelated attachments, repository
parity, concurrent capacity/idempotency races, callback-before-originate-result,
outbox crash points, token replay/expiry/isolation, remote teardown, transfer
glare, restart, and drain. The existing `ConnectScreenPopServer` remains the
default StandardCharter path until Gate 7 moves Amazon behind the common engine.

Exit: state/repository tests pass and unrelated concurrent calls cannot
cross-connect.

### Gate 7 — Complete SIP/WebRTC and Amazon paths (`pending`)

The 2026-07-12 interface audit established the following implementation order.
These prerequisites are intentionally sequential: later call-engine work must
not hide an earlier adapter side effect behind a nominally staged API.

1. [ ] Extend rvoip origination with an opaque, typed, and redaction-safe
   adapter context plus stable activation and external-connection references.
   Define transport-owned `SipOriginateContext`, `WebRtcOriginateContext`, and
   `AmazonConnectOriginateContext` values behind the core request seam without
   exposing transport types through Bridgefu's durable domain. Context secrets
   must never appear in logs, diagnostics, equality output, or metrics.
2. [ ] Make SIP origination genuinely dormant. `prepare_outbound` may reserve
   identifiers, routes, sockets, and capacity, but it must emit no INVITE or
   other peer-visible signaling. Only a single successful `activate` may send
   the INVITE, after Bridgefu has durably bound the exact Connection ID and
   installed its operational-event owner. Cancellation before activation must
   release every reservation without a network side effect.
3. [ ] Implement real target-contacting WebRTC clients for WS, WSS, WHIP, and
   WHEP, while retaining the corresponding authenticated server roles. Local
   SDP offer construction is not an outbound client. For attachable WHEP,
   authenticate and validate the resource tag, allocate a provisional
   connection, bind its exact Connection ID transactionally, and install its
   owner before returning `201` and emitting the operational event. Rejection,
   expiry, replay, disconnect, or abandonment must close the provisional
   connection and erase its context.
4. [ ] Persist signaling role independently from media direction using
   `SignalingInitiator` and `MediaFlow` (`send_only`, `receive_only`, or
   `send_recv`). Derive offerer/answerer behavior from the protocol and
   signaling role, never from media direction, and construct directional
   MediaGraph routes so one-way legs do not accidentally transmit.
5. [ ] Give the Amazon adapter the same prepare/bind/activate/terminal/drain
   lifecycle. Its typed per-call context must contain the actual Connect
   target, attributes, display name, and a stable client token reused during
   reconciliation; default targets, empty attributes, or a newly generated
   retry token are not compatible evidence. Operational events must cover
   liveness, remote termination, activation failure, and drain cleanup.
6. [ ] Add an initial-context readiness barrier. Durable
   `bridgefu.context.v1` metadata must be validated and available before an
   outbound SIP activation so allowlisted values are present on the first
   INVITE. Later context uses SIP MESSAGE where negotiated. Reject CR/LF,
   reserved or hop-by-hop headers, oversized values, identifier overrides, and
   envelopes whose tenant/call/leg fields do not match the exact durable
   connection binding.
7. [ ] Drive inbound and outbound SIP and WebRTC through the durable call
   engine using the staged interfaces above. Support G.711, Opus, RFC 4733
   DTMF, arbitrary DataChannels, context translation, transfer, remote hangup,
   timeout, and teardown in both directions without bypassing the actor or
   MediaGraph ownership model.
8. [ ] Preserve the frozen StandardCharter path while adding a protected
   canary compatibility route for its trusted Vapi contract: `sip:<tenant>`
   plus `X-Correlation-Id`, without a public attachment token. The canary may
   auto-create or attach only after source authentication, explicit tenant
   enablement, correlation validation, and durable idempotency/deduplication;
   unrelated or replayed requests must fail closed. The existing runtime stays
   the default until this path passes every frozen regression and the
   non-production canary workflow.
9. [ ] Add configurable STUN/TURN, symmetric RTP, advertised addresses, SIP
   `rport`, ICE/DTLS timeout handling, and NAT-aware media-port allocation.
   Prove real PCMU and PCMA SIP/RTP to Opus WebRTC media in both directions,
   real RFC 4733 DTMF, WS/WSS and WHIP/WHEP signaling, initial and subsequent
   context translation, terminal cleanup, and no media after teardown across
   representative NAT topologies. Mock-adapter bridge tests alone do not
   satisfy this prerequisite or the gate.

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
