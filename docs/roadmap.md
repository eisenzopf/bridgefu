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

### Gate 1 — Freeze StandardCharter (`in progress — reopened`)

- [x] Add hermetic Connect and Chime test doubles and golden Vapi SIP fixtures.
- [x] Assert `X-Correlation-Id` to Amazon `correlation_id` mapping and exact
  StartWebRTCContact attributes.
- [ ] Assert G.711 to/from Opus media, screen-pop events, and bidirectional
  teardown.
- [ ] Add a protected non-production Vapi-to-Connect smoke workflow and a
  drain/rollback runbook.
- [x] Keep the existing production path isolated.

The Gate 7 Amazon audit reopened this gate at Bridgefu revision `6e30708`.
`tests/standardcharter_contract.rs` proves the real localhost SIP fixture,
tenant routing, allowlisted correlation/attributes, `180`, `200`, and SDP
shape, but its starter deliberately fails immediately after capturing
StartWebRTCContact and the test aborts `serve`. It therefore does not prove a
Chime session, PCMU↔Opus frames, screen-pop progression, StopContact,
bidirectional teardown, or process drain. The checked-in workflows contain no
protected Vapi-to-Connect smoke job. Strengthen the hermetic golden flow and
link an owner-authorized protected non-production workflow before restoring
either checkbox; keep all external AWS execution review-only until separately
authorized.

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

### Gate 3 — Harden rvoip authentication and lifecycle (`in progress — reopened`)

- [x] Authenticate WS/WSS before upgrade and enforce full route ownership.
- [x] Enforce SIP Digest, Bearer, trusted-CIDR, and server-verified mTLS at the
  listener before application events.
- [x] Verify UCTP version, replay, signature, principal, scopes, and ownership
  before delivering replies or commands.
- [x] Enforce caps and deterministic peer cleanup on QUIC, WebTransport, and
  WebSocket substrates.
- [ ] Close the release-wide credential diagnostic boundary found by the final
  SIP integration audit. Every direct and enclosing auth container in
  auth-core, core/core-traits, client, UCTP, WebRTC, IMS-AKA, LDAP, and
  users-core must preserve live/serialized values while exposing only
  scheme/stage, presence/length/count, and fixed classes in `Debug`/`Display`.
  This includes bearer/access/refresh/ID/DPoP tokens, passwords/hashes, Digest
  challenge/nonce/response/cnonce/HA1, AKA vectors, bind/TURN credentials,
  signed credentials, signature headers, step-up payloads, WebSocket query auth,
  and mapped principals.
- [ ] Replace production registrar and UCTP auth log relays with metadata-only
  fields. Boxed/erased auth errors must enter the same typed stage classifier as
  direct conversions; no `Other(err.to_string())` or provider error can bypass
  the boundary. Add source guards and malicious first-party canaries.
- [ ] Make all UCTP/core/client outer event, envelope, payload, and state Debug
  implementations metadata-only while retaining serde and routing behavior.
  Re-run negative auth, transport, and lifecycle suites before Gate 3 is closed
  again.

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
2. [ ] Make SIP origination genuinely dormant. `prepare_outbound` may reserve
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
   - [ ] 2a — Add `SipOriginateContext`, ordered bounded initial headers,
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
   - [ ] 2b — Replace eager originate with a dormant route, deferred media,
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
   - [ ] 2c — Add byte-preserving reliable-ordered SIP MESSAGE/DataMessage in
     both directions, with validated internal label/message-ID headers and
     explicit reliability capability errors.
   - [ ] 2d — Publish typed REFER progress/completion/failure and implement
     all-or-nothing bounded RFC 4733 digit validation, requested duration, and
     inter-digit pacing.
   - [ ] 2e — Run SIP library/dialog/adapter, packet, lifecycle, strict lint,
     documentation, and real localhost interoperability qualification; obtain
     an independent P0/P1 audit before item 2 is complete. Property/fuzz
     evidence must show that no accepted header or auth value can serialize an
     additional SIP header line.
3. [ ] Implement real target-contacting WebRTC clients for WS, WSS, WHIP, and
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
   - [ ] 3a — Add redacted `WebRtcOriginateContext`, an explicit signaling
     protocol, per-exchange ICE policy, async bearer credential provider, and
     bounded target/redirect policy. Reject userinfo, query credentials,
     fragments, disallowed schemes/ports/resolved addresses, TLS downgrade,
     ambiguous create retries, and cross-origin credential forwarding before
     DNS or network I/O. Keep released exhaustive `WebRtcConfig` source-
     compatible through additive types/builders.
   - [ ] 3b — Replace the separate outbound stage with one private retained
     `WebRtcOutboundRoute` modeled on `SipOutboundRoute`. Preparation is local-
     only; one activation driver owns signaling, candidate pumps, FIFO plus
     reserved terminal, exact receipt, cancellation compensation, cleanup,
     setup deadline, health, and drain. `accept` never initiates outbound
     signaling, and cancelled waiters cannot cancel or re-enter the driver.
   - [ ] 3c — Replace per-operation `WsSignaler` sockets with one persistent,
     authenticated WS/WSS connection carrying request-correlated logical
     sessions, scoped candidates, and BYE. Require and echo exactly
     `rvoip.webrtc.v1`; never echo private auth/attachment subprotocol values.
     Track socket-leased routes so one BYE affects one route while disconnect,
     pong expiry, or drain closes and joins every owned route/task. Keep legacy
     `Signaler` APIs only as truthful compatibility wrappers and key any pool
     by sanitized origin, TLS profile, and opaque credential partition.
   - [ ] 3d — Add production rustls WHIP HTTP clients with automatic redirects
     disabled. Own canonical endpoint, bounded relative/absolute `Location`,
     strong rotating `ETag`, conditional serialized PATCH/DELETE, response
     bounds, ordered pre-resource candidate buffering/completion, and no retry
     after an ambiguous POST. Harden the server to require content type and
     preconditions and rotate ETags on mutation/restart.
   - [ ] 3e — Add the minimal alpha-engine
     offer→rollback→counter-offer→answer conformance test before implementing
     canonical WHEP-04 and typed `406`. Use an owner-reviewed private exact-
     revision fork only if that test fails; create no upstream issue or PR.
     Make draft-04 the default and place empty-POST/server-offer behavior
     behind explicit legacy configuration and a warning/metric.
   - [ ] 3f — Route attachable WHEP through authenticated provisional inbound
     admission. Convert the tag to a bounded routing hint, consume a hashed
     single-use attachment token, bind the exact generated Connection ID and
     owner transactionally before `201`, and clean every replay loser,
     rejection, expiry, timeout, disconnect, or abandonment.
   - [ ] 3g — Add tracked HTTP/WS/peer-session supervisors, actual abort after
     drain deadline, route-owned `LocalIceEvent::{Candidate, Complete,
     Overflow}`, bounded task/resource counters, redacted diagnostics, and
     churn/soak leak tests. Global `WebRtcConfig.trickle_ice` must not choose
     policy for all exchanges.
   - [ ] 3h — Qualify real HTTP/HTTPS and WS/WSS client-to-rvoip loopbacks with
     ICE/DTLS/media/teardown; redirect and credential isolation; ETag races;
     WHEP-04 success and exact 406 fixtures; concurrent attachment replay;
     stalled-peer shutdown; and zero leaked routes, contexts, tasks, socket
     leases, or candidate pumps. Server-role and local-offer tests alone do not
     satisfy item 3.
4. [ ] Persist signaling role independently from media direction using
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
5. [ ] Give the Amazon adapter the same prepare/bind/activate/terminal/drain
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
   - [ ] 5c — Add an injectable `ConnectMediaConnector`/session lifecycle seam
     backed in production by Chime plus rvoip WebRTC. Own PONG/activity,
     distinct remote terminal/error causes, joined task, absolute-deadline
     close, streams, hold/resume/DTMF, and secret-free logs. Use the existing
     hermetic Chime server to test the adapter without another media library.
   - [ ] 5d — Implement a retained `AmazonOutboundRoute` with local-only
     prepare, immutable context, single-flight activation/cleanup, bounded FIFO
     plus first terminal, authoritative liveness/fallback, stable deferred
     stream, owned tasks, and `amazon-connect.contact-id` receipt. A known
     contact is stopped exactly once on every post-Start failure, cancellation,
     remote end, peer failure, PONG expiry, or repeated local end; route becomes
     non-live before terminal delivery.
   - [ ] 5e — Add bounded adapter and `ConnectScreenPopServer` admission,
     `begin_drain`/absolute-deadline drain, owned JoinSets, terminal fallback,
     cancellation/join for the metrics updater, and explicit pending-cleanup
     records after hard local abort. Bridgefu shuts this path down by draining,
     never by merely aborting `serve`.
   - [ ] 5f — Persist a redaction-safe Bridgefu Amazon start spec containing
     profile, exact instance/flow, attributes, display, and optional
     description. Derive the token deterministically from immutable effect ID
     with a versioned domain prefix; callers never supply it and durable state
     never contains credentials. Migrate plan schema explicitly rather than
     defaulting legacy records into runnable work.
   - [ ] 5g — Execute Amazon StartLeg through exact durable effect authority:
     build context, prepare, transactionally bind the exact Connection ID, then
     activate and reconcile its contact reference. Bind failure produces zero
     Start. Restart never migrates old media; an ambiguous Start repeats the
     identical token/request only to recover and stop the same contact, then
     fails the old leg. Register one profile-resolving adapter only after rvoip
     lifecycle tests pass.
   - [ ] 5h — Keep the legacy listener/default runtime byte- and behavior-
     compatible while adding a separate false-by-default authenticated canary
     listener/tenant allowlist. Require trusted Vapi principal, matching
     tenant/correlation, and atomic durable create/attach/dedup. Add full fake-
     Connect/fake-Chime PCMU↔Opus golden teardown/drain tests, repository crash-
     barrier tests, canary replay/cross-tenant negatives, and a manually
   protected non-production workflow that verifies AWS token idempotency
   before any production switch.

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
   MediaGraph ownership model. Each SIP and WebRTC route must have one owned
   supervisor for negotiation, candidate, media-pump, disconnect-grace, and
   terminal tasks; teardown must cancel and join them, remove exact mappings,
   close transport resources, and emit exactly one authoritative terminal
   event. Transfer completion is established by typed protocol outcome, not by
   successful command dispatch alone.
8. [ ] Preserve the frozen StandardCharter path while adding a protected
   canary compatibility route for its trusted Vapi contract: `sip:<tenant>`
   plus `X-Correlation-Id`, without a public attachment token. The canary may
   auto-create or attach only after source authentication, explicit tenant
   enablement, correlation validation, and durable idempotency/deduplication;
   unrelated or replayed requests must fail closed. The existing runtime stays
   the default until this path passes every frozen regression and the
   non-production canary workflow.
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

The current exact-revision `rtc` alpha fork remains pinned while these adapter
and lifecycle defects are fixed in rvoip. A further private fork is justified
only by a minimal failing engine conformance test (directional RTP,
rollback/counter-offer, close/candidate lifecycle, or late DataChannel). Any
such patch remains on an exact reviewed revision; no upstream issue or pull
request is created before owner review.

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

  Qualification also exposes a default-stack failure: the 422/fast-response
  integration family and the tenant-bound listener test can overflow Tokio's
  default 2 MiB debug worker stack and currently require
  `RUST_MIN_STACK=16777216`. Reproduce at the exact pre-remediation baseline,
  identify recursion or oversized async frames/types, and either remove the
  excess stack use or make a justified bounded runtime-stack setting explicit
  in every shipped process mode. Add default/release/long-churn evidence; no
  release candidate may rely on an undocumented test-only environment flag or
  retain a plausible production worker-stack crash.

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
