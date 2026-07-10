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

### Gate 0 — Plan and baseline (`in progress`)

- [x] Record the canonical roadmap before implementation edits.
- [x] Preserve the existing dirty worktrees on coordinated branches.
- [x] Record exact starting revisions.
- [x] Run and record the baseline test matrix.
- [x] Separate existing scaffolding from new functional changes.
- [x] Pin Bridgefu CI to an exact rvoip revision rather than floating `main`.

Exit: all existing work is accounted for and the baseline is reproducible.

### Gate 1 — Freeze StandardCharter (`pending`)

- [ ] Add hermetic Connect and Chime test doubles and golden Vapi SIP fixtures.
- [ ] Assert `X-Correlation-Id` to Amazon `correlation_id` mapping and exact
  StartWebRTCContact attributes.
- [ ] Assert G.711 to/from Opus media, screen-pop events, and bidirectional
  teardown.
- [ ] Add a protected non-production Vapi-to-Connect smoke workflow and a
  drain/rollback runbook.
- [ ] Keep the existing production path isolated.

Exit: current StandardCharter behavior is reproducibly protected without a
production change.

### Gate 2 — Complete rvoip foundations (`pending`)

- [ ] Move `AuthenticatedPrincipal` to core traits and preserve issuer, tenant,
  subject, scopes, expiry, method, and assurance through every validator/event.
- [ ] Add transport-neutral DataMessage adapter, Orchestrator, and client APIs.
- [ ] Complete MediaGraph IDs, snapshots, codec grouping, bounded fanout,
  queue/transcoder diagnostics, and aggregate-safe metrics.
- [ ] Preserve compatibility through re-exports and legacy wrappers.

Exit: validator parity, ownership isolation, DataMessage round trips, and
MediaGraph stress tests pass.

### Gate 3 — Harden rvoip authentication and lifecycle (`pending`)

- [ ] Authenticate WS/WSS before upgrade and enforce full route ownership.
- [ ] Enforce SIP Digest, Bearer, trusted-CIDR, and server-verified mTLS at the
  listener before application events.
- [ ] Verify UCTP version, replay, signature, principal, scopes, and ownership
  before delivering replies or commands.
- [ ] Enforce caps and deterministic peer cleanup on QUIC, WebTransport, and
  WebSocket substrates.
- [ ] Route multi-session datagrams by session and stream.

Exit: auth-negative, cross-tenant, replay, expiry, cap, and leak tests pass on
every supported substrate.

### Gate 4 — Release UCTP 0.2 (`pending`)

- [ ] Finalize the eight-byte UCTP header followed by a complete RTP packet.
- [ ] Add golden byte vectors and packet-capture conformance tests.
- [ ] Version UCTP, QUIC, and WebTransport crates as 0.2.
- [ ] Register MediaGraph virtual publishers through the existing Orchestrator
  publisher/subscriber path and authorize real network listeners.

Exit: authenticated QUIC and WebTransport listeners receive media and the 0.2
wire suite passes.

### Gate 5 — Finish rvoip-moq draft-19 (`pending`)

- [ ] Patch and exact-pin moq-rs for MOQT-19/MSF-01/LOC-03.
- [ ] Replace the current runtime/target mismatch with `MoqProtocolVersion` and
  `MoqCompatibility`.
- [ ] Implement LOC Opus objects, MSF catalogs, raw QUIC, WebTransport, origins,
  subscribers, embedded/external relays, mTLS, authorization, reconnect,
  health, and drain.
- [ ] Interoperate with the patched moq-rs stack and an independent matching
  implementation; upstream the moq-rs changes.

Exit: both substrates traverse a relay and version, packet-capture, and
interoperability suites pass.

### Gate 6 — Build Bridgefu's durable call engine (`pending`)

- [ ] Add typed calls/legs, transition rules, deadlines, atomic admission, and
  transactional command handling.
- [ ] Implement common memory, SQLite, and PostgreSQL repository contracts.
- [ ] Add Redis leases, worker selection, replay, routing, and command delivery.
- [ ] Replace FIFO pairing with explicit attachment tokens.
- [ ] Handle cancellation, glare, timeouts, hangup, teardown, transfer
  compensation, restart recovery, and drain.

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
