# Changelog

## Unreleased — crates.io rvoip 0.3.8 and recipe runtime cleanup

- Repointed the coordinated rvoip dependency graph to exact crates.io `0.3.8`
  packages and removed every Git/path override.
- Kept the provider-neutral recipe compiler and the built-in
  `vapi-amazon-connect-screen-pop@1` runtime contract while moving its AWS
  CloudFormation, Lambda, AMI, Vapi provisioning, and live qualification
  implementation to `bridgefu-vapi-awsconnect`.
- Added explicit `sips_optional_srtp`: SIP signaling remains TLS-only, Bridgefu
  offers and negotiates SDES-SRTP when the peer offers it, and otherwise
  accepts RTP/AVP. Strict `sips_srtp` remains the default.
- Added an explicit DNS `sips:` Contact for secure recipe UAS responses so a
  2xx ACK remains on the secure dialog route with rvoip 0.3.8. Bridgefu keeps
  the explicit `;transport=tls` route contract used by deployed integrations.
- Added redacted runtime evidence for the exact media-security posture of a
  fully established SIPS ingress leg. Strict SDES-SRTP and the explicit
  RTP/AVP compatibility fallback are distinguishable without logging raw SDP,
  SIP URIs, keys, addresses, or correlation IDs.

## Unreleased — Bridgefu 0.9.0 customer-preview candidate

This working tree is not yet a published release. An owner-reviewed immutable
revision and the protected two-platform OCI candidate remain 0.9.0 release
gates. The rvoip #54 fix and fourth exact-Chromium pass, TURN/public-NAT,
live-provider and StandardCharter checks, cloud deployment evidence, and the
one-hour qualification profiles remain explicit 1.0 gates.

### Audit scope and review status

This entry is the review index for the complete coordinated change surface as
of 2026-07-31. The owner-authorized candidate is frozen by the commit containing
this entry on `codex/bridgefu-1.0`; it remains unmerged and unpublished until
the PR and protected two-platform workflow pass.

- The complete candidate diff, not only a historical commit range, is the
  review scope. Formatting, whitespace validation, strict all-target/all-feature
  Clippy, the locked all-target Rust suite, and the TypeScript SDK suite pass.
- The release-candidate build now uses exact crates.io `=0.3.5` rvoip
  component packages, with registry checksums and the complete transitive graph
  recorded in `Cargo.lock`; a sibling checkout is no longer a build input.
  Later references to `../rvoip` retain historical evidence from the original
  2026-07-16 audit and do not describe the current dependency source.
- The credential-free nine-check runtime smoke and a hardened native
  `linux/arm64` image build pass. No cloud infrastructure, live provider call,
  registry publication, or one-hour release profile was run.
- Exact built-SDK Chromium qualification passes for generic SIP, Amazon
  Connect, and Telnyx. Generic WSS reaches Bridgefu's rvoip core but outbound
  RFC 4733 never reaches Chromium; the dependency defect is recorded as
  [rvoip issue #54](https://github.com/eisenzopf/rvoip/issues/54).

### rvoip 0.3.5 registry integration — 2026-07-31

- The coordinated 44-crate rvoip 0.3.5 release is published from
  `c4f95e0c696a11e2e6e15183fbaa9b3dc6f94fec` and tagged `v0.3.5`.
- Bridgefu resolves 25 rvoip packages at exactly `0.3.5`, all from crates.io
  with checksums and no Git, path, or temporary Cargo override.
- The 0.3.5 graph removes Smol, async-std, and their executor/runtime packages
  from Bridgefu's lockfile. Tokio remains the supported async runtime.
- `cargo test --locked --all-targets` and strict all-target/all-feature Clippy
  pass against the published graph. The TypeScript SDK passes 20/20 tests with
  its own pinned Playwright 1.61.1 installation.
- Exact Chromium handoffs to generic SIP, Amazon Connect, and Telnyx pass.
  Generic WSS is blocked by the outbound RFC 4733 defect tracked in rvoip #54;
  Bridgefu carries no local rvoip patch.
- The release-image policy, OCI verifier tests, executable Compose preflight,
  credential-free runtime smoke, and native hardened `linux/arm64` image pass.
  The retained two-platform OCI candidate remains a protected post-commit
  workflow gate.
- All 44 published package archives matched their crates.io checksums. The
  interrupted strict rvoip beta qualification was not completed before the
  owner-directed publication and is not represented as a current strict pass.

### Release build-context hardening — 2026-07-31

- Docker build contexts now exclude local agent worktrees, SDK `node_modules`,
  Playwright browsers, Terraform provider caches and state, editor files,
  operator environment/configuration files, Compose-mounted `deploy/tls`, and
  common private-key and certificate formats.
- The release-image policy requires those exclusions. The measured local
  context fell from 8.6 GB to 7.96 MB before the successful native image build.

### Minimal OCI runtime hardening — 2026-07-31

- The canonical final image moves from Debian `bookworm-slim` plus APT and
  curl to a digest-pinned, nonroot distroless Debian 13 `cc` runtime for both
  `linux/amd64` and `linux/arm64`.
- Bridgefu now provides a configuration-independent `healthcheck` command that
  performs the local `/livez` probe itself. The final image no longer needs a
  shell, package manager, curl, or their transitive userland.
- Compose and ECS invoke that probe directly. GCP init containers prepare the
  Redis trust bundle and URL file, while every Bridgefu workload starts the
  binary directly and resolves `env:NAME` secrets from `NAME_FILE` only when
  the direct environment variable is absent.
- The exact pinned runtime manifest and complete native images report zero
  HIGH/CRITICAL findings under Trivy 0.70.0 on both release architectures. CI
  limits retained SARIF to that exit threshold, while the protected candidate
  gate retains all severities in JSON. The strict policy is unchanged.

### rvoip 0.3.4 registry integration — 2026-07-29

- Bridgefu now resolves one registry-only rvoip package graph at exactly
  `0.3.4`; all 25 resolved rvoip packages carry crates.io sources and
  checksums, with no path, Git, or temporary Cargo patch.
- Pending inbound attachments subscribe to rvoip's exact-generation
  `InboundAdmissionTermination` signal. The call actor no longer wakes every
  25 ms to infer cancellation from principal lookup failure.
- The terminal signal is translated into Bridgefu's durable
  `SourceTerminatedBeforeAnswer` command before peer teardown. A pending
  destination receives CANCEL, a final-answer race receives ACK then BYE, and
  an established destination receives BYE through the existing idempotent
  generation-fenced effect path.
- The real generic-SIP cancellation case passes its one-second destination
  CANCEL bound. The complete six-case generic SIP reference suite, 40-case
  call execution supervisor suite, 82-case StandardCharter contract, and two
  hermetic Amazon Connect qualification cases pass against registry-only
  rvoip `0.3.4`. The owner-gated Chromium case remains separately ignored.

### Dependency migration verification — 2026-07-26

- Bridgefu resolves 24 checksum-locked rvoip packages at exactly `0.3.1` from
  crates.io. `cargo metadata --locked` reports no Git or path package sources,
  and `cargo check --locked --all-targets` passes.
- The release-image policy, configuration-schema, Compose, OCI-helper,
  qualification-evidence, browser-SDK, and focused runtime suites pass against
  the published package graph.
- The locked all-target regression exposed one release-blocking rvoip lifecycle
  defect: an inbound SIP CANCEL completes the source transaction but does not
  promptly invalidate its pending `InboundAdmission`. Bridgefu consequently
  cancels the already-ringing destination only at its ten-second setup
  deadline, while the strict reference test requires propagation within five
  seconds. The test remains strict and unchanged.
- The dependency migration is complete, but release qualification remains open
  until the rvoip defect is corrected in an owner-reviewed published patch and
  Bridgefu is repointed to that patch. No fork push, publication, upstream
  issue, or maintainer contact is authorized by this work.

### Product shape

- Expanded Bridgefu from the original Vapi-to-Amazon gateway into an
  audio-only, exactly-two-logical-leg call controller and media bridge. Each
  side is independently terminated; audio, DTMF, and permitted context are
  bridged through rvoip rather than proxying one protocol end to end.
- Kept the original fixed SIP listener as a compatibility product while adding
  a durable v1 named-route product. A destination leg can be replaced while the
  source leg remains attached, but Bridgefu does not create a three-party mix.
- Added a plain-language guide to both primary workflows in
  [docs/product-overview.md](docs/product-overview.md), and an illustrative,
  deliberately unexecuted combined configuration in
  [config/browser-vapi-amazon-handoff.example.yaml](config/browser-vapi-amazon-handoff.example.yaml).

### Added — call control and durable execution

- Added a tenant-scoped, event-driven two-leg aggregate with typed leg
  direction, signaling initiation, media flow, leg/call lifecycle, terminal
  outcomes, deadlines, connection and binding generations, and append-only leg
  replacement state in [src/call_engine](src/call_engine).
- Added a durable call service and execution supervisor with effect claiming,
  worker placement and fencing, restart recovery, bounded setup/media-idle
  deadlines, owned drain, provider-event reconciliation, and generation-safe
  teardown in [src/call_service](src/call_service).
- Added exactly-once request receipts for create, hangup, DTMF, transfer, and
  replacement. Mutations require a visible-ASCII `Idempotency-Key`; identical
  retries return the original receipt and conflicting reuse returns `409`.
- Added two-minute, single-use inbound attachment proofs for SIP, WebRTC, WHIP,
  and WHEP. Proof consumption, ownership, expiry, worker assignment, and
  connection binding are committed atomically.
- Added server-controlled make-before-break leg replacement. The existing
  destination is held without a three-way media interval, the replacement is
  promoted only after readiness, and failure/rejection/timeout resumes the old
  destination when possible.
- Added authoritative SIP REFER/NOTIFY transfer tracking, provider transfer
  intents, RFC 4733 DTMF sequencing, terminal hangup, early-media handling, and
  stale-generation rejection.

### Added — v1 API and named routes

- Added tenant-scoped REST surfaces for typed call creation, named-route
  discovery/creation, call reads, DTMF, transfer, leg replacement, and hangup in
  [src/api.rs](src/api.rs), [src/api/calls.rs](src/api/calls.rs), and
  [docs/api.md](docs/api.md).
- Added server-owned named routes and typed ingress/destination profiles. Public
  clients select only a route ID, ingress kind, and sanitized context; targets,
  provider identifiers, credentials, TLS policy, and TURN secrets remain
  server-side. The low-level arbitrary-destination API requires the separate
  `calls:destinations:arbitrary` scope.
- Added non-secret profile revisions. Calls retain profile kind, ID, role, and
  a canonical SHA-256 policy revision while secrets and secret-reference names
  remain outside durable plans and API discovery.
- Added complete one-use SIPS or WSS attachment descriptors. Browser signaling
  uses a short-lived `webrtc:connect` JWT cryptographically bound to the exact
  attachment instead of reusing the control-plane bearer.
- Added provider capability discovery, verified provider webhook ingress,
  authenticated diagnostics, screen-pop evidence lookup, and broadcast CRUD
  and token endpoints.

### Added — Vapi to Amazon Connect

- Preserved the frozen StandardCharter-compatible Vapi SIP-transfer listener on
  the configured legacy SIP port (default `5060`). It routes by Request-URI,
  then `To`, then optional default tenant; maps allowlisted `X-*` headers to
  Amazon attributes; starts `StartWebRTCContact`; bridges SIP G.711 to Chime
  Opus; and owns bidirectional teardown.
- Added a secure managed alternative: the application creates a named call,
  receives a two-minute one-use SIPS address, and directs Vapi to that exact
  attachment. Referenced Vapi ingress profiles bind tenant/principal identity,
  trusted CIDRs, TLS, optional Digest or verified mTLS leaf identity, mandatory
  SRTP, and codec policy.
- Added attach-then-dial behavior for managed routes so destination work begins
  only after the authenticated source attachment is accepted, and source final
  answer can wait for destination readiness.
- Added durable Amazon start specifications and contact/reference roles so
  restart recovery does not infer provider meaning from an untyped ID.
- Added one deterministic `StartWebRTCContact` client token derived from the
  immutable effect ID. Managed execution reuses the byte-identical start
  authority across ambiguous retries and can recover/stop an ambiguously
  created contact after worker restart. The frozen compatibility listener
  intentionally retains its historical `client_token: None` behavior.
- Added [src/amazon_cleanup.rs](src/amazon_cleanup.rs): successful Amazon starts
  retain exact `StopContact` authority before media proceeds, and startup/drain
  reconcile unresolved cleanup records without exposing contact identifiers.
- Added an optional, false-by-default durable StandardCharter canary on the
  generic listener while leaving the original listener independent.

### Added — browser WebRTC to Vapi assistant to Amazon handoff

- Added the alpha TypeScript package `@bridgefu/webrtc-browser` under
  [sdk/typescript](sdk/typescript). It handles attachment parsing, authenticated
  WSS/WebRTC setup, microphone/remote audio, ICE configuration, context and
  arbitrary DataChannels, browser DTMF, ringback, handoff-status events,
  teardown, and bounded reconnect behavior.
- Added named direct-browser routes whose stable source leg is browser
  WebRTC/Opus and whose initial destination can be a profiled Vapi SIPS/SRTP
  assistant. Initial context may be required before the outbound INVITE.
- Added backend-controlled replacement from the Vapi assistant leg to an
  allowlisted Amazon route. The browser PeerConnection stays stable; success
  retires Vapi and failure resumes it. The SDK intentionally does not possess
  API credentials or expose the privileged replacement REST operation.
- Added the reserved authenticated `bridgefu.handoff.v1` status channel with
  monotonic `preparing`, `ringing`, `attaching`, `connected`, `resumed`,
  `failed`, and `ended` states. Bridged peers cannot spoof this label.

### Added — signaling, media, and context

- Added generic SIP/RTP ingress and egress, secure SIP TLS/SRTP profiles,
  interactive WS/WSS WebRTC ingress and egress, and WHIP/WHEP attachment
  surfaces through a shared rvoip Orchestrator.
- Added bidirectional PCMU/PCMA-to-Opus media graphs, codec-specific routes,
  early media, authoritative activity tracking, bounded queues, full-duplex
  DTMF, and exact cleanup/drain ownership.
- Added typed `bridgefu.context.v1` envelopes. Initial context can hold SIP
  origination dormant until one valid allowlisted message is durably captured;
  configured values become initial INVITE headers and later context becomes
  in-dialog SIP MESSAGE. Amazon Connect and Telnyx remain initial-context-only.
- Added arbitrary labeled DataChannel bridging where both profiles allow it,
  while reserving Bridgefu control labels and refusing to translate arbitrary
  channels into SIP MESSAGE.
- Added configurable WebRTC codecs, STUN/TURN descriptors, ICE transport and
  gathering policy, NAT 1:1 candidates, SIP advertised addresses, RFC 3581
  behavior, RTP port ranges, and bounded symmetric-RTP rebinding policy.

### Added — providers

- Added native Amazon Connect execution using typed profiles,
  `StartWebRTCContact`, Chime WebRTC media, initial contact attributes,
  authoritative teardown, and the cleanup journal described above.
- Added native Telnyx Call Control originate, transfer, hangup, and DTMF using
  exactly `telnyx = 0.1.0`, unique durable command IDs, byte-identical bounded
  retries, circuit breaking, SIP media attachments, and typed reconciliation.
- Added raw-body Ed25519/timestamp verification for Telnyx callbacks before
  parsing, strict account/connection/profile binding, event deduplication, and
  safe status-class diagnostics.
- Kept old Twilio and Vonage persisted discriminants readable, but rejects new
  configuration/work for those providers with an explicit deferred capability.

### Added — broadcasts

- Added managed audio broadcast creation from one connected source leg without
  stealing its media receiver from the peer-to-peer call.
- Added UCTP/QUIC direct fanout using the `uctp/0.2` complete-RTP datagram
  contract, canonical mono Opus/PCMU/PCMA selection, bounded subscribers,
  receive-only authorization, credential refresh, replay rejection, and exact
  cleanup.
- Added MOQT draft-19 publishing and relay integration using MSF-01 catalogs and
  LOC-03 audio, raw QUIC or WebTransport subscribers, bounded retention,
  reconnect/health/drain state, and static certificate-to-namespace authority.
- Added short-lived tenant/broadcast/generation-bound subscriber JWTs, Redis
  active-grant projections and cluster session leases, immediate revocation,
  and separate publisher/subscriber authority.
- Added an opt-in sanitized MOQT event track. Peer context is reduced to fixed,
  allowlisted public event kinds; call, tenant, provider, correlation, SIP
  header, and arbitrary metadata values are never published.
- Added durable gateway-to-worker broadcast commands and receipts backed by
  SQLite/PostgreSQL, Redis wakeups, generation-safe worker execution, expiry and
  source-lifecycle reconciliation, and clustered public UCTP delivery.

### Added — persistence, clustering, and process roles

- Added explicit `all-in-one`, `gateway`, `worker`, and `moq-relay` runners.
  Roles fail preflight rather than silently falling back to all-in-one.
- Added memory, SQLite, and PostgreSQL repositories plus Redis coordination.
  SQLite is the standalone default; memory requires an explicit dev/test opt-in;
  clustered roles require PostgreSQL and TLS Redis, with PostgreSQL authoritative.
- Added transactional coordination outboxes, sequence-fenced Redis projections,
  live worker leases/capabilities, exact attachment routing, durable effect
  claims, provider callbacks, execution authority, and bounded recovery polls.
- Added an authenticated private gateway-to-worker UCTP 0.2 plane with mTLS,
  short-lived worker/tenant-bound JWTs, immutable call-to-worker pinning,
  complete RTP, reserved reliable RTCP, DataMessages, DTMF, bounded queues,
  dependency health, and owned drain.
- Added native SIP/RTP, WSS, and WHIP/WHEP termination on split gateways without
  installing a durable call engine there. The exact pinned worker consumes the
  attachment proof before the edge acknowledges signaling.
- Added generation-bound private egress prepare/activate/abort/end, DTMF,
  DataMessage, lifecycle and ACK protocols, Redis-backed gateway epochs/replay
  state, separate target media admission, and local split SIP/WSS initial and
  replacement execution.
- Added a canonical SHA-256 route/capability catalog identity. Workers advertise
  it, durable assignments retain it, gateways reject stale or mismatched
  workers, and a changed catalog cannot strand active calls or released
  terminal calls whose cleanup is still recoverable.
- Added a standalone three-listener MOQT relay role with publisher mTLS,
  WebTransport and raw-QUIC subscribers, Redis grants/leases, least-privilege
  diagnostics, health, limits, and drain.

### Added — configuration, security, and observability

- Added strict `config_version: 1` YAML, a closed JSON Schema, immutable v1
  fixtures, deep `BRIDGEFU__SECTION__KEY` overrides, unknown-key rejection,
  semantic preflight, and CLI `validate` and redacted
  `print-effective-config` commands.
- Added late-bound `env:NAME` secret references whose values and reference names
  are excluded from plans, revisions, logs, diagnostics, and effective output.
- Added tenant/scope-aware API principals, handler-time expiry rechecks,
  constant-time compatibility-key checks, non-reversible ownership
  fingerprints, and separate authority for arbitrary destinations and tenant
  overrides.
- Added TLS for non-loopback split API/WSS/WHIP surfaces, SIP Digest and mTLS
  identity mapping, mandatory-SRTP route validation, and a secure default that
  rejects reusable Bearer credentials over cleartext SIP.
- Added independent bounded token buckets for authenticated control,
  authenticated diagnostics, and pre-verification webhooks, with one-way
  identity keys, idle reclamation, fail-closed capacity, `429` and
  `Retry-After`, plus request-body limits.
- Added JSON/pretty structured logs, W3C-correlated optional OTLP/gRPC tracing,
  Prometheus metrics, authenticated tenant diagnostics, correlation-fingerprinted
  screen-pop evidence, `/livez`, `/readyz`, `/healthz`, and bounded drain state.
- Added a documented low-cardinality inventory that prohibits caller/provider
  identifiers, credentials, tokens, addresses, and payloads as metric labels.

### Added — schema and data migrations

- Added matching SQLite and PostgreSQL migrations `0004` through `0011` for
  coordination outboxes, provider reconciliation, execution authority,
  provider reference roles, Amazon start specifications, Amazon cleanup
  journals, initial context state, and durable broadcast commands/receipts.
- Made execution-plan schema version 3 current while preserving versions 1 and
  2 for inspection and owned teardown. Older plans cannot be submitted as new
  executable work; plans lacking the required principal fingerprint fail
  closed instead of borrowing the current runtime identity.

### Added — deployment and operations

- Added a hardened multi-stage, non-root, read-only-root-compatible image for
  linux/amd64 and linux/arm64 with immutable base/package inputs and explicit
  build provenance metadata.
- Added Compose profiles for StandardCharter, generic SIP/WebRTC, Telnyx, UCTP,
  MOQT, PostgreSQL/Redis, Coturn, and clustered gateway/worker/relay roles.
- Added a protected, manually dispatched release-image candidate workflow that
  builds a no-push OCI layout and verifies exact platforms, SPDX SBOMs, SLSA
  predicates, and HIGH/CRITICAL vulnerability policy.
- Added credential-free runtime/configuration smoke tooling, OCI/platform/Trivy
  policy validators, schema and Compose checkers, local Redis TLS generation,
  and a retained evidence format that records dirty tracked and untracked state.
- Added the protected, manually dispatched StandardCharter nonproduction smoke
  workflow, runbook, retained-artifact verifier, and bounded drain/rollback
  scripts. They do not authorize or imply a production deployment.
- Expanded AWS Terraform to a role-separated ECS-on-EC2/NLB/RDS/ElastiCache
  shape and added a GCP GKE/load-balancer/Cloud SQL/Memorystore shape, including
  IAM/workload identity, secrets, networking, autoscaling, and operations
  isolation. These roots are static definitions, not proof of a successful
  cloud apply.
- Preserved the legacy single-host `deploy.sh` and systemd path as an isolated
  StandardCharter compatibility deployment rather than the clustered reference.
- Added MIT licensing and contribution/security-reporting guidance.

### Changed

- Changed the package description and top-level documentation from a dedicated
  SIP-to-Amazon screen-pop gateway to a programmable SIP, WebRTC, provider, and
  QUIC audio bridge, while retaining version `0.1.1` and `publish = false`.
- Changed configuration from permissive legacy YAML to strict versioned parsing
  with safe defaults, redacted secret refs, named profiles/routes, explicit
  process roles, and dependency-aware preflight.
- Changed generic call admission from process-local/FIFO assumptions to durable
  tenant ownership, worker placement, atomic one-use attachment consumption,
  and generation-fenced execution.
- Changed outbound setup to support attach-then-dial, dormant initial context,
  early media, application/media-ready promotion, and compensating leg
  replacement instead of treating adapter submission as completion.
- Changed split gateways from an API/lifecycle shell into executable public
  API, SIP/RTP, WSS, WHIP/WHEP, and UCTP edges with private worker routing;
  locally composed SIP/WSS egress exists but remains unqualified for release.
- Changed worker capability advertisement to include only concretely installed
  adapters/executors; named routes are hidden or rejected when no live worker
  can execute them.
- Changed operational exposure so a split gateway keeps unauthenticated health
  and metrics on `observability.http_bind`, separate from the public TLS API.
- Changed CI to pin executable Actions, validate schemas/fixtures/Compose and
  both Terraform roots, run repository/Redis/private-egress conformance, retain
  runtime-smoke evidence, and build/scan per-architecture images.

### Fixed and hardened

- Fixed attachment expiry and consumption races, concurrent aggregate-version
  retries, stale connection/event commits, delayed transfer generation reuse,
  and stale media-activity timer rearming.
- Fixed worker lease-loss behavior to fail closed, retained startup recovery
  authority, bounded shutdown/drain deadlines, lifecycle-supervisor races, and
  cleanup gaps after task cancellation or partial startup.
- Fixed provider webhook account/profile binding, callback identity validation,
  durable deduplication/reconciliation, ambiguous completion handling, and
  preservation of legacy provider history.
- Fixed Amazon cleanup loss across setup failure, restart, and drain by making
  cleanup authority durable before media activation.
- Fixed split-route replay, gateway restart fencing, stale lifecycle ACKs,
  source-loss cleanup, target-generation cross-connect, attachment worker
  scanning, and media/control resource leaks.
- Fixed signaling and diagnostic disclosure boundaries: secrets, bearer values,
  raw provider bodies, context values, SIP bodies/authorization, and media
  payloads are excluded from logs and public diagnostics; destinations,
  contact IDs, addresses, and other high-cardinality identifiers are excluded
  from metric labels or reduced to bounded status/count classes. Call IDs remain
  permitted in access-controlled logs and traces for lifecycle correlation.
- Fixed unbounded or ambiguous admission at the API, webhook, SIP transport,
  WebRTC signaling, private UCTP, broadcast subscriber, worker effect, and
  provider retry boundaries.

### Security notes

- The legacy `:5060` StandardCharter listener remains plain SIP/RTP and relies
  on carrier CIDR/firewall isolation; it is not upgraded in place to SIP auth,
  TLS, or SRTP. Use the managed named-SIPS path where those controls are needed.
- Named Vapi profiles require a real shared TLS listener and mandatory SRTP.
  Trusted CIDRs map to one explicit principal; overlaps fail. A client CA does
  not assign identity without allowlisted, transport-verified leaf SHA-256
  fingerprints.
- Control/API credentials are never intended for browser signaling. Browser
  attachments receive a narrower, short-lived, attachment-bound credential.
- Provider webhook signatures cover untouched bytes and are verified before
  parsing or tenant claims are trusted. Public and private reserved control
  labels cannot be supplied through ordinary DataChannels or SIP MESSAGE.
- Public broadcast credentials are receive-only, exact-resource, short-lived,
  generation-bound, replay-protected, and revoked when the managed broadcast
  ends. Publisher credentials are separate.

### Compatibility and breaking protocol changes

- The existing Vapi-to-Amazon StandardCharter listener remains the default
  all-in-one compatibility path and is protected by frozen contract tests.
- UCTP 0.2 datagrams contain the eight-byte UCTP header followed by a complete
  RTP packet; payload-only alpha datagrams are not wire compatible.
- MOQT is pinned to draft-19 with MSF-01 and LOC-03. Incompatible drafts fail
  explicitly; no silent downgrade is performed.
- `config_version: 1` remains the compatibility contract. New migrations are
  additive, and old provider discriminants remain readable even when new work
  for that provider is deferred.
- Legacy permissive YAML must be migrated to explicit `config_version: 1` and
  strict known fields. Call mutation clients must now send exactly one valid
  `Idempotency-Key`. Reusable shared-Bearer authentication over cleartext SIP
  is rejected unless `generic_bridge.sip.allow_cleartext_bearer` is explicitly
  enabled on an appropriately restricted network.
- Context forwarding is opt-in and allowlisted. Existing SIP destinations keep
  immediate origination with `initial_context: none`; `required` deliberately
  changes setup by waiting for an exact context message.

### Testing and qualification added

- Added repository-conformance suites across memory, SQLite, PostgreSQL, Redis
  coordination, Amazon start specs, initial contexts, private egress, and
  durable broadcast commands.
- Added frozen StandardCharter routing/header/media/lifecycle contracts, generic
  SIP reference tests, call-directionality checks, and execution-supervisor
  recovery/teardown matrices.
- Added hermetic all-in-one qualification for browser/Vapi-like SIPS assistant
  handoff to generic SIP, generic WSS, Amazon Connect, and Telnyx, including
  full-duplex media, DTMF, context, hold/no-mix, rejected-generation resume,
  successful promotion, both terminal directions, and cleanup.
- Added real-loopback split gateway/worker coverage for mTLS UCTP forwarding,
  native WHIP/SIP ingress, SIP/WSS initial and replacement egress, generation
  fencing, Redis authority, lifecycle ACKs, and drain.
- Added a built TypeScript SDK Chromium harness plus SDK unit tests for
  attachment, signaling, media, DataMessages, handoff status, DTMF, reconnect,
  and cleanup.
- Added the disposable stock-Vapi feasibility observer and deployment fixture
  under [examples/vapi_feasibility_observer.rs](examples/vapi_feasibility_observer.rs)
  and [deploy/vapi-feasibility](deploy/vapi-feasibility). The dry-run/manual
  harness can observe controlled echo and a generated Bridgefu SIPS transfer;
  its externally credentialed live run remains owner-gated and unperformed.
- Added manual smoke/release harnesses for bidirectional G.711/Opus media,
  1,000-listener UCTP queue and network fanout, 10,000-listener MOQT relay
  fanout, and a finite chaos matrix. Release profiles retain machine/revision,
  latency, delivery, drop, memory, cleanup, and dirty-tree evidence.
- A prior local review of this same working snapshot observed 328/328 Bridgefu
  library tests and 20/20 TypeScript SDK tests passing. They were not repeated
  for this documentation-only task and are not live-provider, cloud, NAT/TURN,
  one-hour, or immutable-release evidence.

### Documentation added or expanded

- Added [docs/product-overview.md](docs/product-overview.md) as the recommended
  conceptual starting point and [docs/api.md](docs/api.md) as the control-plane
  quick start.
- Added or expanded architecture, security, observability, provider capability,
  protocol compatibility, migration, repository, Amazon, gateway-ingress,
  qualification, benchmark, MOQT/RTC fork-review, interop, packet-capture,
  deployment, Terraform, and StandardCharter smoke/rollback documentation.
- Added a non-secret managed-route fixture and the comprehensive illustrative
  browser/Vapi/Amazon configuration. The latter contains placeholder addresses,
  UUIDs, CIDRs, certificates, and `env:` secrets and was intentionally not run
  or validated. Its all-in-one WSS/API endpoints assume external TLS
  termination because `api.tls` is gateway-only.

### Known limitations and open release gates

- The checkout is not reproducible from Bridgefu alone. Its behavior depends on
  the dirty, ahead-of-upstream sibling `../rvoip` workspace described below.
- The exact current `rtc` pin is `1e5b7d4...`. The successful exact-Chromium
  DTMF/codec matrix used a separate temporary six-file RTC candidate; those
  fixes are not in the restored manifest/lockfile dependency. Owner review, an
  immutable fetchable revision, and a complete rerun remain required.
- Stock Vapi website `webCall` to SIP transfer, exact live Vapi header/tool
  behavior, live Amazon agent screen pop/audio, live Telnyx, standards-PBX,
  TURN-only/public-NAT, split built-SDK, process-restart, and deployed cloud
  behavior are not currently release-qualified.
- One-hour 100-call media, 1,000-listener UCTP, 10,000-listener MOQT, deployed
  chaos, latency/memory, multi-architecture OCI, and AWS/GCP apply/smoke/destroy
  evidence remain open. Short local runs do not close these gates.
- Split SIP/WSS execution is locally composed and tested but not release-ready;
  split Amazon/Telnyx, non-loopback peers, real TURN/NAT, and restart recovery
  still need qualification.
- Arbitrary generated MOQT namespaces remain fail-closed until the dynamic
  publisher-lease candidate is owner-reviewed, pinned, enabled, and requalified.
  Static exact namespace bindings and local UCTP fanout are the current safe
  executable modes.
- The browser SDK is alpha and media/signaling-only. It does not call the
  privileged Bridgefu REST replacement endpoint, does not talk directly to
  Vapi or Amazon, and requires a trusted application backend. A reconnect after
  signaling loss requires a fresh attachment.
- Bridgefu is audio-only: no video, screen sharing, conference mixer, or
  three-way handoff interval is implemented. Twilio/Vonage control and provider
  WebSocket media are deferred.
- The legacy Amazon listener answers its SIP side before the complete Amazon
  media setup has succeeded, so downstream setup failure can appear as a quick
  post-answer BYE. The secure named route has the stronger attach-then-dial
  lifecycle.
- Some older documents lag the current code. In particular, `docs/api.md` still
  describes split SIP/WSS egress and split broadcasts as unavailable even
  though local private-egress and durable broadcast paths now exist;
  `docs/amazon-connect.md` says full raw header values are logged while the
  hardened implementation logs counts; and older `src/config.rs` comments and
  historical qualification counts do not describe the final split runtime.
  Treat this changelog, the product overview, current code, and dated
  qualification caveats as the review authority until those passages converge.

### Coupled sibling rvoip foundation — not Bridgefu-owned changes

Bridgefu consumes these capabilities through path dependencies. They live in
the separate dirty `../rvoip` tree and must be reviewed and committed there;
listing them here does not make them part of a Bridgefu commit.

- Added authenticated-principal propagation and ownership checks across SIP,
  WebRTC, UCTP, routes, and operational events.
- Added transport-neutral `DataMessage`, arbitrary WebRTC DataChannels, SIP
  MESSAGE, typed initial SIP headers, RFC 4733 DTMF, correlated transfer
  outcomes, and generation-aware adapter lifecycles.
- Added a single-consumer MediaGraph with directional routes, codec-group
  transcoding, bounded fanout, snapshots, drops/evictions, and metrics.
- Added dormant prepare/bind/activate/abort/end lifecycles for SIP, WebRTC, and
  Amazon Connect, authoritative early media/activity, owned cancellation, and
  bounded drain.
- Added profiled secure SIP origination/listening, TLS/Digest/mTLS policy,
  SRTP, retained INVITE/failover planning, RFC 3581 and symmetric RTP, safe SIP
  MESSAGE/context translation, and authoritative teardown/transfer status.
- Added WebRTC WSS/WHIP/WHEP ingress and outbound origination, ICE/TURN/NAT
  configuration, Opus and negotiated telephone-event handling, DataChannels,
  signaling ownership, and cleanup supervision.
- Added UCTP 0.2 complete-RTP routing, authenticated raw QUIC/WebTransport,
  virtual publishers, and MOQT draft-19 publisher/subscriber/origin/relay,
  authorization, compatibility, reconnect, health, and drain abstractions.
- Hardened credential, signaling, SIP transaction/body/header, provider,
  UCTP, WebRTC, command, payload, and operational diagnostics; bounded stream
  framing, handshake/admission/replay state, and teardown races.

### Subsystem and file review index

1. Product intent and readiness:
   [docs/product-overview.md](docs/product-overview.md),
   [docs/roadmap.md](docs/roadmap.md), and
   [docs/qualification.md](docs/qualification.md).
2. Combined use-case configuration:
   [config/browser-vapi-amazon-handoff.example.yaml](config/browser-vapi-amazon-handoff.example.yaml),
   [config/bridgefu.example.yaml](config/bridgefu.example.yaml), and
   [config/schema.json](config/schema.json).
3. Legacy Vapi-to-Amazon path:
   [src/main.rs](src/main.rs), [src/config.rs](src/config.rs),
   [src/amazon_cleanup.rs](src/amazon_cleanup.rs), and
   [tests/standardcharter_contract.rs](tests/standardcharter_contract.rs).
4. Named route/API contract:
   [src/api.rs](src/api.rs), [src/api/calls.rs](src/api/calls.rs),
   [src/api_principal.rs](src/api_principal.rs), and
   [src/signaling_token.rs](src/signaling_token.rs).
5. Durable call semantics and execution:
   [src/call_engine](src/call_engine), [src/call_service](src/call_service),
   [src/persistence](src/persistence), and [src/coordination](src/coordination).
6. Browser/Vapi/Amazon replacement:
   [sdk/typescript](sdk/typescript), [src/handoff_status.rs](src/handoff_status.rs),
   [tests/qualification_browser_sdk.rs](tests/qualification_browser_sdk.rs), and
   [tests/qualification_amazon_connect.rs](tests/qualification_amazon_connect.rs).
7. Generic SIP/WebRTC and providers:
   [src/runtime.rs](src/runtime.rs), [src/providers.rs](src/providers.rs),
   [tests/generic_sip_reference.rs](tests/generic_sip_reference.rs), and
   [tests/qualification_generic_wss.rs](tests/qualification_generic_wss.rs).
8. Split roles and private transport:
   [src/process_role.rs](src/process_role.rs),
   [src/gateway_forwarding.rs](src/gateway_forwarding.rs),
   [src/gateway_native_ingress.rs](src/gateway_native_ingress.rs),
   [src/private_egress.rs](src/private_egress.rs), and
   [tests/private_forwarding.rs](tests/private_forwarding.rs).
9. Broadcasts and relay:
   [src/broadcast](src/broadcast), [src/gateway_uctp_ingress.rs](src/gateway_uctp_ingress.rs),
   [src/moq_relay_role.rs](src/moq_relay_role.rs), and the
   `tests/qualification_uctp_*` and `tests/qualification_moq_relay.rs` harnesses.
10. Deployment, CI, and operations:
    [compose.yaml](compose.yaml), [deploy](deploy),
    [.github/workflows/ci.yml](.github/workflows/ci.yml),
    [docs/observability.md](docs/observability.md), and
    [BENCHMARKS.md](BENCHMARKS.md).
11. Coupled media/signaling implementation: the sibling
    `../rvoip/CHANGELOG.md` and its changed core, SIP, WebRTC, Amazon Connect,
    UCTP, media, and MOQT crates.
