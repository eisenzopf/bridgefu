# Bridgefu Recipe-First Implementation Progress

- **Goal:** Implement `BRIDGEFU-RECIPE-IMPLEMENTATION-PLAN.md` completely.
- **Branch:** `codex/recipe-first-production`
- **Target:** Additive Bridgefu `0.9.x` implementation
- **Canonical recipe:** `vapi-amazon-connect-screen-pop@1`
- **Started:** 2026-07-31
- **Last verified:** 2026-08-03
- **Overall status:** The current non-root IAM Identity Center session passed
  the guarded identity, absence, permission, collision, and regional-capacity
  preflight for a fresh IP-only Starter execution. Both required Vapi
  credentials are loaded and validated only in the operator process; their
  values were never stored in Git, durable state, reports, logs, or command
  arguments. The exact foundation bootstrap reached `CREATE_COMPLETE` and
  passed template, parameter, tag, output, role, and resource verification.
  Publication generation 3 is stale after qualification-source changes and has
  no published release objects or release ID. No bootstrap-refresh review,
  application review, application stack, or qualification stack exists. The
  next AWS mutation is exactly one generation-4
  `publish --refresh-candidate`, followed—after publication verification—by
  `bootstrap-refresh` in review-only mode. Starter remains an unqualified
  production pilot; HA remains outside this workstream.
- **AWS audit:** Current preflight and the foundation bootstrap succeeded under
  the selected non-root federated session. Exact account, organization,
  principal, quota, usage, resource, and security-posture observations remain
  only in private operator evidence. Later lifecycle boundaries must still
  repeat their fail-closed checks. DNS is not part of the IP-only run.
- **AWS cost guard:** Every live execution receives an operator-approved private
  planning ceiling and deadline. Those values are not real-time spend controls
  and are not published in the repository. An expired deadline blocks paid
  phases for that execution but never blocks explicit inventory or teardown.

## 2026-08-07 registry and CloudFront qualification refresh

- Bridgefu now resolves all 25 rvoip packages at exactly `0.3.7` from
  crates.io, with registry checksums and no Git, path, or Cargo patch override.
- The 11 changes formerly carried in Bridgefu's local rvoip range were compared
  with the published source. Ten are patch-equivalent; the no-MID primary-audio
  change has the equivalent post-refactor implementation and focused regression
  coverage. The later no-MID DTMF fix is also present and its wire tests pass.
- Focused published-package regressions and Bridgefu's built TypeScript SDK to
  generic-WSS Chromium qualification pass locally. The complete local
  regression matrix is being rerun against the exact 0.3.7 lockfile.
- Demo-site verification now binds and inspects the deployed CloudFront
  distribution, ownership tags, zero-TTL cache policy, security response
  policy, SigV4 origin access control, private S3 origin, redirect, exact
  release assets and content types, public config, and missing-object behavior.
  The protected Vapi browser flow loads deployed CloudFront assets and
  intercepts only its one-run qualification config in memory.
- The prior retained AWS execution had `enable_demo_site=false` and cannot
  qualify this change. After local gates pass, it must be inventoried and
  retired under its exact ledger, then a fresh demo-site-enabled execution must
  complete smoke, full, lifecycle, second verification, evidence validation,
  teardown, and retained zero-state proof.

## How to read this journal

This is the implementation ledger for the plan in the project root. A local
item is complete only when the source/assets and repeatable local verification
exist in this branch. That does not promote a recipe or infrastructure profile
to `supported`: the exact immutable release still needs its retained live
interoperability, recovery, latency, load, soak, and teardown evidence.

## Phase status

| Plan phase | Status | Evidence or remaining gate |
|---|---|---|
| 0. Baseline and branch | Complete | Isolated 0.9 branch, topology audit, existing Connect ownership boundary, private cost guard, teardown rules, and historical identity cleanup are recorded. Root is prohibited for publication, deployment, and qualification. Exact cleanup authority and proof remain private. |
| 1. Recipe schema/catalog/compiler/CLI | Complete locally | Strict data-only schema, embedded/external catalog, deterministic compiler, fingerprints, safe views, and `available/list/show/validate/init/explain` commands pass tests. |
| 2. Generic SIP admission/context | Complete locally | Provider-neutral `SipIngress`, managed one-use SIP attachments, authenticated exact stable-URI admission for SIP/RTP compatibility, SIP/RTP and SIPS/SRTP projection, exact correlation validation/persistence/Amazon mapping, restart-safe durable execution, and recipe-only startup are implemented. |
| 3. AWS-native application | Complete locally | DynamoDB plus prepare/transfer/lookup/Vapi-provisioner Lambdas, canonical Vapi assets, Connect wrapper/guide flows, idempotency, fail-open lookup, bounded data, and redaction tests pass. |
| 4. Starter Production CloudFormation | Foundation bootstrap proven; application lifecycle pending | The current exact foundation bootstrap reached `CREATE_COMPLETE`. No application review or stack exists for the current source. The templates include the later CodeBuild, service-role, readiness, governance, persistent-foundation, log-ownership, protection, Connect update-handler IAM, and cleanup fixes. Two clean posture-appropriate nonproduction cycles remain required. |
| 5. Documentation/admin experience | Updated locally; published Launch Stack pending | Schema-2 preflight, foundation order, persistent Connect, recursive review/protection/drift, production destroy blocking, and exact orphan cleanup are documented. A public Launch Stack URL still requires a clean signed release. |
| 6. Protected live qualification | Current foundation proven; release/application qualification pending | The current preflight and foundation bootstrap passed. Generation 3 is stale and incomplete, and no application or qualification review/stack exists. The immediate gates are one generation-4 publication refresh, verified publication, and a bootstrap-refresh review only. DNS is not required. |
| 7. Terraform Starter parity | Complete locally; live apply/update/destroy pending | The module wraps the canonical CloudFormation application and passes format, validate, and mocked contract tests. |
| 8. High Availability | Deferred to premium AWS Marketplace track | The bounded multi-AZ implementation remains technical reference, but it is outside the current free Starter release, launch, qualification, and support gates. Its packaging, licensing, entitlement, pricing, and retained HA evidence require a separate approved plan. |
| 9. Follow-on recipes | Runtime projections complete at preview | SIP/SIPS→WebRTC, WebRTC→SIP/SIPS, and WebRTC→Amazon Connect packages compile and project. Their exact browser/SIP/DTMF/live matrices remain open. Genesys stays roadmap. |
| 10. Google/web administration | Roadmap, as planned | General Terraform contract exists for AWS. Google Infrastructure Manager and an administration UI remain explicitly outside the first hardened version. |

## Delivered implementation

### Recipe product layer

- Added a strict `bridgefu.recipe/v1` package format with typed inputs,
  whole-node substitution, bounded values, collision checks, path containment,
  deterministic credential-free fingerprints, exact selectors, and support
  tiers.
- Embedded four packages:
  `vapi-amazon-connect-screen-pop@1`, `sip-webrtc-bridge@1`,
  `webrtc-sip-bridge@1`, and `webrtc-amazon-connect-bridge@1`.
- Added additive `recipe_catalog`, `recipes`, and `edge` configuration without
  changing `config_version: 1` or removing the expert configuration surface.
- Added safe administrator commands for discovery, initialization,
  validation, explanation, CloudFormation change-set review/execution,
  status, doctor, structural test, and ownership-checked destroy.
- Added a root recipe quickstart and a recipe authoring guide so custom recipes
  remain data-only and cannot execute arbitrary package code.

### Runtime and context

- Added provider-neutral SIP ingress profiles while retaining the persisted
  Vapi ingress variant for compatibility.
- Projected the flagship recipe to an exact tenant, SIP ingress identity,
  Amazon Connect destination, header mapping, and managed one-use attachment.
- Implemented production-default SIPS/SRTP and explicit compatibility
  SIP/RTP listener/media postures with listener-collision and URI-scheme
  checks.
- Bound SIP context inspection and correlation-header corroboration to the
  same attachment proof transaction so malformed, duplicate, missing, or
  mismatched headers do not spend the token.
- Added a bounded, exact-match `RecipeSipAdmissionCatalog` for custom
  `stable_uri` recipes. It verifies the projected ingress identity, creates a
  server-owned named-route call with pinned profile revisions, derives
  operation-bound idempotency, exchanges the fixed URI for an internal
  one-use proof, and then follows the ordinary durable consume path. Secure
  SIPS/SRTP recipes continue to require managed attachments.
- Added a supervisor-level stable-URI test that proves exact correlation
  projection into Amazon Connect, bidirectional media, duplicate-header
  rejection before a second contact, durable terminal state, and exact adapter
  cleanup.
- Fixed recipe Amazon adapter construction to register every projected named
  profile. The supervisor test exposed that the prior default-only adapter
  would reject a recipe's pinned Amazon profile before contact creation; both
  recipe-only and all-in-one generic runtimes now build the complete immutable
  profile catalog.
- Persisted the approved correlation context in the named-route snapshot and
  projected it into the Amazon Connect `correlation_id` attribute before
  attachment consumption.
- Added bounded WebRTC metadata allowlists and required-context enforcement
  before attachment reservation.
- Preserved legacy configuration and reference tenant contracts; the canonical
  recipe package contains no reference tenant dependency or name.

### AWS-native handoff and Amazon Connect

- Added deterministic HMAC-derived opaque correlation records and a bounded
  DynamoDB adapter with consistent reads, TTL, idempotency, replay conflict
  rejection, and fixed display fields.
- Added authenticated `prepare_handoff`, `transfer_destination`, and
  `connect_lookup` Lambdas. Transfer output is server-owned: the model cannot
  choose the SIP destination or correlation ID.
- Added ownership-safe Vapi assistant/tool/webhook-credential provisioning.
  Updates preserve owned IDs and deletion verifies ownership and attachment
  before removing a Vapi object.
- Added the recipe-owned Connect entry wrapper and Agent Workspace guide. The
  wrapper invokes lookup, fails open when context is unavailable, installs the
  screen-pop guide, and transfers to the supplied customer flow.
- The normal template requires an existing Connect instance ARN and target
  contact-flow ARN. It does not update or delete either customer resource.
- Added a separate, explicitly acknowledged demo/test template that can
  create a disposable Connect instance, queue, routing/security profile,
  agent, target flow, and then the ordinary recipe application.
- Added a packaged, outbound-only AWS CodeBuild qualification runner with a
  bootstrap-owned fixed NAT EIP, automated Connect-managed agent login in
  headless Chromium, immutable runner input, redacted evidence upload, local
  checksum/call-count verification, and teardown ownership.
- Made the disposable CLI proof domain-free by default: Starter advertises its
  exact EIP over SIP/RTP and uses an authenticated private-VPC HTTP control
  hop. SIPS/SRTP remains a distinct opt-in proof and production posture that
  requires a customer-controlled public DNS hostname and trusted certificate.
- Added an optional private-S3/CloudFront browser client containing only Vapi
  public configuration for controlled qualification.

### Starter Production infrastructure

- Added a parameter-grouped root template and nested network, handoff,
  Connect, Vapi, runtime, observability, and optional demo-site templates.
- Added new-VPC and existing-VPC modes, least-privilege security groups,
  restricted Vapi CIDRs, direct EIP media, and Route 53 records.
- Added a single hardened ARM EC2 host with no SSH/key pair, SSM access,
  IMDSv2, encrypted root and separate state volumes, backup policy, automatic
  recovery, a non-root container, read-only root filesystem, and dropped
  capabilities.
- Added digest-pinned image and versioned/checksummed runtime/Lambda artifact
  inputs; deterministic builders produce byte-for-byte identical outputs.
- Added exportable ACM certificate issuance, hostname/key/chain verification,
  atomic proxy reload, and idle-only Bridgefu certificate activation.
- Added a private TLS control path outside the RTP packet path and stack
  readiness checks that use the real Bridgefu validator and health endpoints.
- Corrected the bounded deployment-role policy for the regional CloudFormation
  Amazon Connect update handlers. The required update actions are now covered
  by IAM catalog and contract regressions without granting authority over an
  operator-supplied production target flow.

### Bounded High Availability infrastructure

- Added two fixed gateway slots and two base worker slots split across two
  availability zones, each with one ECS-on-EC2 task and immutable role-specific
  config.
- Added optional, predeclared worker C/D slots with independent target groups,
  NLB listeners, zero-minimum single-instance ASGs, protected hosts, zero-
  desired ECS services, and exact A/B/C/D placement identities. The bounded
  controller scales C and then D from zero to one; it never invents worker
  identities or exceeds four total worker slots.
- Added pre-provisioned gateway EIPs, deterministic slot/worker identities,
  host-network media, public SIP/SIPS NLB, private TCP control NLB, and private
  worker forwarding targets.
- Added encrypted Multi-AZ PostgreSQL 17 and encrypted TLS Valkey 7.2
  (Redis-protocol compatible), generated credentials, backups, restricted
  subnets, and role-scoped access.
- Added ECS deployment circuit breakers, graceful drain, managed termination
  protection, per-host active-call/cleanup scale-in protection, idle-only
  certificate reload, and exact role/slot metrics.
- Added a reserved-concurrency, once-per-minute capacity controller with exact
  service/ASG/alarm inventories. It scales out on aggregate route utilization,
  CPU, memory, capacity rejection, or forwarding-drop pressure. Scale-in is
  D-then-C and requires 15 minutes of zero activity on the retiring slot, zero
  durable cleanup across active slots, low aggregate load, fresh monotonic
  pressure counters, a stopped ECS task, and then explicit ASG unprotection.
  Missing/reset counter series, dependency alarms, base-readiness loss, slot
  drift, convergence, or exhausted bounded capacity all fail closed.
- Marked C/D as dialable but optional for readiness. Gateways require a one-of-
  two A/B quorum, probe required targets concurrently, never background-probe
  scaled-to-zero C/D, and serialize connection attempts per worker rather than
  holding the global peer inventory across a failed handshake. Required-worker
  loss wakes the owned monitor for an immediate local quorum decision; paced
  recovery probes remain cancellation-safe during shutdown.
- Added aggregate forwarding-drop and private-egress capacity telemetry,
  counter-continuity safeguards, bounded-capacity/blocked-scaling alarms, and
  dashboard/runbook coverage without adding work to the audio packet path.
- Added HA-specific dashboard, alarms, capacity/failover/private-TLS runbooks,
  Terraform wrapper, and live verifier checks for exact slots, NLB target
  health, EIP/DNS agreement, RDS/Valkey readiness, host hardening, and
  certificates.
- The implementation is intentionally bounded, not an arbitrary or unbounded
  CPU autoscaler. Gateway A/B remain fixed replacement slots, worker capacity
  stops at A/B/C/D, and the HA profile remains preview until retained live
  capacity, failover, scale-in, latency, and soak evidence passes.

### Observability, security, and operations

- Added CloudWatch Agent Prometheus collection and low-cardinality runtime,
  SIP, media, handoff, dependency, cleanup, certificate, and capacity metrics.
- Corrected the recipe-only production telemetry contract so Starter and HA
  dashboards, capacity alarms, idle certificate activation, and call-aware
  scale-in use the emitted generic gateway/worker route metrics and durable
  Amazon cleanup gauge rather than legacy-only or nonexistent metric names.
  HA EMF now publishes explicitly into `Bridgefu/Runtime`, and scale protection
  fails closed while route/cleanup telemetry is unavailable.
- Added Starter and HA dashboards, SNS integration, actionable alarms, and
  linked runbooks for readiness, Vapi, context, Connect, media, DNS/certs,
  cleanup, recovery, capacity, HA failover, private TLS, and upgrade/rollback.
- Kept telemetry and context storage outside the packet path; no per-packet
  logging or unbounded identifiers are introduced.
- Added secret references, refresh behavior, KMS hooks, redaction tests,
  private control TLS, no-secret outputs, explicit data retention modes, and
  scoped temporary deployment roles.
- Added deterministic release, Lambda, runtime, and browser builders plus a
  checksummed/signable recipe bundle and CloudFormation Guard policy.

### Qualification and lifecycle automation

- Added a native-host qualification builder that runs on the ARM development
  host and cross-compiles only the two required Rust SIP probes for x86-64
  Linux. The isolated package graph excludes the disallowed cryptographic
  dependency, pins the builder platform images, and validates ELF architecture
  and glibc compatibility both while packaging and again in the packaged
  runner. The focused build and release guards pass.
- Added a strict posture-selected matrix: SIP/RTP deployments require the two
  SIP/RTP codec scenarios plus Vapi transfer; SIPS/SRTP deployments require the
  two secure codec scenarios plus Vapi transfer. Shared media, DTMF,
  screen-pop, negative, cleanup, network, and recovery checks remain mandatory.
- Added an execution-scoped real Rust SIP source for all four direct transport
  and codec cases. It observes the rendered INVITE without retaining values,
  verifies TLS/UDP and SRTP/RTP state, emits deterministic bidirectional audio
  markers and DTMF, exercises both BYE origins, and writes a strict redacted
  observation bound to its exact source digest.
- Added a real Agent Workspace Playwright observer with a mode-`0600` reusable
  authentication state, deterministic fake microphone, WebAudio marker/DTMF
  detection, exact synthetic screen-pop checks, keypad interaction, both
  hangup origins, stable cleanup, and screenshot hashing.
- Added a stock `@vapi-ai/web` browser-transfer observer that serves the exact
  immutable release ZIP only on loopback, pauses before its one fixed
  synthetic prepare/transfer prompt, and retains only call/source hashes,
  media/DTMF observations, and cleanup facts. The qualifier independently
  verifies the recipe-owned assistant and both tools in Vapi's final call
  object.
- Added server-side `bridgefu_sip_invite_evidence` only after successful
  attachment consumption proves one exact duplicate-preserving correlation
  header. The collector requires this actual received-wire fact in addition
  to the source, DynamoDB, lookup, lifecycle, media, and Agent Workspace facts.
- Corrected the protected controller's correlation derivation to the exact AWS
  Lambda `bridgefu|deployment|org|call` HMAC contract and added a fixed-vector
  regression test. Private sessions now bind the source org/call identity,
  correlation, immutable candidate, and expected context under HMAC.
- Added an immutable public IPv4 `/32` qualification-source binding to the
  change set and rechecks the runner's current public IP immediately before
  each direct SIP call. It cannot be widened or replaced within an execution.
- Added a versioned redacted evidence schema and validator. Evidence rejects
  customer identifiers, credentials, raw context, and other sensitive fields.
- Added a real negative SIP peer for missing and duplicate correlation headers,
  expired one-use attachments, and pre-answer source cancellation. The release
  controller also drives unauthorized, malformed, conflicting-replay,
  attachment-replay, and missing-context cases; the latter conditionally
  removes only its exact synthetic DynamoDB row and proves the generic Agent
  Workspace state while voice, DTMF, teardown, and one-contact behavior remain
  correct.
- Added controller-owned Starter process-restart, dependency-timeout, and host-
  recovery drills. Each drill binds its before/after state and one common real
  post-recovery matrix call to the immutable controller revision.
- Added a one-hour soak monitor running through Systems Manager on the exact
  runtime host. It samples every 30 seconds and fails on CPU/memory/FD/RTP-port
  bounds, host-interface errors, media drops, cleanup backlog, counter resets,
  Lambda errors, DynamoDB errors/throttling, incomplete 20-call distribution,
  latency SLOs, or nonzero final state.
- Added a guarded live AWS workflow:
  `init → bootstrap → publish → optional bootstrap-refresh review → authorized
  admin execution → bootstrap-refresh-verify → change-set → execute → verify →
  lifecycle-test → verify → destroy`.
- Added a narrow lost-ledger workflow for a recent bootstrap-only execution:
  read-only `recover-lost-ledger-review` → independent review of the immutable
  file and exact file-byte SHA-256 → read-only
  `recover-lost-ledger-execute` → `inventory` → `destroy`. The recovered ID is
  permanently teardown-only. `destroy` must retain three identical complete
  zero observations spanning at least 60 seconds before any fresh ID may
  initialize.
- Added a two-party pre-deployment bootstrap-role refresh that accepts only the
  exact published role template and non-replacing modifications to the
  deployment compute policy, deployment data policy, and qualifier role.
  The scoped deployer can create/review but cannot execute its own IAM update;
  an administrator must execute the one reviewed ARN. Application-stack
  absence, the owned hosted-zone transition, caller identity, parameters,
  tags, source digest, active template hash, role ARNs, and both post-update
  role assumptions are verified; AWS lookup errors fail closed.
- Publication is restart-safe: it verifies ownership before reusing a recorded
  zone, bucket, repository, secret, image, signed release, or object version.
  Local Terraform/provider caches, state, bytecode, and build caches are
  excluded, and hard file-count and byte-size limits stop an oversized bundle.
- An explicit pre-deployment `publish --refresh-candidate` transition freezes
  the complete source-tree digest, preserves a superseded-candidate audit
  record, uses a new immutable ECR tag/generation, and refuses refresh after a
  change set or application stack exists.
- The mutable root progress journal is the sole repository path excluded from
  the source freeze, allowing required qualification updates without changing
  the candidate. Product source, recipe assets, documentation, changelogs, and
  the approved implementation plan remain hashed; a unit test proves stable
  source changes still invalidate the digest.
- The workflow uses a unique execution ID, explicit allowlists, exact tags,
  a conservative profile-aware cost estimate, confirmation strings, immutable
  artifacts, nested change-set review, and a teardown ledger. Durable authority
  resides in a controller-enforced private location outside the repository and
  build directories. Its portable default root is
  `${XDG_STATE_HOME:-$HOME/.local/state}/bridgefu/aws-live`; an operator may set
  `BRIDGEFU_AWS_LIVE_STATE_DIR` to another private root satisfying the same
  boundary. No resolved operator-specific path is repository data. State is
  never copied between hosts, remote recovery capsules are write-only and not
  consumed, and one operator/host owns recovery at a time.
- Change-set review now recursively follows AWS's `ResourceChange.ChangeSetId`
  through the complete nested stack hierarchy rather than trusting only the
  root summary. Depth, child count, and resource count are bounded; every
  resource/action/replacement is checked; missing child reviews fail closed.
  This audit surfaced and explicitly admitted the production Backup resources
  and Vapi custom resource while continuing to reject disposable Connect
  instance/user/queue resources from the existing-Connect workflow.
- Starter and HA verification are profile-specific. HA additionally verifies
  the exact four slot-tagged instances, four stable ECS services, all target
  groups, RDS, Valkey, gateway EIPs/DNS, and the test-only private TLS secret.
- Teardown is incomplete until stack/artifact/secret/role deletion and
  independent tag/name/global-resource inventory all prove zero test-owned
  resources.
- Added an execution-ID-confirmed CloudFormation lifecycle drill. It reviews
  and applies one bounded, non-replacing context-TTL update, then reviews an
  intentionally invalid owned Lambda object version and requires
  `UPDATE_ROLLBACK_COMPLETE` to restore the published working version. Secret
  parameters use `UsePreviousValue`, change sets must be allowlisted
  `Modify`-only with no replacement, interrupted attempts are bounded, and a
  second structural verification is required.
- The proven reference tenant GCP deployment has a browser-safe Vapi public key
  in instance metadata. Its value was not copied into the repository or
  ledger; a future explicitly enabled CloudFront/full-demo run can retrieve it
  just in time without exposing private credentials.

## Verification snapshot

Current qualification-release checks establish that the native ARM-hosted
builder cross-compiles the isolated qualification package for x86-64 Linux and
that both generated binaries satisfy the packaged architecture and glibc
guards. Focused builder/runner tests, locked package metadata and checks, the
release-image policy, Python compilation, public-document identifier checks,
neutral-naming checks, and whitespace checks pass. A complete final regression
pass against the committed generation-4 source remains required before the
single publication refresh.

The historical remediation pass on 2026-08-02 completed the following against
its then-current working tree:

- Full locked Rust all-target tests, all-target/all-feature Clippy with warnings
  denied, formatting, Python compilation, and whitespace checks passed.
- All 88 flagship Python unit/contract/security tests, configuration schema
  checks, and all 23 recipe documentation/runbook checks passed.
- All 20 CloudFormation templates passed `cfn-lint` and Guard. The 19 templates
  within the inline API limit passed AWS `ValidateTemplate` in both
  `us-west-2` and `us-east-1` (38 region/template pairs); the 55,816-byte
  deployment-role template is URL-only and passed local lint/Guard.
- Starter and HA Terraform contract tests and both existing AWS/GCP Terraform
  validations passed. Recursive format and runtime shell checks passed.
- Two complete unsigned release builds were byte-identical. A complete signed
  build produced and independently verified an exact 64-byte detached Ed25519
  signature and public-key digest; CI now exercises the same signed path.
- AWS teardown independently reported zero matching review shells and Connect
  test log groups in both regions. The obsolete bootstrap ledger recorded zero
  stacks, IAM roles/policies, and tagged resources at the time; its IAM
  user/key and local usable credential were revoked. That repository-local
  ledger was later removed and was not migrated to the durable state root.

The older implementation checkpoint below is retained for historical detail.

The following passed against the then-current working tree on 2026-08-01:

- `cargo fmt --all -- --check`.
- Strict all-target/all-feature Clippy with warnings denied.
- Full locked Rust all-target suite: 358 library tests, 151 binary tests, and
  all ordinary integration targets passed; credentialed/manual tests remained
  explicitly ignored by their existing gates.
- All ten disposable database/coordination conformance checks passed against
  pinned local service containers: three PostgreSQL tests and seven Redis
  tests covering ordering, repository restart, projection fallback, private
  egress fencing/recovery, shared grants, ownership, replay, and revocation.
  Both containers were removed immediately after the run.
- Four manual production-path smoke profiles passed and emitted strict JSON
  evidence under `target/`: authenticated raw-QUIC UCTP network fanout (four
  listeners, 100% delivery), direct UCTP fanout (32 listeners, 100% delivery),
  role-separated MOQT relay audio, and four-call bidirectional PCMU/Opus media
  transcoding. Each report identifies itself as `smoke`; none is used as a
  substitute for deployed or one-hour release evidence.
- The manual finite chaos matrix passed all 16 exact scenarios with no skips:
  14 local deterministic faults plus disposable Redis connection-loss recovery
  and PostgreSQL projector crash/reclaim. The strict v3 report is retained at
  `target/qualification-chaos-smoke-gen7.json` and truthfully leaves the release
  criterion false because it is not the deployed one-hour chaos/load campaign.
  Its first run failed closed on two zero-test Telnyx selections; correcting
  their library target and adding a catalog invariant produced the complete
  16/16 rerun. All temporary containers were removed.
- The repository-pinned Playwright 1.61.1 Chromium was installed and the exact
  built TypeScript SDK rerun passed for generic SIP/SIPS, the Amazon Connect
  fixture, and the Telnyx fixture, including both terminal directions where
  provided. The generic-WSS fourth fixture reproduced its disclosed rvoip #54
  boundary: browser-to-destination DTMF and the reverse core event succeed, but
  outbound RFC 4733 does not reach Chromium. It therefore remains preview and
  is not represented as a pass. The SDK's 20 unit tests and strict TypeScript
  typecheck also pass.
- 69 flagship Python unit/contract/security tests, including strict duplicate
  YAML-key, bootstrap-policy-size, release-cache-exclusion, publication-size,
  source-freeze/candidate-refresh, mutable-journal exclusion, secret-safe
  update parameter reuse, bootstrap-refresh boundaries, fail-closed stack
  absence, recursive nested change-set review, production allowlist coverage,
  negative SIP evidence, soak sampling, resumable-resource guards, and exact
  retirement/rebinding of an unexecuted bootstrap review across candidate
  refresh.
- Bridgefu config schema, all recipe manifests/values, compatibility fixtures,
  negative fixtures, and canonical assets.
- Recipe documentation/link/runbook verification across 21 documents.
- All 16 recipe CloudFormation root/demo/role/nested templates under
  `cfn-lint`, CloudFormation Guard 3.2.0, and the live AWS
  `ValidateTemplate` API in `us-west-2`.
- Terraform recursive formatting plus Starter and HA `init`, `validate`, and
  mocked contract tests.
- Shell syntax and ShellCheck for every Starter/HA bootstrap, secret,
  certificate, image, and scale-protection script.
- Two independent Lambda, runtime, browser-site, and complete recipe-release
  builds compared byte for byte.
- The credential-free role/call/media/context/broadcast runtime smoke produced
  and accepted its strict JSON evidence document.
- Rust change formatting and `git diff --check`.

These local results and the current foundation `CREATE_COMPLETE` do not replace
an application CloudFormation deployment or a live Vapi/Amazon Connect media
test.

## Definition-of-done evidence audit

This audit maps the plan's explicit release criteria to evidence, rather than
inferring completion from the amount of implementation present. `Complete
locally` means the source and repeatable local checks exist; it does not satisfy
a requirement whose scope is a published artifact, deployed AWS lifecycle, or
real media/provider behavior.

### First supported recipe

| Requirement group | Current evidence | Audit result |
|---|---|---|
| Built-in package, schema, minimal compilation, expert compatibility, no reference tenant dependency | Embedded `vapi-amazon-connect-screen-pop@1`, strict v1 schemas/compiler, backward-compatibility fixtures, deterministic builds, and canonical-package dependency/name checks pass. | Complete locally |
| SIP/RTP and SIPS/SRTP runtime, correlation validation/persistence/Amazon mapping, restart-safe cleanup | Generic and managed SIP admission, exact header validation, durable call/context repositories, Amazon projection, recovery tests, and current-tree SIP/SIPS Chromium fixtures pass. | Complete locally; real-provider matrix pending |
| AWS-native Vapi, DynamoDB, Lambda, Connect flow/guide, missing-context, and agent-permission assets | Deterministic Vapi/Lambda/Connect assets and their contract, security, idempotency, bounded-data, fail-open, and redaction suites pass. | Complete locally; provisioning and visible Agent Workspace proof pending |
| Starter hardening and administration | Nested CloudFormation includes the hardened EC2 runtime, private control plane, exportable ACM path, SSM, encryption/backups, CloudWatch/SNS, readiness, guarded update/rollback/destroy, and runbooks. All 20 current templates pass local lint/Guard and live `ValidateTemplate`. | Complete locally; revised create/readiness/update/rollback/destroy proof pending |
| Signed multi-architecture public image and immutable regional release | A protected non-publishing workflow builds and checks the multi-platform runtime image with SBOM, provenance, and vulnerability policy. The qualification package now builds natively on the ARM host while cross-compiling its isolated probes for x86-64 Linux, with independent packaged ABI guards. Current publication generation 3 is stale and has no published release objects or release ID. | One generation-4 refresh, completed release verification, protected candidate run, public publication, signature verification, and release-manifest binding pending |
| SIPp, Asterisk, and FreeSWITCH interoperability | The current source pins real SIPp, Asterisk, and FreeSWITCH peers; validates secure/insecure startup; requires three negative SIPp observations and 16 PBX calls across both security modes, codecs, products, and hangup origins; and binds redacted peer/call provenance into final evidence. | Complete locally; deployed retained calls pending |
| Real Vapi/SIP/Connect functional matrix | The protected controller requires SIP/RTP and SIPS/SRTP, PCMU and PCMA, exact Vapi header, full-duplex markers, DTMF, screen pop, both hangups, replay/retry/error/missing context, exact cleanup, and redacted evidence. | Implemented gate; live execution pending |
| Adverse network, load, latency, capacity, and one-hour soak | The controller requires the exact 20-call matrix, two adverse-network profiles, failure drills, one-hour soak, SLO facts, and final zero state. Local finite chaos and short media smoke evidence pass but truthfully do not satisfy the deployed release criterion. | Live execution pending |
| Scheduled nonproduction canary | The current source contains an opt-in weekly workflow and strict canary controller. It uses a dedicated GitHub OIDC role, an immutable versioned seed ledger, an isolated stable-address ephemeral runner, explicit nonproduction/canary tags, exact release checkout/source verification, both stock-Vapi hangup paths, final zero state, a redacted schema, and a complete operations/rotation/cost/teardown runbook. | Persistent nonproduction deployment, GitHub environment/runner, manual canary, and scheduled evidence pending |
| Terraform Starter parity | The Terraform wrapper, contract tests, formatting, initialization, and validation pass against the canonical CloudFormation application. | Complete locally; live apply/update/destroy parity pending |
| Documentation and support evidence | Recipe-first root docs, flagship guide, authoring guide, security/cost/retention/DR material, runbooks, snippets, links, and generated contracts pass documentation CI. Support wording is conditional on an exact retained release. | Complete locally; Launch Stack URL and exact retained evidence revision pending |

### High Availability profile

| Requirement | Current evidence | Audit result |
|---|---|---|
| Two gateways and workers across AZs, stable signaling identities, shared PostgreSQL/Valkey, SIPS and private worker NLBs | HA CloudFormation/Terraform model two gateway and two worker slots across AZs, two EIPs, Multi-AZ data services, private TLS, ECS-on-EC2 role separation, and shared durable authority. | Complete locally; live deployment pending |
| Automated gateway replacement and active-call protection/drain | One single-instance ASG per fixed gateway/worker slot, EIP reassociation, ECS task placement, scale-in protection timer, termination hooks, and durable cleanup are implemented and structurally tested. | Bounded replacement complete locally; failure evidence pending |
| Worker autoscaling and gateway scaling within media-slot capacity | Gateway A/B remain fixed replacement slots. Base workers A/B remain one each; optional C/D each have bounded 0–1 ASG/ECS capacity and distinct private NLB slots. An exact-inventory controller implements ordered pressure-based scale-out and sustained-idle, cleanup-safe, telemetry-safe staged scale-in. Gateway readiness treats only A/B as required with a one-of-two quorum, while C/D remain dialable after registration. | Historical bounded local work only; HA is outside the Starter release and current qualification scope |
| Gateway/worker/AZ/data failover, deploy, rollback, refresh, load, latency, and soak | Runbooks and controller boundaries exist; no exact deployed HA evidence has been retained. | Live execution pending after local scaling closure |
| CloudFormation/Terraform HA parity | Both representations validate and share the same nested application contract. | Complete locally; live apply/update/destroy parity pending |

### Current external-state checkpoint

The current non-root preflight passed and the exact foundation bootstrap reached
`CREATE_COMPLETE` with full controller verification. Both required Vapi
credentials remain process-only. Publication generation 3 is stale and
incomplete, with no published release objects or release ID. No
bootstrap-refresh review, application review, application stack, or
qualification stack exists. The only next mutation is one generation-4
`publish --refresh-candidate`; after verified publication, the next action is a
bootstrap-refresh review only.

Separately, a historical bootstrap refresh reached `EXECUTE_COMPLETE`, and a
superseded disposable path reached application `CREATE_COMPLETE`; neither is
authority for the current source. A later bootstrap-only execution was recovered
and destroyed, with stable zero proof retained privately. Exact live identifiers
remain only in private operator evidence.

## Historical isolated next-candidate implementation

Before the historical teardown, generation 8 was frozen while its reviewed
bootstrap change set still existed. To avoid racing or invalidating that
evidence, an ignored local work area at `target/recipe-next-work` was created
from an exact byte-for-byte generation-8 source snapshot; the matching private
digest was recorded outside the repository.
At that checkpoint, only the isolated copy contained the following work. This
subsection is retained as history and is not deployment authority:

- A `release-image-publish.yml` authority boundary that may run only from an
  exact `v0.9.x`/RC tag, consumes a successful protected candidate run by ID,
  verifies same-repository workflow/run/revision/artifact ownership, downloads
  the retained OCI archive, repeats the amd64/arm64 SBOM/provenance and
  HIGH/CRITICAL vulnerability policy, copies the exact digest without a build,
  rejects tag rebinding, signs through GitHub OIDC/Cosign, proves anonymous
  resolution/signature verification, and retains one joined publication
  record. Eight new promotion/evidence regressions pass; all actions are exact
  commit pins and the ordinary candidate workflow still has no publication
  authority.
- A recurring flagship canary workflow/controller/schema/runbook. A canary
  execution ID receives explicit `BridgefuCanary=true` and
  `BridgefuEnvironment=nonproduction` tags. The workflow is opt-in, has no PR
  or static-key path, checks out the exact deployed release, retrieves one
  exact S3 ledger object version, uses a dedicated OIDC IAM role and isolated
  stable-IP runner, executes both real Vapi/Agent Workspace hangup origins,
  proves final zero state, removes browser/ledger credentials, and uploads only
  a redacted report that cannot satisfy a release criterion.
- Durable trust normalization for GitHub/AWS assumed-role sessions. The
  lifecycle records the backing IAM role ARN, compares later sessions to that
  role, and rejects AWS root and federated-user identities.

The isolated snapshot now passes the complete 98-test flagship Python suite,
config/recipe schemas, 22-document link/runbook verification, all 17
CloudFormation templates under `cfn-lint` and Guard 3.2.0, Starter and HA
Terraform format/validate/contract tests, release-image policy, all OCI and
promotion verifiers, canary contract validation, workflow YAML plus every
shell block, strict all-target Clippy, the complete locked Rust all-target
suite, all Compose profiles, deterministic double-builds of every package,
and whitespace checks. Its immutable non-journal digest and the independently
rechecked generation-8 digest remain in private durable evidence. This staged
work is not yet part of the current AWS release and therefore cannot be cited
as generation-8 live evidence.

## Locked product and ownership decisions

- Production deployment assumes an existing Amazon Connect instance.
- The customer supplies the Connect instance ARN and target contact-flow ARN.
- The recipe creates a narrow Bridgefu-owned wrapper/entry flow and guide, then
  transfers into the customer flow without modifying it.
- Queue selection remains owned by the customer flow, so a queue ARN is not a
  normal recipe input.
- A separate full deployment may create Connect resources only for an
  acknowledged demo, test, or first-instance deployment.
- SIPS/SRTP is the production default; SIP/RTP is explicit compatibility.
- CloudFormation is the primary AWS interface. The recipe Terraform modules
  compose the same templates instead of forking their behavior.
- Kubernetes is out of scope. Starter is EC2; HA is ECS on EC2.
- CloudWatch, Systems Manager, AWS consoles, and the Bridgefu CLI are the first
  administration surface. A web console is roadmap.
- Genesys WebRTC and Google Infrastructure Manager are roadmap.

## Historical AWS live-test authorization and safety summary

Exact live-test accounts, organizations, profiles, roles, customer Connect
identifiers, execution and change-set IDs, deadlines, planning ceilings,
artifact hashes, object counts, and resource inventories are private operator
evidence. They are stored only under the durable live-state boundary outside
the repository and every build-output directory. They are intentionally not
reproduced here.

Every historical candidate is retired and is ineligible for deployment. The
bootstrap-only execution that required lost-ledger recovery was adopted under
teardown-only authority, destroyed idempotently, and verified with stable
multi-observation zero proof retained privately. It never executed an
application or qualification change set. New work must always use a fresh,
never-before-used execution ID and current account-wide preflight.

Repository-safe lessons from the historical qualification work:

- Human AWS work must use a current non-root federated identity. Root,
  long-lived IAM users, expired sessions, and identities that cannot be bound to
  a durable role fail closed.
- Customer-owned Amazon Connect instances and target flows are reference-only.
  Deployment authority must not permit their update, replacement, or deletion.
- Live authority cannot reside in a build-output directory. Ledgers, recovery
  reviews, destroy intents, inventories, and zero proofs require private durable
  storage, strict ownership and modes, immutable identity binding, locking, and
  atomic writes.
- Stack and change-set operations bind exact immutable ARNs and nested ancestry.
  A source, controller, template, or release change invalidates prior reviews;
  stale unexecuted reviews may be retired only after exact ownership checks.
- CloudFormation response fields must be modeled from returned contracts rather
  than request-only assumptions. Elastic IP public identity and allocation
  identity are independently verified.
- S3 recovery and teardown accept only explicitly modeled encryption and delete
  responses. Quiet delete success remains provisional until a fresh
  version-aware listing proves the bucket empty.
- Release publication excludes Terraform caches, local state, and unrelated
  build artifacts; enforces file-count and byte bounds; records resumable
  progress; and performs version-aware teardown.
- Qualification catalogs assert that every required test actually ran. Empty or
  misrouted test selections fail even when the underlying test binary would
  otherwise pass.
- Interrupted teardown resumes from durable intent without broadening authority.
  Completion requires repeated identical zero observations, not a single empty
  query.
- Local container builds are bounded and cleaned by exact ownership so builder
  layers cannot silently exhaust the workstation or remove unrelated images.

These lessons describe controller requirements, not current AWS authority,
capacity, or production approval.

## Historical isolated post-candidate hardening (not deployed)

The following work was developed in a historical ignored build-output snapshot
to avoid changing a candidate while its review was pending. That location was
never durable live authority, the historical review is retired, and no current
work or evidence depends on it. None of the following is live qualification
evidence:

- Added an immutable real SIPp 3.7.3 peer with strict mode-`0600` sessions,
  exact zero/one/two `X-Correlation-Id` wire cases, public-target enforcement,
  a schema-valid redacted observation, and ephemeral raw-trace deletion. The
  missing-header, duplicate-header, and expired-attachment negative gates now
  require SIPp; source cancellation remains a separate purpose-built Rust
  probe.
- Added immutable real Asterisk 20.9.3 and FreeSWITCH 1.10.12 B2BUA peers.
  Their generated configurations keep source and destination signaling/media
  postures equal, support SIP/RTP and SIPS/SRTP with PCMU or PCMA, anchor
  media, forward exactly one correlation header, use private short-lived TLS
  material, run non-root/read-only with dropped capabilities, and remove their
  exact containers and private configuration on exit.
- Extended the protected direct-call runner with `--source-peer native`,
  `asterisk`, or `freeswitch`. Real-PBX calls retain call evidence separately
  from the 20-call native/Vapi soak matrix and bind it to an independently
  hashed peer observation.
- Made interoperability mandatory for final assembly: three SIPp observations
  plus 16 PBX calls (two products × four codec/security scenarios × two hangup
  origins). Final evidence now carries peer image/revision hashes, call and
  observation hashes, latency facts, and exact provenance counts. The
  independent semantic validator rejects missing, duplicate, substituted, or
  reused peer evidence.
- Added a CI peer-image matrix that builds SIPp, Asterisk, and FreeSWITCH and
  starts each PBX in both insecure and secure lifecycle modes. The release
  runbook now distinguishes the 20 native/Vapi soak calls from the 16 PBX
  interoperability calls and documents the complete 36-call positive gate.
- Added bounded worker burst slots C/D to CloudFormation and Terraform without
  altering fixed gateway A/B. Each optional slot has an exact worker identity,
  private NLB listener/target group, 0–1 protected ASG, zero-desired ECS
  service, lifecycle hook, observability dimensions, alarm coverage, and
- Added an exact-inventory capacity Lambda, reserved to one concurrent run and
  scheduled once per minute. It scales C then D on active-route, CPU, memory,
  capacity-rejection, or aggregate-forwarding-drop pressure; it drains D then
  C only after sustained idle, zero cleanup, low resources, and continuous
  monotonic counter telemetry, and unprotects the host only after ECS reaches
  zero running and pending tasks.
- Added `required_for_readiness` worker targets and an explicit readiness
  quorum. A/B are required with minimum one ready; C/D are optional and are not
  probed while scaled to zero. Required probes run concurrently, per-worker
  connection locks isolate failed handshakes from healthy call setup, and peer
  loss triggers an immediate local quorum recomputation without starting an
  eager reconnect that could delay shutdown.
- Added aggregate forwarding-drop and private-egress capacity metrics,
  counter-reset/missing-series scale-in blocks, a counter-telemetry alarm,
  bounded-capacity alarms, dashboard series, and capacity/failover runbooks.
- Local interoperability verification completed on 2026-08-01: SIPp image
  build/version passed;
  Asterisk and FreeSWITCH each reached readiness under both SIP/RTP and
  SIPS/SRTP; all temporary peer containers were removed; the qualification
  contracts and documentation checker passed. That checkpoint passed 87/87
  flagship tests; subsequent historical HA/controller coverage raised that
  clean suite to 98/98. Real PBX calls and capacity transitions through a deployed
  AWS recipe remain external live gates.
- Final isolated-candidate verification on 2026-08-01 passed strict Clippy,
  the complete Rust all-target suite (358 library tests, 151 binary tests, all
  ordinary integration/example targets, and only predeclared credentialed or
  manual ignores), the quorum/failed-worker latency and prompt-health
  regressions, schema/docs, `cfn-lint`, Guard, Terraform Starter/HA contracts,
  release/static/shell checks, all Compose profiles, byte-identical Lambda,
  runtime, demo-site, and complete release builds, `cargo fmt`, and
  `git diff --check`. The exact candidate digest is retained only in private
  durable evidence.

## Remaining local implementation gates

These items are intentionally visible rather than hidden behind a support
claim:

1. Complete the final full regression pass, intentionally commit the reviewed
   public source, then run exactly one generation-4
   `publish --refresh-candidate`. Generation 3 is stale and incomplete. If the
   generation-4 publish requires a retry without another source change, resume
   it with ordinary `publish`. HA assets and selectors remain ineligible for
   the Starter candidate.
2. Complete and verify the owner-approved two-platform immutable OCI image and
   signed regional release/Launch Stack manifest. Local deterministic bundles
   use a test digest and are not a customer release.
3. Run the protected deployed release workflow against the exact immutable
   revision. Disposable PostgreSQL/Redis conformance, the finite 16-scenario
   chaos matrix, current-tree Chromium fixtures, and the short real-peer UCTP,
   fanout, MOQT, and media-graph smoke profiles are complete; deployed failure
   drills and their one-hour modes remain release gates.

## Qualification and production gates

The prior bootstrap-only execution is permanently retired and fully destroyed;
its stable multi-observation zero proof is retained only in private durable
state. No application change set was executed for that retired execution.
Never reuse a retired execution ID. The current fresh execution passed
its non-root preflight and exact foundation bootstrap, but no application or
qualification review/stack exists. Continue to follow the
[IP-only nonproduction live-qualification runbook](recipes/vapi-amazon-connect-screen-pop/runbooks/nonproduction-live-qualification.md).
Later controller reads still decide whether an exact permission or quota
request is needed. DNS remains outside the IP-only scope.

The following remain long-term production-roadmap gates:

1. Establish the approved dedicated management, nonproduction, and production
   account layout without placing Bridgefu workloads in management.
2. Complete Identity Center/GitHub OIDC, governance, persistent nonproduction
   Connect, billing/alarm routing, and protected account foundations.
3. Configure delegated production DNS and certificates, then pass the secure
   SIPS/SRTP production preflight and synthetic gate.
4. Keep exact historical cleanup inventories and zero-state observations in
   private durable evidence, never in repository build output.
5. Publish a new signed release from a clean committed source. Complete two
   posture-appropriate nonproduction deploy/qualification/lifecycle/teardown cycles while
   retaining only the persistent Connect and account foundations.
6. Create the production Starter change set against the configured
   customer-owned Connect instance and approved target flow. Require protected
   review, synthetic audio/screen-pop proof, recursive drift, alarms, rollback
   evidence, and an unchanged customer target flow before any customer traffic.
7. Treat Starter as a controlled pilot. HA is outside this workstream and may
   not be used to satisfy the Starter production gate.

## Next action

Keep both validated Vapi credentials process-only and finish the full local
regression pass. Then run exactly one generation-4
`publish --refresh-candidate` and verify the completed release. Next create only
the `bootstrap-refresh` review and independently audit it; do not execute the
review and do not create or execute application or qualification change sets in
that step. Only after later explicit approval, verified foundation refresh, and
a separate GO decision may engineering proceed to application review and the
nonproduction qualification, lifecycle, verification, teardown, and stable
zero-proof sequence.
