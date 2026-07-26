# bridgefu

## Start here

This working tree contains both the preserved Vapi-to-Amazon gateway and a
larger Bridgefu 1.0 call-control platform. Use these three review artifacts
before reading the subsystem documentation:

- [Product overview](docs/product-overview.md) explains the exactly-two-leg
  model and the two intended Vapi/Amazon call journeys.
- [Complete Vapi/browser/Amazon configuration](config/browser-vapi-amazon-handoff.example.yaml)
  puts the fixed SIP transfer, secure named transfer, and browser-first
  handoff into one annotated all-in-one example. It contains placeholders and
  has deliberately not been executed.
- [Comprehensive changelog](CHANGELOG.md) inventories the work in this release
  candidate, calls out compatibility changes and open gates, and provides a
  subsystem review index.

Bridgefu is a programmable Rust SIP/RTP ↔ WebRTC/RTP bridge and the reference
application for rvoip. It preserves the Vapi → Amazon Connect screen-pop path,
adds a normal rvoip SIP/WebRTC runtime, native Telnyx call control,
safe SIP-header/DataChannel context envelopes, and UCTP or MOQT audio fanout.
Twilio and Vonage provider control are deferred beyond 1.0.

UCTP direct fanout and local/static MOQT relay topologies are executable. The
clustered API-created MOQT namespace policy remains fail-closed until the
private moq-rs admission patch is owner-reviewed, immutably pinned, and
requalified; the tree does not yet claim arbitrary production relay fanout.

```
PSTN caller ─▶ Vapi app ─(SIP transfer/REFER with X- headers)─▶ bridgefu
            ─▶ Amazon Connect (StartWebRTCContact, attributes drive the screen pop)
            ─▶ live agent (CCP rings, screen pop populated, two-way audio)
```

The diagram is the frozen SIP-transfer contract, not a claim that a stock Vapi
website `webCall` is qualified end to end. Browser-to-call-center support is
tracked separately for Vapi-managed and direct Bridgefu WebRTC ingress in the
[full-duplex support matrix and gap gates](docs/roadmap.md#vapi-widget-to-call-center-full-duplex-release-gap).
The externally credentialed stock-widget transfer feasibility run is pending;
no widget path is represented as supported until its exact automated and live
evidence is green.

The core data plane is an rvoip `MediaGraph`, so a call peer and both broadcast
types can observe one source without competing for its receiver. See
[architecture](docs/architecture.md), [security](docs/security.md), the
[observability contract](docs/observability.md), and the
[provider matrix](docs/provider-capabilities.md). A typed call, transfer, DTMF,
and broadcast walkthrough is in the [v1 API quick start](docs/api.md).

This tree is an implementation branch toward 1.0, not a GA performance claim.
The ordered implementation gates and their evidence are tracked in the
[Bridgefu 1.0 roadmap](docs/roadmap.md). Protocol and load requirements are
also documented in
[protocol compatibility](docs/protocol-compatibility.md) and
[BENCHMARKS.md](BENCHMARKS.md).
Existing installations should follow the additive
[v1 migration guide](docs/migration-v1.md) before enabling generic bridging or
broadcasts.
The Gate 6 SQL transaction model and its deterministic PostgreSQL runner are
documented in [durable repository backends](docs/repository-backends.md).
The currently executable role-separated public edge and its deliberately
fail-closed surface boundary are documented in
[split gateway UCTP ingress](docs/gateway-uctp-ingress.md).
The protected StandardCharter staging procedure is documented in the
[non-production smoke, drain, and rollback runbook](docs/standardcharter-smoke-runbook.md).

MOQT draft-19 qualification is recorded in the
[independent interop report](docs/moq-independent-interop.md),
[real-browser WebTransport report](docs/moq-browser-interop.md),
[packet-capture report](docs/moq-packet-capture.md), and the private
[fork review packet](docs/moq-fork-review.md). No upstream submission has been
made.

The separate, unintegrated WebRTC/RTC TURN candidate and its owner-review gate
are recorded in the private [WebRTC fork review packet](docs/webrtc-fork-review.md).
It has not been pinned, pushed, or submitted upstream.

Bridgefu is MIT licensed. Development and security-reporting expectations are
in [CONTRIBUTING.md](CONTRIBUTING.md); unreleased compatibility changes are in
[CHANGELOG.md](CHANGELOG.md).

Release load runs are intentionally manual and retain versioned evidence; see
[release qualification](docs/qualification.md). A short smoke run never counts
as the one-hour release gate.

---

## How it's built and deployed

- Development uses a sibling `../rvoip` workspace because several reusable
  crates are not yet published. Release inputs name exact Bridgefu and rvoip
  revisions; floating branches are not release inputs.
- The multi-stage image supports `linux/amd64` and `linux/arm64`, runs as a
  non-root user, and is compatible with a read-only root filesystem. The
  protected release-candidate workflow assembles one OCI index and verifies
  its platform manifests, SBOMs, provenance statements, and vulnerability
  policy without granting registry publication authority.
- Compose profiles cover StandardCharter, generic SIP↔WebRTC, Telnyx, UCTP,
  MOQT, PostgreSQL/Redis, and Coturn. The executable process roles are
  `all-in-one`, `gateway`, `worker`, and `moq-relay`; see
  [deployment details](deploy/README.md) for the exact supported edge surfaces.
- Terraform roots under `deploy/terraform/aws` and `deploy/terraform/gcp`
  define role-separated ECS-on-EC2 and GKE deployments. They are statically
  validated but deliberately require an owner-authorized disposable account
  or project before `apply` and smoke evidence can be called complete.
- `deploy.sh` and the systemd unit remain as an isolated legacy
  StandardCharter deployment path. They are not the reference clustered
  topology.

---

## Prerequisites

For local containers and validation:

- Docker with Compose; Buildx is required only for the retained multi-platform
  release-candidate artifact.
- Rust stable when running the source test suites directly.

For an owner-authorized cloud deployment:

- [Terraform](https://developer.hashicorp.com/terraform/downloads) ≥ 1.5
- The AWS CLI v2 or Google Cloud CLI, authenticated to the disposable target.
- Provider credentials supplied only through the documented secret references.

The StandardCharter profile additionally requires an Amazon Connect instance
with the screen-pop contact flow described below.

---

## AWS authentication

Two distinct credential paths:

1. **Terraform or the legacy deploy script** uses your local AWS identity to
   create only the resources in the selected root. Provide it through the
   normal AWS CLI/SDK chain:

   ```bash
   export AWS_PROFILE=your-profile          # or:
   export AWS_ACCESS_KEY_ID=...
   export AWS_SECRET_ACCESS_KEY=...
   export AWS_REGION=us-west-2              # match var.region
   ```

   The reference AWS root needs the Terraform operations required for VPC/EC2,
   ECS, ELB, RDS, ElastiCache, IAM, Secrets Manager, CloudWatch, and
   autoscaling. The isolated legacy single-EC2 root needs only its documented
   EC2/VPC/EIP/IAM and SSM-read subset. Use a disposable account and scope the
   identity to the selected root rather than granting a permanent broad role.

2. **Bridgefu at runtime** uses its ECS task role (or the legacy EC2 instance
   role). No AWS keys live in YAML or in the image. The reference runtime role
   scopes `connect:DescribeContact`, `connect:StartWebRTCContact`, and
   `connect:StopContact` to configured Connect instance/contact resources; the
   legacy proof-of-concept role has only Start/Stop and still requires tighter
   resource scoping. The daemon resolves credentials through the standard AWS
   chain.

---

## Amazon Connect setup

You need two IDs for `bridgefu.yaml`:

- **`instance_id`** — Amazon Connect → your instance → the instance ID (a UUID).
- **`contact_flow_id`** — the contact flow that handles the inbound contact and
  performs the screen pop (a UUID, visible in the flow's URL / ARN).

The mapped attribute keys must match what the flow's *Check contact attributes*
block reads. The hosted widget surfaces them as `$.Attributes.HostedWidget-<name>`,
which is why the default `rename` map targets `HostedWidget-*` keys — so the same
screen pop is reused. Edit the `mapping.rename` table in your config to match your
flow.

See [docs/amazon-connect.md](docs/amazon-connect.md) for the full setup: finding the
IDs, the attribute-mapping contract, what the contact flow must read, verifying the
`X-` header path (PRD FR6), and common errors.

---

## Configuration

`bridgefu` reads one YAML file (`/etc/bridgefu/bridgefu.yaml` on the instance).
Copy the example and edit:

```bash
cp config/bridgefu.example.yaml bridgefu.yaml
$EDITOR bridgefu.yaml          # set aws.region + instance_id + contact_flow_id
```

Leave `sip.advertised_ip` and `sip.media_public_ip` as `auto` — on EC2 the daemon
resolves the public (Elastic) IP via IMDSv2. AWS credentials are **never** in this
file. See [config/bridgefu.example.yaml](config/bridgefu.example.yaml) for every
field. Every scalar can be overridden with a double-underscore environment key,
for example `BRIDGEFU__RUNTIME__MAX_CONCURRENT_CALLS=200`. Configuration keys
are strict at every depth, so a misspelled file or environment-override key
fails startup instead of being ignored. `print-effective-config` validates that
typed shape and redacts secret references without requiring those secrets to be
provisioned first; `validate` resolves secrets and performs the full runtime
preflight.

The non-secret
[StandardCharter managed-route fixture](config/fixtures/standardcharter-managed-routes.yaml)
defines the paired `amazon-connect`, `generic-sip`, `telnyx`, and `generic-wss`
routes, both approved ingress modes, and only `env:` credential references. Its
[StandardCharter environment half](config/fixtures/standardcharter-managed-routes.env)
keeps legacy rollback explicitly scoped to the default Amazon route. The schema
check validates both files and their shared route catalog in CI.

```bash
bridgefu --config bridgefu.yaml validate
bridgefu --config bridgefu.yaml print-effective-config  # secrets redacted
```

The versioned API is served with health and Prometheus on the configured HTTP
bind. Provider webhooks authenticate with provider signatures; all other `/v1`
routes require the configured `api.bearer_token`.

Transactional call routes additionally require `api.control_hmac_key` (at
least 32 bytes). With the compatibility shared API key, set
`api.static_tenant` when more than one tenant is configured. Mutating call
requests require exactly one visible-ASCII `Idempotency-Key` header; receipts
are tenant-bound and retained for 24 hours. `POST /v1/calls` accepts exactly two
typed SIP, WebRTC, WHIP/WHEP, Amazon Connect, or provider-controlled legs.
Outbound SIP endpoints may set `initial_context: required`; that opt-in keeps
the first INVITE completely dormant until an exact source connection delivers
one valid, durable `bridgefu.context.v1` envelope. The default is `none`, so
existing callers retain immediate SIP origination. Initial allowlisted values
become ordered INVITE headers, while later valid context uses SIP MESSAGE.
Startup validation resolves the control-key reference, verifies its byte
length without rendering it, and rejects a static tenant that is not present
in the configured routing table. Transactional state uses durable SQLite by
default (`persistence.backend: sqlite`) and retains one stable standalone
worker identity across restarts. PostgreSQL requires both a secret-referenced
`database_url` and a distinct stable `worker_id` per worker. A requested SQL
backend fails startup on connection, migration, or worker-registration errors;
it never falls back to memory. The memory backend is dev/test-only and requires
both `backend: memory` and `allow_ephemeral_memory: true`. Connection URLs and
control keys are redacted from effective configuration and diagnostics.
Attachment-principal resolution and worker
placement share the original setup budget; Bridgefu commits no call or worker
capacity after that budget or the two-minute attachment window is exhausted.
Missing API authentication makes every protected route fail closed with `503`;
missing call-control key material makes the call routes fail with `503`. The
existing StandardCharter listener and public health/metrics endpoints continue
to start normally. A separate durable `sip:<tenant>` StandardCharter canary is
available only through the explicitly enabled
`generic_bridge.standardcharter_canary` policy; it requires the exact trusted
principal, tenant, scopes, and one mapped `X-Correlation-Id`, then consumes the
same single-use attachment proof as every other inbound leg. Legacy Amazon-call broadcasts and screen-pop diagnostics
remain available in an unambiguous single-tenant runtime. In a multi-tenant
runtime they fail closed until those legacy resources carry durable tenant
ownership; broadcast reads, token creation, and deletion always require the
authenticated tenant to match the stored broadcast owner.

```bash
curl -H "Authorization: Bearer $BRIDGEFU_API_TOKEN" \
  http://127.0.0.1:9090/v1/providers/telnyx/capabilities
```

---

## Legacy StandardCharter single-EC2 deployment

The commands below preserve the original StandardCharter proof-of-concept
path. They do not deploy the Bridgefu 1.0 gateway/worker/MOQT-relay topology.
For the reference container profiles and the statically validated AWS ECS and
GCP GKE roots, start with [deployment details](deploy/README.md) and
`deploy/terraform/{aws,gcp}`. Cloud apply/smoke/destroy remains an
owner-authorized release gate.

```bash
# 1. Stand up the infra.
cd terraform
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars       # public_key, admin_cidr, region (and optionally sip_cidrs)
terraform init
terraform apply

# 2. Grab the Elastic IP and other outputs.
terraform output
#   public_ip      = "<EIP>"
#   sip_uri        = "sip:<EIP>:5060"
#   ...

# 3. Fill in your config (from the repo root).
cd ..
cp config/bridgefu.example.yaml bridgefu.yaml
$EDITOR bridgefu.yaml

# 4. Build on the instance + start the service.
INSTANCE_IP=$(terraform -chdir=terraform output -raw public_ip) \
SSH_KEY=~/.ssh/id_ed25519 \
CONFIG=./bridgefu.yaml \
./deploy.sh
```

`deploy.sh` syncs the source, builds the image on the instance, installs the
systemd unit, restarts the service, and polls `/healthz`. The first run includes
the cold rvoip build — expect several minutes.

### Verify

```bash
curl http://<EIP>:9090/healthz                       # -> ok   (from admin_cidr)
ssh ec2-user@<EIP> 'sudo journalctl -u bridgefu -f'  # SIP UAS "listening"
```

---

## Point Vapi at it

Configure your Vapi app's SIP transfer/REFER target to:

```
sip:<EIP>:5060
```

attaching the custom headers your flow expects, e.g.:

```
X-Vapi-Customer-Id: <id>
X-Vapi-Call-Id:     <id>
X-Account-Tier:     <tier>
```

These map (per `mapping.rename`) to `HostedWidget-customerId` /
`HostedWidget-vapiCallId` / `HostedWidget-accountTier` contact attributes.

A successful protected test (PRD §9) uses synthetic non-sensitive metadata and
retains only redacted lifecycle evidence: authenticated INVITE accepted,
nonzero mapped-attribute count, StartWebRTCContact success, Chime connected,
bridge active, CCP screen pop populated, bidirectional audio, and exact teardown.
Raw SIP headers, attribute values, tokens, and contact identifiers are not log
evidence.

---

## Operations

```bash
ssh ec2-user@<EIP>
sudo systemctl status bridgefu
sudo systemctl restart bridgefu          # apply a new config
sudo journalctl -u bridgefu -f           # follow logs (structured JSON)
docker logs bridgefu                     # same, via docker

curl http://<EIP>:9090/metrics           # Prometheus (from admin_cidr)
#   bridgefu_active_sessions
#   bridgefu_contacts_started_total
#   bridgefu_failures_total
#   + rvoip's internal counters
```

To redeploy after a code or config change, just re-run `deploy.sh`.

---

## Security

Do not expose signaling until the configured carrier and identity policies are
in place:

- The legacy root restricts SIP signaling with `sip_cidrs`; its defaults are
  the two documented Vapi signaling `/32` addresses. Replace them with the
  exact carrier ranges for your deployment. RTP uses the separate `rtp_cidr`
  and defaults to `0.0.0.0/0` because Vapi media source addresses are dynamic;
  established-session checks do not replace network-level protection.
- SSH (22) and metrics (9090) are restricted to `admin_cidr` — set this to your IP.
- The legacy IAM policy uses `Resource = "*"` for its two Connect actions.
  Scope it to the specific instance and contact resources before use; the
  reference AWS root already accepts explicit instance ARNs.
- Use SIPS/SRTP or private carrier networks where required. See the complete
  [security model](docs/security.md).

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `docker build` killed / OOM (SIGKILL, signal 9) | Build host ran out of RAM. The full rvoip tree needs real memory — use `t4g.2xlarge` (32 GB) or larger; don't build on a 2 GB box. |
| `package X requires rustc 1.9x` | The AWS SDK crates float their MSRV above rvoip's declared 1.88. `deploy/Dockerfile` pins the builder to `rust:1.95`; bump it if a future `cargo update` raises the floor again. |
| First build very slow | Expected — the full rvoip tree compiles once. Redeploys reuse cached layers. |
| `IMDS request timed out (not on EC2?)` | You're running off-EC2, or IMDSv2 is blocked. Set literal IPs for `advertised_ip` / `media_public_ip` instead of `auto`. |
| Expected `X-` context is absent | Do not enable raw-header or attribute-value logging. Use synthetic values in the protected non-production workflow, inspect redacted context/admission counters and traces, and run the hermetic StandardCharter contract test to isolate mapping from carrier delivery. |
| `AccessDenied` on StartWebRTCContact | Region mismatch (config vs Connect instance) or the contact flow isn't WebRTC-enabled; confirm `instance_id`/`contact_flow_id`. |
| No audio / one-way audio | RTP may be blocked — confirm `sip_cidrs` allows carrier signaling, `rtp_cidr` and UDP 16384–32767 match the media policy, and the EIP is advertised in SDP. |

---

## Local development

```bash
# Builds against ../rvoip (path dep). Requires the rvoip workspace checked out
# as a sibling of this repo.
cargo build
export BRIDGEFU_API_TOKEN=dev-api-token
export BRIDGEFU_CONTROL_HMAC_KEY=change-this-32-byte-control-key-now
export BRIDGEFU_BROADCAST_TOKEN_SECRET=dev-broadcast-secret-change-me-32-bytes
cargo run -- --config config/bridgefu.example.yaml validate

# Build/run the non-root, read-only-capable image (BuildKit required).
docker compose up --build
```

## Layout

```
src/                      API, provider adapters, runtimes, config, observability
config/bridgefu.example.yaml
Dockerfile                reproducible multi-stage non-root image
compose.yaml              local all-in-one deployment
deploy/bridgefu.service   systemd unit (docker run --network host, Restart=always)
deploy.sh                 sync -> build-on-instance -> restart -> healthcheck
terraform/                legacy StandardCharter single-EC2 root
deploy/terraform/aws/     reference ECS/EC2 gateway, worker, relay, RDS, Redis
deploy/terraform/gcp/     reference GKE gateway, worker, relay, SQL, Redis
```
