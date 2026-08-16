# Deployment assets

`deploy/Dockerfile` is the canonical release image definition. It resolves the
exact crates.io `rvoip` 0.3.8 package set from the committed `Cargo.lock`; no
separate rvoip checkout or named build context is required. The image runs as
UID/GID 65532 and supports a read-only root filesystem. Its Rust and Debian
bases are pinned to multi-platform manifest digests. Builder packages come from
an immutable Debian snapshot with explicit top-level package versions. The
final stage is the package-manager-free distroless Debian 13 `cc` runtime: it
contains no shell or curl, and `bridgefu healthcheck` probes `/livez` without
loading configuration or secrets. `Cargo.lock` registry checksums, the Bridgefu
source revision, commit-derived build date, and `SOURCE_DATE_EPOCH` complete the
reproducible input record. This is a reproducible-input contract, not an
unsupported claim that rustc produces a byte-identical layer on every BuildKit
version and host.

## Release build hosts and targets

The production artifacts are Linux containers for two 64-bit platforms:

- `linux/amd64` covers both AMD and Intel x86-64 processors.
- `linux/arm64` covers AArch64 servers and Apple Silicon through Docker's Linux
  virtual machine. No 32-bit CPU target is released.

macOS on Apple Silicon or Intel and Linux on either supported architecture can
act as build hosts. A native single-platform build needs Docker. A combined
candidate needs BuildKit with the Docker Buildx plugin; building the non-native
platform on one host additionally needs QEMU/binfmt emulation. Native builders
for both architectures are preferred for ordinary CI because they are faster
and remove emulation from each architecture's compile result. Python 3 runs the
OCI verifiers, and Trivy enforces the retained vulnerability policy. ShellCheck
is required for the complete static CI replica.

Run the static contract before sending any context to Docker:

```sh
bash deploy/scripts/check-release-image.sh
```

`.dockerignore` deliberately excludes local agent worktrees, SDK installs and
browsers, Terraform caches/state, editor files, operator configuration and
environment files, Compose-mounted `deploy/tls`, and common private-key and
certificate formats. Docker does not honor `.gitignore`; removing these
exclusions can leak local state into the builder context even when Git is clean.

The protected `release-image-candidate.yml` workflow is the authoritative way
to build the non-published `linux/amd64,linux/arm64` OCI archive with embedded
SBOM and provenance and per-platform Trivy reports. It accepts only an exact
clean 40-character commit, has no registry write permission, and retains the
verified archive as a review artifact. A local host may reproduce that workflow
with Buildx, QEMU, Python 3, and Trivy, but a native `docker build` proves only
the host architecture.

Allow at least 32 GB of memory and substantial build-cache space for a cold
compile of the complete rvoip graph. A 32-vCPU, 128-GB RAM, 1.2-TB Linux runner
is comfortably sized for parallel native jobs and retained OCI evidence.

## Local profiles

Only one edge profile should be active at a time because each binds the same
SIP, WebRTC, API, and QUIC ports:

```sh
docker compose --profile reference-tenant config --quiet
docker compose --profile generic config --quiet
docker compose --profile telnyx config --quiet
docker compose --profile uctp config --quiet
docker compose --profile moqt config --quiet
```

The `cluster` profile defines PostgreSQL, TLS Redis, gateway, worker, and MOQT
relay services. Gateway-to-worker media uses authenticated UCTP 0.2 over
mutually authenticated QUIC. Redis and that private transport require
caller-owned certificates at `BRIDGEFU_TLS_DIR` (`ca.crt`,
`redis.{crt,key}`, `gateway.{crt,key}`, `public-uctp.{crt,key}`,
`public-api.{crt,key}`, and `worker.{crt,key}`); private keys are never
committed. The public API certificate is reused by the gateway's rvoip WSS and
WHIP/WHEP HTTPS listeners. The helper below creates disposable
localhost/Compose certificates for Redis, private forwarding, public UCTP,
and public HTTPS/WSS/WHIPS. The MOQT relay additionally
needs its separately scoped publisher/server material before the entire
cluster profile can become healthy. This profile is an integration topology,
not a production security boundary.

```sh
deploy/scripts/create-local-redis-tls.sh /tmp/bridgefu-redis-tls
BRIDGEFU_TLS_DIR=/tmp/bridgefu-redis-tls \
  docker compose --profile cluster config --quiet
```

### Route-catalog upgrade drain

Split gateway/worker assignments persist the exact SHA-256 identity of their
route and codec catalog. Bridgefu deliberately does not treat a legacy
assignment without that identity as compatible with a fingerprinted worker,
and it does not treat one fingerprint as compatible with another. Before the
first fingerprinted deployment, or before changing any named route, outbound
profile revision, target, transport, or codec catalog, stop new call admission
and drain every affected stable worker ID to zero unreleased assignments. Also
allow its terminal cleanup/outbox work to finish before restarting the worker
or gateway with the changed catalog.

Worker registration fails explicitly when the same worker ID still owns an
unreleased legacy or differently fingerprinted assignment. Do not rotate the
worker ID to bypass this gate: that strands the old assignment instead of
making it compatible. If a complete drain cannot be demonstrated, abort the
upgrade and keep or restore the exact preceding catalog. Release evidence must
retain the zero-reservation drain observation, successful same-catalog worker
registration, and rejection of a deliberately mismatched registration.

Telnyx additionally requires `TELNYX_API_KEY`, `TELNYX_WEBHOOK_PUBLIC_KEY`,
`TELNYX_CONNECTION_ID`, `TELNYX_FROM`, `TELNYX_MEDIA_SIP_AUTHORITY`, and
`TELNYX_MEDIA_SIP_PASSWORD`. `TELNYX_MEDIA_SIP_USERNAME` defaults to
`telnyx-media`; realm and transport default to `bridgefu` and `UDP`. The API
key, webhook key, and media password remain `env:` references in the effective
Bridgefu configuration. The reference tenant requires a real configuration path in
`BRIDGEFU_CONFIG` and the normal AWS credential chain. The generic profile
starts Coturn and requires explicit TURN credentials and an advertised address
outside loopback.

CI and local maintainers can validate the rendered service environments
without credentials or containers. The checker injects clearly marked,
non-secret placeholders, requires all executable services to pass Bridgefu's
own strict configuration and role preflight, and confirms provider and private
forwarding credentials remain secret references:

```sh
cargo build --locked --bin bridgefu
python3 config/check-compose-profiles.py target/debug/bridgefu
```

The bounded credential-free runtime smoke combines that preflight with exact
process-runner dispatch, real loopback `/livez`/`/readyz` lifecycle behavior,
worker and gateway drain, relay diagnostics authentication, and concrete mTLS
UCTP private forwarding. It also runs hermetic durable-call, bidirectional
media, context/DataMessage, and shared-source broadcast lifecycle checks. It
writes only hashes and byte counts for command output and removes
cloud/provider/test-database credentials from child environments. Source
evidence records the Bridgefu revision and tracked/untracked dirty state, plus
the exact resolved crates.io rvoip, WebRTC, RTC, and MOQT package versions and
checksums from `Cargo.lock`, without copying repository paths or dependency
URLs:

The child environment strips all `BRIDGEFU_*`, `RVOIP_*`, `OTEL_*`, cloud,
provider, and arbitrary Cargo/Rust behavior variables inherited from the
operator. It restores only the smoke's fixed Cargo/Rust settings while
retaining required toolchain/location variables such as `PATH`, `HOME`,
`CARGO_HOME`, and `RUSTUP_HOME`.

```sh
python3 deploy/scripts/runtime-smoke.py \
  --binary target/debug/bridgefu \
  --output /tmp/bridgefu-runtime-smoke.json
```

The report deliberately sets `release_criterion_satisfied` to `false`: this
smoke does not place a carrier call, exchange public media/context, exercise a
deployed relay, run release-scale load, or apply cloud infrastructure.

## Cloud modules

`terraform/aws` and `terraform/gcp` are intentionally modules: callers own
state backends, DNS, certificate issuance, organization policies, and secret
values. Copy each module's `terraform.tfvars.example` and replace every
placeholder. The AWS module rejects tagged images and exposes the security
group that must be attached to every instance in the supplied ECS capacity
provider. The GCP module references an existing Secret Manager secret so its
contents are not copied into Terraform state. Its init containers fetch the
Redis URL and private CA into a memory-backed volume, build the combined trust
bundle, and pass only file paths to the shell-free Bridgefu workload. Existing
`env:BRIDGEFU_REDIS_URL` config references resolve through the standard
`BRIDGEFU_REDIS_URL_FILE` fallback; a direct environment value still wins.

Static validation never applies infrastructure. Credentialed smoke tests must
use disposable projects/accounts and run `terraform destroy` even after a
failed assertion. Ordinary CI builds each architecture natively, generates an
independent SPDX SBOM, and rejects HIGH or CRITICAL vulnerabilities.

One combined digest is assembled only by the manual
`release-image-candidate.yml` workflow. Configure required reviewers on its
`bridgefu-release-image-candidate` environment before treating a run as
authorized evidence. GitHub accepts `workflow_dispatch` only after the workflow
definition exists on the default branch, so the owner-reviewed candidate must
first land on `main`; pushing a candidate branch alone does not make this gate
runnable. Dispatch the landed workflow with that exact 40-character candidate
commit. The workflow builds the exact crates.io dependency graph recorded in
its `Cargo.lock`; it has
read-only repository permission, has no package or OIDC publication permission,
and always uses `push: false`. It retains one OCI layout containing
`linux/amd64` and `linux/arm64`; BuildKit embeds SPDX SBOM and SLSA provenance
statements. The verifier accepts only the layout root or one top-level image
index (never a reachable child manifest), verifies every blob, binds each
statement to its exact platform manifest, and requires both predicates for
both platforms. Trivy scans minimal exact-platform layouts derived from that
same archive, and the retained policy report rejects HIGH or CRITICAL findings.
These BuildKit statements are registry-compatible build evidence, not a signed
public provenance record. Publishing the image or an external attestation
requires separate owner authorization.

## systemd host mode

`bridgefu.service` retains host networking for the explicit RTP range but uses
the same nonroot, read-only, capability-free container contract. Before
starting it, install the configuration and an immutable image reference:

```sh
install -m 0600 bridgefu.yaml /etc/bridgefu/bridgefu.yaml
install -m 0600 bridgefu-runtime.env /etc/bridgefu/runtime.env
printf '%s\n' 'BRIDGEFU_IMAGE=registry.example/bridgefu@sha256:…' \
  > /etc/bridgefu/image.env
systemctl daemon-reload
systemctl enable --now bridgefu
```

`deploy.sh` packages Bridgefu source with `git archive`; it requires and
verifies an exact `BRIDGEFU_REVISION`, expands it into a new remote release
directory, and runs `cargo build --locked` inside the canonical image. The
exact rvoip 0.3.8 inputs come from crates.io and are verified against the
checksums in the committed `Cargo.lock`; `RVOIP_DIR` and `RVOIP_REVISION` are
not deployment inputs. The Docker build captures an immutable local image ID in
`/etc/bridgefu/image.env`, then requires `/readyz` and `/livez`; a failed check
restores the previous config and image ID when one exists.
`RUNTIME_ENV` is required so `env:` secret references are passed to the
container without embedding values in the YAML or image; it is installed with
mode 0600 and restored together with the config during rollback.
