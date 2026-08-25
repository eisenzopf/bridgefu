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
browsers, editor files, operator configuration and environment files,
Compose-mounted `deploy/tls`, and common private-key and certificate formats.
It also still excludes Terraform state and caches: no Terraform remains in this
repository, but the guard costs nothing and a local experiment must never leak
state into a build context. Docker does not honor `.gitignore`; removing these
exclusions can leak local state into the builder context even when Git is clean.

There is no image release pipeline. Bridgefu publishes no container image to
any registry, and `ci.yml` is checked to make sure it never gains permission to.
CI builds the image natively per architecture, runs its healthcheck, and retains
an SBOM and a Trivy SARIF report; that is the extent of it.

A multi-platform candidate workflow used to live here. It was dispatched twice,
timed out at three hours both times without ever producing an archive, and has
been removed along with its OCI verification helpers. If Bridgefu ever needs
published images, that pipeline should be rebuilt against a build that can
actually finish -- QEMU-emulated cross-compilation of the full rvoip graph is
not it.

Allow at least 32 GB of memory and substantial build-cache space for a cold
compile of the complete rvoip graph.

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
relay services. **This topology is unproven**: it has conformance tests in CI
and no deployment evidence whatsoever. It exists so the distributed code has a
local harness. The only configuration ever run in production is a single
all-in-one instance on SQLite -- see the deployment status table in
[the repository README](../README.md). Gateway-to-worker media uses authenticated UCTP 0.2 over
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

## What is not here

There is no deployment driver, cloud module, or systemd unit in this
repository. `deploy/` builds and verifies the container image; that is all.

The one production-qualified deployment -- a Vapi SIP transfer into Amazon
Connect with a correlated agent screen pop -- is maintained in
[bridgefu-vapi-awsconnect](https://github.com/eisenzopf/bridgefu-vapi-awsconnect).
That repository pins an immutable Bridgefu commit, compiles the binary natively
inside a Packer AMI build, and ships it with CloudFormation. It does not use
this image, this directory, or anything else under `deploy/`.

If you are deploying Bridgefu yourself, build the image from
`deploy/Dockerfile` and run it with whatever orchestration you already have.
Bridgefu has only ever been operated as a **single all-in-one instance**; see
[docs/recipes.md](../docs/recipes.md) for what is and is not proven.
