# Deployment assets

`deploy/Dockerfile` is the canonical release image definition. It requires an
exact rvoip checkout as the named `rvoip` build context, runs as UID/GID 65532,
and supports a read-only root filesystem. Its Rust and Debian bases are pinned
to multi-platform manifest digests. Builder and runtime packages come from
separate immutable Debian snapshots with explicit top-level package versions;
`Cargo.lock`, the source revisions, commit-derived build date, and
`SOURCE_DATE_EPOCH` complete the reproducible input record. This is a
reproducible-input contract, not an unsupported claim that rustc produces a
byte-identical layer on every BuildKit version and host.

## Local profiles

Only one edge profile should be active at a time because each binds the same
SIP, WebRTC, API, and QUIC ports:

```sh
docker compose --profile standardcharter config --quiet
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

Telnyx additionally requires `TELNYX_API_KEY`, `TELNYX_WEBHOOK_PUBLIC_KEY`,
`TELNYX_CONNECTION_ID`, `TELNYX_FROM`, `TELNYX_MEDIA_SIP_AUTHORITY`, and
`TELNYX_MEDIA_SIP_PASSWORD`. `TELNYX_MEDIA_SIP_USERNAME` defaults to
`telnyx-media`; realm and transport default to `bridgefu` and `UDP`. The API
key, webhook key, and media password remain `env:` references in the effective
Bridgefu configuration. StandardCharter requires a real configuration path in
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
evidence records Bridgefu and sibling rvoip revisions, tracked and untracked
dirty state, and the exact resolved WebRTC, RTC, and moq-transport lockfile
inputs without copying repository paths or dependency URLs:

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
contents are not copied into Terraform state.

Static validation never applies infrastructure. Credentialed smoke tests must
use disposable projects/accounts and run `terraform destroy` even after a
failed assertion. Ordinary CI builds each architecture natively, generates an
independent SPDX SBOM, and rejects HIGH or CRITICAL vulnerabilities.

One combined digest is assembled only by the manual
`release-image-candidate.yml` workflow. Configure required reviewers on its
`bridgefu-release-image-candidate` environment before treating a run as
authorized evidence. The workflow accepts full Bridgefu and rvoip commit IDs,
has read-only repository permission, has no package or OIDC publication
permission, and always uses `push: false`. It retains one OCI layout containing
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

`deploy.sh` packages source with `git archive`; it requires exact
`BRIDGEFU_REVISION` and `RVOIP_REVISION` commit IDs, verifies them locally, and
expands them into a new remote release directory. It never rsyncs with
`--delete` and never mutates an existing rvoip checkout. `RVOIP_DIR` defaults to
the sibling `../rvoip` only as a local source of the explicitly requested
commit. The Docker build captures an immutable local image ID in
`/etc/bridgefu/image.env`, then requires `/readyz` and `/livez`; a failed check
restores the previous config and image ID when one exists.
`RUNTIME_ENV` is required so `env:` secret references are passed to the
container without embedding values in the YAML or image; it is installed with
mode 0600 and restored together with the config during rollback.
