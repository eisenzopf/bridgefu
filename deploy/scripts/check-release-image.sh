#!/usr/bin/env bash
set -euo pipefail

dockerfile="${1:-deploy/Dockerfile}"

test -f "$dockerfile"
test -f Cargo.lock
test -f .dockerignore
test ! -e deploy/missing-rvoip-context
if ! cmp -s Dockerfile deploy/Dockerfile; then
  echo "root Dockerfile diverged from canonical deploy/Dockerfile" >&2
  exit 1
fi

bridgefu_version="$(
  python3 - <<'PY'
from pathlib import Path
import tomllib

manifest = tomllib.loads(Path("Cargo.toml").read_text())
print(manifest["package"]["version"])
PY
)"
if ! [[ "$bridgefu_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
  echo "Cargo.toml contains an invalid Bridgefu release version" >&2
  exit 1
fi

# Docker does not honor .gitignore. Keep local agent worktrees, SDK installs,
# Terraform caches/state, and the operator's filled-in configuration out of
# every build context before COPY . reaches the builder layer.
for ignored_path in \
  '.claude/' \
  '.vscode/' \
  '**/node_modules/' \
  '**/.terraform/' \
  '**/*.tfstate' \
  '**/*.tfstate.*' \
  'terraform/terraform.tfvars' \
  'bridgefu.yaml' \
  'deploy/tls/' \
  '**/.env' \
  '**/.env.*' \
  '**/*.key' \
  '**/*.pem' \
  '**/*.crt' \
  '**/*.cer' \
  '**/*.p12' \
  '**/*.pfx' \
  '**/*.jks'; do
  if ! grep -Fxq -- "$ignored_path" .dockerignore; then
    echo "release Docker context does not exclude $ignored_path" >&2
    exit 1
  fi
done

for ignored_path in \
  '/deploy/tls/' \
  '.env' \
  '.env.*' \
  '*.key' \
  '*.pem' \
  '*.crt' \
  '*.cer' \
  '*.p12' \
  '*.pfx' \
  '*.jks'; do
  if ! grep -Fxq -- "$ignored_path" .gitignore; then
    echo "source-control policy does not exclude $ignored_path" >&2
    exit 1
  fi
done

# The canonical image must use immutable multi-platform base manifests.
base_args=$(grep -Ec '^ARG (RUST_IMAGE|RUNTIME_IMAGE)=.+@sha256:[0-9a-f]{64}$' "$dockerfile")
if [ "$base_args" -ne 2 ]; then
  echo "release Dockerfile must pin both base manifest digests" >&2
  exit 1
fi
snapshot_args=$(grep -Ec '^ARG BUILDER_DEBIAN_SNAPSHOT=[0-9]{8}T[0-9]{6}Z$' "$dockerfile")
if [ "$snapshot_args" -ne 1 ]; then
  echo "release Dockerfile must pin the Debian builder package snapshot" >&2
  exit 1
fi
if grep -Eq '^ARG RUNTIME_DEBIAN_SNAPSHOT=' "$dockerfile"; then
  echo "distroless release runtime must not carry a Debian package snapshot" >&2
  exit 1
fi
grep -Eq '^ARG RUNTIME_IMAGE=gcr\.io/distroless/cc-debian13:nonroot@sha256:[0-9a-f]{64}$' \
  "$dockerfile"
grep -Eq 'snapshot\.debian\.org/archive/debian/' "$dockerfile"
grep -Eq 'snapshot\.debian\.org/archive/debian-security/' "$dockerfile"
grep -Eq 'build-essential=[^ ]+' "$dockerfile"

runtime_run_steps="$(awk '
  /^FROM \$\{RUNTIME_IMAGE\} AS runtime$/ { in_runtime = 1; next }
  in_runtime && /^FROM / { in_runtime = 0 }
  in_runtime && /^RUN / { count++ }
  END { print count + 0 }
' "$dockerfile")"
if [ "$runtime_run_steps" -ne 0 ]; then
  echo "distroless release runtime must not execute package or shell setup" >&2
  exit 1
fi

grep -Eq '^COPY \. /src/bridgefu$' "$dockerfile"
grep -Eq 'cargo build --locked --release' "$dockerfile"
grep -Fq 'COPY --from=builder --chown=65532:65532 /out/bridgefu /usr/local/bin/bridgefu' \
  "$dockerfile"
grep -Eq '^USER 65532:65532$' "$dockerfile"
grep -Eq '^HEALTHCHECK ' "$dockerfile"
grep -Fq 'CMD ["/usr/local/bin/bridgefu", "healthcheck"]' "$dockerfile"
grep -Eq '^STOPSIGNAL SIGTERM$' "$dockerfile"
grep -Eq '^ENV SOURCE_DATE_EPOCH=' "$dockerfile"
grep -Fq 'org.opencontainers.image.source="https://github.com/eisenzopf/bridgefu"' "$dockerfile"
grep -Fq "org.opencontainers.image.version=\"$bridgefu_version\"" "$dockerfile"
grep -Eq 'org.opencontainers.image.rvoip.version="0\.3\.5"' "$dockerfile"
grep -Fq "org.opencontainers.image.version=\"$bridgefu_version\"" deploy/vapi-feasibility/Dockerfile
grep -Fq 'org.opencontainers.image.source="https://github.com/eisenzopf/bridgefu"' deploy/vapi-feasibility/Dockerfile
grep -Eq 'org.opencontainers.image.rvoip.version="0\.3\.5"' deploy/vapi-feasibility/Dockerfile
grep -Eq 'dockerfile: deploy/Dockerfile' compose.yaml
if grep -Eq 'additional_contexts:' compose.yaml deploy/vapi-feasibility/compose.local.yaml; then
  echo "Compose must build from the Bridgefu context alone" >&2
  exit 1
fi
grep -Eq 'file: bridgefu/deploy/Dockerfile' .github/workflows/ci.yml
grep -Eq 'platform: linux/amd64' .github/workflows/ci.yml
grep -Eq 'platform: linux/arm64' .github/workflows/ci.yml
grep -Fq 'Verify locked rvoip crates.io graph' .github/workflows/ci.yml
release_workflow=.github/workflows/release-image-candidate.yml
test -f "$release_workflow"
grep -Eq '^  workflow_dispatch:$' "$release_workflow"
grep -Eq '^    environment: bridgefu-release-image-candidate$' "$release_workflow"
grep -Fq 'run: bash deploy/scripts/check-release-image.sh' "$release_workflow"
grep -Eq 'platforms: linux/amd64,linux/arm64' "$release_workflow"
grep -Eq 'outputs: type=oci,dest=' "$release_workflow"
grep -Eq '^          push: false$' "$release_workflow"
grep -Eq 'provenance: mode=max' "$release_workflow"

grep -Fq 'name: Verify native runtime and healthcheck execution' .github/workflows/ci.yml
grep -Fq -- '--entrypoint /usr/local/bin/bridgefu' .github/workflows/ci.yml
grep -Fq 'healthcheck --address 127.0.0.1:19090 --path /livez' .github/workflows/ci.yml
grep -Fq "docker inspect --format '{{json .Config.Healthcheck.Test}}'" \
  .github/workflows/ci.yml

# Every deployment of the canonical distroless image must execute Bridgefu
# directly. Shell-based startup and curl healthchecks cannot work in the final
# stage and would make a successfully built image undeployable.
grep -Fq 'test: [CMD, /usr/local/bin/bridgefu, healthcheck, --path, /readyz]' compose.yaml
grep -Fq 'command     = ["CMD", "/usr/local/bin/bridgefu", "healthcheck"' \
  deploy/terraform/aws/main.tf

gcp_bridgefu_commands=$(grep -Fc 'command = ["/usr/local/bin/bridgefu"]' \
  deploy/terraform/gcp/kubernetes.tf)
if [ "$gcp_bridgefu_commands" -ne 3 ]; then
  echo "every GCP Bridgefu workload must use the direct distroless entrypoint" >&2
  exit 1
fi
if grep -Fq 'exec /usr/local/bin/bridgefu' deploy/terraform/gcp/kubernetes.tf; then
  echo "GCP Bridgefu workloads must not depend on a shell wrapper" >&2
  exit 1
fi
gcp_redis_file_refs=$(grep -Fc 'name  = "BRIDGEFU_REDIS_URL_FILE"' \
  deploy/terraform/gcp/kubernetes.tf)
gcp_ca_file_refs=$(grep -Fc 'name  = "SSL_CERT_FILE"' \
  deploy/terraform/gcp/kubernetes.tf)
gcp_ca_bundles=$(grep -Fc '> /run/bridgefu-secrets/ca-bundle.pem' \
  deploy/terraform/gcp/kubernetes.tf)
if [ "$gcp_redis_file_refs" -ne 3 ] || [ "$gcp_ca_file_refs" -ne 3 ] || \
  [ "$gcp_ca_bundles" -ne 3 ]; then
  echo "GCP Bridgefu workloads must receive file-backed Redis and CA secrets" >&2
  exit 1
fi
# Kubernetes, not this shell, expands the worker pod-name variable.
# shellcheck disable=SC2016
grep -Fq 'args    = ["--config", "/run/bridgefu-secrets/$(BRIDGEFU_CONFIG_NAME).yaml", "run"]' \
  deploy/terraform/gcp/kubernetes.tf
grep -Fq 'let path_variable = format!("{name}_FILE");' src/secret_ref.rs

grep -Eq '^          sbom: true$' "$release_workflow"
grep -Eq 'verify-multiarch-oci\.py' "$release_workflow"
grep -Eq 'verify-trivy-policy\.py' "$release_workflow"
grep -Eq 'select-oci-platform\.py' "$release_workflow"
grep -Eq 'TRIVY_PLATFORM: linux/amd64' "$release_workflow"
grep -Eq 'TRIVY_PLATFORM: linux/arm64' "$release_workflow"
if grep -Eq 'packages: write|id-token: write|push: true' "$release_workflow"; then
  echo "release-candidate workflow must not have registry/publication authority" >&2
  exit 1
fi
if grep -Eq '^  multiarch-image:$' .github/workflows/ci.yml; then
  echo "multi-architecture candidate assembly must remain manually authorized" >&2
  exit 1
fi
if grep -Eiq \
  'rvoip_revision|RVOIP_REVISION|RVOIP_DIR|repository:[[:space:]]*eisenzopf/rvoip|--build-context[[:space:]]+rvoip|build-contexts:[[:space:]]*rvoip|COPY --from=rvoip|FROM scratch AS rvoip|rvoip\.revision|[.][.]/rvoip' \
  Dockerfile deploy/Dockerfile deploy/vapi-feasibility/Dockerfile \
  compose.yaml deploy/vapi-feasibility/compose.local.yaml \
  .github/workflows/ci.yml "$release_workflow" deploy.sh \
  deploy/scripts/runtime-smoke.py; then
  echo "build and release infrastructure still references a sibling rvoip checkout or revision" >&2
  exit 1
fi

# Actions that execute in ordinary image CI or the manual release-candidate
# workflow are immutable commit pins. Human-readable version comments may
# follow the SHA, but floating tags and branches are rejected.
while IFS= read -r use; do
  if ! grep -Eq 'uses: [^@[:space:]]+@[0-9a-f]{40}([[:space:]]+#.*)?$' <<<"$use"; then
    echo "workflow action is not commit-pinned: $use" >&2
    exit 1
  fi
done < <(grep -hE '^[[:space:]]+- uses:' .github/workflows/ci.yml "$release_workflow")

# Trivy's action and scanner are separate supply-chain inputs. Keep both
# immutable and synchronized across ordinary image CI and the retained
# multi-platform candidate workflow. The previous v0.28.0 action depended on a
# removed setup-trivy tag and could not even prepare a GitHub Actions job.
trivy_action_uses="$(awk '
  /uses: aquasecurity\/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25/ {
    count++
  }
  END { print count + 0 }
' .github/workflows/ci.yml "$release_workflow")"
if [ "$trivy_action_uses" -ne 3 ]; then
  echo "all three Trivy scans must use the reviewed v0.36.0 action commit" >&2
  exit 1
fi
trivy_version_pins="$(awk '
  /^[[:space:]]+version: v0[.]70[.]0$/ { count++ }
  END { print count + 0 }
' .github/workflows/ci.yml "$release_workflow")"
if [ "$trivy_version_pins" -ne 3 ]; then
  echo "all three Trivy scans must pin scanner version v0.70.0" >&2
  exit 1
fi
sarif_severity_limits=$(grep -Ec \
  '^          limit-severities-for-sarif: "true"$' .github/workflows/ci.yml)
if [ "$sarif_severity_limits" -ne 1 ]; then
  echo "CI SARIF must apply the configured HIGH/CRITICAL exit threshold" >&2
  exit 1
fi
ci_strict_severities=$(grep -Ec '^          severity: HIGH,CRITICAL$' \
  .github/workflows/ci.yml || true)
ci_strict_exits=$(grep -Ec '^          exit-code: "1"$' \
  .github/workflows/ci.yml || true)
if [ "$ci_strict_severities" -ne 1 ] || [ "$ci_strict_exits" -ne 1 ]; then
  echo "CI image scanning must fail on every HIGH/CRITICAL finding" >&2
  exit 1
fi
candidate_all_severities=$(grep -Ec \
  '^          severity: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL$' "$release_workflow" || true)
candidate_json_reports=$(grep -Ec '^          format: json$' "$release_workflow" || true)
candidate_vuln_scanners=$(grep -Ec '^          scanners: vuln$' "$release_workflow" || true)
candidate_retained_exits=$(grep -Ec '^          exit-code: "0"$' "$release_workflow" || true)
if [ "$candidate_all_severities" -ne 2 ] || [ "$candidate_json_reports" -ne 2 ] || \
  [ "$candidate_vuln_scanners" -ne 2 ] || [ "$candidate_retained_exits" -ne 2 ]; then
  echo "candidate scans must retain all vulnerability severities for both platforms" >&2
  exit 1
fi

# rvoip-amazon-connect compiles its published protobuf schema at build time.
# The canonical builder installs protoc from its pinned Debian snapshot; the
# distroless runtime contains neither protoc nor a package manager. The
# host-based Rust CI job must provision and identify the required build tool
# before Clippy or tests can compile the registry package.
grep -Fq 'Install protobuf compiler required by rvoip-amazon-connect' \
  .github/workflows/ci.yml
grep -Fq 'sudo apt-get install --yes --no-install-recommends protobuf-compiler' \
  .github/workflows/ci.yml
grep -Fq 'protoc --version' .github/workflows/ci.yml

test -x deploy/scripts/verify-multiarch-oci.py
test -x deploy/scripts/verify-trivy-policy.py
test -x deploy/scripts/select-oci-platform.py
test -x deploy/scripts/runtime-smoke.py
python3 - <<'PY'
import ast
from pathlib import Path

for name in (
    "runtime-smoke.py",
    "select-oci-platform.py",
    "test_select_oci_platform.py",
    "verify-multiarch-oci.py",
    "test_verify_multiarch_oci.py",
    "verify-trivy-policy.py",
    "test_verify_trivy_policy.py",
):
    ast.parse(Path("deploy/scripts", name).read_text())
PY
python3 - <<'PY'
from pathlib import Path
import tomllib

lock = tomllib.loads(Path("Cargo.lock").read_text())
packages = [
    package for package in lock["package"]
    if package["name"] == "rvoip" or package["name"].startswith("rvoip-")
]
if not packages:
    raise SystemExit("Cargo.lock contains no rvoip packages")
invalid = [
    (package["name"], package["version"], package.get("source"))
    for package in packages
    if package["version"] != "0.3.5"
    or not package.get("source", "").startswith("registry+")
]
if invalid:
    raise SystemExit(f"Cargo.lock has non-registry or non-0.3.5 rvoip packages: {invalid}")
required = {
    "rvoip-amazon-connect",
    "rvoip-auth-core",
    "rvoip-core",
    "rvoip-media-core",
    "rvoip-moq",
    "rvoip-quic",
    "rvoip-redis",
    "rvoip-sip",
    "rvoip-uctp",
    "rvoip-webrtc",
    "rvoip-webrtc-stack",
}
missing = required - {package["name"] for package in packages}
if missing:
    raise SystemExit(f"Cargo.lock is missing required rvoip packages: {sorted(missing)}")
PY
grep -Eq 'runtime-smoke\.py' .github/workflows/ci.yml
grep -Eq 'bridgefu-runtime-smoke-' .github/workflows/ci.yml
grep -Eq '^EnvironmentFile=/etc/bridgefu/image.env$' deploy/bridgefu.service
grep -Eq -- '--read-only' deploy/bridgefu.service
grep -Eq -- '--user 65532:65532' deploy/bridgefu.service
grep -Eq -- '--env-file /etc/bridgefu/runtime.env' deploy/bridgefu.service
grep -Eq '\$\{BRIDGEFU_IMAGE\}' deploy/bridgefu.service
if grep -q 'bridgefu:latest' deploy/bridgefu.service; then
  echo "systemd unit must not use a floating image tag" >&2
  exit 1
fi

bash -n deploy.sh deploy/scripts/*.sh
grep -Fq ": \"\${BRIDGEFU_REVISION:?" deploy.sh
grep -Fq ": \"\${RUNTIME_ENV:?" deploy.sh
grep -Fq "git -C \"\$REPO_ROOT\" archive" deploy.sh
grep -Fq 'readonly RVOIP_VERSION=0.3.5' deploy.sh
grep -Fq -- '--iidfile' deploy.sh
grep -Fq '/etc/bridgefu/image.env' deploy.sh
grep -Fq '/readyz' deploy.sh
grep -Fq '/livez' deploy.sh
if grep -Eq -- '--delete|bridgefu:latest|/healthz' deploy.sh; then
  echo "deploy.sh contains a destructive sync, floating image, or stale health route" >&2
  exit 1
fi

while IFS= read -r image; do
  case "$image" in
    bridgefu:local | *@sha256:*) ;;
    *)
      echo "Compose image is not immutable: $image" >&2
      exit 1
      ;;
  esac
done < <(docker compose --profile cluster --profile generic config --images)

# Compose must preserve the runtime hardening contract for every Bridgefu role.
for profile in standardcharter generic telnyx uctp moqt cluster; do
  rendered=$(docker compose --profile "$profile" config)
  if ! grep -q 'read_only: true' <<<"$rendered"; then
    echo "profile $profile lost read-only root filesystem" >&2
    exit 1
  fi
  if ! grep -q 'no-new-privileges:true' <<<"$rendered"; then
    echo "profile $profile lost no-new-privileges" >&2
    exit 1
  fi
  if ! grep -q 'cap_drop:' <<<"$rendered"; then
    echo "profile $profile lost its capability-drop policy" >&2
    exit 1
  fi
done
