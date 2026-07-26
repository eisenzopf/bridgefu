#!/usr/bin/env bash
set -euo pipefail

dockerfile="${1:-deploy/Dockerfile}"

test -f "$dockerfile"
test -f deploy/missing-rvoip-context
if ! cmp -s Dockerfile deploy/Dockerfile; then
  echo "root Dockerfile diverged from canonical deploy/Dockerfile" >&2
  exit 1
fi

# The canonical image must use immutable multi-platform base manifests.
base_args=$(grep -Ec '^ARG (RUST_IMAGE|RUNTIME_IMAGE)=.+@sha256:[0-9a-f]{64}$' "$dockerfile")
if [ "$base_args" -ne 2 ]; then
  echo "release Dockerfile must pin both base manifest digests" >&2
  exit 1
fi
snapshot_args=$(grep -Ec '^ARG (BUILDER_DEBIAN_SNAPSHOT|RUNTIME_DEBIAN_SNAPSHOT)=[0-9]{8}T[0-9]{6}Z$' "$dockerfile")
if [ "$snapshot_args" -ne 2 ]; then
  echo "release Dockerfile must pin both Debian package snapshots" >&2
  exit 1
fi
grep -Eq 'snapshot\.debian\.org/archive/debian/' "$dockerfile"
grep -Eq 'snapshot\.debian\.org/archive/debian-security/' "$dockerfile"
grep -Eq 'build-essential=[^ ]+' "$dockerfile"
grep -Eq 'ca-certificates=[^ ]+' "$dockerfile"
grep -Eq 'curl=[^ ]+' "$dockerfile"

grep -Eq '^COPY --from=rvoip ' "$dockerfile"
grep -Eq '^FROM scratch AS rvoip$' "$dockerfile"
grep -Eq '&& cargo build --locked --release ' "$dockerfile"
grep -Eq 'bridgefu-missing-rvoip-build-context' "$dockerfile"
grep -Eq '^USER 65532:65532$' "$dockerfile"
grep -Eq '^HEALTHCHECK ' "$dockerfile"
grep -Eq '^STOPSIGNAL SIGTERM$' "$dockerfile"
grep -Eq '^ENV SOURCE_DATE_EPOCH=' "$dockerfile"
grep -Eq 'org.opencontainers.image.rvoip.revision=' "$dockerfile"
grep -Eq 'dockerfile: deploy/Dockerfile' compose.yaml
grep -Eq 'file: bridgefu/deploy/Dockerfile' .github/workflows/ci.yml
grep -Eq 'platform: linux/amd64' .github/workflows/ci.yml
grep -Eq 'platform: linux/arm64' .github/workflows/ci.yml
release_workflow=.github/workflows/release-image-candidate.yml
test -f "$release_workflow"
grep -Eq '^  workflow_dispatch:$' "$release_workflow"
grep -Eq '^    environment: bridgefu-release-image-candidate$' "$release_workflow"
grep -Eq 'platforms: linux/amd64,linux/arm64' "$release_workflow"
grep -Eq 'outputs: type=oci,dest=' "$release_workflow"
grep -Eq '^          push: false$' "$release_workflow"
grep -Eq 'provenance: mode=max' "$release_workflow"
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

# Actions that execute in ordinary image CI or the manual release-candidate
# workflow are immutable commit pins. Human-readable version comments may
# follow the SHA, but floating tags and branches are rejected.
while IFS= read -r use; do
  if ! grep -Eq 'uses: [^@[:space:]]+@[0-9a-f]{40}([[:space:]]+#.*)?$' <<<"$use"; then
    echo "workflow action is not commit-pinned: $use" >&2
    exit 1
  fi
done < <(grep -hE '^[[:space:]]+- uses:' .github/workflows/ci.yml "$release_workflow")

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
grep -Fq ": \"\${RVOIP_REVISION:?" deploy.sh
grep -Fq ": \"\${RUNTIME_ENV:?" deploy.sh
grep -Fq "git -C \"\$RVOIP_DIR\" archive" deploy.sh
grep -Fq -- '--iidfile' deploy.sh
grep -Fq -- '--build-context rvoip=../rvoip' deploy.sh
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
