#!/usr/bin/env bash
# Deploy one explicitly reviewed Bridgefu source revision to the legacy EC2
# host-mode service. The committed Cargo.lock pins the crates.io-hosted rvoip
# 0.3.8 graph; no sibling source checkout participates in the build.
set -euo pipefail

: "${INSTANCE_IP:?set INSTANCE_IP to the disposable target host}"
: "${SSH_KEY:?set SSH_KEY to the matching private key path}"
: "${CONFIG:?set CONFIG to the reviewed bridgefu.yaml}"
: "${RUNTIME_ENV:?set RUNTIME_ENV to the mode-0600 container environment file}"
: "${BRIDGEFU_REVISION:?set BRIDGEFU_REVISION to the exact 40-character commit}"

SSH_USER="${SSH_USER:-ec2-user}"
REMOTE_DIR="${REMOTE_DIR:-/opt/bridgefu-releases}"
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly RVOIP_VERSION=0.3.8

if [[ ! "$INSTANCE_IP" =~ ^[A-Za-z0-9.-]+$ ]]; then
  echo "INSTANCE_IP must be an IPv4 address or DNS hostname" >&2
  exit 1
fi
if [[ ! "$SSH_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
  echo "SSH_USER contains unsupported characters" >&2
  exit 1
fi
if [[ ! "$REMOTE_DIR" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
  echo "REMOTE_DIR must be an absolute path without shell metacharacters" >&2
  exit 1
fi

if [[ ! "$BRIDGEFU_REVISION" =~ ^[0-9a-f]{40}$ ]]; then
  echo "BRIDGEFU_REVISION must be an exact lowercase 40-character commit SHA" >&2
  exit 1
fi

if [[ ! -f "$CONFIG" ]]; then
  printf 'CONFIG file not found: %s\n' "$CONFIG" >&2
  exit 1
fi
if [[ ! -f "$RUNTIME_ENV" ]]; then
  printf 'RUNTIME_ENV file not found: %s\n' "$RUNTIME_ENV" >&2
  exit 1
fi
if grep -Eq '^BRIDGEFU_IMAGE=' "$RUNTIME_ENV"; then
  echo "RUNTIME_ENV must not override the deployment-owned BRIDGEFU_IMAGE" >&2
  exit 1
fi

verify_revision() {
  local repository=$1
  local revision=$2
  local label=$3
  local resolved
  resolved=$(git -C "$repository" rev-parse --verify "${revision}^{commit}")
  if [[ "$resolved" != "$revision" ]]; then
    printf '%s did not resolve byte-for-byte to requested revision %s\n' "$label" "$revision" >&2
    exit 1
  fi
}

verify_revision "$REPO_ROOT" "$BRIDGEFU_REVISION" BRIDGEFU_REVISION

BRIDGEFU_BUILD_DATE=$(git -C "$REPO_ROOT" show -s --format=%cI "$BRIDGEFU_REVISION")
release_nonce=$(printf '%08x' "$(( (RANDOM << 16) | RANDOM ))")
release_id="${BRIDGEFU_REVISION:0:12}-$(date -u +%Y%m%dT%H%M%SZ)-${release_nonce}"
remote_release="${REMOTE_DIR}/${release_id}"
remote_bridgefu_archive="/tmp/bridgefu-${release_id}.tar"
remote_config="/tmp/bridgefu-config-${release_id}.yaml"
remote_runtime_env="/tmp/bridgefu-runtime-${release_id}.env"
remote_iidfile="/tmp/bridgefu-image-${release_id}.iid"
remote_image_env="/tmp/bridgefu-image-${release_id}.env"
rollback_dir="/etc/bridgefu/rollback/${release_id}"

stage=$(mktemp -d)
cleanup() {
  rm -rf "$stage"
}
trap cleanup EXIT

git -C "$REPO_ROOT" archive --format=tar --output="$stage/bridgefu.tar" "$BRIDGEFU_REVISION"
install -m 0600 "$CONFIG" "$stage/bridgefu.yaml"
install -m 0600 "$RUNTIME_ENV" "$stage/runtime.env"

SSH_OPTS=(
  -i "$SSH_KEY"
  -o StrictHostKeyChecking=accept-new
  -o ServerAliveInterval=30
)
remote="${SSH_USER}@${INSTANCE_IP}"
ssh_run() {
  # Every interpolated remote path/identity is validated above or derived only
  # from the exact hexadecimal revision. The command itself must expand locally.
  # shellcheck disable=SC2029
  ssh "${SSH_OPTS[@]}" "$remote" "$1"
}

cleanup_with_remote() {
  rm -rf "$stage"
  ssh_run "rm -f '${remote_bridgefu_archive}' '${remote_config}' '${remote_runtime_env}' '${remote_iidfile}' '${remote_image_env}'" >/dev/null 2>&1 || true
}
trap cleanup_with_remote EXIT

printf '==> [1/6] Uploading exact source archive for %s\n' "$release_id"
scp "${SSH_OPTS[@]}" \
  "$stage/bridgefu.tar" "${remote}:${remote_bridgefu_archive}"
scp "${SSH_OPTS[@]}" \
  "$stage/bridgefu.yaml" "${remote}:${remote_config}"
scp "${SSH_OPTS[@]}" \
  "$stage/runtime.env" "${remote}:${remote_runtime_env}"

printf '==> [2/6] Expanding into a new revision-isolated source directory\n'
ssh_run "set -euo pipefail
  umask 077
  sudo install -d -o \$(id -u) -g \$(id -g) -m 0750 '${REMOTE_DIR}'
  test ! -e '${remote_release}'
  mkdir -p '${remote_release}/bridgefu'
  tar -xf '${remote_bridgefu_archive}' -C '${remote_release}/bridgefu'
  rm -f '${remote_bridgefu_archive}'"

printf '==> [3/6] Building canonical image and capturing immutable local image ID\n'
ssh_run "set -euo pipefail
  cd '${remote_release}/bridgefu'
  rm -f '${remote_iidfile}' '${remote_image_env}'
  docker build \
    --iidfile '${remote_iidfile}' \
    --build-arg VCS_REF='${BRIDGEFU_REVISION}' \
    --build-arg BUILD_DATE='${BRIDGEFU_BUILD_DATE}' \
    -f deploy/Dockerfile .
  image_id=\$(cat '${remote_iidfile}')
  if [[ ! \"\$image_id\" =~ ^sha256:[0-9a-f]{64}\$ ]]; then
    echo 'docker returned a non-immutable image ID' >&2
    exit 1
  fi
  docker image inspect \"\$image_id\" >/dev/null
  printf 'BRIDGEFU_IMAGE=%s\\n' \"\$image_id\" > '${remote_image_env}'
  chmod 0600 '${remote_image_env}'
  rm -f '${remote_iidfile}'"

printf '==> [4/6] Installing candidate config, image ID, and hardened service\n'
ssh_run "set -euo pipefail
  sudo install -d -m 0700 '${rollback_dir}'
  if sudo test -f /etc/bridgefu/image.env; then
    sudo cp -p /etc/bridgefu/image.env '${rollback_dir}/image.env'
  fi
  if sudo test -f /etc/bridgefu/bridgefu.yaml; then
    sudo cp -p /etc/bridgefu/bridgefu.yaml '${rollback_dir}/bridgefu.yaml'
  fi
  if sudo test -f /etc/bridgefu/runtime.env; then
    sudo cp -p /etc/bridgefu/runtime.env '${rollback_dir}/runtime.env'
  fi
  sudo install -D -m 0600 '${remote_config}' /etc/bridgefu/bridgefu.yaml
  sudo install -D -m 0600 '${remote_runtime_env}' /etc/bridgefu/runtime.env
  sudo install -D -m 0600 '${remote_image_env}' /etc/bridgefu/image.env
  sudo install -D -m 0644 '${remote_release}/bridgefu/deploy/bridgefu.service' /etc/systemd/system/bridgefu.service
  rm -f '${remote_config}' '${remote_runtime_env}' '${remote_image_env}'
  sudo systemctl daemon-reload
  sudo systemctl enable bridgefu
  sudo systemctl restart bridgefu"

rollback() {
  printf 'candidate failed health checks; restoring prior config/image when available\n' >&2
  ssh_run "set -euo pipefail
    if sudo test -f '${rollback_dir}/image.env'; then
      sudo install -m 0600 '${rollback_dir}/image.env' /etc/bridgefu/image.env
      if sudo test -f '${rollback_dir}/bridgefu.yaml'; then
        sudo install -m 0600 '${rollback_dir}/bridgefu.yaml' /etc/bridgefu/bridgefu.yaml
      fi
      if sudo test -f '${rollback_dir}/runtime.env'; then
        sudo install -m 0600 '${rollback_dir}/runtime.env' /etc/bridgefu/runtime.env
      fi
      sudo systemctl restart bridgefu
    else
      sudo systemctl stop bridgefu
    fi" || true
}

printf '==> [5/6] Waiting for dependency-aware readiness\n'
ready=""
for _ in $(seq 1 45); do
  if ssh_run "curl --fail --silent --show-error http://127.0.0.1:9090/readyz >/dev/null"; then
    ready=1
    break
  fi
  sleep 2
done
if [[ -z "$ready" ]]; then
  rollback
  ssh_run "sudo journalctl -u bridgefu -n 50 --no-pager" || true
  exit 1
fi

printf '==> [6/6] Verifying process liveness after readiness\n'
if ! ssh_run "curl --fail --silent --show-error http://127.0.0.1:9090/livez >/dev/null"; then
  rollback
  ssh_run "sudo journalctl -u bridgefu -n 50 --no-pager" || true
  exit 1
fi

ssh_run "sudo journalctl -u bridgefu -n 30 --no-pager" || true
printf 'Bridgefu revision %s with locked rvoip %s is ready on %s\n' \
  "$BRIDGEFU_REVISION" "$RVOIP_VERSION" "$INSTANCE_IP"
printf 'SIP target: sip:%s:5060\n' "$INSTANCE_IP"
printf 'Metrics: http://%s:9090/metrics (restricted by the host firewall)\n' "$INSTANCE_IP"
