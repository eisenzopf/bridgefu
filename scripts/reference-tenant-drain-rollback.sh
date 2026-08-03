#!/usr/bin/env bash
set -euo pipefail

readonly REQUIRED_ENVIRONMENT="reference-tenant-nonproduction"
readonly REQUIRED_AUTHORIZATION="OWNER-AUTHORIZED-NONPROD-ROLLBACK"

fail() {
  echo "reference-tenant rollback: $*" >&2
  exit 2
}

require_value() {
  local name="$1"
  [[ -n "${!name:-}" ]] || fail "required environment value is missing: ${name}"
}

validate_plan() {
  for name in \
    BRIDGEFU_ROLLBACK_ENVIRONMENT \
    BRIDGEFU_ROLLBACK_APPROVAL_REFERENCE \
    BRIDGEFU_ROLLBACK_SSH_TARGET \
    BRIDGEFU_ROLLBACK_IMAGE; do
    require_value "${name}"
  done
  [[ "${BRIDGEFU_ROLLBACK_ENVIRONMENT}" == "${REQUIRED_ENVIRONMENT}" ]] ||
    fail "the rollback environment is not the fixed non-production environment"
  [[ "${BRIDGEFU_ROLLBACK_APPROVAL_REFERENCE}" =~ ^[A-Za-z0-9._:/-]{3,80}$ ]] ||
    fail "the approval reference is invalid"
  [[ "${BRIDGEFU_ROLLBACK_SSH_TARGET}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*@[A-Za-z0-9][A-Za-z0-9.-]*$ ]] ||
    fail "the SSH target is invalid"

  local target_host="${BRIDGEFU_ROLLBACK_SSH_TARGET#*@}"
  case "${target_host}" in
    *nonprod* | *non-production* | *staging* | *sandbox* | *.test) ;;
    *) fail "the SSH hostname lacks a non-production marker" ;;
  esac

  if [[ ! "${BRIDGEFU_ROLLBACK_IMAGE}" =~ ^sha256:[0-9a-f]{64}$ ]] &&
    [[ ! "${BRIDGEFU_ROLLBACK_IMAGE}" =~ ^[A-Za-z0-9][A-Za-z0-9._/:@-]*@sha256:[0-9a-f]{64}$ ]]; then
    fail "the rollback image must be an immutable local image ID or digest reference"
  fi

  BRIDGEFU_ROLLBACK_DRAIN_SECONDS="${BRIDGEFU_ROLLBACK_DRAIN_SECONDS:-30}"
  [[ "${BRIDGEFU_ROLLBACK_DRAIN_SECONDS}" =~ ^[0-9]+$ ]] ||
    fail "the drain deadline is invalid"
  ((BRIDGEFU_ROLLBACK_DRAIN_SECONDS >= 15 && BRIDGEFU_ROLLBACK_DRAIN_SECONDS <= 300)) ||
    fail "the drain deadline must be between 15 and 300 seconds"
}

print_plan() {
  cat <<'PLAN'
ReferenceTenant non-production rollback plan (no network calls made):
1. Verify the target is healthy and the immutable rollback image already exists.
2. Ask systemd to stop bridgefu; SIGTERM drives Bridgefu's bounded call/media drain.
3. Refuse to retag while the service or bridgefu container remains active.
4. Require a successful service result, then retag the reviewed image as bridgefu:latest.
5. Start bridgefu and require localhost /readyz.
6. If readiness fails, restore the exact pre-rollback image ID and restart it.

The script never invokes `docker kill`, pulls an image, changes infrastructure,
or targets production. The reviewed service manager timeout remains the final
bound on an explicitly authorized non-production drain.
PLAN
}

validate_execute_authorization() {
  for name in \
    BRIDGEFU_ROLLBACK_CONFIRM_NONPRODUCTION \
    BRIDGEFU_ROLLBACK_OWNER_AUTHORIZATION \
    BRIDGEFU_ROLLBACK_SSH_KEY_PATH \
    BRIDGEFU_ROLLBACK_SSH_KNOWN_HOSTS_PATH; do
    require_value "${name}"
  done
  [[ "${BRIDGEFU_ROLLBACK_CONFIRM_NONPRODUCTION}" == "true" ]] ||
    fail "non-production rollback was not explicitly confirmed"
  [[ "${BRIDGEFU_ROLLBACK_OWNER_AUTHORIZATION}" == "${REQUIRED_AUTHORIZATION}" ]] ||
    fail "owner authorization is absent or does not match the reviewed rollback"
  [[ -f "${BRIDGEFU_ROLLBACK_SSH_KEY_PATH}" ]] || fail "the SSH key file is unavailable"
  [[ -f "${BRIDGEFU_ROLLBACK_SSH_KNOWN_HOSTS_PATH}" ]] ||
    fail "the pinned SSH known-hosts file is unavailable"
  [[ -s "${BRIDGEFU_ROLLBACK_SSH_KEY_PATH}" ]] || fail "the SSH key file is empty"
  [[ -s "${BRIDGEFU_ROLLBACK_SSH_KNOWN_HOSTS_PATH}" ]] ||
    fail "the pinned SSH known-hosts file is empty"
  command -v ssh >/dev/null 2>&1 || fail "required command is unavailable: ssh"
}

execute_rollback() {
  validate_execute_authorization
  ssh \
    -i "${BRIDGEFU_ROLLBACK_SSH_KEY_PATH}" \
    -o BatchMode=yes \
    -o ConnectTimeout=10 \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=${BRIDGEFU_ROLLBACK_SSH_KNOWN_HOSTS_PATH}" \
    "${BRIDGEFU_ROLLBACK_SSH_TARGET}" \
    bash -s -- "${BRIDGEFU_ROLLBACK_IMAGE}" "${BRIDGEFU_ROLLBACK_DRAIN_SECONDS}" <<'REMOTE'
set -euo pipefail

rollback_image="$1"
drain_seconds="$2"

for command in curl docker sudo systemctl; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "rollback host is missing required command: ${command}" >&2
    exit 2
  }
done
sudo -n true

wait_for_stopped() {
  local deadline=$((SECONDS + $1))
  while ((SECONDS < deadline)); do
    if ! sudo -n systemctl is-active --quiet bridgefu &&
      ! docker container inspect bridgefu >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_ready() {
  local deadline=$((SECONDS + $1))
  while ((SECONDS < deadline)); do
    if curl --fail --silent --show-error --connect-timeout 2 --max-time 5 \
      http://127.0.0.1:9090/readyz >/dev/null; then
      return 0
    fi
    sleep 2
  done
  return 1
}

restore_prior_image() {
  if sudo -n systemctl is-active --quiet bridgefu ||
    docker container inspect bridgefu >/dev/null 2>&1; then
    sudo -n systemctl stop --no-block bridgefu || true
    if ! wait_for_stopped 30; then
      echo "the candidate image did not stop; prior image was not retagged" >&2
      return 2
    fi
  fi

  docker tag "${current_image}" bridgefu:latest || return 2
  sudo -n systemctl reset-failed bridgefu >/dev/null 2>&1 || true
  sudo -n systemctl start bridgefu || return 2
  wait_for_ready 60
}

sudo -n systemctl is-active --quiet bridgefu || {
  echo "bridgefu must be active before a controlled rollback" >&2
  exit 2
}
curl --fail --silent --show-error --connect-timeout 2 --max-time 5 \
  http://127.0.0.1:9090/readyz >/dev/null || {
  echo "bridgefu must be ready before a controlled rollback" >&2
  exit 2
}

current_image="$(docker image inspect bridgefu:latest --format '{{.Id}}')"
running_image="$(docker container inspect bridgefu --format '{{.Image}}')" || {
  echo "the expected bridgefu container is not running" >&2
  exit 2
}
[[ "${current_image}" == "${running_image}" ]] || {
  echo "the running container does not match bridgefu:latest" >&2
  exit 2
}
rollback_id="$(docker image inspect "${rollback_image}" --format '{{.Id}}')" || {
  echo "the immutable rollback image is not staged on the host" >&2
  exit 2
}
[[ "${current_image}" != "${rollback_id}" ]] || {
  echo "the requested rollback image is already active" >&2
  exit 2
}

echo "beginning bounded Bridgefu drain"
sudo -n systemctl stop --no-block bridgefu
if ! wait_for_stopped "${drain_seconds}"; then
  echo "drain deadline expired; image was not changed" >&2
  exit 1
fi
service_result="$(sudo -n systemctl show bridgefu --property=Result --value)"
[[ "${service_result}" == "success" ]] || {
  echo "bridgefu did not report a successful drain; image was not changed" >&2
  exit 1
}

if ! docker tag "${rollback_id}" bridgefu:latest; then
  echo "the rollback image could not be tagged; restarting the prior image" >&2
  if restore_prior_image; then
    echo "prior image restarted and ready; rollback operation failed safely" >&2
    exit 1
  fi
  echo "the prior image could not be restarted; operator intervention is required" >&2
  exit 2
fi
sudo -n systemctl reset-failed bridgefu >/dev/null 2>&1 || true
if sudo -n systemctl start bridgefu && wait_for_ready 60; then
  echo "rollback image is ready"
  exit 0
fi

echo "rollback image failed readiness; restoring the exact prior image" >&2
if restore_prior_image; then
  echo "prior image restored and ready; rollback operation failed safely" >&2
  exit 1
fi
echo "the prior image could not be restored safely; operator intervention is required" >&2
exit 2
REMOTE
}

validate_plan
case "${1:-plan}" in
  plan)
    print_plan
    ;;
  execute)
    execute_rollback
    ;;
  *)
    fail "usage: $0 [plan|execute]"
    ;;
esac
