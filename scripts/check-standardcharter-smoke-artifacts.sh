#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workflow="${repo_root}/.github/workflows/standardcharter-nonproduction-smoke.yml"
smoke="${repo_root}/scripts/run-standardcharter-smoke.sh"
rollback="${repo_root}/scripts/standardcharter-drain-rollback.sh"
runbook="${repo_root}/docs/standardcharter-smoke-runbook.md"

fail() {
  echo "standardcharter artifact check: $*" >&2
  exit 1
}

expect_failure() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    fail "${description} unexpectedly succeeded"
  fi
}

require_literal() {
  local file="$1"
  local literal="$2"
  grep -Fq -- "${literal}" "${file}" || fail "${file#${repo_root}/} lacks: ${literal}"
}

for file in "${workflow}" "${smoke}" "${rollback}" "${runbook}"; do
  [[ -f "${file}" ]] || fail "required artifact is missing: ${file#${repo_root}/}"
done
[[ -x "${smoke}" ]] || fail "the smoke runner is not executable"
[[ -x "${rollback}" ]] || fail "the rollback runner is not executable"

bash -n "${smoke}"
bash -n "${rollback}"
if command -v ruby >/dev/null 2>&1; then
  ruby -e 'require "yaml"; abort("invalid YAML") unless YAML.parse_file(ARGV.fetch(0))' \
    "${workflow}"
fi

require_literal "${workflow}" "workflow_dispatch:"
require_literal "${workflow}" "default: validate"
require_literal "${workflow}" "- rollback-plan"
require_literal "${workflow}" "- rollback"
require_literal "${workflow}" "default: false"
require_literal "${workflow}" "cancel-in-progress: false"
require_literal "${workflow}" "name: standardcharter-nonproduction"
require_literal "${workflow}" "id-token: write"
require_literal "${workflow}" 'if: ${{ inputs.operation == '\''validate'\'' }}'
require_literal "${workflow}" 'if: ${{ inputs.operation != '\''validate'\'' }}'

if grep -Eq '^  (push|pull_request|schedule):' "${workflow}"; then
  fail "the protected smoke workflow must be dispatch-only"
fi
if grep -Eq '\$\{\{ inputs\.(aws|vapi|bridgefu|ssh|rollback_image)' "${workflow}"; then
  fail "deployment targets and credentials must not come from dispatch inputs"
fi

for secret in \
  STANDARDCHARTER_SMOKE_AWS_ACCOUNT_ID \
  STANDARDCHARTER_SMOKE_AWS_ROLE_ARN \
  STANDARDCHARTER_SMOKE_AWS_REGION \
  STANDARDCHARTER_SMOKE_BRIDGEFU_URL \
  STANDARDCHARTER_SMOKE_DIAGNOSTICS_TOKEN \
  STANDARDCHARTER_SMOKE_VAPI_TOKEN \
  STANDARDCHARTER_SMOKE_VAPI_CALL_PAYLOAD_JSON \
  STANDARDCHARTER_ROLLBACK_SSH_TARGET \
  STANDARDCHARTER_ROLLBACK_SSH_PRIVATE_KEY \
  STANDARDCHARTER_ROLLBACK_SSH_KNOWN_HOSTS \
  STANDARDCHARTER_ROLLBACK_IMAGE; do
  require_literal "${workflow}" "secrets.${secret}"
done

preflight_output="$(
  BRIDGEFU_SMOKE_ENVIRONMENT=standardcharter-nonproduction \
  BRIDGEFU_SMOKE_APPROVAL_REFERENCE=owner-review-123 \
  AWS_EXPECTED_ACCOUNT_ID=123456789012 \
  BRIDGEFU_DIAGNOSTICS_BASE_URL=https://bridgefu-staging.example.test \
  BRIDGEFU_DIAGNOSTICS_TOKEN=diagnostics-token-test-only \
  VAPI_API_TOKEN=vapi-token-test-only-0000 \
  VAPI_CALL_PAYLOAD_JSON='{"assistantId":"assistant-test","phoneNumberId":"phone-test","customer":{"number":"+15555550123"},"assistantOverrides":{"variableValues":{"bridgefuEnvironment":"standardcharter-nonproduction","bridgefuCorrelationId":"__BRIDGEFU_CORRELATION_ID__"}}}' \
  bash "${smoke}" preflight
)"
[[ "${preflight_output}" == *"no network calls were made"* ]] ||
  fail "the smoke preflight did not prove its offline mode"

expect_failure "a production smoke environment" \
  env \
    BRIDGEFU_SMOKE_ENVIRONMENT=production \
    BRIDGEFU_SMOKE_APPROVAL_REFERENCE=owner-review-123 \
    AWS_EXPECTED_ACCOUNT_ID=123456789012 \
    BRIDGEFU_DIAGNOSTICS_BASE_URL=https://bridgefu-staging.example.test \
    BRIDGEFU_DIAGNOSTICS_TOKEN=diagnostics-token-test-only \
    VAPI_API_TOKEN=vapi-token-test-only-0000 \
    VAPI_CALL_PAYLOAD_JSON='{"assistantId":"assistant-test","phoneNumberId":"phone-test","customer":{"number":"+15555550123"},"assistantOverrides":{"variableValues":{"bridgefuEnvironment":"standardcharter-nonproduction","bridgefuCorrelationId":"__BRIDGEFU_CORRELATION_ID__"}}}' \
    bash "${smoke}" preflight

expect_failure "an unmarked diagnostics target" \
  env \
    BRIDGEFU_SMOKE_ENVIRONMENT=standardcharter-nonproduction \
    BRIDGEFU_SMOKE_APPROVAL_REFERENCE=owner-review-123 \
    AWS_EXPECTED_ACCOUNT_ID=123456789012 \
    BRIDGEFU_DIAGNOSTICS_BASE_URL=https://bridgefu.example.com \
    BRIDGEFU_DIAGNOSTICS_TOKEN=diagnostics-token-test-only \
    VAPI_API_TOKEN=vapi-token-test-only-0000 \
    VAPI_CALL_PAYLOAD_JSON='{"assistantId":"assistant-test","phoneNumberId":"phone-test","customer":{"number":"+15555550123"},"assistantOverrides":{"variableValues":{"bridgefuEnvironment":"standardcharter-nonproduction","bridgefuCorrelationId":"__BRIDGEFU_CORRELATION_ID__"}}}' \
    bash "${smoke}" preflight

expect_failure "smoke execution without explicit authorization" \
  env \
    BRIDGEFU_SMOKE_ENVIRONMENT=standardcharter-nonproduction \
    BRIDGEFU_SMOKE_APPROVAL_REFERENCE=owner-review-123 \
    AWS_EXPECTED_ACCOUNT_ID=123456789012 \
    BRIDGEFU_DIAGNOSTICS_BASE_URL=https://bridgefu-staging.example.test \
    BRIDGEFU_DIAGNOSTICS_TOKEN=diagnostics-token-test-only \
    VAPI_API_TOKEN=vapi-token-test-only-0000 \
    VAPI_CALL_PAYLOAD_JSON='{"assistantId":"assistant-test","phoneNumberId":"phone-test","customer":{"number":"+15555550123"},"assistantOverrides":{"variableValues":{"bridgefuEnvironment":"standardcharter-nonproduction","bridgefuCorrelationId":"__BRIDGEFU_CORRELATION_ID__"}}}' \
    bash "${smoke}" execute

dummy_target="runner@bridgefu-staging.example.test"
dummy_image="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
plan_output="$(
  BRIDGEFU_ROLLBACK_ENVIRONMENT=standardcharter-nonproduction \
  BRIDGEFU_ROLLBACK_APPROVAL_REFERENCE=owner-review-123 \
  BRIDGEFU_ROLLBACK_SSH_TARGET="${dummy_target}" \
  BRIDGEFU_ROLLBACK_IMAGE="${dummy_image}" \
  BRIDGEFU_ROLLBACK_DRAIN_SECONDS=30 \
  bash "${rollback}" plan
)"
[[ "${plan_output}" == *"no network calls made"* ]] ||
  fail "the rollback plan did not prove its offline mode"
[[ "${plan_output}" != *"${dummy_target}"* && "${plan_output}" != *"${dummy_image}"* ]] ||
  fail "the rollback plan exposed secret-backed target configuration"

expect_failure "a production rollback target" \
  env \
    BRIDGEFU_ROLLBACK_ENVIRONMENT=standardcharter-nonproduction \
    BRIDGEFU_ROLLBACK_APPROVAL_REFERENCE=owner-review-123 \
    BRIDGEFU_ROLLBACK_SSH_TARGET=runner@bridgefu.example.com \
    BRIDGEFU_ROLLBACK_IMAGE="${dummy_image}" \
    BRIDGEFU_ROLLBACK_DRAIN_SECONDS=30 \
    bash "${rollback}" plan

expect_failure "an option-looking rollback target" \
  env \
    BRIDGEFU_ROLLBACK_ENVIRONMENT=standardcharter-nonproduction \
    BRIDGEFU_ROLLBACK_APPROVAL_REFERENCE=owner-review-123 \
    BRIDGEFU_ROLLBACK_SSH_TARGET=-oProxyCommand@bridgefu-staging.example.test \
    BRIDGEFU_ROLLBACK_IMAGE="${dummy_image}" \
    BRIDGEFU_ROLLBACK_DRAIN_SECONDS=30 \
    bash "${rollback}" plan

expect_failure "an option-looking rollback image" \
  env \
    BRIDGEFU_ROLLBACK_ENVIRONMENT=standardcharter-nonproduction \
    BRIDGEFU_ROLLBACK_APPROVAL_REFERENCE=owner-review-123 \
    BRIDGEFU_ROLLBACK_SSH_TARGET="${dummy_target}" \
    BRIDGEFU_ROLLBACK_IMAGE="--format@${dummy_image}" \
    BRIDGEFU_ROLLBACK_DRAIN_SECONDS=30 \
    bash "${rollback}" plan

expect_failure "rollback execution without explicit authorization" \
  env \
    BRIDGEFU_ROLLBACK_ENVIRONMENT=standardcharter-nonproduction \
    BRIDGEFU_ROLLBACK_APPROVAL_REFERENCE=owner-review-123 \
    BRIDGEFU_ROLLBACK_SSH_TARGET="${dummy_target}" \
    BRIDGEFU_ROLLBACK_IMAGE="${dummy_image}" \
    BRIDGEFU_ROLLBACK_DRAIN_SECONDS=30 \
    bash "${rollback}" execute

require_literal "${runbook}" "standardcharter-nonproduction"
require_literal "${runbook}" "OWNER-AUTHORIZED-NONPROD-SMOKE"
require_literal "${runbook}" "OWNER-AUTHORIZED-NONPROD-ROLLBACK"
require_literal "${runbook}" "No external smoke has been executed by checking in these artifacts"
require_literal "${runbook}" "never automatic"
require_literal "${rollback}" "restore_prior_image"
require_literal "${rollback}" "the running container does not match bridgefu:latest"

echo "standardcharter artifact check: protected workflow and offline runbook checks passed"
