#!/usr/bin/env bash
set -euo pipefail

readonly REQUIRED_ENVIRONMENT="reference-tenant-nonproduction"
readonly REQUIRED_AUTHORIZATION="OWNER-AUTHORIZED-NONPROD-SMOKE"
readonly CORRELATION_PLACEHOLDER="__BRIDGEFU_CORRELATION_ID__"
readonly VAPI_API_BASE_URL="https://api.vapi.ai"

fail() {
  echo "reference-tenant smoke: $*" >&2
  exit 2
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

require_value() {
  local name="$1"
  [[ -n "${!name:-}" ]] || fail "required environment value is missing: ${name}"
}

validate_configuration() {
  require_command jq
  for name in \
    BRIDGEFU_SMOKE_ENVIRONMENT \
    BRIDGEFU_SMOKE_APPROVAL_REFERENCE \
    AWS_EXPECTED_ACCOUNT_ID \
    BRIDGEFU_DIAGNOSTICS_BASE_URL \
    BRIDGEFU_DIAGNOSTICS_TOKEN \
    VAPI_API_TOKEN \
    VAPI_CALL_PAYLOAD_JSON; do
    require_value "${name}"
  done

  [[ "${BRIDGEFU_SMOKE_ENVIRONMENT}" == "${REQUIRED_ENVIRONMENT}" ]] ||
    fail "the smoke environment is not the fixed non-production environment"
  [[ "${BRIDGEFU_SMOKE_APPROVAL_REFERENCE}" =~ ^[A-Za-z0-9._:/-]{3,80}$ ]] ||
    fail "the approval reference is invalid"
  [[ "${AWS_EXPECTED_ACCOUNT_ID}" =~ ^[0-9]{12}$ ]] ||
    fail "the allowlisted AWS account ID must contain 12 digits"
  [[ "${BRIDGEFU_DIAGNOSTICS_BASE_URL}" =~ ^https://[a-z0-9.-]+(:[0-9]+)?$ ]] ||
    fail "the diagnostics base URL must be an HTTPS origin without a path"

  local diagnostics_host="${BRIDGEFU_DIAGNOSTICS_BASE_URL#https://}"
  diagnostics_host="${diagnostics_host%%:*}"
  case "${diagnostics_host}" in
    *nonprod* | *non-production* | *staging* | *sandbox* | *.test) ;;
    *) fail "the diagnostics hostname lacks a non-production marker" ;;
  esac

  [[ ${#BRIDGEFU_DIAGNOSTICS_TOKEN} -ge 16 ]] ||
    fail "the diagnostics token is unexpectedly short"
  [[ ${#VAPI_API_TOKEN} -ge 16 ]] || fail "the Vapi token is unexpectedly short"
  [[ "${BRIDGEFU_DIAGNOSTICS_TOKEN}" != *$'\r'* &&
    "${BRIDGEFU_DIAGNOSTICS_TOKEN}" != *$'\n'* ]] ||
    fail "the diagnostics token contains a forbidden line break"
  [[ "${VAPI_API_TOKEN}" != *$'\r'* && "${VAPI_API_TOKEN}" != *$'\n'* ]] ||
    fail "the Vapi token contains a forbidden line break"
  printf '%s' "${VAPI_CALL_PAYLOAD_JSON}" | jq -e \
    --arg environment "${REQUIRED_ENVIRONMENT}" \
    --arg placeholder "${CORRELATION_PLACEHOLDER}" '
      (.assistantId? | type == "string" and length > 0) and
      (.phoneNumberId? | type == "string" and length > 0) and
      (
        (.customerId? | type == "string" and length > 0) or
        (.customer.number? | type == "string" and length > 0)
      ) and
      (.assistantOverrides.variableValues.bridgefuEnvironment? == $environment) and
      (.assistantOverrides.variableValues.bridgefuCorrelationId? == $placeholder)
    ' >/dev/null || fail "the Vapi payload is invalid or lacks the protected smoke variables"
}

validate_execute_authorization() {
  require_value BRIDGEFU_SMOKE_CONFIRM_NONPRODUCTION
  require_value BRIDGEFU_SMOKE_OWNER_AUTHORIZATION
  require_value BRIDGEFU_SMOKE_REPORT_PATH
  [[ "${BRIDGEFU_SMOKE_CONFIRM_NONPRODUCTION}" == "true" ]] ||
    fail "non-production execution was not explicitly confirmed"
  [[ "${BRIDGEFU_SMOKE_OWNER_AUTHORIZATION}" == "${REQUIRED_AUTHORIZATION}" ]] ||
    fail "owner authorization is absent or does not match the reviewed operation"
}

poll_evidence_stage() {
  local encoded_correlation="$1"
  local stage="$2"
  local destination="$3"
  local timeout_seconds="$4"
  local deadline=$((SECONDS + timeout_seconds))
  local status

  while ((SECONDS < deadline)); do
    if ! status="$(curl --silent --show-error \
      --connect-timeout 5 \
      --max-time 15 \
      --output "${destination}" \
      --write-out '%{http_code}' \
      --header "Authorization: Bearer ${BRIDGEFU_DIAGNOSTICS_TOKEN}" \
      "${BRIDGEFU_DIAGNOSTICS_BASE_URL}/v1/diagnostics/screen-pop/${encoded_correlation}")"; then
      sleep 2
      continue
    fi
    if [[ "${status}" == "200" ]]; then
      if jq -e '.stages.failed.observed? == true' "${destination}" >/dev/null; then
        fail "screen-pop diagnostics reported a typed failure stage"
      fi
      if jq -e --arg stage "${stage}" '.stages[$stage].observed? == true' \
        "${destination}" >/dev/null; then
        return 0
      fi
    elif [[ "${status}" != "404" && ! "${status}" =~ ^5[0-9][0-9]$ ]]; then
      fail "screen-pop diagnostics returned HTTP ${status}"
    fi
    sleep 2
  done
  fail "timed out waiting for the redacted ${stage} lifecycle stage"
}

run_smoke() {
  validate_execute_authorization
  for command in aws curl jq mktemp; do
    require_command "${command}"
  done

  local actual_account
  actual_account="$(aws sts get-caller-identity --query Account --output text)"
  [[ "${actual_account}" == "${AWS_EXPECTED_ACCOUNT_ID}" ]] ||
    fail "the active AWS identity is not the allowlisted non-production account"

  local ready_file ready_status
  ready_file="$(mktemp)"
  ready_status="$(curl --silent --show-error \
    --connect-timeout 5 \
    --max-time 15 \
    --output "${ready_file}" \
    --write-out '%{http_code}' \
    "${BRIDGEFU_DIAGNOSTICS_BASE_URL}/readyz")"
  rm -f "${ready_file}"
  [[ "${ready_status}" == "200" ]] || fail "the non-production bridge is not ready"

  local temp_dir call_id correlation encoded_correlation request_file response_file evidence_file
  temp_dir="$(mktemp -d)"
  call_id=""
  cleanup() {
    if [[ -n "${call_id}" ]]; then
      curl --silent --show-error \
        --connect-timeout 5 \
        --max-time 15 \
        --request DELETE \
        --header "Authorization: Bearer ${VAPI_API_TOKEN}" \
        --output /dev/null \
        "${VAPI_API_BASE_URL}/call/${call_id}" >/dev/null 2>&1 || true
    fi
    rm -rf "${temp_dir}"
  }
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  correlation="bf-smoke-${GITHUB_RUN_ID:-manual}-${GITHUB_RUN_ATTEMPT:-1}-${RANDOM}"
  encoded_correlation="$(jq -nr --arg value "${correlation}" '$value | @uri')"
  request_file="${temp_dir}/request.json"
  response_file="${temp_dir}/response.json"
  evidence_file="${temp_dir}/evidence.json"
  printf '%s' "${VAPI_CALL_PAYLOAD_JSON}" | jq \
    --arg correlation "${correlation}" \
    '.assistantOverrides.variableValues.bridgefuCorrelationId = $correlation' \
    >"${request_file}"

  local create_status
  create_status="$(curl --silent --show-error \
    --connect-timeout 10 \
    --max-time 30 \
    --request POST \
    --header "Authorization: Bearer ${VAPI_API_TOKEN}" \
    --header 'Content-Type: application/json' \
    --data-binary "@${request_file}" \
    --output "${response_file}" \
    --write-out '%{http_code}' \
    "${VAPI_API_BASE_URL}/call")"
  [[ "${create_status}" =~ ^20[01]$ ]] || fail "Vapi call creation returned HTTP ${create_status}"
  call_id="$(jq -er '.id | select(type == "string")' "${response_file}")" ||
    fail "Vapi call creation did not return an ID"
  [[ "${call_id}" =~ ^[A-Za-z0-9_-]{8,128}$ ]] || fail "Vapi returned an invalid call ID"

  local timeout_seconds="${BRIDGEFU_SMOKE_TIMEOUT_SECONDS:-180}"
  [[ "${timeout_seconds}" =~ ^[0-9]+$ ]] || fail "the smoke timeout is invalid"
  ((timeout_seconds >= 30 && timeout_seconds <= 600)) ||
    fail "the smoke timeout must be between 30 and 600 seconds"
  poll_evidence_stage "${encoded_correlation}" media_connected "${evidence_file}" \
    "${timeout_seconds}"

  local delete_status
  delete_status="$(curl --silent --show-error \
    --connect-timeout 10 \
    --max-time 30 \
    --request DELETE \
    --header "Authorization: Bearer ${VAPI_API_TOKEN}" \
    --output /dev/null \
    --write-out '%{http_code}' \
    "${VAPI_API_BASE_URL}/call/${call_id}")"
  [[ "${delete_status}" =~ ^20[024]$ ]] || fail "Vapi call termination returned HTTP ${delete_status}"
  poll_evidence_stage "${encoded_correlation}" terminated "${evidence_file}" \
    "${timeout_seconds}"

  jq -e '
    .stages.sip_invite_received.observed == true and
    .stages.attributes_mapped.observed == true and
    .stages.contact_started.observed == true and
    .stages.media_connected.observed == true and
    .stages.teardown_started.observed == true and
    .stages.terminated.observed == true and
    (.stages.failed == null)
  ' "${evidence_file}" >/dev/null || fail "the final lifecycle evidence is incomplete"

  jq --arg environment "${REQUIRED_ENVIRONMENT}" \
    '{result: "passed", environment: $environment, evidence: .}' \
    "${evidence_file}" >"${BRIDGEFU_SMOKE_REPORT_PATH}"
  call_id=""

  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo "## ReferenceTenant non-production smoke"
      echo
      echo "Result: passed"
      echo "Environment: ${REQUIRED_ENVIRONMENT}"
      echo "Evidence: redacted screen-pop lifecycle reached media_connected and terminated"
      echo "Approval reference: ${BRIDGEFU_SMOKE_APPROVAL_REFERENCE}"
    } >>"${GITHUB_STEP_SUMMARY}"
  fi
  trap - EXIT INT TERM
  cleanup
  echo "reference-tenant smoke: redacted lifecycle qualification passed"
}

case "${1:-preflight}" in
  preflight)
    validate_configuration
    echo "reference-tenant smoke: secret-backed configuration is valid; no network calls were made"
    ;;
  execute)
    validate_configuration
    run_smoke
    ;;
  *)
    fail "usage: $0 [preflight|execute]"
    ;;
esac
