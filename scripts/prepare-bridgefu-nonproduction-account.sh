#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
readonly DEFAULT_REGION="us-west-2"
readonly EIP_QUOTA_CODE="L-0263D0A3"
readonly CONNECT_INSTANCE_QUOTA_CODE="L-AA17A6B9"
readonly VPC_QUOTA_CODE="L-F678F1CE"
readonly NAT_GATEWAY_QUOTA_CODE="L-FE5A380F"
readonly STANDARD_VCPU_QUOTA_CODE="L-1216C47A"
readonly CLOUDFORMATION_STACK_QUOTA_CODE="L-0485CB21"
readonly GITHUB_OIDC_URL="https://token.actions.githubusercontent.com"
readonly GITHUB_OIDC_HOST="token.actions.githubusercontent.com"
readonly GITHUB_OIDC_AUDIENCE="sts.amazonaws.com"
readonly GOVERNANCE_STACK_NAME="bridgefu-nonproduction-governance"

mode="check"
profile=""
region="${DEFAULT_REGION}"
expected_account_id=""
budget_email=""
budget_amount="200"
confirmation=""
approved_source_commit=""
governance_template=""

usage() {
  printf '%s\n' \
    "Usage:" \
    "  ${SCRIPT_NAME} check --profile PROFILE --expected-account-id ACCOUNT_ID" \
    "  ${SCRIPT_NAME} apply --profile PROFILE --expected-account-id ACCOUNT_ID \\" \
    "    --budget-email EMAIL [--budget-amount 200] \\" \
    "    --approved-source-commit FULL_GIT_COMMIT \\" \
    "    --confirm PREPARE-BRIDGEFU-NONPRODUCTION-ACCOUNT_ID" \
    "" \
    "check is read-only. apply may request an EIP quota increase, create the" \
    "GitHub OIDC provider, and deploy/update the nonproduction governance stack."
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 2
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

while (($# > 0)); do
  case "$1" in
    check | apply)
      mode="$1"
      shift
      ;;
    --profile)
      (($# >= 2)) || fail "--profile requires a value"
      profile="$2"
      shift 2
      ;;
    --region)
      (($# >= 2)) || fail "--region requires a value"
      region="$2"
      shift 2
      ;;
    --expected-account-id)
      (($# >= 2)) || fail "--expected-account-id requires a value"
      expected_account_id="$2"
      shift 2
      ;;
    --budget-email)
      (($# >= 2)) || fail "--budget-email requires a value"
      budget_email="$2"
      shift 2
      ;;
    --budget-amount)
      (($# >= 2)) || fail "--budget-amount requires a value"
      budget_amount="$2"
      shift 2
      ;;
    --confirm)
      (($# >= 2)) || fail "--confirm requires a value"
      confirmation="$2"
      shift 2
      ;;
    --approved-source-commit)
      (($# >= 2)) || fail "--approved-source-commit requires a value"
      approved_source_commit="$2"
      shift 2
      ;;
    --governance-template)
      (($# >= 2)) || fail "--governance-template requires a value"
      governance_template="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

require_command aws
require_command jq

[[ -n "${profile}" ]] || fail "--profile is required"
[[ "${region}" == "us-west-2" ]] || fail "Bridgefu nonproduction is fixed to us-west-2"
[[ "${expected_account_id}" =~ ^[0-9]{12}$ ]] || fail "--expected-account-id must be 12 digits"
[[ "${budget_amount}" =~ ^[0-9]+([.][0-9]{1,2})?$ ]] || fail "--budget-amount must be a positive USD amount"
[[ ! "${budget_amount}" =~ ^0+([.]0{1,2})?$ ]] || fail "--budget-amount must be greater than zero"

if [[ -z "${governance_template}" ]]; then
  script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  governance_template="${script_directory}/../recipes/vapi-amazon-connect-screen-pop/cloudformation/account-governance.yaml"
fi

aws_global() {
  AWS_PROFILE="${profile}" AWS_PAGER="" aws --no-cli-pager "$@"
}

aws_regional() {
  AWS_PROFILE="${profile}" AWS_PAGER="" aws --no-cli-pager --region "${region}" "$@"
}

identity_json="$(aws_global sts get-caller-identity --output json)"
actual_account_id="$(jq -er '.Account' <<<"${identity_json}")"
caller_arn="$(jq -er '.Arn' <<<"${identity_json}")"

[[ "${actual_account_id}" == "${expected_account_id}" ]] ||
  fail "caller account ${actual_account_id} does not match expected account ${expected_account_id}"
[[ "${caller_arn}" != "arn:aws:iam::${actual_account_id}:root" ]] ||
  fail "root sessions are prohibited"
[[ "${caller_arn}" == arn:aws:sts::*:assumed-role/* ]] ||
  fail "a federated assumed-role session is required"

organization_json="$(aws_global organizations describe-organization --output json)" ||
  fail "the account is not an accessible AWS Organizations member"
organization_id="$(jq -er '.Organization.Id' <<<"${organization_json}")"
management_account_id="$(jq -er '.Organization.MasterAccountId' <<<"${organization_json}")"

eips_json="$(aws_regional ec2 describe-addresses --output json)"
eip_usage="$(jq -er '.Addresses | length' <<<"${eips_json}")"
eip_quota="$(aws_regional service-quotas get-service-quota \
  --service-code ec2 \
  --quota-code "${EIP_QUOTA_CODE}" \
  --query 'Quota.Value' \
  --output text)"
eip_quota_integer="${eip_quota%.*}"
eip_required="$((eip_usage + 2))"
if ((eip_required < 5)); then
  eip_required=5
fi
eip_headroom="$((eip_quota_integer - eip_usage))"

connect_json="$(aws_regional connect list-instances --output json)"
connect_usage="$(jq -er '.InstanceSummaryList | length' <<<"${connect_json}")"
connect_quota="$(aws_regional service-quotas get-service-quota \
  --service-code connect \
  --quota-code "${CONNECT_INSTANCE_QUOTA_CODE}" \
  --query 'Quota.Value' \
  --output text)"
connect_quota_integer="${connect_quota%.*}"
connect_headroom="$((connect_quota_integer - connect_usage))"

vpc_json="$(aws_regional ec2 describe-vpcs --output json)"
vpc_usage="$(jq -er '.Vpcs | length' <<<"${vpc_json}")"
vpc_quota="$(aws_regional service-quotas get-service-quota \
  --service-code vpc \
  --quota-code "${VPC_QUOTA_CODE}" \
  --query 'Quota.Value' \
  --output text)"
vpc_quota_integer="${vpc_quota%.*}"
vpc_headroom="$((vpc_quota_integer - vpc_usage))"

nat_gateway_usage="$(aws_regional ec2 describe-nat-gateways \
  --filter Name=state,Values=pending,available \
  --output json |
  jq -er '.NatGateways | length')"
nat_gateway_quota="$(aws_regional service-quotas get-service-quota \
  --service-code vpc \
  --quota-code "${NAT_GATEWAY_QUOTA_CODE}" \
  --query 'Quota.Value' \
  --output text)"
nat_gateway_quota_integer="${nat_gateway_quota%.*}"
nat_gateway_conservative_headroom="$((nat_gateway_quota_integer - nat_gateway_usage))"

lambda_json="$(aws_regional lambda get-account-settings --output json)"
lambda_total="$(jq -er '.AccountLimit.ConcurrentExecutions' <<<"${lambda_json}")"
lambda_unreserved="$(jq -er '.AccountLimit.UnreservedConcurrentExecutions' <<<"${lambda_json}")"

standard_vcpu_quota="$(aws_regional service-quotas get-service-quota \
  --service-code ec2 \
  --quota-code "${STANDARD_VCPU_QUOTA_CODE}" \
  --query 'Quota.Value' \
  --output text)"
standard_vcpu_quota_integer="${standard_vcpu_quota%.*}"

stacks_json="$(aws_regional cloudformation list-stacks --output json)"
active_stack_usage="$(jq -er '[.StackSummaries[] | select(.StackStatus != "DELETE_COMPLETE")] | length' <<<"${stacks_json}")"
stack_quota="$(aws_regional service-quotas get-service-quota \
  --service-code cloudformation \
  --quota-code "${CLOUDFORMATION_STACK_QUOTA_CODE}" \
  --query 'Quota.Value' \
  --output text)"
stack_quota_integer="${stack_quota%.*}"
stack_headroom="$((stack_quota_integer - active_stack_usage))"

iam_summary_json="$(aws_global iam get-account-summary --output json)"
role_usage="$(jq -er '.SummaryMap.Roles' <<<"${iam_summary_json}")"
role_quota="$(jq -er '.SummaryMap.RolesQuota' <<<"${iam_summary_json}")"
role_headroom="$((role_quota - role_usage))"

github_oidc_arn="$(aws_global iam list-open-id-connect-providers --output json |
  jq -r --arg suffix "oidc-provider/${GITHUB_OIDC_HOST}" \
    '.OpenIDConnectProviderList[]?.Arn | select(endswith($suffix))' |
  head -n 1)"
github_oidc_valid=0
if [[ -n "${github_oidc_arn}" ]]; then
  github_oidc_json="$(aws_global iam get-open-id-connect-provider \
    --open-id-connect-provider-arn "${github_oidc_arn}" \
    --output json)"
  if jq -e \
    --arg url "${GITHUB_OIDC_HOST}" \
    --arg audience "${GITHUB_OIDC_AUDIENCE}" \
    '.Url == $url and (.ClientIDList | index($audience) != null)' \
    <<<"${github_oidc_json}" >/dev/null; then
    github_oidc_valid=1
  fi
fi

trails_json="$(aws_regional cloudtrail describe-trails --include-shadow-trails --output json)"
validating_multiregion_trails="$(jq -er \
  '[.trailList[] | select(.IsMultiRegionTrail == true and .IncludeGlobalServiceEvents == true and .LogFileValidationEnabled == true)] | length' \
  <<<"${trails_json}")"
governance_trail_arn="$(jq -r \
  '.trailList[] | select(.Name == "bridgefu-nonproduction" and .IsMultiRegionTrail == true and .IncludeGlobalServiceEvents == true and .LogFileValidationEnabled == true) | .TrailARN' \
  <<<"${trails_json}" | head -n 1)"
governance_trail_logging=0
if [[ -n "${governance_trail_arn}" ]]; then
  if [[ "$(aws_regional cloudtrail get-trail-status --name "${governance_trail_arn}" --query 'IsLogging' --output text)" == "True" ]]; then
    governance_trail_logging=1
  fi
fi
config_recorders="$(aws_regional configservice describe-configuration-recorders --output json |
  jq -er '.ConfigurationRecorders | length')"
config_channels="$(aws_regional configservice describe-delivery-channels --output json |
  jq -er '.DeliveryChannels | length')"
recording_config_recorders="$(aws_regional configservice describe-configuration-recorder-status --output json |
  jq -er '[.ConfigurationRecordersStatus[] | select(.Recording == true)] | length')"
access_analyzers="$(aws_regional accessanalyzer list-analyzers --type ACCOUNT --output json |
  jq -er '[.analyzers[] | select(.status == "ACTIVE")] | length')"
guardduty_json="$(aws_regional guardduty list-detectors --output json)"
guardduty_detectors="$(jq -er '.DetectorIds | length' <<<"${guardduty_json}")"
enabled_guardduty_detectors=0
while IFS= read -r detector_id; do
  [[ -n "${detector_id}" ]] || continue
  if [[ "$(aws_regional guardduty get-detector --detector-id "${detector_id}" --query 'Status' --output text)" == "ENABLED" ]]; then
    enabled_guardduty_detectors="$((enabled_guardduty_detectors + 1))"
  fi
done < <(jq -r '.DetectorIds[]?' <<<"${guardduty_json}")

budget_exists=0
if aws_global budgets describe-budget \
  --account-id "${actual_account_id}" \
  --budget-name bridgefu-nonproduction-monthly \
  --output json >/dev/null 2>&1; then
  budget_exists=1
fi

governance_stack_status="absent"
if stack_json="$(aws_regional cloudformation describe-stacks \
  --stack-name "${GOVERNANCE_STACK_NAME}" --output json 2>/dev/null)"; then
  governance_stack_status="$(jq -er '.Stacks[0].StackStatus' <<<"${stack_json}")"
fi

jq -n \
  --arg mode "${mode}" \
  --arg account_id "${actual_account_id}" \
  --arg caller_arn "${caller_arn}" \
  --arg organization_id "${organization_id}" \
  --arg management_account_id "${management_account_id}" \
  --arg region "${region}" \
  --arg github_oidc_arn "${github_oidc_arn}" \
  --argjson github_oidc_valid "${github_oidc_valid}" \
  --arg governance_stack_status "${governance_stack_status}" \
  --argjson eip_usage "${eip_usage}" \
  --argjson eip_quota "${eip_quota_integer}" \
  --argjson eip_required "${eip_required}" \
  --argjson eip_headroom "${eip_headroom}" \
  --argjson connect_usage "${connect_usage}" \
  --argjson connect_quota "${connect_quota_integer}" \
  --argjson connect_headroom "${connect_headroom}" \
  --argjson vpc_usage "${vpc_usage}" \
  --argjson vpc_quota "${vpc_quota_integer}" \
  --argjson vpc_headroom "${vpc_headroom}" \
  --argjson nat_gateway_usage "${nat_gateway_usage}" \
  --argjson nat_gateway_quota "${nat_gateway_quota_integer}" \
  --argjson nat_gateway_conservative_headroom "${nat_gateway_conservative_headroom}" \
  --argjson lambda_total "${lambda_total}" \
  --argjson lambda_unreserved "${lambda_unreserved}" \
  --argjson standard_vcpu_quota "${standard_vcpu_quota_integer}" \
  --argjson active_stack_usage "${active_stack_usage}" \
  --argjson stack_quota "${stack_quota_integer}" \
  --argjson stack_headroom "${stack_headroom}" \
  --argjson role_usage "${role_usage}" \
  --argjson role_quota "${role_quota}" \
  --argjson role_headroom "${role_headroom}" \
  --argjson validating_multiregion_trails "${validating_multiregion_trails}" \
  --argjson governance_trail_logging "${governance_trail_logging}" \
  --argjson config_recorders "${config_recorders}" \
  --argjson config_channels "${config_channels}" \
  --argjson recording_config_recorders "${recording_config_recorders}" \
  --argjson access_analyzers "${access_analyzers}" \
  --argjson guardduty_detectors "${guardduty_detectors}" \
  --argjson enabled_guardduty_detectors "${enabled_guardduty_detectors}" \
  --argjson budget_exists "${budget_exists}" \
  '{
    mode: $mode,
    identity: {
      account_id: $account_id,
      caller_arn: $caller_arn,
      region: $region,
      organization_id: $organization_id,
      management_account_id: $management_account_id
    },
    capacity: {
      elastic_ips: {used: $eip_usage, applied_quota: $eip_quota, required_quota: $eip_required, headroom: $eip_headroom, required_headroom: 2},
      connect_instances: {used: $connect_usage, quota: $connect_quota, headroom: $connect_headroom, required_headroom: 1},
      vpcs: {used: $vpc_usage, quota: $vpc_quota, headroom: $vpc_headroom, required_headroom: 2},
      nat_gateways: {active_region_total: $nat_gateway_usage, per_az_quota: $nat_gateway_quota, conservative_headroom: $nat_gateway_conservative_headroom, required_headroom_in_runner_az: 1},
      lambda: {total_concurrency: $lambda_total, unreserved_concurrency: $lambda_unreserved, required_unreserved: 100},
      standard_on_demand_vcpus: {quota: $standard_vcpu_quota, required: 2},
      cloudformation_stacks: {active: $active_stack_usage, quota: $stack_quota, headroom: $stack_headroom, required_headroom: 20},
      iam_roles: {used: $role_usage, quota: $role_quota, headroom: $role_headroom, required_headroom: 30}
    },
    identity_federation: {
      github_oidc_provider_arn: (if $github_oidc_arn == "" then null else $github_oidc_arn end),
      github_oidc_provider_valid: ($github_oidc_valid == 1)
    },
    governance: {
      stack_status: $governance_stack_status,
      validating_multiregion_trails: $validating_multiregion_trails,
      bridgefu_trail_logging: ($governance_trail_logging == 1),
      config_recorders: $config_recorders,
      recording_config_recorders: $recording_config_recorders,
      config_delivery_channels: $config_channels,
      active_account_access_analyzers: $access_analyzers,
      guardduty_detectors: $guardduty_detectors,
      enabled_guardduty_detectors: $enabled_guardduty_detectors,
      budget_exists: ($budget_exists == 1)
    }
  }'

if [[ "${mode}" == "check" ]]; then
  if ((eip_headroom < 2 || connect_headroom < 1 || vpc_headroom < 2 ||
       nat_gateway_conservative_headroom < 1 ||
       lambda_unreserved < 100 || standard_vcpu_quota_integer < 2 ||
       stack_headroom < 20 || role_headroom < 30)); then
    printf '%s\n' "CHECK RESULT: account capacity is not ready" >&2
    exit 3
  fi
  if [[ -z "${github_oidc_arn}" || "${github_oidc_valid}" != "1" ||
        "${governance_stack_status}" != "CREATE_COMPLETE" && "${governance_stack_status}" != "UPDATE_COMPLETE" ||
        "${governance_trail_logging}" != "1" ||
        "${recording_config_recorders}" -lt 1 ||
        "${config_channels}" -lt 1 ||
        "${access_analyzers}" -lt 1 ||
        "${enabled_guardduty_detectors}" -lt 1 ||
        "${budget_exists}" != "1" ]]; then
    printf '%s\n' "CHECK RESULT: account bootstrap is incomplete" >&2
    exit 3
  fi
  printf '%s\n' "CHECK RESULT: AWS-admin prerequisites are ready"
  exit 0
fi

[[ "${budget_email}" =~ ^[^@[:space:]]+@[^@[:space:]]+$ ]] ||
  fail "apply requires a valid --budget-email"
expected_confirmation="PREPARE-BRIDGEFU-NONPRODUCTION-${expected_account_id}"
[[ "${confirmation}" == "${expected_confirmation}" ]] ||
  fail "apply requires --confirm ${expected_confirmation}"
[[ -f "${governance_template}" ]] || fail "governance template not found: ${governance_template}"
require_command git
[[ "${approved_source_commit}" =~ ^[0-9a-f]{40}$ ]] ||
  fail "apply requires --approved-source-commit with the full reviewed Git commit"
repository_root="$(git -C "$(dirname "${governance_template}")" rev-parse --show-toplevel 2>/dev/null)" ||
  fail "the governance template must be in a Git checkout"
actual_source_commit="$(git -C "${repository_root}" rev-parse HEAD)"
[[ "${actual_source_commit}" == "${approved_source_commit}" ]] ||
  fail "checkout ${actual_source_commit} does not match approved commit ${approved_source_commit}"
[[ -z "$(git -C "${repository_root}" status --porcelain --untracked-files=normal)" ]] ||
  fail "apply requires a clean working tree at the approved commit"

if ((connect_headroom < 1 || vpc_headroom < 2 ||
     nat_gateway_conservative_headroom < 1 ||
     lambda_unreserved < 100 || standard_vcpu_quota_integer < 2 ||
     stack_headroom < 20 || role_headroom < 30)); then
  fail "non-EIP account capacity is insufficient; resolve the reported quotas before apply"
fi

if [[ "${governance_stack_status}" == "absent" ]]; then
  if ((config_recorders > 0 || config_channels > 0 || access_analyzers > 0 || guardduty_detectors > 0)); then
    fail "existing Config, Access Analyzer, or GuardDuty singletons require manual reconciliation before governance deployment"
  fi
fi

if [[ -n "${github_oidc_arn}" && "${github_oidc_valid}" != "1" ]]; then
  fail "the existing GitHub OIDC provider lacks the required URL or sts.amazonaws.com audience"
fi

if ((eip_headroom < 2)); then
  pending_desired="$(aws_regional service-quotas list-requested-service-quota-change-history-by-quota \
    --service-code ec2 \
    --quota-code "${EIP_QUOTA_CODE}" \
    --output json |
    jq -r '[.RequestedQuotas[] | select((.Status == "PENDING" or .Status == "CASE_OPENED") and .DesiredValue >= '"${eip_required}"')] | length')"
  if ((pending_desired == 0)); then
    aws_regional service-quotas request-service-quota-increase \
      --service-code ec2 \
      --quota-code "${EIP_QUOTA_CODE}" \
      --desired-value "${eip_required}" \
      --output json
  else
    printf 'EIP quota request for at least %s is already pending.\n' "${eip_required}"
  fi
fi

if [[ -z "${github_oidc_arn}" ]]; then
  oidc_json="$(aws_global iam create-open-id-connect-provider \
    --url "${GITHUB_OIDC_URL}" \
    --client-id-list "${GITHUB_OIDC_AUDIENCE}" \
    --tags Key=Project,Value=bridgefu-recipe Key=Environment,Value=nonproduction \
    --output json)"
  github_oidc_arn="$(jq -er '.OpenIDConnectProviderArn' <<<"${oidc_json}")"
  printf 'Created GitHub OIDC provider: %s\n' "${github_oidc_arn}"
else
  printf 'Reusing GitHub OIDC provider: %s\n' "${github_oidc_arn}"
fi

aws_regional cloudformation deploy \
  --stack-name "${GOVERNANCE_STACK_NAME}" \
  --template-file "${governance_template}" \
  --parameter-overrides \
    Environment=nonproduction \
    BudgetAmountUsd="${budget_amount}" \
    BudgetEmail="${budget_email}" \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset

aws_regional cloudformation update-termination-protection \
  --stack-name "${GOVERNANCE_STACK_NAME}" \
  --enable-termination-protection

printf '%s\n' \
  "APPLY RESULT: bootstrap actions completed or submitted" \
  "GitHub OIDC provider ARN: ${github_oidc_arn}" \
  "Rerun check after any EIP quota request reaches APPROVED/APPLIED status."
