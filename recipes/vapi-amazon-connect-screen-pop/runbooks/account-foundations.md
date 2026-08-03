# Bridgefu AWS account foundations

Use this runbook once per workload account. Application deployments must not
bootstrap their own long-term identity, artifact store, audit controls, or
Amazon Connect instance.

## Required account layout

- A workload-free AWS Organizations management account.
- A dedicated nonproduction workload account.
- A production workload account containing the approved existing Amazon
  Connect instance.
- IAM Identity Center access for administrators. Root is break-glass only.
- GitHub protected environments named `bridgefu-nonproduction` and
  `bridgefu-production` with required reviewers for production.

Do not apply restrictive SCPs to the existing production account until their
effect on Amazon Connect and Direct Connect has been reviewed separately.

## One-time order

1. From a federated administrator session, publish the reviewed foundation
   templates to an immutable HTTPS release location.
2. Deploy `cloudformation/account-governance.yaml`. Use USD 200 for
   nonproduction and USD 500 for the production pilot unless a different
   approved budget is recorded. Confirm the budget email subscriptions.
3. In nonproduction, deploy
   `cloudformation/nonproduction-foundation.yaml` once with the exact
   `CREATE_PERSISTENT_NONPRODUCTION_CONNECT` acknowledgement. Record its
   Connect instance and target-flow outputs.
4. Deploy `cloudformation/account-foundation.yaml` with the environment's
   Connect ARN, public hosted-zone ID, Identity Center role ARN, GitHub OIDC
   provider ARN, and immutable nested-template base URL.
5. Enable termination protection on all foundation root stacks.
6. Put the environment-specific Vapi API key in Secrets Manager out of band.
   Nonproduction and production must use distinct credentials.
7. Configure these GitHub environment variables from the foundation outputs:
   `BRIDGEFU_AWS_DEPLOYMENT_ROLE_ARN`, `BRIDGEFU_AWS_ACCOUNT_ID`, and
   `BRIDGEFU_AWS_REGION`.
8. Delegate the stable Route 53 subzone at the external parent and confirm its
   public NS response before requesting a certificate.

## Acceptance checks

- `aws sts get-caller-identity` returns an assumed role in the intended account,
  never the account root or an IAM user.
- CloudTrail reports an actively logging multi-region trail; Config has a
  recorder and delivery channel; Access Analyzer is active; GuardDuty is
  enabled; production has Security Hub; and at least one account budget exists.
- The artifact bucket is private, encrypted, versioned, and retained. The ECR
  repository is immutable and scans on push.
- The deployer can pass only the exact CloudFormation service role. The service
  role trusts only CloudFormation.
- The deployment rollback alarm exists before an application change set.
- `bridgefu recipe preflight` passes with the schema-2 environment descriptor.

Never place customer data, Vapi secret values, generated agent passwords, or
GitHub credentials in a descriptor, CloudFormation parameter, output, or
workflow artifact.
