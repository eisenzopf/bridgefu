# Deployment and runtime readiness

## Impact

CloudFormation is not complete, Bridgefu reports not-ready, or new transfers
cannot be admitted. Existing calls may remain healthy; do not replace the host
until active sessions and cleanup state are known.

## Safe checks

1. Read the root and nested CloudFormation events. Identify the first failed
   logical resource, not the last cascading failure.
2. Check the EC2 system/instance status and Systems Manager managed-node state.
3. Open the runtime and Prometheus log groups. Search only bounded error/result
   fields; do not enable request-body logging.
4. Through SSM, inspect `systemctl status bridgefu haproxy docker
   amazon-cloudwatch-agent` and `journalctl` for the failed unit.
5. Check the encrypted data-volume attachment/mount, immutable image digest,
   certificate files, and `/readyz` on loopback.
6. If the stack is waiting, inspect the bootstrap console log before extending
   the WaitCondition timeout.

## Decision and remediation

- Package/repository failure: verify the exact S3 object version, SHA-256, ECR
  digest, runtime role policy, and VPC endpoint/egress path. Republish; never
  substitute `latest`.
- Data-volume failure: verify one non-root volume is attached in the expected
  AZ. Do not format a volume that already has an unexpected filesystem.
- Config failure: render in a clean directory and run the real Bridgefu
  `validate` command. Fix the recipe/compiler input, not the generated host
  file.
- Certificate failure: use [DNS and certificates](dns-certificate.md).
- Service crash: capture status, exit code, image digest, and bounded logs.
  Roll back to the previous reviewed digest if the failure follows an update.
- EC2 system failure with no active calls: allow the recovery alarm or replace
  through CloudFormation. With active calls, drain if possible before action.

Never add SSH, make the control API public, disable IMDSv2, or loosen the
security group as a diagnostic shortcut.

## Verify and close

Confirm `/livez` and `/readyz`, SIPS hostname verification, CloudWatch
`RuntimeReady=1`, no cleanup backlog, the expected image digest, and a passing
synthetic prepare/transfer/lookup check. Record logical resource, cause,
revision, action, and times; omit customer data and correlation IDs.
