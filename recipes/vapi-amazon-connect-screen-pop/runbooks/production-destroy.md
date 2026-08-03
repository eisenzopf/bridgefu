# Production deletion break-glass

Normal `bridgefu recipe destroy` refuses a production descriptor. Use this
runbook only for an approved product uninstall or unrecoverable incident—not
for rollback, routine updates, or traffic disablement.

## Preconditions

1. Record owner, security, operations, and change-management approval.
2. Stop new Vapi routing to the Bridgefu SIP hostname and prove active sessions
   and pending durable cleanups are zero.
3. Run `bridgefu recipe doctor` and retain its redacted output, recursive drift
   result, stack events, current release manifest, and target-flow description.
4. Confirm the exact stack account, region, tags, persisted service role, and
   `EnableTerminationProtection=true` with `describe-stacks`.
5. Confirm data-retention and export requirements. Production DynamoDB, EBS,
   backups, and HA database resources may be retained or snapshotted. Vapi
   objects are retained by the production parameter and require a separate
   ownership-checked removal decision.

## Controlled deletion

From a federated production administrator session, set variables to the exact
reviewed values; never derive them from a wildcard or name prefix.

```bash
aws cloudformation update-termination-protection \
  --region "$AWS_REGION" \
  --stack-name "$BRIDGEFU_STACK_NAME" \
  --no-enable-termination-protection

aws cloudformation delete-stack \
  --region "$AWS_REGION" \
  --stack-name "$BRIDGEFU_STACK_NAME" \
  --role-arn "$BRIDGEFU_CLOUDFORMATION_ROLE_ARN" \
  --deletion-mode STANDARD

aws cloudformation wait stack-delete-complete \
  --region "$AWS_REGION" \
  --stack-name "$BRIDGEFU_STACK_NAME"
```

If deletion fails, stop and preserve events. Do not force-delete or remove
resources manually until ownership and retention are reviewed.

## Required final evidence

- The customer-owned Connect instance and target flow still exist and the
  target flow content matches its pre-deletion capture.
- Only recipe-owned wrapper/guide flows and Lambda associations were removed.
- Retained data, snapshots, backups, and Vapi objects are explicitly listed
  with owners and expiry/removal decisions.
- No EIP, NAT gateway, endpoint, instance, role, secret, log group, preview
  stack, or external Vapi object remains unintentionally owned by the deleted
  application.
- Account governance and account-foundation stacks remain protected and
  operational.
