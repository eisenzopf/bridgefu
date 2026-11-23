# AWS runbook

Use this alongside the [setup guide](SETUP.md) or [existing-environment walkthrough](EXISTING-ENVIRONMENT.md). Commands use placeholders so no account, user, contact, or assistant IDs are published here. Replace them with your own private values. Command output may contain those values or contact context; do not paste raw output into a public issue.

## Confirm your AWS access

```sh
aws sso login --profile YOUR_AWS_PROFILE
aws sts get-caller-identity --profile YOUR_AWS_PROFILE
```

The account should be the one containing your nonproduction Connect instance. Set `--region YOUR_REGION` explicitly for the commands below.

## Find your Connect instance and flow

```sh
aws connect list-instances \
  --profile YOUR_AWS_PROFILE --region YOUR_REGION \
  --query 'InstanceSummaryList[].{Name:InstanceAlias,Arn:Arn,Status:InstanceStatus}'

aws connect list-contact-flows \
  --instance-id YOUR_CONNECT_INSTANCE_ARN \
  --contact-flow-types CONTACT_FLOW \
  --profile YOUR_AWS_PROFILE --region YOUR_REGION \
  --query 'ContactFlowSummaryList[].{Name:Name,Arn:Arn}'

aws connect describe-contact-flow \
  --instance-id YOUR_CONNECT_INSTANCE_ARN \
  --contact-flow-id YOUR_TARGET_FLOW_ARN \
  --profile YOUR_AWS_PROFILE --region YOUR_REGION \
  --query 'ContactFlow.{Name:Name,Status:Status,State:State}'
```

The target flow should be `PUBLISHED` and `ACTIVE`. Its ARN must belong to the same instance and region you supply to the deploy helper.

## Inspect the example deployment

```sh
aws cloudformation describe-stacks \
  --stack-name YOUR_UNIQUE_EXAMPLE_NAME \
  --profile YOUR_AWS_PROFILE --region YOUR_REGION \
  --query 'Stacks[0].{Status:StackStatus,Outputs:Outputs}'
```

Useful outputs:

| Output | Use |
| --- | --- |
| `EntryContactFlowArn` | Flow Bridgefu starts; use this in gateway IAM permissions |
| `WebhookUrl` | HTTPS server for the Vapi function tool |
| `WebhookSecretArn` | Reference to the webhook secret; the helper fills the tool header |
| `TransferFunctionName` | Lambda that prepares and requests the transfer |
| `LookupFunctionName` | Correlation mode only: Connect context resolver |
| `ContextTableName` | Correlation mode only: expiring context store |

If deployment fails:

```sh
aws cloudformation describe-stack-events \
  --stack-name YOUR_UNIQUE_EXAMPLE_NAME \
  --profile YOUR_AWS_PROFILE --region YOUR_REGION \
  --query 'StackEvents[?contains(ResourceStatus, `FAILED`)].{Resource:LogicalResourceId,Reason:ResourceStatusReason}'
```

Read the first resource failure, not just the final rollback. Common causes are missing deployment permissions, a target flow in another instance, or service quotas. Keep the private deployment state for cleanup.

## Check a disposable gateway build

The test gateway uses Systems Manager rather than SSH. Its instance ID is in the private test state's `gateway_outputs.InstanceId`.

```sh
aws ssm send-command \
  --instance-ids YOUR_TEST_GATEWAY_INSTANCE_ID \
  --document-name AWS-RunShellScript \
  --parameters '{"commands":["tail -n 30 /var/log/bridgefu-bootstrap.log","tail -n 30 /var/log/bridgefu-build.log","tail -n 30 /var/log/peer-build.log"]}' \
  --profile YOUR_AWS_PROFILE --region YOUR_REGION \
  --query Command.CommandId --output text

aws ssm get-command-invocation \
  --command-id YOUR_RETURNED_COMMAND_ID \
  --instance-id YOUR_TEST_GATEWAY_INSTANCE_ID \
  --profile YOUR_AWS_PROFILE --region YOUR_REGION
```

The first build is CPU-intensive. `Compiling` without an error normally means it is still working. Bootstrap output also shows certificate setup failures. Keep these logs private.

## Check the gateway's AWS role

The gateway needs these actions. Substitute your own ARNs in this policy fragment:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "connect:StartWebRTCContact",
      "Resource": "YOUR_ENTRY_CONTACT_FLOW_ARN"
    },
    {
      "Effect": "Allow",
      "Action": "connect:StopContact",
      "Resource": "YOUR_CONNECT_INSTANCE_ARN/contact/*"
    }
  ]
}
```

The example's Lambda roles are created by CloudFormation. They are separate from the gateway role. The transfer Lambda reads its webhook/Vapi secrets; correlation mode also allows it to write context. The lookup Lambda can read its context table and does not receive the Vapi secret.

On a gateway managed by systemd:

```sh
sudo systemctl status bridgefu
sudo journalctl -u bridgefu --since '10 minutes ago'
```

Treat logs as private. Check config validation, TLS certificate loading, admission failures, and AWS start/cleanup errors before changing the assistant.

## Inspect a real test contact

Find the contact in Connect's contact search or the private test evidence. Use its initial contact ID:

```sh
aws connect describe-contact \
  --instance-id YOUR_CONNECT_INSTANCE_ARN \
  --contact-id YOUR_CONTACT_ID \
  --profile YOUR_AWS_PROFILE --region YOUR_REGION

aws connect get-contact-attributes \
  --instance-id YOUR_CONNECT_INSTANCE_ARN \
  --initial-contact-id YOUR_INITIAL_CONTACT_ID \
  --profile YOUR_AWS_PROFILE --region YOUR_REGION
```

Compare values, not just field presence. With the default header example, expect `customer_session`, `vapi_reference`, `customer_intent`, and `conversation_summary`. With correlation mode, also expect `handoff_id` and `handoff_status=found`. Your configured names take precedence.

After hanging up, `describe-contact` should include a disconnect timestamp. If a test contact is stuck, stop that exact contact:

```sh
aws connect stop-contact \
  --instance-id YOUR_CONNECT_INSTANCE_ARN \
  --contact-id YOUR_TEST_CONTACT_ID \
  --profile YOUR_AWS_PROFILE --region YOUR_REGION
```

## Diagnose a failed handoff

| What you observe | Check next |
| --- | --- |
| No function call in Vapi | The assistant prompt, tool name, and tool schema. The caller must request a transfer. |
| Function endpoint returns 401 | The Vapi tool's webhook secret must match this deployment. Use the deploy helper to populate it. |
| Function returns “Transfer not confirmed” | Inspect the Lambda's static failure stage below. Do not automatically repeat an ambiguous transfer. |
| `fetch_call` failure | Vapi key validity, network access, and the live call's status. |
| `validate_fields` failure | Required input variables, actual argument names, byte limits, and control characters. Supply the session at call start. |
| `prepare_destination` failure | Correlation table permissions, expiry, or conflicting retry values. |
| `request_transfer` failure | Vapi live control availability and transfer support for that call type. |
| SIP 403 | Fixed SIP user, trusted source CIDRs, TLS policy, and duplicate/malformed configured headers. |
| Secure signaling but no call setup | Required SRTP versus the media profile offered by Vapi. TLS and RTP encryption are separate. |
| Connect contact exists but agent does not ring | Published target flow, queue membership, routing profile, and agent Available status. |
| Correlation status is `unavailable` | Lookup Lambda association/permission, token attribute mapping, item expiry, and lookup logs. |
| Call works but an attribute is absent | Settings must agree across the generated tool, header map, and flow. Inspect actual tool arguments and contact attributes. |
| One-way audio | Gateway public media IP, UDP ports, SDP/security negotiation, and browser microphone permission. |

The transfer Lambda logs a static stage and exception class, without event bodies, context, call IDs, or secrets:

```sh
aws logs filter-log-events \
  --log-group-name /aws/lambda/YOUR_UNIQUE_EXAMPLE_NAME-transfer \
  --filter-pattern handoff_failed \
  --profile YOUR_AWS_PROFILE --region YOUR_REGION
```

Do not enable raw webhook logging to investigate this example. The private automated test evidence already retains the inputs needed for an exact comparison.

## Remove your example resources

Use the recorded state, with `VAPI_PRIVATE_KEY` still available:

```sh
python3 examples/vapi-amazon-connect/shared/manage.py cleanup \
  --state examples/vapi-amazon-connect/.local/deployment.json
```

This deletes the new assistant, example stack, context table if present, and example secrets. It keeps your preexisting Connect instance, target flow, and gateway. The example context table has a delete policy; export anything you intentionally need before cleanup.

If you used the complete disposable test environment, use its broader cleanup instead:

```sh
python3 examples/vapi-amazon-connect/tests/live.py cleanup \
  --state examples/vapi-amazon-connect/.local/live/state.json
```

That also removes its temporary phone entries, selectors, gateway, DNS record, artifact bucket contents, agent, and Connect instance. Keep the private state until cleanup completes. Do not delete unrelated resources by matching a broad name prefix.
