# Vapi provisioning and authentication

## Impact

The Vapi nested stack fails, prepare/transfer webhooks return 401/403, or the
assistant does not request a dynamic transfer destination.

## Safe checks

1. Read the Vapi provisioner Lambda result code and CloudFormation custom
   resource reason. Payloads and keys must remain absent from logs.
2. Verify the supplied secret ARN exists, is in-region, and its resource policy
   permits only the provisioner role to read it.
3. In Vapi, confirm the assistant/tool names and Bridgefu ownership metadata,
   prepare/transfer URLs, one credential ID, empty static transfer
   destinations, and `transfer-destination-request` server message.
4. Send an authenticated synthetic prepare event. A wrong token must return
   401 without DynamoDB writes.
5. Check HTTP API throttles and Lambda concurrency before treating a 429 as an
   authentication failure.

## Remediation

- Correct the Vapi API-key secret and update the stack. Never paste it into a
  CloudFormation parameter or terminal history.
- Resolve ownership conflicts manually. Do not rename/delete a same-named Vapi
  object unless its metadata proves it belongs to this stack.
- Restore the exact custom credential association if an administrator edited
  the assistant.
- Rotate webhook authentication with a blue/green recipe deployment: create
  and verify the new assistant/secret, move the website or phone binding, drain
  old calls, then delete the old deployment. This provides an overlap window
  without weakening either endpoint.

## Verify

Run idempotent prepare twice, request transfer, and confirm one SIPS URI and one
`X-Correlation-Id`. Verify Vapi object IDs are unchanged on a no-op update and
owned objects disappear on test teardown.
