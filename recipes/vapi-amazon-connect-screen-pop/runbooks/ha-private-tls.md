# HA private mTLS identity

## Impact

The HA gateways authenticate to workers with a recipe-private CA. If the
bundle is missing, malformed, expired, or inconsistent, gateways remain unable
to forward new calls even when SIP and ECS look healthy. Public ACM
certificates are separate and rotate automatically on idle gateway slots.

## Initial creation

Use a non-root IAM or federated AWS identity that can create one tagged Secrets
Manager secret. The worker hostname must be exactly `worker.<SipHostname>`:

```text
python3 scripts/create-recipe-ha-private-tls.py \
  --deployment-id DEPLOYMENT_ID \
  --worker-hostname worker.sip.example.com \
  --region AWS_REGION
```

The command prints only the secret ARN. It never prints a key or certificate,
uses a temporary `0700` directory, verifies the chain and worker hostname, and
refuses to overwrite a secret whose ownership tags do not match the deployment.
Put that ARN in `PrivateTlsSecretArn`. The JSON keys are an exact contract:
`ca_crt`, `gateway_crt`, `gateway_key`, `worker_crt`, and `worker_key`.

## Safe checks

1. Run `bridgefu recipe doctor deployment.yaml --profile high-availability`.
2. Confirm all four slot readiness alarms are `OK`.
3. Inspect certificate metadata without retrieving key material:

   ```text
   aws secretsmanager describe-secret --secret-id SECRET_ARN --region AWS_REGION
   ```

4. On an SSM-authorized host, inspect only expiry/subject data from the mounted
   certificate. Never copy or log `/etc/bridgefu/private/*.key`.

## Rotation

The v1 bundle has one CA trust set, so private-CA rotation is deliberately
blue/green instead of an unsafe mixed in-place restart:

1. Create a second deployment ID and private bundle.
2. Deploy the same immutable recipe release with the new ID and distinct SIP
   hostname.
3. Run structural, synthetic, audio, DTMF, and screen-pop qualification.
4. Move the Vapi transfer destination to the new deployment.
5. Verify the old deployment has zero sessions and cleanup backlog.
6. Delete the old stack according to its retention mode.
7. Schedule deletion of the old external secret only after the rollback window.

Re-running the helper for an existing ID replaces the whole bundle atomically,
but that behavior is intended for a controlled recovery before traffic or a
coordinated maintenance window—not ad-hoc production rotation.

## Teardown

The private TLS secret is administrator-owned and intentionally outside the
CloudFormation stack so a failed replacement cannot destroy the CA. After the
stack is deleted, inventory proves no instances use it, and the rollback window
has ended, schedule recoverable deletion:

```text
aws secretsmanager delete-secret --secret-id SECRET_ARN \
  --recovery-window-in-days 30 --region AWS_REGION
```

Never force-delete it during an incident. Retain the ARN, deployment ID,
certificate serials/expiry, and deletion change record; do not retain keys.
