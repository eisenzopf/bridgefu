# Bridgefu AWS High Availability Terraform module

This module composes the exact canonical CloudFormation application in a
Terraform-managed AWS estate. It selects `RuntimeProfile=HighAvailability` and
therefore creates two bounded gateway slots, two bounded worker slots,
Multi-AZ PostgreSQL, TLS Valkey 7.2 (Redis-protocol compatible), private
control/forwarding load balancers, and
AWS-native dashboards and alarms. It does not duplicate those security and
deletion contracts in Terraform.

Create the private mTLS bundle first:

```text
python3 scripts/create-recipe-ha-private-tls.py \
  --deployment-id support \
  --worker-hostname worker.sip.example.com \
  --region us-west-2
```

Pass the resulting ARN as `PrivateTlsSecretArn` in `parameters`. The secret is
administrator-owned so that a stack replacement cannot destroy the private CA;
rotate or delete it deliberately according to `runbooks/ha-private-tls.md`.

The HA profile is `preview` until the exact published revision has retained
gateway/worker/AZ/database/Redis failure, load, latency, upgrade, and rollback
evidence. Use Starter Production for the smallest already-hardened footprint.
