# Starter recovery, backup, and disaster recovery

## Impact

The single Starter host or Availability Zone is unavailable. New calls stop and
active calls on that host end; context in DynamoDB remains independent.

## Safe checks

1. Confirm EC2 system versus instance failure, volume health, Elastic IP
   association, DNS, SSM state, alarms, and active-call/cleanup evidence.
2. Check the latest encrypted data-volume recovery point and DynamoDB PITR
   window. Identify the recovery point before changing resources.
3. Preserve failed-host logs and console output.

## Remediation

- For a system-status failure, use EC2 recovery when safe. The EIP and volumes
  remain attached to the logical instance.
- For an application failure, roll back the immutable image/config after
  draining or acknowledging active-call loss.
- For instance loss, create a reviewed replacement, attach or restore the
  encrypted data volume, re-associate the EIP, validate state, then admit calls.
- For volume corruption, restore to a new volume from AWS Backup; never overwrite
  the only retained volume.
- For context-table corruption or accidental writes, restore DynamoDB to a new
  table at a selected PITR time and update through a reviewed stack change.

Starter has recovery, not seamless AZ failover. Deploy the qualified HA profile
when the recovery-time objective requires continued admission through host/AZ
loss.

## Verify

Prove data mount, validator/readiness, certificate, EIP/DNS, synthetic handoff,
durable cleanup reconciliation, and a controlled real call. Document recovery
point/time, data loss window, revision, and RTO/RPO outcome without PII.
