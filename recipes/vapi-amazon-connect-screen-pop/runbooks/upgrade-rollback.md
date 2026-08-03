# Upgrade, drain, and rollback

## Impact

An image, recipe, Lambda, template, certificate, or configuration revision is
being changed, or an update has degraded calls.

## Before change

1. Verify the signed release manifest, source revision, image digest, every
   object version/checksum, SBOM/provenance, and vulnerability policy.
2. Review the complete nested CloudFormation change set. Unexpected replacement
   of the data table, data volume, EIP, Connect wrapper, or Vapi resources stops
   the change.
3. Record the previous immutable parameters and confirm backup/PITR health.
4. Stop new admissions and wait for active calls and cleanup backlog to reach
   zero. Announce a maintenance decision if they cannot.

## Upgrade

Apply the reviewed change, wait for stack/runtime readiness, run structural
doctor checks, then synthetic and controlled live calls before restoring normal
admission. Monitor setup latency, media quality, errors, and cleanup.

## Rollback

- Reapply the previous immutable image digest, Lambda object versions,
  templates, and recipe values through a reviewed change set.
- Do not roll a persistence/config contract backward unless compatibility is
  explicitly documented by the target release.
- If CloudFormation update rollback fails, preserve events and use
  `continue-update-rollback` with the smallest reviewed skip set; repair drift
  immediately afterward.
- Never delete retained production data to make rollback complete.

## Verify and record

Confirm exact revision, readiness, prepare/transfer/lookup, real SIPS/SRTP
audio/DTMF/hangup, zero cleanup, and alarms healthy. Retain change-set IDs,
digests, times, approval, and redacted results.
