# Cleanup backlog or orphan Amazon contact

## Impact

An Amazon contact, Bridgefu call, route reservation, or capacity lease remains
after hangup. Continued backlog can consume capacity and create unexpected
Connect charges.

## Safe checks

1. Stop new admissions if backlog is increasing; keep established calls
   running.
2. Read cleanup pending/age/retry metrics and durable call/effect state.
3. For each restricted operational contact reference, compare Bridgefu state
   with `DescribeContact`; do not bulk-stop unrelated customer contacts.
4. Verify runtime StopContact permissions, AWS availability, retry/backoff, and
   the current leader/worker lease.
5. Confirm whether the source or destination already ended before intervening.

## Remediation

- Restore dependency access and allow the durable reconciler to retry first.
- Drain the runtime before restart or replacement. Recovery must replay durable
  cleanup effects.
- Manually stop a contact only after proving it was created by this recipe,
  remains active, and automatic reconciliation cannot complete. Record the
  approval and exact target.
- Never delete the state database to clear an alarm; that removes the evidence
  needed for safe cleanup.

## Verify

Require active calls, pending cleanups, reserved attachments, and capacity
leases to return to zero. Repeat both Vapi-led and agent-led hangup, restart
recovery, and dependency outage tests before closing.
