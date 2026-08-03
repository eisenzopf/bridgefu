# Handoff API, DynamoDB, and context availability

## Impact

Prepare or transfer fails, DynamoDB throttles, or agents receive a call with
generic “context unavailable” fields. Voice routing intentionally fails open
when lookup data is absent.

## Safe checks

1. Use the dashboard to identify prepare, transfer, lookup, API, or DynamoDB as
   the failing hop.
2. Inspect Lambda result codes and duration, API status/route, DynamoDB
   throttles, TTL/PITR state, and transfer Lambda VPC ENIs.
3. Reproduce with synthetic data. Never put production PII in a diagnostic
   request.
4. For one known synthetic call, derive the correlation locally and use
   `GetItem`; do not scan the table or paste the key into tickets.
5. Check record state/expiry, content hash, deployment ID, and Vapi call
   fingerprint without logging their values.
6. Verify private DNS resolves `control.<sip-hostname>` to the instance private
   IP and port 443 is reachable only from the transfer Lambda security group.

## Remediation

- 401: restore the current Vapi webhook secret association.
- 409 replay conflict: do not retry with altered fields under the same Vapi
  call identity; create a new call.
- 410 expiry: prepare a new handoff.
- 429: stop abusive retries, then adjust reviewed API/Lambda limits if measured
  legitimate demand requires it.
- Private reservation failure: restore Bridgefu readiness, private DNS/TLS,
  fixed route `support`, and the exact API bearer secret. Do not expose the
  control route publicly.
- DynamoDB failure: restore table availability/PITR/TTL and exact Lambda role
  permissions. Do not disable encryption or broaden table access.

## Verify

Prove create/replay idempotency, conflicting replay rejection, reservation,
one fixed header, bounded lookup fields, missing/expired fail-open behavior,
and no correlation/customer values in logs or evidence.
