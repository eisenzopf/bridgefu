# Capacity, throttling, and high CPU

## Impact

New calls are rejected or slow, Lambda throttles, CPU remains high, or media
queues drop packets. Protect active audio before increasing limits.

## Safe checks

1. Compare active sessions with `MaxConcurrentCalls`, CPU, memory, network,
   media queue drops, transcode errors, Lambda concurrency, API throttles, and
   DynamoDB throttles.
2. Separate legitimate concurrency from retry storms or unauthenticated abuse.
3. Check codec/transcode mix and recent image/config changes.
4. Confirm cleanup backlog is not retaining capacity.

## Remediation

- Stop abusive/retry traffic at the authenticated source and keep rate limits.
- Drain and move Starter to the next reviewed instance size when measured CPU
  is the constraint. Do not resize during active calls without a maintenance
  decision.
- Raise API/Lambda limits only with corresponding runtime capacity and budget.
- For sustained multi-host requirements, use the qualified HA profile; do not
  place a generic load balancer in front of stateful SIP/RTP and call it HA.

## Verify

Run the approved load shape with zero queue drops, zero transcode errors, no
cleanup backlog, acceptable p95 setup/audio latency, and sufficient CPU
headroom. Retain duration, concurrency, codec mix, instance type, and revision.
