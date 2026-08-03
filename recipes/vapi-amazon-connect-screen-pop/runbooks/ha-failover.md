# HA failure, drain, and recovery

## Impact and limits

The HA profile keeps new-call service available through loss or controlled
replacement of one gateway or worker slot. Existing calls on an abruptly lost
media process may end; no system can migrate that process's in-memory RTP/
WebRTC state after host loss. Controlled scale-in and updates close admission,
send `SIGTERM`, and allow a 120-second Bridgefu drain before replacement.

## Safe read-only triage

1. Run `bridgefu recipe status deployment.yaml --profile high-availability`.
2. Run `bridgefu recipe doctor deployment.yaml --profile high-availability`.
3. Open `DashboardUrl`; check the four readiness series, active sessions,
   cleanup backlog, RDS, Redis, and handoff error panels.
4. Describe ECS services and container instances. Each service must be 1/1 and
   each `bridgefu.slot` must occur exactly once.
5. Describe the four Auto Scaling groups. Each desired capacity is one.
6. Check both public NLB targets and both control targets. Do not terminate a
   second slot while one is unhealthy.

## Controlled replacement

Use a reviewed CloudFormation change set or an instance refresh. The host timer
sets Auto Scaling instance protection whenever active-session, native-route,
private-forwarding-route, or cleanup metrics are nonzero. Once idle, the
termination hook puts the ECS instance in `DRAINING`, stops the one exact task,
waits for graceful shutdown, and completes the lifecycle action. A replacement
gateway then reassociates only its fixed slot EIP before becoming ready.

If an update is waiting, do not disable protection blindly. Confirm the slot
metrics are zero and the peer AZ is ready first. A forced termination is an
incident action and can end active calls.

## Failure drill

Run only in an approved synthetic environment with an execution ledger and
cost/time limit:

1. Record stack, image digest, recipe fingerprint, task definitions, EIP
   associations, RDS/Redis IDs, and alarm state.
2. Establish synthetic calls through both gateway targets.
3. Terminate gateway A without decrementing desired capacity. Prove gateway B
   accepts new calls, A's EIP moves to its replacement, ECS returns 1/1, and
   cleanup reaches zero.
4. Repeat for gateway B only after full recovery.
5. Repeat one worker at a time. Record expected impact to a call pinned to the
   failed worker and prove new calls continue through the other worker.
6. Exercise an RDS reboot with failover and an ElastiCache primary failover
   using AWS-supported control-plane operations. Prove bounded recovery and no
   duplicate Amazon Connect contacts.
7. Run an AZ impairment drill only in a disposable account and never by
   changing customer-owned networking.
8. Re-run context, screen-pop, two-way non-silent audio, DTMF, both hangups,
   replay rejection, and zero-state checks.

## Recovery and escalation

- If one slot does not recover, keep it out of service and preserve the healthy
  AZ. Inspect cloud-init, ECS agent, task stopped reason, NLB health, and the
  lifecycle Lambda log through SSM/CloudWatch.
- If both gateway slots are unhealthy, stop transfer traffic at Vapi and route
  callers through the approved fallback; do not expose the private control API.
- If PostgreSQL or Redis is unavailable, stop new admission before manual data
  changes. Use AWS-managed failover/restore procedures and the immutable stack
  parameters.
- Escalation evidence may include timestamps, redacted call IDs, resource IDs,
  task stopped reasons, alarm transitions, and revision hashes. It must not
  include customer fields, correlation IDs, tokens, certificates, or keys.
