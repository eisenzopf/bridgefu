# HA capacity and bounded scaling

## Current contract

The first HA profile intentionally runs two gateway slots and two worker slots,
one task and one host per slot. Stable gateway EIPs, worker UUIDs, listener
ports, and task placement are configuration authority. The profile is not an
unbounded autoscaler and makes no concurrency claim until retained end-to-end
load evidence exists.

`MaxConcurrentCalls` is the per-gateway admission ceiling and
`MaxConcurrentCallsPerWorker` is the per-worker execution ceiling. Keep the
aggregate gateway admission ceiling at or below qualified worker/media/
PostgreSQL/Redis/Connect capacity. Raising either parameter is a reviewed
release change, not an alarm workaround.

## Signals

Use all of these together:

- active sessions, native routes, and private-forwarding routes by slot;
- cleanup backlog and setup/admission failures;
- RTP port availability and packet/drop rate;
- media/transcode utilization, CPU, memory, network, and file descriptors;
- PostgreSQL connections, CPU, storage, latency, and failover events;
- Redis connections, engine CPU, evictions, replication health, and failover;
- Lambda/API/DynamoDB errors and Amazon Connect throttling.

CPU alone is never a safe scaling signal for a stateful audio bridge.

## Capacity response

1. If a single slot is hot, confirm load distribution and target health before
   changing capacity.
2. If both slots approach the reviewed ceiling, lower upstream admission or
   divert to the approved fallback. Do not raise the ceiling beyond evidence.
3. Scale instance classes through an immutable CloudFormation change set, one
   idle protected slot at a time. Verify the other AZ first.
4. Scale RDS/Redis with their AWS-managed modification/failover workflows and
   rerun latency plus recovery qualification.
5. A future bounded C/D slot extension may automate scale-out only after the
   exact EIP/worker identity, call-aware scale-in, and failure gates pass. It is
   not advertised by v1.

## Load evidence required for a claim

Retain attempted/active/completed calls, setup and audio latency percentiles,
packet delivery/loss/jitter, DTMF, transcodes, host/resource measurements,
dependency errors, cleanup zero-state, and the exact image/recipe/
infrastructure revisions. Use synthetic data only. The release gate includes
at least one hour at the advertised steady load plus burst, drain, and failure
phases; retry masking is not allowed.
