# Benchmark gates and current evidence

The repository does not publish unmeasured performance claims. Release builds
must record hardware, kernel, cloud topology, packet size, codec mix, loss,
jitter, dirty-worktree state, and exact Bridgefu, rvoip, moq-rs, WebRTC, and RTC
revisions, then satisfy these gates:

- 100 bidirectional G.711↔Opus calls for one hour at 10 CPS.
- One UCTP publisher to 1,000 direct listeners for one hour.
- One MOQT origin through relays to 10,000 simulated listeners for one hour.
- Bridge-added media latency below 100 ms p95.
- Memory growth below 10% after warm-up.
- Slow listeners never stall a source graph.

Results belong in dated files under `benchmarks/results/`; failures are release
blockers, not values to average away.

## Current local smoke results

These short macOS development runs validate the executable harnesses only.
They are not release results and do not close any one-hour gate.

| Harness | Local smoke | Result |
|---|---:|---|
| Bidirectional MediaGraph transcoding | 1 call, 3 seconds | 302/302 frames and transcodes, no drops/eviction/errors, 1.1 ms p95 bound, 0.71% RSS growth |
| UCTP bounded direct fanout | 16 listeners, 3 seconds | 2,464/2,464 deliveries, no source/publisher drops, 0.4 ms p95 bound, 0.64% RSS growth, capacity rejection verified |
| UCTP authenticated raw-QUIC network | 4 listeners, 3 seconds | 612/612 complete RTP datagrams, 20 wire refreshes, old/current replay probes rejected, no protocol/cleanup errors, 7.3 ms p95 bound, 0.26% RSS growth |
| MOQT draft-19 relay audio | 4 authenticated raw-QUIC listeners, 3 seconds | 151/151 LOC objects per listener, 604 latency samples, no lag/reconnect/cleanup errors, 10 ms p95, 16 ms maximum, 0.66% RSS growth |

The MOQT smoke traverses a real local relay and validates the MSF catalog and
LOC audio objects at every listener. It does not substitute for a separately
deployed relay tier. The UCTP smoke drives the bounded publisher queues; the
separate authenticated network smoke creates one real receive-only raw-QUIC
peer per listener through Bridgefu authorization, the rvoip Orchestrator, and a
MediaGraph-backed virtual publisher. It parses complete UCTP 0.2 RTP datagrams
and verifies credential rotation, replay rejection after initial expiry, and
exact cleanup. Neither local UCTP smoke substitutes for the immutable
1,000-peer one-hour run or deployed-network evidence.

## Reproducing and retaining evidence

The immutable release profiles, environment acknowledgements, report schemas,
failure thresholds, and exact commands are documented in
[`docs/qualification.md`](docs/qualification.md). Each harness writes its JSON
report before asserting so a failed run is retained. The release profile must
run on the intended Linux qualification host; shortening a duration or lowering
a subscriber count changes the run to smoke evidence.

Provider, StandardCharter, cloud, and chaos evidence are deliberately separate
from these throughput measurements. A media benchmark cannot turn a skipped
credentialed workflow into a pass.
