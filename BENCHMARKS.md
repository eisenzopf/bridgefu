# Benchmark gates

The repository does not publish unmeasured performance claims. Release builds
must record hardware, kernel, cloud topology, packet size, codec mix, loss,
jitter, and exact commits, then satisfy these gates:

- 100 bidirectional G.711↔Opus calls for one hour at 10 CPS.
- One UCTP publisher to 1,000 direct listeners for one hour.
- One MOQT origin through relays to 10,000 simulated listeners for one hour.
- Bridge-added media latency below 100 ms p95.
- Memory growth below 10% after warm-up.
- Slow listeners never stall a source graph.

Results belong in dated files under `benchmarks/results/`; failures are release
blockers, not values to average away.
