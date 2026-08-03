# Changelog

## Unreleased — 2026-08-01

- Keep both deployment profiles at preview until an immutable release passes
  the complete retained live qualification and teardown gate twice in the
  governed nonproduction account.
- Bound Starter and HA dashboards, capacity alarms, certificate activation,
  and scale-in protection to the recipe-only gateway/worker route metrics and
  durable Amazon cleanup gauge.
- Made HA scale-in protection fail closed while operational telemetry is
  unavailable and fixed the HA EMF namespace used by CloudWatch alarms.
- Added the guarded CloudFormation update/automatic-rollback lifecycle drill
  and post-rollback verification workflow.
- Recursively review every AWS-generated nested child change set instead of
  relying on the root stack summary.
- Exclude only the mutable root implementation-progress journal from the
  immutable publication digest so live qualification can be logged without
  silently changing the candidate.
- Add independent protected Rust SIP, stock Vapi webCall, and Amazon Connect
  Agent Workspace observers with strict redacted schemas and server-side proof
  of the actual duplicate-free correlation header.
- Require an immutable controlled-source `/32` for direct qualification and
  authenticate each private call session against the exact Lambda correlation
  derivation before starting media.

## 1 — 2026-07-31

- Added the initial data-only recipe manifest.
- Established the canonical `X-Correlation-Id` to `correlation_id` contract.
- Established existing-Connect wrapper-flow production ownership.
- Marked the recipe preview pending retained live qualification evidence.
