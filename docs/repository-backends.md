# Durable call repository backends

Bridgefu exposes one `CallRepository` contract with memory, SQLite, and
PostgreSQL implementations. The memory implementation is the deterministic
transition evaluator and test oracle. SQL remains authoritative: every worker,
call, leg, assignment, command result, idempotency claim, attachment, used
connection-ID tombstone, provider event/reference/completion, outbox effect,
and deadline is stored in a typed table with database uniqueness constraints.
No opaque repository-state blob is persisted.

SQLite mutations start with `BEGIN IMMEDIATE`. PostgreSQL mutations lock the
singleton durable repository epoch with `SELECT ... FOR UPDATE`. This makes
capacity admission, idempotency, token consumption, provider completion, and
work claims safe across independent pools and processes. Read-only
`worker_snapshot`, `load_call`, and `inspect_attachment` operations instead use
consistent read transactions; they do not take the epoch write lock, rewrite
tables, or advance the epoch.

Schema version 5 widens `provider_completions` with a distinct
`service_reconciliation` receipt. Existing command and terminal-acknowledgement
rows are copied unchanged by the SQLite table rebuild and remain in place under
PostgreSQL's widened constraint. The service receipt cross-links the claimed
event, provider account/reference, execution-plan leg, worker fence, and exact
service follow-up so restart replay cannot bypass the service-owned transaction.

Schema version 6 adds the nullable, 32-byte
`authorization_principal_fingerprint` column to `call_execution_plans` and
cross-checks it against the versioned plan body. New version-2 plans must carry
the exact principal that authorized outbound work. Plans migrated from schema 5
remain version 1 with a null fingerprint because authority cannot be inferred
safely. Their already-persisted bindings and provider reconciliation receipts
remain readable and replayable so operators can inspect and terminate those
calls, while every new outbound bind fails closed until the call is recreated
under a version-2 plan.

Gate 6 deliberately chooses correctness before maximum write concurrency. A
mutation loads a consistent normalized snapshot, applies one transition through
the shared evaluator, diffs the snapshots, and writes only inserted, changed,
or expired rows before advancing the epoch. Tests install an aborting SQLite
trigger and inspect PostgreSQL `xmin` to prove an unrelated historical call is
not rewritten. The global mutation lock remains a documented scalability limit:
before Gate 11 load qualification, PostgreSQL should move to per-call/worker row
locks while retaining this conformance suite as its semantic oracle.

Expired 24-hour idempotency rows are deleted as targeted deltas. Terminal call
history is never automatically deleted. `SqlRetentionPolicy` only identifies a
candidate after its assignment is released, idempotency is expired, attachments
are consumed/revoked/expired, and every outbox, deadline, and provider event is
settled. The current API deliberately exposes neither archive acceptance nor a
purge operation: a later archive workflow must hash the complete candidate
history and re-read that same version after external I/O before deletion can be
made safe.

Run the memory and SQLite suite with normal `cargo test`. The PostgreSQL cases
only execute when `BRIDGEFU_TEST_POSTGRES_URL` names a disposable,
Bridgefu-owned database. The deterministic local runner starts the digest-pinned
PostgreSQL 17.5 image, supplies that URL, runs the shared conformance and
two-independent-instance race suite, and removes the container:

```sh
scripts/test-repository-backends.sh
```

The CI test job supplies the same URL through its PostgreSQL service. An unset
URL is printed as an explicit local skip and is never the release evidence for
PostgreSQL.
