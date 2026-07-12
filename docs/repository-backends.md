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
