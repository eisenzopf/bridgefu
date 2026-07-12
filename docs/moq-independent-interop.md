# Independent MOQT draft-19 interoperability

Status: partial independent interoperability evidence; Gate 5 remains in
progress.

## Exact revisions

- Independent implementation: `moq-dev/moq` at
  `ea97ce44470e35a49f5f18acf8ad96daa37aabea`.
- Private draft-19 fork under test:
  `ef52ac8656513bb3b07b4b9b80152ac24bb2467e`.
- Earlier diagnostic implementation: `moqtap/moqtap` at
  `49971ea90506db77957444fb73ef5200fec2b1fe`, with its independent
  `moqtap/test-vectors` corpus at
  `d9ae9ef85312ea44e914cb5de96a1108343eee51`.

No upstream issue, pull request, or maintainer message was created. The
independent sources were not modified for the qualifying run.

## Result matrix

| Check | Result | Evidence and limitation |
|---|---|---|
| WebTransport negotiation | Pass | HTTP/3 negotiated WebTransport protocol `moqt-19`; both peers reported draft-19. |
| SETUP | Pass over WebTransport | The CONNECT target supplied `/tenant/broadcast`; peer SETUP completed. |
| Namespace discovery | Pass after private-fork fix | Independent client received `REQUEST_OK`, `NAMESPACE clock`, and reported `subscribe_namespace ok`. |
| Direct subscription | Pass | Independent client sent SUBSCRIBE for `clock/now` and received SUBSCRIBE_OK with track alias 2. |
| Live Objects | Pass | Independent client printed continuous payloads such as `group-87:object`. |
| Raw QUIC | Blocked by independent peer | The exact independent revision negotiates `moqt-19` but emits neither mandatory PATH nor AUTHORITY in native SETUP. The relay correctly rejects it with `malformed connection authority`. |
| SETUP authorization token | Unsupported by independent peer | Its draft-19 `run_setup` emits only MOQT_IMPLEMENTATION. Its URL `?jwt=` facility is HTTP/transport authentication, not the structured draft-19 SETUP AUTHORIZATION TOKEN. |
| Retained Relative Joining FETCH | Not independently qualified | The independent high-level subscriber cannot initiate FETCH and explicitly rejects FETCH_HEADER. Its publisher-side FETCH path sends an empty FETCH stream, so it cannot prove retained-object transfer. |

The private-fork namespace-discovery change adds a bounded, admitted,
long-lived `SUBSCRIBE_NAMESPACE` handle, request-stream-associated
`REQUEST_OK`/`NAMESPACE`/`NAMESPACE_DONE` ordering, deterministic cleanup, and
a scope/prefix-bound initial coordinator snapshot. It also streams dynamic
namespace additions and removals after that snapshot, rejects overlapping
subscriptions, fails closed on bounded-update overflow, and exposes separate
publish-only and relay subscribe-only mTLS roles. Its validation commands
passed:

```text
cargo fmt --all -- --check
cargo test -p moq-transport --lib --quiet
# 429 passed
cargo test -p moq-relay-ietf --all-features -- --test-threads=1
# 111 library + 25 binary + 1 admission + 5 feature-policy tests passed
```

The earlier moqtap experiment remains diagnostic rather than qualifying
evidence. After local compatibility fixes, it successfully exercised raw QUIC
and WebTransport SUBSCRIBE/live Objects plus Relative Joining FETCH against the
private fork. The unmodified moqtap revision, however, uses the older RFC 9000
1/2/4/8-byte integer encoding and an obsolete request topology, so that result
cannot be described as unmodified independent draft-19 interoperability.

## Reproduction

Run the report-only harness with a local private-fork checkout containing the
pinned commit:

```bash
MOQ_RS_DIR=../moq-rs \
ARTIFACT_DIR=/tmp/bridgefu-moq-interop \
bash scripts/check-moq-dev-interop.sh
```

The script checks out both exact revisions in temporary worktrees, verifies
that the independent checkout has no tracked modifications, builds an
ephemeral two-Object publisher, runs the positive WebTransport flow, records
the expected raw-QUIC blocker, writes redaction-safe logs plus `report.json`,
and stops every child process. It does not update dependencies, patch the
independent implementation, or contact maintainers.

## Remaining qualification work

Gate 5 must remain open until an unmodified independent draft-19 peer passes
both raw QUIC and WebTransport, including retained Joining FETCH object
transfer. The production release also still requires its recorded MSF/LOC,
authorization, browser WebTransport, relay, lifecycle, and packet-capture
evidence. This partial result must not be represented as draft-19 GA
interoperability.
