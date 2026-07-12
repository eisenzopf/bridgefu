# Private moq-rs fork review packet

This document prepares the private draft-19 wire-engine delta for project-owner
review. It does not authorize or create an upstream issue, pull request, or
maintainer message. The working fork remains `eisenzopf/moq-rs` at exact
revision `ef52ac8656513bb3b07b4b9b80152ac24bb2467e`.

## Provenance

- Upstream repository: `cloudflare/moq-rs`.
- Draft-18 port base: `c7e80e49f4189efd1e55e2533eab36adf0e8f4b4`.
- Private branch: `codex/moqt-draft-19-port`.
- Reviewed private head: `ef52ac8656513bb3b07b4b9b80152ac24bb2467e`.
- The draft-18 base is an ancestor of the private head.
- rvoip pins the full 40-character revision; no floating branch is consumed.

## Proposed review series

The current branch is intentionally usable as one pinned integration revision,
but any future upstream proposal should be reviewed and split into cohesive
changes rather than submitted as one large patch.

1. **Draft-19 wire and request topology**
   - `f3c29d3` through `a1a5597`: control/data/PUBLISH/FETCH codecs,
     request-stream placement, session targets, and explicit acceptance.
2. **Bounded retention and Joining FETCH**
   - `75a7ebc` through `28138a3`, then `1d76f57`, `366b3c7`, `1e32c30`,
     `6ef0caa`, `2b54dcb`, `ecf8b11`, `cac1275`, and `276a902`: bounded
     retention, joining state/options, end-of-group, close ordering, cold live
     fallback, and accepted-object drain.
3. **Production admission and lifecycle**
   - `e7b1eb4`, `612cc6f`, `4bcb903`, `6fc4b8c`, `d759845`, `9202260`,
     `8d396fe`, and `99b5eff`: redaction, scoped admission, replay-aware close,
     raw-QUIC token listeners, structured draft-19 authorization, and feature
     separation for embedded runtimes.
4. **Namespace discovery and shared relay routing**
   - `c84534e`, `d6b1583`, `01d7c21`, `1c804f7`, and `450a551`: bounded initial
     discovery, live Added/Removed updates, fail-closed overflow, prefix-overlap
     enforcement, and shared in-process routing state.
5. **Least-privilege relay chaining**
   - `ef52ac8`: a distinct raw-QUIC, subscribe-only mTLS relay identity with
     exact-scope admission; publisher certificates remain publish-only.

Before any submission, the project owner should review protocol correctness,
public API shape, compatibility impact, commit boundaries, security invariants,
and whether each group belongs in moq-rs or only in rvoip. A later approved
submission should preserve authorship and add focused migration notes. No
automated job may submit or update it.

## Validation at the reviewed head

- `moq-transport` passed 429 library tests.
- `moq-relay-ietf` passed 111 library, 25 binary, 1 admission-contract, and 5
  feature-policy tests with all features.
- Strict Clippy and rustdoc with warnings denied passed for the changed wire,
  native-IETF, and relay crates.
- rvoip's managed relay tests traverse raw QUIC and WebTransport, including
  warm Relative Joining FETCH and cold live fallback.
- A packet capture records both `moqt-19` and `h3` ALPN handshakes with no TLS
  key log; see `moq-packet-capture.md`.
- A real browser authenticated with a structured receive-only SETUP token and
  parsed an MSF-01 catalog; see `moq-browser-interop.md`.

## Independent compatibility findings

- Unmodified `moq-dev/moq` at
  `ea97ce44470e35a49f5f18acf8ad96daa37aabea` interoperates over WebTransport
  for draft-19 namespace discovery, subscription, and live Objects. Its native
  client currently omits mandatory PATH/AUTHORITY and its high-level subscriber
  does not expose retained FETCH.
- Meta moxygen at `bdf5ac341f152d69e25eec753ef4fc77ba603b6a`
  supports draft-18 or earlier, so it is not a matching draft-19 peer.
- moqtap at `49971ea90506db77957444fb73ef5200fec2b1fe` advertises draft-19 but its
  unmodified codec still uses RFC 9000's 1/2/4/8-byte integer encoding and its
  client uses the pre-draft-19 request topology. Local diagnostic fixes can
  exercise raw QUIC, WebTransport, and Relative Joining FETCH, but that result
  is not represented as unmodified independent interoperability.

These limitations are protocol-version facts, not reasons to weaken rvoip's
draft-19 validation. Incompatible peers receive explicit errors; rvoip does not
silently downgrade.
