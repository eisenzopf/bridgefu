# Browser MOQT draft-19 interoperability

Status: passing production-authenticated browser WebTransport evidence for Gate
5. This is separate from the unmodified independent-implementation evidence in
`moq-independent-interop.md`.

## Qualified revisions

- Private wire engine: `eisenzopf/moq-rs`
  `ef52ac8656513bb3b07b4b9b80152ac24bb2467e`.
- rvoip managed relay and browser server harness:
  `8dab9d14a49178fa5f9a3e48ed6c1388272bfe58`.
- Bridgefu browser client: `dcd71c3627de413aa49fd03bd4522babd6b9ce13`.
- Browser-side implementation base: `moq-dev/moq`
  `ea97ce44470e35a49f5f18acf8ad96daa37aabea`, with only the checked-in
  deterministic draft-19 structured SETUP-token adapter applied. Because that
  adapter is a local test patch, this run is not represented as unmodified
  independent interoperability.

## Security posture

The rvoip harness starts separate publisher and subscriber listeners over one
managed relay topology. Publisher ingress requires an exact-scope mTLS
certificate. Browser ingress uses rvoip's normal JWT validation, authorization,
replay, lease, expiry, and receive-only scope path.

- The JWT lives in the structured MOQT SETUP parameter, never the URL.
- The subscriber token expires after two minutes and is broadcast- and
  tenant-bound.
- The server certificate is valid for one day and supplied to WebTransport by
  SHA-256 hash.
- The origin publishes canonical 48 kHz mono, 20 ms Opus LOC Objects and an
  MSF-01 catalog.
- Ready diagnostics go to stdout as one JSON object. Operational stderr omits
  the token.

The harness advertises `127.0.0.1` rather than `localhost`: the in-app browser
preferred IPv6 while the bounded test listener was intentionally bound to IPv4.

## Reproduction

Start the rvoip origin/relay harness:

```bash
cd ../rvoip
cargo run -p rvoip-moq --features relay-runtime \
  --example moq_browser_e2e_server
```

Start the exact browser client in another terminal:

```bash
./scripts/run-moq-browser-client.sh
```

Open `http://127.0.0.1:4173`, copy only the ephemeral fields from the harness's
ready descriptor, and run the conformance check. The checked-in client clones
the exact moq-dev revision into a temporary directory, applies the bounded
SETUP-token adapter, installs the lockfile, and removes the temporary checkout
when stopped.

The 2026-07-12 in-app Chromium run returned:

```json
{
  "catalogVersion": "draft-01",
  "negotiatedProtocol": "moq-transport-19",
  "protocol": "moqt-19",
  "track": "catalog",
  "trackCount": 1
}
```

`moq-transport-19` is moq-dev's API label for the negotiated draft-19 wire
version; Bridgefu normalizes that explicit alias to the public `moqt-19`
descriptor and rejects every other version. Shutdown drained both relay roles
and the publisher without leaving the test processes running.
