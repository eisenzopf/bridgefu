# Vapi feasibility observer fixture

This disposable binary closes the local infrastructure gap in
the reference tenant's owner-gated stock Vapi `webCall` → SIP test. It uses
`rvoip-sip` for SIP, RTP, TLS, SDES-SRTP, RFC 4733, audio, and teardown. The
HTTP layer only exposes authenticated, bounded qualification operations; it is
not part of Bridgefu's public administration API.

The fixture provides:

- `GET /livez` and authenticated `GET /readyz`;
- authenticated `POST /v1/observations/query` and `/control`;
- a separately authenticated `POST /v1/observations/vapi-events` callback;
- a controlled silent-until-requested 880 Hz return-audio probe;
- inbound fake-microphone marker detection, RFC 4733/in-band DTMF evidence,
  local or remote BYE evidence, callback/final-reason evidence, and exact
  cleanup; and
- dynamic direct-echo or Bridgefu one-use SIPS transfer responses.

Responses contain only booleans, safe labels, allowlisted header names, and a
short attachment TTL. Raw Vapi call IDs, SIP Call-IDs, URI values, SDP, media,
credentials, transcripts, and header values are never returned or logged. A
call is bound to the harness by an HMAC correlation derived from the protected
observation token plus run nonce, case, and hangup origin.
An outbound RFC 4733 probe is reported only by the control operation's success;
`dtmf.verified` is set solely when the fixture observes inbound RFC 4733 or a
bounded in-band DTMF marker.

## Local verification

No credentials or network are used by the focused suite:

```sh
cargo test --example vapi_feasibility_observer
```

It includes a real localhost rvoip call with SDES-SRTP, audio in both
directions, RFC 4733, and BYE. Start the disposable local HTTP/SIP fixture with:

```sh
docker compose -f deploy/vapi-feasibility/compose.local.yaml up --build
```

Local mode intentionally uses loopback HTTP and UDP SIP so it can run without
public certificates. It is not accepted by the reference tenant's live harness.

## Deployment boundary

The fixture does not provision DNS, certificates, firewall/NAT mappings, Vapi
resources, Bridgefu routes, or cloud infrastructure. A live owner-authorized
run therefore requires a disposable non-production deployment with:

- a publicly trusted HTTPS certificate for the observation/callback origin;
- a publicly trusted SIP TLS certificate, TCP 5061, and the configured UDP
  media range mapped 1:1 to `VAPI_FIXTURE_MEDIA_PUBLIC_IP`;
- a server-authenticated Vapi webhook credential using the distinct fixture
  webhook bearer;
- an allowlisted Bridgefu route whose destination is this fixture and which
  maps context correlation to only `X-Correlation-Id`; and
- secret injection for the observation, webhook, and Bridgefu control tokens.

Copy `fixture.env.example`, replace documentation addresses and tokens, mount
the certificate/key files read-only, then fail closed before binding sockets:

```sh
cargo run --locked --example vapi_feasibility_observer -- --validate-config
```

Deployment mode rejects loopback/unspecified advertised addresses, plaintext
SIP destinations, missing TLS files, optional SRTP, partial Bridgefu settings,
short/shared tokens, undersized media ranges, and missing correlation-header
policy. It never probes Vapi, Bridgefu, or a cloud during validation.

Do not run the live reference tenant workflow, create provider resources, or
publish this image without the project owner's explicit authorization.
