# Bridgefu v1 API quick start

The control API is tenant-scoped. Send exactly one `Authorization: Bearer ...`
header and, for every call mutation, exactly one visible-ASCII
`Idempotency-Key`.
JWT/JWKS principals use the operation scopes `calls:create`, `calls:read`,
`calls:hangup`, `calls:transfer`, and `calls:dtmf`. Supplying `tenant_id`
requires `calls:tenant-override`; otherwise the tenant always comes from the
authenticated principal.

Provider capability discovery, broadcast creation/read/deletion/token issuance,
tenant diagnostics, and screen-pop evidence all require `calls:read`. This
scope is rechecked at the handler boundary, including credential expiry; merely
presenting an otherwise valid tenant credential is not sufficient.

## Create a call through a named route

Public website and Vapi integrations should use the server-owned route catalog
instead of submitting typed destination legs. `GET /v1/routes` returns only
routes owned by the authenticated tenant and exposes capability classes, never
SIP/WSS targets, provider identifiers, credentials, or TURN secrets.

```bash
curl --fail-with-body -X POST \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -H 'Idempotency-Key: widget-transfer-001' \
  -H 'Content-Type: application/json' \
  https://bridgefu.example/v1/routes/support/calls \
  --data '{
    "ingress":"sip",
    "context":{
      "correlation_id":"public-correlation-123",
      "metadata":{"account_tier":"gold"}
    }
  }'
```

The response contains a complete, single-use, two-minute SIPS or WSS
attachment descriptor. The request cannot supply a destination, tenant, call
ID, leg ID, or credential. New route definitions must reference a
`vapi_ingress_profile` or `webrtc_ingress_profile` for each enabled ingress and
one typed `destination_profile`; the embedded destination remains a
server-owned compatibility representation and must match the profile's exact
allowlist or provider profile.

Route capability responses separate `initial_context`,
`live_data_channel_context`, and `sip_message`. Amazon Connect and Telnyx report
initial context only; generic interactive WebRTC may report live DataChannel
context; generic SIP reports initial allowlisted headers and later SIP MESSAGE.
The older compact `context` field remains in v1 responses for compatibility,
but clients should use the explicit booleans when presenting features.

Every created call durably retains the selected profile ID and a lowercase
SHA-256 revision over its canonical non-secret configuration. Secret values
and secret-reference strings are excluded from that revision and from call
plans. Rotating a credential therefore does not rewrite call history, while a
non-secret policy or destination change produces a new revision.

Vapi-managed SIP attachments fail configuration validation unless the shared
rvoip SIP stack has a real TLS listener and mandatory SRTP. The Vapi profile's
certificate/key reference, optional Digest identity, and optional client CA
must match the listener configuration; Bridgefu never advertises `sips:` over
an unencrypted UDP-only runtime. Only Vapi profiles referenced by a named SIP
route add trusted CIDRs to the listener. Every mapping is bound to the
profile's exact tenant principal, and overlapping networks are rejected. If
`mtls_peer_ca_certificates` is present, the profile must also list one or more
transport-verified leaf SHA-256 values in
`mtls_leaf_certificate_sha256_fingerprints`; a CA bundle by itself is not an
application identity and fails configuration validation.

## Create a SIP ↔ WebRTC call

This example reserves an inbound interactive-WebRTC attachment and originates
the SIP leg. The response contains the generated call/leg IDs and a single-use,
two-minute attachment token on the inbound leg. Later reads never return that
token.

```bash
curl --fail-with-body https://bridgefu.example/v1/calls \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -H 'Idempotency-Key: demo-call-001' \
  -H 'Content-Type: application/json' \
  --data @- <<'JSON'
{
  "legs": [
    {
      "direction": "inbound",
      "signaling_initiator": "remote",
      "media_flow": "send_receive",
      "endpoint": {
        "type": "webrtc",
        "config": { "signaling_uri": null }
      }
    },
    {
      "direction": "outbound",
      "signaling_initiator": "bridgefu",
      "media_flow": "send_receive",
      "endpoint": {
        "type": "sip",
        "config": {
          "uri": "sip:destination@example.net",
          "initial_context": "none"
        }
      }
    }
  ]
}
JSON
```

Set the SIP leg's `initial_context` to `required` when one exact
`bridgefu.context.v1` DataChannel message must be durably translated into
allowlisted initial INVITE headers before SIP signaling begins. Subsequent
context uses in-dialog SIP MESSAGE. A missing or invalid envelope times out
without sending an INVITE.

Inbound SIP, WebRTC, WHIP, and WHEP legs use their returned attachment token at
the corresponding configured signaling endpoint. In a split deployment, the
gateway owns this HTTP API and atomically routes commands to an existing
PostgreSQL-pinned worker without registering itself as one. The currently
supported public gateway media attachment contract is documented in
`gateway-uctp-ingress.md`; native gateway-owned SIP/WebRTC ingress is forwarded
to the pinned worker over the same authenticated private route. Generic SIP or
WSS **destination** origination remains unavailable in split mode until the
private prepare/activate/abort/end command plane and gateway proxy adapters are
implemented. `GET /v1/routes` omits those destinations, and mutating requests
return `unsupported_capability` instead of accepting an unexecutable plan.

In gateway mode this public router binds `api.http_bind`. It does not expose
health or Prometheus metrics; `/livez`, `/readyz`, `/healthz`, and `/metrics`
remain isolated on `observability.http_bind`. A non-loopback API bind requires
`api.tls.certificate_chain` and `api.tls.private_key`; Bridgefu terminates HTTPS
with rustls and fails preflight when the key pair is absent. Plain HTTP is
limited to loopback development binds.

## Control an existing call

```bash
# Read
curl --fail-with-body \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  https://bridgefu.example/v1/calls/CALL_ID

# DTMF (RFC 4733 where the negotiated leg supports it)
curl --fail-with-body -X POST \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -H 'Idempotency-Key: demo-dtmf-001' \
  -H 'Content-Type: application/json' \
  https://bridgefu.example/v1/calls/CALL_ID/dtmf \
  --data '{"leg_id":"LEG_ID","digits":"12#","duration_ms":120,"gap_ms":70}'

# SIP transfer; acceptance means submitted, while the call remains
# transferring until an authoritative REFER/NOTIFY outcome arrives.
curl --fail-with-body -X POST \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -H 'Idempotency-Key: demo-transfer-001' \
  -H 'Content-Type: application/json' \
  https://bridgefu.example/v1/calls/CALL_ID/transfer \
  --data '{"target_leg_id":"LEG_ID","target":{"type":"sip","uri":"sip:replacement@example.net"}}'

# Hang up both legs with owned teardown and drain.
curl --fail-with-body -X POST \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -H 'Idempotency-Key: demo-hangup-001' \
  -H 'Content-Type: application/json' \
  https://bridgefu.example/v1/calls/CALL_ID/hangup \
  --data '{}'
```

Bridgefu 1.0 supports authoritative SIP REFER and Telnyx transfer semantics.
There is no interoperable protocol-native transfer operation for an attached
WebRTC leg in the current rvoip stack, so a protocol transfer request for that
leg returns explicit `unsupported_capability`/`409`; it is never acknowledged
as completed. A separate server-controlled make-before-break operation is
available at `POST /v1/calls/{call_id}/legs/{leg_id}/replace`. Its body contains
only an allowlisted `route_id`; the server resolves the replacement endpoint,
profile, and credentials. Acceptance means the durable replacement command was
recorded, not that destination media has connected.

An exact retry with the same idempotency key returns the original receipt. A
different operation or body using that key returns `409`. Invalid lifecycle
transitions also return `409`; admission pressure returns `429` with
`Retry-After`; unavailable durable dependencies return `503`.

## Broadcast a connected source leg

MOQT is the default relay-capable transport. UCTP/QUIC is the direct
rvoip-native option.

Broadcast commands currently require an all-in-one worker/media runtime. A
split gateway returns `503 broadcast_remote_worker_unavailable` until a durable
remote broadcast command and response path is implemented.

```bash
curl --fail-with-body -X POST \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -H 'Content-Type: application/json' \
  https://bridgefu.example/v1/calls/CALL_ID/broadcasts \
  --data '{"source_leg_id":"CONNECTED_LEG_ID","transport":"moqt"}'
```

The response includes the endpoint, namespace/tracks or UCTP session/stream,
expiry, protocol versions, lifecycle, health, and relay path. Mint a short-lived
receive-only listener token with:

```bash
curl --fail-with-body -X POST \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -H 'Content-Type: application/json' \
  https://bridgefu.example/v1/broadcasts/BROADCAST_ID/tokens \
  --data '{"ttl_secs":300}'
```

`sanitized_events: true` is available only for MOQT and only when the tenant's
configuration also permits the event track. Call context is never exposed on a
broadcast by default.

## Provider control

`GET /v1/providers/telnyx/capabilities` reports the configured operations.
Telnyx webhook authentication, deduplication, and callback reconciliation use
`POST /v1/providers/telnyx/webhooks`. Twilio and Vonage are deliberately
deferred and return an explicit capability error for new work.

The complete typed configuration, security boundaries, and current release
qualification status live in `config/schema.json`, `security.md`, and
`roadmap.md` respectively.
