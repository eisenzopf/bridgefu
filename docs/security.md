# Security model

Bridgefu treats every signaling, provider webhook, and broadcast subscription
as a tenant boundary.

- The control API supports a constant-time compared Bearer credential.
- Twilio HMAC-SHA1, Telnyx Ed25519, and Vonage signed-JWT webhooks are verified
  before parsing an event into call state.
- `bridgefu.control.v1` only maps configured `X-*` SIP headers. It rejects
  hop-by-hop/auth headers, CR/LF/NUL, oversized names and values, reserved
  tenant/call keys, and non-allowlisted metadata.
- rvoip's `AuthenticatedPrincipal` carries subject, tenant, scopes, issuer,
  expiry, authentication method, and assurance. WHIP/WHEP resources retain
  ownership, and UCTP rejects expired principals.
- Every new durable call plan stores the HMAC-derived issuer/tenant/subject
  fingerprint that authorized it. Outbound rvoip binding and restart recovery
  must use that exact value. Version-one plans migrated without this field stay
  readable for inspection and teardown but fail closed for outbound work; no
  runtime identity is inferred as a replacement.
- UCTP and MOQT listener tokens must have a broadcast-specific receive scope.
  Publisher credentials are separate. Relays should require origin mTLS.
- Secrets can use `env:VARIABLE`; effective-config output always redacts them.

Transfer effects retain both the selected call leg and its binding generation,
so a delayed transfer cannot be redirected to a replacement session. Media-idle
refreshes likewise require an exact connection ID, binding generation, and
strictly consecutive activity generation. Stale activity cannot re-arm a timer
after binding retirement or teardown.

Production deployments must set API and broadcast secrets, configure WebRTC
authentication, restrict SIP to carrier CIDRs or enable rvoip SIP Digest/Bearer
policy, terminate TLS/SRTP appropriately, and keep provider webhook URLs behind
a trusted proxy that preserves the original scheme and host.

The diagnostics endpoint is on the protected API router. `/livez`, `/readyz`,
and `/metrics` are deliberately unauthenticated for infrastructure probes and
must be network-restricted when metrics are not intended to be public.
