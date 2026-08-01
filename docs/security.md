# Security model

Bridgefu treats every signaling, provider webhook, and broadcast subscription
as a tenant boundary.

- The control API supports a constant-time compared Bearer credential.
- Telnyx Ed25519 webhooks are verified through the pinned `telnyx` SDK over
  the untouched request bytes before parsing. The signed payload must contain
  the exact configured `connection_id` before it can enter call state.
- Telnyx mutations use non-nil durable Bridgefu UUID command IDs with SDK ID
  generation disabled. Retries reuse the byte-identical body, and provider
  diagnostics retain only bounded status/retry classes and byte counts.
- `bridgefu.context.v1` only maps configured `X-*` SIP headers. It rejects
  hop-by-hop/auth headers, CR/LF/NUL, oversized names and values, reserved
  tenant/call keys, and non-allowlisted metadata.
- rvoip's `AuthenticatedPrincipal` carries subject, tenant, scopes, issuer,
  expiry, authentication method, and assurance. WHIP/WHEP resources retain
  ownership, and UCTP rejects expired principals.
- Split-gateway WebRTC uses that same principal before WSS upgrade or
  WHIP/WHEP admission and resolves only an exact two-minute single-use
  attachment. Native SIP accepts optional generic and Telnyx Digest identities;
  when both exist they require one exact realm and distinct usernames. The
  shared Bearer authority is rejected on cleartext SIP UDP/TCP unless
  `generic_bridge.sip.allow_cleartext_bearer` is explicitly enabled; its secure
  default is false. Named Vapi profiles catalog trusted CIDRs, Digest, TLS,
  SRTP, and peer-CA policy. The shared SIP runtime now projects TLS listener,
  optional server-side client-certificate verification, and mandatory SRTP
  into rvoip, and rejects any SIPS route whose profile differs from those
  installed settings. Both all-in-one and gateway roles project only Vapi
  profiles referenced by configured SIP routes into the same tenant-bound
  listener policy. Each trusted CIDR maps to that profile's explicit
  issuer/tenant/subject/scopes; overlapping CIDRs and cross-tenant mappings
  fail startup. An mTLS profile must configure
  `mtls_leaf_certificate_sha256_fingerprints` alongside
  `mtls_peer_ca_certificates`. CA verification alone never assigns a
  principal, and duplicate or conflicting leaf mappings fail startup. Digest
  and Bearer remain independent alternative mechanisms in the shared policy.
- The control-API principal authorizes named-route selection and remains the
  durable outbound-work owner; it is not implicitly authorized to consume a
  Vapi-managed SIP attachment. For named SIP ingress, Bridgefu requires exactly
  one durable `Ingress/VapiIngress` binding and resolves its expected principal
  by exact tenant, profile ID, and canonical non-secret profile revision. The
  configured resolver and SIP trusted-CIDR/mTLS projection both use the same
  Vapi principal constructor, so issuer, tenant, and subject produce one
  ownership fingerprint. Missing, stale, cross-tenant, or multiple ingress
  bindings fail closed instead of falling back to the API identity. Direct
  named WebRTC attachments continue to use their short-lived signaling
  credential derived from the API identity, and privileged unnamed SIP/WebRTC
  calls retain the explicit same-principal compatibility policy.
- Private egress commands use reserved reliable UCTP labels that are rejected
  from public SIP MESSAGE and WebRTC DataChannels. The mTLS attachment route,
  not JSON, supplies authority: worker fence, tenant, call, source leg, and
  attachment generation must match before the command may address one exact
  destination generation. Commands expire within 30 seconds and conflicting
  reuse of a command ID is rejected by digest. Destination media uses a
  separate one-use UCTP admission bound to the same command ID, worker fence,
  tenant, call, source attachment generation, target generation, codec, and
  expiry. A bound connection remains reauthorizable but cannot be admitted a
  second time. The command replay cache is currently process-local, so split
  SIP/WSS activation remains disabled until Redis retains idempotency across
  gateway restart and the durable call supervisor owns/reconciles the proxy
  lifecycle.
- Named-route call plans contain only profile kind, stable profile ID, and a
  SHA-256 revision of canonical non-secret policy. Secret fields are skipped
  before hashing and never enter route discovery, call responses, or durable
  plans. New routes must reference a typed destination profile whose allowlist
  exactly contains the embedded server-owned endpoint.
- Every new durable call plan stores the HMAC-derived issuer/tenant/subject
  fingerprint that authorized it. Outbound rvoip binding and restart recovery
  must use that exact value. Version-one plans migrated without this field stay
  readable for inspection and teardown but fail closed for outbound work; no
  runtime identity is inferred as a replacement.
- The optional StandardCharter durable canary is false by default and lives on
  the separate generic SIP listener. Startup binds it to one configured tenant,
  one exact subject/issuer, required SIP/create scopes, and a correlation
  header explicitly mapped to Amazon `correlation_id`. Its correlation-derived
  operation is durably idempotent, but transport attachment still uses the
  ordinary hashed, two-minute, single-use bearer; a replay cannot attach twice.
  Canary identity and route details are redacted from diagnostics.
- UCTP and MOQT listener tokens are HS256 JWTs with a fixed Bridgefu issuer,
  subscriber audience, contract version, exact tenant and broadcast scope,
  credential ID, issue/not-before/expiry times, a 15-minute maximum lifetime,
  and an active exact-generation broadcast grant. HMAC secrets must contain at
  least 32 bytes. Deletion, managed expiry, and cleanup revoke the grant. UCTP
  refresh rotates the JWT replay ID but retains the credential ID used for
  Session ownership; it may extend only the already-consumed exact Session
  reservation and cannot attach a second peer.
- In clustered MOQT mode, the publisher projects only the tenant, broadcast,
  transport, expiry, and an independent fencing generation into Redis. Relay
  admission rechecks that projection and uses a Redis session lease for the
  cluster-wide replay tombstone and tenant quota. Redis errors are an
  authorization failure; they never fall back to the relay's empty local
  registry.
- Public listener principals never receive wildcard, publish, relay, or data
  scopes. UCTP listener tokens are single-use for one exact Session, accept
  only `recvonly` offers, and their outbound-only media binding drops any
  peer-supplied datagram. Publisher credentials are separate. Relays require
  origin mTLS in production. Static relay mode grants one exact namespace per
  certificate binding. rvoip also contains an active-grant-backed policy whose
  exact or parsed tenant-prefix certificate ceiling can only be narrowed by a
  live, exact, generation-fenced Bridgefu Redis grant. The dynamic runtime
  remains fail-closed at startup until an owner-reviewed private relay revision
  with continuous expiring mTLS lease revalidation is immutably pinned; the
  uncommitted local candidate is not treated as an installed security control.
- Secrets can use `env:VARIABLE`; when that variable is absent,
  `VARIABLE_FILE` may point to a bounded UTF-8 secret file. A direct variable
  always wins, and effective-config output always redacts either source.

Transfer effects retain both the selected call leg and its binding generation,
so a delayed transfer cannot be redirected to a replacement session. Media-idle
refreshes likewise require an exact connection ID, binding generation, and
strictly consecutive activity generation. Stale activity cannot re-arm a timer
after binding retirement or teardown.

Production deployments must set API and broadcast secrets and terminate
HTTPS/WSS/WHIPS with reviewed certificates. A named SIPS attachment requires
`generic_bridge.sip.secure_listener` plus `srtp: required`; startup maps these
to rvoip `ClientAndServer` SIP TLS and strict SDES-SRTP. Keep cleartext SIP Bearer disabled;
use `generic_bridge.sip.digest` or the configured Telnyx Digest identity. If a
generic deployment explicitly opts into SIP Bearer on UDP/TCP, its listener
must stay on a private or cloud-firewall/CIDR-restricted carrier path. Gateway
preflight rejects configurations with no usable SIP authentication. Do not
add a peer CA without an explicit leaf-fingerprint-to-principal mapping; such a
configuration is rejected before a listener opens. Keep provider webhook
URLs behind a trusted proxy that preserves the original scheme and host.

`api.rate_limit` applies process-salted, one-way issuer/tenant/subject-keyed budgets after
control authentication and a separate gateway-wide webhook budget before body
extraction, signature verification, or persistence. The identity cache is
bounded and idle-reclaimed; an unseen principal at capacity fails closed.
Webhook bodies are capped at 256 KiB. These process-local limits complement,
but do not replace, load-balancer/WAF limits for invalid credential floods.

The all-in-one diagnostics endpoint is on the protected API router. The
standalone MOQT relay has a separate 32-to-4096-byte diagnostics bearer and
returns only aggregate listener/dependency state. `/livez`, `/readyz`, and
`/metrics` are deliberately unauthenticated for infrastructure probes; health
responses expose only the configured tenant count, never tenant identifiers.
These endpoints must be network-restricted when metrics are not intended to be
public.
