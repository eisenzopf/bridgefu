# Migration to the v1 configuration

Existing reference-tenant configuration remains valid except for the preview
canary neutral-label migration below. Additive defaults keep the legacy `aws`,
`sip`, `contact`, `mapping`, `tenants`, and `observability` blocks unchanged.

## Preview canary neutral-label migration

This cleanup intentionally renames the preview canary config key and metric,
observer schema IDs, Compose and GitHub identifiers, secret names, scripts and
fixtures, and the public Rust module and types. Strict v1 configuration accepts
`generic_bridge.reference_tenant_canary` only; it does not alias or accept the
retired canary field. Before rollout, update configuration, automation,
dashboards and alerts, evidence collectors, deployment secrets, imports, and
operational commands together. Mixing old and new surface names is unsupported.

The canary's durable idempotency namespace also advances to v2. A fresh
installation may use v2 directly. If a durable store ever ran an earlier
preview canary, first disable canary admission, drain all canary calls and
pending cleanup, and leave it disabled for the full 24-hour idempotency
retention window. Then deploy the renamed configuration while still disabled
and re-enable it only after verification. This boundary prevents one logical
request from being created once under each namespace.

1. Add `config_version: 1`.
2. Set `api.bearer_token`, `api.control_hmac_key` (at least 32 bytes), and
   `broadcast.token_secret` to `env:` references. Set `api.static_tenant` when
   the shared compatibility key serves a configuration with multiple tenants.
3. Copy the existing header mapping into `context.allow_headers`; only values
   in this list may cross a DataChannel boundary.
4. Review `api.rate_limit` for expected per-principal control and diagnostics
   traffic plus aggregate webhook delivery. The safe defaults are enabled;
   capacity responses are `429` with `Retry-After`.
5. Leave `generic_bridge.enabled: false` during the first canary.
6. Keep `generic_bridge.sip.allow_cleartext_bearer: false` unless a generic SIP
   peer cannot use generic/Telnyx Digest and the SIP listener is separately
   restricted to a trusted private/carrier network. Configure
   `generic_bridge.sip.digest` for a first-party Digest peer. Earlier gateway
   scaffolding accepted the shared API Bearer on UDP unconditionally;
   Bridgefu 1.0 does not, and gateway preflight rejects a listener with no
   usable SIP authentication.
7. Validate with `bridgefu --config bridgefu.yaml validate`, then inspect with
   `print-effective-config`.
8. Canary the preserved Amazon path. Rollback drains active calls and starts
   the prior image; there is no in-place session migration.
9. Enable the generic listener on separate ports and test SIP/WebRTC traffic.

The UCTP media wire format is intentionally breaking: update every alpha UCTP
client to 0.2 before enabling media. Signaling envelopes retain their version.
