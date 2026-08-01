# Migration to the v1 configuration

Existing StandardCharter configuration remains valid. Additive defaults keep
the legacy `aws`, `sip`, `contact`, `mapping`, `tenants`, and `observability`
blocks unchanged.

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
