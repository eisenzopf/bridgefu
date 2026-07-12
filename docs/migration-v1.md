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
4. Leave `generic_bridge.enabled: false` during the first canary.
5. Validate with `bridgefu --config bridgefu.yaml validate`, then inspect with
   `print-effective-config`.
6. Canary the preserved Amazon path. Rollback drains active calls and starts
   the prior image; there is no in-place session migration.
7. Enable the generic listener on separate ports and test SIP/WebRTC traffic.

The UCTP media wire format is intentionally breaking: update every alpha UCTP
client to 0.2 before enabling media. Signaling envelopes retain their version.
