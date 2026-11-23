# Set up Bridgefu for your endpoints

First run the [local demo](README.md). The steps below connect your own SIP and WebRTC systems. Run shell commands from the repository root. Use the directory for your chosen direction wherever a command names it.

## 1. Have your endpoint details ready

You need a Bridgefu host with a reachable IP, a DNS name pointing to it, and a TLS certificate/private key for that name.

For **SIP → WebRTC**, also have the SIP caller's signaling CIDRs and a WebRTC service that implements the rvoip interactive WSS signaling protocol, including staged `offer-ready` negotiation. It must accept calls and send/receive audio. A normal website URL or a vendor-specific WebRTC API is not interchangeable with this signaling endpoint. The destination must satisfy Bridgefu's public-address policy.

For **WebRTC → SIP**, have the SIP destination URI, the From URI it accepts, and any required proxy/Digest credentials. The default requires SIPS and SRTP. The included browser page acts as the WebRTC caller.

## 2. Make private working copies

For SIP → WebRTC:

```sh
mkdir -p examples/sip-to-webrtc/.local
chmod 700 examples/sip-to-webrtc/.local
cp examples/sip-to-webrtc/bridgefu.example.yaml examples/sip-to-webrtc/.local/bridgefu.yaml
cp examples/sip-to-webrtc/client.example.json examples/sip-to-webrtc/.local/client.json
```

For WebRTC → SIP, use the same commands with `webrtc-to-sip` in place of `sip-to-webrtc`. Both `.local` directories are excluded from Git and Docker build contexts.

## 3. Edit your Bridgefu YAML

The supplied addresses are documentation placeholders. Replace them before starting the server.

| Field | Your value |
| --- | --- |
| `edge.public_host` | Your Bridgefu DNS name |
| `edge.media_public_addr` | Your media IP followed by `:0` |
| Certificate paths | The full certificate-chain file on the Bridgefu host |
| `observability.http_bind` | Local API/operations listener; sample uses `127.0.0.1:9090` |
| `recipes.support` | Your route name; keep the client `route_id` in sync if renamed |
| `recipes.support.with` | Your direction's endpoint URLs, security mode, CIDRs, and optional authentication |
| `persistence.database_url` | A writable SQLite file; the sample uses your `.local` directory |
| `generic_bridge.sip` | Your RTP port range |
| `generic_bridge.webrtc` | Your WebRTC media port range and any additional ICE settings |

For SIP ingress, update `edge.sip_tls.advertised_addr` and its listening address too. For WebRTC ingress, keep `webrtc_signaling_uri`'s port aligned with `generic_bridge.webrtc_ws_bind` (sample: `8443`). Serve the WSS path through that listener, or configure your TLS reverse proxy accordingly.

Make the configured signaling and media ports reachable through your host/cloud firewall. The samples use TCP `5061` for incoming SIPS or TCP `8443` for incoming WSS, UDP `20000–20199` for SIP media, and UDP `20200–20399` for WebRTC media. The all-in-one control API shares the loopback operations listener on port `9090`; `api.tls` secures WebRTC signaling, not that HTTP listener. Keep API access local, use the SSH tunnel below, or place it behind your own authenticated HTTPS reverse proxy. NAT/TURN needs depend on your network and are not covered by the loopback test.

The recipes under each example's `recipe/` directory are editable data files. You can change codecs, TLS trust roots, data-channel policy, and selected SIP metadata there. `metadata_keys: []` means no required context for WebRTC → SIP. If you add metadata keys, configure the matching header mappings and application context using [recipe authoring](../../docs/recipe-authoring.md) and [the context contract](../../docs/security.md). No customer intent, session, or correlation field is imposed by these examples.

## 4. Supply credentials and start Bridgefu

Generate credentials once in the shell that will run Bridgefu:

```sh
export BRIDGEFU_API_BEARER_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export BRIDGEFU_CONTROL_HMAC_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export BRIDGEFU_TLS_PRIVATE_KEY_PATH=/your/private/key.pem
cargo build --locked --bin bridgefu
```

The last value is a file path, not the key contents. Supply any optional SIP or WSS credentials using the environment-variable names referenced in your YAML. Keep the same API token available to the Python client; do not generate a different one in its shell.

Validate, then start the chosen configuration:

```sh
target/debug/bridgefu --config examples/sip-to-webrtc/.local/bridgefu.yaml validate
target/debug/bridgefu --config examples/sip-to-webrtc/.local/bridgefu.yaml run
```

For WebRTC → SIP, substitute `webrtc-to-sip`. Keep this terminal open. Ctrl-C drains calls and stops Bridgefu.

## 5. Configure the client

Edit your private `client.json`:

- `api_url`: leave `http://127.0.0.1:9090` when the client runs on the Bridgefu host or uses the SSH tunnel below. For a configured HTTPS reverse proxy, use its URL.
- `route_id`: the recipe instance name from your YAML.
- `token_env`: the environment variable holding the same API token.
- `context`: leave `{}` for an audio-only call, or supply the named-route context object your application needs.
- `ca_file`: optionally add a path to your private CA certificate; public CA certificates work without it.
- `browser_port`: your local browser app port, used for WebRTC → SIP.

If Bridgefu runs on another host, keep this tunnel running on the computer that
runs the Python client:

```sh
ssh -N -L 9090:127.0.0.1:9090 YOUR_USER@YOUR_BRIDGEFU_HOST
```

The browser still connects directly to the public WSS/media endpoints in your
Bridgefu configuration. Only the control API passes through this tunnel.

The client validates TLS for HTTPS URLs and refuses redirects. It never sends the control token to browser JavaScript. Finish with the call instructions in [SIP → WebRTC](../sip-to-webrtc/README.md#connect-your-own-endpoints) or [WebRTC → SIP](../webrtc-to-sip/README.md#connect-your-own-endpoints).

## Stop and clean up

Hang up first. Stop the browser app, if running, with Ctrl-C, then stop Bridgefu with Ctrl-C. Delete expired attachment JSON files. Keep your private configuration and persistent database only if you intend to use them again. The automated local demo and matrix shut down their endpoints automatically.
