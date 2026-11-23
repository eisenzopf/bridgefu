# Try native SIP ↔ WebRTC

Choose the call direction:

- **[SIP → WebRTC](../sip-to-webrtc/README.md):** a SIP caller reaches a WebRTC service.
- **[WebRTC → SIP](../webrtc-to-sip/README.md):** a WebRTC caller reaches a SIP phone or contact center.

Both carry audio in both directions. Neither needs AWS, Vapi, or an Amazon Connect account.

## Start with the local demo

You need this repository, Rust **1.95 or newer**, a C/C++ build toolchain, and `protoc` on your PATH. On macOS, install the command-line developer tools and `brew install protobuf`; on Ubuntu, install `build-essential pkg-config protobuf-compiler`. The first Rust build downloads dependencies and can take several minutes.

From the repository root, run either:

```sh
cargo run --locked --example native-sip-webrtc -- \
  --settings examples/sip-to-webrtc/settings.example.json
```

```sh
cargo run --locked --example native-sip-webrtc -- \
  --settings examples/webrtc-to-sip/settings.example.json
```

Each command starts local endpoints, makes one real encrypted call, checks generated audio tones in both directions, hangs up, and exits. It prints four progress lines ending in **PASS**. There is no microphone prompt and you will not hear audio: the automated peers measure the received tones.

The demo uses Bridgefu's production call runtime and real SIP/WebRTC adapters in one process. SIP uses TLS and SRTP; WebRTC uses WSS, ICE, DTLS-SRTP, and Opus. The SIP side uses your selected G.711 codec. Certificates, credentials, and ports are generated for each run.

The outbound WebRTC adapter has an **example-only loopback permission** so both peers can run on your computer. The Bridgefu server retains its normal destination restrictions. This demo does not start the public HTTP API or a browser, and it does not qualify public NAT/TURN, a carrier, or a hosted contact center.

## Change the demo

Copy the direction's settings into its ignored `.local` directory, edit them, and pass the copy to `--settings`.

| Setting | What you can change |
| --- | --- |
| `direction` | `sip-to-webrtc` or `webrtc-to-sip` |
| `tenant`, `route_id`, `sip_user` | Your own synthetic identifiers |
| `sip_codec` | `pcmu` or `pcma` |
| `hangup` | `source` or `destination` |
| `recipe_directory` | The matching editable example recipe directory |

Local-demo sockets remain loopback-only and use temporary ports. For your real hosts, ports, authentication, and endpoint URLs, edit the direction's `bridgefu.example.yaml` instead. Customer fields are not compiled into Bridgefu. These example recipes require no correlation ID or customer metadata by default.

## Repeat the end-to-end tests

Python 3.10+ is needed for the matrix runner:

```sh
python3 examples/native-sip-webrtc/run-e2e.py \
  --output /tmp/bridgefu-native-results.json
```

This runs eight calls: both directions × PCMU/PCMA × caller/destination hangup. PCMA cases also use different tenant, route, and SIP-user settings. Every call checks a 1,000 Hz tone from SIP and a 500 Hz tone from WebRTC after G.711/Opus transcoding, negotiated SIP SRTP, propagated hangup, and empty connection/bridge/admission state. The report contains assertions and counts, with no call IDs, credentials, or addresses.

See [the recorded results](results.json). The matrix is also run in CI.

To repeat the configuration and application-client checks too:

```sh
cargo build --locked --bin bridgefu
python3 examples/native-sip-webrtc/validate-configs.py
python3 -m unittest discover -s examples/native-sip-webrtc -p 'test_*.py'
```

The configuration check uses temporary certificates and generated credentials;
it does not contact your endpoint or provision cloud resources. Five client
tests check configurable context, optional correlation, private attachment
files, redirect refusal, and the browser/backend credential boundary.


## Connect your own endpoints

Follow the chosen direction's guide. The [shared setup](SETUP.md) covers the Bridgefu host, certificates, configuration, and client credentials. The small Python client can either save a one-use SIP attachment or serve a local browser caller using the TypeScript SDK. Its API token stays in the backend.

The recipes remain **preview**. Local protocol tests are distinct from testing your particular SIP server, WebRTC signaling service, browser, firewall, and TURN configuration.
