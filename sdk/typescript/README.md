# `@bridgefu/webrtc-browser`

Typed browser client for Bridgefu's interactive WebRTC ingress. It owns one
`RTCPeerConnection`, the `rvoip.webrtc.v1` WebSocket signaling lease,
microphone/remote audio, `bridgefu.context.v1`, arbitrary DataChannels, DTMF,
and deterministic teardown.

This package is alpha and is locally packable as a release-candidate artifact.
Publishing it remains an explicit owner-authorized release step. Its wire
contracts match the immutable rvoip revision pinned by this Bridgefu checkout.

## What the browser receives

Create a named route through a same-origin backend. Bridgefu returns its stable
snake_case attachment under `attachment`:

```json
{
  "type": "webrtc",
  "signaling_uri": "wss://edge.example.com/webrtc",
  "token": "<two-minute-single-use-token>",
  "signaling_credential": {
    "usage": "bridgefu-webrtc-signaling",
    "token": "<two-minute-attachment-bound-bearer>",
    "expires_at": "2030-01-01T00:02:00Z"
  },
  "subprotocols": [
    "rvoip.webrtc.v1",
    "token.<two-minute-attachment-bound-bearer>",
    "bridgefu.attach.<two-minute-single-use-token>"
  ],
  "ice_servers": [
    {
      "urls": ["turns:turn.example.com:5349?transport=tcp"],
      "username": "<temporary-username>",
      "credential": "<temporary-credential>"
    }
  ],
  "expires_at": "2030-01-01T00:02:00Z"
}
```

The top-level route response also contains `tenant_id`, `call_id`, and `legs`.
Select the inbound WebRTC leg and normalize the response before connecting:

```ts
import {
  BridgefuWebRtcClient,
  normalizeBridgefuRouteAttachment,
} from "@bridgefu/webrtc-browser";

const routeCall = await createRouteCallOnYourBackend();
const browserLeg = routeCall.legs.find(
  (leg: { direction: string; kind: string }) =>
    leg.direction === "inbound" && leg.kind === "webrtc",
);
if (!browserLeg) throw new Error("route returned no inbound WebRTC leg");

const attachment = normalizeBridgefuRouteAttachment(routeCall.attachment, {
  tenantId: routeCall.tenant_id,
  callId: routeCall.call_id,
  legId: browserLeg.leg_id,
});
```

Normalization verifies that both private subprotocols agree with the
attachment and signaling credential. The
attachment's ICE servers override `rtcConfiguration.iceServers`; other peer
configuration, such as `iceTransportPolicy: "relay"`, remains application
controlled.

## Connect

Call `connect` from a user gesture so microphone permission and remote audio
playback comply with browser policy.

```ts
const remoteAudio = document.querySelector<HTMLAudioElement>("#remote")!;

const client = new BridgefuWebRtcClient({
  remoteAudioElement: remoteAudio,
  rtcConfiguration: { iceTransportPolicy: "all" },
  ringback: {
    start: () => ringbackPlayer.start(),
    stop: () => ringbackPlayer.stop(),
  },
  dataChannels: [
    {
      label: "application.events",
      options: {
        protocol: "rvoip.data.v1",
        ordered: false,
        maxRetransmits: 3,
      },
    },
    { label: "application.raw", options: { ordered: false } },
  ],
});

client.on("handoff", ({ status }) => updateStatus(status));
client.on("context", ({ envelope }) => receiveContext(envelope));
client.on("dataMessage", ({ message }) => receiveTypedMessage(message));
client.on("rawMessage", ({ channel, data }) => receiveRaw(channel.label, data));
client.on("reconnectRequired", async () => {
  const nextRouteCall = await createFreshRouteCallOnYourBackend();
  await client.reconnect(normalizeFreshAttachment(nextRouteCall));
});
client.on("error", ({ error }) => reportSafeError(error.code));

await client.connect(attachment);

client.sendContext({
  correlationId: "corr-123",
  metadata: { account_tier: "gold" },
});
client.sendDataMessage(
  "application.events",
  "application/json",
  JSON.stringify({ event: "ready" }),
);
client.sendRaw("application.raw", new Uint8Array([1, 2, 3]));
client.sendDtmf("12#");

await client.disconnect();
```

`handoff` progresses through `preparing`, `ringing`, `attaching`, and
`connected`, followed by `ended` or `failed`. During a server-controlled leg
replacement, authenticated status may repeat `preparing`, `ringing`, and
`attaching`, then finish as `connected` or `resumed`. The ringback hook starts
for dialing states and stops on connection, assistant resume, failure,
reconnect, or end.

## DataChannel contract

Channels using protocol `rvoip.data.v1` carry rvoip's exact `RVDM` v1 envelope.
Textual MIME types use `rvoip-data-v1:<base64url>` string frames; other MIME
types use binary frames. The SDK authenticates the embedded label and
reliability settings against the receiving channel before emitting a
`dataMessage` event.

The managed reliable/ordered channel is labeled `bridgefu.context.v1` and uses
`application/vnd.bridgefu.context.v1+json`. Context identifiers come from the
authenticated attachment, not caller input. Metadata is bounded and rejects
reserved keys, controls, and unknown envelope fields. Bridgefu still applies
its server-side SIP-header allowlist; the browser cannot inject arbitrary SIP
headers.

The second managed reliable/ordered channel is `bridgefu.handoff.v1` with
`application/vnd.bridgefu.handoff.v1+json`. It carries an exact call ID,
replacement leg, append-only binding generation, status, and optional bounded
detail code. Bridgefu's media-bridge policy drops this label when it comes from
either call peer, so only the server can drive the SDK's handoff/ringback state
over the browser's authenticated DTLS session. Application code cannot create
or send on this reserved channel through `addDataChannel`.

Channels with another or empty protocol are passed through as `rawMessage`
events. Use `sendRaw` for those channels.

## Security and reconnect rules

- Never put a Bridgefu REST bearer, provider credential, or long-lived token in
  the browser descriptor, URL, or this client.
- `attachment.token` is private routing material with a two-minute, one-use
  lifetime. The SDK sends it only as `bridgefu.attach.<token>` during the WSS
  handshake and rejects local replay.
- Named-route creation includes a separately minted, attachment-bound
  credential whose `usage` is exactly `bridgefu-webrtc-signaling`. It grants
  only `webrtc:connect`, is sent as `token.<value>`, and is never accepted in
  the signaling URL. The optional credential-provider hook remains only for
  privileged/custom attachment issuers.
- WSS is mandatory. `ws://localhost` is available only when
  `allowInsecureLocalhost` is explicitly enabled for local tests.
- An rvoip signaling socket owns its server route lease. Socket or peer loss
  therefore emits `reconnectRequired` and requires a newly created attachment;
  the old single-use token is never replayed.
- `disconnect` sends route-scoped `bye` when possible, closes every channel and
  socket, stops local tracks, clears remote audio, and closes the peer.
- `sendDtmf` requires an audio sender whose `RTCDTMFSender.canInsertDTMF` is
  true. A non-null but unusable sender fails with `dtmf-unavailable` instead of
  pretending that the tone was queued.

## Development

```sh
npm ci
npm run typecheck
npm test
```

The tests use deterministic WebRTC/WebSocket mocks and cover the request-bound
`offer-ready`/answer/`ready`/`rejected` admission exchange, trickle ICE, TURN
propagation, microphone audio, context and arbitrary data, DTMF, ringback,
signaling loss, fresh-token reconnect, and cleanup. The client reports
`connected` only after both peer connectivity and the exact remote admission
outcome. These tests do not replace the roadmap's required real Chromium and
TURN-only qualification.

The Bridgefu repository also contains an opt-in real-browser run of this built
package:

```sh
cargo test -p bridgefu --test qualification_browser_sdk -- \
  --ignored --nocapture
```

It requires StandardCharter's pinned Playwright Chromium. TURN-only remains a
separate owner-gated qualification.

See [`example/`](./example/) for a same-origin backend integration page. Build
the SDK, serve this directory over HTTPS (or localhost), and configure the demo
backend route endpoint described there.
