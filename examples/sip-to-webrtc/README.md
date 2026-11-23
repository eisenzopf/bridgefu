# SIP caller → WebRTC service

```text
SIP caller ── SIPS/SRTP ── Bridgefu ── WSS + WebRTC audio ── WebRTC service
```

Audio flows both ways. This example needs no AWS or Vapi account.

## Try it locally

1. Install the [local prerequisites](../native-sip-webrtc/README.md#start-with-the-local-demo).
2. From the repository root, run:

   ```sh
   cargo run --locked --example native-sip-webrtc -- \
     --settings examples/sip-to-webrtc/settings.example.json
   ```

3. Look for **PASS**. The command places a real encrypted call between automated local peers, verifies audio tones both ways, hangs up, and stops all endpoints. Nothing remains listening.

To change the codec, identifiers, or which side hangs up, copy `settings.example.json` into `.local/`, edit it, and point `--settings` at the copy. See the [settings reference and test matrix](../native-sip-webrtc/README.md).

## Connect your own endpoints

1. Follow the [shared setup](../native-sip-webrtc/SETUP.md) using this directory's `bridgefu.example.yaml` and `client.example.json`.
2. Set `sip_signaling_cidrs` to your caller's verified source networks. Set `webrtc_signaling_uri` to the answering service's compatible rvoip WSS endpoint; set its optional bearer reference if needed.
3. Start Bridgefu with your private YAML.
4. In a shell with the same API token, reserve a call:

   ```sh
   python3 examples/native-sip-webrtc/client.py \
     --settings examples/sip-to-webrtc/.local/client.json \
     --output examples/sip-to-webrtc/.local/call.json
   ```

5. Open the private `call.json` and give its `attachment.uri` to your SIP caller. Dial that complete URI promptly; its token is short-lived and can be used only once. Your caller must support the configured TLS/SRTP policy.
6. Answer at the WebRTC service, speak from each end, and hang up. Confirm both ends disconnect. Delete `call.json` before reserving another call.

A browser page alone cannot answer an outbound WSS call. The local demo supplies an automated answering service. For your own service, implement the compatible signaling contract or use an integration adapter for its API.

No context fields are required by this example. Edit the recipe and your application settings to choose the fields you need; the release contains no customer-specific field names.
