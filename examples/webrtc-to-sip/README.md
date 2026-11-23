# WebRTC caller → SIP destination

```text
WebRTC caller ── WSS + WebRTC audio ── Bridgefu ── SIPS/SRTP ── SIP destination
```

Audio flows both ways. This example needs no AWS or Vapi account.

## Try it locally

1. Install the [local prerequisites](../native-sip-webrtc/README.md#start-with-the-local-demo).
2. From the repository root, run:

   ```sh
   cargo run --locked --example native-sip-webrtc -- \
     --settings examples/webrtc-to-sip/settings.example.json
   ```

3. Look for **PASS**. An automated WebRTC peer calls a local SIP peer through Bridgefu's runtime. The command checks encrypted audio both ways, hangs up, and stops every endpoint. This test does not launch a browser.

To change the codec, identifiers, or which side hangs up, copy `settings.example.json` into `.local/`, edit it, and point `--settings` at the copy. See the [settings reference and test matrix](../native-sip-webrtc/README.md).

## Connect your own endpoints

1. Follow the [shared setup](../native-sip-webrtc/SETUP.md) using this directory's `bridgefu.example.yaml` and `client.example.json`.
2. Set `sip_target_uri` to your answering SIP server and `sip_from_uri` to the identity it accepts. Configure the optional proxy/Digest fields if needed. Set `webrtc_signaling_uri` to Bridgefu's public WSS listener.
3. Start Bridgefu with your private YAML.
4. Build the browser SDK. Node.js/npm are needed for this step:

   ```sh
   npm ci --prefix sdk/typescript
   npm run build --prefix sdk/typescript
   ```

5. In a shell with the same API token, start the local browser app:

   ```sh
   python3 examples/native-sip-webrtc/client.py \
     --settings examples/webrtc-to-sip/.local/client.json --serve
   ```

6. Open the printed `http://127.0.0.1:8080/` address (or your configured port). Press **Call**, allow microphone access, and answer at the SIP destination. Speak from each end, then press **Hang up**. A new Call gets a fresh one-use attachment.
7. Stop the Python app and Bridgefu with Ctrl-C.

The Python app keeps the Bridgefu API token server-side and fixes the destination through the configured route. It binds only to loopback and is a local example. For a hosted application, put the same call-creation operation behind your own authenticated application backend and serve the SDK over HTTPS.

The editable recipe uses `metadata_keys: []`, so no correlation ID or other context field is required. Configure your own metadata policy and context if your SIP destination needs additional headers.
