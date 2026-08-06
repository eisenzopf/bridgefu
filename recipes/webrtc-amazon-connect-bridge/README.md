# Browser WebRTC to Amazon Connect

`webrtc-amazon-connect-bridge@1` accepts a short-lived, one-use browser
WebRTC attachment and starts one fixed Amazon Connect WebRTC contact. It is the
direct route for a website voice experience that hands a caller to an existing
Connect flow without a SIP hop.

See [the Bridgefu-owned browser WebRTC implementation plan](IMPLEMENTATION-PLAN.md)
for the separate nonproduction-first, non-HA AWS deployment and live
qualification path. That architecture terminates the browser peer connection
at Bridgefu and has no hosted browser-call provider in the media path.

**Support tier: `preview`.** The package, bounded context contract, and runtime
projection are implemented. Promotion requires retained Chrome/Firefox/Safari,
WSS, ICE/TURN, Amazon Connect, codec, DTMF, Agent Workspace, hangup,
adverse-network, load, recovery, and soak evidence for the exact release.

The browser never receives the Bridgefu API credential and never selects the
Connect instance or flow. Its authenticated application backend creates the
call, submits a bound `bridgefu.context.v1` envelope containing an opaque
correlation ID (plus only the optional fields below), and returns only the
one-use WebRTC attachment to the browser. Bridgefu rejects creation before
reserving an attachment when that required context is absent or outside the
route allowlist.

Only `correlation_id`, `customer_name`, `issue_summary`, `intent`,
`verification_status`, and `source_call_reference` can become Connect contact
attributes. The target Connect flow remains customer-owned and is never
modified by this config-only recipe. Unlike the flagship Vapi/SIP recipe, this
direct path does not need DynamoDB lookup unless the customer deliberately
chooses the flagship wrapper-flow pattern.

## Retained live diagnostic

After the nonproduction stack is healthy, the protected diagnostic controller
can mint a one-use browser attachment through SSM, drive the built SDK in real
Chromium through the public CloudFront WSS endpoint, and run the synthetic
Agent Workspace observer concurrently. The reusable API credential remains on
the EC2 host; the controller writes only mode-`0600`, redacted observations to
the private state directory supplied by the operator.

```text
node recipes/webrtc-amazon-connect-bridge/qualification/live-browser-connect-smoke.mjs \
  --aws-profile PROFILE \
  --region us-west-2 \
  --stack-name STACK \
  --connect-url https://INSTANCE-ALIAS.my.connect.aws/agent-app-v2/ \
  --storage-state /private/path/agent-workspace.private.json \
  --output-dir /private/path/evidence \
  --hangup-origin source
```

Run a separate call with `--hangup-origin agent` to prove the opposite
terminal direction. This is a live diagnostic, not support-promotion evidence:
the three-run gate, adverse-path matrix, and TURN/browser coverage in the
implementation plan remain mandatory.
