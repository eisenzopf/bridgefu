# Browser WebRTC to Amazon Connect

`webrtc-amazon-connect-bridge@1` accepts a short-lived, one-use browser
WebRTC attachment and starts one fixed Amazon Connect WebRTC contact. It is the
direct route for a website voice experience that hands a caller to an existing
Connect flow without a SIP hop.

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
`verification_status`, and `vapi_call_reference` can become Connect contact
attributes. The target Connect flow remains customer-owned and is never
modified by this config-only recipe. Unlike the flagship Vapi/SIP recipe, this
direct path does not need DynamoDB lookup unless the customer deliberately
chooses the flagship wrapper-flow pattern.
