# Provider capability matrix

| Provider | Originate | Transfer | Hangup | DTMF | Webhook verification | 1.0 media |
|---|---:|---:|---:|---:|---|---|
| Amazon Connect | Existing inbound `StartWebRTCContact` | Connect flow | Bidirectional teardown | RTP events | AWS control plane | Specialized Chime WebRTC |
| Telnyx | Call Control dial | transfer action | hangup action | send_dtmf action | `telnyx::webhooks::Verifier` (Ed25519 + timestamp) | SIP/RTP |
| Twilio | Deferred beyond 1.0 | Deferred | Deferred | Deferred | Existing scaffold only | Deferred |
| Vonage | Deferred beyond 1.0 | Deferred | Deferred | Deferred | Existing scaffold only | Deferred |

Provider WebSocket media is intentionally deferred. Unsupported semantics
return `unsupported_capability`; Bridgefu does not pretend one provider's
operation has another provider's guarantees.

Bridgefu 1.0 uses the published `telnyx` crate pinned as `telnyx = "=0.1.0"` for
typed Call Control requests, API errors, typed webhook events, and raw-body
Ed25519 verification. Bridgefu owns every non-nil UUID `command_id`, disables
SDK-generated IDs, and sends the exact same serialized command when the SDK
retries a connection failure, timeout, HTTP 408/409/429, or 5xx response.
Timeout and retry budgets are explicit configuration. Bridgefu also retains
ownership of tenant/account binding, durable deduplication and reconciliation,
deadlines, redaction, circuit breaking, SIP attachment routing, and capability
policy.

Each configured Telnyx integration has an `account_profile` referenced by
provider call legs. Profiles are bounded and globally unique. Deployments
should use explicit names such as `telnyx-sandbox` when configuration is
promoted between environments. Credential identifiers carried by signed
callbacks must contain the exact configured `connection_id` before the event
can enter durable call reconciliation. New Twilio and Vonage legs fail with an
explicit deferred capability error; their existing persisted discriminants
remain readable for migration compatibility.

Telnyx verifies the signature and timestamp over the untouched request bytes
before Bridgefu parses the envelope. Callbacks require a nonblank signed
`data.id`, `data.payload.call_control_id`, and configured
`data.payload.connection_id`; no provider normalizer persists an `unknown`
sentinel. Adapter diagnostics expose only status/retry classes and byte counts,
never credentials, raw bodies, destinations, or provider call identifiers.
The SDK `tracing` feature is intentionally disabled because its request event
currently includes the full action URL, which contains the call identifier.
