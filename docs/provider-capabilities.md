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
typed Call Control requests, command identifiers, API errors, typed webhook
events, and raw-body Ed25519 verification. Bridgefu retains ownership of
tenant/account binding, durable deduplication and reconciliation, deadlines,
redaction, circuit breaking, SIP attachment routing, and capability policy.

Each configured Telnyx integration has an `account_profile` referenced by
provider call legs. Profiles are bounded and globally unique. Deployments
should use explicit names such as `telnyx-sandbox` when configuration is
promoted between environments. Credential identifiers carried by signed
callbacks must match the configured provider credentials before the event can
enter durable call reconciliation. New Twilio and Vonage legs fail with an
explicit deferred capability error; their existing persisted discriminants
remain readable for migration compatibility.

Telnyx callbacks require a nonblank signed `data.id`; no provider normalizer
persists an `unknown` sentinel.
