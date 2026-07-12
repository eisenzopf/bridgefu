# Provider capability matrix

| Provider | Originate | Transfer | Hangup | DTMF | Webhook verification | 1.0 media |
|---|---:|---:|---:|---:|---|---|
| Amazon Connect | Existing inbound `StartWebRTCContact` | Connect flow | Bidirectional teardown | RTP events | AWS control plane | Specialized Chime WebRTC |
| Twilio | Calls API/TwiML | TwiML update | Calls update | TwiML digits | Request signature + JSON body hash | SIP/RTP |
| Telnyx | Call Control dial | transfer action | hangup action | send_dtmf action | Ed25519 + timestamp | SIP/RTP |
| Vonage | Voice API | NCCO transfer | call action | call action | HS256 webhook JWT + payload hash | SIP/RTP |

Provider WebSocket media is intentionally deferred. Unsupported semantics
return `unsupported_capability`; Bridgefu does not pretend one provider's
operation has another provider's guarantees.

Each configured provider has an `account_profile` referenced by provider call
legs. Profiles are bounded and globally unique across provider families. The
defaults are `twilio`, `telnyx`, and `vonage`; deployments should use explicit
names such as `twilio-sandbox` when configuration is promoted between
environments. Credential identifiers carried by signed callbacks must match
the configured provider credentials before the event can enter durable call
reconciliation.

Twilio status callbacks use `CallSid`, canonicalized `SequenceNumber`, and
`CallStatus` in the durable event identity. When Twilio omits
`SequenceNumber`, Bridgefu uses an explicit `no-sequence` identity: exact
redelivery of the same call/status deduplicates, while different statuses stay
distinct. Missing or malformed statuses and sequence values are rejected.
Telnyx callbacks require a nonblank signed `data.id`; no provider normalizer
persists an `unknown` sentinel.
