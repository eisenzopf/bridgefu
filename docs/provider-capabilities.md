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
