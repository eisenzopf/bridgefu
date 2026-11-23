# Pass context in SIP headers

Use the [six-step setup](../SETUP.md) to try both recipes in a disposable environment. For your own infrastructure, follow the [service-by-service walkthrough](../EXISTING-ENVIRONMENT.md) and select this directory's `settings.example.json`.

The example defaults are:

| Value source | SIP header | Connect contact attribute |
| --- | --- | --- |
| Input `variables.customer_session` | `X-Customer-Session` | `customer_session` |
| Authoritative `call.id` | `X-Vapi-Call-Id` | `vapi_reference` |
| Assistant `arguments.intent` | `X-Customer-Intent` | `customer_intent` |
| Assistant `arguments.summary` | `X-Conversation-Summary` | `conversation_summary` |

Rename, add, or remove any application field in settings and regenerate. The transfer Lambda receives the tool call, fetches the live Vapi call, and assembles these values into a SIP destination. Bridgefu admits the fixed URI from trusted Vapi signaling addresses and copies only allowed headers into Amazon Connect attributes when starting WebRTC. The Connect entry flow immediately transfers to your target flow. Reference attributes there as `$.Attributes.<configured-name>`.

There is no context database, lookup Lambda, required correlation header, or synthetic correlation ID in this route. The transfer Lambda exists to combine trusted input with dynamic conversation arguments; it does not store context. The checked-in Lambda source and CloudFormation inline code are generated from `../shared/handler.py`.

Missing required values, unresolved templates, control characters, and oversized values stop the transfer request. The assistant stays on the call and continues helping. The gateway rejects duplicate configured headers rather than guessing which value to use. Header field validation is applied before any Connect contact is created.

For verification, compare all configured contact attributes with the input session, Vapi call ID, and actual tool arguments. Confirm the call reaches your target flow and test media in both directions. See [E2E instructions and results](../tests/E2E.md).
