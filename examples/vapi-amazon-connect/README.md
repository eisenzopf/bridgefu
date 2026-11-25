# Vapi → Bridgefu → Amazon Connect

Use these examples to transfer a Vapi caller to Amazon Connect and give the receiving flow the caller's session, Vapi call ID, intent, and a short conversation summary. Those four fields are examples: you choose the fields, names, and mappings.

Choose how you want to carry the data:

| | [SIP headers only](sip-headers/README.md) | [Correlation ID + lookup](correlation-id/README.md) |
| --- | --- | --- |
| What travels in SIP? | All the selected values | One lookup token |
| Where is the context stored? | No separate context store | DynamoDB, with an expiry |
| What does Connect do? | Reads the attributes immediately | Runs a Lambda, then reads the attributes |
| Why use it? | Short context, fewer components | Keep conversation details out of SIP signaling |

Both use a small Vapi webhook hosted in Lambda to assemble the transfer. In the first example, that Lambda **does not store context**. In the second, it stores context before requesting the transfer. You can host the webhook in your own application instead.

**Start with [the step-by-step setup guide](SETUP.md).** It creates a working test environment, explains what was configured in each service, and runs both recipes. For your own infrastructure, use the [service-by-service walkthrough](EXISTING-ENVIRONMENT.md).

After setup:

- [AWS runbook](AWS-RUNBOOK.md): useful commands, troubleshooting, and cleanup.
- [End-to-end test](tests/E2E.md): reproduce the disposable test and understand its results.
- [Restricted-egress TURN test](tests/TURN.md): validate Connect relay media with direct UDP blocked (requires the TURN candidate).
- [Configuration reference](REFERENCE.md): field sources, validation limits, generated files, and deployment details.

These examples require Bridgefu 0.9.1 or newer. They are not included in the `0.9.0` source release. The existing built-in correlation recipe remains available; these examples add two independently configurable routes.
