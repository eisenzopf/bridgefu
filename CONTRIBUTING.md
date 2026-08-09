# Contributing to Bridgefu

Bridgefu is rvoip's reference call/media bridge. Reusable signaling, media,
authentication, UCTP, or MOQT behavior belongs in rvoip first; Bridgefu should
contain provider policy, durable call orchestration, configuration, deployment,
and operational integration.

Before proposing a change:

1. Preserve the frozen reference tenant Vapi → Amazon Connect behavior.
2. Keep tenant and call ownership explicit at every signaling, media, and data
   boundary. Never add an untyped SIP-header or credential escape path.
3. Add deterministic negative tests for lifecycle and authorization failures,
   not only a happy-path test.
4. Run `cargo fmt --all -- --check`, the affected strict Clippy target, and the
   affected Bridgefu test suites with `--locked`. Bridgefu resolves exact
   crates.io rvoip 0.3.7 packages and does not require a sibling checkout;
   reusable rvoip changes must be released and qualified in that repository
   before Bridgefu updates its exact package versions.
5. Update `docs/roadmap.md` with exact evidence, leaving external or long-load
   gates open until those runs actually occurred.

Do not submit private WebRTC/RTC or moq-rs fork changes upstream merely because
Bridgefu consumes them. Their review packets require explicit project-owner
approval before any upstream contact.

Please avoid call IDs, tenant IDs, credentials, phone numbers, SIP contents,
SDP, or provider payloads in issue reports and test artifacts. Use synthetic
fixtures and aggregate diagnostics. Coordinate security-sensitive reports
privately with the project owner rather than opening a public issue.
