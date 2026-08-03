# Authoring a Bridgefu recipe

A recipe is a declarative, data-only package. It cannot load executable code
into the Bridgefu process, run a template language, fetch packages from the
network, or interpolate text. Reviewed deployment packages may contain Lambda
or infrastructure code, but that code is executed only through an explicit
deployment change set.

## Package minimum

```text
my-recipe/
  recipe.yaml
  README.md
  CHANGELOG.md
  values.example.yaml
```

`recipe.yaml` must conform to
[`recipes/schema/recipe-v1.schema.json`](../recipes/schema/recipe-v1.schema.json).
An exact selector includes the source and integer version:

```yaml
recipes:
  support:
    use: external:my-recipe@1
    with:
      signaling_cidrs: [203.0.113.10/32]
```

External packages always report `custom`, regardless of the support string in
their manifest.

## Manifest rules

- `api_version` is exactly `bridgefu.dev/recipe/v1`.
- `kind` is exactly `bridge_recipe`.
- Names and bridge IDs use bounded lowercase identifiers.
- Versions are positive integers; selectors do not accept ranges.
- Unknown fields, missing/unused inputs, collisions, duplicate CIDRs, and paths
  outside the package fail validation.
- Packages and collections have explicit size/count limits.
- Every asset/deployment path is relative, canonicalized, and contained by the
  package root.
- Built-ins are embedded at build time; startup never downloads a recipe.

## Typed inputs

Available types are `string`, `boolean`, `integer`, `enum`, `cidr_list`,
`aws_arn`, `aws_connect_resource_id`, and `secret_ref`. An input replaces one
complete YAML node:

```yaml
security:
  $input: sip_security
```

Partial strings such as `sips:$input@host` are rejected. There is no shell,
environment, expression, include, loop, or arbitrary templating syntax.
Secret references are validated as references and excluded from recipe
fingerprints and redacted output.

## Endpoint and direction model

Each bridge declares one source and one destination. Version 1 understands
SIP, interactive WebRTC, and Amazon Connect WebRTC endpoint shapes. SIP source
admission is explicit:

- `managed_attachment`: recommended; short-lived one-use URI/token.
- `stable_uri`: fixed Request-URI user for a trusted, authenticated SIP peer.
  This mode is available only with the explicit clear SIP/RTP compatibility
  posture; SIPS/SRTP recipes must use `managed_attachment`.

For `stable_uri`, set `uri_user` to one lowercase recipe-owned identifier and
send the INVITE to that exact user at the configured Bridgefu edge, for
example `sip:contact-center@bridge.example.com`. Bridgefu accepts it only from
the route's configured ingress principal and trusted signaling CIDRs. It then
creates the same durable named-route call and internally consumes the same
one-use proof used by managed admission. The stable URI never authorizes an
arbitrary destination, does not bypass profile revisions, and is not returned
by the route-call API. Repeated SIP operations are isolated with a
tenant-, recipe-, route-, connection-, and correlation-bound idempotency
digest.

Use `managed_attachment` unless the upstream SIP product cannot fetch a fresh
URI before transfer. A minimal custom source fragment for the compatibility
mode is:

```yaml
source:
  type: sip
  security: sip_rtp
  admission:
    mode: stable_uri
    uri_user: contact-center
    trusted_cidrs: [198.51.100.0/24]
  codecs: [pcmu, pcma]
```

Treat `trusted_cidrs` as an identity boundary: keep the ranges narrow, prevent
source-address spoofing at the edge, and use a dedicated recipe/tenant for
each fixed peer. Stable URI mode is not accepted for the secure SIPS/SRTP
posture because CIDR identity is not equivalent to one-use admission.

SIP destinations declare an exact target URI and reviewed outbound profile.
WebRTC destinations declare the fixed signaling service and credential
references. Amazon Connect destinations declare the exact existing instance
and recipe entry-flow identity. Amazon Connect ingress is invalid in v1.

## Context

Customer context must be a bounded, typed contract. The flagship canonical
mapping is:

```yaml
context:
  correlation:
    required: true
    from_sip_header: X-Correlation-Id
    to_amazon_attribute: correlation_id
    format: opaque_id_v1
```

Do not put raw customer records, transcripts, credentials, or authorization
decisions in SIP headers, logs, metrics, traces, stack outputs, or evidence.
Define fail-open/fail-closed behavior for every context dependency.

Runtime context admission is explicit per route. Use
`context.allow_sip_headers` for canonical SIP-header mappings and
`context.allow_metadata_keys` for authenticated WebRTC/API metadata that does
not originate in SIP. A required recipe context key must be reachable through
one of those allowlists. Bridgefu rejects a missing, malformed, conflicting, or
out-of-list value before reserving or consuming a one-use attachment.

## Deployments and assets

`deployments` maps a provider and profile to a reviewed package file. `assets`
names documentation, contracts, provider objects, and tests. Paths are data;
Bridgefu does not execute them. Infrastructure must still provide:

- immutable artifacts and checksums;
- explicit ownership/retention;
- least-privilege roles and private secret references;
- readiness, observability, runbooks, update/rollback, and teardown;
- an exact destination/route/header allowlist; and
- a deploy/update/destroy qualification path.

## Required tests

At minimum, a candidate built-in recipe needs:

1. JSON Schema and strict Rust deserialization tests.
2. Deterministic compilation and fingerprint tests.
3. Secret-redaction and path/size/collision negative tests.
4. A generated Bridgefu config accepted by the real validator.
5. Hermetic signaling, codec, context, replay, DTMF, hangup, and cleanup tests.
6. Infrastructure lint/guard/plan and deterministic artifact builds.
7. Disposable create/update/rollback/destroy evidence.
8. Protected live interoperability, audio, adverse-network, load, recovery, and
   soak evidence for every advertised matrix row.
9. Documentation link/snippet/command tests.

## Documentation checklist

Document the problem, exact variants/support tier, architecture, data contract,
inputs/prerequisites, deployment ownership, network/DNS, security/privacy,
costs, monitoring/alarms, troubleshooting, upgrade/rollback/DR, teardown, and
exact evidence revision. Every alarm needs an actionable runbook.

## Promotion

Start external packages as `custom`. A proposal for a built-in recipe must have
maintainer ownership, reviewed contracts, security/threat model, compatibility
policy, infrastructure, complete docs, and reproducible evidence. Promotion
from `development` to `preview` to `supported` occurs only when the exact
published revision passes the corresponding gates; working source alone does
not change the tier.
