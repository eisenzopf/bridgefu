# StandardCharter non-production smoke, drain, and rollback

This runbook qualifies the preserved Vapi → Bridgefu → Amazon Connect path in a
dedicated non-production deployment. It does not authorize a production change.
No external smoke has been executed by checking in these artifacts; an actual
run remains owner-authorized release evidence and must be recorded separately.

## Hard safety boundary

The workflow is manual-only and its default `validate` operation is offline. An
external operation is admitted only when all of these controls agree:

- The job enters the GitHub environment named exactly
  `standardcharter-nonproduction`.
- That environment has required reviewers, prevents self-approval, restricts
  deployment branches, and contains only non-production secret references.
- The dispatcher checks `confirm_nonproduction` and supplies a non-secret owner
  review/change reference.
- `smoke` uses `OWNER-AUTHORIZED-NONPROD-SMOKE`; `rollback-plan` and `rollback`
  use `OWNER-AUTHORIZED-NONPROD-ROLLBACK`.
- The smoke runner verifies the exact allowlisted AWS account, an HTTPS
  diagnostics hostname containing `nonprod`, `staging`, `sandbox`, or `.test`,
  and a Vapi payload marked `standardcharter-nonproduction`.
- Rollback accepts only a similarly marked SSH hostname, pinned SSH host keys,
  and an immutable Docker image ID or digest that is already staged on the host.

There is no production environment option, target input, automatic fallback to
another account, floating rollback tag, or automatic rollback. Rollback is
never automatic because draining calls—and allowing the reviewed service
manager timeout to bound that drain—is a separate destructive decision.

## Environment setup

Create the protected GitHub environment before attempting anything except
`validate`. Configure these environment secrets; do not place their values in
dispatch inputs, repository variables, workflow YAML, issues, or logs.

| Secret | Purpose and required constraint |
|---|---|
| `STANDARDCHARTER_SMOKE_AWS_ROLE_ARN` | OIDC role in the dedicated non-production AWS account |
| `STANDARDCHARTER_SMOKE_AWS_REGION` | Region containing the non-production Connect instance |
| `STANDARDCHARTER_SMOKE_AWS_ACCOUNT_ID` | Exact 12-digit account allowlist checked after OIDC |
| `STANDARDCHARTER_SMOKE_BRIDGEFU_URL` | HTTPS API origin whose hostname visibly identifies staging/non-production |
| `STANDARDCHARTER_SMOKE_DIAGNOSTICS_TOKEN` | Tenant-scoped bearer token for screen-pop evidence |
| `STANDARDCHARTER_SMOKE_VAPI_TOKEN` | Token for the isolated Vapi test organization |
| `STANDARDCHARTER_SMOKE_VAPI_CALL_PAYLOAD_JSON` | Complete call payload using only test assistant, number, and destination resources |
| `STANDARDCHARTER_ROLLBACK_SSH_TARGET` | `user@host` for only the non-production Bridgefu host |
| `STANDARDCHARTER_ROLLBACK_SSH_PRIVATE_KEY` | Least-privilege deploy key for that host |
| `STANDARDCHARTER_ROLLBACK_SSH_KNOWN_HOSTS` | Pinned `known_hosts` entry collected through an authenticated channel |
| `STANDARDCHARTER_ROLLBACK_IMAGE` | Pre-staged immutable `sha256:…` image ID or `repository@sha256:…` reference |

The OIDC role is used to prove the active AWS account before Vapi is contacted;
Bridgefu's own instance role continues to own `StartWebRTCContact` and
`StopContact`. The Vapi test organization, phone number, assistant, Connect
instance/contact flow, Bridgefu host, and rollback image must all be disposable
non-production resources.

The secret call payload follows Vapi's [Create Call API](https://docs.vapi.ai/api-reference/calls/create)
and must include this shape in addition to its test-only IDs and destination:

```json
{
  "assistantId": "<non-production assistant>",
  "phoneNumberId": "<non-production number>",
  "customer": { "number": "<non-production test destination>" },
  "assistantOverrides": {
    "variableValues": {
      "bridgefuEnvironment": "standardcharter-nonproduction",
      "bridgefuCorrelationId": "__BRIDGEFU_CORRELATION_ID__"
    }
  }
}
```

The test assistant must copy `bridgefuCorrelationId` into the trusted
`X-Correlation-Id` SIP header and deterministically transfer to the
non-production Bridgefu SIP URI. The runner replaces only that placeholder; it
does not rewrite assistant, phone, customer, or SIP targets.

## Offline validation

Run the repository check locally before requesting an environment approval:

```bash
bash scripts/check-standardcharter-smoke-artifacts.sh
```

Or dispatch `StandardCharter non-production smoke` with the default values:

- `operation=validate`
- `confirm_nonproduction=false`
- `owner_authorization=NOT-AUTHORIZED`
- `approval_reference=validation-only`

That job checks workflow invariants, parses YAML when Ruby is available, runs
`bash -n`, executes the smoke preflight with synthetic values, and renders a
synthetic rollback plan. It has no GitHub environment, credentials, OIDC, AWS,
Vapi, diagnostics, or SSH step.

## Owner-authorized smoke

After reviewing the target inventory and change reference, dispatch:

- `operation=smoke`
- `confirm_nonproduction=true`
- `owner_authorization=OWNER-AUTHORIZED-NONPROD-SMOKE`
- `approval_reference=<reviewed non-secret reference>`

An environment reviewer must then approve the job. The runner:

1. Validates all secret-backed configuration without network access.
2. Assumes the environment's OIDC role and compares STS account identity with
   the exact allowlist.
3. Requires Bridgefu `/readyz` before creating a call.
4. Generates a one-use correlation ID, injects it into the secret Vapi payload,
   and calls Vapi's `POST /call` endpoint.
5. Polls authenticated, redacted Bridgefu screen-pop diagnostics until
   `media_connected`.
6. Terminates the Vapi test call with `DELETE /call/{id}` and requires ordered
   evidence through `teardown_started` and `terminated`, with no `failed` stage.
7. Uploads only the redacted diagnostics response for seven days. Raw call IDs,
   correlation IDs, payloads, tokens, and Vapi responses remain in a temporary
   directory and are deleted; an exit trap also attempts call cleanup.

A successful workflow proves control, media-session establishment, and Vapi-led
teardown. The existing hermetic contract separately packet-tests PCMU ↔ Opus
audio and both teardown directions. If qualification requires human agent UI or
audio evidence, record that observation in the approval record without placing
customer data in the workflow artifact.

## Drain and rollback

Rollback is a separate manual operation. First dispatch `rollback-plan` with
the rollback authorization phrase. The protected job resolves the environment
secrets, but the script prints a redacted plan and performs no SSH or network
operation.

Before `rollback`, verify:

1. The selected immutable image is the last reviewed healthy revision and is
   already present on the host; the script never pulls an image.
2. No second smoke or deployment is active. Workflow concurrency serializes its
   own operations, but operators must also exclude out-of-band deployment.
3. The current service is healthy. An unhealthy service requires diagnosis,
   not this controlled rollback path.
4. The approval explicitly permits draining non-production calls and accepts
   the reviewed systemd/Docker stop timeout as the final bound.

Then dispatch:

- `operation=rollback`
- `confirm_nonproduction=true`
- `owner_authorization=OWNER-AUTHORIZED-NONPROD-ROLLBACK`
- `approval_reference=<reviewed non-secret reference>`

The executable runbook uses pinned SSH trust and performs these bounded steps:

1. Require the existing service to be active and locally ready.
2. Record its exact image ID and verify the pre-staged rollback digest differs.
3. Request `systemctl stop --no-block bridgefu`; the service's SIGTERM path
   stops admission and drains its owned call/media tasks. The installed unit's
   reviewed stop timeout remains the outer bound; this script never invokes
   `docker kill`.
4. Wait for both systemd and the `bridgefu` container to stop. If the deadline
   expires or systemd reports a failed result, stop without changing the image.
5. Retag the immutable reviewed image as `bridgefu:latest`, start the unit, and
   require localhost `/readyz`.
6. If tagging, startup, or readiness fails, stop the candidate cleanly, restore
   the exact prior image ID, and restart it. If the candidate cannot be stopped
   or the prior image cannot be restored, leave the tag unchanged where safe
   and escalate; do not improvise a production target or force-kill additional
   calls.

The same plan can be rendered locally with secret-manager-provided environment
references and no SSH by running:

```bash
bash scripts/standardcharter-drain-rollback.sh plan
```

Do not paste the values into this document or shell history. Prefer the
environment-protected workflow for execution.

## Evidence and ownership

For a live qualification record, retain the workflow URL, immutable Bridgefu
revision, Cargo.lock digest, exact rvoip 0.3.7 package/checksum evidence,
approval reference, redacted artifact digest, AWS account fingerprint, and
result. Never retain tokens, phone numbers, raw correlations, SIP headers, call
payloads, or Vapi response bodies.

Checking in or validating this workflow and runbook satisfies the Gate 1
artifact requirement. It does not claim an external run. Owner-authorized live
AWS/GCP/provider smoke evidence remains part of later release qualification.
