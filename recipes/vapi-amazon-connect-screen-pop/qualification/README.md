# Protected qualification

[`matrix.yaml`](matrix.yaml) is the exact advertised SIP/RTP, SIPS/SRTP,
codec, Vapi web-transfer, failure, adverse-network, and soak gate.
[`evidence-v1.schema.json`](evidence-v1.schema.json) is the only evidence shape
accepted for promotion. It intentionally has no field for customer data,
correlation IDs, credentials, transcripts, recordings, or raw SIP/SDP.

The current nonproduction gate is Starter SIP/RTP over the runtime IP only; it
uses no DNS, hostname, certificate, secure-SIPS, or HA input. Before qualifying
a fresh ID, recover the privately identified retired execution using the
[IP-only nonproduction live-qualification runbook](../runbooks/nonproduction-live-qualification.md).
The ID is permanently retired, bootstrap-only, and teardown-only; its ledger
was lost and no application change set was executed. It must reach retained
three-observation zero proof before a fresh execution can initialize.

The normal `bridgefu recipe test` and guarded AWS `verify` command are
nonbillable structural/contract gates. They do not manufacture audio evidence
and cannot promote the recipe. A protected live controller must drive the
published browser/Vapi assistant and an authorized synthetic Connect agent,
inject deterministic non-silent markers/DTMF, observe Agent Workspace, execute
the failure matrix, and emit a redacted document conforming to the schema.

The guarded AWS `lifecycle-test` is the separate infrastructure lifecycle
gate. After structural verification it applies a bounded, non-replacing
configuration update, then intentionally supplies a nonexistent version of an
owned Lambda artifact and requires CloudFormation to restore the last working
version through `UPDATE_ROLLBACK_COMPLETE`. A second `verify` run must pass.
This proves update/rollback mechanics; it still does not substitute for live
audio, agent, failure, or soak evidence.

The disposable headless harness is a separate CloudFormation root stack, not a
child of the application under test. Its change set is reviewed independently,
uses a dedicated CloudFormation service role, and must reach `CREATE_COMPLETE`
before the application change set can execute. CREATE failures preserve
successfully provisioned resources for diagnosis; the execution-scoped destroy
flow then deletes the application and harness separately and proves zero state.

Validate a completed document with:

```text
python3 scripts/validate-recipe-evidence.py path/to/evidence.json
```

The validator also checks the semantic matrix: each scenario must occur under
both network profiles, every named check must be true, the profile-specific
failure drills must be present, and the soak/zero state must pass. Evidence is
tied to immutable image, recipe, release-manifest, and CloudFormation hashes.

Live or billed execution requires an approved nonproduction identity, unique
execution ledger, spend and time ceiling, synthetic identities, and mandatory
teardown inventory. The existing customer Connect instance and target flow are
references only and are never teardown targets.

Live authority defaults to
`${XDG_STATE_HOME:-$HOME/.local/state}/bridgefu/aws-live/<execution-id>/`.
An absolute `BRIDGEFU_AWS_LIVE_STATE_DIR` override replaces the entire private
root and must end in `bridgefu/aws-live`; it is not a per-execution path. Keep
controller state and browser credentials on the originating host, with mode
`0700` directories and mode `0600` files. Never copy them to another host or
operator. Remote recovery capsules are write-only evidence and are not
consumed, and there is no cross-host distributed lock, so exactly one operator
and host owns recovery at a time. An existing valid legacy ledger may migrate
automatically, but the former repository-local evidence is absent and was not
migrated.

## Per-call protected controller

The per-call controller consumes only a deployed, structurally verified stack
whose image, release, and complete working-tree digest still match. It uses the
temporary qualifier role for read-only DynamoDB, CloudWatch, secret, stack, and
Vapi verification. Raw call IDs, correlation IDs, and the expiring SIP URI are
kept in mode-`0600` files below that execution's durable private directory and
deleted after a successful join. The retained observations are validated by:

- [`participant-observation-v1.schema.json`](participant-observation-v1.schema.json)
  for the real Agent Workspace browser;
- [`source-observation-v1.schema.json`](source-observation-v1.schema.json) for
  the controlled SIP source;
- [`vapi-source-observation-v1.schema.json`](vapi-source-observation-v1.schema.json)
  for the stock Vapi web SDK; and
- [`call-observation-v1.schema.json`](call-observation-v1.schema.json) for the
  independent DynamoDB, CloudWatch, Vapi API, source, and agent join.

Authenticate the authorized synthetic Connect agent once. The resulting
Playwright storage state is a credential and must remain mode `0600` outside
Git:

```bash
export EXECUTION='bft-FRESH-ID'
LIVE_STATE_ROOT="${BRIDGEFU_AWS_LIVE_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/bridgefu/aws-live}"
LIVE_RUN_DIR="$LIVE_STATE_ROOT/$EXECUTION"
STORAGE_STATE="$LIVE_RUN_DIR/agent-workspace.private.json"
test -d "$LIVE_RUN_DIR"
umask 077

node recipes/vapi-amazon-connect-screen-pop/qualification/agent-workspace-playwright.mjs \
  auth \
  --connect-url https://INSTANCE-ALIAS.my.connect.aws/agent-app-v2/ \
  --storage-state "$STORAGE_STATE" \
  --timeout-seconds 300
```

For each direct scenario, create one HMAC-authenticated expiring session and
then run both independent observers. Repeat with `--hangup-origin source` and
`agent`; change the deployed `SipSecurity` posture through reviewed
non-replacing updates before switching between SIP/RTP and SIPS/SRTP:

```bash
SESSION=$(python3 scripts/collect-recipe-call-evidence.py start-direct \
  --execution-id "$EXECUTION" \
  --scenario sip-rtp-pcmu \
  --hangup-origin source \
  --confirm "$EXECUTION")

python3 scripts/collect-recipe-call-evidence.py run-direct \
  --execution-id "$EXECUTION" \
  --session "$SESSION" \
  --connect-url https://INSTANCE-ALIAS.my.connect.aws/agent-app-v2/ \
  --storage-state "$STORAGE_STATE" \
  --confirm "$EXECUTION"
```

`run-direct` launches the real Rust SIP peer and real Agent Workspace at the
same time. The source proves its rendered wire INVITE, TLS/UDP and SRTP/RTP
posture, negotiated PCMU or PCMA, audio markers, DTMF, and BYE. Bridgefu
independently records the duplicate-preserving INVITE only after it consumes
exactly one matching `X-Correlation-Id`. Agent Workspace proves the exact
synthetic screen-pop values, opposite audio direction, DTMF, and contact
cleanup. The collector joins those facts to DynamoDB, Connect lookup, and all
six runtime lifecycle stages.

The Vapi path uses the exact immutable demo-site ZIP from the published
release. A demo-site-enabled live qualification loads its HTML, JavaScript,
CSS, and license assets from the deployed CloudFront distribution; a
non-deployed qualification falls back to a server bound only to `127.0.0.1`.
For the live browser run, only `config.json` is intercepted in memory to add
the one-run qualification nonce and selected hangup direction. `verify`
separately proves the deployed public configuration, exact release bytes,
private S3 origin, zero-cache policy, origin access control, redirect, content
types, and security headers. Put the browser-safe public key in the
environment; never substitute the private Vapi key. The private key remains in
the execution-owned Secrets Manager secret and is read only by the qualifier
role to verify the final Vapi call object:

```bash
export VAPI_PUBLIC_KEY='browser-safe-public-key'

python3 scripts/collect-recipe-call-evidence.py run-vapi \
  --execution-id "$EXECUTION" \
  --hangup-origin source \
  --connect-url https://INSTANCE-ALIAS.my.connect.aws/agent-app-v2/ \
  --storage-state "$STORAGE_STATE" \
  --confirm "$EXECUTION"
```

The browser starts a stock `@vapi-ai/web` `2.5.2` call, pauses before transfer,
and gives the controller only the private call identity. The controller derives
the same correlation ID as the AWS Lambda, starts the Agent Workspace observer,
then releases one fixed synthetic `prepare_handoff` and transfer prompt. The
final join requires the recipe-owned assistant ID, the real prepare tool and
transfer tool in Vapi's call object, Bridgefu's actual received header, visible
screen pop, bidirectional marker audio, bidirectional DTMF, the selected hangup
origin, and zero per-call cleanup. Repeat with `--hangup-origin agent`.

These commands produce redacted per-call facts. They do not assemble or pass
the complete release evidence by themselves: both network profiles, failure
drills, negative cases, one-hour soak, final zero-state, and teardown still
have to pass before changing a support label.

## Packaged AWS headless smoke and full proof

The disposable-Connect launch path packages this repository's exact frozen
source plus the release-built Linux probe binaries into the immutable release.
Its private-subnet CodeBuild runner verifies those binaries instead of compiling
Rust during the paid run, installs the pinned dependencies and Playwright
Chromium, signs in to the generated
Connect-managed demo agent without human browser state, and invokes the same
collector used by the manual release matrix. The controller accepts a run only
when CodeBuild succeeds, the downloaded archive metadata matches its SHA-256,
and every retained file matches the runner's bounded digest inventory. The
package downloads the exact published manifest, runtime, qualification, and
demo-site object versions before testing and rejects any one if its size,
digest, source revision, binary platform, or image binding changed. The local
controller persists one run ID, immutable input version, CodeBuild ID, and
deadline. A restarted controller lists the exact project and adopts the unique
build matching the input bucket/key/version; it does not depend on CodeBuild's
short idempotency-token lifetime. Ledger files, release payloads, credentials, sessions,
and other `*.private.json` files are never included in the returned evidence
archive.

`--suite smoke` defaults to one IP-addressed SIP/RTP call and one Vapi
web-to-SIP transfer in both hangup directions. It needs no domain and proves
the deployability, media, correlation-header, Amazon Connect WebRTC, Lambda
lookup, screen-pop, and cleanup path. It does not prove SIPS certificate trust.
Do not opt into `--secure-sips-proof` for the current nonproduction proof; DNS
and SIPS/SRTP are later production gates. Neither smoke mode replaces the full
support-promotion matrix below.

`--suite full` runs the deployed three-scenario posture under both `baseline`
and `moderate-wan`, with source and agent hangup: exactly 3 × 2 × 2 = 12
retained calls. It also runs all nine negative cases and all three real Starter
failure drills, distributes the calls across a 60–65 minute soak, and records
a distinct pre-lifecycle zero-state observation. The local controller then
validates every component and cross-reference before importing only the
redacted official evidence into the execution directory. Smoke remains the
quick four-call diagnostic and is not imported as promotion evidence.
Starting a full run requires the complete 180-minute authorization window.
Polling refreshes the scoped AWS session, and a deadline or teardown first
stops any active build and waits for an authoritative terminal status.

```text
python3 scripts/aws-recipe-live-test.py --execution-id "$EXECUTION" run-headless --suite smoke --confirm "$EXECUTION"
python3 scripts/aws-recipe-live-test.py --execution-id "$EXECUTION" run-headless --suite full --confirm "$EXECUTION"
```

## Starter release execution order

The release controller is deliberately order-sensitive. Start all three
failure drills before the soak so the host reboot cannot reset a soak counter.
Start the one-hour monitor only after the host has recovered. Use the first
retained matrix call as the common post-recovery call for all three drills.
The dependency drill holds only the private reservation request behind a
bounded HAProxy tarpit, proves Bridgefu itself remains ready, requires the
exact handled Lambda `503`, and restores the original proxy configuration.
This keeps the deployed matrix at exactly 12 calls rather than manufacturing
extra success evidence:

```text
python3 scripts/run-recipe-qualification.py failure-start --execution-id "$EXECUTION" --id process_restart --confirm "$EXECUTION"
python3 scripts/run-recipe-qualification.py failure-start --execution-id "$EXECUTION" --id dependency_timeout --confirm "$EXECUTION"
python3 scripts/run-recipe-qualification.py failure-start --execution-id "$EXECUTION" --id host_recovery --confirm "$EXECUTION"
python3 scripts/run-recipe-qualification.py soak-start --execution-id "$EXECUTION" --confirm "$EXECUTION"
```

Run the three scenarios selected by the deployed SIP posture in
[`matrix.yaml`](matrix.yaml) under both `baseline` and `moderate-wan`, once
with source hangup and once with agent hangup. That is exactly 3 × 2 × 2 = 12
retained calls for the IP-only SIP/RTP deployment. The first call must finish
within ten minutes of `soak-start`; the last must start at least 50 minutes
after it; no gap between calls may exceed ten minutes. Direct scenarios use
`start-direct` followed by `run-direct`; `vapi-web-transfer` uses `run-vapi`.
After the first call evidence file is written, finish the three failure drills
against that same file:

```text
python3 scripts/run-recipe-qualification.py failure-finish --execution-id "$EXECUTION" --id process_restart --post-recovery-call "$FIRST_CALL" --confirm "$EXECUTION"
python3 scripts/run-recipe-qualification.py failure-finish --execution-id "$EXECUTION" --id dependency_timeout --post-recovery-call "$FIRST_CALL" --confirm "$EXECUTION"
python3 scripts/run-recipe-qualification.py failure-finish --execution-id "$EXECUTION" --id host_recovery --post-recovery-call "$FIRST_CALL" --confirm "$EXECUTION"
```

The nine negative cases are separate from the 12-call success matrix. Run the
three HTTPS cases directly. For each SIP case, create a fresh baseline direct
session and pass its mode-`0600` path to `negative-sip`. Use a successful
baseline direct call for the call-derived replay check. For missing context,
create a fresh source-hangup baseline direct session and provide the real Agent
Workspace login state:

```text
python3 scripts/run-recipe-qualification.py negative-http --execution-id "$EXECUTION" --id prepare_auth_rejected --confirm "$EXECUTION"
python3 scripts/run-recipe-qualification.py negative-http --execution-id "$EXECUTION" --id prepare_conflicting_replay_rejected --confirm "$EXECUTION"
python3 scripts/run-recipe-qualification.py negative-http --execution-id "$EXECUTION" --id malformed_payload_rejected --confirm "$EXECUTION"

python3 scripts/run-recipe-qualification.py negative-sip --execution-id "$EXECUTION" --id missing_correlation_header_rejected --session "$NEGATIVE_SESSION" --confirm "$EXECUTION"
python3 scripts/run-recipe-qualification.py negative-sip --execution-id "$EXECUTION" --id duplicate_correlation_header_rejected --session "$NEGATIVE_SESSION" --confirm "$EXECUTION"
python3 scripts/run-recipe-qualification.py negative-sip --execution-id "$EXECUTION" --id expired_attachment_rejected --session "$NEGATIVE_SESSION" --confirm "$EXECUTION"
python3 scripts/run-recipe-qualification.py negative-sip --execution-id "$EXECUTION" --id source_cancellation_cleanup --session "$NEGATIVE_SESSION" --confirm "$EXECUTION"

python3 scripts/run-recipe-qualification.py negative-from-call --execution-id "$EXECUTION" --id attachment_replay_rejected --call-evidence "$BASELINE_CALL" --confirm "$EXECUTION"
python3 scripts/run-recipe-qualification.py negative-missing-context --execution-id "$EXECUTION" --session "$MISSING_CONTEXT_SESSION" --connect-url "$CONNECT_URL" --storage-state "$STORAGE_STATE" --confirm "$EXECUTION"
```

`$NEGATIVE_SESSION` means a different fresh session for every SIP command; a
successful command consumes and removes it. Finish the soak between 60 and 65
minutes after it started. The controller requires 100–140 30-second host
samples, exact p95 timing calculations, no host-counter reset, no media-drop or
cleanup-backlog increase, and zero Lambda, DynamoDB, or runtime errors:

```text
python3 scripts/run-recipe-qualification.py soak-finish --execution-id "$EXECUTION" --confirm "$EXECUTION"
python3 scripts/run-recipe-qualification.py zero-state --phase pre_lifecycle --execution-id "$EXECUTION" --confirm "$EXECUTION"
```

Next run the guarded CloudFormation update/rollback lifecycle test, re-run
structural verification and final zero state, and destroy the entire
execution. `assemble` runs last because it requires the immutable teardown
inventory as evidence:

```text
python3 scripts/aws-recipe-live-test.py --execution-id "$EXECUTION" lifecycle-test --confirm "$EXECUTION"
python3 scripts/aws-recipe-live-test.py --execution-id "$EXECUTION" verify
python3 scripts/run-recipe-qualification.py zero-state --phase final --execution-id "$EXECUTION" --confirm "$EXECUTION"
python3 scripts/aws-recipe-live-test.py --execution-id "$EXECUTION" destroy --confirm "$EXECUTION"
python3 scripts/run-recipe-qualification.py assemble --execution-id "$EXECUTION" --confirm "$EXECUTION"
```

Any failed command stops promotion. Do not edit an observation, reuse a
session, substitute a hand-written boolean, or publish from a changed working
tree. A Starter support declaration becomes effective only when the exact
release passes this sequence and the independent validator accepts the final
redacted evidence document.
