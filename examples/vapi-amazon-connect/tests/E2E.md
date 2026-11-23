# Reproduce the end-to-end test

This test makes a real call through:

**Synthetic SIP caller → Vapi assistant → transfer webhook → Bridgefu → Amazon Connect → browser agent.**

It runs both recipes separately. It creates a temporary authenticated Vapi SIP entry, supplies a synthetic session through an `assistant-request` response, speaks a synthetic support request, and verifies the resulting Connect contact. It does not call a real telephone number.

## What the test checks

- The session supplied before the call matches the Connect attribute exactly.
- The Vapi reference matches the actual call ID.
- Intent and summary match the assistant's actual function arguments.
- In header mode, there is no correlation attribute or lookup table.
- In correlation mode, lookup succeeds; missing and expired tokens are rejected by the deployed lookup Lambda.
- The contact reaches the test agent.
- A generated agent audio marker reaches the source, and a different generated caller audio probe reaches the browser agent. RTP counters and the source's clean hangup are also checked.
- The Connect contact disconnects after hangup, and Bridgefu has zero active calls, reserved capacity, and unreleased assignments.

All speech and context are synthetic. Raw call records, resource IDs, browser troubleshooting text, SIP credentials, and state remain in a private local directory. The report contains only assertion results, configured field names, and audio counters. Its duration is the whole test—including speech, probes, and verification—not handoff latency. The audio probes carry no session ID or other context.

## Before running

Use an AWS test account/profile, a Vapi private key, and a **public Route 53 hosted zone you control**. The test creates one new subdomain within that zone. You need Python 3.10+, Node.js, npm, Git, and ripgrep locally. CloudFormation builds Bridgefu on an isolated ARM64 EC2 host using the pinned Rust toolchain; a first build can take 30–45 minutes.

The AWS identity needs permission to create the resources in `aws-sandbox.yaml`, `gateway.yaml`, and the two recipe templates, plus Polly synthesis and SSM commands. Check your quotas for a Connect instance, EC2, Elastic IP, and Vapi SIP entries. This test incurs charges until cleanup completes.

The gateway has no SSH ingress. It uses SSM, a generated DNS record and certificate, a private artifact bucket, and a role scoped to its test resources. The SIP caller uses Digest authentication to Vapi. The transferred leg requires TLS. The test default allows optional SRTP because some Vapi paths offer plain RTP; this is an explicit test setting, distinct from the recipe's strict default.

## 1. Install local dependencies

From the repository root:

```sh
python3 -m venv examples/vapi-amazon-connect/.local/venv
. examples/vapi-amazon-connect/.local/venv/bin/activate
pip install -r examples/vapi-amazon-connect/requirements.txt
npm ci --prefix examples/vapi-amazon-connect/tests
PLAYWRIGHT_BROWSERS_PATH=0 npm exec \
  --prefix examples/vapi-amazon-connect/tests -- playwright install chromium
mkdir -p examples/vapi-amazon-connect/.local/live
chmod 700 examples/vapi-amazon-connect/.local/live
```

Authenticate your AWS profile and supply `VAPI_PRIVATE_KEY` through your usual secret mechanism. Never put the key in a command argument or the settings JSON.

## 2. Provision the disposable environment

Choose a unique lowercase name of 3–24 characters, such as `bf-example-test`. Replace every all-caps placeholder:

```sh
python3 examples/vapi-amazon-connect/tests/live.py provision \
  --state examples/vapi-amazon-connect/.local/live/state.json \
  --profile YOUR_AWS_PROFILE \
  --region YOUR_AWS_REGION \
  --name YOUR_UNIQUE_TEST_NAME \
  --zone-id YOUR_PUBLIC_HOSTED_ZONE_ID \
  --zone-name YOUR_PUBLIC_TEST_DOMAIN \
  --signaling-cidr YOUR_FIRST_VAPI_SIGNALING_CIDR \
  --signaling-cidr YOUR_SECOND_VAPI_SIGNALING_CIDR \
  --sip-security sips_optional_srtp
```

Use your Vapi region's current [signaling addresses](https://docs.vapi.ai/advanced/sip/sip-networking). This harness uses US Vapi SIP (`sip.vapi.ai`); changing Vapi regions requires adapting the test endpoint and the webhook API base as well as the allowlist.

Provisioning creates a Connect instance, queue, routing profile, generated test agent, and published target flow. It then creates the gateway and builds this checkout, deploys both examples, generates synthetic audio, builds the SIP peer, and creates the inbound selectors. Existing instances, agents, phone entries, and assistants are not modified.

The selectors return configurable synthetic `variableValues`; they are test fixtures. A production application would supply its real session from trusted application data.

**Expected:** the helper reports that the synthetic speech, SIP peer, and inbound selectors are ready. If provisioning fails, keep the state and inspect the named stack or private build log. The script is not a general-purpose resume/reconciliation engine; use its recorded state for cleanup before starting a fresh test.

## 3. Run each recipe

Run sequentially because both recipes use the same disposable gateway address:

```sh
python3 examples/vapi-amazon-connect/tests/live.py run \
  --state examples/vapi-amazon-connect/.local/live/state.json \
  --mode sip-headers

python3 examples/vapi-amazon-connect/tests/live.py run \
  --state examples/vapi-amazon-connect/.local/live/state.json \
  --mode correlation-id
```

For each case, the runner installs that recipe's gateway config, signs the generated agent into a headless browser, sets the agent Available, and calls the temporary Vapi SIP entry. The source speaks the support request and sends a known audio probe. The agent's fake microphone emits a different marker. The source hangs up only after observing the agent marker and sending its post-transfer probe.

The runner compares the actual contact attributes with the actual Vapi call and arguments. It does not decide that context succeeded merely because a call connected. In correlation mode it additionally invokes the deployed lookup Lambda with a missing token and an expired synthetic record.

Each command must print `PASS` and exit zero. Otherwise, keep its private evidence and use the [AWS runbook](../AWS-RUNBOOK.md).

## 4. Inspect results without publishing private data

The output directory contains:

- `sip-headers-report.json` and `correlation-id-report.json`: bounded assertion summaries.
- Separate run directories: **private** Vapi call records, Connect attributes, contact records, browser state text, and SIP peer output.
- Deployment/state/settings files: **private** resource references and SIP credentials.

Share only the assertion summaries after reviewing the configured field names. Never share the entire directory. The repository ignores `.local`, but that is not a substitute for checking an attachment before sending it.

## 5. Remove the disposable environment

Run cleanup even if a test fails:

```sh
python3 examples/vapi-amazon-connect/tests/live.py cleanup \
  --state examples/vapi-amazon-connect/.local/live/state.json
```

Cleanup uses the resource journal, removes the example resources and temporary Vapi entries, empties the test artifact bucket, and removes the test gateway/DNS/Connect stacks. It checks the AWS account before deletion. Keep the journal until it reports success.

## Recorded result — November 20, 2026

Both recipes passed real calls, then passed again after a fresh provisioning run and a clean local Python dependency install. See the [redacted machine-readable report](results.json).

| Check | SIP headers | Correlation ID |
| --- | --- | --- |
| Supplied session preserved exactly | Pass | Pass |
| Call ID, intent, and summary match their sources | Pass | Pass |
| Initial Connect attributes | All four fields; no correlation attribute | Lookup token only |
| Context available after entry flow | Pass | Pass |
| Agent receives call and audio works both ways | Pass | Pass |
| Missing and expired token rejection | Not applicable | Pass |
| Contact disconnects; gateway releases call capacity | Pass | Pass |
| Unauthenticated webhook request rejected | Pass | Pass |

The report records cleanup status separately and includes a hash of the runtime source used for the build. It contains no account, assistant, user, contact, or call IDs, tokens, credentials, or actual context values.

This validates the configured US Vapi native-SIP → Bridgefu → Connect path in Oregon. It does not qualify load, production resilience, mTLS, every carrier, strict SRTP on a peer that offers only RTP, or a browser `webCall` transfer. It does not change the upstream Connect-to-Vapi phone/DTMF leg. No released image is implied by this source test.

## Local checks

These checks need no AWS or Vapi credentials:

```sh
python3 -m unittest discover -s examples/vapi-amazon-connect/tests -p 'test_*.py'
cargo test --locked --bin bridgefu config::tests::customer_examples_project
cargo test --locked --test call_execution_supervisor stable_recipe
```

The generated contracts are tested with arbitrary customer field names. CloudFormation is checked for alias-free serialization, and Lambda tests cover identity provenance, unauthorized calls, bounds, replay consistency, lookup expiry, and instance isolation. The Rust integration tests verify exact Connect start attributes, real local media forwarding, duplicate-header rejection, and teardown for both correlation and direct-header routes.
