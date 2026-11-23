# Vapi → Bridgefu → Amazon Connect

Two complete examples share a customer-owned field configuration:

| Recipe | SIP carries | Additional context storage | Connect flow |
| --- | --- | --- | --- |
| [SIP headers](sip-headers/README.md) | Every configured value | No lookup store | Attributes already exist when the flow starts |
| [Correlation ID](correlation-id/README.md) | One configurable lookup token | DynamoDB with expiry | Lambda resolves the token and sets attributes |

Both include an assistant, function tool, Lambda source, CloudFormation, Connect flow, and Bridgefu recipe. The first still uses a transfer Lambda to assemble live values; it does **not** store or look up context. Bridgefu’s durable call record and the Connect contact still retain the configured attributes. Choose either independently. Bridgefu has no built-in knowledge of customer session, intent, summary, or Vapi call ID.

These recipes cover the Vapi → Bridgefu → Connect return leg. They assume your application supplies the session to Vapi. They do not change how an existing Connect → Vapi phone leg obtains that session; DTMF capture and its timing remain a separate concern.

## Prerequisites

- Build Bridgefu from this checkout. Bridgefu 0.9.1 includes the fixed-URI TLS and configured header-ingestion changes; the `0.9.0` source release does not include them.
- An AWS account, an authenticated AWS CLI profile, Python 3.10+, and a Vapi private API key in `VAPI_PRIVATE_KEY`.
- An existing Amazon Connect instance and published target contact flow in the same AWS region. The target flow handles queuing/agents. The example creates a new entry flow and transfers to your target.
- A public Bridgefu gateway with DNS, a trusted TLS certificate, its public media IP, and an IAM role allowed to `connect:StartWebRTCContact` on the example entry flow and `connect:StopContact` on that instance's contacts. Use your deployment's normal workload credentials.
- A Vapi telephony path supporting custom SIP headers and dial transfers. The live fixture uses authenticated inbound Vapi SIP. [Vapi documents custom transfer headers for Vapi, BYO SIP, and Telnyx paths, not Twilio](https://docs.vapi.ai/tools/transfer-call). This recipe does not turn a browser `webCall` into a supported telephone transfer.

## 1. Configure the field contract

Run from the repository root:

```sh
python3 -m venv examples/vapi-amazon-connect/.local/venv
. examples/vapi-amazon-connect/.local/venv/bin/activate
pip install -r examples/vapi-amazon-connect/requirements.txt
mkdir -p examples/vapi-amazon-connect/.local
chmod 700 examples/vapi-amazon-connect/.local
cp examples/vapi-amazon-connect/sip-headers/settings.example.json \
  examples/vapi-amazon-connect/.local/settings.local.json
```

For the other recipe, copy `correlation-id/settings.example.json`. Edit your private copy:

- Set `region`, `sip_host`, `sip_user`, `media_public_ip`, `connect_instance_arn`, and `signaling_cidrs`. The checked-in IPs/ARNs are documentation placeholders. Use your Vapi region's current [signaling allowlist](https://docs.vapi.ai/advanced/sip/sip-networking).
- Set the model, voice, prompt, and tool name as needed.
- Edit `fields` to add/remove/rename application data. Each field defines its `source`, SIP `header`, Connect `attribute`, required flag, and UTF-8 byte bound. `name` is the tool argument name when the source is `arguments.<name>`.
- `call.*` reads Vapi's authenticated call API, `variables.*` reads `assistantOverrides.variableValues`, and `arguments.*` reads the assistant's tool arguments. Keep authoritative IDs/session inputs in the first two groups. Intent and concise conversation summary normally come from arguments.
- In correlation mode, configure `correlation.header`, `correlation.attribute`, `correlation.ttl_seconds`, and `status_attribute`. The supplied `X-Correlation-Id` / `handoff_id` pairing is an example, not a requirement.

All customer data names and mappings live in this file, not in the Bridgefu release. Protocol fields such as `assistantOverrides` and Bridgefu's reserved ownership attributes retain their defined meaning. The renderer rejects collisions with reserved keys rather than allowing customer input to overwrite them. No model-generated IDs are accepted as authoritative IDs by default.

The examples bound each string to 2,048 UTF-8 bytes and the sum of configured field bounds to 2,500 bytes. Keep SIP context short: network/provider message limits also apply. Correlation storage is preferable for larger context; increase the example's bounds only after accounting for Connect's 4 KiB Lambda response limit and SIP/provider limits.

## 2. Deploy the integration

Authenticate your AWS profile and supply the Vapi key through your usual secret manager or shell environment. Do not put secrets on command lines or in version control. Replace the all-caps placeholders below with your own resource references:

```sh
python3 examples/vapi-amazon-connect/shared/manage.py deploy \
  --settings examples/vapi-amazon-connect/.local/settings.local.json \
  --profile YOUR_AWS_PROFILE \
  --name YOUR_UNIQUE_EXAMPLE_NAME \
  --instance-arn YOUR_CONNECT_INSTANCE_ARN \
  --target-flow-arn YOUR_PUBLISHED_TARGET_FLOW_ARN \
  --state examples/vapi-amazon-connect/.local/deployment.json
```

This creates new resources: the entry flow, HTTPS function endpoint, Lambda/IAM/logs, webhook secret, a private copy of the Vapi API key in Secrets Manager, and a new Vapi assistant. Correlation mode additionally creates a DynamoDB table and Connect lookup Lambda association. It does not modify existing assistants or your target flow. AWS/Vapi usage incurs charges.

The private state file records resources for cleanup and the `rendered` directory. That directory contains the actual entry flow ID in `bridgefu.example.yaml`. Keep the state, rendered files, and actual IDs private. The deploy script never writes the assistant's expanded webhook secret to disk.

To inspect configuration without deploying:

```sh
python3 examples/vapi-amazon-connect/shared/render.py \
  --settings examples/vapi-amazon-connect/.local/settings.local.json \
  --output examples/vapi-amazon-connect/.local/rendered
```

The checked-in generated files are readable examples. Change settings and rerender; don't maintain contradictory mappings across hand-edited copies. `amazon-connect/contact-flow.json` has CloudFormation substitutions and is a reference, not a directly importable resolved flow. Deploy its enclosing CloudFormation template.

## 3. Install the gateway configuration

Copy the private generated `recipe/` and `bridgefu.example.yaml` to the gateway. Change `recipe_catalog.paths` to the **gateway's** absolute recipe directory. Keep the generated entry flow ID. Set these through your service's secret/environment mechanism:

- `BRIDGEFU_API_BEARER_TOKEN`: a fresh random administration token.
- `BRIDGEFU_CONTROL_HMAC_KEY`: a separate random control secret.
- `BRIDGEFU_SIP_TLS_PRIVATE_KEY_PATH`: the absolute path to the matching PEM private key.

Install the certificate chain at `edge.sip_tls.certificate_chain`, and ensure the service can write `/var/lib/bridgefu/bridgefu.db`. Allow TCP 5061 only from the configured trusted signaling CIDRs; allow the gateway's RTP UDP range for negotiated media. Keep administration and metrics private. Validate and start using your deployment's service manager:

```sh
bridgefu --config /etc/bridgefu/bridgefu.yaml validate
bridgefu --config /etc/bridgefu/bridgefu.yaml run
```

The default is TLS plus required SRTP (`sips_srtp`). Use `sips_optional_srtp` only when intentionally accepting unencrypted RTP from the chosen provider. TLS does not itself encrypt RTP. These external recipes use an allowlisted fixed address; they do not require a managed one-use URI or correlation token. Source-network admission identifies the allowed provider network, not a particular Vapi organization. These examples do not configure client-certificate mTLS.

## 4. Supply the session and place a test call

The private deployment state contains the new `assistant_id`. Use it with a **nonproduction** Vapi phone/SIP entry. For an outbound supported telephony call, adapt the generated `vapi/call.example.json`: replace assistant and phone IDs, use your own consenting test destination, and supply the session under `assistantOverrides.variableValues`. The example telephone number is fictitious.

For inbound calls, your phone-number `server` answers Vapi's `assistant-request` with the new `assistantId` plus `assistantOverrides.variableValues`. Do not also assign an assistant to that phone number, which bypasses the selector. See [Vapi overrides](https://docs.vapi.ai/assistants/assistant-overrides). The [test selector](tests/inbound.yaml) illustrates this using configurable synthetic values; a production selector obtains the session from your trusted application.

Ask for a human and give a short issue description. The assistant calls its function with conversation fields. The Lambda retrieves the authoritative call and input variables, constructs configured headers, and uses that call's live control URL to request a blind SIP `dial` transfer. No DTMF ID transmission or waiting for digits is involved. A successful tool response means transfer requested, not proof that an agent answered.

## 5. Verify and clean up

Follow [the reproducible end-to-end test](tests/E2E.md), including exact attribute comparison, media verification, negative checks, and redacted evidence. The per-recipe pages describe the expected attributes and fallback behavior.

```sh
python3 -m unittest discover -s examples/vapi-amazon-connect/tests -p 'test_*.py'
python3 examples/vapi-amazon-connect/shared/manage.py cleanup \
  --state examples/vapi-amazon-connect/.local/deployment.json
```

Cleanup removes only resources recorded by that deployment, including its new assistant and secrets. It retains the preexisting Connect instance, target flow, and gateway. Correlation context in the example table is deleted with the stack. Follow your retention requirements before adapting this example for production.

The deploy helper is deliberately small: it journals owned resources but is not a production deployment reconciler. If interrupted, preserve its private state and inspect CloudFormation before retrying. Protect webhook secrets, rotate the stored Vapi key when yours rotates (and redeploy these example functions to clear their warm secret caches), and avoid logging raw events, headers, transcripts, control URLs, or tokens.
