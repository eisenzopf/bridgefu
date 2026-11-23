# Set up your first Vapi-to-Connect handoff

This guide sets up one example. Run it again with a different deployment name if you want to try the other one.

The result is straightforward: a caller talks to Vapi, asks for a person, and reaches your Amazon Connect flow. The flow receives the fields you chose. There is no need to send a session ID as DTMF digits.

## Before you start

You need:

- Access to Vapi and a private API key.
- An AWS profile with permission to deploy CloudFormation, Lambda, IAM, API Gateway, Secrets Manager, and Connect resources. The correlation example also uses DynamoDB.
- A nonproduction Amazon Connect instance and a published flow that routes callers to a queue.
- A public Bridgefu server built from this checkout, with DNS, a valid TLS certificate, and an AWS role. Use your normal Bridgefu deployment process; the [test harness](tests/E2E.md) can create a disposable server and Connect instance if you do not have them.

Allow for AWS and Vapi usage charges. Use synthetic context and your own test caller while setting this up.

## Part 1: Prepare Amazon Connect

### 1. Choose the destination flow

Open your nonproduction instance in the Amazon Connect console. Choose the contact flow that should receive transferred callers.

For a simple test, that flow should:

1. Set a working queue.
2. Transfer the caller to that queue.
3. Route errors to a prompt or disconnect step.

Publish the flow. Give your test agent a routing profile that includes the queue, enable the agent's softphone, and sign the agent into the Contact Control Panel or Agent Workspace. The agent will need to be **Available** when you place the call.

Keep these two references in a private note:

- The **instance ARN**, identifying your Connect instance.
- The **target flow ARN**, identifying the published destination flow in that instance.

The [AWS runbook](AWS-RUNBOOK.md#find-your-connect-instance-and-flow) shows how to find them with the CLI. Do not confuse the target flow with the new entry flow created below: Bridgefu starts the entry flow, and that flow hands off to your target.

**Checkpoint:** you have a published target flow, a usable queue, and a test agent who can receive calls.

### 2. Choose how the context travels

For your first test, choose **SIP headers only** if your context is short. Choose **correlation ID** if you want to store the context and send a lookup token instead.

You will copy the matching settings file in the next step. Both examples leave your existing target flow intact.

## Part 2: Configure Bridgefu and the integration

### 3. Make a private settings file

From the Bridgefu repository root:

```sh
python3 -m venv examples/vapi-amazon-connect/.local/venv
. examples/vapi-amazon-connect/.local/venv/bin/activate
pip install -r examples/vapi-amazon-connect/requirements.txt
chmod 700 examples/vapi-amazon-connect/.local
cp examples/vapi-amazon-connect/sip-headers/settings.example.json \
  examples/vapi-amazon-connect/.local/settings.local.json
```

For correlation mode, copy `correlation-id/settings.example.json` instead.

Open `settings.local.json` in your editor. Replace the example infrastructure values:

| Setting | Put your value here |
| --- | --- |
| `region` | The AWS region containing your Connect instance |
| `sip_host` | Your Bridgefu server's public DNS name |
| `sip_user` | The fixed SIP address name you want, such as `support` |
| `media_public_ip` | The server's public IP for RTP audio |
| `signaling_cidrs` | Your Vapi region's current SIP signaling addresses |
| `connect_instance_arn` | The instance ARN from step 1 |

Leave `entry_contact_flow_id` as the placeholder for now. The deploy helper fills it in after creating the new entry flow.

The default `sip_security` is `sips_srtp`: TLS signaling and encrypted RTP are required. If your Vapi path offers plain RTP, select `sips_optional_srtp` deliberately. That keeps TLS signaling but permits plain RTP. Check the [live test report](tests/E2E.md) for the posture actually tested. Do not assume that a `sips:` address encrypts audio.

### 4. Choose the values to pass

The default settings describe four fields:

| Field | Where it comes from | Why |
| --- | --- | --- |
| Customer session | Your application's input variable | Preserves the session you already know |
| Vapi call reference | Vapi's authenticated call API | Uses the actual call ID |
| Intent | The assistant's tool argument | Describes what the caller wants |
| Summary | The assistant's tool argument | Gives the next agent conversation context |

Each entry in `fields` lets you choose the source, SIP header, and Connect attribute name. For example:

```json
{
  "name": "session",
  "source": "variables.customer_session",
  "header": "X-Customer-Session",
  "attribute": "customer_session",
  "max_bytes": 128,
  "required": true,
  "description": "The session supplied by our application.",
  "example": "synthetic-session-001"
}
```

This means “read the input variable `customer_session`, send it in `X-Customer-Session`, and expose it in Connect as `customer_session`.” Change those names to suit your application. Add or remove fields in this same list. The generator keeps the Vapi tool, Bridgefu mapping, and Connect flow consistent.

In correlation mode, those values go into DynamoDB. Only the header named in `correlation.header` travels in SIP. Its Connect attribute name, expiry, and lookup status attribute are also configurable.

**Checkpoint:** the settings describe your infrastructure and your own data contract. No customer field is compiled into Bridgefu.

### 5. Create the integration resources

Sign in to your AWS profile and make `VAPI_PRIVATE_KEY` available through your usual secret manager or shell environment. Do not paste the key into a checked-in file.

Run this command, replacing the all-caps placeholders:

```sh
python3 examples/vapi-amazon-connect/shared/manage.py deploy \
  --settings examples/vapi-amazon-connect/.local/settings.local.json \
  --profile YOUR_AWS_PROFILE \
  --name YOUR_UNIQUE_EXAMPLE_NAME \
  --instance-arn YOUR_CONNECT_INSTANCE_ARN \
  --target-flow-arn YOUR_PUBLISHED_TARGET_FLOW_ARN \
  --state examples/vapi-amazon-connect/.local/deployment.json
```

The helper creates:

- A new Connect entry flow leading to your target flow.
- An HTTPS Vapi webhook and its Lambda, permissions, and secrets.
- A new Vapi assistant with the webhook already connected.
- For correlation mode, the context table and the Connect lookup Lambda.

It also generates your actual Bridgefu config and recipe. Their directory is recorded as `rendered` in the private `deployment.json` file. The same file records the new `assistant_id` and AWS outputs for later use.

**Checkpoint:** CloudFormation reports `CREATE_COMPLETE`, and the helper reports that it created a new assistant. If it fails, keep the state file and use the runbook; do not delete it and repeatedly recreate resources.

### 6. Start Bridgefu with the generated config

Copy the generated `bridgefu.example.yaml` to `/etc/bridgefu/bridgefu.yaml` on your gateway. Copy the generated `recipe/` directory to `/etc/bridgefu/recipe/`.

On the gateway, edit `recipe_catalog.paths` in the config to point to `/etc/bridgefu/recipe`. The local generated path will not work on another machine.

Then configure:

- **TLS:** install your certificate chain at the path in `edge.sip_tls.certificate_chain`. Set `BRIDGEFU_SIP_TLS_PRIVATE_KEY_PATH` to the matching private key file.
- **Administration secrets:** set separate random values for `BRIDGEFU_API_BEARER_TOKEN` and `BRIDGEFU_CONTROL_HMAC_KEY` in your service's environment.
- **AWS access:** give the gateway's role `connect:StartWebRTCContact` on the new entry flow and `connect:StopContact` on contacts in your test instance. Use the region selected in settings.
- **Network:** allow TCP 5061 from the trusted Vapi signaling CIDRs and the configured UDP media range. Keep admin and metrics endpoints private.
- **Storage:** ensure the service can write `/var/lib/bridgefu/bridgefu.db`.

Validate the config before starting the service:

```sh
bridgefu --config /etc/bridgefu/bridgefu.yaml validate
bridgefu --config /etc/bridgefu/bridgefu.yaml run
```

Use your normal service manager for a persistent deployment. The test gateway template includes a reproducible temporary deployment; it is not a production operations template.

**Checkpoint:** validation succeeds and Bridgefu is running. The transfer destination is your chosen fixed address, such as `sips:support@YOUR_HOST:5061;transport=tls`.

## Part 3: Set up the Vapi call

### 7. Review the assistant

Open the new assistant in Vapi using the `assistant_id` from `deployment.json`. Its name matches your deployment name.

Review its model, voice, and system prompt. The assistant should gather the caller's issue and call the configured transfer function when the caller asks for a person. The generated tool declares only the conversation fields the model should provide, such as intent and summary. The webhook supplies the real call ID and trusted session input.

The tool's server URL and authentication header were filled in by the deploy helper. You do not need to copy secrets into the assistant manually. Do not replace this function with a static transfer destination: this example uses the webhook to assemble values from the live call and the conversation at transfer time.

If you change field names, change the private settings and regenerate/redeploy the affected artifacts together. Editing only the tool schema will leave the other components expecting the old names. The simple deploy helper creates new deployments; use a new name and state file when trying another contract, then remove the old test deployment.

### 8. Supply your session before the conversation starts

For an **outbound call**, adapt the generated `vapi/call.example.json`. Use the new assistant, a supported nonproduction phone resource, and your own test destination. Include your session as an input variable:

```json
"assistantOverrides": {
  "variableValues": {
    "customer_session": "synthetic-session-001"
  }
}
```

Use your configured variable name if you changed it. The input should come from your application; the assistant should not invent it.

A Vapi SIP phone entry is inbound-only; do not use it as an outbound calling number. The automated test below calls its SIP address directly. See [Vapi SIP setup](https://docs.vapi.ai/advanced/sip/).

For an **inbound call**, configure a phone-number server that answers Vapi's `assistant-request` with:

```json
{
  "assistantId": "YOUR_NEW_ASSISTANT_ID",
  "assistantOverrides": {
    "variableValues": {
      "customer_session": "synthetic-session-001"
    }
  }
}
```

Leave the phone number's assigned assistant empty so Vapi calls that server. Your server looks up the caller's session in your trusted application. The disposable [inbound test selector](tests/inbound.yaml) demonstrates the response using synthetic inputs. See [Vapi's inbound and outbound override instructions](https://docs.vapi.ai/assistants/assistant-overrides).

**Checkpoint:** the call starts with the session variable you supplied. Having a variable written in a prompt is not the same as supplying its value.

### 9. Ask for a transfer

Set the Connect agent to **Available**, then make the test call through your supported Vapi phone/SIP path. Say, for example:

> My doorbell is offline. I already restarted it. Please transfer me to a person for technical support.

Expected sequence:

1. Vapi calls the function with a short intent and summary.
2. The webhook fetches the live call and assembles the configured values.
3. Vapi sends the SIP transfer to Bridgefu.
4. Bridgefu starts the Connect entry flow with the configured SIP attributes.
5. In correlation mode, Connect resolves the token and sets the context attributes.
6. Your target flow queues the caller, and the available agent receives the call.

### 10. Check the data and audio

In Connect, inspect the contact attributes using the runbook. Check the session against your supplied value, the Vapi reference against the actual Vapi call, and the intent/summary against the tool's arguments.

Your flow can reference a configured attribute as `$.Attributes.customer_session`, for example. Displaying it in a custom agent screen is a separate UI choice; the example ensures the attribute is available to the flow.

In correlation mode, check that the configured status attribute is `found`. A caller can still reach your queue when lookup fails, so an answered call alone does not prove that the context arrived.

Speak in both directions and hang up. Confirm that the Connect contact disconnects. For automated proof, negative checks, and a report you can share without IDs or secrets, follow [the E2E guide](tests/E2E.md).

When finished, use [the cleanup commands](AWS-RUNBOOK.md#remove-your-example-resources). Preserve private state until cleanup completes.
