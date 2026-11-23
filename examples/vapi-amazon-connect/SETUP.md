# Try a working Vapi → Bridgefu → Connect example

The easiest first run is a disposable test environment. One command sets up Amazon Connect, Bridgefu, and two Vapi assistants. Then you test each handoff and remove everything.

**Use a test account and synthetic data.** This creates chargeable AWS and Vapi resources. It does not change your existing assistants, phone entries, or Connect instances.

Already have a gateway and Connect instance? Use the [existing-environment walkthrough](EXISTING-ENVIRONMENT.md) instead.

## 1. Gather four things

- An authenticated **AWS profile** with deployment permissions.
- Your **Vapi private API key**, available as `VAPI_PRIVATE_KEY` through your usual secret manager or shell environment.
- A **public Route 53 hosted zone** you control: its zone ID and domain name. The test adds one new subdomain.
- The two current **US Vapi signaling IP addresses** from [Vapi's networking documentation](https://docs.vapi.ai/advanced/sip/sip-networking). Append `/32` to each address in the command below.

If the Vapi key is not already in your environment, run the following, paste the key, and press Enter. The input is hidden and the key is not written into the command history:

```sh
read -r -s VAPI_PRIVATE_KEY && export VAPI_PRIVATE_KEY
```

Use a machine with Python 3.10+, Node.js 20+, npm, Git, and ripgrep. Run the following commands from this repository's root. You do not need Docker or a local Rust compiler.

## 2. Install the test tools

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

**You should see:** dependency installation completes without errors. All filled-in settings and test evidence will stay in the ignored `.local` directory.

## 3. Create the environment

Replace the capitalized placeholders. Choose a unique lowercase test name of 3–24 characters.

```sh
python3 examples/vapi-amazon-connect/tests/live.py provision \
  --state examples/vapi-amazon-connect/.local/live/state.json \
  --profile YOUR_AWS_PROFILE \
  --region YOUR_AWS_REGION \
  --name YOUR_UNIQUE_TEST_NAME \
  --zone-id YOUR_PUBLIC_HOSTED_ZONE_ID \
  --zone-name YOUR_PUBLIC_TEST_DOMAIN \
  --signaling-cidr YOUR_FIRST_VAPI_SIGNALING_IP/32 \
  --signaling-cidr YOUR_SECOND_VAPI_SIGNALING_IP/32 \
  --sip-security sips_optional_srtp
```

Allow about 30–45 minutes for the first source build. Keep the private state file, including if provisioning fails.

Here is what the command configures:

| Service | What it creates |
| --- | --- |
| **Amazon Connect** | A test instance, queue, published target flow, generated softphone agent, and an entry flow for each recipe |
| **Bridgefu** | A temporary server, DNS record, TLS certificate, current source build, and generated recipe configs |
| **Vapi** | Two assistants with the transfer function already configured, plus authenticated temporary SIP entries |
| **SIP-header recipe** | A webhook that assembles the values; no context database or lookup Lambda |
| **Correlation recipe** | A webhook that stores context, a DynamoDB table, and a Connect lookup Lambda |

The test explicitly requires TLS signaling and allows plain RTP when Vapi does not offer SRTP. That is what `sips_optional_srtp` means. The regular example config defaults to required SRTP; [the reference](REFERENCE.md) explains the distinction.

**You should see:** “Synthetic speech, SIP peer, and inbound selectors ready.” If you do not, use the [AWS runbook](AWS-RUNBOOK.md); do not start a new deployment over the same state.

## 4. Test the SIP-header recipe

```sh
python3 examples/vapi-amazon-connect/tests/live.py run \
  --state examples/vapi-amazon-connect/.local/live/state.json \
  --mode sip-headers
```

The test supplies a session value before the conversation starts. A synthetic caller tells Vapi that a doorbell is offline and asks for a person. Vapi transfers to Bridgefu, which starts Connect with the selected values as attributes. A test browser agent receives the call.

**You should see:** `sip-headers: PASS`. The test checks exact attribute values, audio in both directions, and disconnection—not just whether the transfer request returned success.

## 5. Test the correlation recipe

```sh
python3 examples/vapi-amazon-connect/tests/live.py run \
  --state examples/vapi-amazon-connect/.local/live/state.json \
  --mode correlation-id
```

This time only a token travels in SIP. Connect's Lambda retrieves the context before routing to the agent. The test also checks missing and expired tokens.

**You should see:** `correlation-id: PASS`. Run the recipes sequentially; they share the disposable gateway.

The two `*-report.json` files in `.local/live` contain assertion results suitable for review. The other files contain private IDs, credentials, and call evidence. See [exact test details and recorded results](tests/E2E.md) before sharing anything.

## 6. Remove the test resources

Run this even if a test fails:

```sh
python3 examples/vapi-amazon-connect/tests/live.py cleanup \
  --state examples/vapi-amazon-connect/.local/live/state.json
```

**You should see:** “Disposable resources removed.” Keep the state file until that succeeds.

## Use your own fields and infrastructure

Once the test works, follow the [existing-environment walkthrough](EXISTING-ENVIRONMENT.md). It explains each service separately and lets you keep your own gateway, Connect flow, and test agent.

Each recipe's `settings.example.json` is the field contract. Copy it privately and choose your own variable sources, SIP headers, and Connect attribute names. The supplied session, call ID, intent, and summary are examples, not fixed Bridgefu fields. In correlation mode, the token header, attribute name, and expiry are configurable too.
