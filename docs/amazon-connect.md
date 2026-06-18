# Amazon Connect setup for bridgefu

What the Connect side needs so a Vapi transfer lands on an agent with the screen
pop populated. bridgefu calls **`StartWebRTCContact`** with the mapped attributes;
everything below is about making your instance + contact flow consume them.

## 1. The two IDs bridgefu needs

Put these in `bridgefu.yaml` (`aws.instance_id`, `aws.contact_flow_id`):

- **Instance ID** — Amazon Connect console → your instance → *Overview*. It's the
  UUID at the end of the instance ARN
  (`arn:aws:connect:<region>:<acct>:instance/<INSTANCE_ID>`).
- **Contact flow ID** — open the flow in the flow designer; it's in the URL
  (`.../contact-flows/<FLOW_ID>`) or the *Show additional flow information* panel.
  This flow must be the one that routes to an agent queue and reads the attributes.

`aws.region` must be the region the instance lives in. AWS credentials are **not**
configured here — at runtime they come from the EC2 instance role (Terraform grants
`connect:StartWebRTCContact` + `connect:StopContact`).

## 2. Attribute mapping (the screen-pop contract)

bridgefu reads the inbound INVITE's custom (`X-…`) headers and translates them to
Connect **contact attributes** per the `mapping` block in `bridgefu.yaml`:

```yaml
mapping:
  unmapped: drop                 # drop | pass_prefixed
  passthrough_prefix: "X-"
  rename:                        # inbound SIP header  ->  Connect attribute key
    X-Vapi-Customer-Id: HostedWidget-customerId
    X-Vapi-Call-Id:     HostedWidget-vapiCallId
    X-Account-Tier:     HostedWidget-accountTier
```

- Keys are **sanitized** to Connect's allowed set (`[A-Za-z0-9_-]`); other chars are
  dropped. Total attributes are capped at **32 KB** (oversized ones are dropped).
- `unmapped: drop` ignores any header not in `rename`. `pass_prefixed` instead passes
  every header matching `passthrough_prefix` through (sanitized), in addition to the
  renames.
- The `HostedWidget-` prefix is deliberate: the Connect hosted widget surfaces
  attributes to the flow as `$.Attributes.HostedWidget-<name>`, so reusing that
  prefix lets the **same screen pop** work for both the widget and bridgefu. If your
  flow reads different attribute keys, change the right-hand side of `rename` to match.

These attribute keys are the contract — the names you map **must** equal the names
your contact flow reads (next section).

## 3. Contact flow: read the attributes

In the flow designer, the flow that handles the contact should:

1. **Set working queue** → an agent queue with a logged-in agent (CCP/softphone).
2. **(Optional) Check contact attributes** / **Set contact attributes** blocks that
   reference the mapped keys. To display values in the agent workspace, the flow
   reads them as **`$.Attributes.HostedWidget-customerId`**, etc. — matching the
   `rename` targets above.
3. Route to the queue / transfer to agent.

The agent's screen pop (CCP, or a custom CCP/Agent Workspace view) shows the contact
attributes; whatever your widget/screen-pop config renders from
`HostedWidget-*` will be populated from the transferred `X-` headers.

## 4. Verifying the header → attribute path (PRD FR6)

The open risk is whether the carrier preserves the `X-` headers across the
SIP REFER/transfer. bridgefu logs the full inbound header set and the resulting
attribute map at `debug`. Set in `bridgefu.yaml`:

```yaml
observability:
  log_level: "info,rvoip_amazon_connect=debug"
```

On a test call, the logs should show: `INVITE received` → the inbound headers
(including your `X-` set) → `attributes=N` with `N>0` → `StartWebRTCContact` returning
a real `contact_id`. If `attributes=0`, the carrier stripped the headers — that's the
thing this POC exists to confirm, and you'll see it here before blaming Connect.

## 5. Common gotchas

| Symptom | Likely cause |
|---|---|
| `AccessDeniedException` on StartWebRTCContact | Instance role missing the action (Terraform grants it), or `region`/`instance_id` mismatch. |
| Contact starts but screen pop empty | Attribute key mismatch — `rename` targets ≠ what the flow reads (`$.Attributes.HostedWidget-…`). |
| `ResourceNotFoundException` | Wrong `contact_flow_id`, or the flow isn't published. |
| `attributes=0` in logs | Carrier didn't preserve the `X-` headers across the transfer (FR6). |
| Agent never rings | Flow doesn't route to a queue with an available agent, or agent not in Available state. |
