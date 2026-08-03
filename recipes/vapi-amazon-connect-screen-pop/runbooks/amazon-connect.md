# Amazon Connect and Agent Workspace

## Impact

`StartWebRTCContact` fails, no agent receives the call, the call arrives without
the guide, or the screen pop is blank while audio works.

## Safe checks

1. Confirm the supplied instance and target-flow ARNs are unchanged and the
   recipe wrapper/guide flows are published.
2. Verify the recipe lookup Lambda is associated with the instance and its
   invoke permission has the exact Connect source account/instance.
3. Inspect Bridgefu's bounded Amazon operation result and cleanup metrics.
4. Trace the wrapper flow: Lambda lookup, contact-attribute copy, DefaultAgentUI
   hook, then transfer to the customer target flow.
5. Check the agent's routing/queue availability and Agent Workspace/security
   profile permission. The stack deliberately does not edit security profiles.
6. Test missing context. The contact must continue with safe generic values.

## Remediation

- Restore exact `StartWebRTCContact` permission for the recipe entry flow and
  StopContact authority for contacts in the supplied instance.
- Republish only the recipe-owned wrapper/guide if they drift. Never update the
  customer target flow as part of recipe repair.
- Reassociate the lookup Lambda through the stack; avoid manual duplicate
  associations.
- Grant the required Agent Workspace/view permission through the customer's
  normal access-review process.
- If the guide fails but audio routes, preserve the call and repair the view
  separately; do not disconnect callers solely because screen context is
  unavailable.

## Verify

Use the Connect flow test plus a real controlled contact. Confirm the exact
correlation attribute, lookup result, visible bounded fields, target-flow
transfer, queue/agent connection, both audio directions, and fail-open missing
context. Capture contact IDs only in restricted operational evidence.
