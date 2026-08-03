# AWS Administrator Escalation Template

Do not send an administrator request preemptively. First authenticate with the
approved federated, non-root profile and let the guarded controller run its
read-only identity, absence, permission, and current regional-capacity checks.

An expired SSO session requires normal operator reauthentication; it is not by
itself an access blocker.

If preflight returns `AccessDenied` or an insufficient service-quota result,
create a private ticket containing only:

- `<ACCOUNT_LABEL>` and `<REGION>`; keep the numeric account ID in the private
  ticket system, not Git;
- the exact denied AWS action and narrowly scoped resource ARN, redacted from
  repository artifacts;
- the current quota, current usage, requested quota, and required headroom;
- the federated permission-set owner who should make the change; and
- the controller's redacted failure message and timestamp.

Request only the demonstrated missing action or quota. Do not request root,
long-lived IAM-user credentials, broad administrator policies, account
creation, or unrelated resource changes.

Cost planning values are estimates, not real-time spending caps, budgets,
automatic shutdowns, or teardown mechanisms. Configure an AWS Budget
separately when the owner approves one.
