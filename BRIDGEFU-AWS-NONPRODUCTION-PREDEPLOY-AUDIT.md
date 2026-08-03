# Bridgefu AWS nonproduction pre-deployment audit

This is the repository-safe summary. Exact account, principal, resource, and
proof identifiers remain only in the operator's private durable state.

## Decision

**CURRENT GO** only for the next guarded publication transition. Both required
Vapi credentials are loaded and validated in the operator process. Their values
were never written to Git, the controller ledger, reports, logs, or command
arguments.

The current non-root IAM Identity Center session passed the controller's fresh
identity, absence, permission, collision, and regional-capacity preflight. The
exact foundation bootstrap reached `CREATE_COMPLETE`, and the controller
verified its template, parameters, tags, outputs, roles, and complete resource
set against private durable state.

Publication generation 3 is stale because qualification-source changes were
made after it was frozen. It has no published release objects or release ID.
No bootstrap-refresh review, application review, application stack, or
qualification stack exists for this execution.

The next AWS mutation is exactly one guarded `publish --refresh-candidate`,
which must create generation 4 from the final reviewed source. Do not issue a
second refresh unless a later source change makes that separately necessary.
After publication succeeds, the next permitted controller action is
`bootstrap-refresh` in review-only mode. **NO-GO** remains in force for
executing that review or creating or executing application and qualification
change sets until the exact generated review has been independently audited.

**NO-GO** for production until the IP-only nonproduction deployment completes
smoke, full, lifecycle rollback, final verification, teardown, and stable zero
proof. The runbook then requires a second clean nonproduction cycle with a new
execution ID before production is considered. Both cycles must use the same
immutable release/candidate and relevant source/controller revision, with no
rebuild or release refresh between them.

## Qualified scope

- AWS account: operator-selected nonproduction account
- Region: `us-west-2`
- Authentication: operator-selected federated non-root SSO role
- Runtime profile: Starter, single server
- Amazon Connect mode: disposable qualification instance
- SIP/RTP endpoint: public IP only
- DNS, TLS hostname, demo site, and high availability: disabled
- Production account and unrelated AWS resources: out of scope

No current application or qualification stack has been created or executed.

## Access conclusion

The active federated non-root session successfully completed the current
controller preflight and the exact foundation bootstrap. There is no
demonstrated AWS-permission or capacity blocker and no administrator request is
needed before the guarded publication and bootstrap-refresh review stages.

Independent review of the bootstrap-refresh and later application change sets
remains an operational approval gate, not a known access failure. If a later
command returns `AccessDenied`, stop and request only the exact denied action
and scope; do not request a broad workload policy in advance.

## Retired execution cleanup

The audited historical execution is permanently retired and teardown-only.
Its lost repository-local ledger was recovered through an immutable,
read-only review, then adopted locally only after an independent byte-level
hash and authority check. Its exact execution ID remains in private evidence.

Reviewed authority before deletion:

- exact bootstrap StackId, retained privately
- 4 IAM roles and 7 managed policies
- exact unassociated EIP allocation and address, retained privately
- exact ECR repository, one digest with two tags
- exact versioned S3 bucket, 268 versions and no active multipart uploads
- no application or qualification stack history or change sets
- no Connect instance, CodeBuild project, secrets, Route 53, CloudFront, demo
  site, or Vapi-created resource

Deletion result:

- ECR repository: absent
- artifact bucket and all versions: absent
- bootstrap stack: `DELETE_COMPLETE`
- bootstrap IAM roles and managed policies: absent
- EIP allocation: absent
- final controller inventory: every tracked resource collection empty

## Retained teardown proof

Durable state is held in a controller-enforced private location outside the
repository and every build target. Its exact path is private operator data.

The retained proof files are mode `0600`, owned by the local operator, regular
non-symlink files:

- teardown zero proof, with its exact digest retained privately
- teardown inventory, with its exact digest retained privately
- final controller ledger, with its exact digest retained privately

Proof properties:

- exactly 3 observations
- all normalized projections identical after excluding `checked_at`
- first-to-third observation span: 98.564672 seconds (minimum 60)
- every tracked collection empty in every observation
- final retained inventory exactly equals the third observation
- a later fresh inventory was also empty

## Defects found and closed during live read-only/destroy testing

The audit deliberately remained fail-closed and exposed three AWS response
contract defects before a fresh deployment:

1. `AWS::EC2::EIP` CloudFormation physical identity was modeled as its
   allocation ID. CloudFormation reports the public IP as the physical/`Ref`
   identity and exposes the allocation ID separately. Recovery now binds both
   exact values independently.
2. Amazon S3's April 2026 security rollout adds
   `BlockedEncryptionTypes: SSE-C` to bucket encryption state. Recovery and
   future bucket creation now require the exact stronger rule. All three recipe
   CloudFormation S3 buckets explicitly pin the same setting.
3. Successful S3 `DeleteObjects` quiet mode returns no response body. The
   controller now treats that as provisional success only and requires a fresh,
   empty version listing before proceeding. Malformed, verbose, unknown, or
   per-object error responses still fail closed.
4. Regional CloudFormation handlers for managed Amazon Connect resources can
   invoke update operations during create, rollback, or stabilization. The
   bounded deployment-role policy now includes the required update-handler
   actions, and the IAM catalog/contract checks cover the corrected surface.

The interrupted deletion was recovered idempotently from its durable intent.
It did not broaden authority or retarget resources by mutable names.

## Validation snapshot

The current release path now builds the qualification package natively on the
ARM host while cross-compiling the two required binaries for x86-64 Linux. The
package boundary excludes the disallowed cryptographic dependency, and the
builder-image, source-inventory, target-architecture, ELF, and maximum-glibc
release guards pass. The packaged runner independently repeats the architecture
and compatibility checks before use.

Focused qualification-builder tests, the release-image policy check, locked
package metadata/checks, Python compilation, public-document identifier checks,
neutral-naming checks, and whitespace checks pass. Historical full-suite and
CloudFormation lint results remain useful evidence, but a final full regression
pass against the committed generation-4 source remains mandatory before the
publication refresh.

These local results and the successful foundation bootstrap do not establish an
application deployment or live Vapi/Amazon Connect qualification result.

## Next permitted steps

1. Finish the current full local regression/audit pass without changing the
   reviewed source. Keep both Vapi credential values process-only.
2. Run exactly one `publish --refresh-candidate` transition to generation 4.
   If it fails without a source change, resume with ordinary `publish`; do not
   refresh again merely to retry the same candidate.
3. Verify that publication completes the immutable release object set and
   release record before taking any review action.
4. Run `bootstrap-refresh` in review-only mode. Independently audit its exact
   immutable review, template, parameters, tags, role scope, and replacement
   behavior. Do not execute it in this step.
5. After separate authorization and verification of the foundation refresh,
   create the application and disposable-qualification change sets without
   executing either one.
6. Recursively audit every root and nested change set, IAM/resource scope,
   replacement behavior, cost bounds, and immutable identities. Issue a second
   GO/NO-GO report.
7. Only after that approval, execute, verify, run smoke then full qualification,
   run the lifecycle rollback test, verify again, and destroy.
8. Retain a new three-observation zero proof and repeat one more clean
   nonproduction cycle before any production decision. Use a new execution ID
   but the exact same immutable release/candidate and relevant source/controller
   revision; do not rebuild or refresh the release between the two cycles.

Canonical operator procedure:
`recipes/vapi-amazon-connect-screen-pop/runbooks/nonproduction-live-qualification.md`.
