# Nonproduction IP-only live qualification

## Purpose and current boundary

Use this runbook to:

1. recover and remove one recent, bootstrap-only execution whose local ledger
   was lost;
2. retain the controller's zero-state proof; and
3. start and qualify a fresh Starter execution in `us-west-2` using its public
   IP directly with SIP/RTP.

This runbook does **not** authorize HA, DNS, certificates, SIPS/SRTP,
production deployment, customer traffic, or reuse of the recovered execution
ID. It was derived from a read-only audit of
`scripts/aws-recipe-live-test.py`. It is not evidence that the current AWS
session, permissions, quotas, provider responses, deployment, or teardown have
passed live. Reauthenticate and let the controller fail closed on any missing
read before requesting an access change.

The synthetic retired-execution example is `bft-20990101a`. It represents an
execution for which no application change set was executed and only the
bootstrap remains. Replace it only when recovering an execution that meets
every recovery condition below. Never put a real account, stack, or resource
identifier into this runbook.

## Choose exactly one entry path

- **Path A — eligible lost-ledger recovery.** Use this only for an account that
  contains an eligible lost-ledger, bootstrap-only execution such as the
  synthetic `bft-20990101a` example. Complete Phases 1–5, then initialize and qualify a different ID
  in Phases 6–7.
- **Path B — genuinely fresh user/account.** Use this for a user and account
  with no lost-ledger bootstrap to recover. Skip Phases 1–5 completely and
  begin at the Path B authentication block in Phase 6. This path does not set,
  read, compare, or otherwise depend on `OLD_EXECUTION`, and it does not depend
  on a Phase 5 teardown proof from another account.

In short, Path A is the eligible lost-ledger recovery path. Path B is the
fresh-user/fresh-account path and skips lost-ledger recovery.

Never combine account IDs, profiles, ledgers, reviews, or proof files between
the two paths.

## Authority and state rules

- Use one federated, non-root IAM principal for recovery review, recovery
  execute, inventory, and destroy. A refreshed session is allowed, but it must
  resolve to the same durable IAM role. The principal that originally created
  the bootstrap may be different.
- Exactly one operator on one host owns recovery. The local lock is not a
  distributed cross-host lock.
- State defaults to
  `${XDG_STATE_HOME:-$HOME/.local/state}/bridgefu/aws-live/<execution-id>/`.
  `BRIDGEFU_AWS_LIVE_STATE_DIR` may replace the live-state root only when it is
  an absolute private path ending in `bridgefu/aws-live` and outside the
  repository and every `target` directory. No component may resolve through a
  symlink. Its nearest existing ancestor must be a real directory owned by the
  current operating-system user; if the override already exists, it must
  itself be a real, non-symlink directory owned by that user with mode `0700`.
- Do not copy a ledger, recovery review, destroy intent, or browser credential
  to another host. Do not delete the state directory to bypass a gate. Remote
  recovery capsules are write-only evidence and are not consumed.
- The recovered ID is teardown-only and permanently retired. Only `inventory`,
  `destroy`, and, after a recorded destroy intent, `destroy-finalize` are
  accepted for it.

Resolve the state root for later evidence checks:

```bash
STATE_ROOT="${BRIDGEFU_AWS_LIVE_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/bridgefu/aws-live}"
```

## Path A recovery eligibility

The lost-ledger path is intentionally narrow. Stop if any condition is false:

- the full immutable bootstrap stack ARN is known;
- the bootstrap was created less than 89 days ago and is currently
  `CREATE_COMPLETE` or `UPDATE_COMPLETE`;
- its deployed Original template still has the controller's exact parameter,
  logical-resource, physical-ID, output, IAM attachment, tag, and trust
  contracts;
- no application or qualification stack exists or appears anywhere in retained
  CloudFormation history, including `DELETE_COMPLETE` history;
- the qualification EIP is the exact unassociated bootstrap EIP;
- no active bootstrap change set, disposable Connect instance or log group,
  execution secret, CodeBuild project, demo-site resource, Route 53 zone, or
  CloudFront resource exists;
- any optional artifact bucket has exact ownership/configuration and no active
  multipart upload; and
- any optional ECR repository has its exact account, ARN, ownership,
  immutability, scan-on-push, encryption, and image inventory.

A deployed bootstrap template hash may differ from the current checkout. That
is diagnostic, not automatic rejection: recovery binds the exact deployed
Original template contract and grants teardown authority only. Any application
or qualification history makes this recovery path ineligible even if those
stacks were later deleted.

## Phase 1 — Path A: authenticate and identify the exact target

Run from the repository root. Set the profile explicitly before login; do not
allow any command to fall back to the CLI's default profile. The literal
placeholder below must be replaced with the approved federated profile. No
operator-local profile name belongs in this public runbook. If the profile
uses IAM Identity Center, replace only the login line with
`aws sso login --profile "$AWS_PROFILE"`.

The same exported AWS_PROFILE must select login, STS identity checks, and all
controller commands throughout the chosen path. A separately named admin
profile is allowed only for the bounded manual handoff described in Phase 7.

```bash
export AWS_PROFILE='<current-account-federated-profile>'

aws login --profile "$AWS_PROFILE"
aws sts get-caller-identity --profile "$AWS_PROFILE"

export OLD_EXECUTION='bft-20990101a'
export AWS_ACCOUNT_ID='111122223333'
export AWS_REGION='us-west-2'
export BOOTSTRAP_STACK_ID='arn:aws:cloudformation:us-west-2:111122223333:stack/bridgefu-bft-20990101a-bootstrap/00000000-0000-0000-0000-000000000000'
export EXPECT_DEMO_SITE='false'
```

Replace the example account and UUID. `BOOTSTRAP_STACK_ID` must be the full
stack ARN, never the stack name. `EXPECT_DEMO_SITE` must exactly match the
bootstrap's deployed `EnableDemoSite` parameter; do not guess. The standard
IP-only parameter files use `false`.

## Phase 2 — read-only lost-ledger review

This command performs AWS reads and writes only an immutable local review. It
does not create, update, or delete AWS resources.

```bash
REVIEW_RESULT="$(
  AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \
    --execution-id "$OLD_EXECUTION" \
    recover-lost-ledger-review \
    --account-id "$AWS_ACCOUNT_ID" \
    --region "$AWS_REGION" \
    --bootstrap-stack-id "$BOOTSTRAP_STACK_ID" \
    --expect-demo-site "$EXPECT_DEMO_SITE" \
    --confirm-account "$AWS_ACCOUNT_ID" \
    --confirm-region "$AWS_REGION" \
    --confirm-execution "$OLD_EXECUTION"
)"
printf '%s\n' "$REVIEW_RESULT"

export REVIEW_PATH="$(
  printf '%s' "$REVIEW_RESULT" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["review_path"])'
)"
export REVIEW_SHA256="$(
  printf '%s' "$REVIEW_RESULT" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["review_sha256"])'
)"
```

The review expires 15 minutes after creation. A source edit changes the
controller digest and invalidates the review. AWS state must also remain stable
through execute.

## Phase 3 — independent file and digest review

Do not edit the review. An independent reviewer must inspect the complete JSON,
confirm the recovery eligibility above, and recompute the SHA-256 over the
exact file bytes:

```bash
python3 -m json.tool "$REVIEW_PATH"

CALCULATED_REVIEW_SHA256="$(
  python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' \
    "$REVIEW_PATH"
)"
test "$CALCULATED_REVIEW_SHA256" = "$REVIEW_SHA256"
```

Specifically confirm the account, partition, region, recovery principal,
bootstrap StackId/status/creation time, deployed template hash, parameters,
outputs, physical resources, EIP, IAM bindings, optional S3/ECR inventories,
absence findings, and empty application/qualification history. A failed digest
comparison or an expired review requires a new review.

## Phase 4 — read-only execute and local adoption

Execute repeats the entire AWS read inventory and requires the teardown
authority to match the review. Its only mutation is installation of the local
teardown-only ledger and permanent retired-ID marker.

```bash
AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \
  --execution-id "$OLD_EXECUTION" \
  recover-lost-ledger-execute \
  --account-id "$AWS_ACCOUNT_ID" \
  --region "$AWS_REGION" \
  --review-sha256 "$REVIEW_SHA256" \
  --confirm "$OLD_EXECUTION" \
  --confirm-account "$AWS_ACCOUNT_ID" \
  --confirm-region "$AWS_REGION"

AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \
  --execution-id "$OLD_EXECUTION" inventory
```

The inventory is expected to show the reviewed bootstrap scope at this point;
it is not expected to be empty before destroy.

## Phase 5 — destructive teardown and retained zero proof

This is the first command in the recovery sequence authorized to mutate AWS.
Immediately before its first mutation it repeats recovery validation and writes
an immutable `recovered-destroy-intent.json`.

```bash
AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \
  --execution-id "$OLD_EXECUTION" \
  destroy --confirm "$OLD_EXECUTION"
```

The controller deletes an adopted ECR repository and versioned artifact bucket
when present, then deletes the exact bootstrap StackId ARN. The proof contains
three identical observations in the normalized sense: it requires three stable
identical inventory projections after excluding `checked_at` before comparing
them. The raw observations are not byte-identical because their `checked_at`
timestamps differ. The first and third timestamps must span at least 60
seconds. The proof loop is bounded at 15 minutes.

Inspect the retained proof and a fresh inventory:

```bash
python3 -m json.tool "$STATE_ROOT/$OLD_EXECUTION/teardown-zero-proof.json"
python3 -m json.tool "$STATE_ROOT/$OLD_EXECUTION/teardown-inventory.json"
AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \
  --execution-id "$OLD_EXECUTION" inventory
```

Success requires ledger status `destroyed`, exactly three empty observations,
identical projections except for `checked_at`, at least 60 seconds between the
first and third timestamps, and a final inventory exactly equal to the third
observation.

If destroy is interrupted, rerun the same `destroy --confirm` command. If an
authorized administrator completes exact cleanup externally, use the following
read-only proof command only after `destroy` has already written its durable
intent:

```bash
AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \
  --execution-id "$OLD_EXECUTION" \
  destroy-finalize --confirm "$OLD_EXECUTION"
```

`destroy-finalize` does not delete anything and is rejected before a recovered
destroy intent exists. Do not manually delete the bootstrap before controller
recovery. If another actor deletes it after the intent but leaves an adopted
bucket or repository, zero proof fails closed; complete only the exact
ledger-bound cleanup and then rerun proof.

## Phase 6 — initialize a fresh IP-only Starter execution

Choose the subsection for the entry path selected above, then run the common
`init` command. In both paths, choose a globally fresh execution ID that has
never appeared in local state or CloudFormation history.

### Path A handoff

Path A must not continue until Phase 5 has retained zero proof. Never use
`$OLD_EXECUTION` again.

```bash
export NEW_EXECUTION='bft-yyyymmddb'
test "$NEW_EXECUTION" != "$OLD_EXECUTION"
aws sts get-caller-identity --profile "$AWS_PROFILE"
```

### Path B authentication

Path B skips Phases 1–5 and does not use their variables or files. Set its own
portable profile placeholder, authenticate it, verify its caller and account,
and choose the fresh ID. No profile name from another operator or account is a
default for this path. If this profile uses IAM Identity Center, replace only
the login line with `aws sso login --profile "$AWS_PROFILE"`.

```bash
export AWS_PROFILE='<fresh-account-federated-profile>'
aws login --profile "$AWS_PROFILE"
aws sts get-caller-identity --profile "$AWS_PROFILE"

export NEW_EXECUTION='bft-yyyymmddb'
```

### Common IP-only initialization

Provide the Vapi keys through the approved secret-injection mechanism. Do not
put them in this file, shell history, logs, or evidence. `VAPI_PRIVATE_KEY` is
required, and a disposable-Connect run also requires the browser-safe
`VAPI_PUBLIC_KEY`.

```bash
AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \
  --execution-id "$NEW_EXECUTION" \
  init \
  --region us-west-2 \
  --max-usd 200 \
  --planned-hours 8 \
  --connect-minutes 30 \
  --runtime-profile starter \
  --create-connect-demo
```

This qualification uses no DNS. For the IP-only path, omit
`--hosted-zone-id`, `--delegated-zone-name`,
`--sip-hostname`, `--secure-sips-proof`, and `--enable-demo-site`. The
controller rejects DNS parameters for this SIP/RTP mode. Existing-Connect mode
selects the secure DNS path in this controller and is therefore not the
IP-only disposable qualification described here.

`--max-usd` is a conservative planning-estimate ceiling, not an AWS Budget or
real-time spend cap. The qualification deadline blocks new paid phases after
expiry but does not delete resources. Explicit teardown remains mandatory.

## Phase 7 — fresh guarded qualification order

After `init` succeeds, use this order. Every review file lives under
`$STATE_ROOT/$NEW_EXECUTION/`; do not use the former repository build-output
live-state path.

```bash
AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \
  --execution-id "$NEW_EXECUTION" bootstrap

AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \
  --execution-id "$NEW_EXECUTION" publish

AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \
  --execution-id "$NEW_EXECUTION" \
  bootstrap-refresh --confirm "$NEW_EXECUTION"
```

Independently review
`bootstrap-refresh-change-set-review.json`. It must bind `stack_id` to the full
exact immutable bootstrap StackId ARN for the pre-existing stack. A legacy review with no
`stack_id`, or a review whose `stack_id` differs from the ledger, is invalid and
must be retired and regenerated. If the review reports `NO_CHANGES`, no
administrator execution is needed. Otherwise extract both immutable IDs from
the reviewed file:

```bash
export BOOTSTRAP_REFRESH_REVIEW="$STATE_ROOT/$NEW_EXECUTION/bootstrap-refresh-change-set-review.json"
python3 -m json.tool "$BOOTSTRAP_REFRESH_REVIEW"

export FRESH_BOOTSTRAP_STACK_ID="$(
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["stack_id"])' \
    "$BOOTSTRAP_REFRESH_REVIEW"
)"
export BOOTSTRAP_REFRESH_CHANGE_SET_ID="$(
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["change_set_id"])' \
    "$BOOTSTRAP_REFRESH_REVIEW"
)"
```

An authorized administrator must execute only the exact reviewed ChangeSetId ARN
against that exact StackId ARN, then wait by the same StackId. Do not automate
the independent approval. Keep the admin profile explicit too. Normally it is
the already verified `$AWS_PROFILE`; if policy requires a separate admin
profile, set that approved profile only in `AWS_ADMIN_PROFILE` and leave
`AWS_PROFILE` unchanged for the controller verifier:

```bash
export AWS_ADMIN_PROFILE="$AWS_PROFILE"
aws login --profile "$AWS_ADMIN_PROFILE"
aws sts get-caller-identity --profile "$AWS_ADMIN_PROFILE"

aws cloudformation execute-change-set \
  --profile "$AWS_ADMIN_PROFILE" \
  --region us-west-2 \
  --stack-name "$FRESH_BOOTSTRAP_STACK_ID" \
  --change-set-name "$BOOTSTRAP_REFRESH_CHANGE_SET_ID"

aws cloudformation wait stack-update-complete \
  --profile "$AWS_ADMIN_PROFILE" \
  --region us-west-2 \
  --stack-name "$FRESH_BOOTSTRAP_STACK_ID"
```

Then verify the original controller profile again and continue. If a separate
admin profile executed the change set, do not run the controller under it;
verification must resolve to the durable principal recorded at `init`.

```bash
aws sts get-caller-identity --profile "$AWS_PROFILE"

AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \
  --execution-id "$NEW_EXECUTION" \
  bootstrap-refresh-verify --confirm "$NEW_EXECUTION"

AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \
  --execution-id "$NEW_EXECUTION" change-set
```

Independently review `change-set-review.json` and, for this disposable-Connect
run, `qualification-change-set-review.json`. Only then execute and qualify:

```bash
AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \
  --execution-id "$NEW_EXECUTION" \
  execute --confirm "$NEW_EXECUTION"

AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \
  --execution-id "$NEW_EXECUTION" verify

AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \
  --execution-id "$NEW_EXECUTION" \
  run-headless --suite smoke --confirm "$NEW_EXECUTION"

AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \
  --execution-id "$NEW_EXECUTION" \
  run-headless --suite full --confirm "$NEW_EXECUTION"

AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \
  --execution-id "$NEW_EXECUTION" \
  lifecycle-test --confirm "$NEW_EXECUTION"

AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \
  --execution-id "$NEW_EXECUTION" verify

AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \
  --execution-id "$NEW_EXECUTION" \
  destroy --confirm "$NEW_EXECUTION"
```

The smoke run is an early IP-only proof. The full run, lifecycle rollback test,
second verification, and retained teardown zero proof are required before this
configuration can be used as evidence for a later production decision. Repeat
a second nonproduction cycle with another fresh ID rather than reusing this
one.

## AWS permissions

These are controller requirements, not proof that the active role has them.
Test them with the current federated session. An `AccessDenied` should become a
request for that exact action and scope; do not request an unrelated workload
policy.

The lists below cover the recovery, `init`, recovered `destroy`, and zero-proof
paths audited for this runbook. Fresh bootstrap and application qualification
use additional create/update/read actions encoded in
`cloudformation/test-deployment-role.yaml` and the generated temporary roles;
the controller validates those policies before application review. Do not
treat the lists below as a complete application-deployment policy.

### Recovery review and execute reads

Both commands run the same complete inventory:

```text
sts:GetCallerIdentity
ec2:DescribeRegions
ec2:DescribeAddresses
cloudformation:DescribeStacks
cloudformation:GetTemplate
cloudformation:ListStackResources
cloudformation:ListChangeSets
cloudformation:ListStacks
tag:GetResources
iam:GetRole
iam:ListRoles
iam:ListPolicies
iam:ListAttachedRolePolicies
iam:ListRolePolicies
iam:ListInstanceProfilesForRole
iam:ListRoleTags
iam:ListEntitiesForPolicy
s3:ListBucket
s3:GetBucketTagging
s3:GetBucketLocation
s3:GetBucketVersioning
s3:GetBucketPublicAccessBlock
s3:GetEncryptionConfiguration
s3:ListBucketVersions
s3:ListBucketMultipartUploads
ecr:DescribeRepositories
ecr:ListTagsForResource
ecr:DescribeImages
connect:ListInstances
logs:DescribeLogGroups
secretsmanager:ListSecrets
codebuild:BatchGetProjects
route53:ListHostedZones
cloudfront:ListDistributions
cloudfront:ListCachePolicies
cloudfront:ListResponseHeadersPolicies
cloudfront:ListOriginAccessControls
```

Detailed bucket and repository reads are conditional on those resources
existing, but their exact existence probes are unconditional. AWS documents
`sts:GetCallerIdentity` as callable without an explicit allow; it remains part
of the controller's observed API set.

### Fresh IP-only init reads

`init` changes only local state, but its account-wide zero-state and exact-name
checks require:

```text
sts:GetCallerIdentity
iam:GetRole
tag:GetResources
cloudformation:ListStacks
cloudformation:DescribeStacks
s3:ListAllMyBuckets
s3:ListBucket
ecr:DescribeRepositories
iam:ListRoles
iam:ListPolicies
logs:DescribeLogGroups
```

`iam:GetRole` is used when the caller is an assumed-role session. Existing
Connect adds `connect:DescribeInstance` and `connect:DescribeContactFlow`; DNS
mode adds `route53:GetHostedZone`. Those conditional modes are not used by the
IP-only command above.

The account-wide gates deliberately need `Resource: "*"` for discovery actions
such as `tag:GetResources`, `cloudformation:ListStacks`,
`s3:ListAllMyBuckets`, `iam:ListRoles`, `iam:ListPolicies`, and
`logs:DescribeLogGroups`. Missing visibility fails closed even when create
permissions exist.

### Recovered destroy and zero proof

Before its first mutation, recovered destroy repeats the complete recovery
read set. Its direct mutations are:

```text
ecr:DeleteRepository
s3:DeleteObject
s3:DeleteObjectVersion
s3:DeleteBucket
cloudformation:DeleteStack
```

The recovered bootstrap stack has no CloudFormation service-role ARN, so its
resource deletion runs with authority derived from the active caller. That
caller must also be able to remove the four exact bootstrap roles, seven exact
managed policies, and exact qualification EIP:

```text
iam:DetachRolePolicy
iam:DeleteRolePolicy
iam:DeleteRole
iam:GetPolicy
iam:ListPolicyVersions
iam:DeletePolicyVersion
iam:DeletePolicy
ec2:ReleaseAddress
```

Zero proof repeats identity and inventory reads. If the tagging index still
contains a possible tombstone, it may additionally call:

```text
connect:DescribeInstance
ec2:DescribeInstances
ec2:DescribeNatGateways
ec2:DescribeVpcEndpoints
ec2:DescribeSubnets
ec2:DescribeVolumes
codebuild:ListBuildsForProject
codebuild:BatchGetBuilds
secretsmanager:DescribeSecret
```

Scope stack, role, policy, S3, ECR, CodeBuild, Connect, Route 53, and EIP
actions to exact or execution-narrowed ARNs where AWS supports it. Discovery
actions normally requiring `Resource: "*"` include `tag:GetResources`,
`cloudformation:ListStacks`, `s3:ListAllMyBuckets`, `iam:ListRoles`,
`iam:ListPolicies`, `logs:DescribeLogGroups`, `secretsmanager:ListSecrets`,
`connect:ListInstances`, `route53:ListHostedZones`, `cloudfront:List*`, and
`ec2:Describe*`.

Do not claim that no administrator action is required until the active role has
successfully completed the read-only review and its caller-side bootstrap
deletion authority has been verified. A static policy or historical session
check is not current authorization.

## Stop conditions

Stop without improvising when:

- AWS authentication is expired;
- account, region, StackId, confirmation, or durable principal differs;
- the review expires or its digest changes;
- any application or qualification history is found;
- AWS inventory differs between review and execute or before destroy;
- the controller reports an unmodeled resource, attachment, tag, association,
  multipart upload, or active build;
- a delete target is not exact and ledger-owned;
- zero proof reports leftovers or an incomplete schema; or
- the qualification deadline expires.

Do not broaden permissions, delete resources by name alone, manually edit the
ledger, skip the independent reviews, or proceed to production. Preserve the
bounded controller evidence and request help with the exact failed check.
