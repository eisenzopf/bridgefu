from __future__ import annotations

import contextlib
import copy
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "scripts" / "aws-recipe-live-test.py"
SPEC = importlib.util.spec_from_file_location("aws_recipe_lost_ledger", SCRIPT)
assert SPEC and SPEC.loader
LIVE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LIVE
SPEC.loader.exec_module(LIVE)


class LostLedgerRecoveryTests(unittest.TestCase):
    def state_environment(self, parent: Path) -> dict[str, str]:
        return {
            LIVE.LIVE_STATE_OVERRIDE_ENV: os.fspath(
                parent.resolve() / "bridgefu" / "aws-live"
            )
        }

    def sample_inventory(
        self, *, caller_arn: str = "arn:aws:iam::111122223333:role/RecoveryAdmin"
    ) -> dict:
        execution_id = "bft-safe1"
        account = "111122223333"
        region = "us-west-2"
        base = f"bridgefu-{execution_id}"
        stack_id = (
            f"arn:aws:cloudformation:{region}:{account}:stack/{base}-bootstrap/"
            "12345678-1234-1234-1234-123456789abc"
        )
        return {
            "schema_version": 1,
            "complete": True,
            "authority_mode": "teardown_only",
            "execution_id": execution_id,
            "identity": {
                "account_id": account,
                "partition": "aws",
                "region": region,
                "caller_arn": caller_arn,
                "durable_principal_arn": (
                    "arn:aws:iam::111122223333:role/RecoveryAdmin"
                ),
            },
            "expected_names": {
                "application_stack": base,
                "qualification_stack": f"{base}-qualification",
                "bootstrap_stack": f"{base}-bootstrap",
                "artifact_bucket": (
                    f"bridgefu-recipe-{account}-{region}-{execution_id}"
                ),
                "ecr_repository": f"bridgefu-test/{execution_id}",
            },
            "bootstrap": {
                "name": f"{base}-bootstrap",
                "stack_id": stack_id,
                "status": "CREATE_COMPLETE",
                "creation_time": "2026-08-03T01:00:00Z",
                "tags": {},
                "parameters": {
                    "TrustedPrincipalArn": (
                        "arn:aws:iam::111122223333:role/OriginalDeployer"
                    ),
                    "ConnectInstanceArn": (
                        "arn:aws:connect:us-west-2:111122223333:instance/unused"
                    ),
                    "EnableDemoSite": "false",
                },
                "outputs": {
                    "DeploymentRoleArn": (
                        f"arn:aws:iam::{account}:role/{base}-deployer"
                    ),
                    "CloudFormationExecutionRoleArn": (
                        f"arn:aws:iam::{account}:role/{base}-cloudformation"
                    ),
                    "QualificationRoleArn": (
                        f"arn:aws:iam::{account}:role/{base}-qualifier"
                    ),
                    "QualificationRunnerRoleArn": (
                        f"arn:aws:iam::{account}:role/{base}-runner"
                    ),
                },
                "deployed_template_sha256": "a" * 64,
                "current_template_sha256": "b" * 64,
                "matches_current_template": False,
                "resources": [
                    {
                        "logical_id": "QualificationSourceEip",
                        "physical_id": "eipalloc-0123456789abcdef0",
                        "resource_type": "AWS::EC2::EIP",
                        "status": "CREATE_COMPLETE",
                    }
                ],
                "change_sets": [],
            },
            "cloudformation_history": [],
            "tagged_resources": [],
            "iam": {"roles": [], "policies": [], "attachments": {}},
            "artifact_bucket": {
                "name": f"bridgefu-recipe-{account}-{region}-{execution_id}",
                "exists": False,
            },
            "ecr_repository": {
                "name": f"bridgefu-test/{execution_id}",
                "exists": False,
            },
            "absence": {"application_stack_history": True},
            "coverage": {"cloudformation": "direct"},
            "qualification_source": {
                "allocation_id": "eipalloc-0123456789abcdef0",
                "cidr": "203.0.113.10/32",
            },
        }

    def sample_review(self, inventory: dict) -> tuple[dict, str]:
        authority = LIVE.recovery_teardown_authority_projection(inventory)
        reviewed = dt.datetime.now(dt.timezone.utc)
        review = {
            "schema_version": 1,
            "review_kind": "bootstrap_only_teardown_recovery",
            "execution_id": inventory["execution_id"],
            "account_id": inventory["identity"]["account_id"],
            "region": inventory["identity"]["region"],
            "bootstrap_stack_id": inventory["bootstrap"]["stack_id"],
            "expect_demo_site": False,
            "reviewed_at": LIVE.recovery_iso(reviewed),
            "expires_at": LIVE.recovery_iso(
                reviewed + dt.timedelta(seconds=LIVE.RECOVERY_REVIEW_TTL_SECONDS)
            ),
            "controller_sha256": LIVE.recovery_controller_sha256(),
            "inventory_sha256": LIVE.canonical_json_sha256(inventory),
            "teardown_authority_sha256": LIVE.canonical_json_sha256(authority),
            "inventory": inventory,
            "teardown_authority": authority,
        }
        raw = (json.dumps(review, indent=2, sort_keys=True) + "\n").encode()
        return review, hashlib.sha256(raw).hexdigest()

    def empty_teardown_inventory(self, checked_at: str) -> dict:
        return {
            key: checked_at if key == "checked_at" else []
            for key in LIVE.TEARDOWN_INVENTORY_KEYS
        }

    def run_full_inventory_fixture(
        self,
        *,
        extra_tagged_arn: bool = False,
        application_history: bool = False,
        application_on_later_page: bool = False,
        associated_eip: bool = False,
        eip_physical_id: str | None = None,
    ) -> dict:
        execution_id = "bft-safe1"
        account = "111122223333"
        region = "us-west-2"
        partition = "aws"
        base = f"bridgefu-{execution_id}"
        bootstrap_name = f"{base}-bootstrap"
        stack_id = (
            f"arn:aws:cloudformation:{region}:{account}:stack/{bootstrap_name}/"
            "12345678-1234-1234-1234-123456789abc"
        )
        allocation_id = "eipalloc-0123456789abcdef0"
        source_ip = "8.8.8.8"
        trusted = f"arn:aws:iam::{account}:role/OriginalDeployer"
        recovery_principal = f"arn:aws:iam::{account}:role/RecoveryAdmin"
        parameters = {
            "ExecutionId": execution_id,
            "TrustedPrincipalArn": trusted,
            "GitHubOidcProviderArn": "none",
            "GitHubRepository": "eisenzopf/bridgefu",
            "GitHubEnvironment": "none",
            "ConnectInstanceArn": (
                f"arn:aws:connect:{region}:{account}:instance/unused"
            ),
            "ConnectMode": "Disposable",
            "EnableQualificationRunner": "false",
            "ArtifactBucketName": (
                f"bridgefu-recipe-{account}-{region}-{execution_id}"
            ),
            "EcrRepositoryName": f"bridgefu-test/{execution_id}",
            "ArtifactAccessMode": "EphemeralManage",
            "PublicHostedZoneId": "none",
            "EnableDemoSite": "false",
        }
        outputs = {
            "DeploymentRoleArn": f"arn:aws:iam::{account}:role/{base}-deployer",
            "CloudFormationExecutionRoleArn": (
                f"arn:aws:iam::{account}:role/{base}-cloudformation"
            ),
            "DeploymentRoleSessionName": base,
            "QualificationRoleArn": (
                f"arn:aws:iam::{account}:role/{base}-qualifier"
            ),
            "QualificationRoleSessionName": f"{base}-qualification",
            "QualificationRunnerRoleArn": (
                f"arn:aws:iam::{account}:role/{base}-runner"
            ),
            "QualificationSourceEipAllocationId": allocation_id,
            "QualificationSourceEipPublicIp": source_ip,
        }
        stack_tags = {
            "Project": LIVE.PROJECT,
            "ManagedBy": LIVE.MANAGED_BY,
            "BridgefuExecutionId": execution_id,
            "BridgefuRecipe": LIVE.RECIPE,
        }
        created = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
        stack = {
            "StackId": stack_id,
            "StackName": bootstrap_name,
            "StackStatus": "UPDATE_COMPLETE",
            "CreationTime": created.isoformat(),
            "RoleARN": None,
            "EnableTerminationProtection": False,
            "Tags": [
                {"Key": key, "Value": value} for key, value in stack_tags.items()
            ],
            "Parameters": [
                {"ParameterKey": key, "ParameterValue": value}
                for key, value in parameters.items()
            ],
            "Outputs": [
                {"OutputKey": key, "OutputValue": value}
                for key, value in outputs.items()
            ],
        }
        physical = {
            "DeploymentRole": f"{base}-deployer",
            "CloudFormationExecutionRole": f"{base}-cloudformation",
            "QualificationRole": f"{base}-qualifier",
            "QualificationRunnerRole": f"{base}-runner",
            "DeploymentControlPolicy": (
                f"arn:aws:iam::{account}:policy/{base}-deployer-control"
            ),
            "DeploymentArtifactPolicy": (
                f"arn:aws:iam::{account}:policy/{base}-deployer-artifacts"
            ),
            "DeploymentApplicationPolicy": (
                f"arn:aws:iam::{account}:policy/{base}-deployer-application"
            ),
            "DeploymentComputePolicy": (
                f"arn:aws:iam::{account}:policy/{base}-deployer-compute"
            ),
            "DeploymentDataPolicy": (
                f"arn:aws:iam::{account}:policy/{base}-deployer-data"
            ),
            "DeploymentDemoPolicy": (
                f"arn:aws:iam::{account}:policy/{base}-deployer-demo"
            ),
            "DeploymentQualificationRunnerPolicy": (
                f"arn:aws:iam::{account}:policy/{base}-deployer-runner"
            ),
            "QualificationSourceEip": eip_physical_id or source_ip,
        }
        resources = [
            {
                "LogicalResourceId": logical_id,
                "PhysicalResourceId": resource_id,
                "ResourceType": LIVE.RECOVERY_BOOTSTRAP_RESOURCE_TYPES[logical_id],
                "ResourceStatus": (
                    "UPDATE_COMPLETE"
                    if logical_id == "DeploymentControlPolicy"
                    else "CREATE_COMPLETE"
                ),
            }
            for logical_id, resource_id in physical.items()
        ]
        template_path = (
            ROOT
            / "recipes/vapi-amazon-connect-screen-pop/cloudformation"
            / "test-deployment-role.yaml"
        )
        deployed_template = copy.deepcopy(LIVE.cloudformation_document(template_path))
        deployed_template["Description"] = "older deployed bootstrap revision"
        role_names = sorted(
            resource_id
            for logical_id, resource_id in physical.items()
            if LIVE.RECOVERY_BOOTSTRAP_RESOURCE_TYPES[logical_id] == "AWS::IAM::Role"
        )
        policy_arns = sorted(
            resource_id
            for logical_id, resource_id in physical.items()
            if LIVE.RECOVERY_BOOTSTRAP_RESOURCE_TYPES[logical_id]
            == "AWS::IAM::ManagedPolicy"
        )
        eip_tags = {**stack_tags, "ManagedBy": "bridgefu-test-bootstrap"}
        tagged = [
            {
                "ResourceARN": (
                    f"arn:aws:ec2:{region}:{account}:elastic-ip/{allocation_id}"
                ),
                "Tags": [
                    {"Key": key, "Value": value} for key, value in eip_tags.items()
                ],
            }
        ]
        if extra_tagged_arn:
            tagged.append(
                {
                    "ResourceARN": (
                        f"arn:aws:lambda:{region}:{account}:function:{base}-spoof"
                    ),
                    "Tags": [
                        {"Key": key, "Value": value}
                        for key, value in stack_tags.items()
                    ],
                }
            )
        bootstrap_summary = {
            "StackName": bootstrap_name,
            "StackId": stack_id,
            "StackStatus": "UPDATE_COMPLETE",
        }
        app_summary = {
            "StackName": base,
            "StackId": (
                f"arn:aws:cloudformation:{region}:{account}:stack/{base}/"
                "22345678-1234-1234-1234-123456789abc"
            ),
            "StackStatus": "DELETE_COMPLETE",
        }

        def aws(arguments, **_kwargs):
            operation = tuple(arguments[:2])
            if operation == ("cloudformation", "describe-stacks"):
                return {"Stacks": [stack]}
            if operation == ("cloudformation", "get-template"):
                return {"TemplateBody": deployed_template}
            if operation == ("iam", "get-role"):
                return {
                    "Role": {
                        "RoleName": physical["DeploymentRole"],
                        "Arn": outputs["DeploymentRoleArn"],
                        "MaxSessionDuration": 43_200,
                        "AssumeRolePolicyDocument": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"AWS": trusted},
                                    "Action": "sts:AssumeRole",
                                    "Condition": {
                                        "StringEquals": {
                                            "sts:RoleSessionName": base
                                        }
                                    },
                                }
                            ]
                        },
                    }
                }
            if operation == ("ec2", "describe-addresses"):
                address = {
                    "AllocationId": allocation_id,
                    "PublicIp": source_ip,
                    "Domain": "vpc",
                    "Tags": [
                        {"Key": key, "Value": value}
                        for key, value in eip_tags.items()
                    ],
                }
                if associated_eip:
                    address["AssociationId"] = "eipassoc-1234"
                return {"Addresses": [address]}
            if operation == ("cloudformation", "list-stack-resources"):
                return {"StackResourceSummaries": resources}
            if operation == ("cloudformation", "list-change-sets"):
                return {"Summaries": []}
            if operation == ("cloudformation", "list-stacks"):
                if application_on_later_page:
                    if "--next-token" in arguments:
                        return {"StackSummaries": [app_summary]}
                    return {
                        "StackSummaries": [bootstrap_summary],
                        "NextToken": "later",
                    }
                values = [bootstrap_summary]
                if application_history:
                    values.append(app_summary)
                return {"StackSummaries": values}
            if operation == ("resourcegroupstaggingapi", "get-resources"):
                return {"ResourceTagMappingList": tagged}
            if operation == ("iam", "list-roles"):
                return {"Roles": [{"RoleName": name} for name in role_names]}
            if operation == ("iam", "list-policies"):
                return {
                    "Policies": [
                        {"PolicyName": arn.rsplit("/", 1)[-1], "Arn": arn}
                        for arn in policy_arns
                    ]
                }
            if operation == ("connect", "list-instances"):
                return {"InstanceSummaryList": []}
            if operation == ("logs", "describe-log-groups"):
                return {"logGroups": []}
            if operation == ("secretsmanager", "list-secrets"):
                return {"SecretList": []}
            if operation == ("codebuild", "batch-get-projects"):
                return {
                    "projects": [],
                    "projectsNotFound": [f"{base}-qualification"],
                }
            self.fail(f"unexpected AWS fixture operation: {arguments}")

        identity = {
            "account_id": account,
            "partition": partition,
            "region": region,
            "caller_arn": recovery_principal,
            "durable_principal_arn": recovery_principal,
        }
        global_absence = {
            "demo_site_bucket": True,
            "route53_hosted_zone": True,
            "cloudfront_distribution": True,
            "cloudfront_cache_policy": True,
            "cloudfront_response_headers_policy": True,
            "cloudfront_origin_access_control": True,
        }
        with mock.patch.object(
            LIVE, "recovery_identity_binding", return_value=identity
        ), mock.patch.object(
            LIVE, "aws_json", side_effect=aws
        ), mock.patch.object(
            LIVE,
            "recovery_artifact_bucket",
            return_value={
                "name": f"bridgefu-recipe-{account}-{region}-{execution_id}",
                "exists": False,
            },
        ), mock.patch.object(
            LIVE,
            "recovery_ecr_repository",
            return_value={"name": f"bridgefu-test/{execution_id}", "exists": False},
        ), mock.patch.object(
            LIVE, "recovery_iam_attachment_contract", return_value={"exact": True}
        ), mock.patch.object(
            LIVE, "recovery_global_absence", return_value=global_absence
        ):
            return LIVE.recovery_lost_ledger_inventory(
                execution_id=execution_id,
                account_id=account,
                region=region,
                bootstrap_stack_id=stack_id,
                expect_demo_site=False,
            )

    def test_full_inventory_accepts_refreshed_stack_stale_template_and_new_caller(self):
        inventory = self.run_full_inventory_fixture()
        self.assertEqual(inventory["bootstrap"]["status"], "UPDATE_COMPLETE")
        self.assertFalse(inventory["bootstrap"]["matches_current_template"])
        self.assertEqual(
            inventory["bootstrap"]["parameters"]["TrustedPrincipalArn"],
            "arn:aws:iam::111122223333:role/OriginalDeployer",
        )
        self.assertEqual(
            inventory["identity"]["durable_principal_arn"],
            "arn:aws:iam::111122223333:role/RecoveryAdmin",
        )
        self.assertTrue(
            any(
                item["status"] == "UPDATE_COMPLETE"
                for item in inventory["bootstrap"]["resources"]
            )
        )

    def test_eip_physical_identity_is_exact_public_ip_not_allocation_id(self):
        inventory = self.run_full_inventory_fixture()
        eip = next(
            item
            for item in inventory["bootstrap"]["resources"]
            if item["logical_id"] == "QualificationSourceEip"
        )
        self.assertEqual(eip["physical_id"], "8.8.8.8")

        for invalid_physical_id in (
            "eipalloc-0123456789abcdef0",
            "8.8.4.4",
        ):
            with self.subTest(physical_id=invalid_physical_id), self.assertRaisesRegex(
                LIVE.LiveTestError,
                "resources differ from its deployed Original template",
            ):
                self.run_full_inventory_fixture(
                    eip_physical_id=invalid_physical_id
                )

    def test_full_inventory_rejects_adversarial_or_application_scope(self):
        cases = (
            ("extra_tagged_arn", "tag inventory"),
            ("application_history", "application or qualification"),
            ("application_on_later_page", "application or qualification"),
            ("associated_eip", "EIP binding"),
        )
        for option, message in cases:
            with self.subTest(option=option):
                with self.assertRaisesRegex(LIVE.LiveTestError, message):
                    self.run_full_inventory_fixture(**{option: True})

    def test_exact_string_map_rejects_duplicate_or_malformed_entries(self):
        with self.assertRaisesRegex(LIVE.LiveTestError, "duplicate"):
            LIVE.recovery_exact_string_map(
                [
                    {"Key": "Project", "Value": "bridgefu"},
                    {"Key": "Project", "Value": "spoofed"},
                ],
                key_field="Key",
                value_field="Value",
                label="test tags",
            )
        with self.assertRaisesRegex(LIVE.LiveTestError, "malformed"):
            LIVE.recovery_exact_string_map(
                ["not-a-map"],
                key_field="Key",
                value_field="Value",
                label="test tags",
            )

    def test_stack_creation_time_must_be_inside_complete_history_window(self):
        now = dt.datetime.now(dt.timezone.utc)
        recent = (now - dt.timedelta(hours=1)).isoformat()
        self.assertEqual(
            LIVE.recovery_stack_creation_time(recent),
            recent.replace("+00:00", "Z"),
        )
        old = (now - dt.timedelta(days=90)).isoformat().replace("+00:00", "Z")
        with self.assertRaisesRegex(LIVE.LiveTestError, "history window"):
            LIVE.recovery_stack_creation_time(old)

    def test_identity_binding_rejects_wrong_account_before_any_inventory_call(self):
        caller = {
            "Account": "111122223333",
            "Arn": "arn:aws:iam::111122223333:role/Admin",
        }
        with mock.patch.object(LIVE, "identity", return_value=caller), mock.patch.object(
            LIVE, "aws_json"
        ) as aws:
            with self.assertRaisesRegex(LIVE.LiveTestError, "active AWS account"):
                LIVE.recovery_identity_binding("999900001111", "us-west-2")
        aws.assert_not_called()

    def test_identity_binding_rejects_wrong_partition_and_region(self):
        wrong_partition = {
            "Account": "111122223333",
            "Arn": "arn:not-aws:iam::111122223333:role/Admin",
        }
        with mock.patch.object(
            LIVE, "identity", return_value=wrong_partition
        ), mock.patch.object(LIVE, "aws_json") as aws:
            with self.assertRaisesRegex(LIVE.LiveTestError, "partition"):
                LIVE.recovery_identity_binding("111122223333", "us-west-2")
        aws.assert_not_called()

        caller = {
            "Account": "111122223333",
            "Arn": "arn:aws:iam::111122223333:role/Admin",
        }
        with mock.patch.object(LIVE, "identity", return_value=caller), mock.patch.object(
            LIVE,
            "aws_json",
            return_value={"Regions": [{"RegionName": "us-east-1"}]},
        ):
            with self.assertRaisesRegex(LIVE.LiveTestError, "exact recovery region"):
                LIVE.recovery_identity_binding("111122223333", "us-west-2")

    def test_paginated_inventory_includes_later_pages_and_rejects_cycles(self):
        pages = [
            {"Items": [], "NextToken": "next-page"},
            {"Items": [{"id": "late-leftover"}]},
        ]
        with mock.patch.object(LIVE, "aws_json", side_effect=pages) as aws:
            items = LIVE.recovery_paginated_items(
                ["service", "list-things"],
                list_key="Items",
                response_token="NextToken",
                request_token="--next-token",
            )
        self.assertEqual(items, [{"id": "late-leftover"}])
        self.assertEqual(
            aws.call_args_list[1].args[0],
            ["service", "list-things", "--no-paginate", "--next-token", "next-page"],
        )

        repeated = [
            {"Items": [], "NextToken": "same"},
            {"Items": [], "NextToken": "same"},
        ]
        with mock.patch.object(LIVE, "aws_json", side_effect=repeated):
            with self.assertRaisesRegex(LIVE.LiveTestError, "pagination token"):
                LIVE.recovery_paginated_items(
                    ["service", "list-things"],
                    list_key="Items",
                    response_token="NextToken",
                    request_token="--next-token",
                )

    def test_marker_only_cloudfront_inventory_includes_later_page_and_cycles_fail(self):
        pages = [
            {
                "CachePolicyList": {
                    "Quantity": 0,
                    "Items": [],
                    "NextMarker": "later",
                }
            },
            {
                "CachePolicyList": {
                    "Quantity": 1,
                    "Items": [{"CachePolicy": {"Id": "late-policy"}}],
                }
            },
        ]
        with mock.patch.object(LIVE, "aws_json", side_effect=pages) as aws:
            items = LIVE.recovery_paginated_nested_items(
                ["cloudfront", "list-cache-policies", "--type", "custom"],
                container_key="CachePolicyList",
            )
        self.assertEqual(items, [{"CachePolicy": {"Id": "late-policy"}}])
        self.assertEqual(aws.call_args_list[1].args[0][-2:], ["--marker", "later"])

        repeated = [
            {
                "ResponseHeadersPolicyList": {
                    "Quantity": 0,
                    "Items": [],
                    "NextMarker": "same",
                }
            },
            {
                "ResponseHeadersPolicyList": {
                    "Quantity": 0,
                    "Items": [],
                    "NextMarker": "same",
                }
            },
        ]
        with mock.patch.object(LIVE, "aws_json", side_effect=repeated):
            with self.assertRaisesRegex(LIVE.LiveTestError, "did not advance"):
                LIVE.recovery_paginated_nested_items(
                    [
                        "cloudfront",
                        "list-response-headers-policies",
                        "--type",
                        "custom",
                    ],
                    container_key="ResponseHeadersPolicyList",
                )

    def test_s3_inventory_accepts_missing_uploads_as_empty(self):
        pages = [
            {"IsTruncated": False},
            {"IsTruncated": False},
        ]
        with mock.patch.object(LIVE, "aws_json", side_effect=pages) as aws:
            inventory = LIVE.recovery_s3_contents(
                "bridgefu-recipe-111122223333-us-west-2-bft-safe1",
                "111122223333",
                "us-west-2",
            )
        self.assertEqual(inventory["version_count"], 0)
        self.assertEqual(inventory["multipart_uploads"], [])
        for call in aws.call_args_list:
            self.assertIn("--expected-bucket-owner", call.args[0])
            owner_index = call.args[0].index("--expected-bucket-owner")
            self.assertEqual(call.args[0][owner_index + 1], "111122223333")

    def test_s3_inventory_uses_paired_version_and_upload_markers(self):
        pages = [
            {
                "Versions": [{"Key": "same-key", "VersionId": "v1"}],
                "IsTruncated": True,
                "NextKeyMarker": "same-key",
                "NextVersionIdMarker": "v1",
            },
            {
                "DeleteMarkers": [{"Key": "same-key", "VersionId": "v0"}],
                "IsTruncated": False,
            },
            {
                "Uploads": [{"Key": "same-key", "UploadId": "u1"}],
                "IsTruncated": True,
                "NextKeyMarker": "same-key",
                "NextUploadIdMarker": "u1",
            },
            {
                "Uploads": [{"Key": "same-key", "UploadId": "u2"}],
                "IsTruncated": False,
            },
        ]
        with mock.patch.object(LIVE, "aws_json", side_effect=pages) as aws:
            inventory = LIVE.recovery_s3_contents(
                "bridgefu-recipe-111122223333-us-west-2-bft-safe1",
                "111122223333",
                "us-west-2",
            )
        self.assertEqual(inventory["version_count"], 2)
        self.assertEqual(
            inventory["multipart_uploads"],
            [
                {"key": "same-key", "upload_id": "u1"},
                {"key": "same-key", "upload_id": "u2"},
            ],
        )
        version_page_two = aws.call_args_list[1].args[0]
        self.assertEqual(
            version_page_two[-4:],
            ["--key-marker", "same-key", "--version-id-marker", "v1"],
        )
        upload_page_two = aws.call_args_list[3].args[0]
        self.assertEqual(
            upload_page_two[-4:],
            ["--key-marker", "same-key", "--upload-id-marker", "u1"],
        )

    def artifact_bucket_pages(self, rules: list[dict]) -> list[dict]:
        return [
            {
                "TagSet": [
                    {"Key": "Project", "Value": LIVE.PROJECT},
                    {"Key": "ManagedBy", "Value": LIVE.MANAGED_BY},
                    {"Key": "BridgefuExecutionId", "Value": "bft-safe1"},
                    {"Key": "BridgefuRecipe", "Value": LIVE.RECIPE},
                ]
            },
            {"LocationConstraint": "us-west-2"},
            {"Status": "Enabled"},
            {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            },
            {"ServerSideEncryptionConfiguration": {"Rules": rules}},
        ]

    def test_artifact_bucket_accepts_exact_current_encryption_rule(self):
        rule = {
            "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
            "BucketKeyEnabled": True,
            "BlockedEncryptionTypes": {"EncryptionType": ["SSE-C"]},
        }
        contents = {
            "version_count": 0,
            "versions_sha256": "0" * 64,
            "multipart_uploads": [],
        }
        with mock.patch.object(
            LIVE, "exact_probe_exists", return_value=True
        ), mock.patch.object(
            LIVE, "aws_json", side_effect=self.artifact_bucket_pages([rule])
        ), mock.patch.object(
            LIVE, "recovery_s3_contents", return_value=contents
        ) as inventory:
            recovered = LIVE.recovery_artifact_bucket(
                "bft-safe1", "111122223333", "us-west-2"
            )
        self.assertTrue(recovered["exists"])
        self.assertEqual(recovered["contents"], contents)
        inventory.assert_called_once_with(
            "bridgefu-recipe-111122223333-us-west-2-bft-safe1",
            "111122223333",
            "us-west-2",
        )

    def test_artifact_bucket_rejects_nonexact_encryption_rule(self):
        exact_rule = {
            "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
            "BucketKeyEnabled": True,
            "BlockedEncryptionTypes": {"EncryptionType": ["SSE-C"]},
        }
        invalid_rules = {
            "missing SSE-C block": {
                "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
                "BucketKeyEnabled": True,
            },
            "SSE-C explicitly allowed": {
                **exact_rule,
                "BlockedEncryptionTypes": {"EncryptionType": ["NONE"]},
            },
            "additional blocked value": {
                **exact_rule,
                "BlockedEncryptionTypes": {
                    "EncryptionType": ["SSE-C", "NONE"]
                },
            },
            "unknown nested field": {
                **exact_rule,
                "BlockedEncryptionTypes": {
                    "EncryptionType": ["SSE-C"],
                    "Unexpected": True,
                },
            },
            "unknown rule field": {**exact_rule, "Unexpected": True},
            "wrong algorithm": {
                **exact_rule,
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms"
                },
            },
            "bucket key disabled": {**exact_rule, "BucketKeyEnabled": False},
            "bucket key missing": {
                "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
                "BlockedEncryptionTypes": {"EncryptionType": ["SSE-C"]},
            },
        }
        for label, rule in invalid_rules.items():
            with self.subTest(label=label), mock.patch.object(
                LIVE, "exact_probe_exists", return_value=True
            ), mock.patch.object(
                LIVE,
                "aws_json",
                side_effect=self.artifact_bucket_pages([copy.deepcopy(rule)]),
            ):
                with self.assertRaisesRegex(LIVE.LiveTestError, "encryption"):
                    LIVE.recovery_artifact_bucket(
                        "bft-safe1", "111122223333", "us-west-2"
                    )

    def test_artifact_bucket_rejects_any_extra_encryption_rule(self):
        pages = self.artifact_bucket_pages(
            [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    },
                    "BucketKeyEnabled": True,
                    "BlockedEncryptionTypes": {"EncryptionType": ["SSE-C"]},
                },
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms"
                    }
                },
            ]
        )
        with mock.patch.object(
            LIVE, "exact_probe_exists", return_value=True
        ), mock.patch.object(LIVE, "aws_json", side_effect=pages):
            with self.assertRaisesRegex(LIVE.LiveTestError, "encryption"):
                LIVE.recovery_artifact_bucket(
                    "bft-safe1", "111122223333", "us-west-2"
                )

    def test_artifact_bucket_recovery_rejects_active_multipart_uploads(self):
        pages = self.artifact_bucket_pages(
            [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    },
                    "BucketKeyEnabled": True,
                    "BlockedEncryptionTypes": {"EncryptionType": ["SSE-C"]},
                }
            ]
        )
        contents = {
            "version_count": 0,
            "versions_sha256": "0" * 64,
            "multipart_uploads": [{"key": "release", "upload_id": "u1"}],
        }
        with mock.patch.object(
            LIVE, "exact_probe_exists", return_value=True
        ), mock.patch.object(
            LIVE, "aws_json", side_effect=pages
        ), mock.patch.object(
            LIVE, "recovery_s3_contents", return_value=contents
        ):
            with self.assertRaisesRegex(LIVE.LiveTestError, "multipart"):
                LIVE.recovery_artifact_bucket(
                    "bft-safe1", "111122223333", "us-west-2"
                )

    def test_disposable_false_flag_still_requires_runner_policy_attachment(self):
        account = "111122223333"
        base = "bridgefu-bft-safe1"
        physical = {
            "DeploymentRole": f"{base}-deployer",
            "CloudFormationExecutionRole": f"{base}-cloudformation",
            "QualificationRole": f"{base}-qualifier",
            "QualificationRunnerRole": f"{base}-runner",
            "DeploymentControlPolicy": (
                f"arn:aws:iam::{account}:policy/{base}-deployer-control"
            ),
            "DeploymentArtifactPolicy": (
                f"arn:aws:iam::{account}:policy/{base}-deployer-artifacts"
            ),
            "DeploymentApplicationPolicy": (
                f"arn:aws:iam::{account}:policy/{base}-deployer-application"
            ),
            "DeploymentComputePolicy": (
                f"arn:aws:iam::{account}:policy/{base}-deployer-compute"
            ),
            "DeploymentDataPolicy": (
                f"arn:aws:iam::{account}:policy/{base}-deployer-data"
            ),
            "DeploymentDemoPolicy": (
                f"arn:aws:iam::{account}:policy/{base}-deployer-demo"
            ),
            "DeploymentQualificationRunnerPolicy": (
                f"arn:aws:iam::{account}:policy/{base}-deployer-runner"
            ),
            "QualificationSourceEip": "eipalloc-0123456789abcdef0",
        }
        role_names = sorted(
            physical[key]
            for key, kind in LIVE.RECOVERY_BOOTSTRAP_RESOURCE_TYPES.items()
            if kind == "AWS::IAM::Role"
        )
        policy_arns = sorted(
            physical[key]
            for key, kind in LIVE.RECOVERY_BOOTSTRAP_RESOURCE_TYPES.items()
            if kind == "AWS::IAM::ManagedPolicy"
        )
        deployer_policies = {
            physical["DeploymentControlPolicy"],
            physical["DeploymentArtifactPolicy"],
        }
        execution_policies = set(policy_arns)
        explicit_role_tags = [
            {"Key": "Project", "Value": LIVE.PROJECT},
            {"Key": "ManagedBy", "Value": "bridgefu-test-bootstrap"},
            {"Key": "BridgefuExecutionId", "Value": "bft-safe1"},
        ]
        stack_name = f"{base}-bootstrap"
        stack_id = (
            "arn:aws:cloudformation:us-west-2:111122223333:stack/"
            f"{stack_name}/12345678-1234-1234-1234-123456789abc"
        )
        role_logical_id = {
            physical[key]: key
            for key, kind in LIVE.RECOVERY_BOOTSTRAP_RESOURCE_TYPES.items()
            if kind == "AWS::IAM::Role"
        }

        def paginated(arguments, **_kwargs):
            operation = arguments[1]
            if operation == "list-attached-role-policies":
                role_name = arguments[arguments.index("--role-name") + 1]
                values = (
                    deployer_policies
                    if role_name == physical["DeploymentRole"]
                    else execution_policies
                    if role_name == physical["CloudFormationExecutionRole"]
                    else set()
                )
                return [{"PolicyArn": arn} for arn in sorted(values)]
            if operation == "list-instance-profiles-for-role":
                return []
            if operation == "list-role-tags":
                role_name = arguments[arguments.index("--role-name") + 1]
                return [
                    *explicit_role_tags,
                    {
                        "Key": "aws:cloudformation:stack-name",
                        "Value": stack_name,
                    },
                    {"Key": "aws:cloudformation:stack-id", "Value": stack_id},
                    {
                        "Key": "aws:cloudformation:logical-id",
                        "Value": role_logical_id[role_name],
                    },
                ]
            if operation == "list-entities-for-policy":
                entity = arguments[arguments.index("--entity-filter") + 1]
                if entity != "Role":
                    return []
                policy_arn = arguments[arguments.index("--policy-arn") + 1]
                roles = []
                if policy_arn in deployer_policies:
                    roles.append(physical["DeploymentRole"])
                if policy_arn in execution_policies:
                    roles.append(physical["CloudFormationExecutionRole"])
                return [{"RoleName": name} for name in roles]
            self.fail(f"unexpected IAM operation: {operation}")

        def inline(arguments, **_kwargs):
            role_name = arguments[arguments.index("--role-name") + 1]
            return {
                physical["QualificationRole"]: ["BridgefuRecipeQualification"],
                physical["QualificationRunnerRole"]: ["BridgefuQualificationRunner"],
            }.get(role_name, [])

        with mock.patch.object(
            LIVE, "recovery_paginated_items", side_effect=paginated
        ), mock.patch.object(
            LIVE, "recovery_paginated_strings", side_effect=inline
        ):
            contract = LIVE.recovery_iam_attachment_contract(
                execution_id="bft-safe1",
                bootstrap_stack_id=stack_id,
                bootstrap_stack_name=stack_name,
                expected_role_names=role_names,
                expected_policy_arns=policy_arns,
                expected_physical_ids=physical,
                # This is the resolved Disposable OR false condition.
                qualification_runner_enabled=True,
            )
        self.assertEqual(
            contract["policies"][physical["DeploymentQualificationRunnerPolicy"]][
                "role_names"
            ],
            [physical["CloudFormationExecutionRole"]],
        )

    def test_ecr_repository_requires_scan_on_push(self):
        repository = {
            "registryId": "111122223333",
            "repositoryName": "bridgefu-test/bft-safe1",
            "repositoryArn": (
                "arn:aws:ecr:us-west-2:111122223333:repository/"
                "bridgefu-test/bft-safe1"
            ),
            "imageTagMutability": "IMMUTABLE",
            "imageScanningConfiguration": {"scanOnPush": False},
            "encryptionConfiguration": {"encryptionType": "AES256"},
        }
        with mock.patch.object(
            LIVE, "exact_probe_exists", return_value=True
        ), mock.patch.object(
            LIVE, "aws_json", return_value={"repositories": [repository]}
        ):
            with self.assertRaisesRegex(LIVE.LiveTestError, "configuration"):
                LIVE.recovery_ecr_repository(
                    "bft-safe1", "111122223333", "aws", "us-west-2"
                )

    def test_ecr_recovery_and_deletion_bind_the_exact_registry(self):
        account = "111122223333"
        region = "us-west-2"
        name = "bridgefu-test/bft-safe1"
        arn = f"arn:aws:ecr:{region}:{account}:repository/{name}"
        repository = {
            "registryId": account,
            "repositoryName": name,
            "repositoryArn": arn,
            "imageTagMutability": "IMMUTABLE",
            "imageScanningConfiguration": {"scanOnPush": True},
            "encryptionConfiguration": {"encryptionType": "AES256"},
        }
        tags = [
            {"Key": "Project", "Value": LIVE.PROJECT},
            {"Key": "ManagedBy", "Value": LIVE.MANAGED_BY},
            {"Key": "BridgefuExecutionId", "Value": "bft-safe1"},
            {"Key": "BridgefuRecipe", "Value": LIVE.RECIPE},
        ]
        with mock.patch.object(
            LIVE, "exact_probe_exists", return_value=True
        ), mock.patch.object(
            LIVE,
            "aws_json",
            side_effect=[{"repositories": [repository]}, {"tags": tags}],
        ) as aws, mock.patch.object(
            LIVE, "recovery_paginated_items", return_value=[]
        ) as pages:
            observed = LIVE.recovery_ecr_repository(
                "bft-safe1", account, "aws", region
            )
        self.assertEqual(observed["arn"], arn)
        for call in (aws.call_args_list[0].args[0], pages.call_args.args[0]):
            self.assertIn("--registry-id", call)
            self.assertEqual(call[call.index("--registry-id") + 1], account)

        ledger = {
            "execution_id": "bft-safe1",
            "account_id": account,
            "partition": "aws",
            "region": region,
            "ecr_repository": name,
            "created_resources": [{"type": "ecr_repository", "id": name}],
        }
        wrong_registry = {**repository, "registryId": "999900001111"}
        with mock.patch.object(
            LIVE, "aws_json", return_value={"repositories": [wrong_registry]}
        ) as deletion_aws:
            with self.assertRaisesRegex(LIVE.LiveTestError, "target name changed"):
                LIVE.require_owned_ecr_for_deletion(ledger, {})
        arguments = deletion_aws.call_args.args[0]
        self.assertEqual(
            arguments[arguments.index("--registry-id") + 1], account
        )

    def test_assume_env_rejects_wrong_session_or_account(self):
        account = "111122223333"
        execution_id = "bft-safe1"
        role_name = f"bridgefu-{execution_id}-deployer"
        expected_arn = f"arn:aws:iam::{account}:role/{role_name}"
        expected_session = (
            f"arn:aws:sts::{account}:assumed-role/{role_name}/"
            f"bridgefu-{execution_id}"
        )
        ledger = {
            "execution_id": execution_id,
            "account_id": account,
            "partition": "aws",
            "region": "us-west-2",
            "deployment_role_arn": expected_arn,
        }
        response = {
            "Credentials": {
                "AccessKeyId": "access",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
            },
            "AssumedRoleUser": {"Arn": expected_session},
        }
        with mock.patch.object(
            LIVE, "aws_json", return_value=response
        ), mock.patch.object(
            LIVE,
            "identity",
            return_value={"Account": "999900001111", "Arn": expected_session},
        ):
            with self.assertRaisesRegex(LIVE.LiveTestError, "failed to assume"):
                LIVE.assume_env(ledger, "deployment")

        wrong_session = copy.deepcopy(response)
        wrong_session["AssumedRoleUser"]["Arn"] = expected_session + "-other"
        with mock.patch.object(
            LIVE, "aws_json", return_value=wrong_session
        ), mock.patch.object(LIVE, "identity") as active_identity:
            with self.assertRaisesRegex(LIVE.LiveTestError, "response is not exact"):
                LIVE.assume_env(ledger, "deployment")
        active_identity.assert_not_called()

    def test_review_sha_is_exact_file_digest_and_execute_is_local_only(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            LIVE.os.environ, self.state_environment(Path(directory)), clear=True
        ):
            reviewed_inventory = self.sample_inventory()
            executed_inventory = self.sample_inventory(
                caller_arn=(
                    "arn:aws:sts::111122223333:assumed-role/RecoveryAdmin/refreshed"
                )
            )
            review_args = mock.Mock(
                execution_id="bft-safe1",
                account_id="111122223333",
                region="us-west-2",
                bootstrap_stack_id=reviewed_inventory["bootstrap"]["stack_id"],
                expect_demo_site="false",
                confirm_account="111122223333",
                confirm_region="us-west-2",
                confirm_execution="bft-safe1",
            )
            output = io.StringIO()
            with mock.patch.object(
                LIVE,
                "recovery_lost_ledger_inventory",
                side_effect=[reviewed_inventory, executed_inventory],
            ) as inventory, mock.patch.object(
                LIVE, "aws_json", side_effect=AssertionError("unexpected direct AWS call")
            ), contextlib.redirect_stdout(output):
                LIVE.recover_lost_ledger_review(review_args)
                review_result = json.loads(output.getvalue())
                review_path = Path(review_result["review_path"])
                self.assertEqual(
                    hashlib.sha256(review_path.read_bytes()).hexdigest(),
                    review_result["review_sha256"],
                )
                output.seek(0)
                output.truncate(0)
                execute_args = mock.Mock(
                    execution_id="bft-safe1",
                    account_id="111122223333",
                    region="us-west-2",
                    review_sha256=review_result["review_sha256"],
                    confirm="bft-safe1",
                    confirm_account="111122223333",
                    confirm_region="us-west-2",
                )
                LIVE.recover_lost_ledger_execute(execute_args)
            self.assertEqual(inventory.call_count, 2)
            path, ledger = LIVE.load_ledger("bft-safe1")
            self.assertEqual(ledger["recovery_mode"], "teardown_only")
            self.assertEqual(ledger["vapi_teardown_mode"], "not_created")
            self.assertEqual(ledger["vapi_not_created_reason"], "application_not_executed")
            self.assertEqual(
                ledger["recovery_authorizer_principal_arn"],
                "arn:aws:iam::111122223333:role/RecoveryAdmin",
            )
            marker = LIVE.read_retired_execution_marker("bft-safe1")
            self.assertEqual(
                marker["recovery_authority_sha256"],
                ledger["recovery_authority_sha256"],
            )
            execute_result = json.loads(output.getvalue())
            for command in execute_result["next_actions"]:
                parsed = LIVE.parser().parse_args(command.split()[2:])
                self.assertEqual(parsed.execution_id, "bft-safe1")
            self.assertEqual(path, LIVE.ledger_path("bft-safe1"))

    def test_installed_ledger_survives_retirement_marker_failure_and_resumes(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            LIVE.os.environ, self.state_environment(Path(directory)), clear=True
        ):
            inventory = self.sample_inventory()
            review, review_sha = self.sample_review(inventory)
            ledger = LIVE.recovered_ledger_from_review(review, inventory, review_sha)
            authority = LIVE.lost_ledger_recovery_authority(ledger)
            ledger["recovery_authority_sha256"] = LIVE.canonical_json_sha256(authority)
            with mock.patch.object(
                LIVE,
                "ensure_retired_marker_for_ledger",
                side_effect=OSError("simulated marker write failure"),
            ):
                with self.assertRaisesRegex(OSError, "marker write"):
                    LIVE.install_recovered_ledger(
                        ledger, authority, review_sha
                    )
            self.assertTrue(LIVE.ledger_path("bft-safe1").is_file())
            self.assertIsNone(LIVE.read_retired_execution_marker("bft-safe1"))

            args = mock.Mock(
                execution_id="bft-safe1",
                account_id="111122223333",
                region="us-west-2",
                review_sha256=review_sha,
                confirm="bft-safe1",
                confirm_account="111122223333",
                confirm_region="us-west-2",
            )
            with mock.patch.object(
                LIVE, "recovery_lost_ledger_inventory"
            ) as aws_inventory, contextlib.redirect_stdout(io.StringIO()):
                LIVE.recover_lost_ledger_execute(args)
            aws_inventory.assert_not_called()
            self.assertIsNotNone(LIVE.read_retired_execution_marker("bft-safe1"))

    def test_recovery_authority_mutation_and_non_teardown_command_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            LIVE.os.environ, self.state_environment(Path(directory)), clear=True
        ):
            inventory = self.sample_inventory()
            review, review_sha = self.sample_review(inventory)
            ledger = LIVE.recovered_ledger_from_review(review, inventory, review_sha)
            authority = LIVE.lost_ledger_recovery_authority(ledger)
            ledger["recovery_authority_sha256"] = LIVE.canonical_json_sha256(authority)
            path = LIVE.install_recovered_ledger(ledger, authority, review_sha)
            with self.assertRaisesRegex(LIVE.LiveTestError, "teardown-only"):
                LIVE.enforce_teardown_only_command_authority(
                    mock.Mock(execution_id="bft-safe1", command="verify")
                )
            changed = json.loads(path.read_text())
            changed["deployment_role_arn"] = (
                "arn:aws:iam::111122223333:role/not-the-recovered-role"
            )
            LIVE.atomic_json(path, changed)
            with self.assertRaisesRegex(LIVE.LiveTestError, "teardown binding"):
                LIVE.load_ledger("bft-safe1")

    def test_recovered_destroy_revalidates_before_mutation_and_uses_stack_arn(self):
        inventory = self.sample_inventory()
        review, review_sha = self.sample_review(inventory)
        ledger = LIVE.recovered_ledger_from_review(review, inventory, review_sha)
        authority = LIVE.lost_ledger_recovery_authority(ledger)
        ledger["recovery_authority_sha256"] = LIVE.canonical_json_sha256(authority)
        order: list[str] = []

        def bind(_ledger):
            return inventory["identity"]

        def reinventory(**_kwargs):
            order.append("full-reinventory")
            return inventory

        def write_intent(_path, _ledger):
            order.append("durable-intent")

        def mutate(arguments, **_kwargs):
            order.append("aws-mutation")
            self.assertEqual(arguments[0:2], ["cloudformation", "delete-stack"])
            stack_index = arguments.index("--stack-name")
            self.assertEqual(
                arguments[stack_index + 1], inventory["bootstrap"]["stack_id"]
            )
            return {}

        with mock.patch.object(LIVE, "bind_active_ledger_identity", side_effect=bind), mock.patch.object(
            LIVE, "recovered_destroy_intent_is_valid", return_value=False
        ), mock.patch.object(
            LIVE, "recovery_lost_ledger_inventory", side_effect=reinventory
        ), mock.patch.object(
            LIVE, "write_recovered_destroy_intent", side_effect=write_intent
        ), mock.patch.object(
            LIVE, "record"
        ), mock.patch.object(
            LIVE, "stack_status_if_exists", return_value="CREATE_COMPLETE"
        ), mock.patch.object(
            LIVE, "exact_probe_exists", return_value=False
        ), mock.patch.object(
            LIVE, "require_owned_stack_for_deletion"
        ), mock.patch.object(
            LIVE, "aws_json", side_effect=mutate
        ), mock.patch.object(
            LIVE, "aws_wait"
        ) as waiter, mock.patch.object(
            LIVE, "prove_teardown_zero_state"
        ):
            LIVE.destroy_recovered_teardown_only(
                Path("/private/state/bft-safe1/ledger.json"), ledger
            )
        self.assertLess(order.index("full-reinventory"), order.index("aws-mutation"))
        self.assertLess(order.index("durable-intent"), order.index("aws-mutation"))
        waiter_arguments = waiter.call_args.args[0]
        self.assertEqual(
            waiter_arguments[waiter_arguments.index("--stack-name") + 1],
            inventory["bootstrap"]["stack_id"],
        )

    def test_recovered_destroy_resumes_exact_partial_state_without_new_authority(self):
        inventory = self.sample_inventory()
        bucket_name = inventory["expected_names"]["artifact_bucket"]
        inventory["artifact_bucket"] = {
            "name": bucket_name,
            "exists": True,
            "tags": {
                "Project": LIVE.PROJECT,
                "ManagedBy": LIVE.MANAGED_BY,
                "BridgefuExecutionId": "bft-safe1",
                "BridgefuRecipe": LIVE.RECIPE,
            },
            "contents": {
                "version_count": 1,
                "versions_sha256": "a" * 64,
                "multipart_uploads": [],
            },
        }
        review, review_sha = self.sample_review(inventory)
        ledger = LIVE.recovered_ledger_from_review(review, inventory, review_sha)
        ledger["status"] = "destroying"
        authority = LIVE.lost_ledger_recovery_authority(ledger)
        ledger["recovery_authority_sha256"] = LIVE.canonical_json_sha256(authority)
        environment = {"AWS_PROFILE": "nonroot"}

        def aws_call(arguments, **_kwargs):
            if arguments[:2] == ["s3api", "list-object-versions"]:
                return {"Versions": [], "DeleteMarkers": []}
            if arguments[:2] == ["cloudformation", "delete-stack"]:
                return {}
            self.fail(f"unexpected AWS JSON operation: {arguments}")

        with mock.patch.object(
            LIVE, "bind_active_ledger_identity", return_value=inventory["identity"]
        ), mock.patch.object(
            LIVE, "recovered_destroy_intent_is_valid", return_value=True
        ), mock.patch.object(
            LIVE, "revalidate_recovered_teardown_authority"
        ) as revalidate, mock.patch.object(
            LIVE, "write_recovered_destroy_intent"
        ) as write_intent, mock.patch.object(
            LIVE, "recovered_direct_environment", return_value=environment
        ), mock.patch.object(
            LIVE, "stack_status_if_exists", return_value="CREATE_COMPLETE"
        ), mock.patch.object(
            LIVE, "exact_probe_exists", side_effect=[False, True]
        ) as probe, mock.patch.object(
            LIVE, "require_owned_ecr_for_deletion"
        ) as own_ecr, mock.patch.object(
            LIVE, "require_owned_bucket_for_deletion"
        ) as own_bucket, mock.patch.object(
            LIVE, "exact_delete", return_value=True
        ) as deletion, mock.patch.object(
            LIVE, "require_owned_stack_for_deletion"
        ) as own_stack, mock.patch.object(
            LIVE, "aws_json", side_effect=aws_call
        ) as aws, mock.patch.object(
            LIVE, "aws_wait"
        ) as waiter, mock.patch.object(
            LIVE, "record"
        ), mock.patch.object(
            LIVE, "prove_teardown_zero_state"
        ) as prove:
            LIVE.destroy_recovered_teardown_only(
                Path("/private/state/bft-safe1/ledger.json"), ledger
            )

        revalidate.assert_not_called()
        write_intent.assert_not_called()
        own_ecr.assert_not_called()
        self.assertEqual(probe.call_count, 2)
        repository_probe = probe.call_args_list[0].args[0]
        self.assertEqual(
            repository_probe[repository_probe.index("--repository-names") + 1],
            inventory["expected_names"]["ecr_repository"],
        )
        bucket_probe = probe.call_args_list[1].args[0]
        self.assertEqual(bucket_probe[bucket_probe.index("--bucket") + 1], bucket_name)
        self.assertEqual(
            bucket_probe[bucket_probe.index("--expected-bucket-owner") + 1],
            inventory["identity"]["account_id"],
        )
        own_bucket.assert_called_once_with(ledger, environment)
        deletion.assert_called_once()
        bucket_delete = deletion.call_args.args[0]
        self.assertEqual(bucket_delete[:2], ["s3api", "delete-bucket"])
        self.assertEqual(
            bucket_delete[bucket_delete.index("--bucket") + 1], bucket_name
        )
        self.assertEqual(
            bucket_delete[bucket_delete.index("--expected-bucket-owner") + 1],
            inventory["identity"]["account_id"],
        )
        own_stack.assert_called_once_with(
            ledger,
            environment,
            inventory["expected_names"]["bootstrap_stack"],
            inventory["bootstrap"]["stack_id"],
        )
        delete_stack_calls = [
            call
            for call in aws.call_args_list
            if call.args[0][:2] == ["cloudformation", "delete-stack"]
        ]
        self.assertEqual(len(delete_stack_calls), 1)
        stack_delete = delete_stack_calls[0].args[0]
        self.assertEqual(
            stack_delete[stack_delete.index("--stack-name") + 1],
            inventory["bootstrap"]["stack_id"],
        )
        waiter.assert_called_once()
        wait_command = waiter.call_args.args[0]
        self.assertEqual(
            wait_command[wait_command.index("--stack-name") + 1],
            inventory["bootstrap"]["stack_id"],
        )
        prove.assert_called_once()
        self.assertEqual(ledger["status"], "destroying_base_finalize")

    def test_recovered_partial_destroy_with_invalid_intent_cannot_resume(self):
        inventory = self.sample_inventory()
        inventory["artifact_bucket"] = {
            "name": inventory["expected_names"]["artifact_bucket"],
            "exists": True,
            "tags": {},
            "contents": {
                "version_count": 1,
                "versions_sha256": "a" * 64,
                "multipart_uploads": [],
            },
        }
        inventory["ecr_repository"] = {
            "name": inventory["expected_names"]["ecr_repository"],
            "exists": True,
            "arn": (
                "arn:aws:ecr:us-west-2:111122223333:repository/"
                "bridgefu-test/bft-safe1"
            ),
            "tags": {},
            "image_count": 1,
            "images_sha256": "b" * 64,
        }
        review, review_sha = self.sample_review(inventory)
        ledger = LIVE.recovered_ledger_from_review(review, inventory, review_sha)
        ledger["status"] = "destroying"
        authority = LIVE.lost_ledger_recovery_authority(ledger)
        ledger["recovery_authority_sha256"] = LIVE.canonical_json_sha256(authority)
        with mock.patch.object(
            LIVE, "bind_active_ledger_identity", return_value=inventory["identity"]
        ), mock.patch.object(
            LIVE, "recovered_destroy_intent_is_valid", return_value=False
        ), mock.patch.object(
            LIVE,
            "revalidate_recovered_teardown_authority",
            side_effect=LIVE.LiveTestError(
                "current AWS resources differ from the recovered teardown authority"
            ),
        ) as revalidate, mock.patch.object(
            LIVE, "write_recovered_destroy_intent"
        ) as write_intent, mock.patch.object(
            LIVE, "exact_probe_exists"
        ) as probe, mock.patch.object(
            LIVE, "exact_delete"
        ) as deletion, mock.patch.object(
            LIVE, "aws_json"
        ) as mutation:
            with self.assertRaisesRegex(
                LIVE.LiveTestError, "differ from the recovered teardown authority"
            ):
                LIVE.destroy_recovered_teardown_only(
                    Path("/private/state/bft-safe1/ledger.json"), ledger
                )
        revalidate.assert_called_once_with(ledger)
        write_intent.assert_not_called()
        probe.assert_not_called()
        deletion.assert_not_called()
        mutation.assert_not_called()
        self.assertEqual(ledger["status"], "destroying")

    def test_recovered_destroy_reconciles_delete_complete_tombstone(self):
        inventory = self.sample_inventory()
        review, review_sha = self.sample_review(inventory)
        ledger = LIVE.recovered_ledger_from_review(review, inventory, review_sha)
        authority = LIVE.lost_ledger_recovery_authority(ledger)
        ledger["recovery_authority_sha256"] = LIVE.canonical_json_sha256(authority)
        with mock.patch.object(
            LIVE, "bind_active_ledger_identity", return_value=inventory["identity"]
        ), mock.patch.object(
            LIVE, "recovered_destroy_intent_is_valid", return_value=True
        ), mock.patch.object(
            LIVE, "stack_status_if_exists", return_value="DELETE_COMPLETE"
        ), mock.patch.object(
            LIVE, "prove_teardown_zero_state"
        ) as prove, mock.patch.object(LIVE, "aws_json") as mutation:
            LIVE.destroy_recovered_teardown_only(
                Path("/private/state/bft-safe1/ledger.json"), ledger
            )
        prove.assert_called_once()
        mutation.assert_not_called()

    def test_finalize_incomplete_status_does_not_bypass_destroy_revalidation(self):
        inventory = self.sample_inventory()
        review, review_sha = self.sample_review(inventory)
        ledger = LIVE.recovered_ledger_from_review(review, inventory, review_sha)
        ledger["status"] = "teardown_incomplete"
        authority = LIVE.lost_ledger_recovery_authority(ledger)
        ledger["recovery_authority_sha256"] = LIVE.canonical_json_sha256(authority)
        with mock.patch.object(
            LIVE, "bind_active_ledger_identity", return_value=inventory["identity"]
        ), mock.patch.object(
            LIVE, "recovered_destroy_intent_is_valid", return_value=False
        ), mock.patch.object(
            LIVE, "revalidate_recovered_teardown_authority",
            side_effect=LIVE.LiveTestError("fresh revalidation failed"),
        ) as revalidate, mock.patch.object(LIVE, "aws_json") as mutation:
            with self.assertRaisesRegex(LIVE.LiveTestError, "revalidation failed"):
                LIVE.destroy_recovered_teardown_only(
                    Path("/private/state/bft-safe1/ledger.json"), ledger
                )
        revalidate.assert_called_once()
        mutation.assert_not_called()

    def test_teardown_only_identity_rejects_same_account_wrong_principal(self):
        ledger = {
            "account_id": "111122223333",
            "partition": "aws",
            "region": "us-west-2",
            "recovery_mode": "teardown_only",
            "recovery_authorizer_principal_arn": (
                "arn:aws:iam::111122223333:role/RecoveryAdmin"
            ),
        }
        wrong = {
            "account_id": "111122223333",
            "partition": "aws",
            "region": "us-west-2",
            "caller_arn": "arn:aws:iam::111122223333:role/OtherAdmin",
            "durable_principal_arn": "arn:aws:iam::111122223333:role/OtherAdmin",
        }
        with mock.patch.object(
            LIVE, "recovery_identity_binding", return_value=wrong
        ):
            with self.assertRaisesRegex(LIVE.LiveTestError, "recovery authorizer"):
                LIVE.bind_active_ledger_identity(ledger)

    def test_zero_proof_accepts_exact_delete_complete_tombstone_across_one_minute(self):
        ledger = {
            "execution_id": "bft-safe1",
            "account_id": "111122223333",
            "partition": "aws",
            "stack_name": "bridgefu-bft-safe1",
            "qualification_stack_name": "bridgefu-bft-safe1-qualification",
            "bootstrap_stack_name": "bridgefu-bft-safe1-bootstrap",
            "bootstrap_stack_id": (
                "arn:aws:cloudformation:us-west-2:111122223333:stack/"
                "bridgefu-bft-safe1-bootstrap/"
                "12345678-1234-1234-1234-123456789abc"
            ),
            "region": "us-west-2",
            "status": "destroying_base_finalize",
        }
        clock = {"value": 0.0}

        def monotonic():
            return clock["value"]

        def sleep(seconds):
            clock["value"] += seconds

        observations: list[dict] = []

        def persist(_path, payload):
            if payload.get("minimum_span_seconds") == 60:
                observations.append(payload)

        statuses = []

        def status(identifier, _region):
            if identifier.startswith("arn:"):
                statuses.append(identifier)
                return "DELETE_COMPLETE"
            return None

        with mock.patch.object(
            LIVE, "bind_active_ledger_identity"
        ), mock.patch.object(
            LIVE, "assert_absent_stack"
        ), mock.patch.object(
            LIVE, "stack_status_if_exists", side_effect=status
        ), mock.patch.object(
            LIVE,
            "inventory_for_execution",
            side_effect=[
                self.empty_teardown_inventory("2026-08-03T01:00:00Z"),
                self.empty_teardown_inventory("2026-08-03T01:00:30Z"),
                self.empty_teardown_inventory("2026-08-03T01:01:00Z"),
            ],
        ), mock.patch.object(
            LIVE.time, "monotonic", side_effect=monotonic
        ), mock.patch.object(
            LIVE.time, "sleep", side_effect=sleep
        ), mock.patch.object(
            LIVE, "atomic_json", side_effect=persist
        ), mock.patch.object(
            LIVE, "record"
        ):
            LIVE.prove_teardown_zero_state(
                Path("/private/state/bft-safe1/ledger.json"),
                ledger,
                success_event="success",
                incomplete_event="incomplete",
            )
        self.assertEqual(ledger["status"], "destroyed")
        self.assertEqual(len(observations[0]["observations"]), 3)
        self.assertTrue(statuses)

    def test_zero_proof_rejects_incomplete_inventory_schema(self):
        ledger = {
            "execution_id": "bft-safe1",
            "account_id": "111122223333",
            "partition": "aws",
            "stack_name": "bridgefu-bft-safe1",
            "qualification_stack_name": "bridgefu-bft-safe1-qualification",
            "bootstrap_stack_name": "bridgefu-bft-safe1-bootstrap",
            "region": "us-west-2",
        }
        with mock.patch.object(
            LIVE, "bind_active_ledger_identity"
        ), mock.patch.object(
            LIVE, "assert_absent_stack"
        ), mock.patch.object(
            LIVE, "inventory_for_execution", return_value={"checked_at": "now"}
        ):
            with self.assertRaisesRegex(LIVE.LiveTestError, "schema is not exact"):
                LIVE.prove_teardown_zero_state(
                    Path("/private/state/bft-safe1/ledger.json"),
                    ledger,
                    success_event="success",
                    incomplete_event="incomplete",
                )

    def test_zero_proof_rejects_active_exact_stack_arn(self):
        ledger = {
            "execution_id": "bft-safe1",
            "account_id": "111122223333",
            "partition": "aws",
            "stack_name": "bridgefu-bft-safe1",
            "qualification_stack_name": "bridgefu-bft-safe1-qualification",
            "bootstrap_stack_name": "bridgefu-bft-safe1-bootstrap",
            "bootstrap_stack_id": (
                "arn:aws:cloudformation:us-west-2:111122223333:stack/"
                "bridgefu-bft-safe1-bootstrap/"
                "12345678-1234-1234-1234-123456789abc"
            ),
            "region": "us-west-2",
        }
        with mock.patch.object(
            LIVE, "bind_active_ledger_identity"
        ), mock.patch.object(
            LIVE, "assert_absent_stack"
        ), mock.patch.object(
            LIVE, "stack_status_if_exists", return_value="DELETE_IN_PROGRESS"
        ), mock.patch.object(LIVE, "inventory_for_execution") as inventory:
            with self.assertRaisesRegex(LIVE.LiveTestError, "stack ID still exists"):
                LIVE.prove_teardown_zero_state(
                    Path("/private/state/bft-safe1/ledger.json"),
                    ledger,
                    success_event="success",
                    incomplete_event="incomplete",
                )
        inventory.assert_not_called()

    def test_fresh_recovered_finalize_is_prohibited_before_destroy_intent(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            LIVE.os.environ, self.state_environment(Path(directory)), clear=True
        ):
            inventory = self.sample_inventory()
            review, review_sha = self.sample_review(inventory)
            ledger = LIVE.recovered_ledger_from_review(review, inventory, review_sha)
            authority = LIVE.lost_ledger_recovery_authority(ledger)
            ledger["recovery_authority_sha256"] = LIVE.canonical_json_sha256(authority)
            LIVE.install_recovered_ledger(ledger, authority, review_sha)
            args = mock.Mock(execution_id="bft-safe1", confirm="bft-safe1")
            with mock.patch.object(
                LIVE, "bind_active_ledger_identity"
            ), mock.patch.object(LIVE, "prove_teardown_zero_state") as prove:
                with self.assertRaisesRegex(LIVE.LiveTestError, "run destroy first"):
                    LIVE.destroy_finalize(args)
            prove.assert_not_called()

    def test_fresh_init_gate_requires_retained_zero_and_a_fresh_id(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            LIVE.os.environ, self.state_environment(Path(directory)), clear=True
        ):
            inventory = self.sample_inventory()
            review, review_sha = self.sample_review(inventory)
            ledger = LIVE.recovered_ledger_from_review(review, inventory, review_sha)
            authority = LIVE.lost_ledger_recovery_authority(ledger)
            ledger["recovery_authority_sha256"] = LIVE.canonical_json_sha256(authority)
            path = LIVE.install_recovered_ledger(ledger, authority, review_sha)
            with self.assertRaisesRegex(LIVE.LiveTestError, "unresolved live execution"):
                LIVE.assert_no_unresolved_local_live_state_for_init("bft-fresh2")

            ledger["status"] = "teardown_incomplete"
            LIVE.record(path, ledger, "simulated_incomplete")
            with self.assertRaisesRegex(LIVE.LiveTestError, "unresolved live execution"):
                LIVE.assert_no_unresolved_local_live_state_for_init("bft-fresh2")

            ledger["status"] = "destroyed"
            ledger["destroyed_at"] = "2026-08-03T02:01:01Z"
            LIVE.record(path, ledger, "simulated_zero")
            observations = [
                self.empty_teardown_inventory("2026-08-03T02:00:00Z"),
                self.empty_teardown_inventory("2026-08-03T02:00:30Z"),
                self.empty_teardown_inventory("2026-08-03T02:01:00Z"),
            ]
            LIVE.atomic_json(path.parent / "teardown-inventory.json", observations[-1])
            LIVE.atomic_json(
                path.parent / "teardown-zero-proof.json",
                {
                    "schema_version": 1,
                    "execution_id": "bft-safe1",
                    "required_observations": 3,
                    "minimum_span_seconds": 60,
                    "observations": observations,
                    "proven_at": "2026-08-03T02:01:01Z",
                },
            )
            LIVE.assert_no_unresolved_local_live_state_for_init("bft-fresh2")
            with self.assertRaisesRegex(LIVE.LiveTestError, "fresh execution ID"):
                LIVE.assert_no_unresolved_local_live_state_for_init("bft-safe1")

    def test_fresh_init_gate_rejects_orphan_marker_and_unsafe_entry(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            LIVE.os.environ, self.state_environment(Path(directory)), clear=True
        ):
            root = LIVE.ensure_live_state_root()
            marker_root = root / ".retired-executions"
            LIVE.ensure_private_directory(marker_root)
            LIVE.immutable_private_json(
                marker_root / "bft-orphan1.json",
                {
                    "schema_version": 1,
                    "marker_kind": "lost_ledger_teardown_only",
                    "execution_id": "bft-orphan1",
                    "retired_at": "2026-08-03T01:00:00Z",
                    "recovery_review_sha256": "a" * 64,
                    "recovery_authority_sha256": "b" * 64,
                },
            )
            with self.assertRaisesRegex(LIVE.LiveTestError, "no retained zero proof"):
                LIVE.assert_no_unresolved_local_live_state_for_init("bft-fresh2")

        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            LIVE.os.environ, self.state_environment(Path(directory)), clear=True
        ):
            root = LIVE.ensure_live_state_root()
            LIVE.atomic_json(root / "unexpected.json", {"unsafe": True})
            with self.assertRaisesRegex(LIVE.LiveTestError, "unsafe entry"):
                LIVE.assert_no_unresolved_local_live_state_for_init("bft-fresh2")

        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            LIVE.os.environ, self.state_environment(Path(directory)), clear=True
        ):
            root = LIVE.ensure_live_state_root()
            locks = root / ".locks"
            locks.mkdir(mode=0o700)
            locks.chmod(0o755)
            with self.assertRaisesRegex(LIVE.LiveTestError, "mode 0700"):
                LIVE.assert_no_unresolved_local_live_state_for_init("bft-fresh2")

    def test_account_init_gate_rejects_direct_ecr_leftover(self):
        repository = {
            "repositoryName": "bridgefu-test/bft-oldrun",
            "repositoryArn": (
                "arn:aws:ecr:us-west-2:111122223333:repository/"
                "bridgefu-test/bft-oldrun"
            ),
        }
        with mock.patch.object(
            LIVE, "recovery_paginated_items", side_effect=[[], [], [], [repository]]
        ) as pages, mock.patch.object(
            LIVE, "recovery_stack_history", return_value=[]
        ), mock.patch.object(
            LIVE, "aws_json", return_value={"Buckets": []}
        ):
            with self.assertRaisesRegex(LIVE.LiveTestError, "ECR repository"):
                LIVE.assert_no_account_live_state_for_init(
                    "bft-fresh2", "111122223333", "aws", "us-west-2"
                )
        ecr_arguments = pages.call_args_list[3].args[0]
        self.assertEqual(
            ecr_arguments[ecr_arguments.index("--registry-id") + 1],
            "111122223333",
        )

    def test_empty_local_state_still_rejects_known_bootstrap_stack_in_aws(self):
        stack = {
            "StackName": "bridgefu-bft-20990101a-bootstrap",
            "StackId": (
                "arn:aws:cloudformation:us-west-2:111122223333:stack/"
                "bridgefu-bft-20990101a-bootstrap/"
                "12345678-1234-1234-1234-123456789abc"
            ),
            "StackStatus": "CREATE_COMPLETE",
        }
        with mock.patch.object(
            LIVE, "recovery_paginated_items", side_effect=[[], [], []]
        ), mock.patch.object(
            LIVE, "recovery_stack_history", return_value=[stack]
        ), mock.patch.object(LIVE, "aws_json") as buckets:
            with self.assertRaisesRegex(LIVE.LiveTestError, "CloudFormation stack"):
                LIVE.assert_no_account_live_state_for_init(
                    "bft-fresh2", "111122223333", "aws", "us-west-2"
                )
        buckets.assert_not_called()

    def test_empty_local_state_rejects_reuse_from_delete_complete_history(self):
        execution_id = "bft-retired1"
        stack = {
            "StackName": f"bridgefu-{execution_id}-bootstrap",
            "StackId": (
                "arn:aws:cloudformation:us-west-2:111122223333:stack/"
                f"bridgefu-{execution_id}-bootstrap/"
                "12345678-1234-1234-1234-123456789abc"
            ),
            "StackStatus": "DELETE_COMPLETE",
        }
        with mock.patch.object(
            LIVE, "recovery_paginated_items", side_effect=[[], [], []]
        ), mock.patch.object(
            LIVE, "recovery_stack_history", return_value=[stack]
        ), mock.patch.object(LIVE, "aws_json") as later_inventory:
            with self.assertRaisesRegex(LIVE.LiveTestError, "fresh execution ID"):
                LIVE.assert_no_account_live_state_for_init(
                    execution_id, "111122223333", "aws", "us-west-2"
                )
        later_inventory.assert_not_called()

    def test_account_init_gate_rejects_cloudformation_managed_tagged_leftover(self):
        leftover = {
            "ResourceARN": (
                "arn:aws:ec2:us-west-2:111122223333:network-interface/eni-1234"
            )
        }
        with mock.patch.object(
            LIVE, "recovery_paginated_items", side_effect=[[], [], [leftover]]
        ), mock.patch.object(LIVE, "recovery_stack_history") as stacks:
            with self.assertRaisesRegex(LIVE.LiveTestError, "test-owned resources"):
                LIVE.assert_no_account_live_state_for_init(
                    "bft-fresh2", "111122223333", "aws", "us-west-2"
                )
        stacks.assert_not_called()


if __name__ == "__main__":
    unittest.main()
