from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "scripts" / "aws-recipe-live-test.py"
SPEC = importlib.util.spec_from_file_location("aws_recipe_template_submission", SCRIPT)
assert SPEC and SPEC.loader
LIVE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LIVE
SPEC.loader.exec_module(LIVE)


class CloudFormationSubmissionTests(unittest.TestCase):
    def test_nested_stack_parameter_and_output_contracts_are_exact(self):
        cloudformation = ROOT / "recipes/vapi-amazon-connect-screen-pop/cloudformation"
        templates = sorted(cloudformation.rglob("*.yaml"))
        documents = {
            template.name: LIVE.cloudformation_document(template)
            for template in templates
        }

        def nested_output_references(value, logical_id):
            if isinstance(value, dict):
                get_att = value.get("Fn::GetAtt")
                if isinstance(get_att, list) and get_att[0] == logical_id:
                    attribute = get_att[1]
                    if isinstance(attribute, str) and attribute.startswith("Outputs."):
                        yield attribute.removeprefix("Outputs.")
                for item in value.values():
                    yield from nested_output_references(item, logical_id)
            elif isinstance(value, list):
                for item in value:
                    yield from nested_output_references(item, logical_id)

        for parent_path in templates:
            parent = documents[parent_path.name]
            for logical_id, resource in parent.get("Resources", {}).items():
                if resource.get("Type") != "AWS::CloudFormation::Stack":
                    continue
                template_url = resource["Properties"]["TemplateURL"]
                if isinstance(template_url, dict):
                    template_url = template_url["Fn::Sub"]
                if isinstance(template_url, list):
                    template_url = template_url[0]
                child_name = template_url.rsplit("/", 1)[-1]
                self.assertIn(child_name, documents, parent_path.name)
                child = documents[child_name]
                supplied = set(resource["Properties"].get("Parameters", {}))
                accepted = set(child.get("Parameters", {}))
                required = {
                    name
                    for name, parameter in child.get("Parameters", {}).items()
                    if "Default" not in parameter
                }
                self.assertFalse(supplied - accepted, (parent_path.name, logical_id))
                self.assertFalse(required - supplied, (parent_path.name, logical_id))
                for output in nested_output_references(parent, logical_id):
                    self.assertIn(
                        output,
                        child.get("Outputs", {}),
                        (parent_path.name, logical_id, child_name),
                    )

    def test_certificate_evidence_is_mode_specific_and_always_affirmative(self):
        self.assertEqual(
            LIVE.certificate_evidence_checks("sip_rtp"),
            {"certificate_not_required_for_ip_only": True},
        )
        self.assertEqual(
            LIVE.certificate_evidence_checks("sips_srtp"),
            {"exportable_certificate_issued": True},
        )
        with self.assertRaises(LIVE.LiveTestError):
            LIVE.certificate_evidence_checks("unknown")

    def test_small_template_uses_file_body(self):
        with tempfile.TemporaryDirectory() as directory:
            template = Path(directory) / "small.yaml"
            template.write_text(
                "AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n"
            )
            self.assertEqual(
                LIVE.template_body_argument(template), f"file://{template}"
            )

    def test_oversized_template_is_compacted_with_intrinsics_preserved(self):
        template = (
            ROOT
            / "recipes/vapi-amazon-connect-screen-pop/cloudformation"
            / "test-deployment-role.yaml"
        )
        self.assertGreater(template.stat().st_size, LIVE.MAX_INLINE_TEMPLATE_BYTES)
        body = LIVE.template_body_argument(template)
        self.assertFalse(body.startswith("file://"))
        self.assertLessEqual(len(body.encode()), LIVE.MAX_INLINE_TEMPLATE_BYTES)
        document = json.loads(body)
        self.assertEqual(
            LIVE.canonical_template_sha256(template),
            LIVE.canonical_template_sha256(document),
        )
        self.assertEqual(
            LIVE.canonical_template_sha256(template),
            LIVE.canonical_template_sha256(body),
        )
        role = document["Resources"]["DeploymentRole"]
        self.assertEqual(
            role["Properties"]["RoleName"]["Fn::Sub"],
            "bridgefu-${ExecutionId}-deployer",
        )
        self.assertEqual(
            document["Outputs"]["DeploymentRoleArn"]["Value"]["Fn::GetAtt"],
            ["DeploymentRole", "Arn"],
        )

    def test_ephemeral_publication_can_manage_only_its_two_vapi_verification_secrets(
        self,
    ):
        template = (
            ROOT
            / "recipes/vapi-amazon-connect-screen-pop/cloudformation"
            / "test-deployment-role.yaml"
        )
        document = LIVE.cloudformation_document(template)
        statements = document["Resources"]["DeploymentArtifactPolicy"]["Properties"][
            "PolicyDocument"
        ]["Statement"]
        conditional = next(
            statement["Fn::If"]
            for statement in statements
            if isinstance(statement, dict)
            and "Fn::If" in statement
            and isinstance(statement["Fn::If"][1], dict)
            and statement["Fn::If"][1].get("Sid")
            == "ManageOnlyEphemeralVapiVerificationSecrets"
        )
        self.assertEqual(conditional[0], "ManageEphemeralArtifacts")
        self.assertEqual(conditional[2], {"Ref": "AWS::NoValue"})
        permission = conditional[1]
        self.assertEqual(set(permission), {"Sid", "Effect", "Action", "Resource"})
        self.assertEqual(permission["Effect"], "Allow")
        self.assertEqual(
            permission["Action"],
            [
                "secretsmanager:CreateSecret",
                "secretsmanager:DeleteSecret",
                "secretsmanager:DescribeSecret",
                "secretsmanager:GetSecretValue",
                "secretsmanager:TagResource",
            ],
        )
        self.assertEqual(
            permission["Resource"],
            [
                {
                    "Fn::Sub": "arn:${AWS::Partition}:secretsmanager:${AWS::Region}:"
                    "${AWS::AccountId}:secret:bridgefu-${ExecutionId}-vapi-api-key-*"
                },
                {
                    "Fn::Sub": "arn:${AWS::Partition}:secretsmanager:${AWS::Region}:"
                    "${AWS::AccountId}:secret:bridgefu-${ExecutionId}-vapi-public-key-*"
                },
            ],
        )

    def test_disposable_connect_and_qualifier_include_provider_and_runtime_actions(
        self,
    ):
        template = (
            ROOT
            / "recipes/vapi-amazon-connect-screen-pop/cloudformation"
            / "test-deployment-role.yaml"
        )
        document = LIVE.cloudformation_document(template)
        demo = document["Resources"]["DeploymentDemoPolicy"]["Properties"][
            "PolicyDocument"
        ]["Statement"]
        connect = next(
            item for item in demo if item.get("Sid") == "ManageDisposableConnect"
        )
        required_connect_actions = {
            "connect:AssociateHoursOfOperations",
            "connect:DisassociateHoursOfOperations",
            "connect:ListChildHoursOfOperations",
            "connect:UpdateUserConfig",
        }
        for action in required_connect_actions:
            with self.subTest(action=action):
                self.assertEqual(connect["Action"].count(action), 1)
                self.assertEqual(json.dumps(document).count(f'"{action}"'), 1)
        service_role = next(
            item
            for item in demo
            if item.get("Sid") == "ManageExactConnectServiceRolePolicy"
        )
        self.assertEqual(
            service_role["Action"], ["iam:DeleteRolePolicy", "iam:PutRolePolicy"]
        )

        qualifier = document["Resources"]["QualificationRole"]["Properties"][
            "Policies"
        ][0]["PolicyDocument"]["Statement"]
        by_sid = {
            item.get("Sid"): item
            for item in qualifier
            if isinstance(item, dict) and item.get("Sid")
        }
        self.assertEqual(
            by_sid["UseAwsRunShellScriptDocument"]["Action"], "ssm:SendCommand"
        )
        self.assertEqual(
            by_sid["CommandOnlyOwnedQualificationInstances"]["Action"],
            "ssm:SendCommand",
        )
        self.assertEqual(
            by_sid["RebootOnlyOwnedQualificationInstances"]["Action"],
            "ec2:RebootInstances",
        )
        self.assertIn(
            "arn:${AWS::Partition}:secretsmanager:${AWS::Region}:"
            "${AWS::AccountId}:secret:bridgefu-${ExecutionId}-vapi-api-key-*",
            [item["Fn::Sub"] for item in by_sid["ReadOnlyTestCredentials"]["Resource"]],
        )

    def test_starter_data_volume_is_attached_as_part_of_instance_creation(self):
        template = (
            ROOT
            / "recipes/vapi-amazon-connect-screen-pop/cloudformation/nested"
            / "runtime-starter.yaml"
        )
        document = LIVE.cloudformation_document(template)
        resources = document["Resources"]
        gateway = resources["GatewayInstance"]["Properties"]
        self.assertEqual(gateway["Volumes"][0]["Device"], "/dev/sdf")
        self.assertEqual(
            gateway["Volumes"][0]["VolumeId"]["Fn::If"],
            [
                "RetainData",
                {"Ref": "ProductionDataVolume"},
                {"Ref": "TestDataVolume"},
            ],
        )
        self.assertFalse(
            any(
                resource.get("Type") == "AWS::EC2::VolumeAttachment"
                for resource in resources.values()
            )
        )

    def test_disposable_demo_passes_bounded_starter_volume_sizes(self):
        template = (
            ROOT
            / "recipes/vapi-amazon-connect-screen-pop/cloudformation"
            / "demo-template.yaml"
        )
        document = LIVE.cloudformation_document(template)
        parameters = document["Parameters"]
        self.assertEqual(parameters["RootVolumeGiB"]["Default"], 12)
        self.assertEqual(parameters["DataVolumeGiB"]["Default"], 8)

        application_parameters = document["Resources"]["RecipeApplication"][
            "Properties"
        ]["Parameters"]
        self.assertEqual(application_parameters["RuntimeProfile"], "Starter")
        self.assertEqual(
            application_parameters["RootVolumeGiB"], {"Ref": "RootVolumeGiB"}
        )
        self.assertEqual(
            application_parameters["DataVolumeGiB"], {"Ref": "DataVolumeGiB"}
        )

        source = (
            SCRIPT.read_text()
            .split("def create_change_set(", 1)[1]
            .split('if ledger.get("connect_mode") == "disposable":', 1)[1]
            .split("change_set_name =", 1)[0]
        )
        self.assertIn('parameter("RootVolumeGiB", "12")', source)
        self.assertIn('parameter("DataVolumeGiB", "8")', source)

    def test_vapi_custom_resource_outputs_support_exact_external_teardown(self):
        template = (
            ROOT
            / "recipes/vapi-amazon-connect-screen-pop/cloudformation/nested"
            / "vapi.yaml"
        )
        document = LIVE.cloudformation_document(template)
        custom = document["Resources"]["VapiResources"]
        self.assertEqual(custom["Type"], "Custom::BridgefuVapiResources")
        self.assertEqual(
            custom["Properties"]["RetainVapiResourcesOnDelete"],
            {"Ref": "RetainVapiResourcesOnDelete"},
        )
        self.assertEqual(
            document["Parameters"]["RetainVapiResourcesOnDelete"]["Default"],
            "false",
        )
        expected = {
            "AssistantId": "AssistantId",
            "PrepareToolId": "PrepareToolId",
            "WebhookCredentialId": "WebhookCredentialId",
        }
        for output, attribute in expected.items():
            self.assertEqual(
                document["Outputs"][output]["Value"],
                {"Fn::GetAtt": ["VapiResources", attribute]},
            )


if __name__ == "__main__":
    unittest.main()
