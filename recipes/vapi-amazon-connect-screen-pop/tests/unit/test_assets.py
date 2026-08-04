from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

import yaml


RECIPE = Path(__file__).resolve().parents[2]
COMMON = RECIPE / "lambda" / "common"
sys.path.insert(0, str(COMMON))

from bridgefu_handoff import DISPLAY_FIELDS, RETURN_FIELDS  # noqa: E402


def load_template(relative: str):
    return json.loads((RECIPE / relative).read_text())


class CfnLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def construct_cfn_tag(loader, _suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


CfnLoader.add_multi_constructor("!", construct_cfn_tag)


class RecipeAssetContractTests(unittest.TestCase):
    def test_agent_workspace_supports_two_step_native_connect_login(self):
        source = (RECIPE / "qualification/agent-workspace-playwright.mjs").read_text()
        fill_username = source.index("await username.fill(credential.username)")
        continue_username = source.index(
            'await clickButton(page, [/^Next$/i, /^Continue$/i])'
        )
        wait_for_password = source.index(
            'await password.waitFor({ state: "visible"', continue_username
        )
        fill_password = source.index(
            "await password.fill(credential.password)", wait_for_password
        )
        self.assertLess(fill_username, continue_username)
        self.assertLess(continue_username, wait_for_password)
        self.assertLess(wait_for_password, fill_password)

    def test_agent_workspace_requires_api_selected_available_without_menu_clicks(self):
        source = (RECIPE / "qualification/agent-workspace-playwright.mjs").read_text()
        ensure = source.split("async function ensureAvailable", 1)[1].split(
            "async function endControlVisible", 1
        )[0]
        self.assertIn('await visibleExact(page, "Available")', ensure)
        self.assertIn('await buttonVisible(page, [/^Available$/i])', ensure)
        self.assertNotIn("clickButton", ensure)

    def test_cloudformation_templates_have_unique_mapping_keys(self):
        templates = sorted((RECIPE / "cloudformation").glob("*.yaml"))
        templates.extend(sorted((RECIPE / "cloudformation/nested").glob("*.yaml")))
        self.assertGreaterEqual(len(templates), 14)
        for template in templates:
            with self.subTest(template=template.name):
                yaml.load(template.read_text(), Loader=CfnLoader)

    def test_cloudformation_templates_are_ascii_stable_for_service_round_trip(self):
        templates = sorted((RECIPE / "cloudformation").glob("*.yaml"))
        templates.extend(sorted((RECIPE / "cloudformation/nested").glob("*.yaml")))
        self.assertGreaterEqual(len(templates), 14)
        for template in templates:
            with self.subTest(template=template.name):
                template.read_bytes().decode("ascii")

    def test_bootstrap_deployment_permissions_fit_managed_policy_limits(self):
        source = (
            RECIPE / "cloudformation/test-deployment-role.yaml"
        ).read_text()
        template = yaml.load(source, Loader=CfnLoader)
        resources = template["Resources"]
        deployment = resources["DeploymentRole"]["Properties"]
        self.assertNotIn("Policies", deployment)
        self.assertEqual(len(deployment["ManagedPolicyArns"]), 2)
        cloudformation = resources["CloudFormationExecutionRole"]["Properties"]
        self.assertNotIn("Policies", cloudformation)
        self.assertEqual(len(cloudformation["ManagedPolicyArns"]), 7)
        self.assertEqual(
            cloudformation["AssumeRolePolicyDocument"]["Statement"][0][
                "Principal"
            ],
            {"Service": "cloudformation.amazonaws.com"},
        )
        managed = [
            resource
            for resource in resources.values()
            if resource["Type"] == "AWS::IAM::ManagedPolicy"
        ]
        self.assertEqual(len(managed), 7)
        for policy in managed:
            encoded = json.dumps(
                policy["Properties"]["PolicyDocument"], separators=(",", ":")
            )
            self.assertLessEqual(len(encoded), 6144)
        self.assertNotIn("role/bridgefu-${ExecutionId}-*", source)
        self.assertIn("PassExactCloudFormationExecutionRole", source)
        self.assertIn("iam:PassedToService", source)
        for action in (
            "cloudformation:DetectStackDrift",
            "cloudformation:DescribeStackDriftDetectionStatus",
            "cloudformation:GetStackPolicy",
            "cloudformation:SetStackPolicy",
        ):
            self.assertIn(action, source)
        self.assertIn("ManageExactConnectLogGroup", source)
        self.assertIn("/aws/connect/${ExecutionId}-connect", source)
        self.assertEqual(source.count("connect:PutUserStatus"), 1)
        self.assertEqual(source.count("connect:ListAgentStatuses"), 1)
        self.assertIn(
            "instance/*/agent-state/*'",
            source,
        )

        compute_statements = resources["DeploymentComputePolicy"]["Properties"][
            "PolicyDocument"
        ]["Statement"]
        service_linked_role = next(
            statement
            for statement in compute_statements
            if statement.get("Sid") == "CreateRequiredServiceLinkedRoles"
        )
        self.assertEqual(service_linked_role["Action"], "iam:CreateServiceLinkedRole")
        self.assertIn(
            "events.amazonaws.com",
            service_linked_role["Condition"]["StringEquals"][
                "iam:AWSServiceName"
            ],
        )

    def test_vpc_no_source_qualification_runner_disables_local_cache(self):
        template = yaml.load(
            (
                RECIPE
                / "cloudformation/nested/qualification-runner.yaml"
            ).read_text(),
            Loader=CfnLoader,
        )
        project = template["Resources"]["QualificationProject"]["Properties"]
        self.assertEqual(project["Source"]["Type"], "NO_SOURCE")
        self.assertIn("VpcConfig", project)
        self.assertEqual(project["Cache"], {"Type": "NO_CACHE"})
        self.assertNotIn("\ncache:", project["Source"]["BuildSpec"])
        self.assertNotIn("set -euo pipefail", project["Source"]["BuildSpec"])
        self.assertIn(
            "aws s3api get-object", project["Source"]["BuildSpec"]
        )

    def test_vapi_tools_leave_destination_and_correlation_server_owned(self):
        prepare = load_template("vapi/prepare-handoff-tool.json.tmpl")
        schema = prepare["function"]["parameters"]
        self.assertEqual(prepare["type"], "function")
        self.assertEqual(prepare["function"]["name"], "prepare_handoff")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), set(DISPLAY_FIELDS))
        self.assertEqual(set(schema["properties"]), set(DISPLAY_FIELDS))
        self.assertNotIn("correlation", json.dumps(schema).lower())
        self.assertNotIn("route", schema["properties"])
        self.assertNotIn("sip", schema["properties"])
        self.assertEqual(prepare["server"]["timeoutSeconds"], 10)
        self.assertNotIn("timeoutSeconds", set(prepare) - {"server"})

        transfer = load_template("vapi/transfer-tool.json.tmpl")
        self.assertEqual(transfer["type"], "transferCall")
        self.assertEqual(transfer["destinations"], [])

    def test_vapi_assistant_uses_exact_tools_and_transfer_event(self):
        assistant = load_template("vapi/assistant.json.tmpl")
        self.assertEqual(
            assistant["model"]["toolIds"],
            ["__PREPARE_TOOL_ID__"],
        )
        transfer = load_template("vapi/transfer-tool.json.tmpl")
        self.assertEqual(assistant["model"]["tools"], [transfer])
        self.assertEqual(
            assistant["serverMessages"], ["transfer-destination-request"]
        )
        self.assertEqual(
            assistant["server"]["credentialId"],
            "__WEBHOOK_CREDENTIAL_ID__",
        )
        self.assertFalse(assistant["artifactPlan"]["recordingEnabled"])

    def test_connect_wrapper_fails_open_to_customer_flow(self):
        wrapper = load_template("connect/inbound-flow.json.tmpl")
        actions = {item["Identifier"]: item for item in wrapper["Actions"]}
        self.assertEqual(actions["lookup-context"]["Type"], "InvokeLambdaFunction")
        self.assertEqual(
            actions["set-agent-guide"]["Type"], "UpdateContactEventHooks"
        )
        self.assertEqual(
            actions["set-agent-guide"]["Parameters"]["EventHooks"],
            {"DefaultAgentUI": "__AGENT_GUIDE_FLOW_ARN__"},
        )
        transfer = actions["transfer-to-customer-flow"]
        self.assertEqual(transfer["Type"], "TransferToFlow")
        self.assertEqual(
            transfer["Parameters"]["ContactFlowId"],
            "__TARGET_CONTACT_FLOW_ARN__",
        )
        lookup_error = actions["lookup-context"]["Transitions"]["Errors"][0]
        self.assertEqual(lookup_error["NextAction"], "context-unavailable")
        unavailable = actions["context-unavailable"]["Parameters"]["Attributes"]
        self.assertEqual(unavailable["context_available"], "false")
        self.assertEqual(unavailable["vapi_call_reference"], "unavailable")
        self.assertNotIn("", unavailable.values())
        self.assertEqual(
            actions["context-unavailable"]["Transitions"]["NextAction"],
            "set-agent-guide",
        )

    def test_connect_guide_and_lambda_outputs_share_exact_fields(self):
        guide = load_template("connect/agent-guide-flow.json.tmpl")
        show = next(item for item in guide["Actions"] if item["Type"] == "ShowView")
        serialized = json.dumps(show["Parameters"]["ViewData"])
        for field in RETURN_FIELDS:
            self.assertIn(f"$.Attributes.{field}", serialized)
        self.assertIn("$.Attributes.context_available", serialized)

        contract = load_template("handoff-contract.json")
        self.assertEqual(
            set(contract["required"]), {"correlation_id", *RETURN_FIELDS}
        )
        self.assertEqual(
            set(contract["properties"]),
            {"correlation_id", *RETURN_FIELDS, "expires_at"},
        )

    def test_cloudformation_connect_flows_cannot_drift_from_canonical_assets(self):
        template = yaml.load(
            (RECIPE / "cloudformation/nested/connect.yaml").read_text(),
            Loader=CfnLoader,
        )
        embedded_guide = json.loads(
            template["Resources"]["AgentGuideFlow"]["Properties"]["Content"]
        )
        self.assertEqual(
            embedded_guide,
            load_template("connect/agent-guide-flow.json.tmpl"),
        )

        embedded_entry = json.loads(
            template["Resources"]["WrapperEntryFlow"]["Properties"]["Content"]
        )
        canonical_entry = load_template("connect/inbound-flow.json.tmpl")
        serialized = json.dumps(canonical_entry)
        replacements = {
            "__LOOKUP_LAMBDA_ARN__": "${LookupFunctionArn}",
            "__AGENT_GUIDE_FLOW_ARN__": "${AgentGuideFlow.ContactFlowArn}",
            "__TARGET_CONTACT_FLOW_ARN__": "${TargetContactFlowArn}",
        }
        for old, new in replacements.items():
            serialized = serialized.replace(old, new)
        self.assertEqual(embedded_entry, json.loads(serialized))

    def test_root_stack_references_only_owned_nested_templates(self):
        root = yaml.load(
            (RECIPE / "cloudformation/template.yaml").read_text(),
            Loader=CfnLoader,
        )
        expected = {
            "network.yaml",
            "handoff-service.yaml",
            "connect.yaml",
            "runtime-starter.yaml",
            "runtime-ha.yaml",
            "vapi.yaml",
            "observability.yaml",
            "observability-ha.yaml",
            "demo-site.yaml",
        }
        observed = set()
        for resource in root["Resources"].values():
            if resource["Type"] == "AWS::CloudFormation::Stack":
                observed.add(resource["Properties"]["TemplateURL"].rsplit("/", 1)[-1])
        self.assertEqual(observed, expected)
        for name in observed:
            self.assertTrue((RECIPE / "cloudformation/nested" / name).is_file())

        forbidden_outputs = {"secret", "token", "password", "correlation"}
        for output in root["Outputs"]:
            lowered = output.lower()
            self.assertFalse(
                any(needle in lowered for needle in forbidden_outputs),
                output,
            )

    def test_full_demo_is_explicit_and_separate_from_existing_connect_default(self):
        production = yaml.load(
            (RECIPE / "cloudformation/template.yaml").read_text(),
            Loader=CfnLoader,
        )
        production_text = json.dumps(production)
        self.assertNotIn("AWS::Connect::Instance", production_text)
        self.assertIn("ConnectInstanceArn", production["Parameters"])
        self.assertIn(
            "customer-owned",
            production["Parameters"]["TargetContactFlowArn"][
                "Description"
            ].lower(),
        )
        self.assertEqual(
            production["Parameters"]["LambdaReservedConcurrencyPerFunction"][
                "Default"
            ],
            20,
        )

        demo = yaml.load(
            (RECIPE / "cloudformation/demo-template.yaml").read_text(),
            Loader=CfnLoader,
        )
        acknowledgement = demo["Parameters"]["DemoAcknowledgement"]
        self.assertEqual(acknowledgement["Default"], "NOT_ACKNOWLEDGED")
        self.assertIn(
            "CREATE_NONPRODUCTION_CONNECT", acknowledgement["AllowedValues"]
        )
        self.assertEqual(
            demo["Resources"]["RecipeApplication"]["Properties"]["Parameters"][
                "DataRetentionMode"
            ],
            "TestDelete",
        )
        self.assertEqual(
            demo["Resources"]["RecipeApplication"]["Properties"]["Parameters"][
                "RetainVapiResourcesOnDelete"
            ],
            "false",
        )
        self.assertEqual(
            demo["Parameters"]["LambdaReservedConcurrencyPerFunction"]["Default"],
            0,
        )
        self.assertEqual(
            demo["Resources"]["RecipeApplication"]["Properties"]["Parameters"][
                "LambdaReservedConcurrencyPerFunction"
            ],
            "LambdaReservedConcurrencyPerFunction",
        )
        self.assertNotIn("QualificationRunner", demo["Resources"])
        for parameter in (
            "QualificationArtifactKey",
            "QualificationArtifactVersion",
            "QualificationArtifactSha256",
            "QualificationRunnerRoleArn",
            "QualificationSourceEipAllocationId",
            "QualificationSourceEipPublicIp",
        ):
            self.assertNotIn(parameter, demo["Parameters"])
        self.assertFalse(
            any(name.startswith("Qualification") for name in demo["Outputs"])
        )

        runner = yaml.load(
            (
                RECIPE / "cloudformation/nested/qualification-runner.yaml"
            ).read_text(),
            Loader=CfnLoader,
        )
        self.assertIn("QualificationProject", runner["Resources"])
        self.assertFalse(
            any(
                resource["Type"] == "AWS::CloudFormation::Stack"
                for resource in runner["Resources"].values()
            )
        )

        handoff = yaml.load(
            (RECIPE / "cloudformation/nested/handoff-service.yaml").read_text(),
            Loader=CfnLoader,
        )
        for function in ("PrepareFunction", "TransferFunction", "LookupFunction"):
            self.assertEqual(
                handoff["Resources"][function]["Properties"][
                    "ReservedConcurrentExecutions"
                ][0],
                "UseReservedConcurrency",
            )

        for logical_id in ("VapiResources", "DemoSite"):
            self.assertEqual(
                production["Resources"][logical_id]["Properties"]["Parameters"][
                    "LambdaReservedConcurrencyPerFunction"
                ],
                "LambdaReservedConcurrencyPerFunction",
            )

        for filename, function in (
            ("vapi.yaml", "ProvisionerFunction"),
            ("demo-site.yaml", "PublisherFunction"),
        ):
            nested = yaml.load(
                (RECIPE / "cloudformation/nested" / filename).read_text(),
                Loader=CfnLoader,
            )
            self.assertEqual(
                nested["Parameters"]["LambdaReservedConcurrencyPerFunction"][
                    "Default"
                ],
                0,
            )
            self.assertEqual(
                nested["Resources"][function]["Properties"][
                    "ReservedConcurrentExecutions"
                ][0],
                "UseReservedConcurrency",
            )
            if filename == "vapi.yaml":
                self.assertEqual(
                    nested["Resources"][function]["Properties"]["Timeout"],
                    240,
                )

        connect = yaml.load(
            (RECIPE / "cloudformation/nested/demo-connect.yaml").read_text(),
            Loader=CfnLoader,
        )
        connect_logs = connect["Resources"]["DemoConnectLogGroup"]
        self.assertEqual(connect_logs["Type"], "AWS::Logs::LogGroup")
        self.assertEqual(
            connect_logs["Properties"]["LogGroupName"],
            "/aws/connect/${DeploymentId}-connect",
        )
        self.assertEqual(connect_logs["Properties"]["RetentionInDays"], 7)
        self.assertEqual(connect_logs["DeletionPolicy"], "Delete")
        self.assertEqual(
            connect["Resources"]["DemoInstance"]["DependsOn"],
            "DemoConnectLogGroup",
        )
        self.assertEqual(
            connect["Resources"]["DemoInstance"]["Type"],
            "AWS::Connect::Instance",
        )
        self.assertEqual(
            connect["Resources"]["DemoInstance"]["DeletionPolicy"], "Delete"
        )
        target_flow = json.loads(
            connect["Resources"]["DemoTargetFlow"]["Properties"]["Content"]
        )
        actions = {action["Identifier"]: action for action in target_flow["Actions"]}
        self.assertEqual(
            actions["set-demo-queue"]["Type"], "UpdateContactTargetQueue"
        )
        self.assertEqual(
            actions["transfer-to-demo-queue"]["Type"],
            "TransferContactToQueue",
        )
        serialized_outputs = json.dumps(demo["Outputs"])
        self.assertNotIn("resolve:secretsmanager", serialized_outputs)
        self.assertNotIn("SecretString", serialized_outputs)

    def test_persistent_nonproduction_connect_is_a_separate_foundation(self):
        foundation = yaml.load(
            (
                RECIPE / "cloudformation/nonproduction-foundation.yaml"
            ).read_text(),
            Loader=CfnLoader,
        )
        acknowledgement = foundation["Parameters"]["FoundationAcknowledgement"]
        self.assertEqual(acknowledgement["Default"], "NOT_ACKNOWLEDGED")
        self.assertIn(
            "CREATE_PERSISTENT_NONPRODUCTION_CONNECT",
            acknowledgement["AllowedValues"],
        )
        resources = foundation["Resources"]
        self.assertEqual(set(resources), {"ConnectFoundation"})
        self.assertEqual(
            resources["ConnectFoundation"]["Type"],
            "AWS::CloudFormation::Stack",
        )
        self.assertIn(
            "demo-connect.yaml",
            resources["ConnectFoundation"]["Properties"]["TemplateURL"],
        )
        serialized = json.dumps(foundation)
        self.assertNotIn("RecipeApplication", serialized)
        self.assertNotIn("QualificationRunner", serialized)

    def test_account_governance_baseline_is_durable_and_cost_aware(self):
        governance = yaml.load(
            (
                RECIPE / "cloudformation/account-governance.yaml"
            ).read_text(),
            Loader=CfnLoader,
        )
        resources = governance["Resources"]
        expected_types = {
            "AWS::CloudTrail::Trail",
            "AWS::Config::ConfigurationRecorder",
            "AWS::Config::DeliveryChannel",
            "AWS::AccessAnalyzer::Analyzer",
            "AWS::GuardDuty::Detector",
            "AWS::SecurityHub::Hub",
            "AWS::Budgets::Budget",
        }
        self.assertTrue(
            expected_types.issubset(
                {resource["Type"] for resource in resources.values()}
            )
        )
        bucket = resources["AuditBucket"]
        self.assertEqual(bucket["DeletionPolicy"], "Retain")
        self.assertEqual(
            bucket["Properties"]["VersioningConfiguration"]["Status"],
            "Enabled",
        )
        trail = resources["AuditTrail"]["Properties"]
        self.assertTrue(trail["IsLogging"])
        self.assertTrue(trail["IsMultiRegionTrail"])
        self.assertTrue(trail["EnableLogFileValidation"])
        self.assertIn(
            "ConfigRecorder", resources["ConfigDeliveryChannel"]["DependsOn"]
        )
        self.assertNotIn("DependsOn", resources["ConfigRecorder"])
        bucket_policy = json.dumps(
            resources["AuditBucketPolicy"]["Properties"]["PolicyDocument"]
        )
        self.assertGreaterEqual(
            bucket_policy.count('"s3:x-amz-acl": "bucket-owner-full-control"'),
            2,
        )
        notifications = resources["MonthlyBudget"]["Properties"][
            "NotificationsWithSubscribers"
        ]
        self.assertEqual(
            [entry["Notification"]["Threshold"] for entry in notifications],
            [50, 80, 100],
        )

    def test_account_foundation_is_persistent_and_oidc_bound(self):
        foundation = yaml.load(
            (RECIPE / "cloudformation/account-foundation.yaml").read_text(),
            Loader=CfnLoader,
        )
        resources = foundation["Resources"]
        bucket = resources["ArtifactBucket"]
        repository = resources["ImageRepository"]
        self.assertEqual(bucket["DeletionPolicy"], "Retain")
        self.assertEqual(repository["DeletionPolicy"], "Retain")
        self.assertEqual(
            bucket["Properties"]["VersioningConfiguration"], {"Status": "Enabled"}
        )
        self.assertEqual(repository["Properties"]["ImageTagMutability"], "IMMUTABLE")
        self.assertTrue(
            repository["Properties"]["ImageScanningConfiguration"]["ScanOnPush"]
        )
        permissions = resources["DeploymentPermissions"]["Properties"]
        self.assertIn("test-deployment-role.yaml", permissions["TemplateURL"])
        self.assertEqual(permissions["Parameters"]["ConnectMode"], "Existing")
        self.assertEqual(
            permissions["Parameters"]["ArtifactAccessMode"],
            "PersistentReadOnly",
        )
        self.assertEqual(
            permissions["Parameters"]["EnableQualificationRunner"],
            ["NonproductionEnvironment", "true", "false"],
        )
        for output in (
            "QualificationRoleArn",
            "QualificationRunnerRoleArn",
            "QualificationSourceEipAllocationId",
            "QualificationSourceEipPublicIp",
        ):
            self.assertIn(output, foundation["Outputs"])
        self.assertEqual(
            permissions["Parameters"]["GitHubRepository"], "eisenzopf/bridgefu"
        )

        roles = yaml.load(
            (RECIPE / "cloudformation/test-deployment-role.yaml").read_text(),
            Loader=CfnLoader,
        )
        trust = roles["Resources"]["DeploymentRole"]["Properties"][
            "AssumeRolePolicyDocument"
        ]["Statement"]
        serialized = json.dumps(trust)
        self.assertIn("sts:AssumeRoleWithWebIdentity", serialized)
        self.assertIn("token.actions.githubusercontent.com:sub", serialized)
        self.assertIn("repo:${GitHubRepository}:environment:${GitHubEnvironment}", serialized)
        control = roles["Resources"]["DeploymentControlPolicy"]["Properties"][
            "PolicyDocument"
        ]["Statement"]
        serialized_control = json.dumps(control)
        for action in (
            "organizations:DescribeOrganization",
            "cloudtrail:GetTrailStatus",
            "config:DescribeConfigurationRecorderStatus",
            "access-analyzer:ListAnalyzers",
            "budgets:ViewBudget",
            "guardduty:GetDetector",
            "securityhub:DescribeHub",
            "servicequotas:GetServiceQuota",
            "lambda:GetAccountSettings",
            "cloudwatch:DescribeAlarms",
        ):
            self.assertIn(action, serialized_control)

    def test_nonproduction_starter_is_direct_ip_clear_sip_without_public_dns(self):
        parameters = {
            entry["ParameterKey"]: entry["ParameterValue"]
            for entry in json.loads(
                (RECIPE / "parameters-nonproduction-starter.json").read_text()
            )
        }
        self.assertEqual(parameters["RuntimeProfile"], "Starter")
        self.assertEqual(parameters["SipSecurity"], "sip_rtp")
        self.assertEqual(parameters["PublicHostedZoneId"], "none")
        self.assertEqual(parameters["SipHostname"], "unused.bridgefu.invalid")

        roles = yaml.load(
            (RECIPE / "cloudformation/test-deployment-role.yaml").read_text(),
            Loader=CfnLoader,
        )
        self.assertEqual(
            roles["Resources"]["QualificationSourceEip"]["Condition"],
            "CreateQualificationRunner",
        )
        self.assertEqual(
            roles["Resources"]["QualificationRunnerRole"]["Condition"],
            "CreateQualificationRunner",
        )

        runtime = yaml.load(
            (RECIPE / "cloudformation/nested/runtime-starter.yaml").read_text(),
            Loader=CfnLoader,
        )
        self.assertEqual(runtime["Resources"]["PublicCertificate"]["Condition"], "SecureSip")
        self.assertEqual(runtime["Resources"]["SipDnsRecord"]["Condition"], "HasPublicDns")

        observability = yaml.load(
            (RECIPE / "cloudformation/nested/observability.yaml").read_text(),
            Loader=CfnLoader,
        )
        self.assertEqual(
            observability["Resources"]["CertificateExpiryAlarm"]["Condition"],
            "SecureSip",
        )

    def test_starter_readiness_uses_ec2_creation_policy_not_wait_condition(self):
        template = yaml.load(
            (
                RECIPE / "cloudformation/nested/runtime-starter.yaml"
            ).read_text(),
            Loader=CfnLoader,
        )
        resources = template["Resources"]
        self.assertFalse(
            any(
                resource["Type"]
                in {
                    "AWS::CloudFormation::WaitCondition",
                    "AWS::CloudFormation::WaitConditionHandle",
                }
                for resource in resources.values()
            )
        )
        instance = resources["GatewayInstance"]
        self.assertEqual(
            instance["CreationPolicy"],
            {"ResourceSignal": {"Count": 1, "Timeout": "PT30M"}},
        )
        self.assertEqual(instance["DependsOn"], "GatewayEipAssociation")
        self.assertEqual(
            instance["Properties"]["NetworkInterfaces"],
            [{"DeviceIndex": "0", "NetworkInterfaceId": "GatewayNetworkInterface"}],
        )
        association = resources["GatewayEipAssociation"]["Properties"]
        self.assertEqual(
            association["NetworkInterfaceId"], "GatewayNetworkInterface"
        )
        self.assertNotIn("InstanceId", association)
        statements = resources["GatewayRole"]["Properties"]["Policies"][0][
            "PolicyDocument"
        ]["Statement"]
        signal = next(
            statement
            for statement in statements
            if isinstance(statement, dict)
            and statement.get("Sid") == "SignalOnlyThisRuntimeStack"
        )
        self.assertEqual(signal["Action"], "cloudformation:SignalResource")
        self.assertEqual(signal["Resource"], "AWS::StackId")
        user_data = instance["Properties"]["UserData"]["Fn::Base64"]["Fn::Sub"][0]
        self.assertIn("aws cloudformation signal-resource", user_data)
        self.assertIn("--logical-resource-id GatewayInstance", user_data)

    def test_production_stack_policy_blocks_accidental_core_replacement_or_delete(self):
        policy = json.loads(
            (
                RECIPE / "cloudformation/production-stack-policy.json"
            ).read_text()
        )
        allow, deny = policy["Statement"]
        self.assertEqual(
            allow,
            {
                "Effect": "Allow",
                "Action": "Update:*",
                "Principal": "*",
                "Resource": "*",
            },
        )

        ha_data = yaml.load(
            (
                RECIPE / "cloudformation/nested/runtime-ha-data.yaml"
            ).read_text(),
            Loader=CfnLoader,
        )
        self.assertTrue(
            ha_data["Resources"]["ProductionDatabase"]["Properties"][
                "DeletionProtection"
            ]
        )
        self.assertEqual(
            set(deny["Action"]), {"Update:Replace", "Update:Delete"}
        )
        self.assertEqual(
            set(deny["Resource"]),
            {
                "LogicalResourceId/Network",
                "LogicalResourceId/HandoffService",
                "LogicalResourceId/ConnectIntegration",
                "LogicalResourceId/StarterRuntime",
                "LogicalResourceId/HighAvailabilityRuntime",
                "LogicalResourceId/VapiResources",
            },
        )

    def test_demo_site_is_optional_private_and_public_configuration_only(self):
        root = yaml.load(
            (RECIPE / "cloudformation/template.yaml").read_text(),
            Loader=CfnLoader,
        )
        self.assertEqual(root["Parameters"]["EnableDemoSite"]["Default"], "false")
        self.assertEqual(root["Resources"]["DemoSite"]["Condition"], "CreateDemoSite")
        self.assertEqual(root["Outputs"]["DemoSiteUrl"]["Condition"], "CreateDemoSite")

        site = yaml.load(
            (RECIPE / "cloudformation/nested/demo-site.yaml").read_text(),
            Loader=CfnLoader,
        )
        bucket = site["Resources"]["SiteBucket"]["Properties"]
        self.assertEqual(
            bucket["BucketName"],
            "bfu-${AWS::AccountId}-${AWS::Region}-${DeploymentId}-site",
        )
        self.assertEqual(
            bucket["PublicAccessBlockConfiguration"],
            {
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True,
            },
        )
        publisher = site["Resources"]["PublisherFunction"]["Properties"]["Code"][
            "ZipFile"
        ]
        self.assertIn('"vapi_public_key"', publisher)
        self.assertIn('"vapi_assistant_id"', publisher)
        for forbidden in (
            "VapiApiKeySecretArn",
            "BridgefuApiBearer",
            "private_key",
            "correlation_id",
        ):
            self.assertNotIn(forbidden, publisher)
        policy = site["Resources"]["SiteBucketPolicy"]["Properties"][
            "PolicyDocument"
        ]
        self.assertIn("cloudfront.amazonaws.com", json.dumps(policy))

        deployment_role = (
            RECIPE / "cloudformation/test-deployment-role.yaml"
        ).read_text()
        self.assertIn("ManageOnlyExactDemoSiteBucket", deployment_role)
        self.assertIn("ManageRecipeDemoCloudFront", deployment_role)
        self.assertIn("cloudfront:CreateDistribution", deployment_role)

    def test_ha_profile_is_bounded_multi_az_and_never_creates_connect(self):
        root = yaml.load(
            (RECIPE / "cloudformation/template.yaml").read_text(),
            Loader=CfnLoader,
        )
        self.assertEqual(
            root["Parameters"]["RuntimeProfile"]["AllowedValues"],
            ["Starter", "HighAvailability"],
        )
        self.assertEqual(root["Resources"]["StarterRuntime"]["Condition"], "StarterProfile")
        self.assertEqual(
            root["Resources"]["HighAvailabilityRuntime"]["Condition"],
            "HighAvailabilityProfile",
        )
        self.assertNotIn("AWS::Connect::Instance", json.dumps(root))

        edge = yaml.load(
            (RECIPE / "cloudformation/nested/runtime-ha-edge.yaml").read_text(),
            Loader=CfnLoader,
        )
        self.assertEqual(edge["Resources"]["GatewayEipA"]["Type"], "AWS::EC2::EIP")
        self.assertEqual(edge["Resources"]["GatewayEipB"]["Type"], "AWS::EC2::EIP")
        self.assertEqual(
            edge["Resources"]["WorkerLoadBalancer"]["Properties"]["Scheme"],
            "internal",
        )
        self.assertEqual(
            edge["Resources"]["SecureSipListener"]["Properties"]["Protocol"],
            "TCP",
        )
        self.assertEqual(
            edge["Resources"]["ControlListener"]["Properties"]["Protocol"],
            "TCP",
        )
        self.assertEqual(
            edge["Resources"]["ControlTargetGroup"]["Properties"]["Protocol"],
            "TCP",
        )

        data = yaml.load(
            (RECIPE / "cloudformation/nested/runtime-ha-data.yaml").read_text(),
            Loader=CfnLoader,
        )
        for database in ("ProductionDatabase", "TestDatabase"):
            properties = data["Resources"][database]["Properties"]
            self.assertTrue(properties["MultiAZ"])
            self.assertTrue(properties["StorageEncrypted"])
            self.assertFalse(properties["PubliclyAccessible"])
        for redis in ("ProductionRedis", "TestRedis"):
            properties = data["Resources"][redis]["Properties"]
            self.assertEqual(properties["Engine"], "valkey")
            self.assertEqual(properties["EngineVersion"], "7.2")
            self.assertTrue(properties["TransitEncryptionEnabled"])
            self.assertTrue(properties["AtRestEncryptionEnabled"])
            self.assertTrue(properties["AutomaticFailoverEnabled"])

        compute = yaml.load(
            (RECIPE / "cloudformation/nested/runtime-ha-compute.yaml").read_text(),
            Loader=CfnLoader,
        )
        services = {
            name
            for name, resource in compute["Resources"].items()
            if resource["Type"] == "AWS::ECS::Service"
        }
        self.assertEqual(
            services,
            {"GatewayServiceA", "GatewayServiceB", "WorkerServiceA", "WorkerServiceB"},
        )
        for task in ("GatewayTaskDefinition", "WorkerTaskDefinition"):
            container = compute["Resources"][task]["Properties"]["ContainerDefinitions"][0]
            self.assertTrue(container["ReadonlyRootFilesystem"])
            self.assertFalse(container["Privileged"])
            self.assertEqual(container["LinuxParameters"]["Capabilities"]["Drop"], ["ALL"])
        serialized = json.dumps(compute)
        self.assertNotIn("KeyName", serialized)
        self.assertIn("autoscaling:SetInstanceProtection", serialized)
        self.assertIn("LifecycleHook", serialized)

        observability = yaml.load(
            (RECIPE / "cloudformation/nested/observability-ha.yaml").read_text(),
            Loader=CfnLoader,
        )
        resources = observability["Resources"]
        self.assertEqual(
            resources["GatewayACapacity"]["Properties"]["MetricName"],
            "bridgefu_gateway_native_active_routes",
        )
        self.assertEqual(
            resources["WorkerACapacity"]["Properties"]["MetricName"],
            "bridgefu_private_egress_active_routes",
        )
        self.assertEqual(
            resources["CleanupBacklog"]["Properties"]["MetricName"],
            "bridgefu_amazon_durable_cleanups_pending",
        )

if __name__ == "__main__":
    unittest.main()
