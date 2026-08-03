from __future__ import annotations

import importlib.util
import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "scripts" / "aws-recipe-live-test.py"
SPEC = importlib.util.spec_from_file_location("aws_recipe_live_test", SCRIPT)
assert SPEC and SPEC.loader
LIVE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LIVE
SPEC.loader.exec_module(LIVE)
RELEASE_SCRIPT = ROOT / "scripts" / "build-recipe-release.py"
RELEASE_SPEC = importlib.util.spec_from_file_location(
    "build_recipe_release", RELEASE_SCRIPT
)
assert RELEASE_SPEC and RELEASE_SPEC.loader
RELEASE = importlib.util.module_from_spec(RELEASE_SPEC)
sys.modules[RELEASE_SPEC.name] = RELEASE
RELEASE_SPEC.loader.exec_module(RELEASE)
DEMO_SCRIPT = ROOT / "scripts" / "build-recipe-demo-site.py"
DEMO_SPEC = importlib.util.spec_from_file_location(
    "build_recipe_demo_site", DEMO_SCRIPT
)
assert DEMO_SPEC and DEMO_SPEC.loader
DEMO = importlib.util.module_from_spec(DEMO_SPEC)
sys.modules[DEMO_SPEC.name] = DEMO
DEMO_SPEC.loader.exec_module(DEMO)
QUALIFICATION_SCRIPT = ROOT / "scripts" / "build-recipe-qualification.py"
QUALIFICATION_SPEC = importlib.util.spec_from_file_location(
    "build_recipe_qualification", QUALIFICATION_SCRIPT
)
assert QUALIFICATION_SPEC and QUALIFICATION_SPEC.loader
QUALIFICATION = importlib.util.module_from_spec(QUALIFICATION_SPEC)
sys.modules[QUALIFICATION_SPEC.name] = QUALIFICATION
QUALIFICATION_SPEC.loader.exec_module(QUALIFICATION)


class CfnLoader(yaml.SafeLoader):
    pass


def construct_cfn_tag(loader, _suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


CfnLoader.add_multi_constructor("!", construct_cfn_tag)


class ReleaseAndLiveGuardTests(unittest.TestCase):
    def test_bootstrap_log_permissions_cover_cloudwatch_resource_suffixes(self):
        template = yaml.load(
            (
                ROOT
                / "recipes"
                / "vapi-amazon-connect-screen-pop"
                / "cloudformation"
                / "test-deployment-role.yaml"
            ).read_text(),
            Loader=CfnLoader,
        )
        resources = template["Resources"]
        policy_documents = [
            resource["Properties"]["PolicyDocument"]
            for resource in resources.values()
            if resource.get("Type") == "AWS::IAM::ManagedPolicy"
        ]
        def mappings(value):
            if isinstance(value, dict):
                yield value
                for child in value.values():
                    yield from mappings(child)
            elif isinstance(value, list):
                for child in value:
                    yield from mappings(child)

        statements = [
            mapping
            for document in policy_documents
            for mapping in mappings(document["Statement"])
            if "Sid" in mapping
        ]
        by_sid = {statement.get("Sid"): statement for statement in statements}
        expected_sids = {
            "DeleteExactDisposableConnectLogFallback",
            "ManageRecipeLogsOnly",
            "ManageExactConnectLogGroup",
        }
        self.assertTrue(expected_sids.issubset(by_sid))
        for sid in expected_sids:
            statement = by_sid[sid]
            resources = statement["Resource"]
            if isinstance(resources, str):
                resources = [resources]
            self.assertTrue(resources)
            self.assertTrue(all(resource.endswith(":*") for resource in resources))

    def bootstrap_stack_id(self) -> str:
        return (
            "arn:aws:cloudformation:us-west-2:111122223333:stack/"
            "bridgefu-bft-safe1-bootstrap/12345678-1234-1234-1234-123456789abc"
        )

    def refresh_ledger(self) -> dict:
        return {
            "execution_id": "bft-safe1",
            "account_id": "111122223333",
            "partition": "aws",
            "region": "us-west-2",
            "status": "published",
            "stack_name": "bridgefu-bft-safe1",
            "bootstrap_stack_name": "bridgefu-bft-safe1-bootstrap",
            "bootstrap_stack_id": self.bootstrap_stack_id(),
            "trusted_principal_arn": ("arn:aws:iam::111122223333:role/RecoveryAdmin"),
            "release_id": "release-one",
            "publication_source_tree_sha256": "b" * 64,
            "connect_instance_arn": (
                "arn:aws:connect:us-west-2:111122223333:instance/unused"
            ),
            "connect_mode": "existing",
            "artifact_bucket": "bridgefu-recipe-111122223333-us-west-2-bft-safe1",
            "ecr_repository": "bridgefu-test/bft-safe1",
            "public_hosted_zone_id": "none",
            "enable_demo_site": False,
            "deployment_role_arn": (
                "arn:aws:iam::111122223333:role/bridgefu-bft-safe1-deployer"
            ),
            "qualification_role_arn": (
                "arn:aws:iam::111122223333:role/bridgefu-bft-safe1-qualifier"
            ),
        }

    def refresh_stack(self, ledger: dict) -> dict:
        parameters = LIVE.bootstrap_stack_parameters(
            ledger, ledger["trusted_principal_arn"]
        )
        return {
            "StackId": ledger["bootstrap_stack_id"],
            "StackName": ledger["bootstrap_stack_name"],
            "StackStatus": "UPDATE_COMPLETE",
            "Parameters": [
                {"ParameterKey": key, "ParameterValue": value}
                for key, value in parameters.items()
            ],
            "Outputs": [
                {
                    "OutputKey": "DeploymentRoleArn",
                    "OutputValue": ledger["deployment_role_arn"],
                },
                {
                    "OutputKey": "QualificationRoleArn",
                    "OutputValue": ledger["qualification_role_arn"],
                },
            ],
            "Tags": [
                {"Key": "Project", "Value": LIVE.PROJECT},
                {"Key": "ManagedBy", "Value": LIVE.MANAGED_BY},
                {"Key": "BridgefuExecutionId", "Value": ledger["execution_id"]},
                {"Key": "BridgefuRecipe", "Value": LIVE.RECIPE},
            ],
        }

    def test_access_analyzer_catalog_lag_waiver_is_exact_and_fail_closed(self):
        execution_id = "bft-safe1"
        connect_finding = {
            "policy": f"bridgefu-{execution_id}-deployer-demo",
            "findingType": "ERROR",
            "issueCode": "INVALID_ACTION",
            "findingDetails": (
                "The action connect:ListChildHoursOfOperations does not exist."
            ),
        }
        connect_reason = LIVE.access_analyzer_waiver_reason(
            connect_finding, execution_id
        )
        self.assertIsNotNone(connect_reason)
        self.assertIn("AWS::Connect::HoursOfOperation", connect_reason)
        self.assertIn("regional CloudFormation resource schema", connect_reason)

        update_findings = {
            "The action connect:AssociateHoursOfOperations does not exist.": (
                "AWS::Connect::HoursOfOperation"
            ),
            "The action connect:DisassociateHoursOfOperations does not exist.": (
                "AWS::Connect::HoursOfOperation"
            ),
            "The action connect:UpdateUserConfig does not exist.": (
                "AWS::Connect::User"
            ),
        }
        for details, resource_type in update_findings.items():
            with self.subTest(details=details):
                finding = {**connect_finding, "findingDetails": details}
                reason = LIVE.access_analyzer_waiver_reason(finding, execution_id)
                self.assertIsNotNone(reason)
                self.assertIn(resource_type, reason)
                self.assertIsNone(
                    LIVE.access_analyzer_waiver_reason(
                        {**finding, "findingDetails": details.rstrip(".")},
                        execution_id,
                    )
                )

        for details in (
            "The action connect:ListChildHoursOfOperation does not exist.",
            "The action connect:ListChildHoursOfOperations does not exist",
            "The action connect:* does not exist.",
        ):
            with self.subTest(details=details):
                self.assertIsNone(
                    LIVE.access_analyzer_waiver_reason(
                        {**connect_finding, "findingDetails": details}, execution_id
                    )
                )

        for mutation in (
            {"policy": f"bridgefu-{execution_id}-deployer-application"},
            {"findingType": "SECURITY_WARNING"},
            {"issueCode": "MISSING_ACTION_FOR_CONDITION_KEY"},
            {"findingDetails": None},
        ):
            with self.subTest(mutation=mutation):
                self.assertIsNone(
                    LIVE.access_analyzer_waiver_reason(
                        {**connect_finding, **mutation}, execution_id
                    )
                )

        unrelated_error = {
            "policy": f"bridgefu-{execution_id}-deployer-demo",
            "findingType": "ERROR",
            "issueCode": "INVALID_ACTION",
            "findingDetails": "The action connect:Typo does not exist.",
        }
        errors, waivers = LIVE.partition_access_analyzer_errors(
            [connect_finding, unrelated_error], execution_id
        )
        self.assertEqual(errors, [unrelated_error])
        self.assertEqual(len(waivers), 1)
        self.assertEqual(waivers[0]["policy"], connect_finding["policy"])
        self.assertEqual(waivers[0]["reason"], connect_reason)

    def test_access_analyzer_catalog_lag_waivers_retain_specific_evidence(self):
        execution_id = "bft-safe1"
        findings = {
            details: LIVE.access_analyzer_waiver_reason(
                {
                    "policy": f"bridgefu-{execution_id}-{policy_suffix}",
                    "findingType": "ERROR",
                    "issueCode": "INVALID_ACTION",
                    "findingDetails": details,
                },
                execution_id,
            )
            for details, (
                policy_suffix,
                _reason,
            ) in LIVE.ACCESS_ANALYZER_CATALOG_LAG_WAIVERS.items()
        }
        self.assertEqual(
            findings,
            {
                details: reason
                for details, (
                    _policy_suffix,
                    reason,
                ) in LIVE.ACCESS_ANALYZER_CATALOG_LAG_WAIVERS.items()
            },
        )
        self.assertIn(
            "AWS::ApiGatewayV2::Stage",
            findings["The action apigateway:TagResource does not exist."],
        )
        self.assertIn(
            "AWS::Connect::HoursOfOperation",
            findings["The action connect:ListChildHoursOfOperations does not exist."],
        )
        self.assertIn(
            "AWS::Connect::User",
            findings["The action connect:UpdateUserConfig does not exist."],
        )

    def test_docker_registry_credentials_use_a_temporary_private_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            user_config = root / "user-docker-config"
            local_plugins = user_config / "cli-plugins"
            extra_plugins = root / "extra-plugins"
            local_plugins.mkdir(parents=True)
            extra_plugins.mkdir()
            original_settings = json.dumps(
                {
                    "auths": {"registry.example": {"auth": "secret"}},
                    "credsStore": "desktop",
                    "credHelpers": {"registry.example": "helper"},
                    "cliPluginsExtraDirs": [str(extra_plugins)],
                },
                sort_keys=True,
            )
            (user_config / "config.json").write_text(original_settings)

            calls = []

            def docker_command(arguments, **kwargs):
                calls.append((arguments, kwargs.get("env", {})))
                if arguments == ["docker", "context", "show"]:
                    return mock.Mock(stdout="colima\n")
                if arguments[:3] == ["docker", "context", "export"]:
                    Path(arguments[-1]).write_bytes(b"exported-context")
                    return mock.Mock(stdout="")
                if arguments[:3] == ["docker", "context", "import"]:
                    imported_config = Path(kwargs["env"]["DOCKER_CONFIG"])
                    metadata = imported_config / "contexts" / "meta" / "only-context"
                    metadata.mkdir(parents=True)
                    (metadata / "meta.json").write_text(
                        '{"Name":"bridgefu-publication"}'
                    )
                    return mock.Mock(stdout="")
                self.fail(f"unexpected Docker operation: {arguments}")

            with mock.patch.dict(
                LIVE.os.environ, {"DOCKER_CONFIG": str(user_config)}, clear=True
            ), mock.patch.object(LIVE, "command", side_effect=docker_command):
                with LIVE.isolated_docker_environment(root) as environment:
                    config = Path(environment["DOCKER_CONFIG"])
                    self.assertNotEqual(config, user_config)
                    self.assertEqual(config.stat().st_mode & 0o777, 0o700)
                    self.assertEqual(
                        environment["DOCKER_CONTEXT"], "bridgefu-publication"
                    )
                    self.assertEqual(
                        (
                            config / "contexts" / "meta" / "only-context" / "meta.json"
                        ).read_text(),
                        '{"Name":"bridgefu-publication"}',
                    )
                    self.assertFalse((config / "active.dockercontext").exists())
                    temporary_settings = json.loads(
                        (config / "config.json").read_text()
                    )
                    self.assertEqual(set(temporary_settings), {"cliPluginsExtraDirs"})
                    self.assertEqual(
                        temporary_settings["cliPluginsExtraDirs"],
                        [str(local_plugins.resolve()), str(extra_plugins.resolve())],
                    )
                    self.assertEqual(LIVE.os.environ["DOCKER_CONFIG"], str(user_config))
                    temporary_settings["auths"] = {"temporary": {"auth": "token"}}
                    (config / "config.json").write_text(json.dumps(temporary_settings))
            self.assertEqual(calls[0][0], ["docker", "context", "show"])
            self.assertEqual(calls[1][0][2:4], ["export", "colima"])
            self.assertEqual(calls[1][1]["DOCKER_CONFIG"], str(user_config))
            self.assertEqual(calls[2][0][2:4], ["import", "bridgefu-publication"])
            self.assertNotIn("DOCKER_CONTEXT", calls[2][1])
            self.assertEqual(
                (user_config / "config.json").read_text(), original_settings
            )
            self.assertFalse(config.exists())

    def test_default_docker_context_preserves_an_explicit_host_without_export(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            LIVE.os.environ,
            {
                "DOCKER_CONFIG": str(Path(directory) / "missing-user-config"),
                "DOCKER_HOST": "unix:///private/docker.sock",
            },
            clear=True,
        ), mock.patch.object(
            LIVE, "command", return_value=mock.Mock(stdout="default\n")
        ) as command:
            with LIVE.isolated_docker_environment(Path(directory)) as environment:
                config = Path(environment["DOCKER_CONFIG"])
                self.assertEqual(
                    environment["DOCKER_HOST"], "unix:///private/docker.sock"
                )
                self.assertNotIn("DOCKER_CONTEXT", environment)
                self.assertFalse((config / "config.json").exists())
            self.assertEqual(command.call_count, 1)
            self.assertFalse(config.exists())

    def test_docker_context_import_failure_removes_private_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def docker_command(arguments, **_kwargs):
                if arguments == ["docker", "context", "show"]:
                    return mock.Mock(stdout="colima\n")
                if arguments[:3] == ["docker", "context", "export"]:
                    Path(arguments[-1]).write_bytes(b"exported-context")
                    return mock.Mock(stdout="")
                raise LIVE.LiveTestError("simulated context import failure")

            with mock.patch.dict(LIVE.os.environ, {}, clear=True), mock.patch.object(
                LIVE, "command", side_effect=docker_command
            ), self.assertRaisesRegex(LIVE.LiveTestError, "simulated"):
                with LIVE.isolated_docker_environment(root):
                    self.fail("context import unexpectedly succeeded")
            self.assertEqual(list(root.glob(".docker-config-*")), [])

    def test_demo_site_allows_only_target_or_marker_bound_release_staging(self):
        self.assertEqual(DEMO.RELEASE_STAGING_MARKER, RELEASE.STAGING_MARKER)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            root.mkdir()
            target_output = root / "target" / "demo-site"
            self.assertTrue(DEMO.output_is_allowed(target_output, root, None))

            staging = Path(directory) / "private-state" / ".release.candidate"
            output = staging / "artifacts" / "demo-site"
            staging.mkdir(parents=True)
            self.assertFalse(DEMO.output_is_allowed(output, root, staging))
            marker = staging / DEMO.RELEASE_STAGING_MARKER
            marker.write_text("bridgefu recipe release staging\n")
            self.assertTrue(DEMO.output_is_allowed(output, root, staging))
            self.assertFalse(DEMO.output_is_allowed(staging, root, staging))
            marker.write_text("wrong marker\n")
            self.assertFalse(DEMO.output_is_allowed(output, root, staging))

    def test_qualification_build_uses_native_builder_and_cross_target(self):
        builder_images = QUALIFICATION.qualification_builder_images(ROOT)
        builder_image = builder_images["linux/arm64"]
        self.assertEqual(
            builder_image,
            "ghcr.io/rust-cross/cargo-zigbuild@sha256:"
            "cd8eb227db9f70e7c098ed1d63cdfba3b85d73b1dcbc6aa59d8f9a92ae7dd50d",
        )
        header = bytearray(20)
        header[:6] = b"\x7fELF\x02\x01"
        header[18:20] = b"\x3e\x00"
        binary = bytes(header) + b"\0GLIBC_2.31\0"
        calls = []

        def docker_run(arguments, **_kwargs):
            calls.append(arguments)
            if arguments[:2] == ["docker", "info"]:
                return mock.Mock(stdout="linux/aarch64\n")
            if arguments[:3] == ["docker", "manifest", "inspect"]:
                return mock.Mock(
                    stdout=json.dumps(
                        {
                            "schemaVersion": 2,
                            "manifests": [
                                {
                                    "digest": builder_images["linux/amd64"].rsplit(
                                        "@", 1
                                    )[1],
                                    "platform": {
                                        "os": "linux",
                                        "architecture": "amd64",
                                    },
                                },
                                {
                                    "digest": builder_images["linux/arm64"].rsplit(
                                        "@", 1
                                    )[1],
                                    "platform": {
                                        "os": "linux",
                                        "architecture": "arm64",
                                    },
                                },
                            ],
                        }
                    )
                )
            if arguments[:3] == ["docker", "image", "inspect"]:
                return mock.Mock(stdout="linux/arm64\n")
            if arguments[:2] == ["docker", "create"]:
                return mock.Mock(stdout="a" * 64 + "\n")
            if arguments[:2] == ["docker", "cp"]:
                Path(arguments[-1]).write_bytes(binary)
            return mock.Mock(stdout="")

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            QUALIFICATION.subprocess, "run", side_effect=docker_run
        ):
            contract = QUALIFICATION.build_qualification_binaries(ROOT, Path(directory))

        self.assertEqual(contract["host_platform"], "linux/arm64")
        self.assertEqual(contract["image"], builder_image)
        self.assertEqual(contract["target"], "x86_64-unknown-linux-gnu.2.31")
        self.assertEqual(contract["rust_toolchain"], "1.95.0")
        self.assertEqual(contract["debian_snapshot"], "20260202T000000Z")
        self.assertEqual(
            contract["binary_glibc"],
            {
                "recipe_sip_source": "2.31",
                "recipe_sip_negative": "2.31",
            },
        )
        pull = next(call for call in calls if call[:2] == ["docker", "pull"])
        self.assertEqual(pull[-1], builder_image)
        self.assertEqual(pull[pull.index("--platform") + 1], "linux/arm64")
        build = next(call for call in calls if call[:2] == ["docker", "build"])
        self.assertEqual(
            build[build.index("--build-arg") + 1],
            f"QUALIFICATION_BUILDER_IMAGE={builder_image}",
        )
        self.assertNotIn("--platform", build)
        self.assertIn(str(ROOT / "deploy" / "Dockerfile.qualification"), build)
        create = next(call for call in calls if call[:2] == ["docker", "create"])
        self.assertNotIn("--platform", create)
        inspect = next(
            call for call in calls if call[:3] == ["docker", "manifest", "inspect"]
        )
        self.assertEqual(inspect[-1], builder_images["multi_platform_index"])

    def test_qualification_builder_pins_fail_closed(self):
        digest = "a" * 64
        parent = f"example.test/tool@sha256:{digest}"
        amd64 = f"example.test/tool@sha256:{'b' * 64}"
        arm64 = f"example.test/tool@sha256:{'c' * 64}"
        valid = (
            f"ARG QUALIFICATION_BUILDER_IMAGE={parent}\n"
            f"ARG QUALIFICATION_BUILDER_AMD64_IMAGE={amd64}\n"
            f"ARG QUALIFICATION_BUILDER_ARM64_IMAGE={arm64}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dockerfile = root / "deploy" / "Dockerfile.qualification"
            dockerfile.parent.mkdir()
            dockerfile.write_text(valid)
            self.assertEqual(
                QUALIFICATION.qualification_builder_images(root)["linux/amd64"],
                amd64,
            )
            dockerfile.write_text(valid.replace(amd64, "example.test/tool:latest", 1))
            with self.assertRaisesRegex(SystemExit, "unique pinned"):
                QUALIFICATION.qualification_builder_images(root)
            dockerfile.write_text(
                valid + f"ARG QUALIFICATION_BUILDER_ARM64_IMAGE={arm64}\n"
            )
            with self.assertRaisesRegex(SystemExit, "unique pinned"):
                QUALIFICATION.qualification_builder_images(root)

    def test_qualification_builder_index_rejects_wrong_child(self):
        images = QUALIFICATION.qualification_builder_images(ROOT)
        manifest = {
            "schemaVersion": 2,
            "manifests": [
                {
                    "digest": "sha256:" + "a" * 64,
                    "platform": {"os": "linux", "architecture": "amd64"},
                },
                {
                    "digest": images["linux/arm64"].rsplit("@", 1)[1],
                    "platform": {"os": "linux", "architecture": "arm64"},
                },
            ],
        }
        with mock.patch.object(
            QUALIFICATION.subprocess,
            "run",
            return_value=mock.Mock(stdout=json.dumps(manifest)),
        ), self.assertRaisesRegex(SystemExit, "does not bind linux/amd64"):
            QUALIFICATION.verify_qualification_builder_index(ROOT, images)

    def test_qualification_builder_configuration_fails_closed(self):
        source = (ROOT / "deploy" / "Dockerfile.qualification").read_text()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dockerfile = root / "deploy" / "Dockerfile.qualification"
            dockerfile.parent.mkdir()
            dockerfile.write_text(source)
            self.assertEqual(
                QUALIFICATION.qualification_builder_configuration(root),
                {
                    "debian_snapshot": "20260202T000000Z",
                    "rust_toolchain": "1.95.0",
                    "target": "x86_64-unknown-linux-gnu.2.31",
                    "maximum_glibc": "2.31",
                },
            )
            dockerfile.write_text(source.replace("1.95.0", "1.96.0"))
            with self.assertRaisesRegex(SystemExit, "configuration changed"):
                QUALIFICATION.qualification_builder_configuration(root)
            dockerfile.write_text(
                source + "\nARG QUALIFICATION_TARGET=x86_64-unknown-linux-gnu.2.31\n"
            )
            with self.assertRaisesRegex(SystemExit, "unique pinned"):
                QUALIFICATION.qualification_builder_configuration(root)

    def test_qualification_binary_rejects_arm64_and_newer_glibc(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "probe"
            header = bytearray(20)
            header[:6] = b"\x7fELF\x02\x01"
            header[18:20] = b"\xb7\x00"
            binary.write_bytes(bytes(header) + b"\0GLIBC_2.31\0")
            with self.assertRaisesRegex(SystemExit, "wrong platform"):
                QUALIFICATION.validate_qualification_binary(binary, "probe")
            header[18:20] = b"\x3e\x00"
            binary.write_bytes(bytes(header) + b"\0GLIBC_2.32\0")
            with self.assertRaisesRegex(SystemExit, "incompatible glibc"):
                QUALIFICATION.validate_qualification_binary(binary, "probe")

    def test_qualification_cross_build_contract_is_archived(self):
        qualification = (ROOT / "deploy" / "Dockerfile.qualification").read_text()
        self.assertIn("zigbuild --locked --release", qualification)
        self.assertIn('--target "${QUALIFICATION_TARGET}"', qualification)
        self.assertIn("--package bridgefu-recipe-qualification", qualification)
        self.assertNotIn("--platform", qualification)
        self.assertIn("! grep -Eq '^aws-lc-(rs|sys) '", qualification)
        self.assertIn("ENV LIBOPUS_NO_PKG=1", qualification)
        self.assertIn("Shared library: [libopus.so", qualification)
        self.assertIn(
            'audiopus_sys = { version = "=0.2.2", features = ["static"] }',
            (ROOT / "tools" / "recipe-qualification" / "Cargo.toml").read_text(),
        )
        self.assertNotIn("qualification-builder", (ROOT / "Dockerfile").read_text())
        inputs = {
            path.relative_to(ROOT).as_posix()
            for path in QUALIFICATION.source_files(ROOT)
        }
        self.assertIn("deploy/Dockerfile.qualification", inputs)
        self.assertIn("tools/recipe-qualification/Cargo.toml", inputs)

    def test_federated_session_is_bound_to_its_durable_iam_role(self):
        self.assertEqual(LIVE.ROLE_CHAIN_SESSION_SECONDS, 3_600)
        account = "123456789012"
        root_arn = f"arn:aws:iam::{account}:root"
        self.assertEqual(
            LIVE.durable_trusted_principal({"Account": account, "Arn": root_arn}),
            root_arn,
        )
        session = {
            "Account": account,
            "Arn": (
                f"arn:aws:sts::{account}:assumed-role/"
                "AWSReservedSSO_AdministratorAccess_example/reviewer"
            ),
        }
        role_arn = (
            f"arn:aws:iam::{account}:role/aws-reserved/sso.amazonaws.com/"
            "AWSReservedSSO_AdministratorAccess_example"
        )
        with mock.patch.object(
            LIVE,
            "aws_json",
            return_value={"Role": {"Arn": role_arn}},
        ) as aws:
            self.assertEqual(LIVE.durable_trusted_principal(session), role_arn)
        self.assertEqual(
            aws.call_args.args[0],
            [
                "iam",
                "get-role",
                "--role-name",
                "AWSReservedSSO_AdministratorAccess_example",
            ],
        )
        with self.assertRaises(LIVE.LiveTestError):
            LIVE.durable_trusted_principal(
                {
                    "Account": account,
                    "Arn": f"arn:aws:sts::{account}:federated-user/unsupported",
                }
            )

    def test_release_copy_excludes_local_build_and_provider_caches(self):
        names = [
            ".terraform",
            ".terragrunt-cache",
            "node_modules",
            "__pycache__",
            ".pytest_cache",
            "terraform.tfstate",
            "terraform.tfstate.backup",
            "module.tf",
            ".terraform.lock.hcl",
        ]
        ignored = RELEASE.ignored_recipe_assets("unused", names)
        self.assertTrue(
            {
                ".terraform",
                ".terragrunt-cache",
                "node_modules",
                "__pycache__",
                ".pytest_cache",
                "terraform.tfstate",
                "terraform.tfstate.backup",
            }.issubset(ignored)
        )
        self.assertNotIn("module.tf", ignored)
        self.assertNotIn(".terraform.lock.hcl", ignored)

    def test_release_publication_size_and_resource_guards_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory)
            (release / "manifest.json").write_text("{}")
            files = LIVE.bounded_release_files(release)
            self.assertEqual(files[0][1:], ("manifest.json", 2))

        ledger: dict[str, object] = {"created_resources": []}
        LIVE.record_created_resource(ledger, "s3_bucket", "example")
        LIVE.record_created_resource(ledger, "s3_bucket", "example")
        self.assertTrue(LIVE.created_resource(ledger, "s3_bucket", "example"))
        self.assertEqual(len(ledger["created_resources"]), 1)
        self.assertEqual(
            LIVE.working_tree_digest(ROOT), RELEASE.working_tree_digest(ROOT)
        )
        self.assertEqual(
            LIVE.MUTABLE_SOURCE_DIGEST_PATHS,
            RELEASE.MUTABLE_SOURCE_DIGEST_PATHS,
        )
        self.assertEqual(
            LIVE.MUTABLE_SOURCE_DIGEST_PATHS,
            frozenset({"BRIDGEFU-RECIPE-IMPLEMENTATION-PROGRESS.md"}),
        )

    def test_mutable_progress_journal_does_not_invalidate_candidate(self):
        listed = "BRIDGEFU-RECIPE-IMPLEMENTATION-PROGRESS.md\nstable.txt\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            progress = root / "BRIDGEFU-RECIPE-IMPLEMENTATION-PROGRESS.md"
            stable = root / "stable.txt"
            progress.write_text("first\n")
            stable.write_text("stable\n")
            with mock.patch.object(
                LIVE,
                "command",
                return_value=mock.Mock(stdout=listed),
            ), mock.patch.object(RELEASE, "run", return_value=listed.strip()):
                first_live = LIVE.working_tree_digest(root)
                first_release = RELEASE.working_tree_digest(root)
                progress.write_text("second\n")
                self.assertEqual(first_live, LIVE.working_tree_digest(root))
                self.assertEqual(first_release, RELEASE.working_tree_digest(root))
                stable.write_text("changed\n")
                self.assertNotEqual(first_live, LIVE.working_tree_digest(root))
                self.assertNotEqual(first_release, RELEASE.working_tree_digest(root))

    def test_release_builder_rejects_source_mutation_before_replacement(self):
        def copy_recipe(_source, destination):
            staged_recipe = destination / "recipe"
            staged_recipe.mkdir()
            (staged_recipe / "recipe.yaml").write_text("schema_version: 1\n")
            (staged_recipe / "handoff-contract.json").write_text("{}\n")

        def git_output(*arguments, **_kwargs):
            return "" if "status" in arguments else "revision"

        image = "example.test/bridgefu@sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "release"
            output.mkdir()
            sentinel = output / "keep.txt"
            sentinel.write_text("existing release\n")
            with mock.patch.object(
                sys,
                "argv",
                [
                    "build-recipe-release.py",
                    "--image-uri",
                    image,
                    "--output",
                    str(output),
                ],
            ), mock.patch.object(
                RELEASE, "working_tree_digest", side_effect=["b" * 64, "c" * 64]
            ), mock.patch.object(
                RELEASE, "copy_recipe_assets", side_effect=copy_recipe
            ), mock.patch.object(
                RELEASE.subprocess, "run"
            ), mock.patch.object(
                RELEASE, "run", side_effect=git_output
            ), mock.patch.object(
                RELEASE, "artifact_inventory", return_value=[]
            ), mock.patch.object(
                RELEASE, "safe_replace"
            ) as replace:
                with self.assertRaisesRegex(
                    SystemExit, "working tree changed while building release"
                ):
                    RELEASE.main()
            replace.assert_not_called()
            self.assertEqual(sentinel.read_text(), "existing release\n")
            self.assertEqual(list(Path(directory).glob(".release.*")), [])

        captured: dict[str, object] = {}

        def capture_release(staging, _output):
            captured.update(json.loads((staging / "manifest.json").read_text()))

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "release"
            with mock.patch.object(
                sys,
                "argv",
                [
                    "build-recipe-release.py",
                    "--image-uri",
                    image,
                    "--output",
                    str(output),
                ],
            ), mock.patch.object(
                RELEASE, "working_tree_digest", return_value="d" * 64
            ), mock.patch.object(
                RELEASE, "copy_recipe_assets", side_effect=copy_recipe
            ), mock.patch.object(
                RELEASE.subprocess, "run"
            ), mock.patch.object(
                RELEASE, "run", side_effect=git_output
            ), mock.patch.object(
                RELEASE, "artifact_inventory", return_value=[]
            ), mock.patch.object(
                RELEASE, "safe_replace", side_effect=capture_release
            ) as replace:
                self.assertEqual(RELEASE.main(), 0)
            replace.assert_called_once()
            self.assertEqual(
                captured["bridgefu"]["source_tree_sha256"],
                "d" * 64,
            )
            self.assertEqual(
                captured["recipe"]["manifest_sha256"],
                hashlib.sha256(b"schema_version: 1\n").hexdigest(),
            )
            self.assertEqual(
                captured["recipe"]["handoff_contract_sha256"],
                hashlib.sha256(b"{}\n").hexdigest(),
            )

    def test_undeployed_candidate_refresh_is_explicit_and_auditable(self):
        ledger = {
            "status": "published",
            "execution_id": "bft-safe1",
            "bridgefu_image_uri": "example.invalid/repository@sha256:" + "a" * 64,
            "release_id": "release-one",
            "release_prefix": "qualification/bft-safe1/release-one",
            "nested_template_base_url": "https://example.invalid/release-one",
            "publication_source_tree_sha256": "b" * 64,
            "published_objects": {"manifest.json": {"version_id": "one"}},
            "bootstrap_refresh_change_set_arn": "arn:refresh-one",
            "bootstrap_refresh_change_set_name": "bootstrap-refresh-release-one",
            "bootstrap_refresh_template_sha256": "c" * 64,
        }
        self.assertEqual(LIVE.candidate_image_tag(ledger), "bft-safe1")
        LIVE.refresh_publication_candidate(ledger)
        self.assertEqual(ledger["status"], "publishing")
        self.assertEqual(ledger["publication_generation"], 2)
        self.assertEqual(LIVE.candidate_image_tag(ledger), "bft-safe1-r2")
        self.assertNotIn("bridgefu_image_uri", ledger)
        self.assertNotIn("release_id", ledger)
        self.assertNotIn("bootstrap_refresh_change_set_arn", ledger)
        self.assertNotIn("bootstrap_refresh_change_set_name", ledger)
        self.assertNotIn("bootstrap_refresh_template_sha256", ledger)
        self.assertEqual(ledger["published_objects"], {})
        self.assertEqual(ledger["superseded_candidates"][0]["object_count"], 1)
        self.assertEqual(
            ledger["superseded_candidates"][0]["bootstrap_refresh_change_set_arn"],
            "arn:refresh-one",
        )

        reviewed = {"status": "published", "change_set_arn": "arn:change-set"}
        with self.assertRaises(LIVE.LiveTestError):
            LIVE.refresh_publication_candidate(reviewed)

        reviewed_but_retired = {
            "status": "change_set_reviewed",
            "execution_id": "bft-safe1",
            "publication_generation": 2,
            "published_objects": {},
        }
        LIVE.refresh_publication_candidate(reviewed_but_retired)
        self.assertEqual(reviewed_but_retired["status"], "publishing")
        self.assertEqual(reviewed_but_retired["publication_generation"], 3)

        for status in (
            "qualification_runner_deploying",
            "qualification_runner_deployed",
            "deploying",
            "deployed",
        ):
            with self.subTest(status=status), self.assertRaises(LIVE.LiveTestError):
                LIVE.refresh_publication_candidate({"status": status})

    def test_partial_publication_candidate_can_be_explicitly_refreshed(self):
        ledger = {
            "status": "publishing",
            "execution_id": "bft-safe1",
            "publication_generation": 1,
            "publication_source_tree_sha256": "b" * 64,
            "published_objects": {},
        }
        LIVE.refresh_publication_candidate(ledger)
        self.assertEqual(ledger["status"], "publishing")
        self.assertEqual(ledger["publication_generation"], 2)
        self.assertNotIn("publication_source_tree_sha256", ledger)
        self.assertEqual(ledger["superseded_candidates"][0]["object_count"], 0)

    def test_candidate_refresh_retires_only_exact_pending_bootstrap_review(self):
        bootstrap_stack_id = (
            "arn:aws:cloudformation:us-west-2:111122223333:stack/"
            "bridgefu-bft-safe1-bootstrap/12345678-1234-1234-1234-123456789abc"
        )
        change_set_id = (
            "arn:aws:cloudformation:us-west-2:111122223333:changeSet/"
            "bootstrap-refresh-release-one/"
            "00000000-0000-0000-0000-000000000010"
        )
        ledger = {
            "account_id": "111122223333",
            "partition": "aws",
            "region": "us-west-2",
            "release_id": "release-one",
            "bootstrap_stack_name": "bridgefu-bft-safe1-bootstrap",
            "bootstrap_stack_id": bootstrap_stack_id,
            "bootstrap_refresh_change_set_arn": change_set_id,
            "bootstrap_refresh_change_set_name": "bootstrap-refresh-release-one",
        }
        description = {
            "ChangeSetId": change_set_id,
            "ChangeSetName": "bootstrap-refresh-release-one",
            "StackName": "bridgefu-bft-safe1-bootstrap",
            "StackId": bootstrap_stack_id,
            "Status": "CREATE_COMPLETE",
            "ExecutionStatus": "AVAILABLE",
        }

        def response(arguments, **_kwargs):
            if "describe-change-set" in arguments:
                return description
            if "delete-change-set" in arguments:
                return {}
            self.fail(f"unexpected AWS operation: {arguments}")

        with mock.patch.object(LIVE, "aws_json", side_effect=response) as aws:
            self.assertEqual(
                LIVE.retire_pending_bootstrap_refresh(ledger, {"SAFE": "1"}),
                "bootstrap-refresh-release-one",
            )
        self.assertEqual(aws.call_count, 2)
        self.assertIn("delete-change-set", aws.call_args_list[1].args[0])
        for call in aws.call_args_list:
            arguments = call.args[0]
            self.assertEqual(
                arguments[arguments.index("--stack-name") + 1],
                bootstrap_stack_id,
            )
            self.assertEqual(
                arguments[arguments.index("--change-set-name") + 1],
                change_set_id,
            )

        stale_ledger = {
            **ledger,
            "release_id": "release-two",
            "superseded_candidates": [{"release_id": "release-one"}],
        }
        with mock.patch.object(LIVE, "aws_json", side_effect=response):
            self.assertEqual(
                LIVE.retire_pending_bootstrap_refresh(stale_ledger, {"SAFE": "1"}),
                "bootstrap-refresh-release-one",
            )

        with mock.patch.object(LIVE, "aws_json") as aws:
            self.assertIsNone(
                LIVE.retire_pending_bootstrap_refresh(
                    {**ledger, "bootstrap_refresh_complete": True}, {"SAFE": "1"}
                )
            )
        aws.assert_not_called()

        for unsafe in (
            {**ledger, "bootstrap_refresh_change_set_name": "bootstrap-refresh-other"},
            ledger,
        ):
            unsafe_description = {
                **description,
                "ExecutionStatus": "EXECUTE_COMPLETE",
            }
            with mock.patch.object(
                LIVE, "aws_json", return_value=unsafe_description
            ) as aws:
                with self.assertRaises(LIVE.LiveTestError):
                    LIVE.retire_pending_bootstrap_refresh(unsafe, {"SAFE": "1"})
            self.assertLessEqual(aws.call_count, 1)

        with mock.patch.object(
            LIVE,
            "aws_json",
            return_value={**description, "StackId": bootstrap_stack_id + "-other"},
        ) as aws:
            with self.assertRaises(LIVE.LiveTestError):
                LIVE.retire_pending_bootstrap_refresh(ledger, {"SAFE": "1"})
        aws.assert_called_once()

    def test_unexecuted_create_review_cleanup_uses_immutable_stack_id(self):
        stack_id = (
            "arn:aws:cloudformation:us-west-2:111122223333:stack/"
            "bridgefu-bft-safe1/12345678-1234-1234-1234-123456789abc"
        )
        change_set_id = (
            "arn:aws:cloudformation:us-west-2:111122223333:changeSet/"
            "reviewed-bft-safe1/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        )
        ledger = {
            "execution_id": "bft-safe1",
            "account_id": "111122223333",
            "partition": "aws",
            "region": "us-west-2",
            "stack_name": "bridgefu-bft-safe1",
            "change_set_arn": change_set_id,
            "change_set_name": "reviewed-bft-safe1",
            "review_stack_id": stack_id,
            "change_set_review_sha256": "a" * 64,
        }
        existing = {
            "StackName": ledger["stack_name"],
            "StackId": stack_id,
            "StackStatus": "REVIEW_IN_PROGRESS",
        }
        description = {
            "ChangeSetId": change_set_id,
            "ChangeSetName": ledger["change_set_name"],
            "StackName": ledger["stack_name"],
            "StackId": stack_id,
            "Status": "CREATE_COMPLETE",
            "ExecutionStatus": "AVAILABLE",
            "Tags": [
                {"Key": "Project", "Value": LIVE.PROJECT},
                {"Key": "ManagedBy", "Value": LIVE.MANAGED_BY},
                {"Key": "BridgefuExecutionId", "Value": ledger["execution_id"]},
                {"Key": "BridgefuRecipe", "Value": LIVE.RECIPE},
            ],
        }

        def response(arguments, **_kwargs):
            operation = arguments[1]
            if operation == "describe-change-set":
                return description
            if operation == "list-stack-resources":
                return {"StackResourceSummaries": []}
            if operation in {"delete-change-set", "delete-stack"}:
                return {}
            self.fail(f"unexpected AWS operation: {arguments}")

        with mock.patch.object(
            LIVE, "aws_json", side_effect=response
        ) as aws, mock.patch.object(LIVE, "aws_wait") as waiter:
            self.assertEqual(
                LIVE.retire_unexecuted_application_review(
                    ledger, {"SAFE": "1"}, existing
                ),
                "reviewed-bft-safe1",
            )
        for call in aws.call_args_list:
            arguments = call.args[0]
            self.assertEqual(arguments[arguments.index("--stack-name") + 1], stack_id)
        wait_arguments = waiter.call_args.args[0]
        self.assertEqual(
            wait_arguments[wait_arguments.index("--stack-name") + 1], stack_id
        )
        self.assertNotIn("change_set_arn", ledger)
        self.assertNotIn("change_set_name", ledger)
        self.assertNotIn("review_stack_id", ledger)
        self.assertNotIn("change_set_review_sha256", ledger)

        unsafe_ledger = {
            **ledger,
            "change_set_arn": change_set_id,
            "change_set_name": "reviewed-bft-safe1",
        }
        with mock.patch.object(
            LIVE,
            "aws_json",
            return_value={**description, "StackId": stack_id + "-replacement"},
        ) as aws, mock.patch.object(LIVE, "aws_wait") as waiter:
            with self.assertRaises(LIVE.LiveTestError):
                LIVE.retire_unexecuted_application_review(
                    unsafe_ledger, {"SAFE": "1"}, existing
                )
        aws.assert_called_once()
        waiter.assert_not_called()

    def test_candidate_refresh_recovers_unrecorded_review_after_stale_id(self):
        stack_name = "bridgefu-bft-safe1-qualification"
        stale_stack_id = (
            "arn:aws:cloudformation:us-west-2:111122223333:stack/"
            f"{stack_name}/11111111-1111-1111-1111-111111111111"
        )
        current_stack_id = (
            "arn:aws:cloudformation:us-west-2:111122223333:stack/"
            f"{stack_name}/22222222-2222-2222-2222-222222222222"
        )
        change_set_id = (
            "arn:aws:cloudformation:us-west-2:111122223333:changeSet/"
            "qualification-bft-safe1/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        )
        ledger = {
            "execution_id": "bft-safe1",
            "account_id": "111122223333",
            "partition": "aws",
            "region": "us-west-2",
            "qualification_stack_name": stack_name,
            "qualification_review_stack_id": stale_stack_id,
            "qualification_change_set_review_sha256": "b" * 64,
        }
        existing = {
            "StackName": stack_name,
            "StackId": current_stack_id,
            "StackStatus": "REVIEW_IN_PROGRESS",
        }
        description = {
            "ChangeSetId": change_set_id,
            "ChangeSetName": "qualification-bft-safe1",
            "StackName": stack_name,
            "StackId": current_stack_id,
            "Status": "CREATE_COMPLETE",
            "ExecutionStatus": "AVAILABLE",
            "Tags": [
                {"Key": "Project", "Value": LIVE.PROJECT},
                {"Key": "ManagedBy", "Value": LIVE.MANAGED_BY},
                {"Key": "BridgefuExecutionId", "Value": ledger["execution_id"]},
                {"Key": "BridgefuRecipe", "Value": LIVE.RECIPE},
            ],
        }

        def response(arguments, **_kwargs):
            operation = arguments[1]
            if operation == "describe-change-set":
                return description
            if operation == "list-stack-resources":
                return {"StackResourceSummaries": []}
            if operation in {"delete-change-set", "delete-stack"}:
                return {}
            self.fail(f"unexpected AWS operation: {arguments}")

        with mock.patch.object(
            LIVE, "stack_status_if_exists", return_value="DELETE_COMPLETE"
        ) as stale_status, mock.patch.object(
            LIVE, "describe_change_set_if_exists", return_value=description
        ) as reconcile, mock.patch.object(
            LIVE, "aws_json", side_effect=response
        ), mock.patch.object(LIVE, "aws_wait"):
            self.assertEqual(
                LIVE.retire_unexecuted_qualification_review(
                    ledger, {"SAFE": "1"}, existing
                ),
                "qualification-bft-safe1",
            )
        stale_status.assert_called_once_with(
            stale_stack_id, "us-west-2", {"SAFE": "1"}
        )
        reconcile.assert_called_once_with(
            ledger,
            {"SAFE": "1"},
            stack_name,
            "qualification-bft-safe1",
            expected_stack_id=current_stack_id,
        )
        self.assertNotIn("qualification_review_stack_id", ledger)
        self.assertNotIn("qualification_change_set_review_sha256", ledger)

    def test_cost_guard_is_conservative_and_bounded(self):
        estimate = LIVE.cost_estimate(8, 30)
        estimate_with_site = LIVE.cost_estimate(8, 30, True)
        ha_estimate = LIVE.cost_estimate(8, 30, False, "high_availability")
        self.assertLess(estimate["conservative_total"], 200)
        self.assertLess(ha_estimate["conservative_total"], 200)
        self.assertGreater(
            ha_estimate["conservative_total"], estimate["conservative_total"]
        )
        self.assertEqual(ha_estimate["runtime_profile"], "high_availability")
        self.assertEqual(
            estimate["limit_kind"], "planning_estimate_not_realtime_spend_cap"
        )
        self.assertEqual(
            estimate_with_site["conservative_total"],
            estimate["conservative_total"] + 2,
        )
        self.assertGreaterEqual(
            estimate["breakdown"]["unexpected_usage_contingency"], 30
        )
        with self.assertRaises(LIVE.LiveTestError):
            LIVE.cost_estimate(49, 0)
        with self.assertRaises(LIVE.LiveTestError):
            LIVE.cost_estimate(float("nan"), 0)
        with self.assertRaises(LIVE.LiveTestError):
            LIVE.cost_estimate(True, 0)
        with self.assertRaises(LIVE.LiveTestError):
            LIVE.cost_estimate(1, 241)
        with self.assertRaises(LIVE.LiveTestError):
            LIVE.cost_estimate(1, True)
        with self.assertRaises(LIVE.LiveTestError):
            LIVE.cost_estimate(1, 0, False, "unknown")
        LIVE.require_cost_estimate_within_ceiling(200, estimate["conservative_total"])
        for ceiling, total in (
            (float("nan"), 1),
            (200, float("nan")),
            (200, 201),
        ):
            with self.assertRaises(LIVE.LiveTestError):
                LIVE.require_cost_estimate_within_ceiling(ceiling, total)

    def test_qualification_deadline_is_immutable_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.json"
            ledger = {
                "created_at": "2026-08-03T04:00:00Z",
                "max_usd": 200.0,
                "cost_estimate": {
                    "planned_hours": 8.0,
                    "conservative_total": 81.92,
                },
                "events": [],
            }
            now = LIVE.dt.datetime(2026, 8, 3, 5, tzinfo=LIVE.dt.timezone.utc)
            self.assertEqual(
                LIVE.require_qualification_deadline(
                    path, ledger, "test operation", now=now
                ),
                7 * 60 * 60,
            )
            self.assertEqual(
                ledger["qualification_deadline_at"], "2026-08-03T12:00:00Z"
            )
            self.assertEqual(
                ledger["cost_ceiling_type"], "estimate_with_absolute_deadline"
            )
            persisted = json.loads(path.read_text())
            self.assertEqual(
                persisted["events"][-1]["event"], "qualification_deadline_bound"
            )

            expired = LIVE.dt.datetime(2026, 8, 3, 12, tzinfo=LIVE.dt.timezone.utc)
            with self.assertRaisesRegex(
                LIVE.LiveTestError, "does not stop existing AWS resources"
            ):
                LIVE.require_qualification_deadline(
                    path, ledger, "test operation", now=expired
                )

            ledger["qualification_deadline_at"] = "2026-08-03T13:00:00Z"
            with self.assertRaisesRegex(LIVE.LiveTestError, "original authorization"):
                LIVE.require_qualification_deadline(
                    path, ledger, "test operation", now=now
                )

    def test_paid_phase_deadline_guard_does_not_block_teardown_code(self):
        source = SCRIPT.read_text()
        for start, end in (
            ("def publish(args: argparse.Namespace) -> None:", "def resolve_ns"),
            (
                "def create_change_set(args: argparse.Namespace) -> None:",
                "def bind_qualification_source",
            ),
            ("def execute(args: argparse.Namespace) -> None:", "def stack_description"),
            (
                "def verify(args: argparse.Namespace) -> None:",
                "def reviewed_update_change_set",
            ),
            ("def lifecycle_test(args: argparse.Namespace) -> None:", "def destroy"),
        ):
            section = source.split(start, 1)[1].split(end, 1)[0]
            self.assertIn("require_qualification_deadline", section)
        for start, end in (
            ("def destroy(args: argparse.Namespace) -> None:", "def destroy_finalize"),
            ("def destroy_finalize", "def cleanup_orphans"),
            ("def cleanup_orphans", "def run_headless"),
        ):
            section = source.split(start, 1)[1].split(end, 1)[0]
            self.assertNotIn("require_qualification_deadline", section)

    def test_execution_identity_and_confirmations_are_explicit(self):
        self.assertTrue(LIVE.EXECUTION_PATTERN.fullmatch("bft-20990101a"))
        self.assertFalse(LIVE.EXECUTION_PATTERN.fullmatch("production"))
        parser = LIVE.parser()
        parsed = parser.parse_args(
            [
                "--execution-id",
                "bft-safe1",
                "init",
                "--connect-instance-arn",
                "arn:aws:connect:us-west-2:123456789012:instance/test",
                "--target-flow-arn",
                "arn:aws:connect:us-west-2:123456789012:instance/test/contact-flow/test",
                "--hosted-zone-id",
                "Z123",
                "--sip-hostname",
                "sip.example.com",
                "--enable-demo-site",
                "--runtime-profile",
                "high_availability",
            ]
        )
        self.assertTrue(parsed.enable_demo_site)
        self.assertEqual(parsed.runtime_profile, "high_availability")
        self.assertFalse(parsed.allow_root_bootstrap)
        root_exception = parser.parse_args(
            [
                "--execution-id",
                "bft-safe1",
                "init",
                "--create-connect-demo",
                "--allow-root-bootstrap",
            ]
        )
        self.assertTrue(root_exception.allow_root_bootstrap)
        bootstrap = parser.parse_args(
            ["--execution-id", "bft-safe1", "bootstrap", "--adopt-existing"]
        )
        self.assertTrue(bootstrap.adopt_existing)
        publish = parser.parse_args(
            ["--execution-id", "bft-safe1", "publish", "--refresh-candidate"]
        )
        self.assertTrue(publish.refresh_candidate)
        refresh = parser.parse_args(
            [
                "--execution-id",
                "bft-safe1",
                "bootstrap-refresh",
                "--confirm",
                "bft-safe1",
            ]
        )
        self.assertEqual(refresh.confirm, "bft-safe1")
        refresh_verify = parser.parse_args(
            [
                "--execution-id",
                "bft-safe1",
                "bootstrap-refresh-verify",
                "--confirm",
                "bft-safe1",
            ]
        )
        self.assertEqual(refresh_verify.confirm, "bft-safe1")
        lifecycle = parser.parse_args(
            [
                "--execution-id",
                "bft-safe1",
                "lifecycle-test",
                "--confirm",
                "bft-safe1",
            ]
        )
        self.assertEqual(lifecycle.confirm, "bft-safe1")
        source = parser.parse_args(
            [
                "--execution-id",
                "bft-safe1",
                "bind-qualification-source",
                "--cidr",
                "8.8.8.8/32",
                "--confirm",
                "bft-safe1",
            ]
        )
        self.assertEqual(source.cidr, "8.8.8.8/32")
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(["--execution-id", "bft-safe1", "execute"])
            with self.assertRaises(SystemExit):
                parser.parse_args(["--execution-id", "bft-safe1", "destroy"])

    def test_qualification_source_binding_is_public_exact_and_immutable(self):
        ledger = {
            "status": "published",
            "execution_id": "bft-safe1",
            "events": [],
        }
        args = mock.Mock(
            execution_id="bft-safe1",
            confirm="bft-safe1",
            cidr="8.8.8.8/32",
        )
        with mock.patch.object(
            LIVE, "load_ledger", return_value=(Path("ledger.json"), ledger)
        ), mock.patch.object(LIVE, "record") as record, contextlib.redirect_stdout(
            io.StringIO()
        ):
            LIVE.bind_qualification_source(args)
        self.assertEqual(ledger["qualification_source_cidr"], "8.8.8.8/32")
        record.assert_called_once()

        args.cidr = "1.1.1.1/32"
        with mock.patch.object(
            LIVE, "load_ledger", return_value=(Path("ledger.json"), ledger)
        ), self.assertRaises(LIVE.LiveTestError):
            LIVE.bind_qualification_source(args)

        ledger.pop("qualification_source_cidr")
        args.cidr = "10.0.0.1/32"
        with mock.patch.object(
            LIVE, "load_ledger", return_value=(Path("ledger.json"), ledger)
        ), self.assertRaises(LIVE.LiveTestError):
            LIVE.bind_qualification_source(args)

    def test_lifecycle_update_reuses_every_secret_parameter_and_overrides_one(self):
        stack = {
            "Parameters": [
                {"ParameterKey": "VapiPublicKey", "ParameterValue": "****"},
                {"ParameterKey": "ContextTtlSeconds", "ParameterValue": "900"},
                {"ParameterKey": "LookupArtifactVersion", "ParameterValue": "v1"},
            ]
        }
        arguments = LIVE.previous_parameter_arguments(
            stack, {"ContextTtlSeconds": "901"}
        )
        self.assertEqual(
            arguments,
            [
                "ParameterKey=ContextTtlSeconds,ParameterValue=901",
                "ParameterKey=LookupArtifactVersion,UsePreviousValue=true",
                "ParameterKey=VapiPublicKey,UsePreviousValue=true",
            ],
        )
        self.assertNotIn("****", " ".join(arguments))
        with self.assertRaises(LIVE.LiveTestError):
            LIVE.previous_parameter_arguments(stack, {"MissingParameter": "value"})

    def test_nested_change_set_review_walks_every_child_and_fails_closed(self):
        root_change_set_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:changeSet/"
            "root-change/00000000-0000-0000-0000-000000000010"
        )
        child_change_set_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:changeSet/"
            "child-change/00000000-0000-0000-0000-000000000011"
        )
        descriptions = {
            root_change_set_id: {
                "Status": "CREATE_COMPLETE",
                "ChangeSetId": root_change_set_id,
                "Changes": [
                    {
                        "ResourceChange": {
                            "LogicalResourceId": "Application",
                            "ResourceType": "AWS::CloudFormation::Stack",
                            "Action": "Add",
                            "ChangeSetId": child_change_set_id,
                        }
                    }
                ],
            },
            child_change_set_id: {
                "Status": "CREATE_COMPLETE",
                "ChangeSetId": child_change_set_id,
                "Changes": [
                    {
                        "ResourceChange": {
                            "LogicalResourceId": "Function",
                            "ResourceType": "AWS::Lambda::Function",
                            "Action": "Add",
                        }
                    }
                ],
            },
        }

        def response(arguments, **_kwargs):
            change_set_id = arguments[arguments.index("--change-set-name") + 1]
            return descriptions[change_set_id]

        ledger = {
            "partition": "aws",
            "region": "us-west-2",
            "account_id": "123456789012",
        }
        with mock.patch.object(LIVE, "aws_json", side_effect=response):
            root, changes = LIVE.review_change_set_tree(
                ledger, {}, root_change_set_id, expected_action="Add"
            )
        self.assertEqual(root["ChangeSetId"], root_change_set_id)
        self.assertEqual(
            [item["path"] for item in changes],
            ["root/Application", "root/Application/Function"],
        )

        descriptions[child_change_set_id]["Changes"][0]["ResourceChange"][
            "ResourceType"
        ] = "AWS::Organizations::Account"
        with mock.patch.object(LIVE, "aws_json", side_effect=response):
            with self.assertRaises(LIVE.LiveTestError):
                LIVE.review_change_set_tree(
                    ledger, {}, root_change_set_id, expected_action="Add"
                )

    def test_bootstrap_refresh_is_limited_to_exact_nonreplacing_resources(self):
        description = {
            "Status": "CREATE_COMPLETE",
            "ExecutionStatus": "AVAILABLE",
        }
        changes = [
            {
                "path": "root/DeploymentControlPolicy",
                "resource_type": "AWS::IAM::ManagedPolicy",
                "action": "Modify",
                "replacement": "False",
            },
            {
                "path": "root/DeploymentArtifactPolicy",
                "resource_type": "AWS::IAM::ManagedPolicy",
                "action": "Modify",
                "replacement": "False",
            },
            {
                "path": "root/DeploymentComputePolicy",
                "resource_type": "AWS::IAM::ManagedPolicy",
                "action": "Modify",
                "replacement": "False",
            },
            {
                "path": "root/DeploymentDataPolicy",
                "resource_type": "AWS::IAM::ManagedPolicy",
                "action": "Modify",
                "replacement": "False",
            },
            {
                "path": "root/QualificationRole",
                "resource_type": "AWS::IAM::Role",
                "action": "Modify",
                "replacement": "False",
            },
            {
                "path": "root/DeploymentDemoPolicy",
                "resource_type": "AWS::IAM::ManagedPolicy",
                "action": "Modify",
                "replacement": "False",
            },
            {
                "path": "root/DeploymentQualificationRunnerPolicy",
                "resource_type": "AWS::IAM::ManagedPolicy",
                "action": "Modify",
                "replacement": "False",
            },
            {
                "path": "root/QualificationRunnerRole",
                "resource_type": "AWS::IAM::Role",
                "action": "Modify",
                "replacement": "False",
            },
            {
                "path": "root/QualificationSourceEip",
                "resource_type": "AWS::EC2::EIP",
                "action": "Modify",
                "replacement": "False",
            },
        ]
        LIVE.validate_bootstrap_refresh_review(description, changes)
        with self.assertRaises(LIVE.LiveTestError):
            LIVE.validate_bootstrap_refresh_review(
                description,
                changes
                + [
                    {
                        "path": "root/UnrelatedRole",
                        "resource_type": "AWS::IAM::Role",
                        "action": "Modify",
                        "replacement": "False",
                    }
                ],
            )
        with self.assertRaises(LIVE.LiveTestError):
            LIVE.validate_bootstrap_refresh_review(
                {**description, "ExecutionStatus": "EXECUTE_COMPLETE"}, changes
            )
        self.assertEqual(
            LIVE.validate_bootstrap_refresh_review(description, changes[:1]),
            changes[:1],
        )
        for invalid in (
            [],
            [{**changes[0], "resource_type": "AWS::IAM::Role"}],
            [{**changes[0], "action": "Add"}],
            [{**changes[0], "replacement": "True"}],
            [changes[0], changes[0]],
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(LIVE.LiveTestError):
                    LIVE.validate_bootstrap_refresh_review(description, invalid)

    def test_live_correlation_derivation_matches_the_deployed_lambda_contract(self):
        self.assertEqual(
            LIVE.derive_correlation_id(
                "k" * 32,
                "bft-test1234",
                "org_test",
                "call_test",
            ),
            "bf1_NlBgAHb4u7HAun9Uajj4Ijfx0UncXTSClFf7Q1kUEd0",
        )
        with self.assertRaises(LIVE.LiveTestError):
            LIVE.derive_correlation_id("short", "bft-test1234", "org", "call")
        with self.assertRaises(LIVE.LiveTestError):
            LIVE.derive_correlation_id("k" * 32, "bad|id", "org", "call")

    def test_bootstrap_refresh_accepts_only_owned_zone_parameter_transition(self):
        ledger = {
            "dns_mode": "temporary_delegated_zone",
            "public_hosted_zone_id": "Z123",
            "created_resources": [{"type": "route53_hosted_zone", "id": "Z123"}],
        }
        expected = {
            "ExecutionId": "bft-safe1",
            "PublicHostedZoneId": "Z123",
        }
        observed = {
            "ExecutionId": "bft-safe1",
            "PublicHostedZoneId": "none",
        }
        self.assertTrue(LIVE.bootstrap_zone_transition(ledger, observed, expected))
        self.assertFalse(LIVE.bootstrap_zone_transition(ledger, expected, expected))
        with self.assertRaises(LIVE.LiveTestError):
            LIVE.bootstrap_zone_transition(
                ledger,
                {**observed, "ExecutionId": "bft-other"},
                expected,
            )

    def test_bootstrap_refresh_review_never_executes_its_own_iam_change_set(self):
        source = SCRIPT.read_text()
        planner = source.split(
            "def bootstrap_refresh(args: argparse.Namespace) -> None:", 1
        )[1].split(
            "def bootstrap_refresh_verify(args: argparse.Namespace) -> None:", 1
        )[
            0
        ]
        self.assertNotIn('"execute-change-set"', planner)
        self.assertIn('"--change-set-type"', planner)
        self.assertIn('"UPDATE"', planner)
        self.assertIn(
            "authorized administrator execution is required",
            planner,
        )

    def test_authorize_caller_updates_and_waits_for_the_exact_bootstrap_stack_id(self):
        ledger = self.refresh_ledger()
        ledger["status"] = "initialized"
        root_arn = "arn:aws:iam::111122223333:root"
        user_arn = "arn:aws:iam::111122223333:user/non-root-admin"
        ledger["trusted_principal_arn"] = root_arn
        args = mock.Mock(
            execution_id=ledger["execution_id"],
            confirm=ledger["execution_id"],
            principal_arn=user_arn,
        )

        def response(arguments, **_kwargs):
            if arguments[:2] == ["iam", "get-user"]:
                return {"User": {"Arn": user_arn}}
            if arguments[:2] == ["cloudformation", "update-stack"]:
                return {"StackId": ledger["bootstrap_stack_id"]}
            self.fail(f"unexpected AWS operation: {arguments}")

        with mock.patch.object(
            LIVE, "load_ledger", return_value=(Path("ledger.json"), ledger)
        ), mock.patch.object(
            LIVE,
            "identity",
            return_value={"Account": ledger["account_id"], "Arn": root_arn},
        ), mock.patch.object(
            LIVE, "aws_json", side_effect=response
        ) as aws, mock.patch.object(
            LIVE, "aws_wait"
        ) as waiter, mock.patch.object(
            LIVE, "record"
        ), contextlib.redirect_stdout(
            io.StringIO()
        ):
            LIVE.authorize_caller(args)

        update_arguments = aws.call_args_list[1].args[0]
        wait_arguments = waiter.call_args.args[0]
        self.assertEqual(
            update_arguments[update_arguments.index("--stack-name") + 1],
            self.bootstrap_stack_id(),
        )
        self.assertEqual(
            wait_arguments[wait_arguments.index("--stack-name") + 1],
            self.bootstrap_stack_id(),
        )

    def test_bootstrap_resume_never_rebinds_a_missing_exact_stack_by_name(self):
        ledger = self.refresh_ledger()
        ledger["status"] = "initialized"
        args = mock.Mock(execution_id=ledger["execution_id"], adopt_existing=False)
        principal = {
            "Account": ledger["account_id"],
            "Arn": ledger["trusted_principal_arn"],
        }
        with mock.patch.object(
            LIVE, "load_ledger", return_value=(Path("ledger.json"), ledger)
        ), mock.patch.object(
            LIVE, "identity", return_value=principal
        ), mock.patch.object(
            LIVE, "aws_json", return_value=None
        ) as aws:
            with self.assertRaisesRegex(LIVE.LiveTestError, "exact ledger-bound"):
                LIVE.bootstrap(args)
        aws.assert_called_once()
        arguments = aws.call_args.args[0]
        self.assertEqual(
            arguments[arguments.index("--stack-name") + 1],
            ledger["bootstrap_stack_id"],
        )

    def test_authorize_caller_rejects_replacement_stack_update_response(self):
        ledger = self.refresh_ledger()
        ledger["status"] = "initialized"
        root_arn = "arn:aws:iam::111122223333:root"
        user_arn = "arn:aws:iam::111122223333:user/non-root-admin"
        ledger["trusted_principal_arn"] = root_arn
        args = mock.Mock(
            execution_id=ledger["execution_id"],
            confirm=ledger["execution_id"],
            principal_arn=user_arn,
        )
        replacement_id = ledger["bootstrap_stack_id"].replace(
            "12345678-1234-1234-1234-123456789abc",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        )
        with mock.patch.object(
            LIVE, "load_ledger", return_value=(Path("ledger.json"), ledger)
        ), mock.patch.object(
            LIVE,
            "identity",
            return_value={"Account": ledger["account_id"], "Arn": root_arn},
        ), mock.patch.object(
            LIVE,
            "aws_json",
            side_effect=[{"User": {"Arn": user_arn}}, {"StackId": replacement_id}],
        ), mock.patch.object(
            LIVE, "aws_wait"
        ) as waiter:
            with self.assertRaisesRegex(LIVE.LiveTestError, "exact stack identity"):
                LIVE.authorize_caller(args)
        waiter.assert_not_called()

    def test_bootstrap_refresh_rejects_same_name_replacement_before_review(self):
        ledger = self.refresh_ledger()
        replacement_id = ledger["bootstrap_stack_id"].replace(
            "12345678-1234-1234-1234-123456789abc",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        )
        args = mock.Mock(
            execution_id=ledger["execution_id"], confirm=ledger["execution_id"]
        )
        missing_application = mock.Mock(
            returncode=1,
            stderr="ValidationError: Stack does not exist",
        )
        response = {
            "Stacks": [
                {
                    "StackName": ledger["bootstrap_stack_name"],
                    "StackId": replacement_id,
                    "StackStatus": "UPDATE_COMPLETE",
                }
            ]
        }

        with mock.patch.object(
            LIVE, "load_ledger", return_value=(Path("ledger.json"), ledger)
        ), mock.patch.object(
            LIVE,
            "working_tree_digest",
            return_value=ledger["publication_source_tree_sha256"],
        ), mock.patch.object(
            LIVE,
            "identity",
            return_value={
                "Account": ledger["account_id"],
                "Arn": ledger["trusted_principal_arn"],
            },
        ), mock.patch.object(
            LIVE, "command", return_value=missing_application
        ), mock.patch.object(
            LIVE, "assume_env", return_value={"SAFE": "1"}
        ), mock.patch.object(
            LIVE, "aws_json", return_value=response
        ) as aws:
            with self.assertRaisesRegex(LIVE.LiveTestError, "exact stack identity"):
                LIVE.bootstrap_refresh(args)

        describe_arguments = aws.call_args.args[0]
        self.assertEqual(
            describe_arguments[describe_arguments.index("--stack-name") + 1],
            ledger["bootstrap_stack_id"],
        )

    def test_bootstrap_refresh_resume_requires_stack_id_in_existing_evidence(self):
        ledger = self.refresh_ledger()
        ledger["bootstrap_refresh_change_set_arn"] = (
            "arn:aws:cloudformation:us-west-2:111122223333:changeSet/"
            "bootstrap-refresh-release-one/"
            "00000000-0000-0000-0000-000000000010"
        )
        ledger["bootstrap_refresh_change_set_name"] = "bootstrap-refresh-release-one"
        args = mock.Mock(
            execution_id=ledger["execution_id"], confirm=ledger["execution_id"]
        )
        base_evidence = {
            "change_set_id": ledger["bootstrap_refresh_change_set_arn"],
            "change_set_name": ledger["bootstrap_refresh_change_set_name"],
            "stack_name": ledger["bootstrap_stack_name"],
            "stack_id": ledger["bootstrap_stack_id"],
        }
        principal = {
            "Account": ledger["account_id"],
            "Arn": ledger["trusted_principal_arn"],
        }
        with tempfile.TemporaryDirectory() as directory:
            ledger_path = Path(directory) / "ledger.json"
            evidence_path = (
                ledger_path.parent / "bootstrap-refresh-change-set-review.json"
            )
            for label, evidence, succeeds in (
                ("exact", base_evidence, True),
                (
                    "legacy-missing-id",
                    {k: v for k, v in base_evidence.items() if k != "stack_id"},
                    False,
                ),
                (
                    "replacement",
                    {
                        **base_evidence,
                        "stack_id": ledger["bootstrap_stack_id"] + "-other",
                    },
                    False,
                ),
            ):
                with self.subTest(label=label):
                    evidence_path.write_text(json.dumps(evidence))
                    with mock.patch.object(
                        LIVE, "load_ledger", return_value=(ledger_path, ledger)
                    ), mock.patch.object(
                        LIVE,
                        "working_tree_digest",
                        return_value=ledger["publication_source_tree_sha256"],
                    ), mock.patch.object(
                        LIVE, "identity", return_value=principal
                    ), contextlib.redirect_stdout(
                        io.StringIO()
                    ):
                        if succeeds:
                            LIVE.bootstrap_refresh(args)
                        else:
                            with self.assertRaisesRegex(
                                LIVE.LiveTestError, "exact stack ID"
                            ):
                                LIVE.bootstrap_refresh(args)

    def test_no_change_bootstrap_refresh_records_and_reads_the_exact_stack_id(self):
        ledger = self.refresh_ledger()
        stack = self.refresh_stack(ledger)
        args = mock.Mock(
            execution_id=ledger["execution_id"], confirm=ledger["execution_id"]
        )
        principal = {
            "Account": ledger["account_id"],
            "Arn": ledger["trusted_principal_arn"],
        }
        missing_application = mock.Mock(
            returncode=1,
            stderr="ValidationError: Stack does not exist",
        )
        template_body = '{"Resources":{}}\n'

        with tempfile.TemporaryDirectory() as directory:
            ledger_path = Path(directory) / "ledger.json"
            template = (
                ledger_path.parent
                / "release"
                / "recipe"
                / "cloudformation"
                / "test-deployment-role.yaml"
            )
            template.parent.mkdir(parents=True)
            template.write_text(template_body)
            template_sha = hashlib.sha256(template.read_bytes()).hexdigest()
            manifest = {
                "artifacts": [
                    {
                        "path": "recipe/cloudformation/test-deployment-role.yaml",
                        "sha256": template_sha,
                    }
                ]
            }
            (ledger_path.parent / "release" / "manifest.json").write_text(
                json.dumps(manifest)
            )

            def response(arguments, **_kwargs):
                if arguments[:2] == ["cloudformation", "describe-stacks"]:
                    return {"Stacks": [stack]}
                if arguments[:2] == ["cloudformation", "get-template"]:
                    return {"TemplateBody": {"Resources": {}}}
                self.fail(f"unexpected AWS operation: {arguments}")

            with mock.patch.object(
                LIVE, "load_ledger", return_value=(ledger_path, ledger)
            ), mock.patch.object(
                LIVE,
                "working_tree_digest",
                return_value=ledger["publication_source_tree_sha256"],
            ), mock.patch.object(
                LIVE, "identity", return_value=principal
            ), mock.patch.object(
                LIVE, "command", return_value=missing_application
            ), mock.patch.object(
                LIVE, "assume_env", return_value={"SAFE": "1"}
            ), mock.patch.object(
                LIVE, "aws_json", side_effect=response
            ) as aws, mock.patch.object(
                LIVE, "validate_deployment_role_policies"
            ), mock.patch.object(
                LIVE, "record"
            ), contextlib.redirect_stdout(
                io.StringIO()
            ):
                LIVE.bootstrap_refresh(args)

            evidence = json.loads(
                (
                    ledger_path.parent / "bootstrap-refresh-change-set-review.json"
                ).read_text()
            )
            self.assertEqual(evidence["status"], "NO_CHANGES")
            self.assertEqual(evidence["stack_id"], ledger["bootstrap_stack_id"])
            self.assertTrue(ledger["bootstrap_refresh_complete"])
            for call in aws.call_args_list:
                arguments = call.args[0]
                if "--stack-name" in arguments:
                    self.assertEqual(
                        arguments[arguments.index("--stack-name") + 1],
                        ledger["bootstrap_stack_id"],
                    )

    def test_bootstrap_refresh_change_set_review_uses_immutable_identifiers(self):
        ledger = self.refresh_ledger()
        stack = self.refresh_stack(ledger)
        args = mock.Mock(
            execution_id=ledger["execution_id"], confirm=ledger["execution_id"]
        )
        principal = {
            "Account": ledger["account_id"],
            "Arn": ledger["trusted_principal_arn"],
        }
        missing = mock.Mock(returncode=1, stderr="ChangeSetNotFound: does not exist")
        change_set_id = (
            "arn:aws:cloudformation:us-west-2:111122223333:changeSet/"
            "bootstrap-refresh-release-one/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        )
        description = {
            "ChangeSetId": change_set_id,
            "ChangeSetName": "bootstrap-refresh-release-one",
            "StackName": ledger["bootstrap_stack_name"],
            "StackId": ledger["bootstrap_stack_id"],
            "Status": "CREATE_COMPLETE",
            "ExecutionStatus": "AVAILABLE",
        }
        template_body = '{"Resources":{"DeploymentRole":{"Type":"AWS::IAM::Role"}}}\n'

        with tempfile.TemporaryDirectory() as directory:
            ledger_path = Path(directory) / "ledger.json"
            template = (
                ledger_path.parent
                / "release"
                / "recipe"
                / "cloudformation"
                / "test-deployment-role.yaml"
            )
            template.parent.mkdir(parents=True)
            template.write_text(template_body)
            template_sha = hashlib.sha256(template.read_bytes()).hexdigest()
            manifest = {
                "artifacts": [
                    {
                        "path": "recipe/cloudformation/test-deployment-role.yaml",
                        "sha256": template_sha,
                    }
                ]
            }
            (ledger_path.parent / "release" / "manifest.json").write_text(
                json.dumps(manifest)
            )

            def shell_response(arguments, **_kwargs):
                if "describe-stacks" in arguments:
                    return mock.Mock(
                        returncode=1,
                        stderr="ValidationError: Stack does not exist",
                    )
                if "describe-change-set" in arguments:
                    self.assertEqual(
                        arguments[arguments.index("--stack-name") + 1],
                        ledger["bootstrap_stack_id"],
                    )
                    return missing
                self.fail(f"unexpected shell AWS operation: {arguments}")

            def response(arguments, **_kwargs):
                operation = arguments[1]
                if operation == "describe-stacks":
                    return {"Stacks": [stack]}
                if operation == "get-template":
                    return {"TemplateBody": {"Resources": {}}}
                if operation == "create-change-set":
                    return {
                        "Id": change_set_id,
                        "StackId": ledger["bootstrap_stack_id"],
                    }
                if operation == "describe-change-set":
                    return description
                self.fail(f"unexpected AWS operation: {arguments}")

            with mock.patch.object(
                LIVE, "load_ledger", return_value=(ledger_path, ledger)
            ), mock.patch.object(
                LIVE,
                "working_tree_digest",
                return_value=ledger["publication_source_tree_sha256"],
            ), mock.patch.object(
                LIVE, "identity", return_value=principal
            ), mock.patch.object(
                LIVE, "command", side_effect=shell_response
            ), mock.patch.object(
                LIVE, "assume_env", return_value={"SAFE": "1"}
            ), mock.patch.object(
                LIVE, "aws_json", side_effect=response
            ) as aws, mock.patch.object(
                LIVE, "aws_wait"
            ) as waiter, mock.patch.object(
                LIVE, "require_qualification_deadline"
            ), mock.patch.object(
                LIVE,
                "bootstrap_refresh_changes",
                return_value=[
                    {
                        "path": "root/DeploymentRole",
                        "action": "Modify",
                        "resource_type": "AWS::IAM::Role",
                        "replacement": "False",
                    }
                ],
            ), mock.patch.object(
                LIVE, "record"
            ), contextlib.redirect_stdout(
                io.StringIO()
            ):
                LIVE.bootstrap_refresh(args)

            evidence = json.loads(
                (
                    ledger_path.parent / "bootstrap-refresh-change-set-review.json"
                ).read_text()
            )
            self.assertEqual(evidence["change_set_id"], change_set_id)
            self.assertEqual(evidence["stack_id"], ledger["bootstrap_stack_id"])
            wait_arguments = waiter.call_args.args[0]
            self.assertEqual(
                wait_arguments[wait_arguments.index("--stack-name") + 1],
                ledger["bootstrap_stack_id"],
            )
            self.assertEqual(
                wait_arguments[wait_arguments.index("--change-set-name") + 1],
                change_set_id,
            )
            for call in aws.call_args_list:
                arguments = call.args[0]
                if "--stack-name" in arguments:
                    self.assertEqual(
                        arguments[arguments.index("--stack-name") + 1],
                        ledger["bootstrap_stack_id"],
                    )

    def test_bootstrap_refresh_verify_rechecks_identity_and_preserves_stack_id(self):
        ledger = self.refresh_ledger()
        change_set_id = (
            "arn:aws:cloudformation:us-west-2:111122223333:changeSet/"
            "bootstrap-refresh-release-one/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        )
        ledger.update(
            {
                "bootstrap_refresh_change_set_arn": change_set_id,
                "bootstrap_refresh_change_set_name": "bootstrap-refresh-release-one",
                "bootstrap_refresh_template_sha256": "c" * 64,
            }
        )
        evidence = {
            "change_set_id": change_set_id,
            "change_set_name": ledger["bootstrap_refresh_change_set_name"],
            "stack_name": ledger["bootstrap_stack_name"],
            "stack_id": ledger["bootstrap_stack_id"],
            "status": "CREATE_COMPLETE",
            "execution_status": "AVAILABLE",
            "change_set_type": "UPDATE",
            "template_sha256": ledger["bootstrap_refresh_template_sha256"],
            "release_id": ledger["release_id"],
            "publication_source_tree_sha256": ledger["publication_source_tree_sha256"],
            "changes": [{"path": "root/DeploymentRole", "action": "Modify"}],
            "reviewed_at": "2026-08-03T01:00:00Z",
        }
        description = {
            "ChangeSetId": change_set_id,
            "ChangeSetName": ledger["bootstrap_refresh_change_set_name"],
            "StackName": ledger["bootstrap_stack_name"],
            "StackId": ledger["bootstrap_stack_id"],
            "Status": "CREATE_COMPLETE",
            "ExecutionStatus": "EXECUTE_COMPLETE",
        }
        stack = self.refresh_stack(ledger)
        args = mock.Mock(
            execution_id=ledger["execution_id"], confirm=ledger["execution_id"]
        )
        principal = {
            "Account": ledger["account_id"],
            "Arn": ledger["trusted_principal_arn"],
        }
        template_body = '{"Resources":{}}\n'

        with tempfile.TemporaryDirectory() as directory:
            ledger_path = Path(directory) / "ledger.json"
            template = (
                ledger_path.parent
                / "release"
                / "recipe"
                / "cloudformation"
                / "test-deployment-role.yaml"
            )
            template.parent.mkdir(parents=True)
            template.write_text(template_body)
            (
                ledger_path.parent / "bootstrap-refresh-change-set-review.json"
            ).write_text(json.dumps(evidence))
            with mock.patch.object(
                LIVE, "load_ledger", return_value=(ledger_path, ledger)
            ), mock.patch.object(
                LIVE,
                "working_tree_digest",
                return_value=ledger["publication_source_tree_sha256"],
            ), mock.patch.object(
                LIVE, "identity", return_value=principal
            ), mock.patch.object(
                LIVE, "assume_env", return_value={"SAFE": "1"}
            ), mock.patch.object(
                LIVE,
                "aws_json",
                side_effect=[
                    description,
                    {"Stacks": [stack]},
                    {"TemplateBody": {"Resources": {}}},
                ],
            ) as aws, mock.patch.object(
                LIVE, "validate_deployment_role_policies"
            ), mock.patch.object(
                LIVE, "record"
            ), contextlib.redirect_stdout(
                io.StringIO()
            ):
                LIVE.bootstrap_refresh_verify(args)

        self.assertEqual(ledger["bootstrap_stack_id"], self.bootstrap_stack_id())
        self.assertTrue(ledger["bootstrap_refresh_complete"])
        for call in aws.call_args_list:
            arguments = call.args[0]
            if "--stack-name" in arguments:
                self.assertEqual(
                    arguments[arguments.index("--stack-name") + 1],
                    self.bootstrap_stack_id(),
                )

    def test_bootstrap_refresh_verify_rejects_replacement_identities(self):
        base_ledger = self.refresh_ledger()
        change_set_id = (
            "arn:aws:cloudformation:us-west-2:111122223333:changeSet/"
            "bootstrap-refresh-release-one/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        )
        base_ledger.update(
            {
                "bootstrap_refresh_change_set_arn": change_set_id,
                "bootstrap_refresh_change_set_name": "bootstrap-refresh-release-one",
                "bootstrap_refresh_template_sha256": "c" * 64,
            }
        )
        evidence = {
            "change_set_id": change_set_id,
            "change_set_name": base_ledger["bootstrap_refresh_change_set_name"],
            "stack_name": base_ledger["bootstrap_stack_name"],
            "stack_id": base_ledger["bootstrap_stack_id"],
            "change_set_type": "UPDATE",
            "template_sha256": base_ledger["bootstrap_refresh_template_sha256"],
            "release_id": base_ledger["release_id"],
            "publication_source_tree_sha256": base_ledger[
                "publication_source_tree_sha256"
            ],
        }
        exact_description = {
            "ChangeSetId": change_set_id,
            "ChangeSetName": base_ledger["bootstrap_refresh_change_set_name"],
            "StackName": base_ledger["bootstrap_stack_name"],
            "StackId": base_ledger["bootstrap_stack_id"],
            "Status": "CREATE_COMPLETE",
            "ExecutionStatus": "EXECUTE_COMPLETE",
        }
        args = mock.Mock(
            execution_id=base_ledger["execution_id"],
            confirm=base_ledger["execution_id"],
        )
        principal = {
            "Account": base_ledger["account_id"],
            "Arn": base_ledger["trusted_principal_arn"],
        }

        with tempfile.TemporaryDirectory() as directory:
            ledger_path = Path(directory) / "ledger.json"
            (
                ledger_path.parent / "bootstrap-refresh-change-set-review.json"
            ).write_text(json.dumps(evidence))
            mutations = {
                "ChangeSetId": change_set_id + "-other",
                "ChangeSetName": "bootstrap-refresh-other",
                "StackName": base_ledger["bootstrap_stack_name"] + "-replacement",
                "StackId": base_ledger["bootstrap_stack_id"] + "-replacement",
            }
            for field, replacement in mutations.items():
                with self.subTest(field=field):
                    ledger = dict(base_ledger)
                    with mock.patch.object(
                        LIVE, "load_ledger", return_value=(ledger_path, ledger)
                    ), mock.patch.object(
                        LIVE,
                        "working_tree_digest",
                        return_value=ledger["publication_source_tree_sha256"],
                    ), mock.patch.object(
                        LIVE, "identity", return_value=principal
                    ), mock.patch.object(
                        LIVE, "assume_env", return_value={"SAFE": "1"}
                    ), mock.patch.object(
                        LIVE,
                        "aws_json",
                        return_value={**exact_description, field: replacement},
                    ) as aws:
                        with self.assertRaises(LIVE.LiveTestError):
                            LIVE.bootstrap_refresh_verify(args)
                    aws.assert_called_once()

            replacement_stack = {
                **self.refresh_stack(base_ledger),
                "StackId": base_ledger["bootstrap_stack_id"] + "-replacement",
            }
            with mock.patch.object(
                LIVE, "load_ledger", return_value=(ledger_path, dict(base_ledger))
            ), mock.patch.object(
                LIVE,
                "working_tree_digest",
                return_value=base_ledger["publication_source_tree_sha256"],
            ), mock.patch.object(
                LIVE, "identity", return_value=principal
            ), mock.patch.object(
                LIVE, "assume_env", return_value={"SAFE": "1"}
            ), mock.patch.object(
                LIVE,
                "aws_json",
                side_effect=[exact_description, {"Stacks": [replacement_stack]}],
            ) as aws:
                with self.assertRaisesRegex(LIVE.LiveTestError, "exact stack identity"):
                    LIVE.bootstrap_refresh_verify(args)
            self.assertEqual(aws.call_count, 2)

    def test_stack_absence_check_fails_closed_on_aws_errors(self):
        missing = mock.Mock(
            returncode=255,
            stderr=(
                "An error occurred (ValidationError) when calling the "
                "DescribeStacks operation: Stack with id absent does not exist"
            ),
        )
        denied = mock.Mock(
            returncode=255,
            stderr=(
                "An error occurred (AccessDenied) when calling the "
                "DescribeStacks operation"
            ),
        )
        with mock.patch.object(LIVE, "command", return_value=missing):
            LIVE.assert_absent_stack("absent", "us-west-2")
        with mock.patch.object(LIVE, "command", return_value=denied):
            with self.assertRaises(LIVE.LiveTestError):
                LIVE.assert_absent_stack("unknown", "us-west-2")

    def test_bootstrap_roles_are_temporary_and_not_administrator(self):
        template = (
            ROOT
            / "recipes"
            / "vapi-amazon-connect-screen-pop"
            / "cloudformation"
            / "test-deployment-role.yaml"
        ).read_text()
        self.assertIn("QualificationRole:", template)
        self.assertIn("DeploymentRole:", template)
        self.assertIn("CloudFormationExecutionRole:", template)
        self.assertIn("bridgefu-${ExecutionId}-deployer", template)
        self.assertIn("bridgefu-${ExecutionId}-cloudformation", template)
        self.assertIn("bridgefu-${ExecutionId}-qualifier", template)
        self.assertIn("lambda:PutFunctionConcurrency", template)
        self.assertIn("lambda:DeleteFunctionConcurrency", template)
        self.assertIn("events.amazonaws.com", template)
        for action in (
            "connect:AssociateLambdaFunction",
            "connect:CreateIntegrationAssociation",
            "connect:DeleteIntegrationAssociation",
            "connect:DisassociateLambdaFunction",
            "connect:ListIntegrationAssociations",
            "connect:ListLambdaFunctions",
        ):
            self.assertIn(action, template)
        self.assertNotIn("AdministratorAccess", template)
        parsed = yaml.load(template, Loader=CfnLoader)

        def scalar_values(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    yield key
                    yield from scalar_values(child)
            elif isinstance(value, list):
                for child in value:
                    yield from scalar_values(child)
            else:
                yield value

        values = set(scalar_values(parsed))
        self.assertNotIn("iam:*", values)
        self.assertNotIn("connect:*", values)
        source = SCRIPT.read_text()
        self.assertIn('"bootstrap_stack_adopted"', source)
        self.assertIn("adopted bootstrap stack parameters do not match", source)
        self.assertIn("adopted bootstrap stack ownership tags do not match", source)
        self.assertIn("bootstrap stack returned unexpected role ARNs", source)
        self.assertIn('"--role-arn"', source)
        self.assertIn('ledger["cloudformation_execution_role_arn"]', source)

    def test_deployer_can_revalidate_only_its_ephemeral_vapi_secrets(self):
        template = (
            ROOT
            / "recipes"
            / "vapi-amazon-connect-screen-pop"
            / "cloudformation"
            / "test-deployment-role.yaml"
        ).read_text()
        statement = template.split(
            "Sid: ManageOnlyEphemeralVapiVerificationSecrets", 1
        )[1].split("- !Ref AWS::NoValue", 1)[0]
        self.assertIn("secretsmanager:GetSecretValue", statement)
        self.assertIn("bridgefu-${ExecutionId}-vapi-api-key-*", statement)
        self.assertIn("bridgefu-${ExecutionId}-vapi-public-key-*", statement)
        self.assertNotIn("Resource: '*'", statement)

    def test_failed_bootstrap_refresh_review_can_be_retired_exactly(self):
        bootstrap_stack_id = (
            "arn:aws:cloudformation:us-west-2:111122223333:stack/"
            "bridgefu-bft-safe1-bootstrap/12345678-1234-1234-1234-123456789abc"
        )
        change_set_id = (
            "arn:aws:cloudformation:us-west-2:111122223333:changeSet/"
            "bootstrap-refresh-release-one/"
            "00000000-0000-0000-0000-000000000010"
        )
        ledger = {
            "execution_id": "bft-safe1",
            "account_id": "111122223333",
            "partition": "aws",
            "region": "us-west-2",
            "bootstrap_stack_name": "bridgefu-bft-safe1-bootstrap",
            "bootstrap_stack_id": bootstrap_stack_id,
            "bootstrap_refresh_change_set_arn": change_set_id,
            "bootstrap_refresh_change_set_name": "bootstrap-refresh-release-one",
            "release_id": "release-one",
        }
        failed = {
            "ChangeSetId": change_set_id,
            "ChangeSetName": "bootstrap-refresh-release-one",
            "StackName": "bridgefu-bft-safe1-bootstrap",
            "StackId": bootstrap_stack_id,
            "Status": "FAILED",
            "ExecutionStatus": "UNAVAILABLE",
        }
        with mock.patch.object(LIVE, "aws_json", side_effect=[failed, {}]) as aws:
            self.assertEqual(
                LIVE.retire_pending_bootstrap_refresh(ledger, {"SAFE": "1"}),
                "bootstrap-refresh-release-one",
            )
        self.assertEqual(aws.call_count, 2)
        self.assertEqual(aws.call_args_list[-1].args[0][1], "delete-change-set")
        for call in aws.call_args_list:
            arguments = call.args[0]
            self.assertEqual(
                arguments[arguments.index("--stack-name") + 1],
                bootstrap_stack_id,
            )

        with mock.patch.object(
            LIVE,
            "aws_json",
            return_value={**failed, "StackId": bootstrap_stack_id + "-replacement"},
        ) as aws:
            with self.assertRaises(LIVE.LiveTestError):
                LIVE.retire_pending_bootstrap_refresh(ledger, {"SAFE": "1"})
        aws.assert_called_once()

    def test_disposable_runner_is_reviewed_and_deployed_before_application(self):
        source = SCRIPT.read_text()
        qualification_reviewer = source.split(
            "def review_qualification_runner_change_set(", 1
        )[1].split("def create_change_set", 1)[0]
        self.assertLess(
            qualification_reviewer.index(
                'ledger["qualification_review_stack_id"] = '
                "qualification_review_stack_id"
            ),
            qualification_reviewer.index("aws_wait("),
        )
        planner = source.split(
            "def create_change_set(args: argparse.Namespace) -> None:", 1
        )[1].split("def bind_qualification_source", 1)[0]
        self.assertLess(
            planner.index("review_qualification_runner_change_set"),
            planner.index('change_set_name = f"reviewed-'),
        )
        self.assertEqual(source.count('"--on-stack-failure"'), 2)
        self.assertGreaterEqual(source.count('"DO_NOTHING"'), 4)
        application_reviewer = planner.split('change_set_name = f"reviewed-', 1)[1]
        self.assertLess(
            application_reviewer.index('ledger["review_stack_id"] = review_stack_id'),
            application_reviewer.index("aws_wait("),
        )
        executor = source.split("def execute(args: argparse.Namespace) -> None:", 1)[
            1
        ].split("def stack_description", 1)[0]
        self.assertLess(
            executor.index('"qualification_change_set_execution_requested"'),
            executor.index("application_execution ="),
        )
        self.assertIn('"qualification_runner_deployed"', executor)
        self.assertIn('"qualification-runner-failure-events.json"', executor)
        destroyer = source.split("def destroy(args: argparse.Namespace) -> None:", 1)[
            1
        ].split("def destroy_finalize", 1)[0]
        self.assertLess(
            destroyer.index('"recipe_stack"'),
            destroyer.index('"qualification_runner_stack"'),
        )

    def test_vapi_verification_secrets_are_created_after_bootstrap_refresh(self):
        source = SCRIPT.read_text()
        publisher = source.split("def publish(args: argparse.Namespace) -> None:", 1)[
            1
        ].split("def resolve_ns", 1)[0]
        planner = source.split(
            "def create_change_set(args: argparse.Namespace) -> None:", 1
        )[1].split("def bind_qualification_source", 1)[0]
        self.assertNotIn("ensure_vapi_verification_secrets", publisher)
        self.assertIn("ensure_vapi_verification_secrets(path, ledger, env)", planner)
        self.assertLess(
            planner.index('if not ledger.get("bootstrap_refresh_complete")'),
            planner.index("ensure_vapi_verification_secrets(path, ledger, env)"),
        )

    def test_publisher_rechecks_source_before_manifest_binding_or_upload(self):
        source = SCRIPT.read_text()
        publisher = source.split("def publish(args: argparse.Namespace) -> None:", 1)[
            1
        ].split("def resolve_ns", 1)[0]
        release_builder = publisher.index('"build-recipe-release.py"')
        mutation_guard = publisher.index(
            "working tree changed while building the release bundle"
        )
        manifest_binding = publisher.index(
            'manifest_bytes = (release / "manifest.json").read_bytes()'
        )
        first_upload = publisher.index('"put-object"')
        self.assertLess(release_builder, mutation_guard)
        self.assertLess(mutation_guard, manifest_binding)
        self.assertLess(mutation_guard, first_upload)

    def test_headless_proof_preserves_the_stable_lifecycle_status(self):
        source = SCRIPT.read_text()
        headless = source.split("def run_headless", 1)[1].split("def parser", 1)[0]
        self.assertIn('{"verified", "lifecycle_verified"}', headless)
        self.assertIn('ledger["headless_qualification_verified"] = True', headless)
        self.assertNotIn('ledger["status"] = "headless_verified"', headless)

    def test_evidence_contract_does_not_include_customer_identifiers(self):
        source = SCRIPT.read_text()
        self.assertIn('"customer_data_retained": False', source)
        self.assertNotIn('"correlation_id": correlation_id,', source)
        self.assertNotIn('"webhook": webhook', source)
        self.assertIn('"demo_site_public_key_sha256"', source)
        self.assertNotIn('"demo_site_public_key": public_key', source)

    def test_optional_demo_site_resources_are_explicitly_allowlisted(self):
        self.assertTrue(
            {
                "AWS::CloudFront::Distribution",
                "AWS::CloudFront::OriginAccessControl",
                "AWS::CloudFront::CachePolicy",
                "AWS::CloudFront::ResponseHeadersPolicy",
                "AWS::S3::Bucket",
                "AWS::S3::BucketPolicy",
                "Custom::BridgefuDemoSite",
            }.issubset(LIVE.ALLOWED_STACK_RESOURCE_TYPES)
        )

    def test_artifact_bucket_creator_pins_exact_encryption_rule(self):
        ledger = {
            "region": "us-west-2",
            "artifact_bucket": ("bridgefu-recipe-111122223333-us-west-2-bft-safe1"),
            "execution_id": "bft-safe1",
        }
        with mock.patch.object(LIVE, "aws_json", return_value={}) as aws:
            LIVE.create_bucket(ledger, {"AWS_PROFILE": "test"})
        encryption_calls = [
            call
            for call in aws.call_args_list
            if call.args[0][:2] == ["s3api", "put-bucket-encryption"]
        ]
        self.assertEqual(len(encryption_calls), 1)
        command = encryption_calls[0].args[0]
        configuration_index = command.index("--server-side-encryption-configuration")
        self.assertEqual(
            json.loads(command[configuration_index + 1]),
            {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        },
                        "BucketKeyEnabled": True,
                        "BlockedEncryptionTypes": {"EncryptionType": ["SSE-C"]},
                    }
                ]
            },
        )

    def test_recipe_bucket_templates_pin_exact_encryption_rule(self):
        cloudformation = (
            ROOT / "recipes" / "vapi-amazon-connect-screen-pop" / "cloudformation"
        )
        templates = [
            cloudformation / "account-foundation.yaml",
            cloudformation / "account-governance.yaml",
            cloudformation / "nested" / "demo-site.yaml",
        ]
        expected_rule = {
            "ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
            "BucketKeyEnabled": True,
            "BlockedEncryptionTypes": {"EncryptionType": ["SSE-C"]},
        }
        for template in templates:
            document = yaml.load(template.read_text(), Loader=CfnLoader)
            buckets = {
                logical_id: resource
                for logical_id, resource in document["Resources"].items()
                if resource["Type"] == "AWS::S3::Bucket"
            }
            self.assertTrue(buckets, template.name)
            for logical_id, bucket in buckets.items():
                with self.subTest(template=template.name, bucket=logical_id):
                    self.assertEqual(
                        bucket["Properties"]["BucketEncryption"][
                            "ServerSideEncryptionConfiguration"
                        ],
                        [expected_rule],
                    )

    def test_recursive_review_allowlist_covers_only_the_production_application(self):
        cloudformation = (
            ROOT / "recipes" / "vapi-amazon-connect-screen-pop" / "cloudformation"
        )
        templates = [cloudformation / "template.yaml"]
        templates.extend(
            path
            for path in sorted((cloudformation / "nested").glob("*.yaml"))
            if path.name != "demo-connect.yaml"
        )
        resource_types: set[str] = set()
        for template in templates:
            document = yaml.load(template.read_text(), Loader=CfnLoader)
            resource_types.update(
                resource["Type"] for resource in document.get("Resources", {}).values()
            )
        self.assertEqual(
            resource_types - LIVE.ALLOWED_STACK_RESOURCE_TYPES,
            set(),
        )
        disposable_connect_types = {
            "AWS::Connect::Instance",
            "AWS::Connect::User",
            "AWS::Connect::Queue",
        }
        self.assertFalse(disposable_connect_types & resource_types)
        self.assertTrue(
            disposable_connect_types.issubset(LIVE.ALLOWED_STACK_RESOURCE_TYPES)
        )

    def test_ha_resources_and_inventory_are_explicitly_guarded(self):
        source = SCRIPT.read_text()
        self.assertIn('"describe-instances"', source)
        self.assertIn('states == ["terminated"]', source)
        self.assertIn('"InvalidInstanceID.NotFound"', source)
        self.assertIn('"describe-volumes"', source)
        self.assertIn('"InvalidVolume.NotFound"', source)
        self.assertTrue(
            {
                "AWS::AutoScaling::AutoScalingGroup",
                "AWS::AutoScaling::LifecycleHook",
                "AWS::EC2::LaunchTemplate",
                "AWS::EC2::NatGateway",
                "AWS::ECS::Cluster",
                "AWS::ECS::Service",
                "AWS::ECS::TaskDefinition",
                "AWS::ElastiCache::ReplicationGroup",
                "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "AWS::RDS::DBInstance",
            }.issubset(LIVE.ALLOWED_STACK_RESOURCE_TYPES)
        )
        self.assertFalse(
            LIVE.inventory_has_leftovers(
                {
                    "tagged_resource_arns": [],
                    "private_tls_secret_arns": [],
                    "iam_policy_arns": [],
                }
            )
        )
        self.assertTrue(
            LIVE.inventory_has_leftovers(
                {"private_tls_secret_arns": ["arn:aws:secretsmanager:example"]}
            )
        )
        self.assertTrue(
            LIVE.inventory_has_leftovers(
                {"iam_policy_arns": ["arn:aws:iam::123456789012:policy/example"]}
            )
        )
        self.assertTrue(
            LIVE.inventory_has_leftovers(
                {"review_stack_ids": ["arn:aws:cloudformation:review"]}
            )
        )
        self.assertTrue(
            LIVE.inventory_has_leftovers(
                {"connect_log_group_names": ["/aws/connect/bft-test-connect"]}
            )
        )

    def test_destroyed_ledgers_are_reaudited_and_orphan_cleanup_is_exact(self):
        source = SCRIPT.read_text()
        inventory = source.split("def inventory_for_execution", 1)[1].split(
            "def inventory_has_leftovers", 1
        )[0]
        self.assertIn('"REVIEW_IN_PROGRESS"', inventory)
        self.assertIn('"review_stack_ids"', inventory)
        self.assertIn('"connect_log_group_names"', inventory)
        destroy = source.split("def destroy(args", 1)[1].split(
            "def destroy_finalize", 1
        )[0]
        self.assertIn('"destroyed_ledger_reaudit_failed"', destroy)
        self.assertIn("delete_owned_empty_review_stacks", destroy)
        self.assertLess(
            destroy.index("review_stack_ids_for_execution(ledger)"),
            destroy.index('record(path, ledger, "bootstrap_stack_delete_requested")'),
        )
        preview_cleanup = source.split(
            "def delete_owned_empty_review_stacks", 1
        )[1].split("def cleanup_orphans", 1)[0]
        cleanup = source.split("def cleanup_orphans", 1)[1].split(
            "def run_headless", 1
        )[0]
        self.assertIn("without exact tags or ledger ancestry", preview_cleanup)
        self.assertIn("top_level_review_stack_is_owned_by_ledger", preview_cleanup)
        self.assertIn("delete_owned_empty_review_stacks", cleanup)
        self.assertIn("owned_connect_log_group_exists(ledger, None)", cleanup)
        self.assertIn("unless it is exact and empty", cleanup)
        self.assertIn('"orphan-cleanup-evidence.json"', cleanup)

    def test_empty_preview_cleanup_deletes_children_before_parents(self):
        execution = "bft-20990102a"
        root_name = f"bridgefu-{execution}"
        root_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:stack/"
            f"{root_name}/00000000-0000-0000-0000-000000000000"
        )
        parent_name = f"{root_name}-RecipeApplication-AAAA"
        parent_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:stack/"
            f"{parent_name}/00000000-0000-0000-0000-000000000001"
        )
        child_name = f"{parent_name}-Network-BBBB"
        child_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:stack/"
            f"{child_name}/00000000-0000-0000-0000-000000000002"
        )
        ledger = {
            "execution_id": execution,
            "account_id": "123456789012",
            "region": "us-west-2",
            "stack_name": root_name,
            "review_stack_id": root_id,
            "created_at": "2000-01-01T00:00:00Z",
        }
        descriptions = {
            parent_id: {
                "StackName": parent_name,
                "StackId": parent_id,
                "StackStatus": "REVIEW_IN_PROGRESS",
                "RootId": root_id,
                "ParentId": root_id,
                "CreationTime": "2000-01-01T00:01:00Z",
            },
            child_id: {
                "StackName": child_name,
                "StackId": child_id,
                "StackStatus": "REVIEW_IN_PROGRESS",
                "RootId": root_id,
                "ParentId": parent_id,
                "CreationTime": "2000-01-01T00:02:00Z",
            },
        }
        deleted = []

        def aws_response(arguments, **_kwargs):
            stack_id = arguments[arguments.index("--stack-name") + 1]
            if "describe-stacks" in arguments:
                return {"Stacks": [descriptions[stack_id]]}
            if "list-stack-resources" in arguments:
                return {"StackResourceSummaries": []}
            if "delete-stack" in arguments:
                deleted.append(stack_id)
                return {}
            self.fail(f"unexpected AWS operation: {arguments}")

        with mock.patch.object(
            LIVE, "aws_json", side_effect=aws_response
        ), mock.patch.object(LIVE, "aws_wait") as waiter:
            self.assertEqual(
                LIVE.delete_owned_empty_review_stacks(
                    ledger, [parent_id, child_id], environment={"SAFE": "1"}
                ),
                [child_id, parent_id],
            )
        self.assertEqual(deleted, [child_id, parent_id])
        self.assertEqual(waiter.call_count, 2)

    def test_top_level_preview_shell_requires_exact_id_and_full_tags(self):
        execution = "bft-20990102a"
        name = f"bridgefu-{execution}"
        stack_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:stack/"
            f"{name}/00000000-0000-0000-0000-000000000000"
        )
        ledger = {
            "execution_id": execution,
            "stack_name": name,
            "qualification_stack_name": f"{name}-qualification",
            "review_stack_id": stack_id,
        }
        description = {
            "StackName": name,
            "StackId": stack_id,
            "Tags": [
                {"Key": "Project", "Value": LIVE.PROJECT},
                {"Key": "ManagedBy", "Value": LIVE.MANAGED_BY},
                {"Key": "BridgefuExecutionId", "Value": execution},
                {"Key": "BridgefuRecipe", "Value": LIVE.RECIPE},
            ],
        }
        self.assertTrue(
            LIVE.top_level_review_stack_is_owned_by_ledger(ledger, description)
        )
        description["StackId"] = stack_id.replace("00000000", "11111111", 1)
        self.assertFalse(
            LIVE.top_level_review_stack_is_owned_by_ledger(ledger, description)
        )
        description["StackId"] = stack_id
        description["Tags"] = description["Tags"][:-1]
        self.assertFalse(
            LIVE.top_level_review_stack_is_owned_by_ledger(ledger, description)
        )

    def test_connect_log_group_ownership_requires_the_full_tag_contract(self):
        execution = "bft-20990102a"
        name = f"/aws/connect/{execution}-connect"
        arn = f"arn:aws:logs:us-west-2:123456789012:log-group:{name}"
        ledger = {"execution_id": execution, "region": "us-west-2"}
        group = {"logGroupName": name, "logGroupArn": arn + ":*"}
        full_tags = {
            "Project": LIVE.PROJECT,
            "ManagedBy": "bridgefu-cloudformation",
            "BridgefuExecutionId": execution,
            "BridgefuRecipe": LIVE.RECIPE,
        }
        with mock.patch.object(
            LIVE,
            "aws_json",
            side_effect=[{"logGroups": [group]}, {"tags": full_tags}],
        ):
            self.assertTrue(LIVE.owned_connect_log_group_exists(ledger, None))
        with mock.patch.object(
            LIVE,
            "aws_json",
            side_effect=[
                {"logGroups": [group]},
                {
                    "tags": {
                        key: value
                        for key, value in full_tags.items()
                        if key != "BridgefuRecipe"
                    }
                },
            ],
        ), self.assertRaises(LIVE.LiveTestError):
            LIVE.owned_connect_log_group_exists(ledger, None)

    def test_tagless_nested_preview_shell_requires_exact_ledger_ancestry(self):
        execution = "bft-20990103a"
        root = f"bridgefu-{execution}"
        ledger = {
            "execution_id": execution,
            "stack_name": root,
            "region": "us-east-1",
            "account_id": "123456789012",
            "created_at": "2000-01-01T00:00:00Z",
            "destroyed_at": "2000-01-01T00:10:00Z",
        }
        root_id = (
            "arn:aws:cloudformation:us-east-1:123456789012:stack/"
            f"{root}/00000000-0000-0000-0000-000000000010"
        )
        ledger["review_stack_id"] = root_id
        name = f"{root}-RecipeApplication-ABC123"
        description = {
            "StackName": name,
            "StackId": (
                "arn:aws:cloudformation:us-east-1:123456789012:stack/"
                f"{name}/00000000-0000-0000-0000-000000000011"
            ),
            "RootId": root_id,
            "ParentId": root_id,
            "CreationTime": "2000-01-01T00:05:00+00:00",
        }
        self.assertTrue(LIVE.review_stack_is_owned_by_ledger(ledger, description))
        description["RootId"] = description["RootId"].replace(
            root, "bridgefu-bft-other"
        )
        self.assertFalse(LIVE.review_stack_is_owned_by_ledger(ledger, description))

    def test_terminated_instance_tag_index_entries_are_tombstones(self):
        terminated = mock.Mock(
            returncode=0,
            stdout=json.dumps(
                {"Reservations": [{"Instances": [{"State": {"Name": "terminated"}}]}]}
            ),
            stderr="",
        )
        running = mock.Mock(
            returncode=0,
            stdout=json.dumps(
                {"Reservations": [{"Instances": [{"State": {"Name": "running"}}]}]}
            ),
            stderr="",
        )
        absent = mock.Mock(
            returncode=255,
            stdout="",
            stderr="InvalidInstanceID.NotFound",
        )
        empty = mock.Mock(
            returncode=0,
            stdout=json.dumps({"Reservations": []}),
            stderr="",
        )
        with mock.patch.object(LIVE, "command", return_value=terminated):
            self.assertTrue(LIVE.ec2_instance_is_tombstone("us-east-1", "i-123"))
        with mock.patch.object(LIVE, "command", return_value=running):
            self.assertFalse(LIVE.ec2_instance_is_tombstone("us-east-1", "i-123"))
        with mock.patch.object(LIVE, "command", return_value=absent):
            self.assertTrue(LIVE.ec2_instance_is_tombstone("us-east-1", "i-123"))
        with mock.patch.object(LIVE, "command", return_value=empty):
            self.assertTrue(LIVE.ec2_instance_is_tombstone("us-east-1", "i-123"))

    def test_deleted_nat_gateway_tag_index_entries_are_tombstones(self):
        deleted = mock.Mock(
            returncode=0,
            stdout=json.dumps({"NatGateways": [{"State": "deleted"}]}),
            stderr="",
        )
        available = mock.Mock(
            returncode=0,
            stdout=json.dumps({"NatGateways": [{"State": "available"}]}),
            stderr="",
        )
        absent = mock.Mock(
            returncode=254, stdout="", stderr="NatGatewayNotFound"
        )
        denied = mock.Mock(returncode=255, stdout="", stderr="AccessDenied")
        with mock.patch.object(LIVE, "command", return_value=deleted):
            self.assertTrue(LIVE.ec2_nat_gateway_is_tombstone("us-east-1", "nat-123"))
        with mock.patch.object(LIVE, "command", return_value=available):
            self.assertFalse(LIVE.ec2_nat_gateway_is_tombstone("us-east-1", "nat-123"))
        with mock.patch.object(LIVE, "command", return_value=absent):
            self.assertTrue(LIVE.ec2_nat_gateway_is_tombstone("us-east-1", "nat-123"))
        with mock.patch.object(LIVE, "command", return_value=denied):
            self.assertFalse(LIVE.ec2_nat_gateway_is_tombstone("us-east-1", "nat-123"))

    def test_tagged_resource_tombstones_require_exact_provider_identity(self):
        arn = "arn:aws:ec2:us-west-2:123456789012:natgateway/nat-123"
        with mock.patch.object(
            LIVE, "ec2_nat_gateway_is_tombstone", return_value=True
        ) as tombstone:
            self.assertTrue(
                LIVE.tagged_resource_is_proven_absent(
                    arn, "123456789012", "us-west-2"
                )
            )
            self.assertFalse(
                LIVE.tagged_resource_is_proven_absent(
                    arn, "999999999999", "us-west-2"
                )
            )
            self.assertFalse(
                LIVE.tagged_resource_is_proven_absent(
                    arn, "123456789012", "us-east-1"
                )
            )
        tombstone.assert_called_once_with("us-west-2", "nat-123")
        init_guard = SCRIPT.read_text().split(
            "def assert_no_account_live_state_for_init", 1
        )[1].split("def ", 1)[0]
        self.assertIn("tagged_resource_is_proven_absent", init_guard)

    def test_starter_capacity_gate_reserves_the_complete_two_stack_path(self):
        ledger = {
            "runtime_profile": "starter",
            "connect_mode": "disposable",
            "deployment_availability_zones": ["us-west-2a", "us-west-2b"],
            "qualification_availability_zone": "us-west-2a",
        }
        self.assertEqual(
            LIVE.capacity_requirements(ledger, "qualification"),
            {
                "vpcs": 2,
                "internet_gateways": 2,
                "elastic_ips": 1,
                "connect_instances": 1,
                "nat_gateways_by_zone": {"us-west-2a": 1},
            },
        )
        self.assertEqual(LIVE.capacity_requirements(ledger, "application")["vpcs"], 1)

    def test_disposable_public_key_is_bound_across_shell_restarts(self):
        ledger = {"connect_mode": "disposable", "enable_demo_site": False}
        with mock.patch.dict(
            LIVE.os.environ, {LIVE.PUBLIC_KEY_ENV: "pk_test_browser_123456"}
        ):
            LIVE.bound_vapi_public_key(ledger, allow_bind=True)
        self.assertRegex(ledger["vapi_public_key_sha256"], r"^[0-9a-f]{64}$")
        with mock.patch.dict(
            LIVE.os.environ, {LIVE.PUBLIC_KEY_ENV: "pk_different_browser_789"}
        ), self.assertRaises(LIVE.LiveTestError):
            LIVE.bound_vapi_public_key(ledger)

    def versioned_bucket_ledger(self) -> dict:
        return {
            "artifact_bucket": "owned",
            "account_id": "111122223333",
            "region": "us-west-2",
        }

    def test_versioned_bucket_delete_accepts_blank_quiet_success_then_relists(self):
        listing = {
            "Versions": [{"Key": "release/a", "VersionId": "v1"}],
            "DeleteMarkers": [],
        }
        responses = [
            mock.Mock(returncode=0, stdout=json.dumps(listing), stderr=""),
            mock.Mock(returncode=0, stdout="\n", stderr=""),
            mock.Mock(
                returncode=0,
                stdout=json.dumps({"Versions": [], "DeleteMarkers": []}),
                stderr="",
            ),
        ]
        with mock.patch.object(LIVE, "command", side_effect=responses) as command:
            LIVE.empty_versioned_bucket(self.versioned_bucket_ledger(), {})
        self.assertEqual(command.call_count, 3)
        delete_command = command.call_args_list[1].args[0]
        self.assertEqual(delete_command[:3], ["aws", "s3api", "delete-objects"])
        payload_index = delete_command.index("--delete")
        self.assertEqual(
            json.loads(delete_command[payload_index + 1]),
            {
                "Objects": [{"Key": "release/a", "VersionId": "v1"}],
                "Quiet": True,
            },
        )
        self.assertEqual(
            command.call_args_list[2].args[0][:3],
            ["aws", "s3api", "list-object-versions"],
        )

    def test_versioned_bucket_delete_accepts_empty_quiet_object_then_relists(self):
        listing = {
            "Versions": [{"Key": "release/a", "VersionId": "v1"}],
            "DeleteMarkers": [],
        }
        empty = {"Versions": [], "DeleteMarkers": []}
        for result in ({}, {"Errors": []}):
            with self.subTest(result=result), mock.patch.object(
                LIVE, "aws_json", side_effect=[listing, result, empty]
            ) as aws:
                LIVE.empty_versioned_bucket(self.versioned_bucket_ledger(), {})
            self.assertEqual(aws.call_count, 3)
            self.assertEqual(
                aws.call_args_list[2].args[0][:2],
                ["s3api", "list-object-versions"],
            )

    def test_versioned_bucket_delete_initially_empty_never_requests_delete(self):
        with mock.patch.object(
            LIVE,
            "aws_json",
            return_value={"Versions": [], "DeleteMarkers": []},
        ) as aws:
            LIVE.empty_versioned_bucket(self.versioned_bucket_ledger(), {})
        aws.assert_called_once()
        self.assertEqual(aws.call_args.args[0][:2], ["s3api", "list-object-versions"])

    def test_versioned_bucket_delete_rejects_malformed_or_verbose_quiet_results(self):
        listing = {
            "Versions": [{"Key": "release/a", "VersionId": "v1"}],
            "DeleteMarkers": [],
        }
        invalid_results = [
            [],
            "",
            {"Deleted": []},
            {"Unexpected": True},
            {"Errors": [], "Deleted": []},
            {"Errors": "invalid"},
        ]
        for result in invalid_results:
            with self.subTest(result=result), mock.patch.object(
                LIVE, "aws_json", side_effect=[listing, result]
            ):
                with self.assertRaises(LIVE.LiveTestError):
                    LIVE.empty_versioned_bucket(self.versioned_bucket_ledger(), {})

    def test_versioned_bucket_delete_blank_success_without_progress_is_bounded(self):
        listing = {
            "Versions": [{"Key": "release/a", "VersionId": "v1"}],
            "DeleteMarkers": [],
        }
        with mock.patch.object(
            LIVE,
            "aws_json",
            side_effect=[
                listing,
                None,
                listing,
                None,
                listing,
                None,
                listing,
            ],
        ) as aws:
            with self.assertRaisesRegex(LIVE.LiveTestError, "made no progress"):
                LIVE.empty_versioned_bucket(self.versioned_bucket_ledger(), {})
        self.assertEqual(aws.call_count, 7)

    def test_versioned_bucket_delete_handles_multiple_quiet_batches(self):
        first = {
            "Versions": [{"Key": "release/a", "VersionId": "v1"}],
            "DeleteMarkers": [],
        }
        second = {
            "Versions": [],
            "DeleteMarkers": [{"Key": "release/b", "VersionId": "v2"}],
        }
        empty = {"Versions": [], "DeleteMarkers": []}
        with mock.patch.object(
            LIVE, "aws_json", side_effect=[first, None, second, {}, empty]
        ) as aws:
            LIVE.empty_versioned_bucket(self.versioned_bucket_ledger(), {})
        delete_calls = [
            call
            for call in aws.call_args_list
            if call.args[0][:2] == ["s3api", "delete-objects"]
        ]
        self.assertEqual(len(delete_calls), 2)
        deleted = []
        for call in delete_calls:
            command = call.args[0]
            payload = json.loads(command[command.index("--delete") + 1])
            self.assertTrue(payload["Quiet"])
            deleted.extend(payload["Objects"])
        self.assertEqual(
            deleted,
            [
                {"Key": "release/a", "VersionId": "v1"},
                {"Key": "release/b", "VersionId": "v2"},
            ],
        )

    def test_versioned_bucket_delete_fails_on_per_object_errors(self):
        listing = {
            "Versions": [{"Key": "release/a", "VersionId": "v1"}],
            "DeleteMarkers": [],
        }
        with mock.patch.object(
            LIVE,
            "aws_json",
            side_effect=[listing, {"Errors": [{"Key": "release/a"}]}],
        ), self.assertRaises(LIVE.LiveTestError):
            LIVE.empty_versioned_bucket(self.versioned_bucket_ledger(), {})

    def test_scheduled_secret_deletion_is_idempotent(self):
        arn = "arn:aws:secretsmanager:us-west-2:123456789012:secret:owned"
        description = {
            "ARN": arn,
            "DeletedDate": "2026-08-03T00:00:00Z",
            "Tags": [
                {"Key": "Project", "Value": LIVE.PROJECT},
                {"Key": "ManagedBy", "Value": LIVE.MANAGED_BY},
                {"Key": "BridgefuExecutionId", "Value": "bft-safe1"},
            ],
        }
        response = mock.Mock(returncode=0, stdout=json.dumps(description), stderr="")
        with mock.patch.object(
            LIVE, "command", return_value=response
        ), mock.patch.object(LIVE, "exact_delete") as deletion:
            self.assertFalse(
                LIVE.request_secret_force_delete(
                    {
                        "region": "us-west-2",
                        "execution_id": "bft-safe1",
                    },
                    {},
                    arn,
                    label="test secret",
                )
            )
        deletion.assert_not_called()

    def test_lifecycle_execute_token_binds_attempt_and_change_set(self):
        stack_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:stack/"
            "bridgefu-bft-safe1/00000000-0000-0000-0000-000000000001"
        )
        change_set = {
            "id": "arn:aws:cloudformation:us-west-2:123:changeSet/update/abc",
            "name": "update",
        }
        ledger = {
            "execution_id": "bft-safe1",
            "partition": "aws",
            "region": "us-west-2",
            "account_id": "123456789012",
            "stack_name": "bridgefu-bft-safe1",
            "review_stack_id": stack_id,
            "stack_id": stack_id,
        }
        with mock.patch.object(
            LIVE, "validate_reviewed_update_for_execution", return_value="AVAILABLE"
        ), mock.patch.object(
            LIVE, "require_qualification_deadline", return_value=3_600
        ), mock.patch.object(
            LIVE, "aws_json"
        ) as aws:
            self.assertTrue(
                LIVE.execute_reviewed_update(
                    Path("ledger.json"),
                    ledger,
                    {},
                    change_set,
                    evidence_path=Path("review.json"),
                    ledger_prefix="lifecycle_update",
                    token_suffix="safe-update",
                    attempt=2,
                )
            )
        arguments = aws.call_args.args[0]
        token = arguments[arguments.index("--client-request-token") + 1]
        self.assertIn("safe-update-r2-", token)
        self.assertEqual(arguments[arguments.index("--stack-name") + 1], stack_id)

    def test_stack_id_authority_rejects_name_account_and_region_drift(self):
        ledger = {
            "partition": "aws",
            "region": "us-west-2",
            "account_id": "123456789012",
        }
        valid = (
            "arn:aws:cloudformation:us-west-2:123456789012:stack/"
            "bridgefu-bft-safe1/00000000-0000-0000-0000-000000000001"
        )
        self.assertEqual(
            LIVE.require_stack_id_for_name(
                ledger, valid, "bridgefu-bft-safe1", "test stack"
            ),
            valid,
        )
        invalid = (
            valid.replace("us-west-2", "us-east-1"),
            valid.replace("123456789012", "999999999999"),
            valid.replace("bridgefu-bft-safe1", "bridgefu-replacement"),
        )
        for stack_id in invalid:
            with self.subTest(stack_id=stack_id), self.assertRaises(LIVE.LiveTestError):
                LIVE.require_stack_id_for_name(
                    ledger, stack_id, "bridgefu-bft-safe1", "test stack"
                )
        with mock.patch.object(LIVE, "aws_json") as aws, self.assertRaises(
            LIVE.LiveTestError
        ):
            LIVE.stack_description(ledger, {}, "bridgefu-bft-safe1")
        aws.assert_not_called()

        change_set_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:changeSet/"
            "reviewed-bft-safe1/00000000-0000-0000-0000-000000000010"
        )
        self.assertEqual(
            LIVE.require_change_set_id_authority(
                ledger,
                change_set_id,
                "test change set",
                expected_name="reviewed-bft-safe1",
            ),
            change_set_id,
        )
        invalid_change_sets = (
            change_set_id.replace("us-west-2", "us-east-1"),
            change_set_id.replace("123456789012", "999999999999"),
            change_set_id.replace("reviewed-bft-safe1", "reviewed-replacement"),
            change_set_id.rsplit("/", 1)[0] + "/not-a-uuid",
        )
        for invalid_change_set_id in invalid_change_sets:
            with self.subTest(
                invalid_change_set_id=invalid_change_set_id
            ), self.assertRaises(LIVE.LiveTestError):
                LIVE.require_change_set_id_authority(
                    ledger,
                    invalid_change_set_id,
                    "test change set",
                    expected_name="reviewed-bft-safe1",
                )
        with mock.patch.object(LIVE, "aws_json") as aws, self.assertRaises(
            LIVE.LiveTestError
        ):
            LIVE.review_change_set_tree(
                ledger,
                {},
                invalid_change_sets[0],
                expected_action="Add",
            )
        aws.assert_not_called()

    def test_execute_resumes_exact_in_progress_create_change_sets_without_reexecution(
        self,
    ):
        application_stack_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:stack/"
            "bridgefu-bft-safe1/00000000-0000-0000-0000-000000000001"
        )
        qualification_stack_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:stack/"
            "bridgefu-bft-safe1-qualification/"
            "00000000-0000-0000-0000-000000000002"
        )
        application_nested_stack_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:stack/"
            "bridgefu-bft-safe1-application/"
            "00000000-0000-0000-0000-000000000003"
        )
        ledger = {
            "execution_id": "bft-safe1",
            "status": "change_set_reviewed",
            "partition": "aws",
            "region": "us-west-2",
            "account_id": "123456789012",
            "connect_mode": "disposable",
            "stack_name": "bridgefu-bft-safe1",
            "review_stack_id": application_stack_id,
            "qualification_stack_name": "bridgefu-bft-safe1-qualification",
            "qualification_review_stack_id": qualification_stack_id,
            "qualification_source_cidr": "203.0.113.10/32",
            "events": [],
        }
        runner = {
            "StackId": qualification_stack_id,
            "StackStatus": "CREATE_COMPLETE",
            "Outputs": [
                {"OutputKey": "ProjectName", "OutputValue": "runner-project"},
                {
                    "OutputKey": "RunnerSourceCidr",
                    "OutputValue": ledger["qualification_source_cidr"],
                },
                {
                    "OutputKey": "RunnerLogGroupName",
                    "OutputValue": "/aws/codebuild/runner-project",
                },
            ],
        }
        application = {
            "StackId": application_stack_id,
            "StackStatus": "CREATE_COMPLETE",
            "Outputs": [
                {"OutputKey": "ConnectInstanceArn", "OutputValue": "arn:connect"},
                {"OutputKey": "ConnectLoginUrl", "OutputValue": "https://login"},
                {
                    "OutputKey": "AgentCredentialSecretArn",
                    "OutputValue": "arn:secret",
                },
            ],
        }

        def stack(_ledger, _environment, stack_id):
            return {
                qualification_stack_id: runner,
                application_stack_id: application,
            }[stack_id]

        args = LIVE.argparse.Namespace(
            execution_id=ledger["execution_id"], confirm=ledger["execution_id"]
        )
        with mock.patch.object(
            LIVE, "load_ledger", return_value=(Path("ledger.json"), ledger)
        ), mock.patch.object(
            LIVE, "require_qualification_deadline", return_value=3_600
        ), mock.patch.object(
            LIVE, "assume_env", return_value={"SAFE": "1"}
        ), mock.patch.object(
            LIVE, "validate_candidate_release"
        ), mock.patch.object(
            LIVE,
            "validate_reviewed_create_for_execution",
            return_value="EXECUTE_IN_PROGRESS",
        ), mock.patch.object(
            LIVE, "ensure_capacity_before_execute"
        ) as capacity, mock.patch.object(
            LIVE, "aws_json"
        ) as aws, mock.patch.object(
            LIVE, "aws_wait"
        ) as waiter, mock.patch.object(
            LIVE, "stack_description", side_effect=stack
        ), mock.patch.object(
            LIVE, "nested_stack_id", return_value=application_nested_stack_id
        ), mock.patch.object(
            LIVE, "exact_nested_stack_description", return_value={}
        ), mock.patch.object(
            LIVE, "bind_deployed_vapi_resources", return_value={}
        ), mock.patch.object(
            LIVE, "record"
        ), mock.patch.object(
            LIVE, "mirror_recovery_snapshot"
        ), contextlib.redirect_stdout(
            io.StringIO()
        ):
            LIVE.execute(args)

        capacity.assert_not_called()
        aws.assert_not_called()
        self.assertEqual(
            [
                call.args[0][call.args[0].index("--stack-name") + 1]
                for call in waiter.call_args_list
            ],
            [qualification_stack_id, application_stack_id],
        )
        self.assertEqual(ledger["qualification_stack_id"], qualification_stack_id)
        self.assertEqual(ledger["stack_id"], application_stack_id)

    def test_preexecution_ownership_uses_reviewed_change_set_tags(self):
        source = SCRIPT.read_text()
        validator = source.split(
            "def validate_reviewed_create_for_execution(", 1
        )[1].split("def execute(args", 1)[0]
        self.assertIn(
            'require_ownership_tags(description.get("Tags", []),', validator
        )
        self.assertNotIn(
            'require_ownership_tags(stack.get("Tags", []),', validator
        )

    def test_execute_rejects_review_deployment_stack_id_drift_before_aws(self):
        reviewed_stack_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:stack/"
            "bridgefu-bft-safe1/00000000-0000-0000-0000-000000000001"
        )
        ledger = {
            "execution_id": "bft-safe1",
            "status": "change_set_reviewed",
            "partition": "aws",
            "region": "us-west-2",
            "account_id": "123456789012",
            "connect_mode": "existing",
            "stack_name": "bridgefu-bft-safe1",
            "review_stack_id": reviewed_stack_id,
            "stack_id": reviewed_stack_id[:-1] + "2",
        }
        args = LIVE.argparse.Namespace(
            execution_id=ledger["execution_id"], confirm=ledger["execution_id"]
        )
        with mock.patch.object(
            LIVE, "load_ledger", return_value=(Path("ledger.json"), ledger)
        ), mock.patch.object(
            LIVE, "require_qualification_deadline", return_value=3_600
        ), mock.patch.object(
            LIVE, "assume_env", return_value={"SAFE": "1"}
        ), mock.patch.object(
            LIVE, "validate_candidate_release"
        ), mock.patch.object(
            LIVE, "validate_reviewed_create_for_execution"
        ) as validate, mock.patch.object(
            LIVE, "aws_json"
        ) as aws, mock.patch.object(
            LIVE, "aws_wait"
        ) as waiter, self.assertRaisesRegex(
            LIVE.LiveTestError, "differs from its reviewed create ID"
        ):
            LIVE.execute(args)
        validate.assert_not_called()
        aws.assert_not_called()
        waiter.assert_not_called()

    def test_verify_reads_application_and_qualification_by_exact_stack_id(self):
        application_stack_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:stack/"
            "bridgefu-bft-safe1/00000000-0000-0000-0000-000000000001"
        )
        qualification_stack_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:stack/"
            "bridgefu-bft-safe1-qualification/"
            "00000000-0000-0000-0000-000000000002"
        )
        ledger = {
            "execution_id": "bft-safe1",
            "status": "deployed",
            "partition": "aws",
            "region": "us-west-2",
            "account_id": "123456789012",
            "connect_mode": "disposable",
            "runtime_profile": "starter",
            "stack_name": "bridgefu-bft-safe1",
            "review_stack_id": application_stack_id,
            "stack_id": application_stack_id,
            "qualification_stack_name": "bridgefu-bft-safe1-qualification",
            "qualification_review_stack_id": qualification_stack_id,
            "qualification_stack_id": qualification_stack_id,
            "qualification_project_name": "runner-project",
            "qualification_source_cidr": "203.0.113.10/32",
            "qualification_runner_log_group_name": "/aws/codebuild/runner-project",
        }
        application = {
            "StackId": application_stack_id,
            "StackStatus": "CREATE_COMPLETE",
            "Outputs": [{"OutputKey": "RuntimeProfile", "OutputValue": "Starter"}],
        }
        qualification = {
            "StackId": qualification_stack_id,
            "StackStatus": "CREATE_COMPLETE",
            "Outputs": [
                {"OutputKey": "ProjectName", "OutputValue": "runner-project"},
                {
                    "OutputKey": "RunnerSourceCidr",
                    "OutputValue": ledger["qualification_source_cidr"],
                },
                {
                    "OutputKey": "RunnerLogGroupName",
                    "OutputValue": ledger["qualification_runner_log_group_name"],
                },
            ],
        }
        identifiers: list[str] = []

        def stack(_ledger, _environment, stack_id):
            identifiers.append(stack_id)
            return {
                application_stack_id: application,
                qualification_stack_id: qualification,
            }[stack_id]

        args = LIVE.argparse.Namespace(execution_id=ledger["execution_id"])
        with mock.patch.object(
            LIVE, "load_ledger", return_value=(Path("ledger.json"), ledger)
        ), mock.patch.object(
            LIVE, "require_qualification_deadline", return_value=3_600
        ), mock.patch.object(
            LIVE, "assume_env", return_value={"SAFE": "1"}
        ), mock.patch.object(
            LIVE, "stack_description", side_effect=stack
        ), mock.patch.object(
            LIVE,
            "nested_stack_id",
            side_effect=LIVE.LiveTestError("verification stopped after root proofs"),
        ), self.assertRaisesRegex(
            LIVE.LiveTestError, "stopped after root proofs"
        ):
            LIVE.verify(args)
        self.assertEqual(identifiers, [application_stack_id, qualification_stack_id])

        drifted = {**ledger, "stack_id": application_stack_id[:-1] + "9"}
        with mock.patch.object(
            LIVE, "load_ledger", return_value=(Path("ledger.json"), drifted)
        ), mock.patch.object(
            LIVE, "require_qualification_deadline", return_value=3_600
        ), mock.patch.object(
            LIVE, "assume_env", return_value={"SAFE": "1"}
        ), mock.patch.object(
            LIVE, "stack_description"
        ) as describe, self.assertRaisesRegex(
            LIVE.LiveTestError, "differs from its reviewed create ID"
        ):
            LIVE.verify(args)
        describe.assert_not_called()

    def test_lifecycle_in_progress_resume_never_reexecutes_and_drift_fails_closed(self):
        stack_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:stack/"
            "bridgefu-bft-safe1/00000000-0000-0000-0000-000000000001"
        )
        ledger = {
            "execution_id": "bft-safe1",
            "partition": "aws",
            "region": "us-west-2",
            "account_id": "123456789012",
            "stack_name": "bridgefu-bft-safe1",
            "review_stack_id": stack_id,
            "stack_id": stack_id,
        }
        change_set = {
            "id": (
                "arn:aws:cloudformation:us-west-2:123456789012:changeSet/"
                "update/00000000-0000-0000-0000-000000000010"
            ),
            "name": "update",
        }
        for ledger_prefix, token_suffix in (
            ("lifecycle_update", "safe-update"),
            ("lifecycle_rollback", "rollback-drill"),
        ):
            with self.subTest(ledger_prefix=ledger_prefix), mock.patch.object(
                LIVE,
                "validate_reviewed_update_for_execution",
                return_value="EXECUTE_IN_PROGRESS",
            ), mock.patch.object(
                LIVE, "require_qualification_deadline"
            ) as deadline, mock.patch.object(
                LIVE, "aws_json"
            ) as aws:
                self.assertFalse(
                    LIVE.execute_reviewed_update(
                        Path("ledger.json"),
                        ledger,
                        {},
                        change_set,
                        evidence_path=Path("review.json"),
                        ledger_prefix=ledger_prefix,
                        token_suffix=token_suffix,
                        attempt=2,
                    )
                )
            deadline.assert_not_called()
            aws.assert_not_called()

        drifted = {**ledger, "stack_id": stack_id[:-1] + "2"}
        with mock.patch.object(
            LIVE, "validate_reviewed_update_for_execution"
        ) as validate, mock.patch.object(
            LIVE, "aws_json"
        ) as aws, self.assertRaisesRegex(
            LIVE.LiveTestError, "differs from its reviewed create ID"
        ):
            LIVE.execute_reviewed_update(
                Path("ledger.json"),
                drifted,
                {},
                change_set,
                evidence_path=Path("review.json"),
                ledger_prefix="lifecycle_update",
                token_suffix="safe-update",
                attempt=2,
            )
        validate.assert_not_called()
        aws.assert_not_called()

    def test_destroy_deletes_and_waits_only_by_exact_stack_ids(self):
        bootstrap_stack_id = self.bootstrap_stack_id()
        application_stack_id = (
            "arn:aws:cloudformation:us-west-2:111122223333:stack/"
            "bridgefu-bft-safe1/00000000-0000-0000-0000-000000000001"
        )
        ledger = {
            "execution_id": "bft-safe1",
            "status": "deployed",
            "partition": "aws",
            "region": "us-west-2",
            "account_id": "111122223333",
            "connect_mode": "existing",
            "bootstrap_stack_name": "bridgefu-bft-safe1-bootstrap",
            "bootstrap_stack_id": bootstrap_stack_id,
            "deployment_role_arn": "arn:aws:iam::111122223333:role/deployer",
            "stack_name": "bridgefu-bft-safe1",
            "review_stack_id": application_stack_id,
            "stack_id": application_stack_id,
            "events": [],
        }
        args = LIVE.argparse.Namespace(
            execution_id=ledger["execution_id"], confirm=ledger["execution_id"]
        )

        def status(identifier, _region, _environment=None):
            if identifier in {bootstrap_stack_id, application_stack_id}:
                return "CREATE_COMPLETE"
            self.fail(f"mutable stack name used for teardown: {identifier}")

        with mock.patch.object(
            LIVE, "load_ledger", return_value=(Path("ledger.json"), ledger)
        ), mock.patch.object(LIVE, "bind_active_ledger_identity"), mock.patch.object(
            LIVE, "stack_status_if_exists", side_effect=status
        ), mock.patch.object(
            LIVE, "assume_env", return_value={"SAFE": "1"}
        ), mock.patch.object(
            LIVE,
            "stack_description",
            return_value={
                "StackId": application_stack_id,
                "StackStatus": "CREATE_COMPLETE",
            },
        ), mock.patch.object(
            LIVE, "require_owned_stack_for_deletion"
        ), mock.patch.object(
            LIVE, "stop_headless_build_before_teardown"
        ), mock.patch.object(
            LIVE, "recover_vapi_teardown_contract", return_value="not_created"
        ), mock.patch.object(
            LIVE, "prove_vapi_teardown_contract"
        ), mock.patch.object(
            LIVE, "review_stack_ids_for_execution", return_value=[]
        ), mock.patch.object(
            LIVE, "aws_json"
        ) as aws, mock.patch.object(
            LIVE, "aws_wait"
        ) as waiter, mock.patch.object(
            LIVE, "record"
        ), mock.patch.object(
            LIVE, "prove_teardown_zero_state"
        ):
            LIVE.destroy(args)

        self.assertEqual(
            [
                call.args[0][call.args[0].index("--stack-name") + 1]
                for call in aws.call_args_list
            ],
            [application_stack_id, bootstrap_stack_id],
        )
        self.assertEqual(
            [
                call.args[0][call.args[0].index("--stack-name") + 1]
                for call in waiter.call_args_list
            ],
            [application_stack_id, bootstrap_stack_id],
        )

    def test_destroy_rejects_same_name_application_replacement_before_mutation(self):
        bootstrap_stack_id = self.bootstrap_stack_id()
        application_stack_id = (
            "arn:aws:cloudformation:us-west-2:111122223333:stack/"
            "bridgefu-bft-safe1/00000000-0000-0000-0000-000000000001"
        )
        replacement_stack_id = application_stack_id[:-1] + "2"
        ledger = {
            "execution_id": "bft-safe1",
            "status": "deployed",
            "partition": "aws",
            "region": "us-west-2",
            "account_id": "111122223333",
            "connect_mode": "existing",
            "bootstrap_stack_name": "bridgefu-bft-safe1-bootstrap",
            "bootstrap_stack_id": bootstrap_stack_id,
            "deployment_role_arn": "arn:aws:iam::111122223333:role/deployer",
            "stack_name": "bridgefu-bft-safe1",
            "review_stack_id": application_stack_id,
            "stack_id": application_stack_id,
            "events": [],
        }

        def status(identifier, _region, _environment=None):
            return {
                bootstrap_stack_id: "CREATE_COMPLETE",
                application_stack_id: "DELETE_COMPLETE",
                ledger["stack_name"]: "CREATE_COMPLETE",
            }[identifier]

        args = LIVE.argparse.Namespace(
            execution_id=ledger["execution_id"], confirm=ledger["execution_id"]
        )
        with mock.patch.object(
            LIVE, "load_ledger", return_value=(Path("ledger.json"), ledger)
        ), mock.patch.object(LIVE, "bind_active_ledger_identity"), mock.patch.object(
            LIVE, "stack_status_if_exists", side_effect=status
        ), mock.patch.object(
            LIVE, "assume_env", return_value={"SAFE": "1"}
        ), mock.patch.object(
            LIVE,
            "stack_description_by_name",
            return_value={
                "StackName": ledger["stack_name"],
                "StackId": replacement_stack_id,
                "StackStatus": "CREATE_COMPLETE",
            },
        ), mock.patch.object(
            LIVE, "stop_headless_build_before_teardown"
        ) as stop, mock.patch.object(
            LIVE, "recover_vapi_teardown_contract"
        ) as recover, mock.patch.object(
            LIVE, "aws_json"
        ) as aws, self.assertRaisesRegex(
            LIVE.LiveTestError, "different live stack ID"
        ):
            LIVE.destroy(args)
        stop.assert_not_called()
        recover.assert_not_called()
        aws.assert_not_called()

    def test_destroy_rejects_same_name_qualification_replacement_before_mutation(
        self,
    ):
        bootstrap_stack_id = self.bootstrap_stack_id()
        application_stack_id = (
            "arn:aws:cloudformation:us-west-2:111122223333:stack/"
            "bridgefu-bft-safe1/00000000-0000-0000-0000-000000000001"
        )
        qualification_stack_id = (
            "arn:aws:cloudformation:us-west-2:111122223333:stack/"
            "bridgefu-bft-safe1-qualification/"
            "00000000-0000-0000-0000-000000000002"
        )
        ledger = {
            "execution_id": "bft-safe1",
            "status": "deployed",
            "partition": "aws",
            "region": "us-west-2",
            "account_id": "111122223333",
            "connect_mode": "disposable",
            "bootstrap_stack_name": "bridgefu-bft-safe1-bootstrap",
            "bootstrap_stack_id": bootstrap_stack_id,
            "deployment_role_arn": "arn:aws:iam::111122223333:role/deployer",
            "stack_name": "bridgefu-bft-safe1",
            "review_stack_id": application_stack_id,
            "stack_id": application_stack_id,
            "qualification_stack_name": "bridgefu-bft-safe1-qualification",
            "qualification_review_stack_id": qualification_stack_id,
            "qualification_stack_id": qualification_stack_id,
            "events": [],
        }
        replacement_stack_id = qualification_stack_id[:-1] + "9"

        def status(identifier, _region, _environment=None):
            return {
                bootstrap_stack_id: "CREATE_COMPLETE",
                application_stack_id: "DELETE_COMPLETE",
                ledger["stack_name"]: None,
                qualification_stack_id: "DELETE_COMPLETE",
                ledger["qualification_stack_name"]: "CREATE_COMPLETE",
            }[identifier]

        args = LIVE.argparse.Namespace(
            execution_id=ledger["execution_id"], confirm=ledger["execution_id"]
        )
        with mock.patch.object(
            LIVE, "load_ledger", return_value=(Path("ledger.json"), ledger)
        ), mock.patch.object(LIVE, "bind_active_ledger_identity"), mock.patch.object(
            LIVE, "stack_status_if_exists", side_effect=status
        ), mock.patch.object(
            LIVE, "assume_env", return_value={"SAFE": "1"}
        ), mock.patch.object(
            LIVE,
            "stack_description_by_name",
            return_value={
                "StackName": ledger["qualification_stack_name"],
                "StackId": replacement_stack_id,
                "StackStatus": "CREATE_COMPLETE",
            },
        ), mock.patch.object(
            LIVE, "stop_headless_build_before_teardown"
        ) as stop, mock.patch.object(
            LIVE, "recover_vapi_teardown_contract"
        ) as recover, mock.patch.object(
            LIVE, "aws_json"
        ) as aws, self.assertRaisesRegex(
            LIVE.LiveTestError, "different live stack ID"
        ):
            LIVE.destroy(args)
        stop.assert_not_called()
        recover.assert_not_called()
        aws.assert_not_called()

    def test_destroy_bootstrap_tombstone_requires_name_absence_before_reconciliation(
        self,
    ):
        bootstrap_stack_id = self.bootstrap_stack_id()
        ledger = {
            "execution_id": "bft-safe1",
            "status": "deployed",
            "partition": "aws",
            "region": "us-west-2",
            "account_id": "111122223333",
            "connect_mode": "existing",
            "bootstrap_stack_name": "bridgefu-bft-safe1-bootstrap",
            "bootstrap_stack_id": bootstrap_stack_id,
            "stack_name": "bridgefu-bft-safe1",
            "events": [],
        }
        args = LIVE.argparse.Namespace(
            execution_id=ledger["execution_id"], confirm=ledger["execution_id"]
        )

        with self.subTest("name absent"), mock.patch.object(
            LIVE, "load_ledger", return_value=(Path("ledger.json"), ledger)
        ), mock.patch.object(LIVE, "bind_active_ledger_identity"), mock.patch.object(
            LIVE,
            "stack_status_if_exists",
            side_effect=["DELETE_COMPLETE", None],
        ), mock.patch.object(
            LIVE, "prove_teardown_zero_state"
        ) as prove, mock.patch.object(
            LIVE, "stop_headless_build_before_teardown"
        ) as stop, mock.patch.object(
            LIVE, "aws_json"
        ) as aws:
            LIVE.destroy(args)
        prove.assert_called_once()
        stop.assert_not_called()
        aws.assert_not_called()

        replacement_stack_id = bootstrap_stack_id[:-1] + "2"
        with self.subTest("same-name replacement"), mock.patch.object(
            LIVE, "load_ledger", return_value=(Path("ledger.json"), ledger)
        ), mock.patch.object(LIVE, "bind_active_ledger_identity"), mock.patch.object(
            LIVE,
            "stack_status_if_exists",
            side_effect=["DELETE_COMPLETE", "CREATE_COMPLETE"],
        ), mock.patch.object(
            LIVE,
            "stack_description_by_name",
            return_value={
                "StackName": ledger["bootstrap_stack_name"],
                "StackId": replacement_stack_id,
                "StackStatus": "CREATE_COMPLETE",
            },
        ), mock.patch.object(
            LIVE, "prove_teardown_zero_state"
        ) as prove, mock.patch.object(
            LIVE, "stop_headless_build_before_teardown"
        ) as stop, mock.patch.object(
            LIVE, "aws_json"
        ) as aws, self.assertRaisesRegex(
            LIVE.LiveTestError, "different live stack ID"
        ):
            LIVE.destroy(args)
        prove.assert_not_called()
        stop.assert_not_called()
        aws.assert_not_called()

    def test_failure_event_capture_walks_nested_stacks(self):
        child = (
            "arn:aws:cloudformation:us-west-2:123456789012:stack/"
            "child/00000000-0000-0000-0000-000000000000"
        )

        def response(arguments, **_kwargs):
            target = arguments[arguments.index("--stack-name") + 1]
            if target == "root":
                return {
                    "StackEvents": [
                        {
                            "LogicalResourceId": "Application",
                            "ResourceType": "AWS::CloudFormation::Stack",
                            "ResourceStatus": "CREATE_FAILED",
                            "PhysicalResourceId": child,
                        }
                    ]
                }
            return {
                "StackEvents": [
                    {
                        "LogicalResourceId": "Runtime",
                        "ResourceType": "AWS::EC2::Instance",
                        "ResourceStatus": "CREATE_FAILED",
                        "ResourceStatusReason": "synthetic failure",
                    }
                ]
            }

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            LIVE, "aws_json", side_effect=response
        ):
            ledger_path = Path(directory) / "ledger.json"
            LIVE.write_stack_failure_events(
                ledger_path,
                {"execution_id": "bft-safe1", "region": "us-west-2"},
                {},
                "root",
                "failure.json",
            )
            evidence = json.loads((Path(directory) / "failure.json").read_text())
        self.assertEqual(evidence["stack_count"], 2)
        self.assertTrue(
            any(
                event["stack_path"] == "root/Application"
                for event in evidence["events"]
            )
        )

    def test_headless_role_credentials_refresh_during_long_polling(self):
        environments = [{"SESSION": "one"}, {"SESSION": "two"}]
        with mock.patch.object(
            LIVE.time, "monotonic", side_effect=[0.0, 899.0, 900.0]
        ), mock.patch.object(LIVE, "assume_env", side_effect=environments) as assume:
            provider = LIVE.RefreshableRoleEnvironment(
                {"execution_id": "bft-safe1"},
                "qualification",
                refresh_after_seconds=900,
            )
            self.assertEqual(provider.get(), environments[0])
            self.assertEqual(provider.get(), environments[0])
            self.assertEqual(provider.get(), environments[1])
        self.assertEqual(assume.call_count, 2)

    def test_headless_build_discovery_adopts_exact_immutable_input(self):
        state = {
            "input_key": "qualification/bft-safe1/runs/full-1785690000/input.json",
            "input_version": "input-version",
            "started_at": "2026-08-02T00:00:00Z",
        }
        ledger = {
            "artifact_bucket": "bucket",
            "qualification_project_name": "bridgefu-bft-safe1-qualification",
        }
        build = {
            "id": "bridgefu-bft-safe1-qualification:00000000-0000-0000-0000-000000000001",
            "startTime": "2026-08-02T00:00:01Z",
            "environment": {
                "environmentVariables": [
                    {
                        "name": "BRIDGEFU_RUNNER_INPUT_BUCKET",
                        "value": "bucket",
                        "type": "PLAINTEXT",
                    },
                    {
                        "name": "BRIDGEFU_RUNNER_INPUT_KEY",
                        "value": state["input_key"],
                        "type": "PLAINTEXT",
                    },
                    {
                        "name": "BRIDGEFU_RUNNER_INPUT_VERSION",
                        "value": "input-version",
                        "type": "PLAINTEXT",
                    },
                ]
            },
        }
        with mock.patch.object(
            LIVE, "list_headless_project_builds", return_value=[build]
        ), mock.patch.object(LIVE, "known_headless_build_ids", return_value=[]):
            self.assertIs(
                LIVE.discover_headless_build(ledger, state, {"SESSION": "fresh"}),
                build,
            )
        conflicting = {
            **build,
            "environment": {"environmentVariables": []},
        }
        with mock.patch.object(
            LIVE, "list_headless_project_builds", return_value=[conflicting]
        ), mock.patch.object(
            LIVE, "known_headless_build_ids", return_value=[]
        ), self.assertRaises(
            LIVE.LiveTestError
        ):
            LIVE.discover_headless_build(ledger, state, {"SESSION": "fresh"})

    def test_headless_start_uses_the_persisted_idempotency_token(self):
        state = {
            "phase": "input_published",
            "suite": "full",
            "run_id": "full-1785690000",
            "input_key": "qualification/bft-safe1/runs/full-1785690000/input.json",
            "input_version": "input-version",
            "idempotency_token": "a" * 64,
        }
        ledger = {
            "region": "us-west-2",
            "artifact_bucket": "bucket",
            "qualification_project_name": "bridgefu-bft-safe1-qualification",
        }
        build_id = (
            "bridgefu-bft-safe1-qualification:" "00000000-0000-0000-0000-000000000001"
        )
        credentials = mock.Mock()
        credentials.get.return_value = {"SESSION": "fresh"}
        with mock.patch.object(
            LIVE, "discover_headless_build", return_value=None
        ), mock.patch.object(
            LIVE,
            "aws_json",
            return_value={
                "build": {
                    "id": build_id,
                    "projectName": ledger["qualification_project_name"],
                    "buildStatus": "IN_PROGRESS",
                }
            },
        ) as aws, mock.patch.object(
            LIVE, "record"
        ), mock.patch.object(
            LIVE, "validate_headless_run_state", return_value=state
        ):
            LIVE.start_headless_build(Path("ledger.json"), ledger, state, credentials)
        arguments = aws.call_args.args[0]
        self.assertEqual(
            arguments[arguments.index("--idempotency-token") + 1], "a" * 64
        )
        self.assertEqual(state["build_id"], build_id)

    def test_headless_start_adopts_discovered_build_without_starting_another(self):
        state = {"phase": "input_published"}
        ledger: dict[str, object] = {}
        build = {"id": "exact-build"}
        credentials = mock.Mock()
        with mock.patch.object(
            LIVE, "discover_headless_build", return_value=build
        ), mock.patch.object(
            LIVE, "persist_adopted_headless_build"
        ) as persist, mock.patch.object(
            LIVE, "aws_json"
        ) as aws:
            LIVE.start_headless_build(Path("ledger.json"), ledger, state, credentials)
        persist.assert_called_once_with(Path("ledger.json"), ledger, state, build)
        aws.assert_not_called()

    def test_full_headless_start_requires_the_complete_180_minute_window(self):
        now = LIVE.dt.datetime.now(LIVE.dt.timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            ledger_path = Path(directory) / "ledger.json"
            ledger = {
                "execution_id": "bft-safe1",
                "publication_source_tree_sha256": "a" * 64,
                "qualification_deadline_at": (now + LIVE.dt.timedelta(hours=4))
                .isoformat()
                .replace("+00:00", "Z"),
                "sip_security": "sip_rtp",
                "connect_login_url": "https://example.test/connect",
                "agent_credential_secret_arn": "arn:agent",
                "vapi_public_key_secret_arn": "arn:public",
                "artifact_bucket": "bucket",
            }
            with mock.patch.object(
                LIVE, "ledger_path", return_value=ledger_path
            ), self.assertRaisesRegex(LIVE.LiveTestError, "180 minutes"):
                LIVE.create_headless_run_state(
                    ledger_path,
                    ledger,
                    "full",
                    LIVE.HEADLESS_BUILD_TIMEOUT_SECONDS - 1,
                )

    def test_active_codebuild_inventory_reports_only_nonterminal_exact_builds(self):
        project = "bridgefu-bft-safe1-qualification"
        build_id = f"{project}:00000000-0000-0000-0000-000000000001"
        ledger = {
            "region": "us-west-2",
            "qualification_project_name": project,
        }
        listing = mock.Mock(
            returncode=0,
            stdout=json.dumps({"ids": [build_id]}),
            stderr="",
        )
        with mock.patch.object(
            LIVE, "command", return_value=listing
        ), mock.patch.object(
            LIVE,
            "aws_json",
            return_value={
                "builds": [
                    {
                        "id": build_id,
                        "projectName": project,
                        "buildStatus": "IN_PROGRESS",
                    }
                ],
                "buildsNotFound": [],
            },
        ):
            self.assertEqual(LIVE.inventory_headless_build_ids(ledger), [build_id])
        with mock.patch.object(
            LIVE, "command", return_value=listing
        ), mock.patch.object(
            LIVE,
            "aws_json",
            return_value={
                "builds": [
                    {
                        "id": build_id,
                        "projectName": project,
                        "buildStatus": "SUCCEEDED",
                    }
                ],
                "buildsNotFound": [],
            },
        ):
            self.assertEqual(LIVE.inventory_headless_build_ids(ledger), [])

    def test_headless_teardown_stops_and_polls_before_returning(self):
        build_id = (
            "bridgefu-bft-safe1-qualification:" "00000000-0000-0000-0000-000000000001"
        )
        state = {"phase": "build_started", "build_id": build_id}
        ledger = {
            "headless_run": state,
            "headless_build_id": build_id,
            "qualification_project_name": "bridgefu-bft-safe1-qualification",
        }
        credentials = mock.Mock()
        with mock.patch.object(
            LIVE, "validate_headless_run_state", return_value=state
        ), mock.patch.object(
            LIVE, "headless_run_history", return_value=[]
        ), mock.patch.object(
            LIVE, "RefreshableRoleEnvironment", return_value=credentials
        ), mock.patch.object(
            LIVE,
            "list_headless_project_builds",
            return_value=[{"id": build_id, "buildStatus": "IN_PROGRESS"}],
        ), mock.patch.object(
            LIVE,
            "exact_headless_build",
            return_value={"id": build_id, "buildStatus": "IN_PROGRESS"},
        ), mock.patch.object(
            LIVE, "request_headless_build_stop"
        ) as stop, mock.patch.object(
            LIVE,
            "wait_for_stopped_headless_build",
            return_value={"id": build_id, "buildStatus": "STOPPED"},
        ) as wait:
            LIVE.stop_headless_build_before_teardown(Path("ledger.json"), ledger)
        stop.assert_called_once()
        wait.assert_called_once()

    def test_headless_evidence_download_is_version_and_build_bound(self):
        payload = b"headless-evidence"
        digest = hashlib.sha256(payload).hexdigest()
        build_id = (
            "bridgefu-bft-safe1-qualification:" "00000000-0000-0000-0000-000000000001"
        )
        ledger = {
            "execution_id": "bft-safe1",
            "region": "us-west-2",
            "artifact_bucket": "bucket",
        }
        state = {
            "run_id": "full-1785690000",
            "build_id": build_id,
            "evidence_key": (
                "qualification/bft-safe1/runs/full-1785690000/evidence.tar.gz"
            ),
        }
        credentials = mock.Mock()
        credentials.get.return_value = {"SESSION": "fresh"}

        def response(arguments, **_kwargs):
            if "head-object" in arguments:
                return {
                    "ContentLength": len(payload),
                    "VersionId": "evidence-version",
                    "Metadata": {
                        "sha256": digest,
                        "execution-id": "bft-safe1",
                        "build-id": build_id,
                    },
                }
            Path(arguments[-1]).write_bytes(payload)
            return {"VersionId": "evidence-version"}

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            LIVE, "aws_json", side_effect=response
        ) as aws:
            ledger_path = Path(directory) / "ledger.json"
            archive, observed_digest, version = LIVE.download_headless_evidence(
                ledger_path, ledger, state, credentials
            )
            self.assertEqual(archive.read_bytes(), payload)
        self.assertEqual(observed_digest, digest)
        self.assertEqual(version, "evidence-version")
        get_arguments = aws.call_args_list[1].args[0]
        self.assertEqual(
            get_arguments[get_arguments.index("--version-id") + 1],
            "evidence-version",
        )

    def test_headless_runner_timeout_and_prebuilt_binary_contract(self):
        template = (
            ROOT
            / "recipes/vapi-amazon-connect-screen-pop/cloudformation/nested/qualification-runner.yaml"
        ).read_text()
        self.assertIn("TimeoutInMinutes: 180", template)
        self.assertNotIn("cargo build", template)
        self.assertNotIn("rustup toolchain", template)
        self.assertIn("target/release/examples/recipe_sip_source --version", template)
        self.assertIn("target/release/examples/recipe_sip_negative --version", template)
        destroyer = (
            SCRIPT.read_text()
            .split("def destroy(args", 1)[1]
            .split("def destroy_finalize", 1)[0]
        )
        self.assertLess(
            destroyer.index("stop_headless_build_before_teardown"),
            destroyer.index("stack_deletions ="),
        )


if __name__ == "__main__":
    unittest.main()
